use std::io;
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{
    AgentVsockEndpoint, AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_RECOVERY_REPORT_FILE_NAME,
    AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
};

/// Cleans attempt-owned artifacts only while a utility-VM connection is being
/// established.
///
/// The shim owns the handoff after the authenticated Agent session passes its
/// contract checks so owner-death recovery can retain exact terminal evidence.
/// Before that point, the Host may terminate the shim without running its Rust
/// destructors. This guard removes only paths proven absent before this launch,
/// allowing the same exact generation to retry without weakening an existing
/// recovery handoff or overwriting prior console evidence.
pub(crate) struct FailedAgentVmLaunchCleanup {
    console: PathBuf,
    recovery: Option<RecoveryHandoffPaths>,
    preserve: bool,
}

struct RecoveryHandoffPaths {
    guest_report: PathBuf,
    guest_directory: PathBuf,
    destination: PathBuf,
    pending: PathBuf,
}

impl FailedAgentVmLaunchCleanup {
    pub(crate) fn new(
        console: &Path,
        runtime_share: &Path,
        endpoint: &AgentVsockEndpoint,
        recovery_destination: Option<&Path>,
    ) -> Result<Self, String> {
        require_absent_path(console, "VM console")?;
        let recovery = recovery_destination
            .map(|destination| -> Result<RecoveryHandoffPaths, String> {
                let guest_directory = runtime_share.join(format!(
                    "{AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX}{}",
                    endpoint.pipe_name()
                ));
                let guest_report = guest_directory.join(AGENT_RECOVERY_REPORT_FILE_NAME);
                let mut pending = destination.as_os_str().to_os_string();
                pending.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
                let pending = PathBuf::from(pending);

                require_absent_path(&guest_directory, "guest recovery handoff directory")?;
                require_absent_path(destination, "trusted recovery report")?;
                require_absent_path(&pending, "trusted recovery pending marker")?;
                Ok(RecoveryHandoffPaths {
                    guest_report,
                    guest_directory,
                    destination: destination.to_path_buf(),
                    pending,
                })
            })
            .transpose()?;

        Ok(Self {
            console: console.to_path_buf(),
            recovery,
            preserve: false,
        })
    }

    pub(crate) fn preserve(mut self) {
        self.preserve = true;
    }

    fn remove(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        remove_file_if_present(&self.console, "VM console", &mut errors);
        if let Some(recovery) = &self.recovery {
            remove_file_if_present(&recovery.guest_report, "guest recovery report", &mut errors);
            remove_directory_if_present(&recovery.guest_directory, &mut errors);
            remove_file_if_present(
                &recovery.destination,
                "trusted recovery report",
                &mut errors,
            );
            remove_file_if_present(
                &recovery.pending,
                "trusted recovery pending marker",
                &mut errors,
            );
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for FailedAgentVmLaunchCleanup {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = self.remove();
        }
    }
}

fn require_absent_path(path: &Path, label: &str) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(format!(
            "refusing to replace an existing {label}: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to inspect {label} {} before VM launch: {error}",
            path.display()
        )),
    }
}

fn remove_file_if_present(path: &Path, label: &str, errors: &mut Vec<String>) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove failed-launch {label} {}: {error}",
            path.display()
        )),
    }
}

fn remove_directory_if_present(path: &Path, errors: &mut Vec<String>) {
    match std::fs::remove_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove failed-launch recovery directory {}: {error}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temporary: tempfile::TempDir,
        cleanup: FailedAgentVmLaunchCleanup,
        console: PathBuf,
        directory: PathBuf,
        guest_report: PathBuf,
        destination: PathBuf,
        pending: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("create recovery cleanup fixture");
            let runtime_share = temporary.path().join("share");
            let recovery_root = temporary.path().join("recovery");
            std::fs::create_dir(&runtime_share).expect("create runtime share");
            std::fs::create_dir(&recovery_root).expect("create recovery root");
            let endpoint = AgentVsockEndpoint::generate().expect("generate recovery endpoint");
            let console = temporary.path().join("console.log");
            let directory = runtime_share.join(format!(
                "{AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX}{}",
                endpoint.pipe_name()
            ));
            let guest_report = directory.join(AGENT_RECOVERY_REPORT_FILE_NAME);
            let destination = recovery_root.join("container-1.json");
            let mut pending = destination.as_os_str().to_os_string();
            pending.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
            let pending = PathBuf::from(pending);
            let cleanup = FailedAgentVmLaunchCleanup::new(
                &console,
                &runtime_share,
                &endpoint,
                Some(&destination),
            )
            .expect("prepare failed-connection cleanup");
            Self {
                _temporary: temporary,
                cleanup,
                console,
                directory,
                guest_report,
                destination,
                pending,
            }
        }

        fn stage(&self) {
            std::fs::write(&self.console, b"console").expect("stage VM console");
            std::fs::create_dir(&self.directory).expect("stage guest recovery directory");
            std::fs::write(&self.guest_report, b"guest report")
                .expect("stage guest recovery report");
            std::fs::write(&self.destination, b"trusted report")
                .expect("stage trusted recovery report");
            std::fs::write(&self.pending, b"").expect("stage recovery pending marker");
        }
    }

    #[test]
    fn failed_connection_removes_attempt_owned_launch_artifacts() {
        let fixture = Fixture::new();
        fixture.stage();
        let Fixture {
            _temporary,
            cleanup,
            console,
            directory,
            guest_report,
            destination,
            pending,
        } = fixture;

        drop(cleanup);

        assert!(!console.exists());
        assert!(!guest_report.exists());
        assert!(!directory.exists());
        assert!(!destination.exists());
        assert!(!pending.exists());
    }

    #[test]
    fn failed_connection_without_recovery_still_removes_the_console() {
        let temporary = tempfile::tempdir().expect("create console cleanup fixture");
        let runtime_share = temporary.path().join("share");
        std::fs::create_dir(&runtime_share).expect("create runtime share");
        let console = temporary.path().join("console.log");
        let endpoint = AgentVsockEndpoint::generate().expect("generate console endpoint");
        let cleanup = FailedAgentVmLaunchCleanup::new(&console, &runtime_share, &endpoint, None)
            .expect("prepare console-only cleanup");
        std::fs::write(&console, b"console").expect("stage VM console");

        drop(cleanup);

        assert!(!console.exists());
    }

    #[test]
    fn established_session_preserves_owner_death_recovery_handoff() {
        let fixture = Fixture::new();
        fixture.stage();
        let Fixture {
            _temporary,
            cleanup,
            console,
            directory,
            guest_report,
            destination,
            pending,
        } = fixture;

        cleanup.preserve();

        assert!(console.is_file());
        assert!(guest_report.is_file());
        assert!(directory.is_dir());
        assert!(destination.is_file());
        assert!(pending.is_file());
    }

    #[test]
    fn failed_connection_cleanup_never_claims_an_existing_recovery_handoff() {
        let temporary = tempfile::tempdir().expect("create existing recovery fixture");
        let runtime_share = temporary.path().join("share");
        let recovery_root = temporary.path().join("recovery");
        std::fs::create_dir(&runtime_share).expect("create runtime share");
        std::fs::create_dir(&recovery_root).expect("create recovery root");
        let endpoint = AgentVsockEndpoint::generate().expect("generate recovery endpoint");
        let destination = recovery_root.join("container-1.json");
        let mut pending = destination.as_os_str().to_os_string();
        pending.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
        let pending = PathBuf::from(pending);
        std::fs::write(&pending, b"").expect("stage existing recovery marker");

        let console = temporary.path().join("console.log");
        let error = match FailedAgentVmLaunchCleanup::new(
            &console,
            &runtime_share,
            &endpoint,
            Some(&destination),
        ) {
            Ok(_) => panic!("an existing handoff must not become attempt-owned"),
            Err(error) => error,
        };

        assert!(error.contains("existing trusted recovery pending marker"));
        assert!(pending.is_file());
    }
}
