use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{
    AgentRecoveryReport, AgentVsockEndpoint, AuthenticatedAgentRecoveryReport, SessionToken,
    AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_RECOVERY_REPORT_FILE_NAME,
    AGENT_RECOVERY_REPORT_MAX_BYTES, AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
    AGENT_RUNTIME_SHARE_GUEST_ROOT,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

pub(crate) struct RecoveryReportHandoff {
    paths: RecoveryCleanupPaths,
    guest_path: String,
    destination: PathBuf,
    cleaned: bool,
}

impl RecoveryReportHandoff {
    pub(crate) fn create(
        host_root: &Path,
        guest_root: &str,
        endpoint: &AgentVsockEndpoint,
        destination: &Path,
    ) -> io::Result<Self> {
        validate_guest_root(guest_root)?;
        let host_root = canonical_plain_directory(host_root, "guest handoff root")?;
        let destination = prepare_destination(destination)?;
        if destination.starts_with(&host_root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "trusted recovery destination must be outside guest handoff root {}: {}",
                    host_root.display(),
                    destination.display()
                ),
            ));
        }

        let pending = pending_path(&destination);
        let pending_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)
            .map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to create trusted recovery pending marker {}",
                        pending.display()
                    ),
                )
            })?;
        if let Err(error) = pending_file.sync_all() {
            drop(pending_file);
            let _ = fs::remove_file(&pending);
            return Err(contextual(
                error,
                format!(
                    "failed to flush trusted recovery pending marker {}",
                    pending.display()
                ),
            ));
        }
        drop(pending_file);

        let directory_name = format!(
            "{AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX}{}",
            endpoint.pipe_name()
        );
        let directory = host_root.join(&directory_name);
        if let Err(error) = fs::create_dir(&directory) {
            let _ = fs::remove_file(&pending);
            return Err(contextual(
                error,
                format!(
                    "failed to create one-time guest recovery directory {}",
                    directory.display()
                ),
            ));
        }
        let paths = RecoveryCleanupPaths {
            file: directory.join(AGENT_RECOVERY_REPORT_FILE_NAME),
            directory,
            pending,
        };

        Ok(Self {
            paths,
            guest_path: guest_path(guest_root, &directory_name, AGENT_RECOVERY_REPORT_FILE_NAME),
            destination,
            cleaned: false,
        })
    }

    pub(crate) fn guest_path(&self) -> &str {
        &self.guest_path
    }

    pub(crate) fn cleanup_paths(&self) -> RecoveryCleanupPaths {
        self.paths.clone()
    }

    pub(crate) fn persist(mut self, token: &SessionToken) -> io::Result<AgentRecoveryReport> {
        let persist_result = self.persist_inner(token);
        let cleanup_result = self.paths.cleanup();
        self.cleaned = cleanup_result.is_ok();
        match (persist_result, cleanup_result) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::new(
                error.kind(),
                format!("{error}; guest recovery cleanup also failed: {cleanup}"),
            )),
        }
    }

    fn persist_inner(&self, token: &SessionToken) -> io::Result<AgentRecoveryReport> {
        let metadata = fs::symlink_metadata(&self.paths.file).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to inspect guest recovery report {}",
                    self.paths.file.display()
                ),
            )
        })?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > AGENT_RECOVERY_REPORT_MAX_BYTES as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "guest recovery report must be a plain file of at most {} bytes: {}",
                    AGENT_RECOVERY_REPORT_MAX_BYTES,
                    self.paths.file.display()
                ),
            ));
        }

        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        File::open(&self.paths.file)
            .and_then(|file| {
                file.take((AGENT_RECOVERY_REPORT_MAX_BYTES + 1) as u64)
                    .read_to_end(&mut encoded)
            })
            .map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to read guest recovery report {}",
                        self.paths.file.display()
                    ),
                )
            })?;
        if encoded.len() > AGENT_RECOVERY_REPORT_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest recovery report grew beyond its bounded size",
            ));
        }
        let report = AuthenticatedAgentRecoveryReport::verify_json(&encoded, token)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let normalized = report
            .to_json()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        atomic_write(&self.destination, &normalized)?;
        Ok(report)
    }
}

fn validate_guest_root(guest_root: &str) -> io::Result<()> {
    if matches!(guest_root, "/") || guest_root == AGENT_RUNTIME_SHARE_GUEST_ROOT {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported guest handoff root: {guest_root}"),
        ))
    }
}

fn guest_path(guest_root: &str, directory: &str, file: &str) -> String {
    if guest_root == "/" {
        format!("/{directory}/{file}")
    } else {
        format!("{guest_root}/{directory}/{file}")
    }
}

impl Drop for RecoveryReportHandoff {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.paths.cleanup();
        }
    }
}

#[derive(Clone)]
pub(crate) struct RecoveryCleanupPaths {
    file: PathBuf,
    directory: PathBuf,
    pending: PathBuf,
}

impl RecoveryCleanupPaths {
    pub(crate) fn cleanup(&self) -> io::Result<()> {
        let mut errors = Vec::new();
        remove_file_if_present(&self.file, &mut errors);
        remove_dir_if_present(&self.directory, &mut errors);
        remove_pending_if_present(&self.pending, &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

fn prepare_destination(destination: &Path) -> io::Result<PathBuf> {
    if !destination.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted recovery destination must be absolute: {}",
                destination.display()
            ),
        ));
    }
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted recovery destination must name a file: {}",
                destination.display()
            ),
        )
    })?;
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted recovery destination has no parent: {}",
                destination.display()
            ),
        )
    })?;
    let parent = canonical_plain_directory(parent, "trusted recovery directory")?;
    let destination = parent.join(file_name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to overwrite trusted recovery destination {}",
                destination.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let pending = pending_path(&destination);
            match fs::symlink_metadata(&pending) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing to replace trusted recovery pending marker {}",
                        pending.display()
                    ),
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(destination),
                Err(error) => Err(contextual(
                    error,
                    format!(
                        "failed to inspect trusted recovery pending marker {}",
                        pending.display()
                    ),
                )),
            }
        }
        Err(error) => Err(contextual(
            error,
            format!(
                "failed to inspect trusted recovery destination {}",
                destination.display()
            ),
        )),
    }
}

fn pending_path(destination: &Path) -> PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
    PathBuf::from(path)
}

fn canonical_plain_directory(path: &Path, label: &str) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        contextual(
            error,
            format!("failed to inspect {label} {}", path.display()),
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be a plain directory: {}", path.display()),
        ));
    }
    path.canonicalize().map_err(|error| {
        contextual(
            error,
            format!("failed to resolve {label} {}", path.display()),
        )
    })
}

fn atomic_write(destination: &Path, encoded: &[u8]) -> io::Result<()> {
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted recovery destination has no file name",
        )
    })?;
    let temporary = destination.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to create temporary trusted recovery report {}",
                    temporary.display()
                ),
            )
        })?;
    let write_result = file.write_all(encoded).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(contextual(
            error,
            format!(
                "failed to write temporary trusted recovery report {}",
                temporary.display()
            ),
        ));
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(contextual(
            error,
            format!(
                "failed to commit trusted recovery report {}",
                destination.display()
            ),
        ));
    }
    Ok(())
}

fn remove_file_if_present(path: &Path, errors: &mut Vec<String>) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove one-time guest recovery report {}: {error}",
            path.display()
        )),
    }
}

fn remove_dir_if_present(path: &Path, errors: &mut Vec<String>) {
    match fs::remove_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove one-time guest recovery directory {}: {error}",
            path.display()
        )),
    }
}

fn remove_pending_if_present(path: &Path, errors: &mut Vec<String>) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove trusted recovery pending marker {}: {error}",
            path.display()
        )),
    }
}

fn contextual(error: io::Error, context: String) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentRecoveryRecord, AgentRecoveryReport, AgentVsockEndpoint,
        AuthenticatedAgentRecoveryReport, SessionToken,
    };
    use a3s_oci_sdk::{ContainerId, ContainerTarget, ExitStatus, Generation};

    use super::{pending_path, RecoveryReportHandoff};

    fn token(byte: u8) -> SessionToken {
        SessionToken::from_bytes([byte; 32]).expect("nonzero token")
    }

    fn report() -> AgentRecoveryReport {
        AgentRecoveryReport::new(vec![AgentRecoveryRecord::new(
            ContainerTarget::exact(ContainerId::new("box").expect("valid ID"), Generation(7)),
            format!("sha256:{}", "b".repeat(64)),
            ExitStatus::exited(23).expect("valid exit"),
        )
        .expect("valid record")])
        .expect("valid report")
    }

    #[test]
    fn verifies_normalizes_and_cleans_one_time_guest_report() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        std::fs::create_dir(&rootfs).unwrap();
        std::fs::create_dir(&trusted).unwrap();
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-recovery-test").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        assert!(pending_path(&destination).is_file());
        let guest_path = rootfs.join(handoff.guest_path().trim_start_matches('/'));
        let encoded = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        std::fs::write(&guest_path, encoded).unwrap();

        let verified = handoff.persist(&token(4)).expect("persist report");
        assert_eq!(verified, report());
        assert_eq!(
            AgentRecoveryReport::from_json(&std::fs::read(&destination).unwrap()).unwrap(),
            report()
        );
        assert!(!guest_path.exists());
        assert!(!guest_path.parent().unwrap().exists());
        assert!(!pending_path(&destination).exists());
    }

    #[test]
    fn rejects_tampering_without_creating_a_trusted_report() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        std::fs::create_dir(&rootfs).unwrap();
        std::fs::create_dir(&trusted).unwrap();
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-tamper-test").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        let guest_path = rootfs.join(handoff.guest_path().trim_start_matches('/'));
        let encoded = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["report"]["records"][0]["initExitStatus"]["exit_code"] = 24.into();
        std::fs::write(&guest_path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(handoff.persist(&token(4)).is_err());
        assert!(!destination.exists());
        assert!(!guest_path.exists());
        assert!(!pending_path(&destination).exists());
    }

    #[test]
    fn refuses_to_copy_trusted_evidence_into_the_guest_root() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        std::fs::create_dir(&rootfs).unwrap();
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-path-test").unwrap();
        assert!(
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &rootfs.join("box-7.json"),)
                .is_err()
        );
    }

    #[test]
    fn drop_cleans_the_guest_path_and_pending_marker() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        std::fs::create_dir(&rootfs).unwrap();
        std::fs::create_dir(&trusted).unwrap();
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-drop-test").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        let guest_directory = rootfs
            .join(handoff.guest_path().trim_start_matches('/'))
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(pending_path(&destination).is_file());
        drop(handoff);
        assert!(!pending_path(&destination).exists());
        assert!(!guest_directory.exists());
    }

    #[test]
    fn normalized_reports_do_not_retain_the_authentication_tag() {
        let authenticated = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&authenticated).unwrap();
        assert!(value.get("authenticationTag").is_some());
        let normalized = AuthenticatedAgentRecoveryReport::verify_json(&authenticated, &token(4))
            .unwrap()
            .to_json()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&normalized).unwrap();
        assert!(value.get("authenticationTag").is_none());
    }
}
