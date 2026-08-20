use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const READY_FILE: &str = ".a3s-oci-kvm-compatibility-drift-ready";
const CONTINUE_FILE: &str = ".a3s-oci-kvm-compatibility-drift-continue";
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CASE_BYTES: u64 = 128;
const SUPPORTED_CASES: &[&str] = &[
    "guest-agent-digest-drift",
    "manifest-content-drift",
    "manifest-replacement",
    "manifest-symlink",
    "system-image-content-drift",
    "system-image-replacement",
    "system-image-symlink",
];

/// Qualification-only synchronization files used to introduce one external
/// asset mutation after configuration and before the first KVM-device access.
#[derive(Debug)]
pub(crate) struct CompatibilityDriftBarrier {
    ready: PathBuf,
    proceed: PathBuf,
}

impl CompatibilityDriftBarrier {
    pub(crate) fn wait(runtime_share: &Path, case: &str) -> Result<Self, String> {
        if !SUPPORTED_CASES.contains(&case) {
            return Err(format!(
                "unsupported Linux KVM compatibility-drift qualification case: {case}"
            ));
        }
        let state = runtime_share.join("run");
        let ready = state.join(READY_FILE);
        let proceed = state.join(CONTINUE_FILE);
        require_absent(&ready)?;
        require_absent(&proceed)?;

        let mut ready_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&ready)
            .map_err(|error| {
                format!(
                    "failed to create Linux KVM compatibility-drift ready marker {}: {error}",
                    ready.display()
                )
            })?;
        ready_file
            .write_all(case.as_bytes())
            .and_then(|()| ready_file.write_all(b"\n"))
            .and_then(|()| ready_file.sync_all())
            .map_err(|error| {
                format!(
                    "failed to publish Linux KVM compatibility-drift ready marker {}: {error}",
                    ready.display()
                )
            })?;

        let barrier = Self { ready, proceed };
        barrier.wait_for_continue(case)?;
        Ok(barrier)
    }

    fn wait_for_continue(&self, case: &str) -> Result<(), String> {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        loop {
            match fs::symlink_metadata(&self.proceed) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(format!(
                            "Linux KVM compatibility-drift continue marker must be a real regular file: {}",
                            self.proceed.display()
                        ));
                    }
                    // SAFETY: geteuid has no arguments and cannot fail.
                    let effective_user_id = unsafe { libc::geteuid() };
                    if metadata.uid() != effective_user_id || metadata.mode() & 0o777 != 0o600 {
                        return Err(format!(
                            "Linux KVM compatibility-drift continue marker must be owned by UID {effective_user_id} with mode 600: {}",
                            self.proceed.display()
                        ));
                    }
                    if metadata.len() == 0 || metadata.len() > MAX_CASE_BYTES {
                        return Err(format!(
                            "Linux KVM compatibility-drift continue marker has an invalid size: {}",
                            self.proceed.display()
                        ));
                    }
                    let mut contents = String::new();
                    File::open(&self.proceed)
                        .and_then(|mut file| file.read_to_string(&mut contents))
                        .map_err(|error| {
                            format!(
                                "failed to read Linux KVM compatibility-drift continue marker {}: {error}",
                                self.proceed.display()
                            )
                        })?;
                    if contents != format!("{case}\n") {
                        return Err(format!(
                            "Linux KVM compatibility-drift continue marker did not authorize case {case}"
                        ));
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect Linux KVM compatibility-drift continue marker {}: {error}",
                        self.proceed.display()
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for Linux KVM compatibility-drift qualification case {case}"
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for CompatibilityDriftBarrier {
    fn drop(&mut self) {
        for path in [&self.proceed, &self.ready] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {}
            }
        }
    }
}

fn require_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect Linux KVM compatibility-drift control path {}: {error}",
            path.display()
        )),
        Ok(_) => Err(format!(
            "Linux KVM compatibility-drift control path already exists: {}",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use super::{CompatibilityDriftBarrier, CONTINUE_FILE, READY_FILE};

    #[test]
    fn exact_case_handshake_is_bounded_and_cleaned() {
        let temporary = tempfile::tempdir().expect("create barrier fixture");
        let state = temporary.path().join("run");
        fs::create_dir(&state).expect("create state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect state directory");
        let proceed = state.join(CONTINUE_FILE);
        let writer = std::thread::spawn(move || {
            let ready = state.join(READY_FILE);
            while !ready.exists() {
                std::thread::yield_now();
            }
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&proceed)
                .expect("create continue marker");
            marker
                .write_all(b"manifest-replacement\n")
                .expect("write continue marker");
            marker.sync_all().expect("flush continue marker");
        });

        let barrier = CompatibilityDriftBarrier::wait(temporary.path(), "manifest-replacement")
            .expect("complete qualification handshake");
        writer.join().expect("join marker writer");
        drop(barrier);
        assert!(!temporary.path().join("run").join(READY_FILE).exists());
        assert!(!temporary.path().join("run").join(CONTINUE_FILE).exists());
    }

    #[test]
    fn unknown_case_fails_before_publishing_a_marker() {
        let temporary = tempfile::tempdir().expect("create barrier fixture");
        fs::create_dir(temporary.path().join("run")).expect("create state directory");
        let error = CompatibilityDriftBarrier::wait(temporary.path(), "unknown")
            .expect_err("unknown case must fail");
        assert!(error.contains("unsupported"));
        assert!(!temporary.path().join("run").join(READY_FILE).exists());
    }
}
