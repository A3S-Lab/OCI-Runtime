use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const READY_FILE: &str = ".a3s-oci-kvm-compatibility-drift-ready";
const CONTINUE_FILE: &str = ".a3s-oci-kvm-compatibility-drift-continue";
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_CASE_BYTES: u64 = 128;
const PRIVATE_FILE_MODE: u32 = 0o600;
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
    ready_file: File,
    ready_identity: EntryIdentity,
    proceed: PathBuf,
    proceed_file: Option<File>,
    proceed_identity: Option<EntryIdentity>,
}

/// Device/inode identity retained for every marker that this barrier may
/// remove.  A path is only a name; retaining the identity prevents a later
/// publisher from turning barrier teardown into deletion of an unrelated
/// entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

impl EntryIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
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

        let ready_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&ready)
            .map_err(|error| {
                format!(
                    "failed to create Linux KVM compatibility-drift ready marker {}: {error}",
                    ready.display()
                )
            })?;
        let ready_identity = EntryIdentity::from_file(&ready_file).map_err(|error| {
            format!(
                "failed to identify Linux KVM compatibility-drift ready marker {}: {error}",
                ready.display()
            )
        })?;

        let mut barrier = Self {
            ready,
            ready_file,
            ready_identity,
            proceed,
            proceed_file: None,
            proceed_identity: None,
        };
        barrier
            .ready_file
            .write_all(case.as_bytes())
            .and_then(|()| barrier.ready_file.write_all(b"\n"))
            .and_then(|()| barrier.ready_file.sync_all())
            .map_err(|error| {
                format!(
                    "failed to publish Linux KVM compatibility-drift ready marker {}: {error}",
                    barrier.ready.display()
                )
            })?;

        let expected_size = u64::try_from(case.len() + 1).map_err(|error| {
            format!("Linux KVM compatibility-drift ready marker size is not representable: {error}")
        })?;
        verify_owned_marker(&barrier.ready, barrier.ready_identity, Some(expected_size)).map_err(
            |error| {
                format!(
                    "Linux KVM compatibility-drift ready marker changed while publishing {}: {error}",
                    barrier.ready.display()
                )
            },
        )?;
        barrier.wait_for_continue(case)?;
        Ok(barrier)
    }

    fn wait_for_continue(&mut self, case: &str) -> Result<(), String> {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        loop {
            match fs::symlink_metadata(&self.proceed) {
                Ok(_) => {
                    let (file, identity) = read_continue_marker(&self.proceed, case).map_err(|error| {
                        format!(
                            "failed to read Linux KVM compatibility-drift continue marker {}: {error}",
                            self.proceed.display()
                        )
                    })?;
                    self.proceed_file = Some(file);
                    self.proceed_identity = Some(identity);
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
        if let Some(identity) = self.proceed_identity {
            if let Some(file) = self.proceed_file.as_ref() {
                remove_owned_marker(&self.proceed, file, identity);
            }
        }
        remove_owned_marker(&self.ready, &self.ready_file, self.ready_identity);
    }
}

fn read_continue_marker(path: &Path, case: &str) -> io::Result<(File, EntryIdentity)> {
    let before = fs::symlink_metadata(path)?;
    let expected_identity = verify_marker_metadata(&before, path, true)?;
    let mut file = open_marker_nofollow(path)?;
    let opened = file.metadata()?;
    if verify_marker_metadata(&opened, path, true)? != expected_identity {
        return Err(invalid_marker("continue marker was replaced while opening"));
    }

    let mut contents =
        Vec::with_capacity(usize::try_from(MAX_CASE_BYTES + 1).unwrap_or(usize::MAX));
    (&mut file)
        .take(MAX_CASE_BYTES + 1)
        .read_to_end(&mut contents)?;
    let bytes_read = u64::try_from(contents.len()).map_err(|error| {
        invalid_marker(format!(
            "continue marker length is not representable: {error}"
        ))
    })?;
    let after = file.metadata()?;
    if bytes_read > MAX_CASE_BYTES
        || after.len() != bytes_read
        || EntryIdentity::from_file(&file)? != expected_identity
    {
        return Err(invalid_marker("continue marker changed while it was read"));
    }
    let path_after = fs::symlink_metadata(path)?;
    if verify_marker_metadata(&path_after, path, false)? != expected_identity
        || path_after.len() != bytes_read
    {
        return Err(invalid_marker(
            "continue marker pathname changed after it was read",
        ));
    }

    let expected = format!("{case}\n");
    if contents != expected.as_bytes() {
        return Err(invalid_marker(format!(
            "continue marker did not authorize case {case}"
        )));
    }
    Ok((file, expected_identity))
}

fn open_marker_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    options.open(path)
}

fn verify_owned_marker(
    path: &Path,
    expected_identity: EntryIdentity,
    expected_size: Option<u64>,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let identity = verify_marker_metadata(&metadata, path, false)?;
    if identity != expected_identity {
        return Err(invalid_marker("marker identity changed"));
    }
    if let Some(expected_size) = expected_size {
        if metadata.len() != expected_size {
            return Err(invalid_marker(format!(
                "marker size changed (expected {expected_size}, observed {})",
                metadata.len()
            )));
        }
    }
    Ok(())
}

fn verify_marker_metadata(
    metadata: &Metadata,
    path: &Path,
    require_non_empty: bool,
) -> io::Result<EntryIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid_marker(format!(
            "marker must be a real regular file: {}",
            path.display()
        )));
    }
    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_user_id = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user_id || metadata.mode() & 0o777 != PRIVATE_FILE_MODE {
        return Err(invalid_marker(format!(
            "marker must be owned by UID {effective_user_id} with mode {PRIVATE_FILE_MODE:03o}: {}",
            path.display()
        )));
    }
    if (require_non_empty && metadata.len() == 0) || metadata.len() > MAX_CASE_BYTES {
        return Err(invalid_marker(format!(
            "marker has an invalid size: {}",
            path.display()
        )));
    }
    Ok(EntryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn remove_owned_marker(path: &Path, file: &File, expected_identity: EntryIdentity) {
    let Ok(handle_identity) = EntryIdentity::from_file(file) else {
        return;
    };
    if handle_identity != expected_identity {
        return;
    }
    let Ok(()) = verify_owned_marker(path, expected_identity, None) else {
        return;
    };
    let _ = fs::remove_file(path);
}

fn invalid_marker(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
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
    use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

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
            let staging = state.join("compatibility-drift-continue.staging");
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&staging)
                .expect("create staged continue marker");
            marker
                .write_all(b"manifest-replacement\n")
                .expect("write staged continue marker");
            marker.sync_all().expect("flush staged continue marker");
            fs::rename(staging, proceed).expect("publish continue marker atomically");
        });

        let barrier = CompatibilityDriftBarrier::wait(temporary.path(), "manifest-replacement")
            .expect("complete qualification handshake");
        writer.join().expect("join marker writer");
        drop(barrier);
        assert!(!temporary.path().join("run").join(READY_FILE).exists());
        assert!(!temporary.path().join("run").join(CONTINUE_FILE).exists());
    }

    #[test]
    fn continue_symlink_is_rejected_and_never_consumed() {
        let temporary = tempfile::tempdir().expect("create barrier fixture");
        let state = temporary.path().join("run");
        fs::create_dir(&state).expect("create state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect state directory");
        let proceed = state.join(CONTINUE_FILE);
        let decoy = state.join("decoy");
        fs::write(&decoy, b"manifest-replacement\n").expect("write decoy marker");
        fs::set_permissions(&decoy, fs::Permissions::from_mode(0o600))
            .expect("protect decoy marker");
        let writer = std::thread::spawn({
            let state = state.clone();
            let proceed = proceed.clone();
            let decoy = decoy.clone();
            move || {
                let ready = state.join(READY_FILE);
                while !ready.exists() {
                    std::thread::yield_now();
                }
                symlink(decoy, proceed).expect("publish symlink continue marker");
            }
        });

        let error = CompatibilityDriftBarrier::wait(temporary.path(), "manifest-replacement")
            .expect_err("a symlink continue marker must fail closed");
        writer.join().expect("join marker writer");
        assert!(error.contains("continue marker"));
        assert!(proceed.is_symlink());
        assert!(decoy.is_file());
        assert!(!state.join(READY_FILE).exists());
    }

    #[test]
    fn cleanup_preserves_a_replacement_after_a_valid_handshake() {
        let temporary = tempfile::tempdir().expect("create barrier fixture");
        let state = temporary.path().join("run");
        fs::create_dir(&state).expect("create state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect state directory");
        let proceed = state.join(CONTINUE_FILE);
        let writer = std::thread::spawn({
            let state = state.clone();
            let proceed = proceed.clone();
            move || {
                let ready = state.join(READY_FILE);
                while !ready.exists() {
                    std::thread::yield_now();
                }
                let staging = state.join("continue.staging");
                let mut marker = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&staging)
                    .expect("create staged continue marker");
                marker
                    .write_all(b"manifest-replacement\n")
                    .expect("write staged continue marker");
                marker.sync_all().expect("flush staged continue marker");
                fs::rename(staging, proceed).expect("publish continue marker");
            }
        });

        let barrier = CompatibilityDriftBarrier::wait(temporary.path(), "manifest-replacement")
            .expect("complete qualification handshake");
        writer.join().expect("join marker writer");
        fs::remove_file(&proceed).expect("remove consumed marker");
        fs::write(&proceed, b"replacement").expect("publish replacement marker");
        fs::set_permissions(&proceed, fs::Permissions::from_mode(0o600))
            .expect("protect replacement marker");
        drop(barrier);

        assert_eq!(
            fs::read(&proceed).expect("read replacement marker"),
            b"replacement"
        );
        assert!(!state.join(READY_FILE).exists());
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
