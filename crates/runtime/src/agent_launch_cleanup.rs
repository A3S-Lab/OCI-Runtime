use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::{CStr, CString};
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

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
/// destructors. Unix console output is reserved with an exclusive descriptor
/// retained until the authenticated Agent session passes its contract checks,
/// preventing the reserved inode from being recycled; cleanup is bound to that
/// inode. Recovery handoff paths remain absent-before-launch artifacts so an
/// existing handoff is never overwritten.
pub(crate) struct FailedAgentVmLaunchCleanup {
    console: PathBuf,
    #[cfg(unix)]
    console_identity: ConsoleIdentity,
    /// Keeps the reserved inode allocated until the Agent session is trusted.
    #[cfg(unix)]
    _console_file: File,
    recovery: Option<RecoveryHandoffPaths>,
    preserve: bool,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsoleIdentity {
    device: u64,
    inode: u64,
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

        #[cfg(unix)]
        let (console, console_identity, console_file) = reserve_console_path(console)?;
        #[cfg(not(unix))]
        let console = console.to_path_buf();

        Ok(Self {
            console,
            #[cfg(unix)]
            console_identity,
            #[cfg(unix)]
            _console_file: console_file,
            recovery,
            preserve: false,
        })
    }

    #[cfg(unix)]
    pub(crate) fn console_identity(&self) -> (u64, u64) {
        (self.console_identity.device, self.console_identity.inode)
    }

    pub(crate) fn preserve(mut self) {
        self.preserve = true;
    }

    fn remove(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        #[cfg(unix)]
        remove_bound_file_if_present(
            &self.console,
            self.console_identity,
            "VM console",
            &mut errors,
        );
        #[cfg(not(unix))]
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

#[cfg(unix)]
fn reserve_console_path(path: &Path) -> Result<(PathBuf, ConsoleIdentity, File), String> {
    let (parent_path, name) = split_entry(path).map_err(|error| {
        format!(
            "failed to prepare VM console {} for exclusive reservation: {error}",
            path.display()
        )
    })?;
    let parent = open_directory_nofollow(parent_path).map_err(|error| {
        format!(
            "failed to pin VM console directory {}: {error}",
            parent_path.display()
        )
    })?;
    verify_parent_binding(&parent, parent_path).map_err(|error| {
        format!(
            "VM console directory changed while it was being pinned: {}: {error}",
            parent_path.display()
        )
    })?;

    let file = open_relative_file(
        &parent,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0o600,
    )
    .map_err(|error| {
        format!(
            "failed to reserve VM console {} exclusively: {error}",
            path.display()
        )
    })?;
    let identity = match verify_console_file(&parent, &name, &file, path, None) {
        Ok(identity) => identity,
        Err(error) => {
            let opened_identity = identity_from_file(&file).ok();
            if let Some(opened_identity) = opened_identity {
                let _ = remove_bound_file_at(&parent, &name, opened_identity, path);
            }
            return Err(format!(
                "reserved VM console did not remain a private regular file: {}: {error}",
                path.display()
            ));
        }
    };
    if let Err(error) = verify_parent_binding(&parent, parent_path) {
        let _ = remove_bound_file_at(&parent, &name, identity, path);
        return Err(format!(
            "VM console directory changed after reservation: {}: {error}",
            parent_path.display()
        ));
    }
    Ok((path.to_path_buf(), identity, file))
}

#[cfg(unix)]
fn remove_bound_file_if_present(
    path: &Path,
    expected: ConsoleIdentity,
    label: &str,
    errors: &mut Vec<String>,
) {
    match remove_bound_file(path, expected) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove failed-launch {label} {} safely: {error}",
            path.display()
        )),
    }
}

#[cfg(unix)]
fn remove_bound_file(path: &Path, expected: ConsoleIdentity) -> io::Result<()> {
    let (parent_path, name) = split_entry(path)?;
    let parent = open_directory_nofollow(parent_path)?;
    verify_parent_binding(&parent, parent_path)?;
    let stat = match fstatat(&parent, &name) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let observed = identity_from_stat(&stat);
    if observed != expected || !is_regular_stat(&stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM console was replaced after launch reservation",
        ));
    }
    remove_bound_file_at(&parent, &name, expected, path)
}

#[cfg(unix)]
fn remove_bound_file_at(
    parent: &File,
    name: &CStr,
    expected: ConsoleIdentity,
    path: &Path,
) -> io::Result<()> {
    let stat = fstatat(parent, name)?;
    if identity_from_stat(&stat) != expected || !is_regular_stat(&stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "VM console identity changed before cleanup: {}",
                path.display()
            ),
        ));
    }
    // SAFETY: `parent` is a live directory descriptor and `name` names one
    // bounded entry. The identity was checked immediately before unlinking.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn split_entry(path: &Path) -> io::Result<(&Path, CString)> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path has no file name: {}", path.display()),
        )
    })?;
    let name = CString::new(name.as_bytes()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path file name contains NUL: {error}"),
        )
    })?;
    Ok((parent, name))
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    options.open(path)
}

#[cfg(unix)]
fn open_relative_file(parent: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: `parent` is a live directory descriptor and `name` is a bounded
    // NUL-terminated component. The caller controls the explicit open flags.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by openat and ownership is transferred here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `file` owns a live descriptor and `stat` is writable storage for
    // the complete libc structure.
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn fstatat(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `parent` is a live directory descriptor, `name` is bounded, and
    // `stat` points to writable storage.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn identity_from_file(file: &File) -> io::Result<ConsoleIdentity> {
    fstat(file).map(|stat| identity_from_stat(&stat))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn identity_from_stat(stat: &libc::stat) -> ConsoleIdentity {
    ConsoleIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    }
}

#[cfg(unix)]
fn verify_parent_binding(parent: &File, path: &Path) -> io::Result<ConsoleIdentity> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM console parent is not a real directory",
        ));
    }
    let identity = identity_from_file(parent)?;
    if identity.device != metadata.dev() || identity.inode != metadata.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM console parent identity changed",
        ));
    }
    Ok(identity)
}

#[cfg(unix)]
fn verify_console_file(
    parent: &File,
    name: &CStr,
    file: &File,
    path: &Path,
    expected: Option<ConsoleIdentity>,
) -> io::Result<ConsoleIdentity> {
    let opened_stat = fstat(file)?;
    let opened = identity_from_stat(&opened_stat);
    if expected.is_some_and(|expected| expected != opened) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM console identity does not match the host reservation",
        ));
    }
    if !is_private_regular_stat(&opened_stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "VM console is not a private regular file: {}",
                path.display()
            ),
        ));
    }
    let named_stat = fstatat(parent, name)?;
    if identity_from_stat(&named_stat) != opened || !is_private_regular_stat(&named_stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VM console pathname does not refer to the opened file",
        ));
    }
    Ok(opened)
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn is_private_regular_stat(stat: &libc::stat) -> bool {
    let mode = stat.st_mode as u32;
    is_regular_stat(stat) && mode & 0o777 == 0o600
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn is_regular_stat(stat: &libc::stat) -> bool {
    stat.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFREG as u32
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
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

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

    #[cfg(unix)]
    #[test]
    fn unix_console_reservation_is_private_and_identity_bound() {
        let temporary = tempfile::tempdir().expect("create console reservation fixture");
        let runtime_share = temporary.path().join("share");
        std::fs::create_dir(&runtime_share).expect("create runtime share");
        let console = temporary.path().join("console.log");
        let endpoint = AgentVsockEndpoint::generate().expect("generate console endpoint");
        let cleanup = FailedAgentVmLaunchCleanup::new(&console, &runtime_share, &endpoint, None)
            .expect("reserve console");

        let metadata = std::fs::symlink_metadata(&console).expect("inspect reserved console");
        assert_eq!(cleanup.console_identity(), (metadata.dev(), metadata.ino()));
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        drop(cleanup);
        assert!(!console.exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_connection_never_removes_a_replaced_console() {
        let temporary = tempfile::tempdir().expect("create console replacement fixture");
        let runtime_share = temporary.path().join("share");
        std::fs::create_dir(&runtime_share).expect("create runtime share");
        let console = temporary.path().join("console.log");
        let endpoint = AgentVsockEndpoint::generate().expect("generate console endpoint");
        let cleanup = FailedAgentVmLaunchCleanup::new(&console, &runtime_share, &endpoint, None)
            .expect("reserve console");

        std::fs::remove_file(&console).expect("remove reserved console name");
        std::fs::write(&console, b"replacement").expect("stage replacement console");

        drop(cleanup);

        assert_eq!(
            std::fs::read(&console).expect("read replacement console"),
            b"replacement"
        );
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
