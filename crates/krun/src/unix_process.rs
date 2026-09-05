use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
#[cfg(target_os = "macos")]
const PRIVATE_TMP_ROOT: &str = "/private/tmp";
#[cfg(target_os = "linux")]
const PRIVATE_TMP_ROOT: &str = "/tmp";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;
const PRIVATE_CONSOLE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsoleIdentity {
    device: u64,
    inode: u64,
}

impl ConsoleIdentity {
    pub(crate) const fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        }
    }
}

/// Console output pinned to the file opened by this process.
///
/// libkrun opens the supplied console path only when VM entry begins. Passing
/// the kernel descriptor namespace keeps that later open bound to this file
/// even if the original pathname is unlinked or replaced in the meantime.
pub(crate) struct PreparedConsoleOutput {
    file: File,
}

impl PreparedConsoleOutput {
    pub(crate) fn pinned_path(&self) -> PathBuf {
        #[cfg(target_os = "linux")]
        let root = "/proc/self/fd";
        #[cfg(target_os = "macos")]
        let root = "/dev/fd";
        Path::new(root).join(self.file.as_raw_fd().to_string())
    }
}

pub(crate) struct WorkerExit {
    pub(crate) status: ExitStatus,
    pub(crate) timed_out: bool,
}

#[cfg(target_os = "macos")]
pub(crate) fn resolve_console(console: &Path) -> Result<PathBuf, String> {
    resolve_console_with_identity(console, None)
}

pub(crate) fn resolve_console_with_identity(
    console: &Path,
    expected: Option<ConsoleIdentity>,
) -> Result<PathBuf, String> {
    let console = resolve_console_path(console, expected.is_none())?;
    match expected {
        Some(expected) => verify_console_path(&console, expected)?,
        None => require_absent(&console, "console output")?,
    }
    Ok(console)
}

pub(crate) fn prepare_console_output(
    console: &Path,
    expected: Option<ConsoleIdentity>,
) -> Result<PreparedConsoleOutput, String> {
    let console = resolve_console_path(console, expected.is_none())?;
    let (parent_path, name) = split_entry(&console).map_err(|error| {
        format!(
            "failed to prepare console output {}: {error}",
            console.display()
        )
    })?;
    let parent = open_directory_nofollow(parent_path).map_err(|error| {
        format!(
            "failed to pin console directory {}: {error}",
            parent_path.display()
        )
    })?;
    verify_parent_binding(&parent, parent_path).map_err(|error| {
        format!(
            "console directory changed while it was being pinned: {}: {error}",
            parent_path.display()
        )
    })?;

    let mut flags = libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if expected.is_none() {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    let file =
        open_relative_file(&parent, &name, flags, PRIVATE_CONSOLE_MODE).map_err(|error| {
            let action = if expected.is_some() {
                "open reserved console output"
            } else {
                "create console output exclusively"
            };
            format!("failed to {action} {}: {error}", console.display())
        })?;
    let opened_identity = identity_from_file(&file).map_err(|error| {
        format!(
            "failed to identify opened console output {}: {error}",
            console.display()
        )
    })?;
    if let Err(error) = verify_console_file(&parent, &name, &file, &console, expected) {
        if expected.is_none() {
            let _ = remove_bound_file_at(&parent, &name, opened_identity, &console);
        }
        return Err(format!(
            "console output failed its descriptor binding: {}: {error}",
            console.display()
        ));
    }
    if let Err(error) = verify_parent_binding(&parent, parent_path) {
        if expected.is_none() {
            let _ = remove_bound_file_at(&parent, &name, opened_identity, &console);
        }
        return Err(format!(
            "console directory changed after output was opened: {}: {error}",
            parent_path.display()
        ));
    }

    Ok(PreparedConsoleOutput { file })
}

fn resolve_console_path(console: &Path, create_parent: bool) -> Result<PathBuf, String> {
    let file_name = console
        .file_name()
        .ok_or_else(|| format!("console path has no file name: {}", console.display()))?;
    let parent = console
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if create_parent {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create console directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let parent = parent.canonicalize().map_err(|error| {
        format!(
            "failed to resolve console directory {}: {error}",
            parent.display()
        )
    })?;
    Ok(parent.join(file_name))
}

fn verify_console_path(console: &Path, expected: ConsoleIdentity) -> Result<(), String> {
    let metadata = fs::symlink_metadata(console).map_err(|error| {
        format!(
            "failed to inspect reserved console output {}: {error}",
            console.display()
        )
    })?;
    let observed = ConsoleIdentity::new(metadata.dev(), metadata.ino());
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o777 != PRIVATE_CONSOLE_MODE
        || observed != expected
    {
        return Err(format!(
            "console output does not match the host reservation: {}",
            console.display()
        ));
    }
    Ok(())
}

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

fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    options.open(path)
}

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

fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `file` owns a live descriptor and `stat` points to writable
    // storage for the complete libc structure.
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

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

fn identity_from_file(file: &File) -> io::Result<ConsoleIdentity> {
    fstat(file).map(|stat| ConsoleIdentity::from_stat(&stat))
}

fn verify_parent_binding(parent: &File, path: &Path) -> io::Result<ConsoleIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "console parent is not a real directory",
        ));
    }
    let identity = identity_from_file(parent)?;
    if identity != ConsoleIdentity::new(metadata.dev(), metadata.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "console parent identity changed",
        ));
    }
    Ok(identity)
}

fn verify_console_file(
    parent: &File,
    name: &CStr,
    file: &File,
    path: &Path,
    expected: Option<ConsoleIdentity>,
) -> io::Result<ConsoleIdentity> {
    let opened_stat = fstat(file)?;
    let opened = ConsoleIdentity::from_stat(&opened_stat);
    if expected.is_some_and(|expected| expected != opened) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "console identity does not match the host reservation",
        ));
    }
    if !is_private_regular_stat(&opened_stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("console is not a private regular file: {}", path.display()),
        ));
    }
    let named_stat = fstatat(parent, name)?;
    if ConsoleIdentity::from_stat(&named_stat) != opened || !is_private_regular_stat(&named_stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "console pathname does not refer to the opened file",
        ));
    }
    Ok(opened)
}

fn remove_bound_file_at(
    parent: &File,
    name: &CStr,
    expected: ConsoleIdentity,
    path: &Path,
) -> io::Result<()> {
    let stat = fstatat(parent, name)?;
    if ConsoleIdentity::from_stat(&stat) != expected || !is_regular_stat(&stat) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "console identity changed before cleanup: {}",
                path.display()
            ),
        ));
    }
    // SAFETY: `parent` is a live directory descriptor and `name` is one
    // bounded component whose identity was just verified.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn is_private_regular_stat(stat: &libc::stat) -> bool {
    let mode = stat.st_mode as u32;
    is_regular_stat(stat) && mode & 0o777 == PRIVATE_CONSOLE_MODE
}

#[allow(clippy::unnecessary_cast)]
fn is_regular_stat(stat: &libc::stat) -> bool {
    stat.st_mode as u32 & libc::S_IFMT as u32 == libc::S_IFREG as u32
}

pub(crate) fn resolve_agent_socket(socket: &Path) -> Result<PathBuf, String> {
    if !socket.is_absolute() {
        return Err(format!(
            "agent socket path must be absolute: {}",
            socket.display()
        ));
    }
    let file_name = socket
        .file_name()
        .ok_or_else(|| format!("agent socket path has no file name: {}", socket.display()))?;
    let parent = socket
        .parent()
        .ok_or_else(|| format!("agent socket path has no parent: {}", socket.display()))?
        .canonicalize()
        .map_err(|error| {
            format!(
                "failed to resolve agent socket directory {}: {error}",
                socket.display()
            )
        })?;
    let private_tmp_root = Path::new(PRIVATE_TMP_ROOT)
        .canonicalize()
        .map_err(|error| {
            format!("failed to resolve private temporary root {PRIVATE_TMP_ROOT}: {error}")
        })?;
    if parent.parent() != Some(private_tmp_root.as_path()) {
        return Err(format!(
            "agent socket directory must be a direct child of {PRIVATE_TMP_ROOT}: {}",
            parent.display()
        ));
    }
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|error| {
        format!(
            "failed to inspect agent socket directory {}: {error}",
            parent.display()
        )
    })?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(format!(
            "agent socket directory must be a non-symlink directory with mode \
             {PRIVATE_DIRECTORY_MODE:03o}: {}",
            parent.display()
        ));
    }

    let socket = parent.join(file_name);
    let socket_metadata = fs::symlink_metadata(&socket).map_err(|error| {
        format!(
            "failed to inspect agent socket {}: {error}",
            socket.display()
        )
    })?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.file_type().is_symlink()
        || socket_metadata.mode() & 0o777 != PRIVATE_SOCKET_MODE
    {
        return Err(format!(
            "agent socket must be a non-symlink Unix socket with mode \
             {PRIVATE_SOCKET_MODE:03o}: {}",
            socket.display()
        ));
    }

    // SAFETY: `geteuid` has no pointer arguments or failure return.
    let effective_user_id = unsafe { libc::geteuid() };
    if parent_metadata.uid() != effective_user_id || socket_metadata.uid() != effective_user_id {
        return Err(format!(
            "agent socket and its private directory must be owned by effective UID \
             {effective_user_id}: {}",
            socket.display()
        ));
    }
    Ok(socket)
}

pub(crate) fn require_absent(path: &Path, description: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "refusing to overwrite existing {description}: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )),
    }
}

pub(crate) fn wait_for_worker(child: &mut Child, timeout: Duration) -> io::Result<WorkerExit> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(WorkerExit {
                status,
                timed_out: false,
            });
        }
        if Instant::now() >= deadline {
            return match child.kill() {
                Ok(()) => child.wait().map(|status| WorkerExit {
                    status,
                    timed_out: true,
                }),
                Err(kill_error) => match child.try_wait()? {
                    Some(status) => Ok(WorkerExit {
                        status,
                        timed_out: false,
                    }),
                    None => Err(kill_error),
                },
            };
        }
        thread::sleep(WORKER_POLL_INTERVAL);
    }
}

pub(crate) fn terminate_and_wait(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    match child.kill() {
        Ok(()) => child.wait(),
        Err(kill_error) => child.try_wait()?.ok_or(kill_error),
    }
}

pub(crate) fn read_bounded_worker_output(mut input: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    input.by_ref().take(limit + 1).read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("utility-VM worker output exceeds {limit} bytes"),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::{prepare_console_output, wait_for_worker, ConsoleIdentity, PRIVATE_CONSOLE_MODE};

    #[test]
    fn prepared_console_is_private_and_uses_the_pinned_descriptor() {
        let temporary = tempfile::tempdir().expect("create console fixture");
        let console = temporary.path().join("console.log");

        let prepared = prepare_console_output(&console, None).expect("prepare console");
        fs::write(prepared.pinned_path(), b"console output").expect("write pinned console");

        let metadata = fs::symlink_metadata(&console).expect("inspect console");
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, PRIVATE_CONSOLE_MODE);
        assert_eq!(fs::read(&console).expect("read console"), b"console output");
    }

    #[test]
    fn prepared_console_opens_the_expected_host_reservation() {
        let temporary = tempfile::tempdir().expect("create reservation fixture");
        let console = temporary.path().join("console.log");
        fs::write(&console, b"").expect("reserve console");
        fs::set_permissions(&console, fs::Permissions::from_mode(PRIVATE_CONSOLE_MODE))
            .expect("protect console");
        let metadata = fs::metadata(&console).expect("identify console");
        let expected = ConsoleIdentity::new(metadata.dev(), metadata.ino());

        let prepared = prepare_console_output(&console, Some(expected)).expect("open reservation");
        fs::write(prepared.pinned_path(), b"guest console").expect("write pinned console");

        assert_eq!(fs::read(&console).expect("read console"), b"guest console");
    }

    #[test]
    fn prepared_console_rejects_a_replaced_host_reservation() {
        let temporary = tempfile::tempdir().expect("create reservation replacement fixture");
        let console = temporary.path().join("console.log");
        fs::write(&console, b"").expect("reserve console");
        fs::set_permissions(&console, fs::Permissions::from_mode(PRIVATE_CONSOLE_MODE))
            .expect("protect reserved console");
        let reservation = fs::OpenOptions::new()
            .write(true)
            .open(&console)
            .expect("retain reserved console");
        let metadata = reservation
            .metadata()
            .expect("identify retained console reservation");
        let expected = ConsoleIdentity::new(metadata.dev(), metadata.ino());
        fs::remove_file(&console).expect("remove reserved console");
        fs::write(&console, b"replacement").expect("write replacement console");
        fs::set_permissions(&console, fs::Permissions::from_mode(PRIVATE_CONSOLE_MODE))
            .expect("protect replacement console");
        let replacement = fs::metadata(&console).expect("identify replacement console");
        assert_ne!(
            expected,
            ConsoleIdentity::new(replacement.dev(), replacement.ino())
        );

        let error = prepare_console_output(&console, Some(expected))
            .err()
            .expect("replacement must be rejected");

        assert!(error.contains("host reservation"));
        assert_eq!(
            fs::read(&console).expect("read replacement console"),
            b"replacement"
        );
        drop(reservation);
    }

    #[test]
    fn prepared_console_refuses_an_unclaimed_existing_file() {
        let temporary = tempfile::tempdir().expect("create incumbent fixture");
        let console = temporary.path().join("console.log");
        fs::write(&console, b"incumbent").expect("write incumbent");

        let error = prepare_console_output(&console, None)
            .err()
            .expect("incumbent must be rejected");

        assert!(error.contains("exclusively"));
        assert_eq!(fs::read(&console).expect("read incumbent"), b"incumbent");
    }

    #[test]
    fn expected_console_never_recreates_a_missing_host_directory() {
        let temporary = tempfile::tempdir().expect("create missing directory fixture");
        let parent = temporary.path().join("missing");
        let console = parent.join("console.log");

        let error = prepare_console_output(&console, Some(ConsoleIdentity::new(7, 11)))
            .err()
            .expect("missing host reservation must be rejected");

        assert!(error.contains("failed to resolve console directory"));
        assert!(!parent.exists());
    }

    #[test]
    fn pinned_console_ignores_a_later_path_replacement() {
        let temporary = tempfile::tempdir().expect("create replacement fixture");
        let console = temporary.path().join("console.log");
        let prepared = prepare_console_output(&console, None).expect("prepare console");
        // Keep an independent read-only handle to the original inode. The
        // descriptor retained by `PreparedConsoleOutput` is intentionally
        // write-only, and macOS rejects reopening its `/dev/fd` path for read.
        let mut original = fs::OpenOptions::new()
            .read(true)
            .open(&console)
            .expect("open original console for verification");
        fs::remove_file(&console).expect("unlink prepared console");
        fs::write(&console, b"replacement").expect("write replacement");

        fs::write(prepared.pinned_path(), b"original inode").expect("write pinned console");

        let mut original_contents = Vec::new();
        original
            .read_to_end(&mut original_contents)
            .expect("read original console through retained handle");

        assert_eq!(
            fs::read(&console).expect("read replacement"),
            b"replacement"
        );
        assert_eq!(original_contents, b"original inode");
    }

    #[test]
    fn timed_out_worker_is_killed_and_reaped() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 10"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test worker must start");

        let result =
            wait_for_worker(&mut child, Duration::from_millis(10)).expect("worker must be reaped");
        assert!(result.timed_out);
        assert!(child
            .try_wait()
            .expect("reaped child must be queryable")
            .is_some());
    }
}
