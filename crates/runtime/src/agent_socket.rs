use std::fs::{self, DirBuilder};
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::net::{UnixListener, UnixStream};

#[cfg(target_os = "macos")]
pub(crate) const PRIVATE_TMP_ROOT: &str = "/private/tmp";
#[cfg(target_os = "linux")]
pub(crate) const PRIVATE_TMP_ROOT: &str = "/tmp";
const SOCKET_FILE_NAME: &str = "agent.sock";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;

/// Exclusive Unix endpoint for one libkrun guest-agent bridge.
///
/// The endpoint lives in a random runtime-owned directory below the platform's
/// private temporary root. The directory and socket are removed when the
/// listener is consumed or dropped.
#[derive(Debug)]
pub struct UnixAgentSocketListener {
    endpoint: AgentVsockEndpoint,
    directory: PathBuf,
    socket_path: PathBuf,
    listener: UnixListener,
    cleaned: bool,
}

impl UnixAgentSocketListener {
    /// Bind a private Unix socket for one generated guest-agent endpoint.
    pub fn bind(endpoint: AgentVsockEndpoint) -> Result<Self> {
        let directory = Path::new(PRIVATE_TMP_ROOT).join(endpoint.pipe_name());
        let socket_path = directory.join(SOCKET_FILE_NAME);
        let mut directory_builder = DirBuilder::new();
        directory_builder.mode(PRIVATE_DIRECTORY_MODE);
        directory_builder.create(&directory).map_err(|error| {
            endpoint_setup_error(
                collision_code(&error),
                "create-agent-socket-directory",
                &directory,
                error,
            )
        })?;
        let mut cleanup_guard = EndpointCleanupGuard::new(&socket_path, &directory);

        if let Err(error) = fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        ) {
            let _ = fs::remove_dir(&directory);
            return Err(endpoint_setup_error(
                ErrorCode::Internal,
                "protect-agent-socket-directory",
                &directory,
                error,
            ));
        }
        if let Err(error) =
            verify_owned_entry(&directory, EntryKind::Directory, PRIVATE_DIRECTORY_MODE)
        {
            let _ = fs::remove_dir(&directory);
            return Err(error);
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                let _ = cleanup_endpoint_paths(&socket_path, &directory);
                return Err(endpoint_setup_error(
                    collision_code(&error),
                    "bind-agent-socket",
                    &socket_path,
                    error,
                ));
            }
        };
        if let Err(error) = fs::set_permissions(
            &socket_path,
            fs::Permissions::from_mode(PRIVATE_SOCKET_MODE),
        ) {
            let _ = cleanup_endpoint_paths(&socket_path, &directory);
            return Err(endpoint_setup_error(
                ErrorCode::Internal,
                "protect-agent-socket",
                &socket_path,
                error,
            ));
        }
        if let Err(error) = verify_owned_entry(&socket_path, EntryKind::Socket, PRIVATE_SOCKET_MODE)
        {
            let _ = cleanup_endpoint_paths(&socket_path, &directory);
            return Err(error);
        }

        let listener = Self {
            endpoint,
            directory,
            socket_path,
            listener,
            cleaned: false,
        };
        cleanup_guard.disarm();
        Ok(listener)
    }

    /// Borrow the portable endpoint identifier mapped to the fixed guest port.
    #[must_use]
    pub fn endpoint(&self) -> &AgentVsockEndpoint {
        &self.endpoint
    }

    /// Borrow the exact short path passed to `krun_add_vsock_port2`.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Borrow the private directory for cleanup verification.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Accept only a Unix peer whose parent is the previously spawned shim.
    ///
    /// libkrun enters the VM in a direct worker child because
    /// `krun_start_enter` takes over that process. The kernel-reported peer PID
    /// and its direct parent are both verified before the session token is
    /// disclosed.
    pub async fn accept_from_child(
        mut self,
        expected_parent_process_id: u32,
    ) -> Result<(UnixStream, u32)> {
        if expected_parent_process_id == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "expected guest-agent bridge parent process ID must be nonzero",
            )
            .for_operation("accept-agent-socket"));
        }

        let (stream, _) = self.listener.accept().await.map_err(|error| {
            Error::new(
                ErrorCode::Unavailable,
                format!(
                    "failed to accept guest-agent bridge on {}: {error}",
                    self.socket_path.display()
                ),
            )
            .for_operation("accept-agent-socket")
            .retryable(true)
        })?;
        let peer_process_id = unix_peer_process_id(&stream)?;
        let parent_process_id = process_parent_id(peer_process_id)?;
        if parent_process_id != expected_parent_process_id {
            return Err(Error::new(
                ErrorCode::PermissionDenied,
                format!(
                    "guest-agent socket peer PID {peer_process_id} has parent PID \
                     {parent_process_id}, not expected libkrun shim PID \
                     {expected_parent_process_id}"
                ),
            )
            .for_operation("accept-agent-socket"));
        }

        self.cleanup().map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to remove consumed guest-agent endpoint {}: {error}",
                    self.socket_path.display()
                ),
            )
            .for_operation("cleanup-agent-socket")
        })?;
        Ok((stream, peer_process_id))
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        cleanup_endpoint_paths(&self.socket_path, &self.directory)?;
        self.cleaned = true;
        Ok(())
    }
}

struct EndpointCleanupGuard {
    socket_path: PathBuf,
    directory: PathBuf,
    armed: bool,
}

impl EndpointCleanupGuard {
    fn new(socket_path: &Path, directory: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
            directory: directory.to_path_buf(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for EndpointCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = cleanup_endpoint_paths(&self.socket_path, &self.directory);
        }
    }
}

impl Drop for UnixAgentSocketListener {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    Socket,
}

fn verify_owned_entry(path: &Path, kind: EntryKind, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        endpoint_setup_error(
            ErrorCode::Internal,
            "inspect-agent-socket-entry",
            path,
            error,
        )
    })?;
    let kind_matches = match kind {
        EntryKind::Directory => metadata.file_type().is_dir(),
        EntryKind::Socket => metadata.file_type().is_socket(),
    };
    if !kind_matches || metadata.file_type().is_symlink() {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "guest-agent endpoint has an unexpected entry type: {}",
                path.display()
            ),
        )
        .for_operation("verify-agent-socket-entry"));
    }
    if metadata.mode() & 0o777 != mode {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "guest-agent endpoint {} has mode {:03o}, expected {mode:03o}",
                path.display(),
                metadata.mode() & 0o777
            ),
        )
        .for_operation("verify-agent-socket-entry"));
    }
    // SAFETY: `geteuid` has no pointer arguments or failure return.
    let effective_user_id = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user_id {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "guest-agent endpoint {} is owned by UID {}, expected {}",
                path.display(),
                metadata.uid(),
                effective_user_id
            ),
        )
        .for_operation("verify-agent-socket-entry"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn unix_peer_process_id(stream: &UnixStream) -> Result<u32> {
    let mut peer_process_id: libc::pid_t = 0;
    let mut value_length =
        libc::socklen_t::try_from(size_of::<libc::pid_t>()).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to represent LOCAL_PEERPID value size: {error}"),
            )
            .for_operation("identify-agent-socket-peer")
        })?;
    // SAFETY: the stream owns a connected Unix descriptor and both output
    // pointers remain valid for the duration of `getsockopt`.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut peer_process_id as *mut libc::pid_t).cast(),
            &mut value_length,
        )
    };
    if status != 0 {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "failed to identify guest-agent socket peer: {}",
                io::Error::last_os_error()
            ),
        )
        .for_operation("identify-agent-socket-peer"));
    }
    if usize::try_from(value_length).ok() != Some(size_of::<libc::pid_t>()) {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "LOCAL_PEERPID returned {value_length} bytes, expected {}",
                size_of::<libc::pid_t>()
            ),
        )
        .for_operation("identify-agent-socket-peer"));
    }
    u32::try_from(peer_process_id).map_err(|_| {
        Error::new(
            ErrorCode::Internal,
            format!("LOCAL_PEERPID returned invalid process ID {peer_process_id}"),
        )
        .for_operation("identify-agent-socket-peer")
    })
}

#[cfg(target_os = "macos")]
fn process_parent_id(process_id: u32) -> Result<u32> {
    let process_id = libc::pid_t::try_from(process_id).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to represent guest-agent socket peer PID: {error}"),
        )
        .for_operation("verify-agent-socket-parent")
    })?;
    let buffer_size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to represent proc_bsdinfo size: {error}"),
        )
        .for_operation("verify-agent-socket-parent")
    })?;
    let mut process_info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `process_info` points to an allocation of exactly
    // `buffer_size` bytes. A complete return initializes every field before
    // `assume_init` below.
    let bytes_read = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTBSDINFO,
            0,
            process_info.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    if bytes_read != buffer_size {
        let detail = if bytes_read <= 0 {
            io::Error::last_os_error().to_string()
        } else {
            format!("returned {bytes_read} bytes, expected {buffer_size}")
        };
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!("failed to inspect guest-agent socket peer PID {process_id}: {detail}"),
        )
        .for_operation("verify-agent-socket-parent"));
    }
    // SAFETY: the kernel reported that the complete structure was written.
    let process_info = unsafe { process_info.assume_init() };
    if process_info.pbi_pid != u32::try_from(process_id).unwrap_or_default() {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "proc_pidinfo returned PID {} for guest-agent socket peer PID {process_id}",
                process_info.pbi_pid
            ),
        )
        .for_operation("verify-agent-socket-parent"));
    }
    Ok(process_info.pbi_ppid)
}

#[cfg(target_os = "linux")]
fn unix_peer_process_id(stream: &UnixStream) -> Result<u32> {
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut value_length =
        libc::socklen_t::try_from(size_of::<libc::ucred>()).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to represent SO_PEERCRED value size: {error}"),
            )
            .for_operation("identify-agent-socket-peer")
        })?;
    // SAFETY: the stream owns a connected Unix descriptor and the output
    // storage is valid for one ucred structure.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut value_length,
        )
    };
    if status != 0 {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "failed to identify guest-agent socket peer: {}",
                io::Error::last_os_error()
            ),
        )
        .for_operation("identify-agent-socket-peer"));
    }
    if usize::try_from(value_length).ok() != Some(size_of::<libc::ucred>()) {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "SO_PEERCRED returned {value_length} bytes, expected {}",
                size_of::<libc::ucred>()
            ),
        )
        .for_operation("identify-agent-socket-peer"));
    }
    // SAFETY: getsockopt reported the complete structure size.
    let credentials = unsafe { credentials.assume_init() };
    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_user_id = unsafe { libc::geteuid() };
    if credentials.uid != effective_user_id {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "guest-agent socket peer UID {} does not match runtime UID {effective_user_id}",
                credentials.uid
            ),
        )
        .for_operation("identify-agent-socket-peer"));
    }
    u32::try_from(credentials.pid).map_err(|_| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "SO_PEERCRED returned invalid process ID {}",
                credentials.pid
            ),
        )
        .for_operation("identify-agent-socket-peer")
    })
}

#[cfg(target_os = "linux")]
fn process_parent_id(process_id: u32) -> Result<u32> {
    let status_path = PathBuf::from(format!("/proc/{process_id}/status"));
    let encoded = fs::read_to_string(&status_path).map_err(|error| {
        Error::new(
            ErrorCode::PermissionDenied,
            format!("failed to inspect guest-agent socket peer PID {process_id}: {error}"),
        )
        .for_operation("verify-agent-socket-parent")
    })?;
    let mut observed_process = None;
    let mut observed_parent = None;
    for line in encoded.lines() {
        if let Some(value) = line.strip_prefix("Pid:") {
            observed_process = value.trim().parse::<u32>().ok();
        } else if let Some(value) = line.strip_prefix("PPid:") {
            observed_parent = value.trim().parse::<u32>().ok();
        }
    }
    if observed_process != Some(process_id) {
        return Err(Error::new(
            ErrorCode::PermissionDenied,
            format!(
                "Linux procfs returned PID {observed_process:?} for guest-agent peer PID {process_id}"
            ),
        )
        .for_operation("verify-agent-socket-parent"));
    }
    observed_parent.ok_or_else(|| {
        Error::new(
            ErrorCode::PermissionDenied,
            format!("Linux procfs omitted the parent of guest-agent peer PID {process_id}"),
        )
        .for_operation("verify-agent-socket-parent")
    })
}

#[cfg(target_os = "macos")]
pub type MacosAgentSocketListener = UnixAgentSocketListener;

#[cfg(target_os = "linux")]
pub type LinuxAgentSocketListener = UnixAgentSocketListener;

fn cleanup_endpoint_paths(socket_path: &Path, directory: &Path) -> io::Result<()> {
    let socket_result = match fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    let directory_result = match fs::remove_dir(directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    match (socket_result, directory_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(socket_error), Ok(())) => Err(socket_error),
        (Ok(()), Err(directory_error)) => Err(directory_error),
        (Err(socket_error), Err(directory_error)) => Err(io::Error::other(format!(
            "socket removal failed: {socket_error}; directory removal failed: {directory_error}"
        ))),
    }
}

fn collision_code(error: &io::Error) -> ErrorCode {
    if error.kind() == io::ErrorKind::AlreadyExists {
        ErrorCode::Conflict
    } else {
        ErrorCode::Internal
    }
}

fn endpoint_setup_error(
    code: ErrorCode,
    operation: &'static str,
    path: &Path,
    error: io::Error,
) -> Error {
    Error::new(
        code,
        format!("{operation} failed for {}: {error}", path.display()),
    )
    .for_operation(operation)
}

#[cfg(test)]
mod tests;
