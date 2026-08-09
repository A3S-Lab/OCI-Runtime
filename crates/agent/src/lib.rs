//! Linux guest bootstrap for the authenticated OCI agent protocol.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
use a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_TAG;
use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, GuestAgentService, SessionToken, AGENT_RUNTIME_SHARE_ENV,
    AGENT_RUNTIME_SHARE_GUEST_ROOT, AGENT_SESSION_TOKEN_DIRECTORY_PREFIX, AGENT_SESSION_TOKEN_ENV,
    AGENT_SESSION_TOKEN_FILE_ENV, AGENT_SESSION_TOKEN_FILE_NAME,
};
#[cfg(target_os = "linux")]
use a3s_oci_agent_protocol::{AgentRecoveryRecord, AgentRecoveryReport, AGENT_RECOVERY_REPORT_ENV};
#[cfg(any(target_os = "linux", test))]
use a3s_oci_agent_protocol::{
    AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_RECOVERY_REPORT_FILE_NAME,
};
use a3s_oci_sdk::{async_trait, Error, ErrorCode, Result};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod executor;
#[cfg(target_os = "linux")]
mod vsock;

#[cfg(target_os = "linux")]
pub use executor::{InheritedDescriptorPlan, LinuxExecutor, LinuxExecutorTombstone};

/// Verify that the Linux kernel supports PID-reuse-safe pidfd signaling.
#[cfg(target_os = "linux")]
pub fn verify_linux_pidfd_support() -> Result<()> {
    executor::verify_pidfd_support()
}

/// Guest implementation version sent during protocol negotiation.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Mount the exact per-generation runtime share when the host requested it.
///
/// The utility-VM system root contains only the fixed agent and mount point.
/// Bundles and one-time handoff files arrive through this separate virtio-fs
/// device. Missing or altered mount configuration fails before token access or
/// host connection.
#[cfg(target_os = "linux")]
pub fn mount_runtime_share_if_requested() -> Result<()> {
    let Some(value) = std::env::var_os(AGENT_RUNTIME_SHARE_ENV) else {
        return Ok(());
    };
    std::env::remove_var(AGENT_RUNTIME_SHARE_ENV);
    if value != AGENT_RUNTIME_SHARE_TAG {
        return Err(runtime_share_error(
            "guest runtime-share tag does not match the fixed host contract",
        ));
    }

    let mount_point = Path::new(AGENT_RUNTIME_SHARE_GUEST_ROOT);
    let metadata = std::fs::symlink_metadata(mount_point).map_err(|error| {
        runtime_share_error(format!(
            "failed to inspect guest runtime-share mount point {}: {error}",
            mount_point.display()
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(runtime_share_error(format!(
            "guest runtime-share mount point must be a real directory: {}",
            mount_point.display()
        )));
    }

    let source = std::ffi::CString::new(AGENT_RUNTIME_SHARE_TAG)
        .map_err(|error| runtime_share_error(format!("invalid runtime-share tag: {error}")))?;
    let target = std::ffi::CString::new(AGENT_RUNTIME_SHARE_GUEST_ROOT)
        .map_err(|error| runtime_share_error(format!("invalid runtime-share path: {error}")))?;
    let filesystem = std::ffi::CString::new("virtiofs").map_err(|error| {
        runtime_share_error(format!("invalid runtime-share filesystem: {error}"))
    })?;
    // SAFETY: all strings are fixed, NUL-terminated values; the target was
    // verified as a real directory and no untrusted guest process runs before
    // this bootstrap boundary.
    let status = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(runtime_share_error(format!(
            "failed to mount the protected runtime share at {}: {}",
            mount_point.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Non-Linux builds can parse the shared crate but cannot mount virtio-fs.
#[cfg(not(target_os = "linux"))]
pub fn mount_runtime_share_if_requested() -> Result<()> {
    match std::env::var_os(AGENT_RUNTIME_SHARE_ENV) {
        None => Ok(()),
        Some(_) => {
            std::env::remove_var(AGENT_RUNTIME_SHARE_ENV);
            Err(runtime_share_error(
                "guest runtime shares require a Linux utility VM",
            ))
        }
    }
}

fn runtime_share_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("mount-agent-runtime-share")
}

/// Run the internal prepared-init mode when selected by the guest executor.
///
/// Normal guest-agent startup returns `None`; the internal child mode returns
/// its terminal result and must not attempt host protocol bootstrap.
#[cfg(target_os = "linux")]
pub fn run_internal_container_init() -> Option<Result<()>> {
    executor::run_container_init_if_requested()
}

/// Non-Linux builds never enter the internal Linux init mode.
#[cfg(not(target_os = "linux"))]
pub const fn run_internal_container_init() -> Option<Result<()>> {
    None
}

/// Guest service that proves transport bootstrap without claiming execution.
#[derive(Debug)]
pub struct NegotiationOnlyAgent {
    capabilities: AgentCapabilities,
}

impl NegotiationOnlyAgent {
    /// Construct a guest that advertises only implemented bootstrap features.
    pub fn new() -> Result<Self> {
        Ok(Self {
            capabilities: AgentCapabilities::handshake_only(AGENT_VERSION, std::env::consts::ARCH)?,
        })
    }
}

#[async_trait]
impl GuestAgentService for NegotiationOnlyAgent {
    fn capabilities(&self) -> AgentCapabilities {
        self.capabilities.clone()
    }

    async fn create(&self, _request: AgentCreateRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-create"))
    }

    async fn state(&self, _request: AgentStateRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-state"))
    }

    async fn start(&self, _request: AgentStartRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-start"))
    }

    async fn kill(&self, _request: AgentKillRequest) -> Result<AgentState> {
        Err(Error::unsupported("agent-kill"))
    }

    async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
        Err(Error::unsupported("agent-delete"))
    }
}

/// Consume the platform-selected protected bootstrap token.
///
/// Windows utility VMs receive a one-time file through the protected shared
/// root. Other hosts retain the existing environment bootstrap.
pub fn take_session_token() -> Result<SessionToken> {
    if std::env::var_os(AGENT_SESSION_TOKEN_FILE_ENV).is_some() {
        take_session_token_from_file()
    } else {
        take_session_token_from_environment()
    }
}

/// Remove and decode the protected bootstrap token from this process.
pub fn take_session_token_from_environment() -> Result<SessionToken> {
    let encoded = Zeroizing::new(std::env::var(AGENT_SESSION_TOKEN_ENV).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!("guest bootstrap token is unavailable: {error}"),
        )
        .for_operation("bootstrap-guest-agent")
    })?);
    std::env::remove_var(AGENT_SESSION_TOKEN_ENV);
    SessionToken::from_hex(encoded.as_str()).map_err(|error| {
        Error::new(
            error.code,
            format!("guest bootstrap token is invalid: {error}"),
        )
        .for_operation("bootstrap-guest-agent")
    })
}

/// Read, unlink, and decode the protected one-time bootstrap token file.
pub fn take_session_token_from_file() -> Result<SessionToken> {
    if std::env::var_os(AGENT_SESSION_TOKEN_ENV).is_some() {
        std::env::remove_var(AGENT_SESSION_TOKEN_ENV);
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            "guest bootstrap token must not be present directly in the guest environment",
        )
        .for_operation("bootstrap-guest-agent"));
    }

    let path = PathBuf::from(
        std::env::var(AGENT_SESSION_TOKEN_FILE_ENV).map_err(|error| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!("guest bootstrap token file is unavailable: {error}"),
            )
            .for_operation("bootstrap-guest-agent")
        })?,
    );
    std::env::remove_var(AGENT_SESSION_TOKEN_FILE_ENV);
    validate_token_path(&path)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to open guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    if !metadata.is_file() || metadata.len() != 64 {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            "guest bootstrap token file must be a regular 64-byte file",
        )
        .for_operation("bootstrap-guest-agent"));
    }

    let mut encoded = Zeroizing::new(String::with_capacity(64));
    (&mut file)
        .take(65)
        .read_to_string(&mut encoded)
        .map_err(|error| {
            Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read guest bootstrap token file {}: {error}",
                    path.display()
                ),
            )
            .for_operation("bootstrap-guest-agent")
        })?;
    drop(file);
    std::fs::remove_file(&path).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to unlink guest bootstrap token file {}: {error}",
                path.display()
            ),
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    if let Some(parent) = path.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    SessionToken::from_hex(encoded.as_str()).map_err(|error| {
        Error::new(
            error.code,
            format!("guest bootstrap token is invalid: {error}"),
        )
        .for_operation("bootstrap-guest-agent")
    })
}

fn validate_token_path(path: &Path) -> Result<()> {
    let mut components = runtime_owned_handoff_components(path).ok_or_else(invalid_token_path)?;
    let Some(Component::Normal(directory)) = components.next() else {
        return Err(invalid_token_path());
    };
    let Some(Component::Normal(file)) = components.next() else {
        return Err(invalid_token_path());
    };
    let valid_directory = directory.to_str().is_some_and(|value| {
        value.starts_with(AGENT_SESSION_TOKEN_DIRECTORY_PREFIX)
            && value.len() > AGENT_SESSION_TOKEN_DIRECTORY_PREFIX.len()
    });
    if components.next().is_some() || file != AGENT_SESSION_TOKEN_FILE_NAME || !valid_directory {
        return Err(invalid_token_path());
    }
    Ok(())
}

fn invalid_token_path() -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        "guest bootstrap token file path is not the runtime-owned one-time path",
    )
    .for_operation("bootstrap-guest-agent")
}

/// Connect to the host bridge and serve the fail-closed Linux executor.
#[cfg(target_os = "linux")]
pub fn run(token: SessionToken) -> Result<()> {
    let recovery_path = take_recovery_report_path()?;
    let recovery_token = token.clone();
    let stream = vsock::connect_host_with_retry()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to initialize guest async runtime: {error}"),
            )
            .for_operation("run-guest-agent")
        })?;
    runtime.block_on(async move {
        let stream = tokio::net::UnixStream::from_std(stream).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to register guest vsock stream: {error}"),
            )
            .for_operation("run-guest-agent")
        })?;
        let service = Arc::new(LinuxExecutor::new().await?);
        let protocol_service: Arc<dyn GuestAgentService> = service.clone();
        let serve_result =
            a3s_oci_agent_protocol::serve_agent_connection(stream, token, protocol_service).await;
        let cleanup_result = service.shutdown_with_recovery().await.and_then(|records| {
            write_recovery_report(recovery_path.as_deref(), &recovery_token, records)
        });
        finish_guest_session(serve_result, cleanup_result)
    })
}

#[cfg(any(target_os = "linux", test))]
fn finish_guest_session(serve_result: Result<()>, cleanup_result: Result<()>) -> Result<()> {
    match (serve_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) if is_clean_host_disconnect(&error) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(Error::new(
            error.code,
            format!("{error}; guest executor cleanup also failed: {cleanup}"),
        )
        .for_operation("run-guest-agent")
        .retryable(error.retryable)),
    }
}

#[cfg(any(target_os = "linux", test))]
fn is_clean_host_disconnect(error: &Error) -> bool {
    error.code == ErrorCode::Unavailable
        && error.retryable
        && matches!(
            error.operation.as_deref(),
            Some(
                "read-agent-frame-header"
                    | "read-agent-frame-payload"
                    | "write-agent-frame-header"
                    | "write-agent-frame-payload"
                    | "flush-agent-frame"
            )
        )
}

#[cfg(target_os = "linux")]
fn take_recovery_report_path() -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(AGENT_RECOVERY_REPORT_ENV) else {
        return Ok(None);
    };
    std::env::remove_var(AGENT_RECOVERY_REPORT_ENV);
    let path = PathBuf::from(value);
    validate_recovery_report_path(&path)?;
    Ok(Some(path))
}

#[cfg(any(target_os = "linux", test))]
fn validate_recovery_report_path(path: &Path) -> Result<()> {
    let mut components =
        runtime_owned_handoff_components(path).ok_or_else(invalid_recovery_report_path)?;
    let Some(Component::Normal(directory)) = components.next() else {
        return Err(invalid_recovery_report_path());
    };
    let Some(Component::Normal(file)) = components.next() else {
        return Err(invalid_recovery_report_path());
    };
    let valid_directory = directory.to_str().is_some_and(|value| {
        value.starts_with(AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX)
            && value.len() > AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX.len()
    });
    if components.next().is_some() || file != AGENT_RECOVERY_REPORT_FILE_NAME || !valid_directory {
        return Err(invalid_recovery_report_path());
    }
    Ok(())
}

fn runtime_owned_handoff_components(path: &Path) -> Option<std::path::Components<'_>> {
    let relative = path
        .strip_prefix(AGENT_RUNTIME_SHARE_GUEST_ROOT)
        .or_else(|_| path.strip_prefix(Path::new("/")))
        .ok()?;
    Some(relative.components())
}

#[cfg(any(target_os = "linux", test))]
fn invalid_recovery_report_path() -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        "guest recovery report path is not the runtime-owned one-time path",
    )
    .for_operation("persist-agent-recovery")
}

#[cfg(target_os = "linux")]
fn write_recovery_report(
    path: Option<&Path>,
    token: &SessionToken,
    records: Vec<AgentRecoveryRecord>,
) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let report = AgentRecoveryReport::new(records)?.authenticate(token)?;
    let encoded = report.to_json()?;
    let parent = path.parent().ok_or_else(invalid_recovery_report_path)?;
    let metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to inspect guest recovery directory {}: {error}",
                parent.display()
            ),
            ErrorCode::FailedPrecondition,
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(recovery_io_error(
            format!(
                "guest recovery directory must be a real directory: {}",
                parent.display()
            ),
            ErrorCode::FailedPrecondition,
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|error| {
        recovery_io_error(
            format!(
                "failed to create guest recovery report {}: {error}",
                path.display()
            ),
            ErrorCode::FailedPrecondition,
        )
    })?;
    let write_result = file
        .write_all(&encoded)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::File::open(parent)?.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(recovery_io_error(
            format!(
                "failed to commit guest recovery report {}: {error}",
                path.display()
            ),
            ErrorCode::Internal,
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn recovery_io_error(message: impl Into<String>, code: ErrorCode) -> Error {
    Error::new(code, message).for_operation("persist-agent-recovery")
}

/// Report that the guest binary cannot run on a non-Linux target.
#[cfg(not(target_os = "linux"))]
pub fn run(_token: SessionToken) -> Result<()> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "the OCI guest agent requires Linux AF_VSOCK",
    )
    .for_operation("run-guest-agent"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_agent_protocol::GuestAgentService;
    use a3s_oci_sdk::{Error, ErrorCode};

    use super::{
        finish_guest_session, validate_recovery_report_path, validate_token_path,
        NegotiationOnlyAgent,
    };

    #[test]
    fn bootstrap_service_does_not_claim_executor_operations() {
        let agent = NegotiationOnlyAgent::new().expect("built-in capabilities are valid");
        let capabilities = agent.capabilities();
        assert!(capabilities.operations().is_empty());
    }

    #[test]
    fn accepts_only_the_runtime_owned_token_file_shape() {
        for path in [
            "/.a3s-oci-bootstrap-a3s-oci-agent-test/session-token",
            "/run/a3s-oci-runtime/.a3s-oci-bootstrap-a3s-oci-agent-test/session-token",
        ] {
            assert!(validate_token_path(Path::new(path)).is_ok(), "{path}");
        }
        for path in [
            "relative/session-token",
            "/session-token",
            "/.a3s-oci-bootstrap-/session-token",
            "/.a3s-oci-bootstrap-test/other",
            "/.a3s-oci-bootstrap-test/nested/session-token",
            "/run/other/.a3s-oci-bootstrap-test/session-token",
            "/run/a3s-oci-runtime/nested/.a3s-oci-bootstrap-test/session-token",
        ] {
            assert!(validate_token_path(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn accepts_only_the_runtime_owned_recovery_file_shape() {
        for path in [
            "/.a3s-oci-recovery-a3s-oci-agent-test/report.json",
            "/run/a3s-oci-runtime/.a3s-oci-recovery-a3s-oci-agent-test/report.json",
        ] {
            assert!(
                validate_recovery_report_path(Path::new(path)).is_ok(),
                "{path}"
            );
        }
        for path in [
            "relative/report.json",
            "/report.json",
            "/.a3s-oci-recovery-/report.json",
            "/.a3s-oci-recovery-test/other",
            "/.a3s-oci-recovery-test/nested/report.json",
            "/run/other/.a3s-oci-recovery-test/report.json",
            "/run/a3s-oci-runtime/nested/.a3s-oci-recovery-test/report.json",
        ] {
            assert!(
                validate_recovery_report_path(Path::new(path)).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn clean_transport_disconnect_succeeds_only_after_executor_cleanup() {
        for operation in [
            "read-agent-frame-header",
            "read-agent-frame-payload",
            "write-agent-frame-header",
            "write-agent-frame-payload",
            "flush-agent-frame",
        ] {
            let disconnected = Error::new(ErrorCode::Unavailable, "host disconnected")
                .for_operation(operation)
                .retryable(true);
            assert!(finish_guest_session(Err(disconnected), Ok(())).is_ok());
        }

        let cleanup = Error::new(ErrorCode::Internal, "cleanup failed")
            .for_operation("shutdown-guest-executor");
        let disconnected = Error::new(ErrorCode::Unavailable, "host disconnected")
            .for_operation("write-agent-frame-payload")
            .retryable(true);
        let combined = finish_guest_session(Err(disconnected), Err(cleanup))
            .expect_err("cleanup failure must remain visible");
        assert_eq!(combined.operation.as_deref(), Some("run-guest-agent"));
        assert!(combined.message.contains("cleanup also failed"));
    }

    #[test]
    fn protocol_and_service_failures_are_not_normalized_as_disconnects() {
        for error in [
            Error::new(ErrorCode::InvalidArgument, "invalid frame")
                .for_operation("read-agent-frame-payload"),
            Error::new(ErrorCode::Unavailable, "service unavailable")
                .for_operation("guest-create")
                .retryable(true),
            Error::new(ErrorCode::Unavailable, "terminal transport failure")
                .for_operation("read-agent-frame-header"),
        ] {
            assert!(finish_guest_session(Err(error), Ok(())).is_err());
        }
    }
}
