//! Opt-in WHPX Live Host reattach through the durable session-owner bridge.
//!
//! When `A3S_OCI_WHPX_SESSION_OWNER=1` and a live authenticated binding exists
//! under the container runtime share, a replacement Host reconnects to the
//! surviving Guest incarnation instead of seeding `RecoveredStopped`.
//!
//! Lives at `utility_vm_driver/whpx_live_reattach.rs` to mirror
//! `kvm_live_reattach` on Linux; the parent `utility_vm_driver` module is not
//! compiled on Windows, so this file is pulled in via `#[path]` from the
//! runtime crate root and wired by `WhpxRuntimeDriver::recover`.
//!
//! A binding whose session-owner or shim identity is no longer live
//! ([`io::ErrorKind::NotFound`] from authenticate) returns [`Ok(None)`] so
//! recovery falls through to stopped — that outcome is permanent for the
//! recorded identity and must not be [`ErrorCode::Unavailable`] (Box retries
//! that code).
//!
//! Guest hello rejects with [`ErrorCode::PermissionDenied`] (wrong token) or
//! [`ErrorCode::FailedPrecondition`] (protocol mismatch) are likewise permanent
//! for the recorded binding and must not be rewritten as retryable Unavailable.
//!
//! Does **not** claim Box Enterprise GA or flip B2.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_agent_protocol::{AgentClient, GuestAgentService, SessionToken};
use a3s_oci_sdk::{ContainerRecord, ContainerTarget, Error, ErrorCode, Result};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::time::timeout;

use crate::agent_driver::AgentDriverClient;
use crate::whpx_durable_session_owner::{owner_mode_from_env, DurableSessionOwner, WhpxOwnerMode};
use crate::whpx_live_session_binding::{load_binding, WhpxLiveSessionBinding};

const HOST_CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_CONTROL_CONNECT_RETRY: Duration = Duration::from_millis(50);
const OPERATION: &str = "utility-vm-whpx-live-reattach";

/// Attempt Live reattach for one durable WHPX container record.
///
/// `runtime_share` is the exact-generation share directory (caller resolves it
/// with the same protected-path checks as create/start). Returns `Ok(None)` when
/// durable mode is off, no live binding is present, or the recorded
/// session-owner/shim identity is no longer live, so the caller can keep the
/// stopped-only recovery path without inventing exit.
pub(crate) async fn try_reattach_live(
    runtime_share: &Path,
    target: &ContainerTarget,
    record: &ContainerRecord,
) -> Result<Option<ReattachedLive>> {
    if owner_mode_from_env() != WhpxOwnerMode::DurableSession {
        return Ok(None);
    }
    let binding_path = WhpxLiveSessionBinding::binding_path(runtime_share);
    if !binding_path.exists() {
        return Ok(None);
    }
    let binding = load_binding(&runtime_share).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to load WHPX Live binding {}: {error}",
                binding_path.display()
            ),
        )
        .for_operation(OPERATION)
    })?;
    if let Some(container_id) = binding.container_id.as_deref() {
        if container_id != target.id.as_str() {
            return Ok(None);
        }
    }
    if let (Some(expected), Some(generation)) = (target.generation, binding.generation) {
        if expected.0 != generation {
            return Ok(None);
        }
    }
    if let Some(digest) = binding.config_digest.as_deref() {
        if digest != record.config_digest {
            return Ok(None);
        }
    }
    match binding.authenticate_live() {
        Ok(()) => {}
        Err(error) => match classify_live_auth_error(&error) {
            LiveAuthDisposition::FallThroughToStopped => return Ok(None),
            LiveAuthDisposition::FailedPrecondition => {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    format!("WHPX Live binding is not authenticated: {error}"),
                )
                .for_operation(OPERATION));
            }
            LiveAuthDisposition::Unavailable => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!("WHPX Live binding is not authenticated: {error}"),
                )
                .for_operation(OPERATION)
                .retryable(true));
            }
        },
    }

    let token = SessionToken::from_hex(&binding.session_token_hex).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!("WHPX Live binding session token is invalid: {error}"),
        )
        .for_operation(OPERATION)
    })?;
    let host_control = binding.host_control_pipe.clone();
    let stream = connect_host_control(&host_control).await?;
    let client = timeout(
        HOST_CONTROL_CONNECT_TIMEOUT,
        AgentClient::connect(stream, token),
    )
    .await
    .map_err(|_| {
        Error::new(
            ErrorCode::Unavailable,
            "timed out negotiating with the reattached WHPX guest agent",
        )
        .for_operation(OPERATION)
        .retryable(true)
    })?
    .map_err(remap_live_agent_hello_error)?;

    let owner_pid = NonZeroU32::new(binding.session_owner.pid).ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            "WHPX Live binding session-owner pid is zero",
        )
        .for_operation(OPERATION)
    })?;
    let shim_pid = NonZeroU32::new(binding.shim.pid).ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            "WHPX Live binding shim pid is zero",
        )
        .for_operation(OPERATION)
    })?;
    let durable = DurableSessionOwner::from_authenticated(owner_pid, shim_pid);
    let service: Arc<dyn GuestAgentService> = Arc::new(client);
    Ok(Some(ReattachedLive {
        client: AgentDriverClient::new(service, "WHPX guest agent", "whpx"),
        durable,
        runtime_share: runtime_share.to_path_buf(),
        host_control_pipe: host_control,
    }))
}

/// Surviving Live session pieces for `WhpxRuntimeDriver` to register.
pub(crate) struct ReattachedLive {
    pub(crate) client: AgentDriverClient,
    pub(crate) durable: DurableSessionOwner,
    pub(crate) runtime_share: PathBuf,
    pub(crate) host_control_pipe: String,
}

async fn connect_host_control(host_control: &str) -> Result<NamedPipeClient> {
    let deadline = tokio::time::Instant::now() + HOST_CONTROL_CONNECT_TIMEOUT;
    loop {
        match ClientOptions::new().open(host_control) {
            Ok(stream) => return Ok(stream),
            Err(error) if host_control_connect_error_is_permanent(&error) => {
                return Err(remap_host_control_connect_error(host_control, error));
            }
            Err(error) if tokio::time::Instant::now() >= deadline => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!("timed out connecting to WHPX host-control {host_control}: {error}"),
                )
                .for_operation(OPERATION)
                .retryable(true));
            }
            Err(_) => tokio::time::sleep(HOST_CONTROL_CONNECT_RETRY).await,
        }
    }
}

/// Host-control named pipes reject remote clients. Access-denied for this Host
/// identity is permanent and must not burn the connect deadline as Unavailable.
fn host_control_connect_error_is_permanent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

fn remap_host_control_connect_error(host_control: &str, error: io::Error) -> Error {
    Error::new(
        ErrorCode::PermissionDenied,
        format!("permission denied connecting to WHPX host-control {host_control}: {error}"),
    )
    .for_operation(OPERATION)
    .retryable(false)
}

/// Preserve permanent guest-hello rejects; wrap only transient negotiate misses.
fn remap_live_agent_hello_error(error: Error) -> Error {
    if live_agent_hello_error_is_permanent(&error) {
        return error.for_operation(OPERATION).retryable(false);
    }
    Error::new(
        ErrorCode::Unavailable,
        format!("failed to authenticate reattached WHPX guest agent: {error}"),
    )
    .for_operation(OPERATION)
    .retryable(true)
}

fn live_agent_hello_error_is_permanent(error: &Error) -> bool {
    matches!(
        error.code,
        ErrorCode::PermissionDenied | ErrorCode::FailedPrecondition
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveAuthDisposition {
    /// Dead or start-time-mismatched identities: fall through to stopped.
    FallThroughToStopped,
    /// Corrupt binding identity (e.g. schema): permanent, not retryable.
    FailedPrecondition,
    /// Transient observation / auth races: Box-retryable Unavailable.
    Unavailable,
}

fn classify_live_auth_error(error: &io::Error) -> LiveAuthDisposition {
    match error.kind() {
        io::ErrorKind::NotFound => LiveAuthDisposition::FallThroughToStopped,
        io::ErrorKind::InvalidInput => LiveAuthDisposition::FailedPrecondition,
        _ => LiveAuthDisposition::Unavailable,
    }
}

#[cfg(test)]
fn auth_miss_falls_through_to_stopped(error: &io::Error) -> bool {
    classify_live_auth_error(error) == LiveAuthDisposition::FallThroughToStopped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whpx_live_session_binding::{WhpxLiveSessionBinding, WhpxProcessIdentity};

    fn sample_binding(
        owner: WhpxProcessIdentity,
        shim: WhpxProcessIdentity,
    ) -> WhpxLiveSessionBinding {
        WhpxLiveSessionBinding {
            schema_version: crate::whpx_live_session_binding::WHPX_LIVE_SESSION_BINDING_SCHEMA
                .to_string(),
            container_id: Some("ctr".to_string()),
            generation: Some(1),
            config_digest: Some("digest".to_string()),
            session_token_hex: "00".repeat(32),
            host_control_pipe: r"\\.\pipe\a3s-oci-whpx-live-control-test".to_string(),
            service_pipe: r"\\.\pipe\a3s-oci-agent-test".to_string(),
            session_owner: owner,
            shim,
        }
    }

    #[test]
    fn dead_or_drifted_auth_miss_falls_through_to_stopped_not_unavailable() {
        let owner =
            WhpxProcessIdentity::capture(std::process::id(), "test-owner").expect("capture self");
        let mut drifted = owner;
        drifted.start_time_ticks = owner.start_time_ticks.saturating_add(1);
        let drift_error = sample_binding(drifted, owner)
            .authenticate_live()
            .expect_err("start-time drift must fail closed");
        assert!(
            auth_miss_falls_through_to_stopped(&drift_error),
            "PID reuse must fall through to stopped recovery, not Unavailable"
        );

        let dead = WhpxProcessIdentity {
            pid: u32::MAX - 7,
            start_time_ticks: 1,
        };
        let dead_error = sample_binding(dead, dead)
            .authenticate_live()
            .expect_err("dead pid must fail closed");
        assert!(
            auth_miss_falls_through_to_stopped(&dead_error),
            "dead session-owner/shim must fall through to stopped recovery, not Unavailable"
        );
    }

    #[test]
    fn zero_pid_auth_miss_falls_through_as_not_live() {
        let zero = WhpxProcessIdentity {
            pid: 0,
            start_time_ticks: 1,
        };
        let zero_error = sample_binding(zero, zero)
            .authenticate_live()
            .expect_err("pid 0 must fail closed");
        assert_eq!(zero_error.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            classify_live_auth_error(&zero_error),
            LiveAuthDisposition::FallThroughToStopped
        );
    }

    #[test]
    fn schema_mismatch_auth_miss_is_failed_precondition_not_unavailable() {
        let owner =
            WhpxProcessIdentity::capture(std::process::id(), "test-owner").expect("capture self");
        let mut binding = sample_binding(owner, owner);
        binding.schema_version = "wrong.schema".to_string();
        let error = binding
            .authenticate_live()
            .expect_err("schema mismatch must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            classify_live_auth_error(&error),
            LiveAuthDisposition::FailedPrecondition
        );
    }

    #[test]
    fn wrong_token_hello_reject_stays_permission_denied_not_unavailable() {
        let rejected = Error::new(
            ErrorCode::PermissionDenied,
            "agent session authentication failed",
        );
        assert!(live_agent_hello_error_is_permanent(&rejected));
        let remapped = remap_live_agent_hello_error(rejected);
        assert_eq!(remapped.code, ErrorCode::PermissionDenied);
        assert!(!remapped.retryable);
    }

    #[test]
    fn protocol_mismatch_hello_reject_stays_failed_precondition_not_unavailable() {
        let rejected = Error::new(
            ErrorCode::FailedPrecondition,
            "no overlapping agent protocol version",
        );
        assert!(live_agent_hello_error_is_permanent(&rejected));
        let remapped = remap_live_agent_hello_error(rejected);
        assert_eq!(remapped.code, ErrorCode::FailedPrecondition);
        assert!(!remapped.retryable);
    }

    #[test]
    fn guest_closed_before_hello_stays_retryable_unavailable() {
        let closed = Error::new(
            ErrorCode::Unavailable,
            "guest closed the stream before protocol negotiation",
        )
        .retryable(true);
        assert!(!live_agent_hello_error_is_permanent(&closed));
        let remapped = remap_live_agent_hello_error(closed);
        assert_eq!(remapped.code, ErrorCode::Unavailable);
        assert!(remapped.retryable);
    }

    #[test]
    fn host_control_permission_denied_is_permanent_not_unavailable() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "ACCESS_DENIED");
        assert!(host_control_connect_error_is_permanent(&error));
        let remapped =
            remap_host_control_connect_error(r"\\.\pipe\a3s-oci-whpx-live-control-test", error);
        assert_eq!(remapped.code, ErrorCode::PermissionDenied);
        assert!(!remapped.retryable);
    }

    #[test]
    fn host_control_not_found_stays_retryable_until_timeout() {
        let error = io::Error::new(io::ErrorKind::NotFound, "ENOENT");
        assert!(!host_control_connect_error_is_permanent(&error));
    }

    #[test]
    fn host_control_pipe_busy_stays_retryable_until_timeout() {
        let error = io::Error::from_raw_os_error(231); // ERROR_PIPE_BUSY
        assert!(!host_control_connect_error_is_permanent(&error));
    }

    #[test]
    fn host_control_pipe_naming_matches_binding_contract() {
        let service = r"\\.\pipe\a3s-oci-agent-abc";
        assert_eq!(
            WhpxLiveSessionBinding::host_control_pipe_for_service(service),
            r"\\.\pipe\a3s-oci-whpx-live-control-a3s-oci-agent-abc"
        );
    }
}
