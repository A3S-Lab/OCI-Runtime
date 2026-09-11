//! Opt-in KVM Live Host reattach through the durable session-owner bridge.
//!
//! When `A3S_OCI_KVM_SESSION_OWNER=1` and a live authenticated binding exists
//! under the container runtime share, a replacement Host reconnects to the
//! surviving Guest incarnation instead of seeding `RecoveredStopped`.
//!
//! A binding whose session-owner or shim identity is no longer live
//! ([`io::ErrorKind::NotFound`] from [`authenticate_live`]) returns
//! [`Ok(None)`] so recovery falls through to stopped — that outcome is
//! permanent for the recorded identity and must not be
//! [`ErrorCode::Unavailable`] (Box retries that code).

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_agent_protocol::{AgentClient, GuestAgentService, SessionToken};
use a3s_oci_sdk::{
    async_trait, ContainerRecord, ContainerTarget, Error, ErrorCode, GuestSessionAttachment, Result,
};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::agent_driver::AgentDriverClient;
use crate::kvm_durable_session_owner::{owner_mode_from_env, DurableSessionOwner, KvmOwnerMode};
use crate::kvm_live_session_binding::{
    authenticate_live, load_binding, remove_binding, KvmLiveSessionBinding,
};

use super::layout::existing_runtime_share_paths;
use super::sessions::{
    ReusableGuestSession, UtilityVmAttachment, UtilityVmContainer, UtilityVmGuest,
    UtilityVmRegistry,
};
use super::{LaunchedUtilityVm, UtilityVmOwner};

const HOST_CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_CONTROL_CONNECT_RETRY: Duration = Duration::from_millis(50);

/// Attempt Live reattach for one durable container record.
///
/// Returns `Ok(None)` when durable mode is off, no live binding is present, or
/// the recorded session-owner/shim identity is no longer live, so the caller
/// can keep the stopped-only recovery path.
pub(super) async fn try_reattach_live(
    runtime_share_root: &Path,
    target: &ContainerTarget,
    record: &ContainerRecord,
    guest_session: Option<&GuestSessionAttachment>,
) -> Result<Option<ReattachedLive>> {
    if owner_mode_from_env() != KvmOwnerMode::DurableSession {
        return Ok(None);
    }
    let Some(paths) = existing_runtime_share_paths(
        runtime_share_root,
        target,
        guest_session,
        "utility-vm-kvm-live-reattach",
    )
    .await?
    else {
        return Ok(None);
    };
    let binding_path = KvmLiveSessionBinding::binding_path(&paths.mount_root);
    if !binding_path.exists() {
        return Ok(None);
    }
    let binding = load_binding(&binding_path).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to load KVM Live binding {}: {error}",
                binding_path.display()
            ),
        )
        .for_operation("utility-vm-kvm-live-reattach")
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
    match authenticate_live(&binding) {
        Ok(()) => {}
        Err(error) => match classify_live_auth_error(&error) {
            LiveAuthDisposition::FallThroughToStopped => return Ok(None),
            LiveAuthDisposition::FailedPrecondition => {
                return Err(Error::new(
                    ErrorCode::FailedPrecondition,
                    format!("KVM Live binding is not authenticated: {error}"),
                )
                .for_operation("utility-vm-kvm-live-reattach"));
            }
            LiveAuthDisposition::Unavailable => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!("KVM Live binding is not authenticated: {error}"),
                )
                .for_operation("utility-vm-kvm-live-reattach")
                .retryable(true));
            }
        },
    }

    let token = SessionToken::from_hex(&binding.session_token_hex).map_err(|error| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!("KVM Live binding session token is invalid: {error}"),
        )
        .for_operation("utility-vm-kvm-live-reattach")
    })?;
    let host_control = PathBuf::from(&binding.host_control_socket);
    let stream = connect_host_control(&host_control).await?;
    let client = timeout(
        HOST_CONTROL_CONNECT_TIMEOUT,
        AgentClient::connect(stream, token),
    )
    .await
    .map_err(|_| {
        Error::new(
            ErrorCode::Unavailable,
            "timed out negotiating with the reattached KVM guest agent",
        )
        .for_operation("utility-vm-kvm-live-reattach")
        .retryable(true)
    })?
    .map_err(|error| {
        Error::new(
            ErrorCode::Unavailable,
            format!("failed to authenticate reattached KVM guest agent: {error}"),
        )
        .for_operation("utility-vm-kvm-live-reattach")
        .retryable(true)
    })?;

    let owner_pid = NonZeroU32::new(binding.session_owner.pid as u32).ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            "KVM Live binding session-owner pid is zero",
        )
        .for_operation("utility-vm-kvm-live-reattach")
    })?;
    let shim_pid = NonZeroU32::new(binding.shim.pid as u32).ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            "KVM Live binding shim pid is zero",
        )
        .for_operation("utility-vm-kvm-live-reattach")
    })?;
    let durable = DurableSessionOwner::from_authenticated(owner_pid, shim_pid);
    let guest_endpoint_dir =
        PathBuf::from(crate::agent_socket::PRIVATE_TMP_ROOT).join(&binding.pipe_name);
    let service: Arc<dyn GuestAgentService> = Arc::new(client);
    let launched = LaunchedUtilityVm {
        client: AgentDriverClient::new(service, "KVM guest agent", "kvm"),
        owner: Arc::new(ReattachedKvmOwner {
            durable: std::sync::Mutex::new(Some(durable)),
            runtime_share: paths.mount_root.clone(),
            host_control_socket: host_control,
            guest_endpoint_dir,
        }),
    };
    let guest = Arc::new(UtilityVmGuest {
        client: launched.client,
        owner: launched.owner,
    });
    let container = Arc::new(UtilityVmContainer {
        target: target.clone(),
        guest_session: guest_session.cloned(),
        guest: Arc::clone(&guest),
    });
    Ok(Some(ReattachedLive {
        container,
        guest_session: guest_session.cloned(),
        guest,
    }))
}

pub(super) struct ReattachedLive {
    pub(super) container: Arc<UtilityVmContainer>,
    pub(super) guest_session: Option<GuestSessionAttachment>,
    pub(super) guest: Arc<UtilityVmGuest>,
}

pub(super) fn register_reattached(
    sessions: &mut UtilityVmRegistry,
    reattached: ReattachedLive,
) -> Result<()> {
    let target = reattached.container.target.clone();
    if let Some(binding) = reattached.guest_session.as_ref() {
        let generation = target.generation.ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "KVM Live reattach for reusable session {} requires an exact generation",
                    binding.id()
                ),
            )
            .for_operation("utility-vm-kvm-live-reattach")
        })?;
        sessions.reusable.insert(
            binding.id().clone(),
            ReusableGuestSession::new(
                binding.clone(),
                Arc::clone(&reattached.guest),
                &target,
                generation,
            ),
        );
    }
    sessions.attachments.insert(
        target.id.clone(),
        UtilityVmAttachment::Live(reattached.container),
    );
    Ok(())
}

async fn connect_host_control(host_control: &Path) -> Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + HOST_CONTROL_CONNECT_TIMEOUT;
    loop {
        match UnixStream::connect(host_control).await {
            Ok(stream) => return Ok(stream),
            Err(error) if tokio::time::Instant::now() >= deadline => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!(
                        "timed out connecting to KVM host-control {}: {error}",
                        host_control.display()
                    ),
                )
                .for_operation("utility-vm-kvm-live-reattach")
                .retryable(true));
            }
            Err(_) => tokio::time::sleep(HOST_CONTROL_CONNECT_RETRY).await,
        }
    }
}

struct ReattachedKvmOwner {
    durable: std::sync::Mutex<Option<DurableSessionOwner>>,
    runtime_share: PathBuf,
    host_control_socket: PathBuf,
    guest_endpoint_dir: PathBuf,
}

#[async_trait]
impl UtilityVmOwner for ReattachedKvmOwner {
    async fn shutdown(&self) -> Result<()> {
        let _ = remove_binding(&self.runtime_share);
        let owner = self
            .durable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(owner) = owner {
            owner.shutdown().map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to shut down reattached KVM session-owner: {error}"),
                )
                .for_operation("shutdown-reattached-kvm-utility-vm")
            })?;
        }
        // SIGKILL skips session-owner's graceful socket unlink; Host must reclaim
        // the durable Live endpoint so reopen evidence does not leave orphans.
        let agent_socket = self.guest_endpoint_dir.join("agent.sock");
        let _ = std::fs::remove_file(&self.host_control_socket);
        let _ = std::fs::remove_file(&agent_socket);
        let _ = std::fs::remove_dir(&self.guest_endpoint_dir);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveAuthDisposition {
    /// Dead or start-time-mismatched identities: fall through to stopped.
    FallThroughToStopped,
    /// Corrupt binding identity (e.g. non-positive PID): permanent, not retryable.
    FailedPrecondition,
    /// Transient observation / auth races: Box-retryable Unavailable.
    Unavailable,
}

/// Classify Live binding authentication failures for Host reattach.
///
/// Dead or start-time-mismatched session-owner/shim identities are permanent
/// for the recorded binding and fall through to stopped recovery instead of
/// returning Box-retryable [`ErrorCode::Unavailable`]. Non-positive PIDs are
/// corrupt binding data ([`ErrorCode::FailedPrecondition`]), not a retryable
/// transport miss.
fn classify_live_auth_error(error: &io::Error) -> LiveAuthDisposition {
    match error.kind() {
        io::ErrorKind::NotFound => LiveAuthDisposition::FallThroughToStopped,
        io::ErrorKind::InvalidInput => LiveAuthDisposition::FailedPrecondition,
        _ => LiveAuthDisposition::Unavailable,
    }
}

fn auth_miss_falls_through_to_stopped(error: &io::Error) -> bool {
    classify_live_auth_error(error) == LiveAuthDisposition::FallThroughToStopped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvm_live_session_binding::{KvmLiveSessionBinding, KvmProcessIdentity};

    fn sample_binding(
        owner: KvmProcessIdentity,
        shim: KvmProcessIdentity,
    ) -> KvmLiveSessionBinding {
        KvmLiveSessionBinding {
            schema_version: crate::kvm_live_session_binding::KVM_LIVE_SESSION_BINDING_SCHEMA
                .to_string(),
            container_id: Some("ctr".to_string()),
            generation: Some(1),
            config_digest: Some("digest".to_string()),
            session_token_hex: "00".repeat(32),
            host_control_socket: "/tmp/a3s-oci-test-host-control.sock".to_string(),
            pipe_name: "a3s-oci-test-pipe".to_string(),
            session_owner: owner,
            shim,
        }
    }

    #[test]
    fn dead_or_drifted_auth_miss_falls_through_to_stopped_not_unavailable() {
        let owner = KvmProcessIdentity::capture(std::process::id() as i32, "test-owner")
            .expect("capture self");
        let mut drifted = owner;
        drifted.start_time_ticks = owner.start_time_ticks.saturating_add(1);
        let drift_error = sample_binding(drifted, owner)
            .authenticate_live()
            .expect_err("start-time drift must fail closed");
        assert!(
            auth_miss_falls_through_to_stopped(&drift_error),
            "PID reuse must fall through to stopped recovery, not Unavailable"
        );

        let dead = KvmProcessIdentity {
            pid: i32::MAX - 7,
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
    fn non_positive_pid_auth_miss_is_failed_precondition_not_unavailable() {
        let zero = KvmProcessIdentity {
            pid: 0,
            start_time_ticks: 1,
        };
        let zero_error = sample_binding(zero, zero)
            .authenticate_live()
            .expect_err("pid 0 must fail closed");
        assert_eq!(zero_error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            classify_live_auth_error(&zero_error),
            LiveAuthDisposition::FailedPrecondition,
            "corrupt non-positive PID must not be Box-retryable Unavailable"
        );
        assert!(
            !auth_miss_falls_through_to_stopped(&zero_error),
            "corrupt PID must not fall through as a missing identity"
        );

        let negative = KvmProcessIdentity {
            pid: -1,
            start_time_ticks: 1,
        };
        let negative_error = sample_binding(negative, negative)
            .authenticate_live()
            .expect_err("negative pid must fail closed");
        assert_eq!(negative_error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            classify_live_auth_error(&negative_error),
            LiveAuthDisposition::FailedPrecondition
        );
    }
}
