//! Opt-in KVM Live Host reattach through the durable session-owner bridge.
//!
//! When `A3S_OCI_KVM_SESSION_OWNER=1` and a live authenticated binding exists
//! under the container runtime share, a replacement Host reconnects to the
//! surviving Guest incarnation instead of seeding `RecoveredStopped`.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_agent_protocol::{AgentClient, GuestAgentService, SessionToken};
use a3s_oci_sdk::{
    async_trait, ContainerRecord, ContainerTarget, Error, ErrorCode, GuestSessionAttachment,
    Result,
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
    ReusableGuestSession, UtilityVmAttachment, UtilityVmContainer, UtilityVmGuest, UtilityVmRegistry,
};
use super::{LaunchedUtilityVm, UtilityVmOwner};

const HOST_CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HOST_CONTROL_CONNECT_RETRY: Duration = Duration::from_millis(50);

/// Attempt Live reattach for one durable container record.
///
/// Returns `Ok(None)` when durable mode is off or no live binding is present so
/// the caller can keep the stopped-only recovery path.
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
    authenticate_live(&binding).map_err(|error| {
        Error::new(
            ErrorCode::Unavailable,
            format!("KVM Live binding is not authenticated: {error}"),
        )
        .for_operation("utility-vm-kvm-live-reattach")
        .retryable(true)
    })?;

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
    let service: Arc<dyn GuestAgentService> = Arc::new(client);
    let launched = LaunchedUtilityVm {
        client: AgentDriverClient::new(service, "KVM guest agent", "kvm"),
        owner: Arc::new(ReattachedKvmOwner {
            durable: std::sync::Mutex::new(Some(durable)),
            runtime_share: paths.mount_root.clone(),
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
        Ok(())
    }
}
