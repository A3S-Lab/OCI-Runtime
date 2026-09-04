use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use a3s_oci_agent_protocol::{GuestPath, AGENT_RUNTIME_SHARE_GUEST_ROOT};
use a3s_oci_core::{DriverCapability, IsolationClass};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, ContainerId, ContainerRecord, ContainerStats,
    ContainerTarget, CreateAttachments, Error, ErrorCode, ExitStatus, FileRequest, FileResponse,
    FilesystemRequest, FilesystemResponse, GuestSessionAttachment, GuestSessionId,
    GuestSessionReset, OciBundle, OperationId, OutputChunk, ProcessRecord, Result,
    RuntimeOperation, RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::agent_driver::{AgentDriverClient, AGENT_DRIVER_HOOKS, AGENT_DRIVER_OPERATIONS};
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateRequest,
    DriverDeleteRequest, DriverExecRequest, DriverKillRequest, DriverProcess,
    DriverReadOutputRequest, DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest,
    DriverState, DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest,
    DriverWriteStdinRequest, OciHookPhase, RuntimeDriver,
};

mod atomic_publication;
mod delegate;
mod directory_cleanup;
mod handoff;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod kvm_network;
pub(crate) mod layout;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod operation_reopen;
pub(crate) mod recovery;
mod session_lifecycle;
mod session_marker;
mod sessions;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use delegate::delegate_utility_vm_runtime_driver;
use handoff::BundleHandoffStore;
use layout::{existing_reusable_guest_session_identity_root, require_exact_generation};
use recovery::RecoveryStore;
use sessions::{
    PendingGuestSessionAdmission, ReusableGuestSession, UtilityVmAttachment, UtilityVmContainer,
    UtilityVmGuest, UtilityVmRegistry,
};

/// Platform-neutral lifecycle for dedicated and explicitly bound reusable utility VMs.
pub(crate) struct UtilityVmRuntimeDriver {
    capability: DriverCapability,
    attachment_capabilities: AttachmentCapabilities,
    backend_name: &'static str,
    runtime_root: PathBuf,
    runtime_share_root: PathBuf,
    system_image_manifest: PathBuf,
    system_image_manifest_sha256: String,
    recovery: RecoveryStore,
    handoff: BundleHandoffStore,
    factory: Arc<dyn UtilityVmFactory>,
    sessions: Mutex<UtilityVmRegistry>,
    create_gates: Mutex<BTreeMap<ContainerId, Weak<Mutex<()>>>>,
    session_gates: Mutex<BTreeMap<GuestSessionId, Weak<Mutex<()>>>>,
}

impl fmt::Debug for UtilityVmRuntimeDriver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UtilityVmRuntimeDriver")
            .field("capability", &self.capability)
            .field("backend_name", &self.backend_name)
            .field("runtime_root", &self.runtime_root)
            .field("runtime_share_root", &self.runtime_share_root)
            .field("system_image_manifest", &self.system_image_manifest)
            .field(
                "system_image_manifest_sha256",
                &self.system_image_manifest_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl UtilityVmRuntimeDriver {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        capability: DriverCapability,
        attachment_capabilities: AttachmentCapabilities,
        backend_name: &'static str,
        runtime_root: PathBuf,
        runtime_share_root: PathBuf,
        system_image_manifest: PathBuf,
        system_image_manifest_sha256: String,
        recovery_directory: PathBuf,
        factory: Arc<dyn UtilityVmFactory>,
    ) -> Self {
        let recovery = RecoveryStore::new(recovery_directory);
        let handoff = BundleHandoffStore::new(runtime_root.clone(), runtime_share_root.clone());
        let attachment_capabilities = attachment_capabilities
            .with_extension(
                RUNTIME_BUNDLE_HANDOFF_EXTENSION,
                vec![RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION],
            )
            .expect("the fixed utility-VM bundle-handoff extension is valid");
        Self {
            capability,
            attachment_capabilities,
            backend_name,
            runtime_root,
            runtime_share_root,
            system_image_manifest,
            system_image_manifest_sha256,
            recovery,
            handoff,
            factory,
            sessions: Mutex::new(UtilityVmRegistry::default()),
            create_gates: Mutex::new(BTreeMap::new()),
            session_gates: Mutex::new(BTreeMap::new()),
        }
    }

    /// Close every live guest connection and reap each driver-owned VM once.
    pub async fn shutdown(&self) -> Result<()> {
        let guests = {
            let mut sessions = self.sessions.lock().await;
            // A graceful owner shutdown invalidates any in-flight admission;
            // a later owner must not inherit an ephemeral permission to use
            // a persisted session root.
            sessions.pending.clear();
            sessions.live_guests()
        };
        let mut shutdowns = JoinSet::new();
        for guest in guests {
            shutdowns.spawn(async move {
                let result = shutdown_guest(&guest).await;
                (guest, result)
            });
        }
        let mut failures = Vec::new();
        while let Some(completed) = shutdowns.join_next().await {
            match completed {
                Ok((guest, Ok(()))) => {
                    let reusable = self.replace_guest_with_stopped(&guest).await;
                    if let Some((attachment, false)) = reusable {
                        for cleanup in [
                            self.recovery.remove_session(&attachment).await,
                            self.handoff.cleanup_empty_session(&attachment).await,
                        ] {
                            if let Err(error) = cleanup {
                                failures.push(error.to_string());
                            }
                        }
                    }
                }
                Ok((_guest, Err(error))) => failures.push(error.to_string()),
                Err(error) => failures.push(format!("utility-VM shutdown task failed: {error}")),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to shut down or clean {} utility VM session(s): {}",
                    failures.len(),
                    failures.join("; ")
                ),
            )
            .for_operation("shutdown-utility-vm-runtime-driver"))
        }
    }

    /// Number of driver-owned utility VMs, including retained empty sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.lock().await.active_guest_count()
    }
}

#[async_trait]
impl RuntimeDriver for UtilityVmRuntimeDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    fn linux_support(&self) -> Result<a3s_oci_sdk::OciLinuxSupport> {
        a3s_oci_sdk::OciLinuxSupport::shared_executor()
    }

    fn operations(&self) -> &[RuntimeOperation] {
        &AGENT_DRIVER_OPERATIONS
    }

    fn hooks(&self) -> &[OciHookPhase] {
        &AGENT_DRIVER_HOOKS
    }

    fn attachment_capabilities(&self) -> AttachmentCapabilities {
        self.attachment_capabilities.clone()
    }

    async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        let guests = self.sessions.lock().await.live_guests();
        for guest in guests {
            guest.client.acknowledge_operation(operation_id).await?;
        }
        Ok(())
    }

    async fn prepare_create_bundle(&self, request: &DriverCreateRequest) -> Result<OciBundle> {
        self.validate_create_contract(request)?;
        let gate = self.create_gate_for(&request.target.id).await;
        let _guard = gate.lock().await;
        let session_gate = match request.attachment_contract.guest_session() {
            Some(session) => Some(self.session_gate_for(session.id()).await),
            None => None,
        };
        let _session_guard = match session_gate.as_ref() {
            Some(gate) => Some(gate.lock().await),
            None => None,
        };
        if let Some(session) = request.attachment_contract.guest_session() {
            self.preflight_session_admission(&request.target, session)
                .await?;
            // Record the admission before touching the filesystem.  The
            // marker is intentionally process-local; if this owner exits
            // during the handoff, a replacement will reject the persisted
            // session root instead of launching a second guest under the
            // same logical identity.
            self.remember_pending_session(&request.target, session)
                .await?;
        }
        match self.handoff.prepare(request).await {
            Ok(bundle) => Ok(bundle),
            Err(error) if error.retryable => Err(error),
            Err(error) => {
                if let Some(session) = request.attachment_contract.guest_session() {
                    self.clear_pending_session(&request.target, session).await;
                }
                Err(error)
            }
        }
    }

    async fn recover(&self, record: &ContainerRecord) -> Result<crate::DriverRecovery> {
        let target =
            ContainerTarget::exact(ContainerId::new(record.state.id())?, record.generation);
        let guest_session = record.guest_session.as_ref();
        if (record.isolation == IsolationClass::SharedGuestKernel) != guest_session.is_some() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "durable container {} has inconsistent shared-guest isolation evidence",
                    target.id
                ),
            )
            .for_operation("utility-vm-recover"));
        }

        if *record.state.status() == a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating {
            // An interrupted durable Create must resume through its original
            // operation. Wait for any owner-death report handoff to settle so
            // the replacement owner cannot race the old shim, but never
            // convert the active create intent into a stopped attachment.
            self.recovery
                .recover(&target, record, guest_session)
                .await?;
            let mut sessions = self.sessions.lock().await;
            if let Some(attachment) = sessions.attachments.get(&target.id) {
                if attachment.target() != &target {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        format!(
                            "container {} is attached at generation {:?}, not durable generation {:?}",
                            target.id,
                            attachment.target().generation,
                            target.generation
                        ),
                    )
                    .for_operation("utility-vm-recover"));
                }
                if attachment.guest_session() != guest_session {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        format!(
                            "container {} has a different utility-VM guest-session binding than durable state",
                            target.id
                        ),
                    )
                    .for_operation("utility-vm-recover"));
                }
                if matches!(attachment, UtilityVmAttachment::RecoveredStopped { .. }) {
                    sessions.attachments.remove(&target.id);
                }
            }
            return Ok(crate::DriverRecovery::none());
        }

        let attachment = {
            let mut sessions = self.sessions.lock().await;
            let recovered = UtilityVmAttachment::RecoveredStopped {
                target: target.clone(),
                guest_session: record.guest_session.clone(),
                init_exit_status: None,
            };
            sessions
                .attachments
                .entry(target.id.clone())
                .or_insert_with(|| recovered.clone())
                .clone()
        };
        if attachment.target() != &target {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} is attached at generation {:?}, not durable generation {:?}",
                    target.id,
                    attachment.target().generation,
                    target.generation
                ),
            )
            .for_operation("utility-vm-recover"));
        }
        if attachment.guest_session() != guest_session {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!(
                    "container {} has a different utility-VM guest-session binding than durable state",
                    target.id
                ),
            )
            .for_operation("utility-vm-recover"));
        }
        match attachment {
            UtilityVmAttachment::Live(container) => {
                let observed = container
                    .guest
                    .client
                    .state_with_digest(target, Some(&record.config_digest))
                    .await?;
                Ok(crate::DriverRecovery::observed(observed))
            }
            UtilityVmAttachment::RecoveredStopped { .. } => {
                let recovery = self
                    .recovery
                    .recover(&target, record, guest_session)
                    .await?;
                let init_exit_status = recovery.clone().into_parts().1;
                let mut sessions = self.sessions.lock().await;
                sessions.attachments.insert(
                    target.id.clone(),
                    UtilityVmAttachment::RecoveredStopped {
                        target,
                        guest_session: record.guest_session.clone(),
                        init_exit_status,
                    },
                );
                Ok(recovery)
            }
        }
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.validate_create_contract(&request)?;
        let guest_session = request.attachment_contract.guest_session().cloned();
        let guest_directory = self
            .handoff
            .guest_bundle_path(
                &request.target,
                request.bundle.directory(),
                guest_session.as_ref(),
            )
            .await?;
        let target = request.target.clone();
        let gate = self.create_gate_for(&target.id).await;
        let _guard = gate.lock().await;
        let session_gate = match guest_session.as_ref() {
            Some(session) => Some(self.session_gate_for(session.id()).await),
            None => None,
        };
        let _session_guard = match session_gate.as_ref() {
            Some(gate) => Some(gate.lock().await),
            None => None,
        };
        let existing = match self
            .existing_create_session(&target, guest_session.as_ref())
            .await
        {
            Ok(existing) => existing,
            Err(mut error) => {
                if !error.retryable {
                    if let Some(binding) = guest_session.as_ref() {
                        self.clear_pending_session(&target, binding).await;
                    }
                    let remove_session = match guest_session.as_ref() {
                        Some(binding) => self.session_root_is_unowned(binding).await,
                        None => true,
                    };
                    if let Err(cleanup) = self
                        .handoff
                        .cleanup(&target, guest_session.as_ref(), remove_session)
                        .await
                    {
                        error.message = format!(
                            "{}; failed to remove rejected exact-generation handoff: {}",
                            error.message, cleanup
                        );
                    }
                }
                return Err(error);
            }
        };
        let container = match existing {
            Some(container) => {
                if let Some(binding) = guest_session.as_ref() {
                    self.clear_pending_session(&target, binding).await;
                }
                container
            }
            None => match self
                .admit_new_container(
                    &target,
                    &request.bundle,
                    &guest_directory,
                    &request.attachment_contract,
                )
                .await
            {
                Ok(container) => container,
                Err(error) if error.retryable => return Err(error),
                Err(mut error) => {
                    if let Some(binding) = guest_session.as_ref() {
                        self.clear_pending_session(&target, binding).await;
                    }
                    let remove_session = match guest_session.as_ref() {
                        Some(binding) => self.session_root_is_unowned(binding).await,
                        None => true,
                    };
                    if let Err(cleanup) = self
                        .handoff
                        .cleanup(&target, guest_session.as_ref(), remove_session)
                        .await
                    {
                        error.message = format!(
                            "{}; failed to remove runtime-owned utility-VM bundle: {}",
                            error.message, cleanup
                        );
                    }
                    return Err(error);
                }
            },
        };
        if let Some(binding) = guest_session.as_ref() {
            self.clear_pending_session(&target, binding).await;
        }
        match container
            .guest
            .client
            .create(request, guest_directory)
            .await
        {
            Ok(state) => Ok(state),
            Err(error) if error.retryable => Err(error),
            Err(error) => Err(self.cleanup_terminal_create(&container, error).await),
        }
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        match self.attachment_for(&target, "utility-vm-state").await? {
            UtilityVmAttachment::Live(container) => container.guest.client.state(target).await,
            UtilityVmAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-start")
            .await?
            .guest
            .client
            .start(request)
            .await
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        match self
            .attachment_for(&request.target, "utility-vm-kill")
            .await?
        {
            UtilityVmAttachment::Live(container) => container.guest.client.kill(request).await,
            UtilityVmAttachment::RecoveredStopped { .. } => Ok(DriverState::stopped()),
        }
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        let initial = self
            .attachment_for(&request.target, "utility-vm-delete")
            .await?;
        let guest_session = initial.guest_session().cloned();
        let target = request.target.clone();
        let gate = self.create_gate_for(&target.id).await;
        let _guard = gate.lock().await;
        let session_gate = match guest_session.as_ref() {
            Some(session) => Some(self.session_gate_for(session.id()).await),
            None => None,
        };
        let _session_guard = match session_gate.as_ref() {
            Some(gate) => Some(gate.lock().await),
            None => None,
        };

        match self.attachment_for(&target, "utility-vm-delete").await? {
            UtilityVmAttachment::Live(container) => {
                let remove_guest = match container.guest_session.as_ref() {
                    None => true,
                    Some(binding) => {
                        let sessions = self.sessions.lock().await;
                        let session = sessions.reusable.get(binding.id()).ok_or_else(|| {
                            Error::new(
                                ErrorCode::FailedPrecondition,
                                format!(
                                    "container {} has no reusable guest-session owner",
                                    target.id
                                ),
                            )
                            .for_operation("utility-vm-delete")
                        })?;
                        if session.attachment != *binding
                            || !session.members.contains_key(&target.id)
                            || !Arc::ptr_eq(&session.guest, &container.guest)
                        {
                            return Err(Error::new(
                                ErrorCode::Conflict,
                                format!(
                                    "container {} reusable guest-session membership drifted",
                                    target.id
                                ),
                            )
                            .for_operation("utility-vm-delete"));
                        }
                        session.members.len() == 1
                            && binding.reset() == GuestSessionReset::DestroyOnEmpty
                    }
                };

                container.guest.client.delete(request).await?;
                if remove_guest {
                    shutdown_guest(&container.guest).await?;
                }
                {
                    let mut sessions = self.sessions.lock().await;
                    if matches!(
                        sessions.attachments.get(&target.id),
                        Some(UtilityVmAttachment::Live(current)) if Arc::ptr_eq(current, &container)
                    ) {
                        sessions.attachments.insert(
                            target.id.clone(),
                            UtilityVmAttachment::RecoveredStopped {
                                target: target.clone(),
                                guest_session: container.guest_session.clone(),
                                init_exit_status: None,
                            },
                        );
                    }
                    if let Some(binding) = container.guest_session.as_ref() {
                        if let Some(session) = sessions.reusable.get_mut(binding.id()) {
                            session.members.remove(&target.id);
                        }
                        if remove_guest {
                            sessions.reusable.remove(binding.id());
                        }
                    }
                }

                match container.guest_session.as_ref() {
                    Some(binding) if remove_guest => {
                        self.recovery.remove_session(binding).await?;
                    }
                    Some(_) => {}
                    None => self.recovery.remove(&target, None).await?,
                }
                self.handoff
                    .cleanup(&target, container.guest_session.as_ref(), remove_guest)
                    .await?;
                self.remove_stopped(&target).await;
                Ok(())
            }
            UtilityVmAttachment::RecoveredStopped {
                target,
                guest_session,
                ..
            } => {
                let remove_session = match guest_session.as_ref() {
                    Some(binding) => {
                        let sessions = self.sessions.lock().await;
                        !sessions.reusable.contains_key(binding.id())
                            && sessions.attachment_count_for_session(binding) == 1
                    }
                    None => true,
                };
                match guest_session.as_ref() {
                    Some(binding) if remove_session => {
                        self.recovery.remove_session(binding).await?;
                    }
                    Some(_) => {}
                    None => self.recovery.remove(&target, None).await?,
                }
                self.handoff
                    .cleanup(&target, guest_session.as_ref(), remove_session)
                    .await?;
                self.remove_stopped(&target).await;
                Ok(())
            }
        }
    }

    async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        match self
            .attachment_for(&request.target, "utility-vm-wait")
            .await?
        {
            UtilityVmAttachment::Live(container) => container.guest.client.wait(request).await,
            UtilityVmAttachment::RecoveredStopped {
                init_exit_status: Some(status),
                ..
            } => Ok(status),
            UtilityVmAttachment::RecoveredStopped { .. } => {
                Err(recovered_exit_error(&request.target, "utility-vm-wait"))
            }
        }
    }

    async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        self.live_session_for(&request.target.container, "utility-vm-exec")
            .await?
            .guest
            .client
            .exec(request)
            .await
    }

    async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-signal-process")
            .await?
            .guest
            .client
            .signal_process(request)
            .await
    }

    async fn wait_process(&self, request: DriverWaitProcessRequest) -> Result<ExitStatus> {
        self.live_session_for(&request.target.container, "utility-vm-wait-process")
            .await?
            .guest
            .client
            .wait_process(request)
            .await
    }

    async fn pause(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-pause")
            .await?
            .guest
            .client
            .pause(request)
            .await
    }

    async fn resume(&self, request: DriverContainerOperationRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-resume")
            .await?
            .guest
            .client
            .resume(request)
            .await
    }

    async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        match self.attachment_for(&target, "utility-vm-processes").await? {
            UtilityVmAttachment::Live(container) => container.guest.client.processes(target).await,
            UtilityVmAttachment::RecoveredStopped { .. } => Ok(Vec::new()),
        }
    }

    async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        self.live_session_for(&request.target, "utility-vm-update")
            .await?
            .guest
            .client
            .update(request)
            .await
    }

    async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        self.live_session_for(&target, "utility-vm-stats")
            .await?
            .guest
            .client
            .stats(target)
            .await
    }

    async fn read_output(&self, request: DriverReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.live_session_for(&request.target.container, "utility-vm-read-output")
            .await?
            .guest
            .client
            .read_output(request)
            .await
    }

    async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-write-stdin")
            .await?
            .guest
            .client
            .write_stdin(request)
            .await
    }

    async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-close-stdin")
            .await?
            .guest
            .client
            .close_stdin(request)
            .await
    }

    async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.live_session_for(&request.target.container, "utility-vm-resize")
            .await?
            .guest
            .client
            .resize(request)
            .await
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.live_session_for(&request.target, "utility-vm-file")
            .await?
            .guest
            .client
            .file(request)
            .await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.live_session_for(&request.target, "utility-vm-filesystem")
            .await?
            .guest
            .client
            .filesystem(request)
            .await
    }
}

pub(crate) struct LaunchedUtilityVm {
    pub(crate) client: AgentDriverClient,
    pub(crate) owner: Arc<dyn UtilityVmOwner>,
}

pub(crate) struct UtilityVmLaunchRequest<'a> {
    pub(crate) target: &'a ContainerTarget,
    pub(crate) runtime_share: &'a Path,
    pub(crate) bundle: &'a OciBundle,
    pub(crate) guest_bundle: &'a GuestPath,
    pub(crate) attachment_contract: &'a CreateAttachments,
}

impl UtilityVmLaunchRequest<'_> {
    fn validate(&self) -> Result<()> {
        self.attachment_contract.validate(self.bundle)?;
        let prefix = format!("{AGENT_RUNTIME_SHARE_GUEST_ROOT}/");
        let relative = self
            .guest_bundle
            .as_str()
            .strip_prefix(&prefix)
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "utility-VM Guest bundle must remain below {AGENT_RUNTIME_SHARE_GUEST_ROOT}: {}",
                        self.guest_bundle.as_str()
                    ),
                )
                .for_operation("validate-utility-vm-launch")
            })?;
        let expected_bundle = self.runtime_share.join(relative);
        if expected_bundle != self.bundle.directory() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "utility-VM Guest bundle {} maps to {}, not exact Host bundle {}",
                    self.guest_bundle.as_str(),
                    expected_bundle.display(),
                    self.bundle.directory().display()
                ),
            )
            .for_operation("validate-utility-vm-launch"));
        }
        Ok(())
    }
}

#[async_trait]
pub(crate) trait UtilityVmFactory: Send + Sync {
    async fn launch(&self, request: UtilityVmLaunchRequest<'_>) -> Result<LaunchedUtilityVm>;
}

#[async_trait]
pub(crate) trait UtilityVmOwner: Send + Sync {
    async fn shutdown(&self) -> Result<()>;
}

async fn shutdown_guest(guest: &UtilityVmGuest) -> Result<()> {
    guest.owner.shutdown().await
}

fn session_conflict(
    requested: &GuestSessionAttachment,
    retained: &GuestSessionAttachment,
    reason: &str,
) -> Error {
    Error::new(
        ErrorCode::Conflict,
        format!(
            "reusable guest session {} requested generation {}, but retained generation {} cannot be replaced because {reason}",
            requested.id(),
            requested.generation(),
            retained.generation()
        ),
    )
    .for_operation("utility-vm-create")
}

fn orphaned_session_error(binding: &GuestSessionAttachment, root: &Path) -> Error {
    Error::new(
        ErrorCode::Conflict,
        format!(
            "reusable guest session {} has an unowned persisted root {}; refusing to launch another guest until the previous incarnation is recovered or deleted",
            binding.id(),
            root.display()
        ),
    )
    .for_operation("utility-vm-create")
}

fn recovered_stopped_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was recovered as stopped after its utility-VM owner exited; delete this generation before another live operation",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}

fn recovered_exit_error(target: &ContainerTarget, operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "container {} generation {:?} was stopped by utility-VM owner-death cleanup, but its exact init exit status was not retained",
            target.id, target.generation
        ),
    )
    .for_operation(operation)
}
