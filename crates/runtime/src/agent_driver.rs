use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Weak};

#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use a3s_oci_agent_protocol::{AgentBundle, AgentCreateRequest, GuestPath};
use a3s_oci_agent_protocol::{
    AgentCloseStdinRequest, AgentContainerOperationRequest, AgentDeleteRequest, AgentExecRequest,
    AgentKillRequest, AgentProcessesRequest, AgentReadOutputRequest, AgentResizeRequest,
    AgentSignalProcessRequest, AgentStartRequest, AgentState, AgentStateRequest, AgentStatsRequest,
    AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest, AgentWriteStdinRequest,
    GuestAgentService, AGENT_MAX_IO_PAYLOAD_BYTES,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use a3s_oci_sdk::RuntimeOperation;
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, Error, ErrorCode, ExitStatus, FileRequest, FileResponse,
    FilesystemRequest, FilesystemResponse, OperationContext, OperationId, OutputChunk,
    ProcessRecord, Result,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedMutexGuard};

#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use crate::driver::DriverCreateRequest;
#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use crate::driver::OciHookPhase;
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverDeleteRequest,
    DriverExecRequest, DriverKillRequest, DriverProcess, DriverReadOutputRequest,
    DriverResizeRequest, DriverSignalProcessRequest, DriverStartRequest, DriverState,
    DriverUpdateRequest, DriverWaitProcessRequest, DriverWaitRequest, DriverWriteStdinRequest,
};

#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
pub(crate) const AGENT_DRIVER_OPERATIONS: [RuntimeOperation; 20] = [
    RuntimeOperation::Create,
    RuntimeOperation::State,
    RuntimeOperation::Start,
    RuntimeOperation::Kill,
    RuntimeOperation::Delete,
    RuntimeOperation::Wait,
    RuntimeOperation::Exec,
    RuntimeOperation::SignalProcess,
    RuntimeOperation::WaitProcess,
    RuntimeOperation::Pause,
    RuntimeOperation::Resume,
    RuntimeOperation::Processes,
    RuntimeOperation::Update,
    RuntimeOperation::Stats,
    RuntimeOperation::ReadOutput,
    RuntimeOperation::WriteStdin,
    RuntimeOperation::CloseStdin,
    RuntimeOperation::Resize,
    RuntimeOperation::File,
    RuntimeOperation::Filesystem,
];

#[cfg(any(
    target_os = "linux",
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
pub(crate) const AGENT_DRIVER_HOOKS: [OciHookPhase; 6] = OciHookPhase::ALL;

/// Single-flights acknowledgement of one Host operation identity.
///
/// A chunked process-I/O mutation can retain several Guest operation IDs. If
/// two Host owners acknowledge the same operation concurrently, one caller
/// must not observe the temporary absence of that mapping and acknowledge only
/// the parent ID. The weak map keeps the coordination state bounded after the
/// operation completes.
#[derive(Default)]
struct AcknowledgementGates {
    entries: Mutex<BTreeMap<OperationId, Weak<Mutex<()>>>>,
}

impl AcknowledgementGates {
    async fn acquire(&self, operation_id: &OperationId) -> OwnedMutexGuard<()> {
        let gate = {
            let mut entries = self.entries.lock().await;
            entries.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = entries.get(operation_id).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(Mutex::new(()));
                entries.insert(operation_id.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        gate.lock_owned().await
    }
}

/// Driver-facing mapping around either an in-process executor or one
/// authenticated utility-VM connection.
#[derive(Clone)]
pub(crate) struct AgentDriverClient {
    service: Arc<dyn GuestAgentService>,
    source: &'static str,
    mapping_scope: &'static str,
    guest_operation_ids: Arc<Mutex<BTreeMap<OperationId, Vec<OperationId>>>>,
    acknowledgement_gates: Arc<AcknowledgementGates>,
}

impl fmt::Debug for AgentDriverClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentDriverClient")
            .field("source", &self.source)
            .field("mapping_scope", &self.mapping_scope)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(all(target_os = "macos", target_arch = "aarch64"), allow(dead_code))]
impl AgentDriverClient {
    pub(crate) fn new(
        service: Arc<dyn GuestAgentService>,
        source: &'static str,
        mapping_scope: &'static str,
    ) -> Self {
        Self {
            service,
            source,
            mapping_scope,
            guest_operation_ids: Arc::new(Mutex::new(BTreeMap::new())),
            acknowledgement_gates: Arc::new(AcknowledgementGates::default()),
        }
    }

    pub(crate) async fn acknowledge_operation(&self, operation_id: &OperationId) -> Result<()> {
        // Keep the derived-ID mapping coupled to the acknowledgement request.
        // Without this guard, concurrent callers can race between removing the
        // mapping and sending the Guest acknowledgement, causing one caller to
        // fall back to the parent ID and leave chunk records retained.  Read
        // the mapping first and remove it only after the Guest call succeeds:
        // cancellation must leave the exact derived identities available for
        // the caller's retry.
        let _gate = self.acknowledgement_gates.acquire(operation_id).await;
        let guest_operation_ids = self
            .guest_operation_ids
            .lock()
            .await
            .get(operation_id)
            .cloned()
            .unwrap_or_else(|| vec![operation_id.clone()]);
        self.service
            .acknowledge_operations(&guest_operation_ids)
            .await?;

        // Do not remove a mapping that was changed by a future extension of
        // the dispatch path while the Guest call was in flight.  Today the
        // per-operation gate already serializes those paths, but retaining
        // this equality check makes the ownership rule explicit and keeps a
        // successful retry idempotent if that implementation evolves.
        let mut retained = self.guest_operation_ids.lock().await;
        if retained
            .get(operation_id)
            .is_some_and(|existing| existing == &guest_operation_ids)
        {
            retained.remove(operation_id);
        }
        Ok(())
    }

    async fn retain_guest_operation_ids(
        &self,
        operation_id: &OperationId,
        guest_operation_ids: &[OperationId],
    ) -> Result<()> {
        let mut retained = self.guest_operation_ids.lock().await;
        match retained.get(operation_id) {
            Some(existing) if existing == guest_operation_ids => Ok(()),
            Some(_) => Err(self.mapping_error(
                ErrorCode::Conflict,
                "operation-acknowledgement",
                format!(
                    "Host operation {operation_id} changed its derived guest operation identities"
                ),
            )),
            None => {
                retained.insert(operation_id.clone(), guest_operation_ids.to_vec());
                Ok(())
            }
        }
    }

    #[cfg(any(
        target_os = "linux",
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    pub(crate) async fn create(
        &self,
        request: DriverCreateRequest,
        guest_directory: GuestPath,
    ) -> Result<DriverState> {
        if !request.attachments.is_empty() {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "{} cannot receive native inherited descriptors",
                    self.source
                ),
            )
            .for_operation("agent-driver-create"));
        }
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .service
            .create(AgentCreateRequest {
                context: request.context,
                target: request.target,
                bundle: AgentBundle::new(&request.bundle, guest_directory),
                io: request.io,
            })
            .await?;
        self.map_state(&expected_target, Some(&expected_digest), state)
    }

    pub(crate) async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.state_with_digest(target, None).await
    }

    pub(crate) async fn state_with_digest(
        &self,
        target: ContainerTarget,
        expected_digest: Option<&str>,
    ) -> Result<DriverState> {
        let state = self
            .service
            .state(AgentStateRequest {
                target: target.clone(),
            })
            .await?;
        self.map_state(&target, expected_digest, state)
    }

    pub(crate) async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let expected_digest = request.bundle.config_digest().to_string();
        let state = self
            .service
            .start(AgentStartRequest {
                context: request.context,
                target: request.target,
                expected_config_digest: expected_digest.clone(),
            })
            .await?;
        self.map_state(&expected_target, Some(&expected_digest), state)
    }

    pub(crate) async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .kill(AgentKillRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
                all: request.all,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.service
            .delete(AgentDeleteRequest {
                context: request.context,
                target: request.target,
                mode: request.mode,
            })
            .await
    }

    pub(crate) async fn wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        self.service
            .wait(AgentWaitRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    pub(crate) async fn exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        let expected_target = request.target.clone();
        let expected_terminal = request.process.terminal().unwrap_or(false);
        let process = self
            .service
            .exec(AgentExecRequest {
                context: request.context,
                target: request.target,
                process: request.process,
                io: request.io,
            })
            .await?;
        if process.target() != &expected_target {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "process",
                format!("{} returned a different process target", self.source),
            ));
        }
        if process.terminal() != expected_terminal {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "process",
                format!("{} returned a different process terminal mode", self.source),
            ));
        }
        DriverProcess::new(process.pid(), process.terminal())
    }

    pub(crate) async fn signal_process(&self, request: DriverSignalProcessRequest) -> Result<()> {
        self.service
            .signal_process(AgentSignalProcessRequest {
                context: request.context,
                target: request.target,
                signal: request.signal,
            })
            .await
    }

    pub(crate) async fn wait_process(
        &self,
        request: DriverWaitProcessRequest,
    ) -> Result<ExitStatus> {
        self.service
            .wait_process(AgentWaitProcessRequest {
                target: request.target,
                timeout_ms: request.timeout_ms,
            })
            .await
    }

    pub(crate) async fn pause(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .pause(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn resume(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .resume(AgentContainerOperationRequest {
                context: request.context,
                target: request.target,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn processes(&self, target: ContainerTarget) -> Result<Vec<ProcessRecord>> {
        self.service
            .processes(AgentProcessesRequest { target })
            .await
    }

    pub(crate) async fn update(&self, request: DriverUpdateRequest) -> Result<DriverState> {
        let expected_target = request.target.clone();
        let state = self
            .service
            .update(AgentUpdateRequest {
                context: request.context,
                target: request.target,
                resources: request.resources,
            })
            .await?;
        self.map_state(&expected_target, None, state)
    }

    pub(crate) async fn stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        let stats = self
            .service
            .stats(AgentStatsRequest {
                target: target.clone(),
            })
            .await?;
        if stats.target != target {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "stats",
                format!(
                    "{} returned stats for a different container generation",
                    self.source
                ),
            ));
        }
        stats.validate()?;
        Ok(stats)
    }

    pub(crate) async fn read_output(
        &self,
        request: DriverReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        self.service
            .read_output(AgentReadOutputRequest {
                process: request.target,
                after_sequence: request.after_sequence,
                max_bytes: request.max_bytes.min(AGENT_MAX_IO_PAYLOAD_BYTES),
                wait_timeout_ms: request.wait_timeout_ms,
            })
            .await
    }

    pub(crate) async fn write_stdin(&self, request: DriverWriteStdinRequest) -> Result<()> {
        // Hold the same per-operation gate as acknowledgement so a Host
        // reconnect cannot acknowledge a chunked mutation before all derived
        // Guest writes have been dispatched.
        let _gate = self
            .acknowledgement_gates
            .acquire(&request.context.operation_id)
            .await;
        if request.data.is_empty() {
            return self
                .service
                .write_stdin(AgentWriteStdinRequest {
                    context: Some(request.context),
                    process: request.target,
                    data: Vec::new(),
                })
                .await;
        }
        let chunk_bytes = AGENT_MAX_IO_PAYLOAD_BYTES as usize;
        let chunk_count = request.data.len().div_ceil(chunk_bytes);
        let contexts = (0..chunk_count)
            .map(|index| {
                if chunk_count == 1 {
                    Ok(request.context.clone())
                } else {
                    process_io_chunk_context(&request.context, index)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        if chunk_count > 1 {
            let guest_operation_ids = contexts
                .iter()
                .map(|context| context.operation_id.clone())
                .collect::<Vec<_>>();
            self.retain_guest_operation_ids(&request.context.operation_id, &guest_operation_ids)
                .await?;
        }
        for (context, data) in contexts.into_iter().zip(request.data.chunks(chunk_bytes)) {
            self.service
                .write_stdin(AgentWriteStdinRequest {
                    context: Some(context),
                    process: request.target.clone(),
                    data: data.to_vec(),
                })
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn close_stdin(&self, request: DriverCloseStdinRequest) -> Result<()> {
        self.service
            .close_stdin(AgentCloseStdinRequest {
                context: Some(request.context),
                process: request.target,
            })
            .await
    }

    pub(crate) async fn resize(&self, request: DriverResizeRequest) -> Result<()> {
        self.service
            .resize(AgentResizeRequest {
                context: Some(request.context),
                process: request.target,
                size: request.size,
            })
            .await
    }

    pub(crate) async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.service.file(request).await
    }

    pub(crate) async fn filesystem(
        &self,
        request: FilesystemRequest,
    ) -> Result<FilesystemResponse> {
        self.service.filesystem(request).await
    }

    pub(crate) fn map_state(
        &self,
        expected_target: &ContainerTarget,
        expected_digest: Option<&str>,
        state: AgentState,
    ) -> Result<DriverState> {
        if state.target() != expected_target {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "state",
                format!("{} returned a different container generation", self.source),
            ));
        }
        if expected_digest.is_some_and(|digest| state.config_digest() != digest) {
            return Err(self.mapping_error(
                ErrorCode::Conflict,
                "state",
                format!("{} returned a different configuration digest", self.source),
            ));
        }
        let mapped = match state.status() {
            ContainerState::Created => DriverState::created(self.required_pid(&state)?),
            ContainerState::Running => DriverState::running(self.required_pid(&state)?),
            ContainerState::Stopped => Ok(DriverState::stopped()),
            status => Err(self.mapping_error(
                ErrorCode::Internal,
                "state",
                format!("{} returned invalid lifecycle state {status}", self.source),
            )),
        }?;
        mapped.with_paused(state.paused())
    }

    fn required_pid(&self, state: &AgentState) -> Result<i32> {
        state.pid().ok_or_else(|| {
            self.mapping_error(
                ErrorCode::Internal,
                "state",
                format!(
                    "{} returned {} without an init PID",
                    self.source,
                    state.status()
                ),
            )
        })
    }

    fn mapping_error(
        &self,
        code: ErrorCode,
        subject: &'static str,
        message: impl Into<String>,
    ) -> Error {
        Error::new(code, message).for_operation(format!("map-{}-{subject}", self.mapping_scope))
    }
}

fn process_io_chunk_context(parent: &OperationContext, index: usize) -> Result<OperationContext> {
    let index = u64::try_from(index).map_err(|error| {
        Error::new(
            ErrorCode::ResourceExhausted,
            format!("stdin chunk index does not fit the guest journal: {error}"),
        )
        .for_operation("derive-stdin-chunk-operation")
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"a3s-oci-stdin-chunk-v1\0");
    hasher.update(parent.operation_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(index.to_be_bytes());
    let operation_id = OperationId::new(format!("io.{:x}", hasher.finalize()))?;
    Ok(OperationContext {
        operation_id,
        deadline_unix_ms: parent.deadline_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;

    use a3s_oci_agent_protocol::{
        AgentCapabilities, AgentState, AgentWriteStdinRequest, GuestAgentService,
        AGENT_MAX_IO_PAYLOAD_BYTES,
    };
    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::{
        async_trait, ContainerId, ContainerTarget, Error, Generation, OperationContext,
        OperationId, ProcessId, ProcessTarget, Result, RuntimeOperation,
    };
    use tokio::sync::Notify;

    use crate::driver::DriverWriteStdinRequest;

    use super::{process_io_chunk_context, AgentDriverClient, AGENT_DRIVER_OPERATIONS};

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OTHER_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn production_agent_driver_contract_does_not_claim_tee_attestation() {
        assert!(!AGENT_DRIVER_OPERATIONS.contains(&RuntimeOperation::Attest));
    }

    #[derive(Default)]
    struct MappingOnlyGuest {
        writes: StdMutex<Vec<OperationId>>,
        acknowledgements: StdMutex<Vec<Vec<OperationId>>>,
        ack_control: Option<Arc<AcknowledgementControl>>,
    }

    struct AcknowledgementControl {
        calls: AtomicUsize,
        fail_first: AtomicBool,
        first_started: Notify,
        release_first: Notify,
        second_started: Notify,
    }

    #[async_trait]
    impl GuestAgentService for MappingOnlyGuest {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::linux_executor("test", "x86_64").expect("capabilities")
        }

        async fn acknowledge_operations(&self, operation_ids: &[OperationId]) -> Result<()> {
            self.acknowledgements
                .lock()
                .expect("acknowledgement capture")
                .push(operation_ids.to_vec());
            if let Some(control) = &self.ack_control {
                match control.calls.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        control.first_started.notify_one();
                        control.release_first.notified().await;
                        if control.fail_first.swap(false, Ordering::SeqCst) {
                            return Err(Error::new(
                                a3s_oci_sdk::ErrorCode::Unavailable,
                                "injected acknowledgement failure",
                            ));
                        }
                    }
                    1 => control.second_started.notify_one(),
                    _ => {}
                }
            }
            Ok(())
        }

        async fn create(
            &self,
            _request: a3s_oci_agent_protocol::AgentCreateRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-create"))
        }

        async fn state(
            &self,
            _request: a3s_oci_agent_protocol::AgentStateRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-state"))
        }

        async fn start(
            &self,
            _request: a3s_oci_agent_protocol::AgentStartRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-start"))
        }

        async fn kill(
            &self,
            _request: a3s_oci_agent_protocol::AgentKillRequest,
        ) -> Result<AgentState> {
            Err(Error::unsupported("mapping-test-kill"))
        }

        async fn delete(&self, _request: a3s_oci_agent_protocol::AgentDeleteRequest) -> Result<()> {
            Err(Error::unsupported("mapping-test-delete"))
        }

        async fn write_stdin(&self, request: AgentWriteStdinRequest) -> Result<()> {
            self.writes.lock().expect("write capture").push(
                request
                    .context
                    .expect("protocol-v8 write context")
                    .operation_id,
            );
            Ok(())
        }
    }

    fn client() -> AgentDriverClient {
        AgentDriverClient::new(
            Arc::new(MappingOnlyGuest::default()),
            "test guest",
            "test-agent",
        )
    }

    #[test]
    fn maps_exact_created_running_and_stopped_states() {
        let target = ContainerTarget::exact(
            ContainerId::new("agent-test").expect("container ID"),
            Generation(1),
        );
        for (status, pid) in [
            (ContainerState::Created, Some(101)),
            (ContainerState::Running, Some(101)),
            (ContainerState::Stopped, None),
        ] {
            let state = AgentState::new(target.clone(), status, pid, DIGEST).expect("agent state");
            let mapped = client()
                .map_state(&target, Some(DIGEST), state)
                .expect("mapped driver state");
            assert_eq!(mapped.status(), status);
            assert_eq!(mapped.pid(), pid);
            assert!(!mapped.paused());
        }

        let paused = AgentState::new_with_pause(
            target.clone(),
            ContainerState::Running,
            Some(101),
            DIGEST,
            true,
        )
        .expect("paused agent state");
        assert!(client()
            .map_state(&target, Some(DIGEST), paused)
            .expect("mapped paused driver state")
            .paused());
    }

    #[test]
    fn rejects_a_mismatched_generation_or_digest() {
        let target = ContainerTarget::exact(
            ContainerId::new("agent-test").expect("container ID"),
            Generation(1),
        );
        let other = ContainerTarget::exact(target.id.clone(), Generation(2));
        let state =
            AgentState::new(other, ContainerState::Created, Some(101), DIGEST).expect("state");
        assert!(client().map_state(&target, Some(DIGEST), state).is_err());

        let state = AgentState::new(
            target.clone(),
            ContainerState::Created,
            Some(101),
            OTHER_DIGEST,
        )
        .expect("agent state");
        assert!(client().map_state(&target, Some(DIGEST), state).is_err());
    }

    #[test]
    fn derives_stable_distinct_chunk_operation_contexts() {
        let parent = OperationContext {
            operation_id: OperationId::new("stdin-parent").expect("operation ID"),
            deadline_unix_ms: Some(42),
        };
        let first = process_io_chunk_context(&parent, 0).expect("first chunk context");
        let first_replay =
            process_io_chunk_context(&parent, 0).expect("replayed first chunk context");
        let second = process_io_chunk_context(&parent, 1).expect("second chunk context");
        let other_parent = OperationContext::new(
            OperationId::new("other-stdin-parent").expect("other operation ID"),
        );
        let other = process_io_chunk_context(&other_parent, 0).expect("other chunk context");

        assert_eq!(first, first_replay);
        assert_ne!(first.operation_id, second.operation_id);
        assert_ne!(first.operation_id, other.operation_id);
        assert_eq!(first.deadline_unix_ms, parent.deadline_unix_ms);
        assert!(first.operation_id.as_str().starts_with("io."));
    }

    #[tokio::test]
    async fn host_acknowledgement_releases_every_derived_stdin_chunk_identity() {
        let guest = Arc::new(MappingOnlyGuest::default());
        let client = AgentDriverClient::new(guest.clone(), "test guest", "test-agent");
        let context = OperationContext::new(
            OperationId::new("chunked-stdin-parent").expect("parent operation ID"),
        );
        let target = ProcessTarget {
            container: ContainerTarget::exact(
                ContainerId::new("chunked-stdin").expect("container ID"),
                Generation(1),
            ),
            process_id: ProcessId::init(),
        };
        client
            .write_stdin(DriverWriteStdinRequest {
                context: context.clone(),
                target,
                data: vec![0x5a; AGENT_MAX_IO_PAYLOAD_BYTES as usize + 1],
            })
            .await
            .expect("dispatch chunked stdin");

        client
            .acknowledge_operation(&context.operation_id)
            .await
            .expect("acknowledge durable Host result");

        let expected = vec![
            process_io_chunk_context(&context, 0)
                .expect("first context")
                .operation_id,
            process_io_chunk_context(&context, 1)
                .expect("second context")
                .operation_id,
        ];
        assert_eq!(*guest.writes.lock().expect("captured writes"), expected);
        assert_eq!(
            *guest
                .acknowledgements
                .lock()
                .expect("captured acknowledgements"),
            vec![expected]
        );
    }

    #[tokio::test]
    async fn concurrent_acknowledgements_retry_the_same_derived_chunk_identities() {
        let control = Arc::new(AcknowledgementControl {
            calls: AtomicUsize::new(0),
            fail_first: AtomicBool::new(true),
            first_started: Notify::new(),
            release_first: Notify::new(),
            second_started: Notify::new(),
        });
        let guest = Arc::new(MappingOnlyGuest {
            writes: StdMutex::new(Vec::new()),
            acknowledgements: StdMutex::new(Vec::new()),
            ack_control: Some(Arc::clone(&control)),
        });
        let client = AgentDriverClient::new(guest.clone(), "test guest", "test-agent");
        let context = OperationContext::new(
            OperationId::new("concurrent-chunked-stdin").expect("operation ID"),
        );
        let target = ProcessTarget {
            container: ContainerTarget::exact(
                ContainerId::new("concurrent-chunked-stdin").expect("container ID"),
                Generation(1),
            ),
            process_id: ProcessId::init(),
        };
        client
            .write_stdin(DriverWriteStdinRequest {
                context: context.clone(),
                target,
                data: vec![0x5a; AGENT_MAX_IO_PAYLOAD_BYTES as usize + 1],
            })
            .await
            .expect("dispatch chunked stdin");

        let first_client = client.clone();
        let first_operation = context.operation_id.clone();
        let first =
            tokio::spawn(async move { first_client.acknowledge_operation(&first_operation).await });
        control.first_started.notified().await;

        let second_client = client.clone();
        let second_operation = context.operation_id.clone();
        let second =
            tokio::spawn(
                async move { second_client.acknowledge_operation(&second_operation).await },
            );

        // The second call must remain behind the first call's in-flight Guest
        // acknowledgement. A buggy implementation enters the Guest here and
        // acknowledges only the parent operation ID.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                control.second_started.notified(),
            )
            .await
            .is_err(),
            "duplicate acknowledgement bypassed the per-operation gate"
        );
        control.release_first.notify_one();

        assert!(first.await.expect("first acknowledgement task").is_err());
        second
            .await
            .expect("second acknowledgement task")
            .expect("retry acknowledgement");

        let expected = vec![
            process_io_chunk_context(&context, 0)
                .expect("first context")
                .operation_id,
            process_io_chunk_context(&context, 1)
                .expect("second context")
                .operation_id,
        ];
        assert_eq!(
            *guest
                .acknowledgements
                .lock()
                .expect("captured acknowledgements"),
            vec![expected.clone(), expected]
        );
    }

    #[tokio::test]
    async fn cancelled_acknowledgement_preserves_derived_chunk_identities() {
        let control = Arc::new(AcknowledgementControl {
            calls: AtomicUsize::new(0),
            fail_first: AtomicBool::new(false),
            first_started: Notify::new(),
            release_first: Notify::new(),
            second_started: Notify::new(),
        });
        let guest = Arc::new(MappingOnlyGuest {
            writes: StdMutex::new(Vec::new()),
            acknowledgements: StdMutex::new(Vec::new()),
            ack_control: Some(Arc::clone(&control)),
        });
        let client = AgentDriverClient::new(guest.clone(), "test guest", "test-agent");
        let context = OperationContext::new(
            OperationId::new("cancelled-chunked-stdin").expect("operation ID"),
        );
        let target = ProcessTarget {
            container: ContainerTarget::exact(
                ContainerId::new("cancelled-chunked-stdin").expect("container ID"),
                Generation(1),
            ),
            process_id: ProcessId::init(),
        };
        client
            .write_stdin(DriverWriteStdinRequest {
                context: context.clone(),
                target,
                data: vec![0x5a; AGENT_MAX_IO_PAYLOAD_BYTES as usize + 1],
            })
            .await
            .expect("dispatch chunked stdin");

        let operation = context.operation_id.clone();
        let first_client = client.clone();
        let first =
            tokio::spawn(async move { first_client.acknowledge_operation(&operation).await });
        control.first_started.notified().await;

        // Dropping the in-flight Guest call must not discard the derived-ID
        // mapping.  The retry below is the only acknowledgement that can
        // release both Guest chunk journals.
        first.abort();
        assert!(first
            .await
            .expect_err("cancelled acknowledgement")
            .is_cancelled());

        client
            .acknowledge_operation(&context.operation_id)
            .await
            .expect("retry acknowledgement");

        let expected = vec![
            process_io_chunk_context(&context, 0)
                .expect("first context")
                .operation_id,
            process_io_chunk_context(&context, 1)
                .expect("second context")
                .operation_id,
        ];
        assert_eq!(
            *guest
                .acknowledgements
                .lock()
                .expect("captured acknowledgements"),
            vec![expected.clone(), expected]
        );
    }
}
