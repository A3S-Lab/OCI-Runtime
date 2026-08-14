use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    CloseStdinRequest, ContainerId, ContainerOperationRequest, ContainerRecord, ContainerStats,
    ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    ExecRequest, ExitStatus, IoMode, IsolationRequest, KillRequest, LinuxResources,
    LocalIpcEndpoint, OciBundle, OperationContext, ProcessId, ProcessIo, ProcessRecord,
    ProcessTarget, ProcessesRequest, ReadOutputRequest, ResizeRequest, Result, RuntimeClient,
    Signal, SignalProcessRequest, StartRequest, StateRequest, StatsRequest, TerminalSize,
    UpdateRequest, WaitProcessRequest, WaitRequest, WriteStdinRequest,
};

use crate::identity;

const DEFAULT_TERMINAL_WIDTH: u16 = 80;
const DEFAULT_TERMINAL_HEIGHT: u16 = 24;
const DELETE_RETRY_INTERVAL: Duration = Duration::from_millis(10);
const DELETE_RETRY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskIdentity {
    pub(crate) namespace: String,
    pub(crate) task_id: String,
    pub(crate) incarnation: Option<identity::IncarnationId>,
    pub(crate) container_id: ContainerId,
}

impl TaskIdentity {
    #[cfg(test)]
    pub(crate) fn new(namespace: impl Into<String>, task_id: impl Into<String>) -> Result<Self> {
        Self::with_optional_incarnation(namespace, task_id, None)
    }

    pub(crate) fn with_incarnation(
        namespace: impl Into<String>,
        task_id: impl Into<String>,
        incarnation: identity::IncarnationId,
    ) -> Result<Self> {
        Self::with_optional_incarnation(namespace, task_id, Some(incarnation))
    }

    pub(crate) fn with_optional_incarnation(
        namespace: impl Into<String>,
        task_id: impl Into<String>,
        incarnation: Option<identity::IncarnationId>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        let task_id = task_id.into();
        if namespace.is_empty() || task_id.is_empty() {
            return Err(adapter_error(
                ErrorCode::InvalidArgument,
                "containerd namespace and task ID must be non-empty",
            ));
        }
        let container_id = identity::container_id(&namespace, &task_id)?;
        Ok(Self {
            namespace,
            task_id,
            incarnation,
            container_id,
        })
    }

    fn operation(&self, exec_id: Option<&str>, action: &str) -> Result<OperationContext> {
        identity::operation(
            &self.namespace,
            &self.task_id,
            self.incarnation.as_ref(),
            exec_id,
            action,
        )
    }

    fn process_id(&self, exec_id: &str) -> Result<ProcessId> {
        identity::process_id(&self.namespace, &self.task_id, exec_id)
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeAdapter {
    client: RuntimeClient,
    isolation: IsolationRequest,
}

impl RuntimeAdapter {
    pub(crate) async fn connect(endpoint: &str, isolation: IsolationRequest) -> Result<Self> {
        #[cfg(unix)]
        let endpoint = LocalIpcEndpoint::unix_socket(endpoint)?;
        #[cfg(windows)]
        let endpoint = LocalIpcEndpoint::windows_named_pipe(endpoint)?;
        let client = RuntimeClient::connect(&endpoint).await?;
        let features = client.features().await?;
        for required in [
            a3s_oci_sdk::RuntimeOperation::Create,
            a3s_oci_sdk::RuntimeOperation::State,
            a3s_oci_sdk::RuntimeOperation::Start,
            a3s_oci_sdk::RuntimeOperation::Kill,
            a3s_oci_sdk::RuntimeOperation::Delete,
            a3s_oci_sdk::RuntimeOperation::Wait,
            a3s_oci_sdk::RuntimeOperation::Exec,
            a3s_oci_sdk::RuntimeOperation::SignalProcess,
            a3s_oci_sdk::RuntimeOperation::WaitProcess,
            a3s_oci_sdk::RuntimeOperation::Pause,
            a3s_oci_sdk::RuntimeOperation::Resume,
            a3s_oci_sdk::RuntimeOperation::Update,
            a3s_oci_sdk::RuntimeOperation::Processes,
            a3s_oci_sdk::RuntimeOperation::Stats,
            a3s_oci_sdk::RuntimeOperation::ReadOutput,
            a3s_oci_sdk::RuntimeOperation::WriteStdin,
            a3s_oci_sdk::RuntimeOperation::CloseStdin,
            a3s_oci_sdk::RuntimeOperation::Resize,
        ] {
            if !features.operations.contains(&required) {
                return Err(adapter_error(
                    ErrorCode::Unsupported,
                    format!("runtime endpoint does not advertise required operation {required:?}"),
                ));
            }
        }
        Ok(Self { client, isolation })
    }

    pub(crate) fn with_isolation(&self, isolation: IsolationRequest) -> Self {
        Self {
            client: self.client.clone(),
            isolation,
        }
    }

    #[cfg(test)]
    pub(crate) const fn from_client(client: RuntimeClient, isolation: IsolationRequest) -> Self {
        Self { client, isolation }
    }

    pub(crate) async fn create(
        &self,
        task: &TaskIdentity,
        bundle_directory: &Path,
        io: ProcessIo,
    ) -> Result<ContainerRecord> {
        let bundle = OciBundle::load(bundle_directory).await?;
        let attachments = CreateAttachments::from_bundle(&bundle, io)?;
        self.client
            .create(CreateRequest {
                context: task.operation(None, "create")?,
                id: task.container_id.clone(),
                bundle,
                isolation: self.isolation.clone(),
                attachments,
            })
            .await
    }

    pub(crate) async fn replay_create_for_cleanup(
        &self,
        task: &TaskIdentity,
        bundle_directory: &Path,
        io: ProcessIo,
    ) -> Result<ContainerRecord> {
        let deadline = tokio::time::Instant::now() + DELETE_RETRY_TIMEOUT;
        loop {
            match self.create(task, bundle_directory, io.clone()).await {
                Ok(record) => return Ok(record),
                Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(DELETE_RETRY_INTERVAL).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn exact_state(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
    ) -> Result<ContainerRecord> {
        self.client
            .state(StateRequest {
                target: ContainerTarget::exact(task.container_id.clone(), generation),
            })
            .await
    }

    pub(crate) async fn start(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
    ) -> Result<ContainerRecord> {
        self.client
            .start(StartRequest {
                context: task.operation(None, "start")?,
                target: ContainerTarget::exact(task.container_id.clone(), generation),
            })
            .await
    }

    pub(crate) async fn kill(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        signal: i32,
        all: bool,
    ) -> Result<ContainerRecord> {
        self.client
            .kill(KillRequest {
                context: task.operation(None, &format!("kill-{signal}-{all}"))?,
                target: ContainerTarget::exact(task.container_id.clone(), generation),
                signal: Signal::new(signal)?,
                all,
            })
            .await
    }

    pub(crate) async fn wait(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
    ) -> Result<ExitStatus> {
        self.client
            .wait(WaitRequest {
                target: ContainerTarget::exact(task.container_id.clone(), generation),
                timeout_ms: None,
            })
            .await
    }

    pub(crate) async fn delete(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        force: bool,
    ) -> Result<()> {
        let request = DeleteRequest {
            context: task.operation(None, if force { "delete-force" } else { "delete" })?,
            target: ContainerTarget::exact(task.container_id.clone(), generation),
            mode: if force {
                DeleteMode::Force
            } else {
                DeleteMode::StoppedOnly
            },
        };
        let deadline = tokio::time::Instant::now() + DELETE_RETRY_TIMEOUT;
        loop {
            match self.client.delete(request.clone()).await {
                Ok(()) => return Ok(()),
                Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(DELETE_RETRY_INTERVAL).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn exec(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: &str,
        process: Process,
        io: ProcessIo,
    ) -> Result<ProcessRecord> {
        let process_id = task.process_id(exec_id)?;
        self.client
            .exec(ExecRequest {
                context: task.operation(Some(exec_id), "exec")?,
                container: ContainerTarget::exact(task.container_id.clone(), generation),
                process_id,
                process,
                io,
            })
            .await
    }

    pub(crate) async fn signal_process(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: &str,
        signal: i32,
    ) -> Result<()> {
        self.client
            .signal_process(SignalProcessRequest {
                context: task.operation(Some(exec_id), &format!("signal-{signal}"))?,
                process: ProcessTarget {
                    container: ContainerTarget::exact(task.container_id.clone(), generation),
                    process_id: task.process_id(exec_id)?,
                },
                signal: Signal::new(signal)?,
            })
            .await
    }

    pub(crate) async fn wait_process(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: &str,
    ) -> Result<ExitStatus> {
        self.client
            .wait_process(WaitProcessRequest {
                process: ProcessTarget {
                    container: ContainerTarget::exact(task.container_id.clone(), generation),
                    process_id: task.process_id(exec_id)?,
                },
                timeout_ms: None,
            })
            .await
    }

    pub(crate) async fn stats(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
    ) -> Result<ContainerStats> {
        self.client
            .stats(StatsRequest {
                target: ContainerTarget::exact(task.container_id.clone(), generation),
            })
            .await
    }

    pub(crate) async fn processes(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
    ) -> Result<Vec<ProcessRecord>> {
        self.client
            .processes(ProcessesRequest {
                target: ContainerTarget::exact(task.container_id.clone(), generation),
            })
            .await
    }

    pub(crate) async fn process(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: &str,
    ) -> Result<ProcessRecord> {
        let target = self.process_target(task, generation, Some(exec_id))?;
        self.processes(task, generation)
            .await?
            .into_iter()
            .find(|process| process.target == target)
            .ok_or_else(|| {
                adapter_error(
                    ErrorCode::NotFound,
                    format!("runtime process inventory omitted exec {exec_id}"),
                )
            })
    }

    pub(crate) async fn pause(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        sequence: u64,
    ) -> Result<ContainerRecord> {
        self.client
            .pause(ContainerOperationRequest {
                context: task.operation(None, &format!("pause-{sequence}"))?,
                target: ContainerTarget::exact(task.container_id.clone(), generation),
            })
            .await
    }

    pub(crate) async fn resume(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        sequence: u64,
    ) -> Result<ContainerRecord> {
        self.client
            .resume(ContainerOperationRequest {
                context: task.operation(None, &format!("resume-{sequence}"))?,
                target: ContainerTarget::exact(task.container_id.clone(), generation),
            })
            .await
    }

    pub(crate) async fn update(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        sequence: u64,
        resources: LinuxResources,
    ) -> Result<ContainerRecord> {
        self.client
            .update(UpdateRequest {
                context: task.operation(None, &format!("update-{sequence}"))?,
                target: ContainerTarget::exact(task.container_id.clone(), generation),
                resources,
            })
            .await
    }

    pub(crate) async fn close_stdin(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: Option<&str>,
    ) -> Result<()> {
        self.client
            .close_stdin(CloseStdinRequest {
                context: task.operation(exec_id, "close-stdin")?,
                process: self.process_target(task, generation, exec_id)?,
            })
            .await
    }

    pub(crate) async fn resize(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: Option<&str>,
        size: TerminalSize,
    ) -> Result<()> {
        self.client
            .resize(ResizeRequest {
                context: task
                    .operation(exec_id, &format!("resize-{}x{}", size.width, size.height))?,
                process: self.process_target(task, generation, exec_id)?,
                size,
            })
            .await
    }

    pub(crate) async fn read_output(
        &self,
        target: ProcessTarget,
        after_sequence: u64,
        max_bytes: u32,
        wait_timeout_ms: Option<u64>,
    ) -> Result<Vec<a3s_oci_sdk::OutputChunk>> {
        self.client
            .read_output(ReadOutputRequest {
                process: target,
                after_sequence,
                max_bytes,
                wait_timeout_ms,
            })
            .await
    }

    pub(crate) async fn write_stdin(
        &self,
        target: ProcessTarget,
        context: OperationContext,
        data: Vec<u8>,
    ) -> Result<()> {
        self.client
            .write_stdin(WriteStdinRequest {
                context,
                process: target,
                data,
            })
            .await
    }

    pub(crate) fn stdin_operation(
        &self,
        task: &TaskIdentity,
        exec_id: Option<&str>,
        sequence: u64,
    ) -> Result<OperationContext> {
        task.operation(exec_id, &format!("write-stdin-{sequence}"))
    }

    pub(crate) fn process_target(
        &self,
        task: &TaskIdentity,
        generation: a3s_oci_sdk::Generation,
        exec_id: Option<&str>,
    ) -> Result<ProcessTarget> {
        Ok(ProcessTarget {
            container: ContainerTarget::exact(task.container_id.clone(), generation),
            process_id: match exec_id {
                Some(exec_id) => task.process_id(exec_id)?,
                None => ProcessId::init(),
            },
        })
    }
}

pub(crate) fn process_io(terminal: bool, stdin: bool, stdout: bool, stderr: bool) -> ProcessIo {
    if terminal {
        ProcessIo {
            stdin: IoMode::Terminal,
            stdout: IoMode::Terminal,
            stderr: IoMode::Terminal,
            terminal_size: Some(TerminalSize {
                width: DEFAULT_TERMINAL_WIDTH,
                height: DEFAULT_TERMINAL_HEIGHT,
            }),
        }
    } else {
        ProcessIo {
            stdin: if stdin { IoMode::Pipe } else { IoMode::Null },
            stdout: if stdout {
                IoMode::Capture
            } else {
                IoMode::Null
            },
            stderr: if stderr {
                IoMode::Capture
            } else {
                IoMode::Null
            },
            terminal_size: None,
        }
    }
}

pub(crate) fn task_status(record: &ContainerRecord) -> i32 {
    match record.state.status() {
        ContainerState::Creating | ContainerState::Created => 1,
        ContainerState::Running => 2,
        ContainerState::Stopped => 3,
    }
}

pub(crate) fn exit_code(status: &ExitStatus) -> u32 {
    status
        .exit_code
        .and_then(|code| u32::try_from(code).ok())
        .or_else(|| {
            status
                .signal
                .and_then(|signal| u32::try_from(128_i32.saturating_add(signal)).ok())
        })
        .unwrap_or(255)
}

fn adapter_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("containerd-shim")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Features, StateBuilder};
    use a3s_oci_sdk::{
        async_trait, AttachmentCapabilities, DeleteMode, DriverKind, Generation, IsolationClass,
        OciRuntimeService, RuntimeFeatures, RuntimeInfo, RuntimeOperation,
    };

    #[derive(Clone, Default)]
    struct RecordingService {
        calls: Arc<Mutex<Vec<(String, OperationContext, ContainerTarget)>>>,
        delete_modes: Arc<Mutex<Vec<DeleteMode>>>,
        retryable_delete_failures: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl RecordingService {
        fn record(
            &self,
            operation: &str,
            context: OperationContext,
            target: ContainerTarget,
        ) -> Result<ContainerRecord> {
            self.calls.lock().expect("recording service calls").push((
                operation.to_string(),
                context,
                target.clone(),
            ));
            record(&target)
        }
    }

    #[async_trait]
    impl OciRuntimeService for RecordingService {
        async fn features(&self) -> Result<RuntimeInfo> {
            Ok(RuntimeInfo {
                oci: Features::default(),
                drivers: RuntimeFeatures::current(Vec::new()),
                operations: required_operations(),
                attachments: AttachmentCapabilities::base_v1(),
            })
        }

        async fn create(&self, _request: CreateRequest) -> Result<ContainerRecord> {
            Err(Error::unsupported("test-create"))
        }

        async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
            record(&request.target)
        }

        async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
            self.record("start", request.context, request.target)
        }

        async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
            self.record("kill", request.context, request.target)
        }

        async fn delete(&self, request: DeleteRequest) -> Result<()> {
            self.delete_modes
                .lock()
                .expect("recording delete modes")
                .push(request.mode);
            self.calls.lock().expect("recording service calls").push((
                "delete".to_string(),
                request.context,
                request.target,
            ));
            if self
                .retryable_delete_failures
                .fetch_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |remaining| remaining.checked_sub(1),
                )
                .is_ok()
            {
                return Err(Error::new(ErrorCode::Conflict, "active process I/O claim")
                    .for_operation("delete")
                    .retryable(true));
            }
            Ok(())
        }

        async fn pause(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
            self.record("pause", request.context, request.target)
        }

        async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
            self.record("resume", request.context, request.target)
        }

        async fn update(&self, request: UpdateRequest) -> Result<ContainerRecord> {
            self.record("update", request.context, request.target)
        }
    }

    fn required_operations() -> Vec<RuntimeOperation> {
        vec![
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
            RuntimeOperation::Update,
            RuntimeOperation::Processes,
            RuntimeOperation::Stats,
            RuntimeOperation::ReadOutput,
            RuntimeOperation::WriteStdin,
            RuntimeOperation::CloseStdin,
            RuntimeOperation::Resize,
        ]
    }

    fn record(target: &ContainerTarget) -> Result<ContainerRecord> {
        let generation = target.generation.unwrap_or(Generation(7));
        let state = StateBuilder::default()
            .version("1.3.0")
            .id(target.id.as_str())
            .status(ContainerState::Running)
            .pid(4242)
            .bundle(std::env::temp_dir())
            .build()
            .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
        Ok(ContainerRecord {
            state,
            generation,
            driver: DriverKind::NativeLinux,
            isolation: IsolationClass::SharedHostKernel,
            config_digest: "0".repeat(64),
            attachments_digest: None,
        })
    }

    #[test]
    fn stdio_contract_matches_oci_terminal_mode() {
        let pipe = process_io(false, true, true, true);
        assert_eq!(pipe.stdin, IoMode::Pipe);
        assert_eq!(pipe.stdout, IoMode::Capture);
        assert_eq!(pipe.stderr, IoMode::Capture);
        assert_eq!(pipe.terminal_size, None);

        let null_output = process_io(false, false, false, false);
        assert_eq!(null_output.stdin, IoMode::Null);
        assert_eq!(null_output.stdout, IoMode::Null);
        assert_eq!(null_output.stderr, IoMode::Null);

        let terminal = process_io(true, false, true, false);
        assert_eq!(terminal.stdin, IoMode::Terminal);
        assert_eq!(terminal.stdout, IoMode::Terminal);
        assert_eq!(terminal.stderr, IoMode::Terminal);
        assert_eq!(
            terminal.terminal_size.unwrap().width,
            DEFAULT_TERMINAL_WIDTH
        );
    }

    #[test]
    fn signal_exit_maps_to_containerd_convention() {
        assert_eq!(exit_code(&ExitStatus::exited(42).expect("exit")), 42);
        assert_eq!(
            exit_code(&ExitStatus::signaled(9, false).expect("signal")),
            137
        );
    }

    #[tokio::test]
    async fn mutations_use_exact_generation_and_stable_replay_identity() {
        let service = RecordingService::default();
        let calls = service.calls.clone();
        let adapter = RuntimeAdapter::from_client(
            RuntimeClient::new(service),
            IsolationRequest::SharedHostKernel,
        );
        let task = TaskIdentity::new("k8s.io", "task-a").expect("task identity");
        let generation = Generation(7);

        let first = adapter.start(&task, generation).await.expect("first start");
        let replay = adapter
            .start(&task, generation)
            .await
            .expect("replayed start");
        assert_eq!(first, replay);
        adapter
            .pause(&task, generation, 1)
            .await
            .expect("first pause");
        adapter
            .pause(&task, generation, 1)
            .await
            .expect("replayed first pause");
        adapter.resume(&task, generation, 2).await.expect("resume");
        adapter
            .pause(&task, generation, 3)
            .await
            .expect("second pause");

        let calls = calls.lock().expect("recorded calls");
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[0].1.operation_id, calls[1].1.operation_id);
        assert_ne!(calls[0].1.operation_id, calls[2].1.operation_id);
        assert_eq!(calls[2].1.operation_id, calls[3].1.operation_id);
        assert_ne!(calls[2].1.operation_id, calls[4].1.operation_id);
        assert_ne!(calls[2].1.operation_id, calls[5].1.operation_id);
        assert_ne!(calls[4].1.operation_id, calls[5].1.operation_id);
        assert!(calls
            .iter()
            .all(|(_, _, target)| target.generation == Some(generation)));
    }

    #[tokio::test]
    async fn normal_and_forced_delete_modes_are_not_conflated() {
        let service = RecordingService::default();
        let delete_modes = service.delete_modes.clone();
        let adapter = RuntimeAdapter::from_client(
            RuntimeClient::new(service),
            IsolationRequest::SharedHostKernel,
        );
        let task = TaskIdentity::new("k8s.io", "task-a").expect("task identity");
        let generation = Generation(7);

        adapter
            .delete(&task, generation, false)
            .await
            .expect("stopped-only delete");
        adapter
            .delete(&task, generation, true)
            .await
            .expect("forced delete");

        assert_eq!(
            *delete_modes.lock().expect("recorded delete modes"),
            vec![DeleteMode::StoppedOnly, DeleteMode::Force]
        );
    }

    #[tokio::test]
    async fn retryable_delete_reuses_the_exact_operation_identity() {
        let service = RecordingService {
            retryable_delete_failures: Arc::new(std::sync::atomic::AtomicUsize::new(2)),
            ..RecordingService::default()
        };
        let calls = service.calls.clone();
        let adapter = RuntimeAdapter::from_client(
            RuntimeClient::new(service),
            IsolationRequest::SharedHostKernel,
        );
        let task = TaskIdentity::new("k8s.io", "task-delete-retry").expect("task identity");
        let generation = Generation(7);

        adapter
            .delete(&task, generation, false)
            .await
            .expect("retryable delete converges");

        let calls = calls.lock().expect("recorded calls");
        assert_eq!(calls.len(), 3);
        let operation_id = &calls[0].1.operation_id;
        assert!(calls
            .iter()
            .all(|(operation, context, target)| operation == "delete"
                && context.operation_id == *operation_id
                && target.generation == Some(generation)));
    }
}
