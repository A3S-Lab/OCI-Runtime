use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use super::{
    AgentDriverClient, DriverCreateRequest, DriverDeleteRequest, LaunchedUtilityVm, RuntimeDriver,
    UtilityVmFactory, UtilityVmOwner, UtilityVmRuntimeDriver,
};
use crate::DriverCreateAttachments;
use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCloseStdinRequest, AgentContainerOperationRequest, AgentCreateRequest,
    AgentDeleteRequest, AgentExecRequest, AgentKillRequest, AgentProcess, AgentProcessesRequest,
    AgentReadOutputRequest, AgentResizeRequest, AgentSignalProcessRequest, AgentStartRequest,
    AgentState, AgentStateRequest, AgentStatsRequest, AgentUpdateRequest, AgentWaitProcessRequest,
    AgentWaitRequest, AgentWriteStdinRequest, GuestAgentService,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    async_trait, runtime_bundle_handoff_directory, ContainerId, ContainerRecord, ContainerStats,
    ContainerTarget, CpuStats, CreateAttachments, DeleteMode, Error, ErrorCode, ExitStatus, FileOp,
    FileRequest, FileResponse, FilesystemOp, FilesystemRequest, FilesystemResponse, Generation,
    IsolationRequest, MemoryStats, OciBundle, OperationContext, OperationId, OutputChunk,
    ProcessId, ProcessIo, ProcessRecord, ProcessTarget, Result, RuntimeOperation, Signal,
    TerminalSize, RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};

const TEST_CONFIG: &str = concat!(
    "{\n",
    "  \"ociVersion\": \"1.3.0\",\n",
    "  \"process\": {\n",
    "    \"terminal\": false,\n",
    "    \"user\": {\"uid\": 0, \"gid\": 0},\n",
    "    \"args\": [\"/bin/true\"],\n",
    "    \"cwd\": \"/\"\n",
    "  },\n",
    "  \"root\": {\"path\": \"rootfs\", \"readonly\": true}\n",
    "}\n",
);

mod isolation;

#[derive(Default)]
struct FakeGuest {
    create_calls: AtomicUsize,
    delete_calls: AtomicUsize,
    next_create_failure: StdMutex<Option<Error>>,
    state: StdMutex<Option<AgentState>>,
    dispatches: StdMutex<Vec<RuntimeOperation>>,
}

impl FakeGuest {
    fn fail_next_create(&self, error: Error) {
        *self
            .next_create_failure
            .lock()
            .expect("create failure lock") = Some(error);
    }

    fn record(&self, operation: RuntimeOperation) {
        self.dispatches
            .lock()
            .expect("dispatch lock")
            .push(operation);
    }

    fn state_for(&self, target: &ContainerTarget) -> Result<AgentState> {
        self.state
            .lock()
            .expect("state lock")
            .clone()
            .filter(|state| state.target() == target)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))
    }
}

#[async_trait]
impl GuestAgentService for FakeGuest {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::linux_executor("test", "aarch64").expect("fake capabilities")
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::Create);
        self.create_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self
            .next_create_failure
            .lock()
            .expect("create failure lock")
            .take()
        {
            return Err(error);
        }
        let state = AgentState::new(
            request.target,
            ContainerState::Created,
            Some(101),
            request.bundle.config_digest(),
        )?;
        *self.state.lock().expect("state lock") = Some(state.clone());
        Ok(state)
    }

    async fn state(&self, request: AgentStateRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::State);
        self.state_for(&request.target)
    }

    async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::Start);
        let state = AgentState::new(
            request.target,
            ContainerState::Running,
            Some(101),
            request.expected_config_digest,
        )?;
        *self.state.lock().expect("state lock") = Some(state.clone());
        Ok(state)
    }

    async fn kill(&self, request: AgentKillRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::Kill);
        let digest = self
            .state
            .lock()
            .expect("state lock")
            .as_ref()
            .map(|state| state.config_digest().to_string())
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))?;
        let state = AgentState::new(request.target, ContainerState::Stopped, None, digest)?;
        *self.state.lock().expect("state lock") = Some(state.clone());
        Ok(state)
    }

    async fn delete(&self, _request: AgentDeleteRequest) -> Result<()> {
        self.record(RuntimeOperation::Delete);
        self.delete_calls.fetch_add(1, Ordering::Relaxed);
        *self.state.lock().expect("state lock") = None;
        Ok(())
    }

    async fn wait(&self, _request: AgentWaitRequest) -> Result<ExitStatus> {
        self.record(RuntimeOperation::Wait);
        ExitStatus::exited(0)
    }

    async fn exec(&self, request: AgentExecRequest) -> Result<AgentProcess> {
        self.record(RuntimeOperation::Exec);
        AgentProcess::new(
            request.target,
            202,
            request.process.terminal().unwrap_or(false),
        )
    }

    async fn signal_process(&self, _request: AgentSignalProcessRequest) -> Result<()> {
        self.record(RuntimeOperation::SignalProcess);
        Ok(())
    }

    async fn wait_process(&self, _request: AgentWaitProcessRequest) -> Result<ExitStatus> {
        self.record(RuntimeOperation::WaitProcess);
        ExitStatus::exited(0)
    }

    async fn pause(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::Pause);
        let current = self.state_for(&request.target)?;
        let state = AgentState::new_with_pause(
            request.target,
            current.status(),
            current.pid(),
            current.config_digest(),
            true,
        )?;
        *self.state.lock().expect("state lock") = Some(state.clone());
        Ok(state)
    }

    async fn resume(&self, request: AgentContainerOperationRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::Resume);
        let current = self.state_for(&request.target)?;
        let state = AgentState::new_with_pause(
            request.target,
            current.status(),
            current.pid(),
            current.config_digest(),
            false,
        )?;
        *self.state.lock().expect("state lock") = Some(state.clone());
        Ok(state)
    }

    async fn processes(&self, request: AgentProcessesRequest) -> Result<Vec<ProcessRecord>> {
        self.record(RuntimeOperation::Processes);
        let state = self.state_for(&request.target)?;
        Ok(vec![ProcessRecord {
            target: ProcessTarget {
                container: request.target,
                process_id: ProcessId::init(),
            },
            pid: state.pid().and_then(|pid| u32::try_from(pid).ok()),
            terminal: false,
        }])
    }

    async fn update(&self, request: AgentUpdateRequest) -> Result<AgentState> {
        self.record(RuntimeOperation::Update);
        self.state_for(&request.target)
    }

    async fn stats(&self, request: AgentStatsRequest) -> Result<ContainerStats> {
        self.record(RuntimeOperation::Stats);
        self.state_for(&request.target)?;
        Ok(ContainerStats {
            target: request.target,
            timestamp_unix_ns: 1,
            cpu: CpuStats::default(),
            memory: MemoryStats::default(),
            process_count: 1,
            metrics: BTreeMap::new(),
        })
    }

    async fn read_output(&self, _request: AgentReadOutputRequest) -> Result<Vec<OutputChunk>> {
        self.record(RuntimeOperation::ReadOutput);
        Ok(Vec::new())
    }

    async fn write_stdin(&self, _request: AgentWriteStdinRequest) -> Result<()> {
        self.record(RuntimeOperation::WriteStdin);
        Ok(())
    }

    async fn close_stdin(&self, _request: AgentCloseStdinRequest) -> Result<()> {
        self.record(RuntimeOperation::CloseStdin);
        Ok(())
    }

    async fn resize(&self, _request: AgentResizeRequest) -> Result<()> {
        self.record(RuntimeOperation::Resize);
        Ok(())
    }

    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        self.record(RuntimeOperation::File);
        Ok(FileResponse {
            target: request.target,
            data: (request.op == FileOp::Download).then(String::new),
            size: 0,
        })
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        self.record(RuntimeOperation::Filesystem);
        Ok(FilesystemResponse {
            target: request.target,
            entry: None,
            entries: Vec::new(),
        })
    }
}

#[derive(Default)]
struct FakeOwner {
    shutdown_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl UtilityVmOwner for FakeOwner {
    async fn shutdown(&self) -> Result<()> {
        self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct FakeFactory {
    launches: AtomicUsize,
    launch_shares: StdMutex<Vec<PathBuf>>,
    next_launch_failure: StdMutex<Option<Error>>,
    guest: Arc<FakeGuest>,
    owner: Arc<FakeOwner>,
}

impl FakeFactory {
    fn fail_next_launch(&self, error: Error) {
        *self
            .next_launch_failure
            .lock()
            .expect("launch failure lock") = Some(error);
    }
}

#[async_trait]
impl UtilityVmFactory for FakeFactory {
    async fn launch(
        &self,
        _target: &ContainerTarget,
        runtime_share: &Path,
    ) -> Result<LaunchedUtilityVm> {
        self.launches.fetch_add(1, Ordering::Relaxed);
        self.launch_shares
            .lock()
            .expect("launch shares lock")
            .push(runtime_share.to_path_buf());
        if let Some(error) = self
            .next_launch_failure
            .lock()
            .expect("launch failure lock")
            .take()
        {
            return Err(error);
        }
        let service: Arc<dyn GuestAgentService> = self.guest.clone();
        let owner: Arc<dyn UtilityVmOwner> = self.owner.clone();
        Ok(LaunchedUtilityVm {
            client: AgentDriverClient::new(service, "fake utility-VM guest", "fake-utility-vm"),
            owner,
        })
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    runtime_root: PathBuf,
    runtime_share_root: PathBuf,
    recovery_directory: PathBuf,
    guest: Arc<FakeGuest>,
    owner: Arc<FakeOwner>,
    factory: Arc<FakeFactory>,
    driver: UtilityVmRuntimeDriver,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct ShutdownFixture {
    pub(crate) driver: Arc<crate::HvfRuntimeDriver>,
    pub(crate) shutdown_calls: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary utility-VM fixture");
        set_private_directory(temporary.path());
        let temporary_root = std::fs::canonicalize(temporary.path()).expect("canonical fixture");
        let runtime_root = temporary_root.join("runtime");
        let runtime_share_root = runtime_root.join("shares");
        let recovery_directory = runtime_root.join("recovery");
        let handoff_root = runtime_root.join("bundle-handoffs");
        for directory in [
            &runtime_root,
            &runtime_share_root,
            &recovery_directory,
            &handoff_root,
        ] {
            create_private_directory(directory);
        }
        let system_image_manifest = temporary_root.join("system-image.json");
        std::fs::write(&system_image_manifest, b"{}\n").expect("system-image fixture");

        let guest = Arc::new(FakeGuest::default());
        let owner = Arc::new(FakeOwner::default());
        let factory = Arc::new(FakeFactory {
            launches: AtomicUsize::new(0),
            launch_shares: StdMutex::new(Vec::new()),
            next_launch_failure: StdMutex::new(None),
            guest: guest.clone(),
            owner: owner.clone(),
        });
        let factory_dyn: Arc<dyn UtilityVmFactory> = factory.clone();
        let driver = UtilityVmRuntimeDriver::new(
            candidate_capability(),
            "test utility VM",
            runtime_root.clone(),
            runtime_share_root.clone(),
            system_image_manifest,
            "fixture-manifest-sha256".to_string(),
            recovery_directory.clone(),
            factory_dyn,
        );
        Self {
            _temporary: temporary,
            runtime_root,
            runtime_share_root,
            recovery_directory,
            guest,
            owner,
            factory,
            driver,
        }
    }

    fn handoff_request(&self, operation: &str) -> DriverCreateRequest {
        self.handoff_request_for(operation, target(), IsolationRequest::DedicatedVm)
    }

    fn handoff_request_for(
        &self,
        operation: &str,
        target: ContainerTarget,
        isolation: IsolationRequest,
    ) -> DriverCreateRequest {
        let context = context(operation);
        let directory =
            runtime_bundle_handoff_directory(&self.runtime_root, &target.id, &context.operation_id)
                .expect("handoff path");
        create_private_path(&self.runtime_root, &directory.join("rootfs"));
        let mut config: serde_json::Value =
            serde_json::from_str(TEST_CONFIG).expect("test OCI config");
        config["annotations"] = serde_json::json!({
            RUNTIME_BUNDLE_HANDOFF_EXTENSION: RUNTIME_BUNDLE_HANDOFF_MOVE_V1
        });
        let config = serde_json::to_string_pretty(&config).expect("handoff config");
        let config_path = directory.join("config.json");
        std::fs::write(&config_path, config.as_bytes()).expect("write handoff config");
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect handoff config");
        let bundle = OciBundle::from_json(directory, config).expect("handoff bundle");
        let attachment_contract = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("base attachments")
            .with_runtime_bundle_handoff(&bundle)
            .expect("runtime bundle handoff");
        DriverCreateRequest {
            context,
            target,
            bundle,
            isolation,
            io: ProcessIo::default(),
            attachment_contract,
            attachments: DriverCreateAttachments::None,
        }
    }

    async fn stage(&self, mut request: DriverCreateRequest) -> DriverCreateRequest {
        request.bundle = self
            .driver
            .prepare_create_bundle(&request)
            .await
            .expect("stage runtime-owned bundle");
        request
    }

    fn record(&self, status: ContainerState, config_digest: &str) -> ContainerRecord {
        let target = target();
        let state = StateBuilder::default()
            .version("1.3.0")
            .id(target.id.as_str())
            .status(status)
            .bundle(self.runtime_root.join("durable-bundle"))
            .build()
            .expect("recovery OCI state");
        ContainerRecord {
            state,
            generation: Generation(1),
            driver: DriverKind::LibkrunHvf,
            isolation: IsolationClass::DedicatedVm,
            config_digest: config_digest.to_string(),
            attachments_digest: None,
        }
    }

    fn generation_share(&self) -> PathBuf {
        self.runtime_share_root.join("utility-vm-test/1")
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) async fn shutdown_fixture(
    runtime_root: PathBuf,
    system_image_manifest: PathBuf,
) -> ShutdownFixture {
    let runtime_share_root = runtime_root.join("shares");
    let recovery_directory = runtime_root.join("recovery");
    let handoff_root = runtime_root.join("bundle-handoffs");
    for directory in [&runtime_share_root, &recovery_directory, &handoff_root] {
        create_private_directory(directory);
    }
    let guest = Arc::new(FakeGuest::default());
    let owner = Arc::new(FakeOwner::default());
    let factory = Arc::new(FakeFactory {
        launches: AtomicUsize::new(0),
        launch_shares: StdMutex::new(Vec::new()),
        next_launch_failure: StdMutex::new(None),
        guest: guest.clone(),
        owner: owner.clone(),
    });
    let factory_dyn: Arc<dyn UtilityVmFactory> = factory;
    let driver = UtilityVmRuntimeDriver::new(
        candidate_capability(),
        "test utility VM",
        runtime_root.clone(),
        runtime_share_root.clone(),
        system_image_manifest,
        "fixture-manifest-sha256".to_string(),
        recovery_directory,
        factory_dyn,
    );
    let service: Arc<dyn GuestAgentService> = guest;
    let owner_dyn: Arc<dyn UtilityVmOwner> = owner.clone();
    let target = target();
    driver.sessions.lock().await.insert(
        target.id.clone(),
        super::UtilityVmAttachment::Live(Arc::new(super::UtilityVmContainer {
            target,
            client: AgentDriverClient::new(service, "fake utility-VM guest", "fake-utility-vm"),
            owner: owner_dyn,
        })),
    );
    let driver = Arc::new(crate::HvfRuntimeDriver::from_test_inner(driver));
    ShutdownFixture {
        driver,
        shutdown_calls: owner.shutdown_calls.clone(),
    }
}

fn candidate_capability() -> DriverCapability {
    DriverCapability {
        driver: DriverKind::LibkrunHvf,
        status: CapabilityStatus::Available,
        readiness: DriverReadiness::Experimental,
        isolation_classes: vec![IsolationClass::DedicatedVm],
        reason: None,
        evidence: BTreeMap::new(),
    }
}

fn target() -> ContainerTarget {
    ContainerTarget::exact(
        ContainerId::new("utility-vm-test").expect("container ID"),
        Generation(1),
    )
}

fn context(operation: &str) -> OperationContext {
    OperationContext::new(OperationId::new(operation).expect("operation ID"))
}

fn create_private_directory(path: &Path) {
    std::fs::create_dir(path).expect("create private directory");
    set_private_directory(path);
}

fn create_private_path(root: &Path, path: &Path) {
    let relative = path.strip_prefix(root).expect("private path under root");
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if !current.exists() {
            std::fs::create_dir(&current).expect("create private path component");
        }
        set_private_directory(&current);
    }
}

fn set_private_directory(path: &Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("protect private directory");
}

#[tokio::test]
async fn concurrent_create_reuses_one_exact_generation_vm() {
    let fixture = Fixture::new();
    let request = fixture.stage(fixture.handoff_request("create")).await;
    let (first, replay) = tokio::join!(
        fixture.driver.create(request.clone()),
        fixture.driver.create(request)
    );
    assert_eq!(first.expect("first create"), replay.expect("create replay"));
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.guest.create_calls.load(Ordering::Relaxed), 2);
    assert_eq!(fixture.driver.active_session_count().await, 1);

    fixture
        .driver
        .delete(DriverDeleteRequest {
            context: context("delete"),
            target: target(),
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete exact generation");
    assert_eq!(fixture.guest.delete_calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    assert!(!fixture.generation_share().exists());
}

#[tokio::test]
async fn interrupted_create_reclaims_the_staged_bundle_and_starts_one_vm() {
    let fixture = Fixture::new();
    let original = fixture.handoff_request("interrupted-create");
    let digest = original.bundle.config_digest().to_string();
    let first_staged = fixture
        .driver
        .prepare_create_bundle(&original)
        .await
        .expect("initial bundle handoff");
    assert!(first_staged.directory().is_dir());
    assert!(!original.bundle.directory().exists());

    let recovery = fixture
        .driver
        .recover(&fixture.record(ContainerState::Creating, &digest))
        .await
        .expect("recover interrupted create");
    assert_eq!(recovery, crate::DriverRecovery::none());

    let resumed = fixture.stage(original).await;
    fixture
        .driver
        .create(resumed)
        .await
        .expect("resume exact create");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.driver.active_session_count().await, 1);
    fixture
        .driver
        .shutdown()
        .await
        .expect("shutdown resumed VM");
}

#[tokio::test]
async fn terminal_create_failure_reaps_vm_and_removes_runtime_handoff() {
    let fixture = Fixture::new();
    fixture.guest.fail_next_create(
        Error::new(ErrorCode::InvalidArgument, "terminal fake create failure")
            .for_operation("fake-create"),
    );
    let request = fixture
        .stage(fixture.handoff_request("terminal-create"))
        .await;
    let error = fixture
        .driver
        .create(request)
        .await
        .expect_err("terminal create must fail");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(!error.retryable);
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.driver.active_session_count().await, 0);
    assert!(!fixture.generation_share().exists());
    assert!(std::fs::read_dir(&fixture.recovery_directory)
        .expect("recovery directory")
        .next()
        .is_none());
}

#[tokio::test]
async fn retryable_launch_failure_retains_handoff_for_exact_retry() {
    let fixture = Fixture::new();
    fixture.factory.fail_next_launch(
        Error::new(ErrorCode::Unavailable, "transient fake launch failure")
            .for_operation("fake-launch")
            .retryable(true),
    );
    let request = fixture
        .stage(fixture.handoff_request("retryable-launch"))
        .await;
    let error = fixture
        .driver
        .create(request.clone())
        .await
        .expect_err("first launch must be retryable");
    assert!(error.retryable);
    assert!(fixture.generation_share().is_dir());
    assert_eq!(fixture.driver.active_session_count().await, 0);

    fixture
        .driver
        .create(request)
        .await
        .expect("exact retry must reuse the retained handoff");
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 2);
    assert_eq!(fixture.driver.active_session_count().await, 1);
    fixture
        .driver
        .shutdown()
        .await
        .expect("shutdown retried VM");
}

#[tokio::test]
async fn terminal_launch_failure_removes_the_unowned_generation() {
    let fixture = Fixture::new();
    fixture.factory.fail_next_launch(
        Error::new(
            ErrorCode::FailedPrecondition,
            "terminal fake launch failure",
        )
        .for_operation("fake-launch"),
    );
    let request = fixture
        .stage(fixture.handoff_request("terminal-launch"))
        .await;
    let error = fixture
        .driver
        .create(request)
        .await
        .expect_err("terminal launch must fail");
    assert!(!error.retryable);
    assert_eq!(fixture.driver.active_session_count().await, 0);
    assert!(!fixture.generation_share().exists());
}

#[tokio::test]
async fn stale_generation_cannot_replace_or_leak_beside_a_live_vm() {
    let fixture = Fixture::new();
    let first = fixture
        .stage(fixture.handoff_request("generation-one"))
        .await;
    fixture
        .driver
        .create(first)
        .await
        .expect("create generation one");

    let second_target = ContainerTarget::exact(target().id, Generation(2));
    let second = fixture.handoff_request_for(
        "generation-two",
        second_target.clone(),
        IsolationRequest::DedicatedVm,
    );
    let second = fixture.stage(second).await;
    let error = fixture
        .driver
        .create(second)
        .await
        .expect_err("generation two cannot replace a live generation");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(!fixture
        .runtime_share_root
        .join("utility-vm-test/2")
        .exists());
    assert_eq!(fixture.factory.launches.load(Ordering::Relaxed), 1);

    let stale_state = fixture
        .driver
        .state(second_target)
        .await
        .expect_err("stale state must be fenced");
    assert_eq!(stale_state.code, ErrorCode::Conflict);
    fixture
        .driver
        .shutdown()
        .await
        .expect("shutdown generation one");
}

#[tokio::test]
async fn graceful_shutdown_is_bounded_to_one_owner_and_exposes_stopped_cleanup() {
    let fixture = Fixture::new();
    let request = fixture.stage(fixture.handoff_request("shutdown")).await;
    fixture
        .driver
        .create(request)
        .await
        .expect("create before shutdown");

    fixture.driver.shutdown().await.expect("first shutdown");
    fixture
        .driver
        .shutdown()
        .await
        .expect("idempotent shutdown");
    assert_eq!(fixture.owner.shutdown_calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.driver.active_session_count().await, 0);
    assert_eq!(
        fixture
            .driver
            .state(target())
            .await
            .expect("stopped tombstone")
            .status(),
        ContainerState::Stopped
    );
    assert!(fixture
        .driver
        .processes(target())
        .await
        .expect("stopped process inventory")
        .is_empty());

    fixture
        .driver
        .delete(DriverDeleteRequest {
            context: context("delete-after-shutdown"),
            target: target(),
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete stopped tombstone");
    assert!(!fixture.generation_share().exists());
}

#[tokio::test]
async fn exact_session_delegates_every_advertised_workload_operation() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.driver.operations(),
        &crate::agent_driver::AGENT_DRIVER_OPERATIONS
    );
    assert_eq!(
        fixture.driver.hooks(),
        &crate::agent_driver::AGENT_DRIVER_HOOKS
    );

    let request = fixture
        .stage(fixture.handoff_request("delegate-create"))
        .await;
    let bundle = request.bundle.clone();
    let process = bundle
        .spec()
        .process()
        .as_ref()
        .expect("fixture process")
        .clone();
    fixture.driver.create(request).await.expect("create");
    fixture.driver.state(target()).await.expect("state");
    fixture
        .driver
        .start(crate::DriverStartRequest {
            context: context("delegate-start"),
            target: target(),
            bundle,
        })
        .await
        .expect("start");

    let process_target = ProcessTarget {
        container: target(),
        process_id: ProcessId::new("exec-one").expect("process ID"),
    };
    fixture
        .driver
        .exec(crate::DriverExecRequest {
            context: context("delegate-exec"),
            target: process_target.clone(),
            process,
            io: ProcessIo::default(),
        })
        .await
        .expect("exec");
    fixture
        .driver
        .signal_process(crate::DriverSignalProcessRequest {
            context: context("delegate-signal-process"),
            target: process_target.clone(),
            signal: Signal::new(15).expect("signal"),
        })
        .await
        .expect("signal process");
    fixture
        .driver
        .wait_process(crate::DriverWaitProcessRequest {
            target: process_target.clone(),
            timeout_ms: Some(1),
        })
        .await
        .expect("wait process");
    fixture
        .driver
        .pause(crate::DriverContainerOperationRequest {
            context: context("delegate-pause"),
            target: target(),
        })
        .await
        .expect("pause");
    fixture
        .driver
        .resume(crate::DriverContainerOperationRequest {
            context: context("delegate-resume"),
            target: target(),
        })
        .await
        .expect("resume");
    fixture.driver.processes(target()).await.expect("processes");
    fixture
        .driver
        .update(crate::DriverUpdateRequest {
            context: context("delegate-update"),
            target: target(),
            resources: serde_json::from_str("{}").expect("empty Linux resources"),
        })
        .await
        .expect("update");
    fixture.driver.stats(target()).await.expect("stats");
    fixture
        .driver
        .read_output(crate::DriverReadOutputRequest {
            target: process_target.clone(),
            after_sequence: 0,
            max_bytes: 1,
            wait_timeout_ms: Some(1),
        })
        .await
        .expect("read output");
    fixture
        .driver
        .write_stdin(crate::DriverWriteStdinRequest {
            context: context("delegate-write-stdin"),
            target: process_target.clone(),
            data: vec![1],
        })
        .await
        .expect("write stdin");
    fixture
        .driver
        .close_stdin(crate::DriverCloseStdinRequest {
            context: context("delegate-close-stdin"),
            target: process_target.clone(),
        })
        .await
        .expect("close stdin");
    fixture
        .driver
        .resize(crate::DriverResizeRequest {
            context: context("delegate-resize"),
            target: process_target,
            size: TerminalSize {
                width: 80,
                height: 24,
            },
        })
        .await
        .expect("resize");
    fixture
        .driver
        .file(FileRequest {
            target: target(),
            op: FileOp::Download,
            path: "/file".to_string(),
            data: None,
            user: None,
            context: None,
        })
        .await
        .expect("file");
    fixture
        .driver
        .filesystem(FilesystemRequest {
            target: target(),
            op: FilesystemOp::Stat,
            path: "/".to_string(),
            destination: None,
            depth: 0,
            user: None,
            context: None,
        })
        .await
        .expect("filesystem");
    fixture
        .driver
        .wait(crate::DriverWaitRequest {
            target: target(),
            timeout_ms: Some(1),
        })
        .await
        .expect("wait");
    fixture
        .driver
        .kill(crate::DriverKillRequest {
            context: context("delegate-kill"),
            target: target(),
            signal: Signal::new(9).expect("signal"),
            all: true,
        })
        .await
        .expect("kill");
    fixture
        .driver
        .delete(DriverDeleteRequest {
            context: context("delegate-delete"),
            target: target(),
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete");

    let dispatches = fixture
        .guest
        .dispatches
        .lock()
        .expect("dispatch lock")
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(dispatches.len(), 20);
    assert_eq!(
        dispatches,
        crate::agent_driver::AGENT_DRIVER_OPERATIONS
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}
