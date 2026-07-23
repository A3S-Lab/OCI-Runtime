use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error,
    ErrorCode, Generation, IsolationRequest, KillRequest, ListRequest, OciBundle,
    OciRuntimeService, OperationContext, OperationId, ProcessIo, Result, RuntimeOperation, Signal,
    StartRequest, StateRequest, TrustDomainId,
};

use super::HostRuntimeService;
use crate::{
    DriverCreateRequest, DriverDeleteRequest, DriverKillRequest, DriverStartRequest, DriverState,
    RuntimeDriver,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum DriverCall {
    Create(DriverCreateRequest),
    State(ContainerTarget),
    Start(DriverStartRequest),
    Kill(DriverKillRequest),
    Delete(DriverDeleteRequest),
}

#[derive(Debug)]
struct RecordingDriver {
    capability: DriverCapability,
    calls: Mutex<Vec<DriverCall>>,
    states: Mutex<HashMap<ContainerId, (Generation, DriverState)>>,
    failures: Mutex<HashMap<&'static str, Vec<Error>>>,
}

impl RecordingDriver {
    fn supported() -> Self {
        Self {
            capability: DriverCapability {
                driver: DriverKind::LibkrunWhpx,
                status: CapabilityStatus::Available,
                readiness: DriverReadiness::Supported,
                isolation_classes: vec![IsolationClass::DedicatedVm],
                reason: None,
                evidence: BTreeMap::from([("test-driver".to_string(), "in-process".to_string())]),
            },
            calls: Mutex::new(Vec::new()),
            states: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn probe_only() -> Self {
        let mut driver = Self::supported();
        driver.capability.readiness = DriverReadiness::ProbeOnly;
        driver
    }

    fn calls(&self) -> Vec<DriverCall> {
        self.calls.lock().expect("driver calls lock").clone()
    }

    fn fail_next(&self, operation: &'static str, error: Error) {
        self.failures
            .lock()
            .expect("driver failures lock")
            .entry(operation)
            .or_default()
            .push(error);
    }

    fn take_failure(&self, operation: &'static str) -> Option<Error> {
        let mut failures = self.failures.lock().expect("driver failures lock");
        let queue = failures.get_mut(operation)?;
        if queue.is_empty() {
            None
        } else {
            Some(queue.remove(0))
        }
    }

    fn exact_generation(target: &ContainerTarget) -> Result<Generation> {
        target.generation.ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidArgument,
                "driver requests must carry an exact generation",
            )
        })
    }
}

#[async_trait]
impl RuntimeDriver for RecordingDriver {
    fn capability(&self) -> DriverCapability {
        self.capability.clone()
    }

    async fn create(&self, request: DriverCreateRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Create(request.clone()));
        if let Some(error) = self.take_failure("create") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let state = DriverState::created(4_242)?;
        self.states
            .lock()
            .expect("driver states lock")
            .insert(request.target.id, (generation, state));
        Ok(state)
    }

    async fn state(&self, target: ContainerTarget) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::State(target.clone()));
        let generation = Self::exact_generation(&target)?;
        let states = self.states.lock().expect("driver states lock");
        let (actual_generation, state) = states.get(&target.id).copied().ok_or_else(|| {
            Error::new(ErrorCode::NotFound, "driver container does not exist")
                .for_operation("driver-state")
        })?;
        if generation != actual_generation {
            return Err(
                Error::new(ErrorCode::Conflict, "driver container generation mismatch")
                    .for_operation("driver-state"),
            );
        }
        Ok(state)
    }

    async fn start(&self, request: DriverStartRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Start(request.clone()));
        if let Some(error) = self.take_failure("start") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let state = DriverState::running(4_242)?;
        self.states
            .lock()
            .expect("driver states lock")
            .insert(request.target.id, (generation, state));
        Ok(state)
    }

    async fn kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Kill(request.clone()));
        if let Some(error) = self.take_failure("kill") {
            return Err(error);
        }
        let generation = Self::exact_generation(&request.target)?;
        let state = DriverState::stopped();
        self.states
            .lock()
            .expect("driver states lock")
            .insert(request.target.id, (generation, state));
        Ok(state)
    }

    async fn delete(&self, request: DriverDeleteRequest) -> Result<()> {
        self.calls
            .lock()
            .expect("driver calls lock")
            .push(DriverCall::Delete(request.clone()));
        if let Some(error) = self.take_failure("delete") {
            return Err(error);
        }
        self.states
            .lock()
            .expect("driver states lock")
            .remove(&request.target.id);
        Ok(())
    }
}

fn identifier<T>(value: &str, constructor: impl FnOnce(String) -> a3s_oci_sdk::Result<T>) -> T {
    constructor(value.to_string()).unwrap_or_else(|error| panic!("valid identifier: {error}"))
}

fn container_id(value: &str) -> ContainerId {
    identifier(value, ContainerId::new)
}

fn operation_id(value: &str) -> OperationId {
    identifier(value, OperationId::new)
}

fn create_request(bundle_directory: &Path, operation: &str) -> CreateRequest {
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id("sdk-container"),
        bundle: OciBundle::from_json(bundle_directory.to_path_buf(), TEST_CONFIG)
            .expect("valid OCI bundle"),
        isolation: IsolationRequest::DedicatedVm,
        io: ProcessIo::default(),
    }
}

async fn open_service(
    temporary: &tempfile::TempDir,
    driver: Arc<RecordingDriver>,
) -> HostRuntimeService {
    HostRuntimeService::open(temporary.path().join("state"), driver)
        .await
        .expect("open host runtime")
}

#[tokio::test]
async fn reports_only_operations_that_are_currently_implemented() {
    let info = HostRuntimeService::new()
        .features()
        .await
        .expect("feature discovery must succeed");

    assert_eq!(info.operations, vec![RuntimeOperation::Features]);
    assert_eq!(info.oci.oci_version_min(), "1.0.0");
    assert_eq!(info.oci.oci_version_max(), "1.3.0");
}

#[tokio::test]
async fn incomplete_lifecycle_fails_explicitly() {
    let error = HostRuntimeService::new()
        .list(ListRequest::default())
        .await
        .expect_err("list must remain disabled before durable state exists");

    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(error.operation.as_deref(), Some("list"));
}

#[tokio::test]
async fn rust_sdk_lifecycle_is_durable_and_exactly_replayed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;

    let info = service.features().await.expect("configured features");
    assert_eq!(
        info.operations,
        vec![
            RuntimeOperation::Features,
            RuntimeOperation::Create,
            RuntimeOperation::State,
            RuntimeOperation::Start,
            RuntimeOperation::Kill,
            RuntimeOperation::Delete,
        ]
    );

    let create = create_request(&bundle_directory, "create-1");
    let created = service.create(create.clone()).await.expect("create");
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert_eq!(*created.state.pid(), Some(4_242));
    assert_eq!(created.generation, Generation(1));
    assert_eq!(
        service.create(create.clone()).await.expect("replay create"),
        created
    );

    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    assert_eq!(
        service
            .state(StateRequest {
                target: target.clone()
            })
            .await
            .expect("query created state"),
        created
    );

    let start = StartRequest {
        context: OperationContext::new(operation_id("start-1")),
        target: target.clone(),
    };
    let running = service.start(start.clone()).await.expect("start");
    assert_eq!(*running.state.status(), ContainerState::Running);
    assert_eq!(service.start(start).await.expect("replay start"), running);

    let kill = KillRequest {
        context: OperationContext::new(operation_id("kill-1")),
        target: target.clone(),
        signal: Signal::new(15).expect("signal"),
        all: true,
    };
    let stopped = service.kill(kill.clone()).await.expect("kill");
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);
    assert_eq!(service.kill(kill).await.expect("replay kill"), stopped);

    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("delete-1")),
        target,
        mode: DeleteMode::StoppedOnly,
    };
    service.delete(delete.clone()).await.expect("delete");
    service.delete(delete).await.expect("replay delete");

    let calls = driver.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Start(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Kill(_)))
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| matches!(call, DriverCall::Delete(_)))
            .count(),
        1
    );
    let DriverCall::Create(driver_create) = &calls[0] else {
        panic!("create must be the first driver call");
    };
    assert_eq!(driver_create.bundle.config_json(), TEST_CONFIG);
    assert_eq!(driver_create.target.generation, Some(Generation(1)));

    let error = service
        .state(StateRequest {
            target: ContainerTarget::current(create.id),
        })
        .await
        .expect_err("deleted state must not remain visible");
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn terminal_driver_failures_replay_and_release_container_claims() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create_failure =
        Error::new(ErrorCode::FailedPrecondition, "guest rejected create").for_operation("create");
    driver.fail_next("create", create_failure.clone());
    let failed_create = create_request(&bundle_directory, "create-failed");

    assert_eq!(
        service
            .create(failed_create.clone())
            .await
            .expect_err("create must fail"),
        create_failure
    );
    assert_eq!(
        service
            .create(failed_create.clone())
            .await
            .expect_err("failed create must replay"),
        create_failure
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        1
    );

    let create = create_request(&bundle_directory, "create-retry-new-operation");
    let created = service
        .create(create.clone())
        .await
        .expect("container ID can be reused after failed create");
    assert_eq!(created.generation, Generation(2));
    assert_eq!(
        service
            .create(failed_create)
            .await
            .expect_err("old failed operation still replays after ID reuse"),
        create_failure
    );

    let target = ContainerTarget::exact(create.id, created.generation);
    let start_failure =
        Error::new(ErrorCode::Internal, "terminal start failure").for_operation("start");
    driver.fail_next("start", start_failure.clone());
    let failed_start = StartRequest {
        context: OperationContext::new(operation_id("start-failed")),
        target: target.clone(),
    };
    assert_eq!(
        service
            .start(failed_start.clone())
            .await
            .expect_err("start must fail"),
        start_failure
    );
    assert_eq!(
        service
            .start(failed_start)
            .await
            .expect_err("failed start must replay"),
        start_failure
    );

    let running = service
        .start(StartRequest {
            context: OperationContext::new(operation_id("start-after-failure")),
            target,
        })
        .await
        .expect("a new start can proceed after terminal failure");
    assert_eq!(*running.state.status(), ContainerState::Running);
}

#[tokio::test]
async fn retryable_driver_failure_keeps_the_same_operation_resumable() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    driver.fail_next(
        "create",
        Error::new(ErrorCode::Unavailable, "guest is booting")
            .for_operation("create")
            .retryable(true),
    );
    let request = create_request(&bundle_directory, "create-retryable");

    let error = service
        .create(request.clone())
        .await
        .expect_err("first create attempt must be retryable");
    assert!(error.retryable);
    let created = service
        .create(request)
        .await
        .expect("same operation resumes");
    assert_eq!(*created.state.status(), ContainerState::Created);
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Create(_)))
            .count(),
        2
    );
}

#[tokio::test]
async fn launch_and_isolation_checks_fail_before_state_or_driver_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path().join("probe-only-state");
    let error = HostRuntimeService::open(&root, Arc::new(RecordingDriver::probe_only()))
        .await
        .expect_err("probe-only drivers cannot open lifecycle state");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(!root.exists());

    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::supported());
    let service = HostRuntimeService::open(
        temporary.path().join("supported-state"),
        Arc::clone(&driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    .expect("open supported driver");
    let mut request = create_request(&bundle_directory, "unsupported-isolation");
    request.isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: identifier("test-domain", TrustDomainId::new),
    };
    let error = service
        .create(request)
        .await
        .expect_err("unsupported isolation must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(driver.calls().is_empty());
}
