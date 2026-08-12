use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use a3s_oci_agent_protocol::{
    AgentCapabilities, AgentCreateRequest, AgentDeleteRequest, AgentKillRequest, AgentStartRequest,
    AgentState, AgentStateRequest, GuestAgentService,
};
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    async_trait, runtime_bundle_handoff_directory, ContainerId, ContainerRecord, ContainerTarget,
    CreateAttachments, DeleteMode, Error, ErrorCode, Generation, IsolationRequest, OciBundle,
    OperationContext, OperationId, ProcessIo, Result, RUNTIME_BUNDLE_HANDOFF_EXTENSION,
    RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};
use tokio::sync::Mutex;

use super::{
    AgentDriverClient, BundleHandoffStore, DriverCreateRequest, DriverDeleteRequest,
    HvfRuntimeDriver, HvfVmFactory, HvfVmOwner, LaunchedHvfVm, RecoveryStore, RuntimeDriver,
};
use crate::DriverCreateAttachments;

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

#[derive(Default)]
struct FakeGuest {
    create_calls: AtomicUsize,
    delete_calls: AtomicUsize,
    next_create_failure: StdMutex<Option<Error>>,
    state: StdMutex<Option<AgentState>>,
}

impl FakeGuest {
    fn fail_next_create(&self, error: Error) {
        *self
            .next_create_failure
            .lock()
            .expect("create failure lock") = Some(error);
    }
}

#[async_trait]
impl GuestAgentService for FakeGuest {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::linux_executor("test", "aarch64").expect("fake capabilities")
    }

    async fn create(&self, request: AgentCreateRequest) -> Result<AgentState> {
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
        self.state
            .lock()
            .expect("state lock")
            .clone()
            .filter(|state| state.target() == &request.target)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing fake guest state"))
    }

    async fn start(&self, request: AgentStartRequest) -> Result<AgentState> {
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
        self.delete_calls.fetch_add(1, Ordering::Relaxed);
        *self.state.lock().expect("state lock") = None;
        Ok(())
    }
}

#[derive(Default)]
struct FakeOwner {
    shutdown_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HvfVmOwner for FakeOwner {
    async fn shutdown(&self) -> Result<()> {
        self.shutdown_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct FakeFactory {
    launches: AtomicUsize,
    launch_shares: StdMutex<Vec<PathBuf>>,
    guest: Arc<FakeGuest>,
    owner: Arc<FakeOwner>,
}

#[async_trait]
impl HvfVmFactory for FakeFactory {
    async fn launch(
        &self,
        _target: &ContainerTarget,
        runtime_share: &Path,
    ) -> Result<LaunchedHvfVm> {
        self.launches.fetch_add(1, Ordering::Relaxed);
        self.launch_shares
            .lock()
            .expect("launch shares lock")
            .push(runtime_share.to_path_buf());
        let service: Arc<dyn GuestAgentService> = self.guest.clone();
        let owner: Arc<dyn HvfVmOwner> = self.owner.clone();
        Ok(LaunchedHvfVm {
            client: AgentDriverClient::new(service, "fake HVF guest", "fake-hvf"),
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
    driver: HvfRuntimeDriver,
}

pub(crate) struct ShutdownFixture {
    pub(crate) driver: Arc<HvfRuntimeDriver>,
    pub(crate) shutdown_calls: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary HVF fixture");
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
            guest: guest.clone(),
            owner: owner.clone(),
        });
        let factory_dyn: Arc<dyn HvfVmFactory> = factory.clone();
        let driver = HvfRuntimeDriver {
            capability: candidate_capability(),
            runtime_root: runtime_root.clone(),
            runtime_share_root: runtime_share_root.clone(),
            system_image_manifest,
            system_image_manifest_sha256: "fixture-manifest-sha256".to_string(),
            recovery: RecoveryStore::new(recovery_directory.clone()),
            handoff: BundleHandoffStore::new(runtime_root.clone(), runtime_share_root.clone()),
            factory: factory_dyn,
            sessions: Mutex::new(BTreeMap::new()),
            create_gates: Mutex::new(BTreeMap::new()),
        };
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
        let context = context(operation);
        let target = target();
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
            isolation: IsolationRequest::DedicatedVm,
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
        self.runtime_share_root.join("hvf-test/1")
    }
}

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
        guest: guest.clone(),
        owner: owner.clone(),
    });
    let factory_dyn: Arc<dyn HvfVmFactory> = factory;
    let driver = Arc::new(HvfRuntimeDriver {
        capability: candidate_capability(),
        runtime_root: runtime_root.clone(),
        runtime_share_root: runtime_share_root.clone(),
        system_image_manifest,
        system_image_manifest_sha256: "fixture-manifest-sha256".to_string(),
        recovery: RecoveryStore::new(recovery_directory),
        handoff: BundleHandoffStore::new(runtime_root, runtime_share_root),
        factory: factory_dyn,
        sessions: Mutex::new(BTreeMap::new()),
        create_gates: Mutex::new(BTreeMap::new()),
    });
    let service: Arc<dyn GuestAgentService> = guest;
    let owner_dyn: Arc<dyn HvfVmOwner> = owner.clone();
    let target = target();
    driver.sessions.lock().await.insert(
        target.id.clone(),
        super::HvfAttachment::Live(Arc::new(super::HvfContainer {
            target,
            client: AgentDriverClient::new(service, "fake HVF guest", "fake-hvf"),
            owner: owner_dyn,
        })),
    );
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
        ContainerId::new("hvf-test").expect("container ID"),
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
