use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    async_trait, AttachmentCapabilities, CheckpointCompatibility, CheckpointDigest,
    CheckpointFormat, CheckpointReference, CheckpointRequest, CheckpointResponse,
    ContainerOperationRequest, ContainerRecord, Error, ErrorCode, ExitStatus, HostPlatform,
    IsolationClass, IsolationRequest, OciBundle, OciRuntimeService, RestoreRequest,
    RestoreResponse, RuntimeArtifact, RuntimeDriverCapabilities, RuntimeExtensions,
    RuntimeOperation, RuntimeOperationCapability, StateRequest, WaitRequest,
    PAUSED_STATE_ANNOTATION,
};
use containerd_shim_protos::shim_async::Task;
use sha2::{Digest, Sha256};

use super::*;

#[derive(Default)]
struct BridgeCalls {
    checkpoint_operation_ids: Vec<String>,
    restore_operation_ids: Vec<String>,
    resume_operation_ids: Vec<String>,
    kills: usize,
    deletes: usize,
    state_calls: usize,
}

#[derive(Clone)]
struct BridgeRuntime {
    artifact: RuntimeArtifact,
    record: Arc<StdMutex<Option<ContainerRecord>>>,
    calls: Arc<StdMutex<BridgeCalls>>,
    killed: Arc<AtomicBool>,
}

impl BridgeRuntime {
    fn new(artifact: RuntimeArtifact, record: Option<ContainerRecord>) -> Self {
        Self {
            artifact,
            record: Arc::new(StdMutex::new(record)),
            calls: Arc::new(StdMutex::new(BridgeCalls::default())),
            killed: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl OciRuntimeService for BridgeRuntime {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(Error::unsupported("test-features"))
    }

    async fn create(
        &self,
        _request: a3s_oci_sdk::CreateRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(Error::unsupported("test-create"))
    }

    async fn start(
        &self,
        _request: a3s_oci_sdk::StartRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(Error::unsupported("test-start"))
    }

    async fn kill(
        &self,
        _request: a3s_oci_sdk::KillRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls.lock().expect("restore bridge calls").kills += 1;
        self.killed.store(true, Ordering::SeqCst);
        self.record
            .lock()
            .expect("restore bridge record")
            .clone()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing restored record"))
    }

    async fn delete(&self, _request: a3s_oci_sdk::DeleteRequest) -> a3s_oci_sdk::Result<()> {
        self.calls.lock().expect("restore bridge calls").deletes += 1;
        *self.record.lock().expect("restore bridge record") = None;
        Ok(())
    }

    async fn checkpoint(
        &self,
        request: CheckpointRequest,
    ) -> a3s_oci_sdk::Result<CheckpointResponse> {
        self.calls
            .lock()
            .expect("checkpoint bridge calls")
            .checkpoint_operation_ids
            .push(request.context().operation_id.as_str().to_string());
        let source = self
            .record
            .lock()
            .expect("checkpoint bridge record")
            .clone()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing checkpoint source"))?;
        let bytes = b"a3s-containerd-checkpoint";
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options
            .open(request.artifact_path().as_path())
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::AlreadyExists,
                    format!("create checkpoint artifact: {error}"),
                )
            })?;
        use tokio::io::AsyncWriteExt;
        file.write_all(bytes)
            .await
            .map_err(|error| Error::new(ErrorCode::Unavailable, error.to_string()))?;
        file.sync_all()
            .await
            .map_err(|error| Error::new(ErrorCode::Unavailable, error.to_string()))?;
        let reference = reference(&source, self.artifact.clone(), bytes);
        CheckpointResponse::new(source, reference)
    }

    async fn restore(&self, request: RestoreRequest) -> a3s_oci_sdk::Result<RestoreResponse> {
        self.calls
            .lock()
            .expect("restore bridge calls")
            .restore_operation_ids
            .push(request.context().operation_id.as_str().to_string());
        let reference = request.reference()?.clone();
        let restored = paused_record(
            request.id().as_str(),
            request.bundle().directory(),
            request.bundle().config_digest(),
            reference.source_attachments_digest().as_str(),
        );
        *self.record.lock().expect("restore bridge record") = Some(restored.clone());
        RestoreResponse::new(restored, reference)
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls.lock().expect("restore bridge calls").state_calls += 1;
        let record = self
            .record
            .lock()
            .expect("restore bridge record")
            .clone()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing restored record"))?;
        if request.target.id.as_str() != record.state.id()
            || request.target.generation != Some(record.generation)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "restore bridge state target drifted",
            ));
        }
        Ok(record)
    }

    async fn resume(
        &self,
        request: ContainerOperationRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls
            .lock()
            .expect("restore bridge calls")
            .resume_operation_ids
            .push(request.context.operation_id.as_str().to_string());
        let mut record = self.record.lock().expect("restore bridge record");
        let current = record
            .as_ref()
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "missing restored record"))?;
        if request.target.id.as_str() != current.state.id()
            || request.target.generation != Some(current.generation)
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "restore bridge resume target drifted",
            ));
        }
        let resumed = record_with_paused_state(current, false);
        *record = Some(resumed.clone());
        Ok(resumed)
    }

    async fn wait(&self, _request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        if self.killed.load(Ordering::SeqCst) {
            ExitStatus::signaled(9, false)
        } else {
            std::future::pending().await
        }
    }
}

#[tokio::test]
async fn checkpoint_commits_one_replayable_containerd_package_and_detects_tampering() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let source = paused_record(
        "a3s-k8s.io-task-a",
        temporary.path(),
        &format!("sha256:{}", "a".repeat(64)),
        &format!("sha256:{}", "b".repeat(64)),
    );
    let artifact = runtime_artifact();
    let runtime = BridgeRuntime::new(artifact.clone(), Some(source.clone()));
    let calls = Arc::clone(&runtime.calls);
    let adapter = RuntimeAdapter::from_client_with_extensions(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
        extensions(artifact, &[RuntimeOperation::Checkpoint]),
    );
    let service = recovery_service_instance(temporary.path(), adapter);
    let mut task = task_state(temporary.path());
    task.identity.container_id = a3s_oci_sdk::ContainerId::new(source.state.id().to_string())
        .expect("checkpoint task identity");
    task.record = source;
    task.exit = None;
    task.exited_at = None;
    task.rootfs_mounted = false;
    service
        .state
        .lock()
        .await
        .tasks
        .insert("task-a".to_string(), task);

    let checkpoint_directory = temporary.path().join("checkpoint");
    tokio::fs::create_dir(&checkpoint_directory)
        .await
        .expect("checkpoint directory");
    let request = checkpoint_request(&checkpoint_directory);
    Task::checkpoint(&service, &ttrpc_context(), request.clone())
        .await
        .expect("checkpoint task");
    let package = crate::checkpoint::CheckpointPackage::load(
        checkpoint_directory
            .to_str()
            .expect("UTF-8 checkpoint path"),
    )
    .await
    .expect("committed checkpoint package");
    assert_eq!(package.reference().source().generation, Some(Generation(7)));

    Task::checkpoint(&service, &ttrpc_context(), request.clone())
        .await
        .expect("replay committed checkpoint package");
    assert_eq!(
        calls
            .lock()
            .expect("checkpoint bridge calls")
            .checkpoint_operation_ids
            .len(),
        1
    );

    tokio::fs::write(package.artifact_path().as_path(), b"tampered")
        .await
        .expect("tamper checkpoint artifact");
    let error = Task::checkpoint(&service, &ttrpc_context(), request)
        .await
        .expect_err("tampered package must fail");
    assert_rpc_code(error, ttrpc::Code::FAILED_PRECONDITION);
    assert_eq!(
        calls
            .lock()
            .expect("checkpoint bridge calls")
            .checkpoint_operation_ids
            .len(),
        1,
        "local package validation must fail before SDK redispatch"
    );
}

#[tokio::test]
async fn restore_create_exposes_created_until_one_durable_start_resume_barrier() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_path = std::fs::canonicalize(temporary.path()).expect("canonical bundle");
    std::fs::create_dir(bundle_path.join("rootfs")).expect("rootfs directory");
    std::fs::write(
        bundle_path.join("config.json"),
        include_str!("../../../../../fixtures/native-linux/config.json"),
    )
    .expect("write OCI config");
    let bundle = OciBundle::load(&bundle_path)
        .await
        .expect("load OCI bundle");
    let attachments = a3s_oci_sdk::CreateAttachments::from_bundle(
        &bundle,
        adapter::process_io(false, false, false, false),
    )
    .expect("restore attachments");
    let source = paused_record(
        "checkpoint-source",
        &bundle_path,
        bundle.config_digest(),
        &attachments.digest().expect("attachment digest"),
    );
    let artifact = runtime_artifact();
    let checkpoint_directory = bundle_path.join("checkpoint");
    std::fs::create_dir(&checkpoint_directory).expect("checkpoint directory");
    let destination = crate::checkpoint::CheckpointDestination::open(
        checkpoint_directory
            .to_str()
            .expect("UTF-8 checkpoint directory"),
    )
    .await
    .expect("checkpoint destination");
    let artifact_bytes = b"restore-bridge-checkpoint";
    tokio::fs::write(destination.artifact_path().as_path(), artifact_bytes)
        .await
        .expect("checkpoint artifact");
    destination
        .commit(reference(&source, artifact.clone(), artifact_bytes))
        .await
        .expect("commit checkpoint package");

    let runtime = BridgeRuntime::new(artifact.clone(), None);
    let calls = Arc::clone(&runtime.calls);
    let adapter = RuntimeAdapter::from_client_with_extensions(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
        extensions(artifact, &[RuntimeOperation::Restore]),
    );
    let service = recovery_service_instance(&bundle_path, adapter);
    let mut create = api::CreateTaskRequest::new();
    create.set_id("task-a".to_string());
    create.set_bundle(bundle_path.to_string_lossy().into_owned());
    create.set_checkpoint(checkpoint_directory.to_string_lossy().into_owned());
    Task::create(&service, &ttrpc_context(), create)
        .await
        .expect("restore containerd task");

    let state = task_state_request(&service).await;
    assert_eq!(state.status.enum_value_or_default(), api::Status::CREATED);
    assert_eq!(
        service
            .task_snapshot("task-a")
            .await
            .expect("restored task")
            .restore_state,
        RestoreState::PendingStart
    );

    let mut resume = api::ResumeRequest::new();
    resume.set_id("task-a".to_string());
    let error = Task::resume(&service, &ttrpc_context(), resume)
        .await
        .expect_err("Resume must not bypass restored Start");
    assert_rpc_code(error, ttrpc::Code::FAILED_PRECONDITION);

    let mut start = api::StartRequest::new();
    start.set_id("task-a".to_string());
    let first = Task::start(&service, &ttrpc_context(), start.clone())
        .await
        .expect("start restored task");
    let replay = Task::start(&service, &ttrpc_context(), start)
        .await
        .expect("replay restored Start");
    assert_eq!(first.pid(), replay.pid());
    assert_eq!(
        task_state_request(&service)
            .await
            .status
            .enum_value_or_default(),
        api::Status::RUNNING
    );
    assert_eq!(
        service
            .task_snapshot("task-a")
            .await
            .expect("started restored task")
            .restore_state,
        RestoreState::Started
    );
    {
        let calls = calls.lock().expect("restore bridge calls");
        assert_eq!(calls.restore_operation_ids.len(), 1);
        assert_eq!(calls.resume_operation_ids.len(), 1);
        assert!(
            calls.state_calls >= 1,
            "replayed Start must adopt exact state"
        );
    }
    let metadata = ShimMetadata::load(&ShimMetadata::path(&bundle_path))
        .expect("load restore metadata")
        .expect("restore metadata exists");
    assert_eq!(metadata.restore_state(), RestoreState::Started);

    service.stop_all_monitors().await;
    service.stop_all_pumps().await;
}

#[tokio::test]
async fn rehydration_adopts_a_restore_resume_committed_before_metadata_advance() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(temporary.path());
    task.stdin.clear();
    task.stdout.clear();
    task.stderr.clear();
    task.rootfs_mounted = false;
    task.exit = None;
    task.exited_at = None;
    task.restore_state = RestoreState::PendingStart;
    task.record = paused_record(
        task.identity.container_id.as_str(),
        temporary.path(),
        &format!("sha256:{}", "a".repeat(64)),
        &format!("sha256:{}", "b".repeat(64)),
    );
    metadata_from_task(&task)
        .store()
        .expect("store pending restore metadata");
    let committed_resume = record_with_paused_state(&task.record, false);
    let artifact = runtime_artifact();
    let runtime = BridgeRuntime::new(artifact.clone(), Some(committed_resume));
    let adapter = RuntimeAdapter::from_client_with_extensions(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
        extensions(artifact, &[RuntimeOperation::Restore]),
    );
    let service = recovery_service_instance(temporary.path(), adapter);

    service
        .restore_task("task-a")
        .await
        .expect("adopt committed restore Resume");
    let restored = service
        .task_snapshot("task-a")
        .await
        .expect("rehydrated restored task");
    assert_eq!(restored.restore_state, RestoreState::Started);
    assert!(!restored.record.is_paused());
    let metadata = ShimMetadata::load(&ShimMetadata::path(temporary.path()))
        .expect("load reconciled metadata")
        .expect("reconciled metadata exists");
    assert_eq!(metadata.restore_state(), RestoreState::Started);

    service.stop_all_monitors().await;
    service.stop_all_pumps().await;
}

#[tokio::test]
async fn delete_shim_replays_a_durable_restore_intent_after_capability_drift() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_path = std::fs::canonicalize(temporary.path()).expect("canonical bundle");
    std::fs::create_dir(bundle_path.join("rootfs")).expect("rootfs directory");
    std::fs::write(
        bundle_path.join("config.json"),
        include_str!("../../../../../fixtures/native-linux/config.json"),
    )
    .expect("write OCI config");
    let bundle = OciBundle::load(&bundle_path)
        .await
        .expect("load OCI bundle");
    let attachments = a3s_oci_sdk::CreateAttachments::from_bundle(
        &bundle,
        adapter::process_io(false, false, false, false),
    )
    .expect("restore attachments");
    let source = paused_record(
        "checkpoint-source-cleanup",
        &bundle_path,
        bundle.config_digest(),
        &attachments.digest().expect("attachment digest"),
    );
    let artifact = runtime_artifact();
    let checkpoint_directory = bundle_path.join("checkpoint-cleanup");
    std::fs::create_dir(&checkpoint_directory).expect("checkpoint directory");
    let destination = crate::checkpoint::CheckpointDestination::open(
        checkpoint_directory
            .to_str()
            .expect("UTF-8 checkpoint directory"),
    )
    .await
    .expect("checkpoint destination");
    let bytes = b"restore-intent-cleanup";
    tokio::fs::write(destination.artifact_path().as_path(), bytes)
        .await
        .expect("checkpoint artifact");
    let reference = reference(&source, artifact.clone(), bytes);
    destination
        .commit(reference.clone())
        .await
        .expect("commit checkpoint package");
    let incarnation =
        ShimMetadata::load_or_create_incarnation(&bundle_path).expect("restore task incarnation");
    let identity = TaskIdentity::with_incarnation("k8s.io", "task-a", incarnation)
        .expect("restore task identity");
    ShimCreateIntent::new(NewShimCreateIntent {
        identity: identity.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        bundle: bundle_path.clone(),
        stdin: String::new(),
        stdout: String::new(),
        stderr: String::new(),
        terminal: false,
        rootfs_mounted: false,
        restore: Some((destination.artifact_path().clone(), reference.clone())),
    })
    .expect("restore create intent")
    .store()
    .expect("store restore create intent");

    let runtime = BridgeRuntime::new(artifact.clone(), None);
    let calls = Arc::clone(&runtime.calls);
    let adapter = RuntimeAdapter::from_client_with_extensions(
        a3s_oci_sdk::RuntimeClient::new(runtime),
        IsolationRequest::SharedHostKernel,
        extensions(artifact, &[RuntimeOperation::Checkpoint]),
    );
    let error = adapter
        .restore(
            &identity,
            &bundle_path,
            adapter::process_io(false, false, false, false),
            destination.artifact_path().clone(),
            reference,
        )
        .await
        .expect_err("a fresh restore must honor the current capability contract");
    assert_eq!(error.code, ErrorCode::Unsupported);

    let mut service = recovery_service_instance(&bundle_path, adapter);
    let response = service
        .delete_shim()
        .await
        .expect("replay and clean restore intent");

    assert_eq!(response.pid(), 4242);
    assert_eq!(response.exit_status(), 137);
    assert!(!ShimCreateIntent::path(&bundle_path).exists());
    let calls = calls.lock().expect("restore bridge calls");
    assert_eq!(calls.restore_operation_ids.len(), 1);
    assert_eq!(calls.kills, 1);
    assert_eq!(calls.deletes, 1);
}

fn checkpoint_request(path: &Path) -> api::CheckpointTaskRequest {
    let mut request = api::CheckpointTaskRequest::new();
    request.set_id("task-a".to_string());
    request.set_path(path.to_string_lossy().into_owned());
    request
}

async fn task_state_request(service: &Service) -> api::StateResponse {
    let mut request = api::StateRequest::new();
    request.set_id("task-a".to_string());
    Task::state(service, &ttrpc_context(), request)
        .await
        .expect("containerd task state")
}

fn paused_record(
    id: &str,
    bundle: &Path,
    config_digest: &str,
    attachments_digest: &str,
) -> ContainerRecord {
    let state = StateBuilder::default()
        .version("1.3.0")
        .id(id)
        .status(ContainerState::Running)
        .pid(4242)
        .bundle(bundle)
        .annotations(HashMap::from([(
            PAUSED_STATE_ANNOTATION.to_string(),
            "true".to_string(),
        )]))
        .build()
        .expect("paused OCI state");
    ContainerRecord {
        state,
        generation: Generation(7),
        driver: DriverKind::NativeLinux,
        isolation: IsolationClass::SharedHostKernel,
        guest_session: None,
        network_enforcement: None,
        config_digest: config_digest.to_string(),
        attachments_digest: Some(attachments_digest.to_string()),
    }
}

fn record_with_paused_state(record: &ContainerRecord, paused: bool) -> ContainerRecord {
    let mut record = record.clone();
    let mut annotations = record.state.annotations().clone().unwrap_or_default();
    if paused {
        annotations.insert(PAUSED_STATE_ANNOTATION.to_string(), "true".to_string());
    } else {
        annotations.remove(PAUSED_STATE_ANNOTATION);
    }
    let mut builder = StateBuilder::default()
        .version(record.state.version())
        .id(record.state.id())
        .status(ContainerState::Running)
        .bundle(record.state.bundle().clone())
        .annotations(annotations);
    if let Some(pid) = record.state.pid() {
        builder = builder.pid(*pid);
    }
    record.state = builder.build().expect("rebuild paused OCI state");
    record
}

fn reference(
    source: &ContainerRecord,
    artifact: RuntimeArtifact,
    bytes: &[u8],
) -> CheckpointReference {
    let compatibility = CheckpointCompatibility::new(
        DriverKind::NativeLinux,
        IsolationClass::SharedHostKernel,
        HostPlatform::Linux,
        std::env::consts::ARCH,
        artifact,
        CheckpointDigest::new(format!("sha256:{}", "d".repeat(64))).expect("driver digest"),
        CheckpointFormat::new("test-checkpoint", 1).expect("checkpoint format"),
    )
    .expect("checkpoint compatibility");
    CheckpointReference::new(
        source,
        compatibility,
        CheckpointDigest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
            .expect("artifact digest"),
        u64::try_from(bytes.len()).expect("artifact size"),
    )
    .expect("checkpoint reference")
}

fn runtime_artifact() -> RuntimeArtifact {
    RuntimeArtifact::new(
        "a3s-oci-runtime",
        "0.2.0",
        format!("sha256:{}", "c".repeat(64)),
        Some("containerd-checkpoint-bridge-test".to_string()),
    )
    .expect("runtime artifact")
}

fn extensions(artifact: RuntimeArtifact, operations: &[RuntimeOperation]) -> RuntimeExtensions {
    RuntimeExtensions::new(
        artifact,
        vec![RuntimeDriverCapabilities::new(
            DriverKind::NativeLinux,
            vec![IsolationClass::SharedHostKernel],
            operations
                .iter()
                .copied()
                .map(RuntimeOperationCapability::v1)
                .collect(),
            AttachmentCapabilities::base_v1(),
        )
        .expect("runtime driver capabilities")],
    )
    .expect("runtime extensions")
}

fn assert_rpc_code(error: ttrpc::Error, expected: ttrpc::Code) {
    let ttrpc::Error::RpcStatus(status) = error else {
        panic!("expected RPC status, got {error}");
    };
    assert_eq!(status.code(), expected);
}
