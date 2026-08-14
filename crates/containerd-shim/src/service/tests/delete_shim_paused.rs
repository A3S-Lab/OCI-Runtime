use std::sync::{Arc, Mutex};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    async_trait, ContainerOperationRequest, ContainerRecord, DeleteMode, DeleteRequest,
    Error as RuntimeError, ErrorCode, ExitStatus, Generation, IsolationRequest, KillRequest,
    OciRuntimeService, StateRequest, WaitRequest, PAUSED_STATE_ANNOTATION,
};
use containerd_shim::asynchronous::Shim;

use super::{metadata_from_task, recovery_service_instance, task_state};
use crate::adapter::RuntimeAdapter;
use crate::metadata::ShimMetadata;

#[derive(Default)]
struct PausedCleanupCalls {
    order: Vec<&'static str>,
    states: Vec<StateRequest>,
    resumes: Vec<ContainerOperationRequest>,
    kills: Vec<KillRequest>,
    waits: Vec<WaitRequest>,
    deletes: Vec<DeleteRequest>,
}

#[derive(Clone)]
struct PausedCleanupService {
    paused: ContainerRecord,
    resumed: ContainerRecord,
    calls: Arc<Mutex<PausedCleanupCalls>>,
    delete_error: Option<RuntimeError>,
}

#[async_trait]
impl OciRuntimeService for PausedCleanupService {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(
        &self,
        _request: a3s_oci_sdk::CreateRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        let mut calls = self.calls.lock().expect("paused cleanup calls");
        calls.order.push("state");
        calls.states.push(request);
        Ok(self.paused.clone())
    }

    async fn start(
        &self,
        _request: a3s_oci_sdk::StartRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn resume(
        &self,
        request: ContainerOperationRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        {
            let mut calls = self.calls.lock().expect("paused cleanup calls");
            calls.order.push("resume");
            calls.resumes.push(request);
        }
        Ok(self.resumed.clone())
    }

    async fn kill(&self, request: KillRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        let mut calls = self.calls.lock().expect("paused cleanup calls");
        calls.order.push("kill");
        calls.kills.push(request);
        Ok(self.resumed.clone())
    }

    async fn wait(&self, request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        let mut calls = self.calls.lock().expect("paused cleanup calls");
        calls.order.push("wait");
        calls.waits.push(request);
        ExitStatus::signaled(9, false)
    }

    async fn delete(&self, request: DeleteRequest) -> a3s_oci_sdk::Result<()> {
        let mut calls = self.calls.lock().expect("paused cleanup calls");
        calls.order.push("delete");
        calls.deletes.push(request);
        match &self.delete_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

#[tokio::test]
async fn delete_shim_force_deletes_a_paused_generation_without_blocking_kill() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    task.exit = None;
    task.exited_at = None;
    let resumed = task.record.clone();
    task.record = record_with_paused_state(&resumed, true);
    metadata_from_task(&task)
        .store()
        .expect("store paused task metadata");

    let calls = Arc::new(Mutex::new(PausedCleanupCalls::default()));
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(PausedCleanupService {
            paused: task.record.clone(),
            resumed,
            calls: calls.clone(),
            delete_error: None,
        }),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let response = service
        .delete_shim()
        .await
        .expect("force-delete paused runtime generation");

    assert_eq!(response.pid(), 4242);
    assert_eq!(response.exit_status(), 137);
    assert!(!ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("paused cleanup calls");
    assert_eq!(calls.order, ["state", "delete"]);
    assert_eq!(calls.states.len(), 1);
    assert_eq!(calls.states[0].target.generation, Some(Generation(7)));
    assert!(calls.resumes.is_empty());
    assert!(calls.kills.is_empty());
    assert!(calls.waits.is_empty());
    assert_eq!(calls.deletes.len(), 1);
    assert_eq!(calls.deletes[0].mode, DeleteMode::Force);
    assert_eq!(calls.deletes[0].target.generation, Some(Generation(7)));
}

#[tokio::test]
async fn delete_shim_retains_metadata_when_paused_force_delete_fails() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    task.exit = None;
    task.exited_at = None;
    let resumed = task.record.clone();
    task.record = record_with_paused_state(&resumed, true);
    metadata_from_task(&task)
        .store()
        .expect("store paused task metadata");

    let calls = Arc::new(Mutex::new(PausedCleanupCalls::default()));
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(PausedCleanupService {
            paused: task.record,
            resumed,
            calls: calls.clone(),
            delete_error: Some(
                RuntimeError::new(
                    ErrorCode::Conflict,
                    "paused force Delete generation no longer matches",
                )
                .for_operation("test-delete"),
            ),
        }),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let error = service
        .delete_shim()
        .await
        .expect_err("failed paused force Delete must fail closed");

    assert!(error.to_string().contains("generation no longer matches"));
    assert!(ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("paused cleanup calls");
    assert_eq!(calls.order, ["state", "delete"]);
    assert!(calls.resumes.is_empty());
    assert!(calls.kills.is_empty());
    assert!(calls.waits.is_empty());
    assert_eq!(calls.deletes.len(), 1);
    assert_eq!(calls.deletes[0].mode, DeleteMode::Force);
    assert_eq!(calls.deletes[0].target.generation, Some(Generation(7)));
}

#[tokio::test]
async fn delete_shim_rejects_a_drifted_paused_generation_before_cleanup() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    task.exit = None;
    task.exited_at = None;
    let resumed = task.record.clone();
    task.record = record_with_paused_state(&resumed, true);
    metadata_from_task(&task)
        .store()
        .expect("store paused task metadata");

    let mut drifted = task.record;
    drifted.generation = Generation(8);
    let calls = Arc::new(Mutex::new(PausedCleanupCalls::default()));
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(PausedCleanupService {
            paused: drifted,
            resumed,
            calls: calls.clone(),
            delete_error: None,
        }),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let error = service
        .delete_shim()
        .await
        .expect_err("drifted paused generation must fail closed");

    assert!(error.to_string().contains("no longer matches"));
    assert!(ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("paused cleanup calls");
    assert_eq!(calls.order, ["state"]);
    assert!(calls.resumes.is_empty());
    assert!(calls.kills.is_empty());
    assert!(calls.waits.is_empty());
    assert!(calls.deletes.is_empty());
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
    record.state = builder.build().expect("rebuild paused test state");
    record
}
