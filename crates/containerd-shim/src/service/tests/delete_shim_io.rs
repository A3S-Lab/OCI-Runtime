use super::*;

#[derive(Default)]
struct CommittedIoCleanupCalls {
    states: Vec<StateRequest>,
    writes: usize,
    closes: usize,
    kills: Vec<RuntimeKillRequest>,
    deletes: Vec<RuntimeDeleteRequest>,
}

#[derive(Clone)]
struct CommittedIoCleanupService {
    record: ContainerRecord,
    calls: Arc<std::sync::Mutex<CommittedIoCleanupCalls>>,
}

#[async_trait]
impl OciRuntimeService for CommittedIoCleanupService {
    async fn features(&self) -> a3s_oci_sdk::Result<a3s_oci_sdk::RuntimeInfo> {
        Err(RuntimeError::unsupported("test-features"))
    }

    async fn create(&self, _request: CreateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-create"))
    }

    async fn state(&self, request: StateRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        if request.target.id.as_str() != self.record.state.id()
            || request.target.generation != Some(self.record.generation)
        {
            return Err(RuntimeError::new(
                ErrorCode::Conflict,
                "cleanup state target drifted from the committed stdin generation",
            )
            .for_operation("test-state"));
        }
        self.calls
            .lock()
            .expect("committed-I/O cleanup calls")
            .states
            .push(request);
        Ok(self.record.clone())
    }

    async fn start(
        &self,
        _request: a3s_oci_sdk::StartRequest,
    ) -> a3s_oci_sdk::Result<ContainerRecord> {
        Err(RuntimeError::unsupported("test-start"))
    }

    async fn kill(&self, request: RuntimeKillRequest) -> a3s_oci_sdk::Result<ContainerRecord> {
        self.calls
            .lock()
            .expect("committed-I/O cleanup calls")
            .kills
            .push(request);
        Ok(self.record.clone())
    }

    async fn delete(&self, request: RuntimeDeleteRequest) -> a3s_oci_sdk::Result<()> {
        self.calls
            .lock()
            .expect("committed-I/O cleanup calls")
            .deletes
            .push(request);
        Ok(())
    }

    async fn wait(&self, _request: WaitRequest) -> a3s_oci_sdk::Result<ExitStatus> {
        ExitStatus::signaled(9, false)
    }

    async fn write_stdin(
        &self,
        _request: a3s_oci_sdk::WriteStdinRequest,
    ) -> a3s_oci_sdk::Result<()> {
        self.calls
            .lock()
            .expect("committed-I/O cleanup calls")
            .writes += 1;
        Ok(())
    }

    async fn close_stdin(
        &self,
        _request: a3s_oci_sdk::CloseStdinRequest,
    ) -> a3s_oci_sdk::Result<()> {
        self.calls
            .lock()
            .expect("committed-I/O cleanup calls")
            .closes += 1;
        Ok(())
    }
}

#[tokio::test]
async fn delete_shim_does_not_replay_a_committed_pending_stdin_write() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    task.exit = None;
    task.pending_stdin_write = Some(
        PendingStdinWrite::new(1, b"committed-before-cleanup\n".to_vec())
            .expect("bounded pending stdin write"),
    );
    metadata_from_task(&task)
        .store()
        .expect("store pending stdin metadata");

    let calls = Arc::new(std::sync::Mutex::new(CommittedIoCleanupCalls {
        writes: 1,
        ..CommittedIoCleanupCalls::default()
    }));
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(CommittedIoCleanupService {
            record: task.record.clone(),
            calls: calls.clone(),
        }),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let response = service
        .delete_shim()
        .await
        .expect("clean exact generation after committed stdin write");

    assert_eq!(response.pid(), 4242);
    assert_eq!(response.exit_status(), 137);
    assert!(!ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("committed-I/O cleanup calls");
    assert_eq!(calls.writes, 1, "DeleteShim replayed committed stdin");
    assert_eq!(calls.closes, 0);
    assert_eq!(calls.states.len(), 1);
    assert_eq!(calls.kills.len(), 1);
    assert_eq!(calls.kills[0].target.generation, Some(Generation(7)));
    assert_eq!(calls.kills[0].signal.get(), 9);
    assert!(calls.kills[0].all);
    assert_eq!(calls.deletes.len(), 1);
    assert_eq!(calls.deletes[0].target.generation, Some(Generation(7)));
    assert_eq!(calls.deletes[0].mode, DeleteMode::Force);
}

#[tokio::test]
async fn delete_shim_does_not_replay_a_committed_pending_stdin_close() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut task = task_state(directory.path());
    task.rootfs_mounted = false;
    task.exit = None;
    task.stdin_close_state = StdinCloseState::Closing;
    metadata_from_task(&task)
        .store()
        .expect("store pending stdin close metadata");

    let calls = Arc::new(std::sync::Mutex::new(CommittedIoCleanupCalls {
        closes: 1,
        ..CommittedIoCleanupCalls::default()
    }));
    let adapter = RuntimeAdapter::from_client(
        a3s_oci_sdk::RuntimeClient::new(CommittedIoCleanupService {
            record: task.record.clone(),
            calls: calls.clone(),
        }),
        IsolationRequest::SharedHostKernel,
    );
    let mut service = recovery_service_instance(directory.path(), adapter);

    let response = service
        .delete_shim()
        .await
        .expect("clean exact generation after committed stdin close");

    assert_eq!(response.pid(), 4242);
    assert_eq!(response.exit_status(), 137);
    assert!(!ShimMetadata::path(directory.path()).exists());
    let calls = calls.lock().expect("committed-I/O cleanup calls");
    assert_eq!(calls.writes, 0);
    assert_eq!(calls.closes, 1, "DeleteShim replayed committed stdin close");
    assert_eq!(calls.states.len(), 1);
    assert_eq!(calls.kills.len(), 1);
    assert_eq!(calls.kills[0].target.generation, Some(Generation(7)));
    assert_eq!(calls.kills[0].signal.get(), 9);
    assert!(calls.kills[0].all);
    assert_eq!(calls.deletes.len(), 1);
    assert_eq!(calls.deletes[0].target.generation, Some(Generation(7)));
    assert_eq!(calls.deletes[0].mode, DeleteMode::Force);
}
