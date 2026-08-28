use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};
use a3s_oci_sdk::{
    async_trait, ContainerId, ContainerRecord, ContainerTarget, CreateRequest, DeleteMode,
    DeleteRequest, DriverKind, Error, ErrorCode, Generation, IsolationClass, IsolationRequest,
    KillRequest, OciBundle, OciRuntimeService, Result, RuntimeClient, RuntimeInfo, Signal,
    StartRequest, StateRequest,
};
use clap::Parser;
use serde_json::json;
use tempfile::TempDir;

use super::{reject_terminal_bundle, Adapter};
use crate::{Cli, Command};

#[derive(Default)]
struct MockService {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    generation: u64,
    record: Option<ContainerRecord>,
    create_response: Option<(String, ContainerRecord)>,
    start_response: Option<(String, ContainerRecord)>,
    kill_response: Option<(String, ContainerRecord)>,
    delete_response: Option<String>,
    create_calls: Vec<String>,
    start_calls: Vec<(String, ContainerTarget)>,
    kill_calls: Vec<(String, ContainerTarget, i32, bool)>,
    delete_calls: Vec<(String, ContainerTarget, DeleteMode)>,
    lose_create_response_once: bool,
    lose_start_response_once: bool,
    lose_delete_response_once: bool,
}

impl MockService {
    fn inner(&self) -> MutexGuard<'_, MockInner> {
        self.inner.lock().expect("mock service lock")
    }

    fn lose_create_response_once(&self) {
        self.inner().lose_create_response_once = true;
    }

    fn lose_start_response_once(&self) {
        self.inner().lose_start_response_once = true;
    }

    fn lose_delete_response_once(&self) {
        self.inner().lose_delete_response_once = true;
    }
}

#[async_trait]
impl OciRuntimeService for MockService {
    async fn features(&self) -> Result<RuntimeInfo> {
        Err(Error::unsupported("features"))
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        let mut inner = self.inner();
        let operation_id = request.context.operation_id.to_string();
        inner.create_calls.push(operation_id.clone());
        if let Some((cached_id, response)) = &inner.create_response {
            if cached_id == &operation_id {
                return Ok(response.clone());
            }
        }
        if inner.record.is_some() {
            return Err(
                Error::new(ErrorCode::AlreadyExists, "mock container already exists")
                    .for_operation("create"),
            );
        }

        inner.generation += 1;
        let generation = Generation(inner.generation);
        let record = record(
            &request.id,
            generation,
            ContainerState::Created,
            Some(4242),
            request.bundle.directory(),
            request.bundle.config_digest(),
            &request.attachments.digest()?,
            request.isolation.class(),
        )?;
        inner.record = Some(record.clone());
        inner.create_response = Some((operation_id, record.clone()));
        if std::mem::take(&mut inner.lose_create_response_once) {
            return Err(response_lost("create"));
        }
        Ok(record)
    }

    async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        let inner = self.inner();
        let record = inner.record.as_ref().ok_or_else(container_not_found)?;
        if request.target.id.as_str() != record.state.id()
            || request
                .target
                .generation
                .is_some_and(|generation| generation != record.generation)
        {
            return Err(container_not_found());
        }
        Ok(record.clone())
    }

    async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        let mut inner = self.inner();
        let operation_id = request.context.operation_id.to_string();
        inner
            .start_calls
            .push((operation_id.clone(), request.target.clone()));
        if let Some((cached_id, response)) = &inner.start_response {
            if cached_id == &operation_id {
                return Ok(response.clone());
            }
        }
        let current = matching_record(&inner, &request.target)?;
        if *current.state.status() != ContainerState::Created {
            return Err(
                Error::new(ErrorCode::FailedPrecondition, "mock start requires created")
                    .for_operation("start"),
            );
        }
        let running = transition(&current, ContainerState::Running, Some(4242))?;
        inner.record = Some(running.clone());
        inner.start_response = Some((operation_id, running.clone()));
        if std::mem::take(&mut inner.lose_start_response_once) {
            return Err(response_lost("start"));
        }
        Ok(running)
    }

    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        let mut inner = self.inner();
        let operation_id = request.context.operation_id.to_string();
        inner.kill_calls.push((
            operation_id.clone(),
            request.target.clone(),
            request.signal.get(),
            request.all,
        ));
        if let Some((cached_id, response)) = &inner.kill_response {
            if cached_id == &operation_id {
                return Ok(response.clone());
            }
        }
        let current = matching_record(&inner, &request.target)?;
        if !matches!(
            *current.state.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "mock kill requires created or running",
            )
            .for_operation("kill"));
        }
        let stopped = transition(&current, ContainerState::Stopped, None)?;
        inner.record = Some(stopped.clone());
        inner.kill_response = Some((operation_id, stopped.clone()));
        Ok(stopped)
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        let mut inner = self.inner();
        let operation_id = request.context.operation_id.to_string();
        inner
            .delete_calls
            .push((operation_id.clone(), request.target.clone(), request.mode));
        if inner.delete_response.as_deref() == Some(&operation_id) {
            return Ok(());
        }
        let current = matching_record(&inner, &request.target)?;
        if request.mode == DeleteMode::StoppedOnly
            && *current.state.status() != ContainerState::Stopped
        {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "mock stopped-only delete requires stopped",
            )
            .for_operation("delete"));
        }
        inner.record = None;
        inner.delete_response = Some(operation_id);
        if std::mem::take(&mut inner.lose_delete_response_once) {
            return Err(response_lost("delete"));
        }
        Ok(())
    }
}

#[tokio::test]
async fn ambiguous_create_reuses_identity_then_rejects_a_duplicate() {
    let fixture = Fixture::new().await;
    fixture.service.lose_create_response_once();
    let pid_file = fixture.temporary.path().join("container.pid");

    let first = fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            Some(pid_file.clone()),
        )
        .await
        .expect_err("first create response is deliberately lost");
    assert!(first.retryable);
    assert!(!pid_file.exists());

    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            Some(pid_file.clone()),
        )
        .await
        .expect("same create must replay");
    assert_eq!(fs::read_to_string(&pid_file).expect("PID file"), "4242");

    let duplicate = fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            Some(pid_file),
        )
        .await
        .expect_err("acknowledged create must not be replayed as a new command");
    assert_eq!(duplicate.code, ErrorCode::AlreadyExists);
    let inner = fixture.service.inner();
    assert_eq!(inner.create_calls.len(), 2);
    assert_eq!(inner.create_calls[0], inner.create_calls[1]);
}

#[tokio::test]
async fn replayed_already_exists_never_adopts_an_unproven_container() {
    let fixture = Fixture::new().await;
    fixture.service.lose_create_response_once();
    let first = fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect_err("first create response is deliberately lost");
    assert!(first.retryable);

    // Simulate a Host that retained the container but lost the operation
    // receipt. AlreadyExists cannot prove that this CLI incarnation created
    // the matching container, even when its immutable configuration matches.
    fixture.service.inner().create_response = None;
    let replay = fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect_err("an unproven existing container must not be adopted");
    assert_eq!(replay.code, ErrorCode::AlreadyExists);

    let local_state = fixture
        .adapter()
        .state(fixture.id())
        .await
        .expect_err("the rejected lifecycle must be retired locally");
    assert_eq!(local_state.code, ErrorCode::NotFound);
    let inner = fixture.service.inner();
    assert_eq!(inner.create_calls.len(), 2);
    assert_eq!(inner.create_calls[0], inner.create_calls[1]);
}

#[tokio::test]
async fn lifecycle_replays_start_and_delete_then_reuses_id_with_a_new_incarnation() {
    let fixture = Fixture::new().await;
    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect("create");

    fixture.service.lose_start_response_once();
    let first_start = fixture
        .adapter()
        .start(fixture.id())
        .await
        .expect_err("first start response is deliberately lost");
    assert!(first_start.retryable);
    fixture
        .adapter()
        .start(fixture.id())
        .await
        .expect("start replay");
    let duplicate_start = fixture
        .adapter()
        .start(fixture.id())
        .await
        .expect_err("duplicate start must fail");
    assert_eq!(duplicate_start.code, ErrorCode::FailedPrecondition);

    fixture
        .adapter()
        .kill(fixture.id(), Signal::new(9).expect("SIGKILL"), false)
        .await
        .expect("kill");
    fixture.service.lose_delete_response_once();
    let first_delete = fixture
        .adapter()
        .delete(fixture.id(), DeleteMode::StoppedOnly)
        .await
        .expect_err("first delete response is deliberately lost");
    assert!(first_delete.retryable);
    fixture
        .adapter()
        .delete(fixture.id(), DeleteMode::StoppedOnly)
        .await
        .expect("delete replay");

    let missing = fixture
        .adapter()
        .state(fixture.id())
        .await
        .expect_err("deleted lifecycle must be absent");
    assert_eq!(missing.code, ErrorCode::NotFound);
    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect("reuse ID after delete");

    let inner = fixture.service.inner();
    assert_eq!(inner.start_calls.len(), 2);
    assert_eq!(inner.start_calls[0].0, inner.start_calls[1].0);
    assert_eq!(inner.start_calls[0].1.generation, Some(Generation(1)));
    assert_eq!(inner.delete_calls.len(), 2);
    assert_eq!(inner.delete_calls[0].0, inner.delete_calls[1].0);
    assert_ne!(inner.create_calls[0], inner.create_calls[1]);
    assert_eq!(
        inner.record.as_ref().expect("second generation").generation,
        Generation(2)
    );
}

#[tokio::test]
async fn definitive_delete_failure_allocates_a_fresh_retry_after_state_changes() {
    let fixture = Fixture::new().await;
    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect("create");
    let created_delete = fixture
        .adapter()
        .delete(fixture.id(), DeleteMode::StoppedOnly)
        .await
        .expect_err("created container cannot be deleted without force");
    assert_eq!(created_delete.code, ErrorCode::FailedPrecondition);
    fixture
        .adapter()
        .kill(fixture.id(), Signal::new(9).expect("SIGKILL"), false)
        .await
        .expect("kill created container");
    fixture
        .adapter()
        .delete(fixture.id(), DeleteMode::StoppedOnly)
        .await
        .expect("delete stopped container");

    let inner = fixture.service.inner();
    assert_eq!(inner.delete_calls.len(), 2);
    assert_ne!(inner.delete_calls[0].0, inner.delete_calls[1].0);
}

#[tokio::test]
async fn ambiguous_create_rejects_changed_bundle_without_dispatch() {
    let fixture = Fixture::new().await;
    fixture.service.lose_create_response_once();
    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect_err("first create response is deliberately lost");
    let changed_bundle = fixture.bundle_with_args(&["/bin/false"]).await;
    let changed = fixture
        .adapter()
        .create(
            fixture.id(),
            changed_bundle,
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect_err("ambiguous create identity must be immutable");
    assert_eq!(changed.code, ErrorCode::FailedPrecondition);
    assert_eq!(fixture.service.inner().create_calls.len(), 1);

    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect("exact create retry");
}

#[tokio::test]
async fn journal_lock_serializes_concurrent_create_commands() {
    let fixture = Fixture::new().await;
    let left_adapter = fixture.adapter();
    let right_adapter = fixture.adapter();
    let left = left_adapter.create(
        fixture.id(),
        fixture.bundle.clone(),
        IsolationRequest::SharedHostKernel,
        None,
    );
    let right = right_adapter.create(
        fixture.id(),
        fixture.bundle.clone(),
        IsolationRequest::SharedHostKernel,
        None,
    );
    let (left, right) = tokio::join!(left, right);
    assert!(left.is_ok() ^ right.is_ok());
    let error = left.err().or_else(|| right.err()).expect("one duplicate");
    assert_eq!(error.code, ErrorCode::AlreadyExists);
    assert_eq!(fixture.service.inner().create_calls.len(), 1);
}

#[tokio::test]
async fn corrupt_latest_snapshot_fails_closed() {
    let fixture = Fixture::new().await;
    fixture
        .adapter()
        .create(
            fixture.id(),
            fixture.bundle.clone(),
            IsolationRequest::SharedHostKernel,
            None,
        )
        .await
        .expect("create");
    let directory = fixture.state_root.join(fixture.id().as_str());
    let snapshot = fs::read_dir(&directory)
        .expect("journal directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .expect("journal snapshot");
    fs::write(&snapshot, b"{broken").expect("corrupt snapshot");

    let error = fixture
        .adapter()
        .state(fixture.id())
        .await
        .expect_err("corruption must not fall back to current generation");
    assert_eq!(error.code, ErrorCode::Internal);
}

#[tokio::test]
async fn terminal_bundle_is_rejected_before_runtime_mutation() {
    let fixture = Fixture::new().await;
    let terminal = fixture.bundle_with_terminal(true).await;
    let error = reject_terminal_bundle(&terminal).expect_err("terminal handoff is not integrated");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(fixture.service.inner().create_calls.is_empty());
}

#[test]
fn parser_accepts_oci_and_runc_signal_forms() {
    let positional =
        Cli::try_parse_from(["a3s-oci", "kill", "sample", "KILL"]).expect("positional signal");
    assert!(matches!(
        positional.command,
        Command::Kill {
            positional_signal: Some(signal),
            signal_option: None,
            ..
        } if signal == "KILL"
    ));
    let option = Cli::try_parse_from(["a3s-oci", "kill", "--signal", "TERM", "--all", "sample"])
        .expect("OCI signal option");
    assert!(matches!(
        option.command,
        Command::Kill {
            positional_signal: None,
            signal_option: Some(signal),
            all: true,
            ..
        } if signal == "TERM"
    ));
}

struct Fixture {
    temporary: TempDir,
    state_root: PathBuf,
    bundle: OciBundle,
    service: Arc<MockService>,
}

impl Fixture {
    async fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        // macOS exposes /var through the system /private/var alias. The
        // production adapter intentionally requires callers to provide the
        // canonical state root, so the cross-platform fixture must do the
        // same instead of weakening the journal's symlink boundary.
        let state_root = fs::canonicalize(temporary.path())
            .expect("canonical temporary directory")
            .join("state");
        create_private_directory(&state_root);
        let bundle = write_bundle(temporary.path().join("bundle"), false, &["/bin/true"]).await;
        Self {
            temporary,
            state_root,
            bundle,
            service: Arc::new(MockService::default()),
        }
    }

    fn adapter(&self) -> Adapter {
        Adapter::new(
            self.state_root.clone(),
            RuntimeClient::from_arc(self.service.clone()),
        )
    }

    fn id(&self) -> ContainerId {
        ContainerId::new("cli-container").expect("container ID")
    }

    async fn bundle_with_args(&self, args: &[&str]) -> OciBundle {
        write_bundle(self.temporary.path().join("changed-bundle"), false, args).await
    }

    async fn bundle_with_terminal(&self, terminal: bool) -> OciBundle {
        write_bundle(
            self.temporary.path().join("terminal-bundle"),
            terminal,
            &["/bin/true"],
        )
        .await
    }
}

async fn write_bundle(directory: PathBuf, terminal: bool, args: &[&str]) -> OciBundle {
    fs::create_dir(&directory).expect("bundle directory");
    fs::create_dir(directory.join("rootfs")).expect("rootfs directory");
    let config = json!({
        "ociVersion": "1.3.0",
        "root": { "path": "rootfs", "readonly": false },
        "process": {
            "terminal": terminal,
            "user": { "uid": 0, "gid": 0 },
            "args": args,
            "env": ["PATH=/bin"],
            "cwd": "/"
        },
        "linux": { "namespaces": [] }
    });
    fs::write(
        directory.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("encode config"),
    )
    .expect("write config");
    OciBundle::load(directory).await.expect("load bundle")
}

fn create_private_directory(path: &Path) {
    fs::create_dir(path).expect("private directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private permissions");
    }
}

fn matching_record(inner: &MockInner, target: &ContainerTarget) -> Result<ContainerRecord> {
    let record = inner.record.as_ref().ok_or_else(container_not_found)?;
    if record.state.id() != target.id.as_str()
        || target
            .generation
            .is_some_and(|generation| generation != record.generation)
    {
        return Err(container_not_found());
    }
    Ok(record.clone())
}

fn transition(
    current: &ContainerRecord,
    status: ContainerState,
    pid: Option<i32>,
) -> Result<ContainerRecord> {
    record(
        &ContainerId::new(current.state.id().to_string())?,
        current.generation,
        status,
        pid,
        current.state.bundle(),
        &current.config_digest,
        current
            .attachments_digest
            .as_deref()
            .ok_or_else(|| Error::new(ErrorCode::Internal, "missing mock attachment digest"))?,
        current.isolation,
    )
}

#[allow(clippy::too_many_arguments)]
fn record(
    id: &ContainerId,
    generation: Generation,
    status: ContainerState,
    pid: Option<i32>,
    bundle: &Path,
    config_digest: &str,
    attachments_digest: &str,
    isolation: IsolationClass,
) -> Result<ContainerRecord> {
    let mut builder = StateBuilder::default()
        .version("1.3.0")
        .id(id.as_str())
        .status(status)
        .bundle(bundle.to_path_buf());
    if let Some(pid) = pid {
        builder = builder.pid(pid);
    }
    let state = builder
        .build()
        .map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))?;
    Ok(ContainerRecord {
        state,
        generation,
        driver: DriverKind::NativeLinux,
        isolation,
        guest_session: None,
        network_enforcement: None,
        config_digest: config_digest.to_string(),
        attachments_digest: Some(attachments_digest.to_string()),
    })
}

fn response_lost(operation: &str) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!("mock {operation} response was lost"),
    )
    .for_operation(operation)
    .retryable(true)
}

fn container_not_found() -> Error {
    Error::new(ErrorCode::NotFound, "mock container not found").for_operation("state")
}
