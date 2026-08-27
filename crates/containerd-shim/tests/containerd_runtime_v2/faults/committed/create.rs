use std::path::PathBuf;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerRecord, ContainerTarget, CreateAttachments,
    CreateRequest as RuntimeCreateRequest, DriverKind, ErrorCode, Generation, IoMode,
    IsolationClass, IsolationRequest, OciBundle, OperationContext, ProcessIo,
    StateRequest as RuntimeStateRequest, TerminalSize,
};
use serde::Deserialize;

use crate::api::{ContainersClient, CreateTaskRequest, GetContainerRequest, TasksClient};
use crate::support::*;

use super::super::shared::{containerd_operation_id, runtime_client};
use super::super::{
    find_exact_shim_pid, find_runtime_host_pid, wait_for_runtime_absence, wait_for_shim_cleanup,
    SuspendedProcess, CREATE_INTENT_FILE_NAME,
};

const CREATE_INTENT_SCHEMA_VERSION: u32 = 2;
const DEFAULT_TERMINAL_WIDTH: u16 = 80;
const DEFAULT_TERMINAL_HEIGHT: u16 = 24;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedCreateIntent {
    schema_version: u32,
    namespace: String,
    task_id: String,
    incarnation: String,
    container_id: ContainerId,
    isolation: IsolationRequest,
    bundle: PathBuf,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    rootfs_mounted: bool,
    restore: Option<serde_json::Value>,
}

pub(crate) async fn qualify_create_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-create-committed");
    create_container(config, &id).await?;
    let channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, &id).await?;
    let host_pid = find_runtime_host_pid(config).await?;
    let mut suspended_host = SuspendedProcess::stop(host_pid, "A3S OCI host service")?;

    let create_channel = channel.clone();
    let create_namespace = config.namespace.clone();
    let create_id = id.clone();
    let mut create: tokio::task::JoinHandle<TestResult<crate::api::CreateTaskResponse>> =
        tokio::spawn(async move {
            TasksClient::new(create_channel)
                .create(namespaced(
                    CreateTaskRequest {
                        container_id: create_id,
                        rootfs,
                    },
                    &create_namespace,
                )?)
                .await
                .map(|response| response.into_inner())
                .map_err(|error| rpc_error("create post-commit shim-kill task", error).into())
        });

    let intent = wait_for_create_intent(config, &id).await?;
    validate_create_intent(config, &id, &intent)?;
    if tokio::time::timeout(Duration::from_millis(100), &mut create)
        .await
        .is_ok()
    {
        return Err(qualification_error(
            "Create completed while the exact A3S OCI host service was suspended",
        )
        .into());
    }

    let shim_pid = find_exact_shim_pid(config, &id).await?;
    let suspended_shim = SuspendedProcess::stop(shim_pid, "create-committed shim")?;
    suspended_host.resume("A3S OCI host service")?;

    let committed = commit_runtime_create(config, &intent).await?;
    validate_committed_record(&intent, &committed)?;
    let init_pid = committed
        .state
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(|| qualification_error("committed Runtime Create returned PID zero"))?;

    suspended_shim.kill("create-committed shim")?;
    match tokio::time::timeout(Duration::from_secs(10), &mut create).await {
        Ok(Ok(Err(_))) => {}
        Ok(Ok(Ok(response))) => {
            return Err(qualification_error(format!(
                "Create returned PID {} after its stopped shim was killed",
                response.pid
            ))
            .into());
        }
        Ok(Err(error)) => {
            return Err(qualification_error(format!(
                "join Create request after post-commit shim SIGKILL: {error}"
            ))
            .into());
        }
        Err(_) => {
            create.abort();
            return Err(qualification_error(
                "Create request remained pending for 10 seconds after post-commit shim SIGKILL",
            )
            .into());
        }
    }

    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[init_pid]).await?;
    wait_for_exact_runtime_absence(config, &intent.container_id, committed.generation).await?;
    wait_for_runtime_absence(config, intent.container_id.clone()).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed Runtime Create and shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

async fn wait_for_create_intent(
    config: &QualificationConfig,
    id: &str,
) -> TestResult<CommittedCreateIntent> {
    let path = config.bundle(id).join(CREATE_INTENT_FILE_NAME);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                return serde_json::from_slice(&bytes).map_err(|error| {
                    qualification_error(format!(
                        "decode post-commit Create intent {}: {error}",
                        path.display()
                    ))
                    .into()
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(qualification_error(format!(
                    "read post-commit Create intent {}: {error}",
                    path.display()
                ))
                .into());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "shim did not persist {} within 5 seconds of the blocked Create request",
                path.display()
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn validate_create_intent(
    config: &QualificationConfig,
    task_id: &str,
    intent: &CommittedCreateIntent,
) -> TestResult<()> {
    if intent.schema_version != CREATE_INTENT_SCHEMA_VERSION
        || intent.namespace != config.namespace
        || intent.task_id != task_id
        || intent.incarnation.is_empty()
        || intent.bundle != config.bundle(task_id)
        || intent.isolation != IsolationRequest::SharedHostKernel
        || !intent.rootfs_mounted
        || intent.restore.is_some()
    {
        return Err(qualification_error(format!(
            "post-commit Create intent did not retain the exact schema, task identity, bundle, isolation, and mounted-rootfs contract: {intent:?}"
        ))
        .into());
    }
    Ok(())
}

async fn commit_runtime_create(
    config: &QualificationConfig,
    intent: &CommittedCreateIntent,
) -> TestResult<ContainerRecord> {
    let bundle = OciBundle::load(&intent.bundle).await.map_err(|error| {
        qualification_error(format!(
            "load post-commit Create bundle {}: {error}",
            intent.bundle.display()
        ))
    })?;
    let attachments =
        CreateAttachments::from_bundle(&bundle, process_io(intent)).map_err(|error| {
            qualification_error(format!("derive post-commit Create attachments: {error}"))
        })?;
    let request = RuntimeCreateRequest {
        context: OperationContext::new(containerd_operation_id(
            &intent.namespace,
            &intent.task_id,
            &intent.incarnation,
            "create",
        )?),
        id: intent.container_id.clone(),
        bundle,
        isolation: intent.isolation.clone(),
        attachments,
    };
    let client = runtime_client(config).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let committed = loop {
        match client.create(request.clone()).await {
            Ok(record) => break record,
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime Create before shim death: {error}"
                ))
                .into());
            }
        }
    };
    let observed = client
        .state(RuntimeStateRequest {
            target: ContainerTarget::exact(intent.container_id.clone(), committed.generation),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read exact generation after committed Runtime Create: {error}"
            ))
        })?;
    if observed != committed {
        return Err(qualification_error(format!(
            "exact Runtime state changed the committed Create record: committed={committed:?}, observed={observed:?}"
        ))
        .into());
    }
    Ok(committed)
}

fn validate_committed_record(
    intent: &CommittedCreateIntent,
    record: &ContainerRecord,
) -> TestResult<()> {
    if record.state.id() != intent.container_id.as_str()
        || *record.state.status() != ContainerState::Created
        || record.generation.0 == 0
        || record.driver != DriverKind::NativeLinux
        || record.isolation != IsolationClass::SharedHostKernel
    {
        return Err(qualification_error(format!(
            "committed Runtime Create changed the container identity, state, generation, or isolation: {record:?}"
        ))
        .into());
    }
    Ok(())
}

fn process_io(intent: &CommittedCreateIntent) -> ProcessIo {
    if intent.terminal {
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
            stdin: if intent.stdin.is_empty() {
                IoMode::Null
            } else {
                IoMode::Pipe
            },
            stdout: if intent.stdout.is_empty() {
                IoMode::Null
            } else {
                IoMode::Capture
            },
            stderr: if intent.stderr.is_empty() {
                IoMode::Null
            } else {
                IoMode::Capture
            },
            terminal_size: None,
        }
    }
}

async fn wait_for_exact_runtime_absence(
    config: &QualificationConfig,
    container_id: &ContainerId,
    generation: Generation,
) -> TestResult<()> {
    let client = runtime_client(config).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .state(RuntimeStateRequest {
                target: ContainerTarget::exact(container_id.clone(), generation),
            })
            .await
        {
            Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {}
            Err(error) => {
                return Err(qualification_error(format!(
                    "inspect committed Runtime Create generation after shim cleanup: {error}"
                ))
                .into());
            }
            Ok(_) if tokio::time::Instant::now() < deadline => {}
            Ok(record) => {
                return Err(qualification_error(format!(
                    "committed Runtime Create generation {} for {} survived shim cleanup as driver {:?} and isolation {:?}",
                    record.generation.0,
                    container_id.as_str(),
                    record.driver,
                    record.isolation
                ))
                .into());
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
