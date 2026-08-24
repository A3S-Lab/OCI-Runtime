use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, Generation, OperationContext, ProcessTarget, StateRequest, WaitProcessRequest,
    WriteStdinRequest,
};
use prost_types::Any;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;

use crate::api::{
    ContainersClient, CreateTaskRequest, ExecProcessRequest, GetContainerRequest, StartRequest,
    TasksClient,
};
use crate::support::*;
use crate::terminal;

use super::shared::{containerd_exec_operation_id, containerd_process_id, runtime_client};
use super::{
    find_exact_shim_pid, wait_for_runtime_absence, wait_for_shim_cleanup, SuspendedProcess,
};

#[path = "process_io/close_stdin.rs"]
mod close_stdin;
#[path = "process_io/resize.rs"]
mod resize;

pub(super) use close_stdin::qualify_close_stdin_effect_committed_shim_sigkill;
pub(super) use resize::qualify_resize_effect_committed_shim_sigkill;

const EXEC_ID: &str = "committed-stdin-exec";
const COMMITTED_STDIN: &[u8] = b"committed-before-cleanup\n";
const EXEC_EXIT_STATUS: i32 = 23;

#[derive(Debug, Deserialize)]
struct MetadataDocument {
    schema_version: u64,
    exec_sequence: u64,
    execs: Vec<ExecStdinEvidence>,
}

#[derive(Debug, Deserialize)]
struct ExecStdinEvidence {
    exec_id: String,
    incarnation: u64,
    #[serde(default)]
    stdin_sequence: u64,
    pending_stdin_write: Option<PendingStdinEvidence>,
    #[serde(default)]
    stdin_close_state: StdinCloseEvidence,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum StdinCloseEvidence {
    #[default]
    Open,
    Closing,
    Closed,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct PendingStdinEvidence {
    sequence: u64,
    data: Vec<u8>,
}

#[test]
fn pending_write_evidence_defaults_an_omitted_zero_stdin_sequence() {
    let document: MetadataDocument = serde_json::from_value(serde_json::json!({
        "schema_version": 9,
        "exec_sequence": 1,
        "execs": [{
            "exec_id": EXEC_ID,
            "incarnation": 1,
            "pending_stdin_write": {
                "sequence": 1,
                "data": COMMITTED_STDIN
            }
        }]
    }))
    .expect("decode metadata that elides a zero stdin sequence");

    assert_eq!(document.execs[0].stdin_sequence, 0);
    assert_eq!(
        document.execs[0].stdin_close_state,
        StdinCloseEvidence::Open
    );
}

pub(super) async fn qualify_write_stdin_effect_committed_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-write-stdin-committed");
    create_container(config, &id).await?;
    let channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, &id).await?;
    let created = TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: id.clone(),
                rootfs,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("create committed-stdin task", error))?
        .into_inner();
    let started = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start committed-stdin task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "committed-stdin task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let bundle = config.bundle(&id);
    let stdin_path = bundle.join("committed-stdin-exec.stdin");
    terminal::create_fifo(&stdin_path).await?;
    let mut stdin = tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&stdin_path)
        .await
        .map_err(|error| {
            qualification_error(format!("open committed-stdin FIFO for read/write: {error}"))
        })?;
    let spec = serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": [
            "/bin/sh",
            "-c",
            "IFS= read -r line; [ \"$line\" = committed-before-cleanup ] || exit 91; exit 23"
        ],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    });
    TasksClient::new(channel.clone())
        .exec(namespaced(
            ExecProcessRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
                stdin: stdin_path.to_string_lossy().into_owned(),
                spec: Some(Any {
                    type_url: crate::PROCESS_SPEC_TYPE.to_string(),
                    value: serde_json::to_vec(&spec).map_err(|error| {
                        qualification_error(format!("encode committed-stdin exec process: {error}"))
                    })?,
                }),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("add committed-stdin exec", error))?;
    let exec = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                exec_id: EXEC_ID.to_string(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start committed-stdin exec", error))?
        .into_inner();
    if exec.pid == 0 || exec.pid == started.pid {
        return Err(qualification_error(format!(
            "committed-stdin exec PID {} must be nonzero and distinct from init PID {}",
            exec.pid, started.pid
        ))
        .into());
    }

    let identity = read_runtime_identity(config, &id).await?;
    let host_pid = super::find_runtime_host_pid(config).await?;
    let shim_pid = find_exact_shim_pid(config, &id).await?;
    let mut suspended_host =
        SuspendedProcess::stop(host_pid, "committed-stdin A3S OCI host service")?;
    stdin
        .write_all(COMMITTED_STDIN)
        .await
        .map_err(|error| qualification_error(format!("write committed-stdin FIFO: {error}")))?;
    stdin
        .flush()
        .await
        .map_err(|error| qualification_error(format!("flush committed-stdin FIFO: {error}")))?;
    wait_for_pending_write(&bundle).await?;
    let suspended_shim = SuspendedProcess::stop(shim_pid, "committed-stdin shim")?;
    suspended_host.resume("committed-stdin A3S OCI host service")?;

    let process = exact_process_target(config, &id, &identity)?;
    commit_runtime_write(config, &id, &identity, &process).await?;
    let exit = wait_runtime_process(config, process).await?;
    if exit.exit_code != Some(EXEC_EXIT_STATUS) || exit.signal.is_some() || exit.oom_killed {
        return Err(qualification_error(format!(
            "committed Runtime WriteStdin produced exitCode={:?}, signal={:?}, oomKilled={}; expected exit {EXEC_EXIT_STATUS}",
            exit.exit_code, exit.signal, exit.oom_killed
        ))
        .into());
    }
    let init = runtime_client(config)
        .await?
        .state(StateRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read init state after committed Runtime WriteStdin: {error}"
            ))
        })?;
    if init.generation != Generation(identity.generation)
        || *init.state.status() != ContainerState::Running
        || init.state.pid().and_then(|pid| u32::try_from(pid).ok()) != Some(started.pid)
    {
        return Err(qualification_error(format!(
            "committed Runtime WriteStdin changed init generation, state, or PID: generation={}, status={}, pid={:?}",
            init.generation.0,
            init.state.status(),
            init.state.pid()
        ))
        .into());
    }

    suspended_shim.kill("committed-stdin shim")?;
    drop(stdin);
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[started.pid, exec.pid]).await?;
    wait_for_runtime_absence(config, identity.container_id).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after committed Runtime WriteStdin and shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

async fn wait_for_pending_write(bundle: &Path) -> TestResult<()> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let document: MetadataDocument = serde_json::from_slice(
            &tokio::fs::read(&path)
                .await
                .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
        )
        .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
        let exec = document
            .execs
            .iter()
            .find(|exec| exec.exec_id == EXEC_ID)
            .ok_or_else(|| qualification_error(format!("shim metadata omitted exec {EXEC_ID}")))?;
        if document.schema_version == 9
            && document.exec_sequence == 1
            && exec.incarnation == 1
            && exec.stdin_sequence == 0
            && exec.pending_stdin_write.as_ref()
                == Some(&PendingStdinEvidence {
                    sequence: 1,
                    data: COMMITTED_STDIN.to_vec(),
                })
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "committed WriteStdin did not retain schema-9 exec incarnation 1, sequence 1, and exact pending bytes before reaching the suspended Runtime: {exec:?}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn commit_runtime_write(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    process: &ProcessTarget,
) -> TestResult<()> {
    let client = runtime_client(config).await?;
    let request = WriteStdinRequest {
        context: OperationContext::new(containerd_exec_operation_id(
            &config.namespace,
            task_id,
            &identity.incarnation,
            EXEC_ID,
            1,
            "write-stdin-1",
        )?),
        process: process.clone(),
        data: COMMITTED_STDIN.to_vec(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.write_stdin(request.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime WriteStdin before shim death: {error}"
                ))
                .into());
            }
        }
    }
}

async fn wait_runtime_process(
    config: &QualificationConfig,
    process: ProcessTarget,
) -> TestResult<a3s_oci_sdk::ExitStatus> {
    let client = runtime_client(config).await?;
    let request = WaitProcessRequest {
        process,
        timeout_ms: Some(2_000),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.wait_process(request.clone()).await {
            Ok(exit) => return Ok(exit),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "observe committed Runtime WriteStdin effect: {error}"
                ))
                .into());
            }
        }
    }
}

fn exact_process_target(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
) -> TestResult<ProcessTarget> {
    Ok(ProcessTarget {
        container: ContainerTarget::exact(
            identity.container_id.clone(),
            Generation(identity.generation),
        ),
        process_id: containerd_process_id(&config.namespace, task_id, EXEC_ID, 1)?,
    })
}
