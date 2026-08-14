use std::time::Duration;

use prost_types::Any;

use super::api::{
    ContainersClient, CreateTaskRequest, DeleteTaskRequest, ExecProcessRequest,
    GetContainerRequest, KillRequest, StartRequest, TasksClient, WaitRequest,
};
use super::support::*;

#[derive(Clone, Copy)]
enum PartialShimStage {
    InitCreated,
    ExecAdded,
    ExecRunning,
}

impl PartialShimStage {
    const fn suffix(self) -> &'static str {
        match self {
            Self::InitCreated => "created",
            Self::ExecAdded => "exec-added",
            Self::ExecRunning => "exec-running",
        }
    }
}

pub(crate) async fn qualify_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    for stage in [
        PartialShimStage::InitCreated,
        PartialShimStage::ExecAdded,
        PartialShimStage::ExecRunning,
    ] {
        qualify_partial_shim_sigkill(config, prefix, stage).await?;
    }

    let id = format!("{prefix}-shim-kill");
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
        .map_err(|error| rpc_error("create shim-kill task", error))?
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
        .map_err(|error| rpc_error("start shim-kill task", error))?
        .into_inner();
    if created.pid == 0 || started.pid != created.pid {
        return Err(qualification_error(format!(
            "shim-kill task PIDs were create={} and start={}; expected one stable nonzero PID",
            created.pid, started.pid
        ))
        .into());
    }

    let identity = read_runtime_identity(config, &id).await?;
    let shim_pid = find_exact_shim_pid(config, &id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[started.pid]).await?;

    ContainersClient::new(channel.clone())
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("read caller-owned metadata after shim SIGKILL", error))?;
    delete_container(config, &id).await?;

    create_container(config, &id).await?;
    let rootfs = task_rootfs(config, &channel, &id).await?;
    let recreated = TasksClient::new(channel.clone())
        .create(namespaced(
            CreateTaskRequest {
                container_id: id.clone(),
                rootfs,
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("recreate task after shim SIGKILL", error))?
        .into_inner();
    let replacement = read_runtime_identity(config, &id).await?;
    if replacement == identity {
        return Err(qualification_error(
            "task recreated after shim SIGKILL reused the deleted runtime identity",
        )
        .into());
    }
    let restarted = TasksClient::new(channel.clone())
        .start(namespaced(
            StartRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("start task recreated after shim SIGKILL", error))?
        .into_inner();
    if recreated.pid == 0 || restarted.pid != recreated.pid {
        return Err(qualification_error(format!(
            "recreated shim-kill task PIDs were create={} and start={}; expected one stable nonzero PID",
            recreated.pid, restarted.pid
        ))
        .into());
    }
    TasksClient::new(channel.clone())
        .kill(namespaced(
            KillRequest {
                container_id: id.clone(),
                signal: 9,
                all: true,
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("kill task recreated after shim SIGKILL", error))?;
    let exit = TasksClient::new(channel.clone())
        .wait(namespaced(
            WaitRequest {
                container_id: id.clone(),
                ..Default::default()
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("wait for task recreated after shim SIGKILL", error))?
        .into_inner();
    if exit.exit_status != 137 {
        return Err(qualification_error(format!(
            "task recreated after shim SIGKILL exited {}, expected 137",
            exit.exit_status
        ))
        .into());
    }
    TasksClient::new(channel)
        .delete(namespaced(
            DeleteTaskRequest {
                container_id: id.clone(),
            },
            &config.namespace,
        )?)
        .await
        .map_err(|error| rpc_error("delete task recreated after shim SIGKILL", error))?;
    delete_container(config, &id).await
}

async fn qualify_partial_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
    stage: PartialShimStage,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-{}", stage.suffix());
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
        .map_err(|error| rpc_error("create partial shim-kill task", error))?
        .into_inner();
    if created.pid == 0 {
        return Err(qualification_error(format!(
            "partial shim-kill task {} Create returned PID zero",
            stage.suffix()
        ))
        .into());
    }
    expect_process(
        &task_process(config, &channel, &id, "").await?,
        STATUS_CREATED,
        Some(created.pid),
        &format!("partial shim-kill task {}", stage.suffix()),
    )?;
    let mut process_pids = vec![created.pid];

    if !matches!(stage, PartialShimStage::InitCreated) {
        let started = TasksClient::new(channel.clone())
            .start(namespaced(
                StartRequest {
                    container_id: id.clone(),
                    ..Default::default()
                },
                &config.namespace,
            )?)
            .await
            .map_err(|error| rpc_error("start partial shim-kill task", error))?
            .into_inner();
        if started.pid != created.pid {
            return Err(qualification_error(format!(
                "partial shim-kill task {} changed PID from {} to {} at Start",
                stage.suffix(),
                created.pid,
                started.pid
            ))
            .into());
        }
        let exec_id = "partial-exec";
        let spec = serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh", "-c", "while :; do sleep 1; done"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/",
            "noNewPrivileges": true
        });
        TasksClient::new(channel.clone())
            .exec(namespaced(
                ExecProcessRequest {
                    container_id: id.clone(),
                    exec_id: exec_id.to_string(),
                    spec: Some(Any {
                        type_url: super::PROCESS_SPEC_TYPE.to_string(),
                        value: serde_json::to_vec(&spec).map_err(|error| {
                            qualification_error(format!(
                                "encode partial shim-kill exec process: {error}"
                            ))
                        })?,
                    }),
                    ..Default::default()
                },
                &config.namespace,
            )?)
            .await
            .map_err(|error| rpc_error("add partial shim-kill exec", error))?;
        expect_process(
            &task_process(config, &channel, &id, exec_id).await?,
            STATUS_CREATED,
            Some(0),
            &format!("partial shim-kill task {} exec", stage.suffix()),
        )?;
        if matches!(stage, PartialShimStage::ExecRunning) {
            let exec = TasksClient::new(channel.clone())
                .start(namespaced(
                    StartRequest {
                        container_id: id.clone(),
                        exec_id: exec_id.to_string(),
                    },
                    &config.namespace,
                )?)
                .await
                .map_err(|error| rpc_error("start partial shim-kill exec", error))?
                .into_inner();
            if exec.pid == 0 {
                return Err(qualification_error(
                    "partial shim-kill running exec Start returned PID zero",
                )
                .into());
            }
            process_pids.push(exec.pid);
        }
    }

    read_runtime_identity(config, &id).await?;
    let shim_pid = find_exact_shim_pid(config, &id).await?;
    signal_kill(shim_pid)?;
    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &process_pids).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after partial shim SIGKILL",
                error,
            )
        })?;
    delete_container(config, &id).await
}

pub(crate) async fn find_exact_shim_pid(config: &QualificationConfig, id: &str) -> TestResult<u32> {
    let binary = tokio::fs::read_to_string(config.bundle(id).join("shim-binary-path"))
        .await
        .map_err(|error| qualification_error(format!("read shim binary path: {error}")))?;
    let binary = tokio::fs::canonicalize(binary.trim())
        .await
        .map_err(|error| qualification_error(format!("resolve shim binary path: {error}")))?;
    let mut entries = tokio::fs::read_dir("/proc")
        .await
        .map_err(|error| qualification_error(format!("inspect procfs for shim PID: {error}")))?;
    let mut matches = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| qualification_error(format!("read procfs entry: {error}")))?
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let process_root = entry.path();
        let Ok(executable) = tokio::fs::read_link(process_root.join("exe")).await else {
            continue;
        };
        if executable != binary {
            continue;
        }
        let Ok(command_line) = tokio::fs::read(process_root.join("cmdline")).await else {
            continue;
        };
        let arguments = command_line
            .split(|byte| *byte == 0)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if has_argument_pair(&arguments, b"-namespace", config.namespace.as_bytes())
            && has_argument_pair(&arguments, b"-id", id.as_bytes())
        {
            matches.push(pid);
        }
    }
    match matches.as_slice() {
        [pid] => Ok(*pid),
        [] => Err(qualification_error(format!("no exact shim process serves task {id}")).into()),
        _ => Err(qualification_error(format!(
            "multiple shim processes serve task {id}: {matches:?}"
        ))
        .into()),
    }
}

fn has_argument_pair(arguments: &[&[u8]], name: &[u8], value: &[u8]) -> bool {
    arguments
        .windows(2)
        .any(|pair| pair[0] == name && pair[1] == value)
}

fn signal_kill(pid: u32) -> TestResult<()> {
    send_signal(pid, libc::SIGKILL, "shim")
}

pub(crate) fn send_signal(pid: u32, signal: i32, target: &str) -> TestResult<()> {
    let pid = i32::try_from(pid)
        .map_err(|_| qualification_error(format!("{target} PID does not fit platform pid_t")))?;
    // SAFETY: `kill` does not dereference pointers. The PID came from an exact
    // shim identity match or systemd's exact MainPID query.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }
    Err(qualification_error(format!(
        "send signal {signal} to {target} PID {pid}: {}",
        std::io::Error::last_os_error()
    ))
    .into())
}

async fn wait_for_shim_cleanup(
    config: &QualificationConfig,
    channel: &tonic::transport::Channel,
    id: &str,
    shim_pid: u32,
    process_pids: &[u32],
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let task_absent = matches!(
            optional_task_process(config, channel, id, "").await,
            Ok(None)
        );
        let bundle_absent = !tokio::fs::try_exists(config.bundle(id))
            .await
            .map_err(|error| qualification_error(format!("inspect shim-kill bundle: {error}")))?;
        let shim_absent = !tokio::fs::try_exists(format!("/proc/{shim_pid}"))
            .await
            .map_err(|error| qualification_error(format!("inspect killed shim PID: {error}")))?;
        let mut processes_absent = true;
        for pid in process_pids {
            if tokio::fs::try_exists(format!("/proc/{pid}"))
                .await
                .map_err(|error| {
                    qualification_error(format!("inspect killed workload PID {pid}: {error}"))
                })?
            {
                processes_absent = false;
            }
        }
        if task_absent && bundle_absent && shim_absent && processes_absent {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(qualification_error(format!(
                "shim SIGKILL cleanup timed out: task_absent={task_absent}, bundle_absent={bundle_absent}, shim_absent={shim_absent}, workload_pids_absent={processes_absent}"
            ))
            .into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
