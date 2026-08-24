use std::time::Duration;

use a3s_oci_sdk::{
    ContainerId, ContainerTarget, ErrorCode, LocalIpcEndpoint, RuntimeClient, StateRequest,
};
use prost_types::Any;
use serde::Deserialize;

use super::api::{
    ContainersClient, CreateTaskRequest, DeleteTaskRequest, ExecProcessRequest,
    GetContainerRequest, KillRequest, StartRequest, TasksClient, WaitRequest,
};
use super::support::*;

#[path = "faults/committed.rs"]
mod committed;
#[path = "faults/controls.rs"]
mod controls;
#[path = "faults/process_io.rs"]
mod process_io;
#[path = "faults/shared.rs"]
mod shared;

pub(crate) use shared::{
    containerd_exec_operation_id, containerd_operation_id, containerd_process_id, runtime_client,
};

const CREATE_INTENT_FILE_NAME: &str = "a3s-oci-shim-create-v1.json";

#[derive(Deserialize)]
struct CreateIntentReference {
    container_id: String,
}

pub(crate) struct SuspendedProcess {
    pid: u32,
    resumed: bool,
}

impl SuspendedProcess {
    pub(crate) fn stop(pid: u32, target: &str) -> TestResult<Self> {
        send_signal(pid, libc::SIGSTOP, target)?;
        Ok(Self {
            pid,
            resumed: false,
        })
    }

    pub(crate) fn resume(&mut self, target: &str) -> TestResult<()> {
        send_signal(self.pid, libc::SIGCONT, target)?;
        self.resumed = true;
        Ok(())
    }

    pub(crate) fn kill(mut self, target: &str) -> TestResult<()> {
        send_signal(self.pid, libc::SIGKILL, target)?;
        self.resumed = true;
        Ok(())
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if !self.resumed {
            let Ok(pid) = i32::try_from(self.pid) else {
                return;
            };
            // SAFETY: `kill` does not dereference pointers. The PID was
            // resolved from the exact listening runtime socket owner.
            let _ = unsafe { libc::kill(pid, libc::SIGCONT) };
        }
    }
}

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
    qualify_create_in_flight_shim_sigkill(config, prefix).await?;
    committed::qualify_create_effect_committed_shim_sigkill(config, prefix).await?;
    committed::qualify_start_effect_committed_shim_sigkill(config, prefix).await?;
    committed::qualify_kill_effect_committed_shim_sigkill(config, prefix).await?;
    committed::qualify_delete_effect_committed_shim_sigkill(config, prefix).await?;
    committed::qualify_exec_effect_committed_shim_sigkill(config, prefix).await?;
    committed::qualify_signal_process_effect_committed_shim_sigkill(config, prefix).await?;
    controls::qualify_pause_effect_committed_shim_sigkill(config, prefix).await?;
    controls::qualify_resume_effect_committed_shim_sigkill(config, prefix).await?;
    controls::qualify_update_effect_committed_shim_sigkill(config, prefix).await?;
    process_io::qualify_write_stdin_effect_committed_shim_sigkill(config, prefix).await?;
    process_io::qualify_close_stdin_effect_committed_shim_sigkill(config, prefix).await?;
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

async fn qualify_create_in_flight_shim_sigkill(
    config: &QualificationConfig,
    prefix: &str,
) -> TestResult<()> {
    let id = format!("{prefix}-shim-kill-create-in-flight");
    create_container(config, &id).await?;
    let channel = connect_ready(config).await?;
    let rootfs = task_rootfs(config, &channel, &id).await?;
    let host_pid = find_runtime_host_pid(config).await?;

    let create_channel = channel.clone();
    let create_namespace = config.namespace.clone();
    let create_id = id.clone();
    let mut create: tokio::task::JoinHandle<TestResult<super::api::CreateTaskResponse>> =
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
                .map_err(|error| rpc_error("create in-flight shim-kill task", error).into())
        });

    let container_id = wait_for_create_intent(config, &id).await?;
    let mut suspended_host = SuspendedProcess::stop(host_pid, "A3S OCI host service")?;
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
    signal_kill(shim_pid)?;
    suspended_host.resume("A3S OCI host service")?;

    match tokio::time::timeout(Duration::from_secs(10), &mut create).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err(qualification_error(format!(
                "join Create request after in-flight shim SIGKILL: {error}"
            ))
            .into());
        }
        Err(_) => {
            create.abort();
            return Err(qualification_error(
                "Create request remained pending for 10 seconds after in-flight shim SIGKILL",
            )
            .into());
        }
    }

    wait_for_shim_cleanup(config, &channel, &id, shim_pid, &[]).await?;
    wait_for_runtime_absence(config, container_id).await?;
    ContainersClient::new(channel)
        .get(namespaced(
            GetContainerRequest { id: id.clone() },
            &config.namespace,
        )?)
        .await
        .map_err(|error| {
            rpc_error(
                "read caller-owned metadata after in-flight Create shim SIGKILL",
                error,
            )
        })?;
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

async fn wait_for_create_intent(config: &QualificationConfig, id: &str) -> TestResult<ContainerId> {
    let path = config.bundle(id).join(CREATE_INTENT_FILE_NAME);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let intent: CreateIntentReference =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        qualification_error(format!(
                            "decode in-flight Create intent {}: {error}",
                            path.display()
                        ))
                    })?;
                return ContainerId::new(intent.container_id).map_err(|error| {
                    qualification_error(format!(
                        "in-flight Create intent {} contains an invalid container ID: {error}",
                        path.display()
                    ))
                    .into()
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(qualification_error(format!(
                    "read in-flight Create intent {}: {error}",
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

pub(crate) async fn find_runtime_host_pid(config: &QualificationConfig) -> TestResult<u32> {
    let table = tokio::fs::read_to_string("/proc/net/unix")
        .await
        .map_err(|error| qualification_error(format!("read Unix socket table: {error}")))?;
    let endpoint = config.runtime_endpoint.to_string_lossy();
    let inodes = table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 8
                && fields[3] == "00010000"
                && fields[4] == "0001"
                && fields[5] == "01"
                && fields[7] == endpoint)
                .then(|| fields[6].to_string())
        })
        .collect::<Vec<_>>();
    let [inode] = inodes.as_slice() else {
        return Err(qualification_error(format!(
            "expected one listening Unix socket inode for {}, found {inodes:?}",
            config.runtime_endpoint.display()
        ))
        .into());
    };
    let expected = format!("socket:[{inode}]");
    let mut proc_entries = tokio::fs::read_dir("/proc").await.map_err(|error| {
        qualification_error(format!("inspect procfs for runtime host: {error}"))
    })?;
    let mut matches = Vec::new();
    while let Some(entry) = proc_entries
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
        let Ok(mut descriptors) = tokio::fs::read_dir(entry.path().join("fd")).await else {
            continue;
        };
        let mut owns_socket = false;
        loop {
            let descriptor = match descriptors.next_entry().await {
                Ok(Some(descriptor)) => descriptor,
                Ok(None) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // `/proc/<pid>/fd` can disappear while unrelated short-lived
                    // processes are enumerated. The listening socket owner is
                    // required to survive the complete scan and will therefore
                    // still be found through its own descriptor directory.
                    break;
                }
                Err(error) => {
                    return Err(qualification_error(format!(
                        "read process {pid} descriptor: {error}"
                    ))
                    .into());
                }
            };
            if tokio::fs::read_link(descriptor.path())
                .await
                .is_ok_and(|target| target == std::path::Path::new(&expected))
            {
                owns_socket = true;
                break;
            }
        }
        if owns_socket {
            matches.push(pid);
        }
    }
    match matches.as_slice() {
        [pid] => Ok(*pid),
        [] => Err(qualification_error(format!(
            "no process owns the listening runtime socket {}",
            config.runtime_endpoint.display()
        ))
        .into()),
        _ => Err(qualification_error(format!(
            "multiple processes own the listening runtime socket {}: {matches:?}",
            config.runtime_endpoint.display()
        ))
        .into()),
    }
}

async fn wait_for_runtime_absence(
    config: &QualificationConfig,
    container_id: ContainerId,
) -> TestResult<()> {
    let endpoint =
        LocalIpcEndpoint::unix_socket(config.runtime_endpoint.clone()).map_err(|error| {
            qualification_error(format!(
                "validate A3S OCI runtime endpoint {}: {error}",
                config.runtime_endpoint.display()
            ))
        })?;
    let client = RuntimeClient::connect(&endpoint).await.map_err(|error| {
        qualification_error(format!(
            "connect A3S OCI runtime endpoint {}: {error}",
            config.runtime_endpoint.display()
        ))
    })?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .state(StateRequest {
                target: ContainerTarget::current(container_id.clone()),
            })
            .await
        {
            Err(error) if error.code == ErrorCode::NotFound => return Ok(()),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {}
            Err(error) => {
                return Err(qualification_error(format!(
                    "inspect runtime state after in-flight Create cleanup: {error}"
                ))
                .into());
            }
            Ok(record) if tokio::time::Instant::now() < deadline => {
                let _ = record;
            }
            Ok(record) => {
                return Err(qualification_error(format!(
                    "runtime generation {} for {} survived in-flight Create shim cleanup",
                    record.generation.0,
                    container_id.as_str()
                ))
                .into());
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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
