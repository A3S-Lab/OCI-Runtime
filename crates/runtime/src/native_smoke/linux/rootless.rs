use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources, Process};
use a3s_oci_sdk::{
    ContainerId, ContainerOperationRequest, ContainerTarget, CreateAttachments, CreateRequest,
    DeleteMode, DeleteRequest, Error, ErrorCode, EventsRequest, ExecRequest, ExitStatus, IoMode,
    IsolationRequest, KillRequest, ListRequest, OciBundle, OperationContext, OperationId,
    ProcessId, ProcessIo, ProcessTarget, RuntimeClient, RuntimeEventKind, Signal,
    SignalProcessRequest, StartRequest, StateRequest, StatsRequest, UpdateRequest,
    WaitProcessRequest, WaitRequest,
};
use tokio::time::{sleep, timeout, Instant};

use super::filesystem::{
    canonical_directory, create_private_directory, fixed_rootfs, path_exists, read_marker,
    remove_marker, unique_nonce,
};
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::{HostRuntimeService, NativeLinuxDriver, NativeLinuxRootlessSmokeReport, RuntimeDriver};

mod config;

use config::{
    cgroup_requirement, read_mapping_file, sorted_mappings, validate_mapping_plan,
    validate_rootfs_ownership, CgroupRequirement, MappingPlan,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MARKER_NAME: &str = ".a3s-oci-rootless-smoke";
const MARKER_CONTENTS: &[u8] = b"a3s-oci-rootless-mapping-v1\n";
const PROGRESS_NAME: &str = ".a3s-oci-rootless-progress";
const PROGRESS_PENDING_NAME: &str = ".a3s-oci-rootless-progress.next";
const UPDATED_MEMORY_LIMIT: u64 = 192 * 1024 * 1024;
const FREEZER_OBSERVATION_INTERVAL: Duration = Duration::from_millis(300);

struct WorkloadFiles {
    marker: std::path::PathBuf,
    progress: std::path::PathBuf,
    progress_pending: std::path::PathBuf,
}

struct RootlessRun<'a> {
    init_executable: &'a Path,
    bundle_directory: &'a Path,
    work_parent: &'a Path,
    delegated_cgroup_root: Option<&'a Path>,
    ready_file: Option<&'a Path>,
    continue_file: Option<&'a Path>,
    device_policy_bootstrap: Option<a3s_oci_agent::RootlessDevicePolicyBootstrap>,
    exercise_device_policy: bool,
}

struct RootlessExercise<'a> {
    client: &'a RuntimeClient,
    bundle: &'a OciBundle,
    mappings: &'a MappingPlan,
    cgroup_requirement: CgroupRequirement,
    nonce: &'a str,
    workload_files: &'a WorkloadFiles,
    device_policy: bool,
}

pub(super) async fn run(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    delegated_cgroup_root: Option<&Path>,
    ready_file: Option<&Path>,
    continue_file: Option<&Path>,
) -> NativeLinuxRootlessSmokeReport {
    run_inner(RootlessRun {
        init_executable,
        bundle_directory,
        work_parent,
        delegated_cgroup_root,
        ready_file,
        continue_file,
        device_policy_bootstrap: None,
        exercise_device_policy: false,
    })
    .await
}

async fn run_inner(run: RootlessRun<'_>) -> NativeLinuxRootlessSmokeReport {
    let RootlessRun {
        init_executable,
        bundle_directory,
        work_parent,
        delegated_cgroup_root,
        ready_file,
        continue_file,
        device_policy_bootstrap,
        exercise_device_policy,
    } = run;
    let device_bootstrap = device_policy_bootstrap.is_some();
    let mut report = NativeLinuxRootlessSmokeReport::initial(HostPlatform::Linux);
    // SAFETY: these credential queries have no pointer arguments or failure
    // return values.
    let (effective_uid, effective_gid) = unsafe {
        if device_bootstrap {
            (libc::getuid(), libc::getgid())
        } else {
            (libc::geteuid(), libc::getegid())
        }
    };
    report.effective_uid = Some(effective_uid);
    report.effective_gid = Some(effective_gid);
    if effective_uid == 0 || effective_gid == 0 {
        return failed(
            report,
            "the rootless lifecycle smoke must run with nonzero effective UID and GID",
        );
    }

    let work_parent = match canonical_directory(work_parent, "rootless smoke work parent").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "rootless OCI bundle").await
    {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(error) => {
            return failed(
                report,
                format!("failed to load rootless OCI bundle: {error}"),
            )
        }
    };
    let mappings = match validate_mapping_plan(&bundle, effective_uid, effective_gid) {
        Ok(mappings) => mappings,
        Err(reason) => return failed(report, reason),
    };
    let cgroup_requirement = match cgroup_requirement(&bundle) {
        Ok(requirement) => requirement,
        Err(reason) => return failed(report, reason),
    };
    report.cgroup_delegation_requested =
        matches!(cgroup_requirement, CgroupRequirement::ExplicitPath);
    if matches!(cgroup_requirement, CgroupRequirement::ExplicitPath)
        && delegated_cgroup_root.is_none()
    {
        return failed(
            report,
            "rootless smoke linux.cgroupsPath requires --delegated-cgroup-root",
        );
    }
    if matches!(cgroup_requirement, CgroupRequirement::None) && delegated_cgroup_root.is_some() {
        return failed(
            report,
            "rootless smoke delegated cgroup root requires linux.cgroupsPath",
        );
    }
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if let Err(reason) = validate_rootfs_ownership(&rootfs, &mappings, effective_uid, effective_gid)
    {
        return failed(report, reason);
    }
    report.mapping_plan_verified = true;
    let workload_files = WorkloadFiles {
        marker: rootfs.join(MARKER_NAME),
        progress: rootfs.join(PROGRESS_NAME),
        progress_pending: rootfs.join(PROGRESS_PENDING_NAME),
    };
    for path in [
        &workload_files.marker,
        &workload_files.progress,
        &workload_files.progress_pending,
    ] {
        match path_exists(path).await {
            Ok(false) => {}
            Ok(true) => {
                return failed(
                    report,
                    format!(
                        "refusing to overwrite an existing rootless smoke artifact: {}",
                        path.display()
                    ),
                );
            }
            Err(reason) => return failed(report, reason),
        }
    }

    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let session_root = work_parent.join(format!("a3s-oci-native-rootless-smoke-{nonce}"));
    if let Err(reason) = create_private_directory(&session_root).await {
        return failed(report, reason);
    }
    let executor_parent = session_root.join("executor");
    if let Err(reason) = create_private_directory(&executor_parent).await {
        return cleanup_session(report, &session_root, reason).await;
    }
    let driver = match match (delegated_cgroup_root, device_policy_bootstrap) {
        (Some(_), Some(bootstrap)) => {
            NativeLinuxDriver::open_experimental_with_rootless_device_policy(
                &executor_parent,
                init_executable,
                bootstrap,
            )
            .await
        }
        (Some(root), None) => {
            NativeLinuxDriver::open_experimental_with_rootless_cgroup_delegation(
                &executor_parent,
                init_executable,
                root,
            )
            .await
        }
        (None, None) => {
            NativeLinuxDriver::open_experimental(&executor_parent, init_executable).await
        }
        (None, Some(_)) => unreachable!("device bootstrap always retains one delegation"),
    } {
        Ok(driver) => Arc::new(driver),
        Err(error) => {
            return cleanup_session(
                report,
                &session_root,
                format!("failed to open rootless native Linux driver: {error}"),
            )
            .await;
        }
    };
    report.device_policy_helper_verified = device_bootstrap;
    let executor_root = driver.executor_root().to_path_buf();
    if let Err(reason) = qualification_barrier(ready_file, continue_file).await {
        cleanup_driver(
            &driver,
            &executor_root,
            delegated_cgroup_root,
            &workload_files,
            &session_root,
            &mut report,
        )
        .await;
        return failed(report, reason);
    }
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = match HostRuntimeService::open(session_root.join("state"), runtime_driver).await {
        Ok(service) => service,
        Err(error) => {
            let reason = format!("failed to open durable rootless runtime: {error}");
            cleanup_driver(
                &driver,
                &executor_root,
                delegated_cgroup_root,
                &workload_files,
                &session_root,
                &mut report,
            )
            .await;
            return failed(report, reason);
        }
    };
    let client = RuntimeClient::new(service.clone());
    let exercise = exercise(
        RootlessExercise {
            client: &client,
            bundle: &bundle,
            mappings: &mappings,
            cgroup_requirement,
            nonce: &nonce,
            workload_files: &workload_files,
            device_policy: exercise_device_policy,
        },
        &mut report,
    )
    .await;
    if exercise.is_err() {
        best_effort_delete(&client, &nonce).await;
    }
    drop(client);
    drop(service);

    cleanup_driver(
        &driver,
        &executor_root,
        delegated_cgroup_root,
        &workload_files,
        &session_root,
        &mut report,
    )
    .await;
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.lifecycle_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

pub(super) async fn run_device_policy(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    bootstrap: a3s_oci_agent::RootlessDevicePolicyBootstrap,
) -> NativeLinuxRootlessSmokeReport {
    let delegated_cgroup_root = bootstrap.delegated_cgroup_root().to_path_buf();
    run_inner(RootlessRun {
        init_executable,
        bundle_directory,
        work_parent,
        delegated_cgroup_root: Some(&delegated_cgroup_root),
        ready_file: None,
        continue_file: None,
        device_policy_bootstrap: Some(bootstrap),
        exercise_device_policy: true,
    })
    .await
}

pub(super) async fn run_device_bootstrap(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
    bootstrap: a3s_oci_agent::RootlessDevicePolicyBootstrap,
    ready_file: Option<&Path>,
    continue_file: Option<&Path>,
) -> NativeLinuxRootlessSmokeReport {
    let delegated_cgroup_root = bootstrap.delegated_cgroup_root().to_path_buf();
    run_inner(RootlessRun {
        init_executable,
        bundle_directory,
        work_parent,
        delegated_cgroup_root: Some(&delegated_cgroup_root),
        ready_file,
        continue_file,
        device_policy_bootstrap: Some(bootstrap),
        exercise_device_policy: false,
    })
    .await
}

async fn qualification_barrier(
    ready_file: Option<&Path>,
    continue_file: Option<&Path>,
) -> Result<(), String> {
    let (Some(ready_file), Some(continue_file)) = (ready_file, continue_file) else {
        if ready_file.is_some() || continue_file.is_some() {
            return Err(
                "rootless post-open qualification requires both ready and continue files".into(),
            );
        }
        return Ok(());
    };
    for (path, label) in [(ready_file, "ready"), (continue_file, "continue")] {
        if !path.is_absolute() || path.parent().is_none_or(|parent| !parent.is_dir()) {
            return Err(format!(
                "rootless post-open qualification {label} path must have an existing absolute parent: {}",
                path.display()
            ));
        }
    }
    if path_exists(ready_file).await? || path_exists(continue_file).await? {
        return Err("refusing to overwrite a rootless post-open qualification marker".into());
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let file = options.open(ready_file).await.map_err(|error| {
        format!(
            "failed to publish rootless post-open qualification readiness {}: {error}",
            ready_file.display()
        )
    })?;
    file.sync_all().await.map_err(|error| {
        format!(
            "failed to sync rootless post-open qualification readiness {}: {error}",
            ready_file.display()
        )
    })?;
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        if path_exists(continue_file).await? {
            let metadata = tokio::fs::symlink_metadata(continue_file)
                .await
                .map_err(|error| {
                    format!(
                        "failed to inspect rootless post-open qualification continuation {}: {error}",
                        continue_file.display()
                    )
                })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "rootless post-open qualification continuation must be a regular file: {}",
                    continue_file.display()
                ));
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for rootless post-open qualification continuation {}",
                continue_file.display()
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn exercise(
    exercise: RootlessExercise<'_>,
    report: &mut NativeLinuxRootlessSmokeReport,
) -> Result<(), String> {
    let RootlessExercise {
        client,
        bundle,
        mappings,
        cgroup_requirement,
        nonce,
        workload_files,
        device_policy,
        ..
    } = exercise;
    report.service_operations = call("rootless features", client.features())
        .await?
        .operations;
    let id = ContainerId::new(format!("native-rootless-{nonce}"))
        .map_err(|error| format!("failed to construct rootless container ID: {error}"))?;
    let create = CreateRequest {
        context: operation(nonce, "create")?,
        id: id.clone(),
        bundle: bundle.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        attachments: CreateAttachments::from_bundle(
            bundle,
            ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        )
        .map_err(|error| format!("failed to derive rootless create attachments: {error}"))?,
    };
    let created = call("rootless create", client.create(create.clone())).await?;
    report.create_returned_created = *created.state.status() == ContainerState::Created;
    report.created_pid = *created.state.pid();
    if !report.create_returned_created {
        return Err("rootless create did not preserve the OCI created barrier".into());
    }
    let replayed = call("replayed rootless create", client.create(create)).await?;
    report.create_replayed = replayed == created;
    if !report.create_replayed {
        return Err("rootless create did not replay exactly".into());
    }
    let target = ContainerTarget::exact(id, created.generation);
    if call(
        "rootless state after create",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?
        != created
        || call(
            "rootless list after create",
            client.list(ListRequest::default()),
        )
        .await?
            != [created.clone()]
    {
        return Err("rootless state or list did not expose the exact created record".into());
    }
    let pid = report
        .created_pid
        .ok_or_else(|| "rootless create returned no host-visible init PID".to_string())?;
    let proc_root = Path::new("/proc").join(pid.to_string());
    report.uid_map_verified = read_mapping_file(&proc_root.join("uid_map"), "UID").await?
        == sorted_mappings(&mappings.uid);
    report.gid_map_verified = read_mapping_file(&proc_root.join("gid_map"), "GID").await?
        == sorted_mappings(&mappings.gid);
    report.setgroups_denied = tokio::fs::read_to_string(proc_root.join("setgroups"))
        .await
        .map_err(|error| format!("failed to inspect rootless setgroups policy: {error}"))?
        .trim()
        == "deny";
    if !report.uid_map_verified || !report.gid_map_verified || !report.setgroups_denied {
        return Err("rootless namespace mapping evidence did not match the OCI request".into());
    }

    let started = call(
        "rootless start",
        client.start(StartRequest {
            context: operation(nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    if *started.state.status() != ContainerState::Running {
        return Err("rootless start did not leave the workload running".into());
    }
    wait_for_marker(client, &target, &workload_files.marker).await?;
    report.workload_verified = true;
    if report.device_policy_helper_verified {
        report.device_nodes_verified = true;
    }

    if matches!(cgroup_requirement, CgroupRequirement::ExplicitPath) {
        exercise_cgroup_control(
            client,
            &target,
            nonce,
            &workload_files.progress,
            report,
            device_policy,
        )
        .await?;
    }

    exercise_exec(client, &target, nonce, report).await?;

    let kill = KillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct rootless container signal: {error}"))?,
        all: true,
    };
    let killed = call("rootless container-wide kill", client.kill(kill.clone())).await?;
    let replayed_kill = call("replayed rootless container-wide kill", client.kill(kill)).await?;
    report.init_kill_replayed = replayed_kill == killed;
    if !report.init_kill_replayed {
        return Err("rootless container-wide kill did not replay exactly".into());
    }
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(LIFECYCLE_TIMEOUT.as_millis() as u64),
    };
    let waited = call("rootless init wait", client.wait(wait.clone())).await?;
    let expected = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct rootless init status: {error}"))?;
    report.init_wait_status = Some(waited.clone());
    if waited != expected || call("repeated rootless init wait", client.wait(wait)).await? != waited
    {
        return Err("rootless init wait did not return a stable SIGKILL result".into());
    }
    if *call(
        "rootless stopped state",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?
    .state
    .status()
        != ContainerState::Stopped
    {
        return Err("rootless state did not observe the stopped workload".into());
    }

    let delete = DeleteRequest {
        context: operation(nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    call("rootless delete", client.delete(delete.clone())).await?;
    call("replayed rootless delete", client.delete(delete)).await?;
    report.delete_replayed = true;
    verify_events(
        client,
        &target,
        matches!(cgroup_requirement, CgroupRequirement::ExplicitPath),
        device_policy,
    )
    .await?;
    report.events_verified = true;
    report.durable_state_removed = state_is_missing(client, target).await?
        && call(
            "rootless list after delete",
            client.list(ListRequest::default()),
        )
        .await?
        .is_empty();
    if !report.durable_state_removed {
        return Err("rootless durable state remained after delete".into());
    }
    Ok(())
}

async fn exercise_exec(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
    report: &mut NativeLinuxRootlessSmokeReport,
) -> Result<(), String> {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/busybox", "sleep", "300"],
        "env": ["PATH=/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct rootless exec process: {error}"))?;
    let request = ExecRequest {
        context: operation(nonce, "exec")?,
        container: target.clone(),
        process_id: ProcessId::new(format!("rootless-exec-{nonce}"))
            .map_err(|error| format!("failed to construct rootless exec process ID: {error}"))?,
        process,
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    };
    let process_target = ProcessTarget {
        container: request.container.clone(),
        process_id: request.process_id.clone(),
    };
    let created = call("rootless exec", client.exec(request.clone())).await?;
    report.exec_replayed = created.target == process_target
        && created.pid.is_some()
        && !created.terminal
        && call("replayed rootless exec", client.exec(request)).await? == created;
    if !report.exec_replayed {
        return Err("rootless exec did not create and replay the exact process".into());
    }
    let signal = SignalProcessRequest {
        context: operation(nonce, "signal-exec")?,
        process: process_target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct rootless exec signal: {error}"))?,
    };
    call(
        "rootless exec signal",
        client.signal_process(signal.clone()),
    )
    .await?;
    call(
        "replayed rootless exec signal",
        client.signal_process(signal),
    )
    .await?;
    report.exec_signal_replayed = true;
    let wait = WaitProcessRequest {
        process: process_target,
        timeout_ms: Some(LIFECYCLE_TIMEOUT.as_millis() as u64),
    };
    let status = call("rootless exec wait", client.wait_process(wait.clone())).await?;
    let expected = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct rootless exec status: {error}"))?;
    report.exec_wait_status = Some(status.clone());
    if status != expected
        || call("repeated rootless exec wait", client.wait_process(wait)).await? != status
    {
        return Err("rootless exec wait did not return a stable SIGKILL result".into());
    }
    Ok(())
}

async fn verify_events(
    client: &RuntimeClient,
    target: &ContainerTarget,
    delegated_cgroup: bool,
    device_policy: bool,
) -> Result<(), String> {
    let batch = call(
        "rootless runtime events",
        client.events(EventsRequest {
            container: Some(target.clone()),
            after_sequence: 0,
            limit: a3s_oci_sdk::MAX_EVENT_BATCH_ITEMS,
            wait_timeout_ms: None,
        }),
    )
    .await?;
    let kinds = batch
        .events
        .iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    let mut expected = vec![
        RuntimeEventKind::ContainerCreating,
        RuntimeEventKind::ContainerCreated,
        RuntimeEventKind::ContainerStarted,
    ];
    if delegated_cgroup {
        expected.push(RuntimeEventKind::ResourcesUpdated);
        if device_policy {
            for _ in 0..2 {
                expected.extend([
                    RuntimeEventKind::ProcessCreated,
                    RuntimeEventKind::ProcessStarted,
                    RuntimeEventKind::ProcessExited,
                ]);
            }
            expected.push(RuntimeEventKind::ResourcesUpdated);
            expected.extend([
                RuntimeEventKind::ProcessCreated,
                RuntimeEventKind::ProcessStarted,
                RuntimeEventKind::ProcessExited,
                RuntimeEventKind::ResourcesUpdated,
                RuntimeEventKind::ProcessCreated,
                RuntimeEventKind::ProcessStarted,
                RuntimeEventKind::ProcessExited,
            ]);
        }
        expected.extend([
            RuntimeEventKind::ContainerPaused,
            RuntimeEventKind::ContainerResumed,
        ]);
    }
    expected.extend([
        RuntimeEventKind::ProcessCreated,
        RuntimeEventKind::ProcessStarted,
        RuntimeEventKind::ProcessExited,
        RuntimeEventKind::ContainerStopped,
        RuntimeEventKind::ProcessExited,
        RuntimeEventKind::ContainerDeleted,
    ]);
    if kinds != expected
        || batch.events.iter().any(|event| event.container != *target)
        || batch
            .events
            .windows(2)
            .any(|window| window[1].sequence != window[0].sequence + 1)
        || batch.events.last().map(|event| event.sequence) != Some(batch.next_sequence)
    {
        return Err(format!(
            "rootless durable event sequence was not exact: expected {expected:?}; observed {kinds:?}"
        ));
    }
    let tail = call(
        "rootless runtime event tail",
        client.events(EventsRequest {
            container: Some(target.clone()),
            after_sequence: batch.next_sequence,
            limit: 1,
            wait_timeout_ms: None,
        }),
    )
    .await?;
    if tail.events.is_empty() && tail.next_sequence == batch.next_sequence {
        Ok(())
    } else {
        Err("rootless durable event tail was not empty and cursor-stable".into())
    }
}

async fn exercise_cgroup_control(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
    progress: &Path,
    report: &mut NativeLinuxRootlessSmokeReport,
    device_policy: bool,
) -> Result<(), String> {
    let mut resources = serde_json::json!({
        "memory": {
            "limit": UPDATED_MEMORY_LIMIT,
            "reservation": 32 * 1024 * 1024,
            "swap": 384 * 1024 * 1024
        },
        "cpu": {"shares": 256, "quota": 40000, "period": 100000},
        "pids": {"limit": 48}
    });
    if device_policy {
        resources["devices"] = serde_json::json!([
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"},
            {"allow": true, "type": "c", "major": 1, "minor": 5, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 7, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 8, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 9, "access": "rwm"},
            {"allow": true, "type": "c", "major": 5, "minor": 0, "access": "rwm"}
        ]);
    }
    let resources: LinuxResources = serde_json::from_value(resources)
        .map_err(|error| format!("failed to construct rootless resource update: {error}"))?;
    let update = UpdateRequest {
        context: operation(nonce, "update")?,
        target: target.clone(),
        resources,
    };
    let updated = call("rootless resource update", client.update(update.clone())).await?;
    report.resources_updated = updated
        == call("replayed rootless resource update", client.update(update)).await?
        && *updated.state.status() == ContainerState::Running;
    if !report.resources_updated {
        return Err("rootless cgroup update was not exact or replay-safe".into());
    }
    if device_policy {
        let readonly_denied =
            run_device_write_probe(client, target, nonce, "readonly", false).await?;
        let invalid: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "c", "major": 8, "minor": 0, "access": "rwm"}
            ]
        }))
        .map_err(|error| format!("failed to construct invalid device update: {error}"))?;
        let invalid_result = timeout(
            CALL_TIMEOUT,
            client.update(UpdateRequest {
                context: operation(nonce, "update-device-invalid")?,
                target: target.clone(),
                resources: invalid,
            }),
        )
        .await;
        let invalid_rejected = matches!(invalid_result, Ok(Err(_)));
        let old_policy_retained =
            run_device_write_probe(client, target, nonce, "rollback", false).await?;

        let disabled: LinuxResources =
            serde_json::from_value(serde_json::json!({"devices": []}))
                .map_err(|error| format!("failed to construct disabled device update: {error}"))?;
        call(
            "disable rootless device policy",
            client.update(UpdateRequest {
                context: operation(nonce, "update-device-disable")?,
                target: target.clone(),
                resources: disabled,
            }),
        )
        .await?;
        let disabled_allows_write =
            run_device_write_probe(client, target, nonce, "disabled", true).await?;

        let restored: LinuxResources = serde_json::from_value(serde_json::json!({
            "devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 5, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 7, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 8, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 9, "access": "rwm"},
                {"allow": true, "type": "c", "major": 5, "minor": 0, "access": "rwm"}
            ]
        }))
        .map_err(|error| format!("failed to construct restored device update: {error}"))?;
        call(
            "restore rootless device policy",
            client.update(UpdateRequest {
                context: operation(nonce, "update-device-restore")?,
                target: target.clone(),
                resources: restored,
            }),
        )
        .await?;
        let restored_allows_write =
            run_device_write_probe(client, target, nonce, "restored", true).await?;
        report.device_policy_updates_verified = readonly_denied
            && invalid_rejected
            && old_policy_retained
            && disabled_allows_write
            && restored_allows_write;
        if !report.device_policy_updates_verified {
            return Err("rootless device policy state-machine evidence was incomplete".into());
        }
    }

    let first = call(
        "rootless cgroup stats",
        client.stats(StatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    let second = call(
        "repeated rootless cgroup stats",
        client.stats(StatsRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.stats_verified = first.target == *target
        && second.target == *target
        && first.memory.limit_bytes == Some(UPDATED_MEMORY_LIMIT)
        && second.memory.limit_bytes == Some(UPDATED_MEMORY_LIMIT)
        && second.cpu.usage_ns >= first.cpu.usage_ns
        && first.metrics.contains_key("memory.events.oom_kill")
        && first.metrics.contains_key("pids.events.max");
    if !report.stats_verified {
        return Err("rootless cgroup stats did not match the updated profile".into());
    }

    let pause = ContainerOperationRequest {
        context: operation(nonce, "pause")?,
        target: target.clone(),
    };
    let paused = call("rootless pause", client.pause(pause.clone())).await?;
    if !paused.is_paused() || call("replayed rootless pause", client.pause(pause)).await? != paused
    {
        return Err("rootless cgroup pause did not replay exactly".into());
    }
    let before_pause = wait_for_progress(progress, None).await?;
    sleep(FREEZER_OBSERVATION_INTERVAL).await;
    let while_paused = read_progress(progress).await?;
    report.progress_before_pause = Some(before_pause);
    report.progress_while_paused = Some(while_paused);
    if while_paused != before_pause {
        return Err(format!(
            "rootless workload progressed while frozen: {before_pause} -> {while_paused}"
        ));
    }
    let resume = ContainerOperationRequest {
        context: operation(nonce, "resume")?,
        target: target.clone(),
    };
    let resumed = call("rootless resume", client.resume(resume.clone())).await?;
    let replayed = call("replayed rootless resume", client.resume(resume)).await?;
    let after_resume = wait_for_progress(progress, Some(while_paused)).await?;
    report.progress_after_resume = Some(after_resume);
    report.freezer_verified = !resumed.is_paused()
        && replayed == resumed
        && while_paused == before_pause
        && after_resume > while_paused;
    if !report.freezer_verified {
        return Err("rootless cgroup resume did not replay exactly".into());
    }
    report.cgroup_delegation_verified = true;
    Ok(())
}

async fn run_device_write_probe(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
    name: &str,
    expect_success: bool,
) -> Result<bool, String> {
    let process: Process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0, "umask": 18},
        "args": ["/bin/sh", "-c", "printf probe > /dev/null"],
        "env": ["PATH=/bin"],
        "cwd": "/",
        "noNewPrivileges": true
    }))
    .map_err(|error| format!("failed to construct {name} device probe: {error}"))?;
    let process_id = ProcessId::new(format!("device-{name}-{nonce}"))
        .map_err(|error| format!("failed to construct {name} device probe ID: {error}"))?;
    let process_target = ProcessTarget {
        container: target.clone(),
        process_id: process_id.clone(),
    };
    call(
        &format!("start {name} device probe"),
        client.exec(ExecRequest {
            context: operation(nonce, &format!("device-{name}-exec"))?,
            container: target.clone(),
            process_id,
            process,
            io: ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        }),
    )
    .await?;
    let status = call(
        &format!("wait {name} device probe"),
        client.wait_process(WaitProcessRequest {
            process: process_target,
            timeout_ms: Some(LIFECYCLE_TIMEOUT.as_millis() as u64),
        }),
    )
    .await?;
    Ok(if expect_success {
        status.exit_code == Some(0)
    } else {
        status.exit_code.is_some_and(|code| code != 0) || status.signal.is_some()
    })
}

async fn wait_for_progress(path: &Path, after: Option<u64>) -> Result<u64, String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        match read_progress(path).await {
            Ok(value) if after.is_none_or(|previous| value > previous) => return Ok(value),
            Ok(_) => {}
            Err(reason) if reason.contains("No such file") => {}
            Err(reason) => return Err(reason),
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for rootless workload progress beyond {after:?}"
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn read_progress(path: &Path) -> Result<u64, String> {
    let value = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| format!("failed to read rootless workload progress: {error}"))?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("rootless workload progress is invalid: {error}"))
}

async fn wait_for_marker(
    client: &RuntimeClient,
    target: &ContainerTarget,
    marker: &Path,
) -> Result<(), String> {
    let deadline = Instant::now() + LIFECYCLE_TIMEOUT;
    loop {
        let state = call(
            "rootless state while waiting for marker",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        if *state.state.status() != ContainerState::Running {
            return Err("rootless workload stopped before producing its marker".into());
        }
        if path_exists(marker).await? {
            match exact_marker_state(&read_marker(marker).await?, MARKER_CONTENTS) {
                ExactMarkerState::Complete => return Ok(()),
                ExactMarkerState::InProgress => {}
                ExactMarkerState::Mismatch => {
                    return Err("rootless workload produced unexpected marker contents".into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for rootless workload marker".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn state_is_missing(client: &RuntimeClient, target: ContainerTarget) -> Result<bool, String> {
    match timeout(CALL_TIMEOUT, client.state(StateRequest { target })).await {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => Ok(true),
        Ok(Err(error)) => Err(call_error("rootless state after delete", &error)),
        Ok(Ok(_)) => Ok(false),
        Err(_) => Err("rootless state after delete timed out".into()),
    }
}

async fn best_effort_delete(client: &RuntimeClient, nonce: &str) {
    let Ok(id) = ContainerId::new(format!("native-rootless-{nonce}")) else {
        return;
    };
    let Ok(context) = operation(nonce, "cleanup") else {
        return;
    };
    let _ = timeout(
        CALL_TIMEOUT,
        client.delete(DeleteRequest {
            context,
            target: ContainerTarget::current(id),
            mode: DeleteMode::Force,
        }),
    )
    .await;
}

async fn call<T>(
    operation: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(call_error(operation, &error)),
        Err(_) => Err(format!("{operation} timed out")),
    }
}

fn call_error(operation: &str, error: &Error) -> String {
    format!(
        "{operation} failed with {:?}: {}",
        error.code, error.message
    )
}

fn operation(nonce: &str, name: &str) -> Result<OperationContext, String> {
    let id = OperationId::new(format!("native-rootless-{nonce}-{name}"))
        .map_err(|error| format!("failed to construct rootless {name} operation ID: {error}"))?;
    Ok(OperationContext::new(id))
}

async fn cleanup_driver(
    driver: &NativeLinuxDriver,
    executor_root: &Path,
    delegated_cgroup_root: Option<&Path>,
    workload_files: &WorkloadFiles,
    session_root: &Path,
    report: &mut NativeLinuxRootlessSmokeReport,
) {
    if let Err(error) = driver.shutdown().await {
        append_reason(
            report,
            format!("rootless executor shutdown failed: {error}"),
        );
    }
    match path_exists(executor_root).await {
        Ok(exists) => report.executor_runtime_clean = !exists,
        Err(reason) => append_reason(report, reason),
    }
    if let Some(root) = delegated_cgroup_root {
        match delegated_cgroup_has_no_children(root).await {
            Ok(clean) => report.cgroup_delegation_clean = clean,
            Err(reason) => append_reason(report, reason),
        }
    }
    match remove_marker(&workload_files.marker).await {
        Ok(()) => report.marker_removed = true,
        Err(reason) => append_reason(report, reason),
    }
    if let Err(reason) = remove_marker(&workload_files.progress).await {
        append_reason(report, reason);
    }
    if let Err(reason) = remove_marker(&workload_files.progress_pending).await {
        append_reason(report, reason);
    }
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => match path_exists(session_root).await {
            Ok(exists) => report.session_root_clean = !exists,
            Err(reason) => append_reason(report, reason),
        },
        Err(error) => append_reason(
            report,
            format!(
                "failed to remove rootless smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
}

async fn delegated_cgroup_has_no_children(root: &Path) -> Result<bool, String> {
    let mut entries = tokio::fs::read_dir(root).await.map_err(|error| {
        format!(
            "failed to inspect rootless cgroup delegation cleanup {}: {error}",
            root.display()
        )
    })?;
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        format!(
            "failed to enumerate rootless cgroup delegation {}: {error}",
            root.display()
        )
    })? {
        let file_type = entry.file_type().await.map_err(|error| {
            format!(
                "failed to inspect rootless cgroup delegation entry {}: {error}",
                entry.path().display()
            )
        })?;
        if file_type.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_none_or(|name| name.starts_with("a3s-oci-"))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn cleanup_session(
    mut report: NativeLinuxRootlessSmokeReport,
    session_root: &Path,
    reason: impl Into<String>,
) -> NativeLinuxRootlessSmokeReport {
    append_reason(&mut report, reason);
    match tokio::fs::remove_dir_all(session_root).await {
        Ok(()) => report.session_root_clean = true,
        Err(error) => append_reason(
            &mut report,
            format!(
                "failed to remove rootless smoke session {}: {error}",
                session_root.display()
            ),
        ),
    }
    report
}

fn append_reason(report: &mut NativeLinuxRootlessSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: NativeLinuxRootlessSmokeReport,
    reason: impl Into<String>,
) -> NativeLinuxRootlessSmokeReport {
    append_reason(&mut report, reason);
    report
}
