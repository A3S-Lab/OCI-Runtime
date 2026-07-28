use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Process};
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    EventsRequest, ExecRequest, ExitStatus, IoMode, IsolationRequest, KillRequest, ListRequest,
    OciBundle, OperationContext, OperationId, ProcessId, ProcessIo, ProcessTarget, RuntimeClient,
    RuntimeEventKind, Signal, SignalProcessRequest, StartRequest, StateRequest, WaitProcessRequest,
    WaitRequest,
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
    read_mapping_file, sorted_mappings, validate_mapping_plan, validate_rootfs_ownership,
    MappingPlan,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MARKER_NAME: &str = ".a3s-oci-rootless-smoke";
const MARKER_CONTENTS: &[u8] = b"a3s-oci-rootless-mapping-v1\n";

pub(super) async fn run(
    init_executable: &Path,
    bundle_directory: &Path,
    work_parent: &Path,
) -> NativeLinuxRootlessSmokeReport {
    let mut report = NativeLinuxRootlessSmokeReport::initial(HostPlatform::Linux);
    // SAFETY: these credential queries have no pointer arguments or failure
    // return values.
    let (effective_uid, effective_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
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
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if let Err(reason) = validate_rootfs_ownership(&rootfs, &mappings, effective_uid, effective_gid)
    {
        return failed(report, reason);
    }
    report.mapping_plan_verified = true;
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing rootless smoke marker: {}",
                    marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
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
    let driver = match NativeLinuxDriver::open_experimental(&executor_parent, init_executable).await
    {
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
    let executor_root = driver.executor_root().to_path_buf();
    let runtime_driver: Arc<dyn RuntimeDriver> = driver.clone();
    let service = match HostRuntimeService::open(session_root.join("state"), runtime_driver).await {
        Ok(service) => service,
        Err(error) => {
            let reason = format!("failed to open durable rootless runtime: {error}");
            cleanup_driver(&driver, &executor_root, &marker, &session_root, &mut report).await;
            return failed(report, reason);
        }
    };
    let client = RuntimeClient::new(service.clone());
    let exercise = exercise(&client, &bundle, &mappings, &nonce, &marker, &mut report).await;
    if exercise.is_err() {
        best_effort_delete(&client, &nonce).await;
    }
    drop(client);
    drop(service);

    cleanup_driver(&driver, &executor_root, &marker, &session_root, &mut report).await;
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    }
    if report.lifecycle_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn exercise(
    client: &RuntimeClient,
    bundle: &OciBundle,
    mappings: &MappingPlan,
    nonce: &str,
    marker: &Path,
    report: &mut NativeLinuxRootlessSmokeReport,
) -> Result<(), String> {
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
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
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
    wait_for_marker(client, &target, marker).await?;
    report.workload_verified = true;

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
    verify_events(client, &target).await?;
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

async fn verify_events(client: &RuntimeClient, target: &ContainerTarget) -> Result<(), String> {
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
    let expected = [
        RuntimeEventKind::ContainerCreating,
        RuntimeEventKind::ContainerCreated,
        RuntimeEventKind::ContainerStarted,
        RuntimeEventKind::ProcessCreated,
        RuntimeEventKind::ProcessStarted,
        RuntimeEventKind::ProcessExited,
        RuntimeEventKind::ContainerStopped,
        RuntimeEventKind::ProcessExited,
        RuntimeEventKind::ContainerDeleted,
    ];
    if kinds != expected
        || batch.events.iter().any(|event| event.container != *target)
        || batch
            .events
            .windows(2)
            .any(|window| window[1].sequence != window[0].sequence + 1)
        || batch.events.last().map(|event| event.sequence) != Some(batch.next_sequence)
    {
        return Err(format!(
            "rootless durable event sequence was {kinds:?}, expected {expected:?}"
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
    marker: &Path,
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
    match remove_marker(marker).await {
        Ok(()) => report.marker_removed = true,
        Err(reason) => append_reason(report, reason),
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
