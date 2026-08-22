use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    ContainerOperationRequest, ContainerRecord, ContainerTarget, Generation, OperationContext,
    StatsRequest, UpdateRequest, PIDS_LIMIT_METRIC,
};
use tokio::process::Child;
use tonic::transport::Channel;

use super::{launch_replacement_while_containerd_suspended, stop_replacement, Bootstrap};
use crate::faults;
use crate::support::{
    containerd_main_pid, qualification_error, read_runtime_identity, restart_containerd,
    task_process, QualificationConfig, RuntimeIdentity, TestResult, STATUS_PAUSED, STATUS_RUNNING,
};

#[path = "control/journal.rs"]
mod journal;

use journal::{assert_completed, read_control_journal, update_digest, wait_for_pending_control};

const EXPECTED_PIDS_LIMIT: u64 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ControlKind {
    Pause,
    Resume,
    Update,
}

impl ControlKind {
    const fn action(self, sequence: u64) -> &'static str {
        match (self, sequence) {
            (Self::Pause, 1) => "pause-1",
            (Self::Resume, 2) => "resume-2",
            (Self::Update, 3) => "update-3",
            _ => "invalid-control-sequence",
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Pause => "Pause",
            Self::Resume => "Resume",
            Self::Update => "Update",
        }
    }

    pub(super) const fn journal_kind(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Update => "update",
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn qualify(
    config: &QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    identity: &RuntimeIdentity,
    init_pid: u32,
    mut replacement: Child,
) -> TestResult<(Channel, Child)> {
    let baseline = read_control_journal(bundle).await?;
    if baseline.schema_version != 9
        || baseline.completed_sequence != 0
        || baseline.pending.is_some()
        || baseline.last_update_digest.is_some()
    {
        return Err(qualification_error(format!(
            "task control journal before committed replacements was {baseline:?}; expected schema 9, sequence 0, and no pending or completed Update"
        ))
        .into());
    }

    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "pids": {"limit": EXPECTED_PIDS_LIMIT}
    }))
    .map_err(|error| qualification_error(format!("build rehydrated Update resources: {error}")))?;

    let (_, next) = qualify_boundary(
        config,
        id,
        bundle,
        binary,
        bootstrap,
        identity,
        init_pid,
        ControlKind::Pause,
        1,
        None,
        replacement,
    )
    .await?;
    replacement = next;
    shim_control(&bootstrap.address, id, ControlKind::Pause, None).await?;
    assert_completed(bundle, 1, None).await?;

    let (_, next) = qualify_boundary(
        config,
        id,
        bundle,
        binary,
        bootstrap,
        identity,
        init_pid,
        ControlKind::Resume,
        2,
        None,
        replacement,
    )
    .await?;
    replacement = next;
    shim_control(&bootstrap.address, id, ControlKind::Resume, None).await?;
    assert_completed(bundle, 2, None).await?;

    let (channel, replacement) = qualify_boundary(
        config,
        id,
        bundle,
        binary,
        bootstrap,
        identity,
        init_pid,
        ControlKind::Update,
        3,
        Some(resources.clone()),
        replacement,
    )
    .await?;
    let update_digest = update_digest(&resources)?;
    shim_control(&bootstrap.address, id, ControlKind::Update, Some(resources)).await?;
    assert_completed(bundle, 3, Some(&update_digest)).await?;

    let stats = faults::runtime_client(config)
        .await?
        .stats(StatsRequest {
            target: ContainerTarget::exact(
                identity.container_id.clone(),
                Generation(identity.generation),
            ),
        })
        .await
        .map_err(|error| {
            qualification_error(format!(
                "read stats after rehydrated Update replay: {error}"
            ))
        })?;
    if stats.metrics.get(PIDS_LIMIT_METRIC) != Some(&EXPECTED_PIDS_LIMIT) {
        return Err(qualification_error(format!(
            "rehydrated Update reported {}={:?}, expected {EXPECTED_PIDS_LIMIT}",
            PIDS_LIMIT_METRIC,
            stats.metrics.get(PIDS_LIMIT_METRIC)
        ))
        .into());
    }

    Ok((channel, replacement))
}

#[allow(clippy::too_many_arguments)]
async fn qualify_boundary(
    config: &QualificationConfig,
    id: &str,
    bundle: &Path,
    binary: &Path,
    bootstrap: &Bootstrap,
    identity: &RuntimeIdentity,
    init_pid: u32,
    kind: ControlKind,
    sequence: u64,
    resources: Option<LinuxResources>,
    mut old_replacement: Child,
) -> TestResult<(Channel, Child)> {
    let old_shim_pid = old_replacement
        .id()
        .ok_or_else(|| qualification_error(format!("committed-{} shim has no PID", kind.name())))?;
    let host_pid = faults::find_runtime_host_pid(config).await?;
    let mut suspended_host = faults::SuspendedProcess::stop(
        host_pid,
        &format!("committed-{} A3S OCI host service", kind.name()),
    )?;
    let call_address = bootstrap.address.clone();
    let call_id = id.to_string();
    let call_resources = resources.clone();
    let mut control_call =
        tokio::spawn(
            async move { shim_control(&call_address, &call_id, kind, call_resources).await },
        );

    wait_for_pending_control(
        bundle,
        sequence,
        kind,
        resources.as_ref(),
        &mut control_call,
    )
    .await?;
    let suspended_shim = faults::SuspendedProcess::stop(
        old_shim_pid,
        &format!("committed-{} original shim", kind.name()),
    )?;
    suspended_host.resume(&format!("committed-{} A3S OCI host service", kind.name()))?;
    commit_runtime_control(config, id, identity, sequence, kind, resources.clone()).await?;

    let containerd_pid = containerd_main_pid(config).await?;
    faults::send_signal(
        containerd_pid,
        libc::SIGSTOP,
        &format!("committed-{} containerd", kind.name()),
    )?;
    let mut replacement = None;
    let relaunch = async {
        suspended_shim.kill(&format!("committed-{} original shim", kind.name()))?;
        wait_for_killed_child(
            &mut old_replacement,
            &format!("committed-{} original shim", kind.name()),
        )
        .await?;
        launch_replacement_while_containerd_suspended(
            config,
            id,
            bundle,
            binary,
            bootstrap,
            containerd_pid,
            &mut replacement,
        )
        .await
    }
    .await;
    let _ = faults::send_signal(
        containerd_pid,
        libc::SIGCONT,
        &format!("committed-{} containerd", kind.name()),
    );
    if let Err(error) = relaunch {
        control_call.abort();
        let _ = control_call.await;
        let _ = old_replacement.start_kill();
        let _ = old_replacement.wait().await;
        stop_replacement(&mut replacement).await;
        let recovery = restart_containerd(
            config,
            &format!("failed-committed-{}-rehydration", kind.journal_kind()),
        )
        .await;
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery_error) => Err(qualification_error(format!(
                "committed {} replacement failed: {error}; containerd recovery also failed: {recovery_error}",
                kind.name()
            ))
            .into()),
        };
    }

    let replacement = replacement.ok_or_else(|| {
        qualification_error(format!(
            "committed-{} relaunch omitted its child process",
            kind.name()
        ))
    })?;
    let replacement_pid = replacement.id().ok_or_else(|| {
        qualification_error(format!("committed-{} replacement has no PID", kind.name()))
    })?;
    let channel = restart_containerd(
        config,
        &format!("committed-{}-shim-rehydration", kind.journal_kind()),
    )
    .await?;
    match tokio::time::timeout(Duration::from_secs(5), control_call).await {
        Ok(Ok(Err(_))) => {}
        Ok(Ok(Ok(()))) => {
            return Err(qualification_error(format!(
                "original {} response survived after its frozen shim was killed",
                kind.name()
            ))
            .into());
        }
        Ok(Err(error)) => {
            return Err(qualification_error(format!(
                "original {} task failed before reporting its lost response: {error}",
                kind.name()
            ))
            .into());
        }
        Err(_) => {
            return Err(qualification_error(format!(
                "original {} call did not observe shim replacement within 5 seconds",
                kind.name()
            ))
            .into());
        }
    }

    let expected_status = if kind == ControlKind::Pause {
        STATUS_PAUSED
    } else {
        STATUS_RUNNING
    };
    super::super::expect_process(
        &task_process(config, &channel, id, "").await?,
        expected_status,
        Some(init_pid),
        &format!("task after committed {} replacement", kind.name()),
    )?;
    if read_runtime_identity(config, id).await? != *identity {
        return Err(qualification_error(format!(
            "committed {} replacement changed the task incarnation or generation",
            kind.name()
        ))
        .into());
    }
    let observed_shim_pid = faults::find_exact_shim_pid(config, id).await?;
    if observed_shim_pid != replacement_pid {
        return Err(qualification_error(format!(
            "containerd connected committed-{} shim PID {observed_shim_pid}, expected {replacement_pid}",
            kind.journal_kind()
        ))
        .into());
    }
    let digest = resources.as_ref().map(update_digest).transpose()?;
    assert_completed(bundle, sequence, digest.as_deref()).await?;

    Ok((channel, replacement))
}

async fn commit_runtime_control(
    config: &QualificationConfig,
    task_id: &str,
    identity: &RuntimeIdentity,
    sequence: u64,
    kind: ControlKind,
    resources: Option<LinuxResources>,
) -> TestResult<()> {
    let client = faults::runtime_client(config).await?;
    let context = OperationContext::new(faults::containerd_operation_id(
        &config.namespace,
        task_id,
        &identity.incarnation,
        kind.action(sequence),
    )?);
    let target = ContainerTarget::exact(
        identity.container_id.clone(),
        Generation(identity.generation),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let result = match kind {
            ControlKind::Pause => {
                client
                    .pause(ContainerOperationRequest {
                        context: context.clone(),
                        target: target.clone(),
                    })
                    .await
            }
            ControlKind::Resume => {
                client
                    .resume(ContainerOperationRequest {
                        context: context.clone(),
                        target: target.clone(),
                    })
                    .await
            }
            ControlKind::Update => {
                client
                    .update(UpdateRequest {
                        context: context.clone(),
                        target: target.clone(),
                        resources: resources.clone().ok_or_else(|| {
                            qualification_error("committed Update omitted Linux resources")
                        })?,
                    })
                    .await
            }
        };
        match result {
            Ok(record) => return validate_runtime_record(record, identity, kind),
            Err(error) if error.retryable && tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => {
                return Err(qualification_error(format!(
                    "commit exact Runtime {} before shim replacement: {error}",
                    kind.name()
                ))
                .into());
            }
        }
    }
}

fn validate_runtime_record(
    record: ContainerRecord,
    identity: &RuntimeIdentity,
    kind: ControlKind,
) -> TestResult<()> {
    let expected_paused = kind == ControlKind::Pause;
    if record.generation != Generation(identity.generation)
        || *record.state.status() != ContainerState::Running
        || record.is_paused() != expected_paused
    {
        return Err(qualification_error(format!(
            "committed Runtime {} returned generation {}, status {}, paused={}; expected generation {}, running, paused={expected_paused}",
            kind.name(),
            record.generation.0,
            record.state.status(),
            record.is_paused(),
            identity.generation
        ))
        .into());
    }
    Ok(())
}

async fn shim_control(
    address: &str,
    id: &str,
    kind: ControlKind,
    resources: Option<LinuxResources>,
) -> TestResult<()> {
    let client = containerd_shim_protos::ttrpc::asynchronous::Client::connect(address)
        .await
        .map_err(|error| {
            qualification_error(format!(
                "connect committed-{} shim at {address}: {error}",
                kind.journal_kind()
            ))
        })?;
    let task = containerd_shim_protos::shim::shim_ttrpc_async::TaskClient::new(client);
    let context = containerd_shim_protos::ttrpc::context::Context::default();
    let result = match kind {
        ControlKind::Pause => {
            let mut request = containerd_shim_protos::api::PauseRequest::new();
            request.set_id(id.to_string());
            task.pause(context, &request).await.map(drop)
        }
        ControlKind::Resume => {
            let mut request = containerd_shim_protos::api::ResumeRequest::new();
            request.set_id(id.to_string());
            task.resume(context, &request).await.map(drop)
        }
        ControlKind::Update => {
            let resources = resources
                .ok_or_else(|| qualification_error("shim Update omitted Linux resources"))?;
            let mut request = containerd_shim_protos::api::UpdateTaskRequest::new();
            request.set_id(id.to_string());
            let mut any = containerd_shim_protos::protobuf::well_known_types::any::Any::new();
            any.type_url = super::super::LINUX_RESOURCES_TYPE.to_string();
            any.value = serde_json::to_vec(&resources).map_err(|error| {
                qualification_error(format!("encode rehydrated Update resources: {error}"))
            })?;
            request.set_resources(any);
            task.update(context, &request).await.map(drop)
        }
    };
    result.map_err(|error| -> crate::support::TestError {
        qualification_error(format!(
            "invoke {} through shim {address} for {id}: {error}",
            kind.name()
        ))
        .into()
    })
}

async fn wait_for_killed_child(child: &mut Child, context: &str) -> TestResult<()> {
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => {
            Err(qualification_error(format!("wait for {context} after SIGKILL: {error}")).into())
        }
        Err(_) => Err(qualification_error(format!(
            "{context} did not exit within 5 seconds after SIGKILL"
        ))
        .into()),
    }
}
