use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest,
    ErrorCode, ExitStatus, IsolationRequest, KillRequest, ListRequest, NetworkAttachmentIdentity,
    NetworkCleanup, OciBundle, OperationContext, OperationId, ProcessIo, RuntimeClient, Signal,
    StartRequest, StateRequest, WaitRequest, NETWORK_ENFORCEMENT_EXTENSION,
    NETWORK_ENFORCEMENT_EXTENSION_VERSION,
};
use tokio::time::{sleep, timeout, Instant};

use super::super::QUALIFICATION_CALL_TIMEOUT as CALL_TIMEOUT;
use super::probe::{interface_exists, probe_mechanism, same_namespace, NamespaceIdentity};
use super::profile::NetworkProfile;
use crate::{
    HostRuntimeService, NativeLinuxDriver, NativeLinuxNetworkEnforcementSmokeConfig,
    NativeLinuxNetworkEnforcementSmokeReport, RuntimeDriver,
};

const POLL_INTERVAL: Duration = Duration::from_millis(25);
const REDIRECT_MARKER_CONTENTS: &[u8] = b"redirect-v1\n";
const REJECTION_MARKER_CONTENTS: &[u8] = b"rejection-v1\n";

pub(super) struct QualificationContext<'a> {
    pub(super) service: HostRuntimeService,
    pub(super) driver: Arc<NativeLinuxDriver>,
    pub(super) state_root: &'a Path,
    pub(super) bundle: &'a OciBundle,
    pub(super) profile: &'a NetworkProfile,
    pub(super) configuration: &'a NativeLinuxNetworkEnforcementSmokeConfig,
    pub(super) nonce: &'a str,
    pub(super) markers: [&'a Path; 2],
    pub(super) namespace_before: NamespaceIdentity,
}

pub(super) async fn exercise(
    context: QualificationContext<'_>,
    report: &mut NativeLinuxNetworkEnforcementSmokeReport,
) -> Result<(), String> {
    let QualificationContext {
        service,
        driver,
        state_root,
        bundle,
        profile,
        configuration,
        nonce,
        markers,
        namespace_before,
    } = context;
    let client = RuntimeClient::new(service.clone());
    let features = native_call("network-enforcement features", client.features()).await?;
    report.extension_advertised = features.attachments.supports_extension(
        NETWORK_ENFORCEMENT_EXTENSION,
        NETWORK_ENFORCEMENT_EXTENSION_VERSION,
    );
    require(
        report.extension_advertised,
        "Native Linux did not advertise network-enforcement extension version 1",
    )?;

    let attachments = CreateAttachments::from_bundle(bundle, ProcessIo::default())
        .map_err(|error| format!("failed to derive base attachments: {error}"))?
        .attach_linux_network_interface(
            bundle,
            profile.namespace_index,
            configuration.source_interface(),
            NetworkAttachmentIdentity::new(
                profile.attachment.namespace().clone(),
                configuration.interface_id().clone(),
                configuration.cleanup_id().clone(),
            ),
            NetworkCleanup::PreserveCallerNamespace,
        )
        .map_err(|error| format!("failed to bind the authorized network interface: {error}"))?
        .attach_network_enforcement(bundle)
        .map_err(|error| format!("failed to bind network-enforcement evidence: {error}"))?;
    let decoded = attachments
        .network_enforcement(bundle)
        .map_err(|error| format!("failed to decode network-enforcement evidence: {error}"))?;
    require(
        decoded.as_ref() == Some(&profile.attachment),
        "decoded network-enforcement evidence changed before Create",
    )?;

    let id = ContainerId::new(format!("native-oar01-{nonce}"))
        .map_err(|error| format!("failed to construct OAR-01 container ID: {error}"))?;
    let create = CreateRequest {
        context: operation(nonce, "create")?,
        id: id.clone(),
        bundle: bundle.clone(),
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
    };
    let created = native_call(
        "create network-enforcement container",
        client.create(create.clone()),
    )
    .await?;
    report.create_returned_created = *created.state.status() == ContainerState::Created;
    require(
        report.create_returned_created,
        "network-enforcement Create did not return the created barrier",
    )?;
    report.created_pid = *created.state.pid();
    let created_pid = report
        .created_pid
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "network-enforcement Create did not return a positive PID".to_string())?;
    require(
        created.network_enforcement.as_ref() == Some(&profile.attachment),
        "created record changed opaque network-enforcement evidence",
    )?;
    let replayed = native_call(
        "replay network-enforcement Create",
        client.create(create.clone()),
    )
    .await?;
    report.create_replayed = replayed == created;
    require(
        report.create_replayed,
        "network-enforcement Create replay changed its result",
    )?;
    report.container_namespace_verified = same_namespace(
        &profile.namespace_path,
        &PathBuf::from(format!("/proc/{created_pid}/ns/net")),
    )
    .await?;
    require(
        report.container_namespace_verified,
        "network-enforcement init did not join the caller-owned namespace",
    )?;
    report.interface_binding_verified =
        interface_exists(&profile.namespace_path, &profile.target_interface)?;
    require(
        report.interface_binding_verified,
        "authorized network interface was not present under its exact target name",
    )?;

    let target = ContainerTarget::exact(id, created.generation);
    let start = StartRequest {
        context: operation(nonce, "start")?,
        target: target.clone(),
    };
    let started = native_call(
        "start network-enforcement container",
        client.start(start.clone()),
    )
    .await?;
    require(
        *started.state.status() == ContainerState::Running,
        "network-enforcement Start did not return Running",
    )?;
    wait_for_markers(&client, &target, markers).await?;
    report.local_redirect_verified = true;
    report.enforcement_rejection_verified = true;

    drop(client);
    drop(service);
    let runtime_driver: Arc<dyn RuntimeDriver> = driver;
    let reopened = HostRuntimeService::open(state_root, runtime_driver)
        .await
        .map_err(|error| format!("failed to reopen durable Host service: {error}"))?;
    report.host_service_reopened = true;
    let client = RuntimeClient::new(reopened.clone());
    let observed = native_call(
        "state after network-enforcement Host reopen",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    report.generation_reused_after_reopen = observed.generation == created.generation;
    report.pid_reused_after_reopen = *observed.state.pid() == Some(created_pid);
    report.attachment_replayed_after_reopen =
        observed.network_enforcement.as_ref() == Some(&profile.attachment);
    require(
        report.generation_reused_after_reopen
            && report.pid_reused_after_reopen
            && report.attachment_replayed_after_reopen,
        "Host reopen changed the generation, PID, or opaque attachment evidence",
    )?;
    let replayed_create = native_call(
        "replay network-enforcement Create after Host reopen",
        client.create(create),
    )
    .await?;
    require(
        replayed_create == created,
        "Host reopen changed the durable Create response",
    )?;
    let replayed_start = native_call(
        "replay network-enforcement Start after Host reopen",
        client.start(start),
    )
    .await?;
    report.start_replayed_after_reopen = replayed_start == started;
    require(
        report.start_replayed_after_reopen,
        "Host reopen redispatched or changed Start",
    )?;

    let kill = KillRequest {
        context: operation(nonce, "kill")?,
        target: target.clone(),
        signal: Signal::new(libc::SIGKILL)
            .map_err(|error| format!("failed to construct qualification signal: {error}"))?,
        all: true,
    };
    let killed = native_call(
        "kill network-enforcement container",
        client.kill(kill.clone()),
    )
    .await?;
    let replayed_kill = native_call("replay network-enforcement Kill", client.kill(kill)).await?;
    require(
        killed == replayed_kill,
        "network-enforcement Kill replay changed its result",
    )?;
    let waited = native_call(
        "wait for network-enforcement container",
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(15_000),
        }),
    )
    .await?;
    let expected_exit = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected exit status: {error}"))?;
    require(
        waited == expected_exit,
        format!("network-enforcement Wait returned {waited:?}, expected {expected_exit:?}"),
    )?;
    report.wait_exit_status = Some(waited);

    let delete = DeleteRequest {
        context: operation(nonce, "delete")?,
        target: target.clone(),
        mode: DeleteMode::StoppedOnly,
    };
    native_call(
        "delete network-enforcement container",
        client.delete(delete.clone()),
    )
    .await?;
    native_call("replay network-enforcement Delete", client.delete(delete)).await?;
    report.delete_replayed = true;
    report.durable_state_removed = match client
        .state(StateRequest {
            target: target.clone(),
        })
        .await
    {
        Err(error) if error.code == ErrorCode::NotFound => native_call(
            "list after network-enforcement Delete",
            client.list(ListRequest::default()),
        )
        .await?
        .is_empty(),
        Err(error) => {
            return Err(format!(
                "state after network-enforcement Delete returned {:?}: {}",
                error.code, error.message
            ));
        }
        Ok(_) => false,
    };
    require(
        report.durable_state_removed,
        "network-enforcement Delete retained durable container state",
    )?;
    report.namespace_preserved_after_delete =
        super::probe::namespace_identity(&profile.namespace_path).await? == namespace_before;
    report.interface_preserved_after_delete =
        interface_exists(&profile.namespace_path, &profile.target_interface)?;
    probe_mechanism(
        &profile.namespace_path,
        configuration.redirect_port(),
        configuration.rejected_port(),
    )?;
    report.mechanism_preserved_after_delete = true;
    require(
        report.namespace_preserved_after_delete && report.interface_preserved_after_delete,
        "Runtime mutated the caller-owned namespace or interface during Delete",
    )?;
    drop(client);
    drop(reopened);
    Ok(())
}

async fn wait_for_markers(
    client: &RuntimeClient,
    target: &ContainerTarget,
    markers: [&Path; 2],
) -> Result<(), String> {
    let deadline = Instant::now() + CALL_TIMEOUT;
    loop {
        let redirect = tokio::fs::read(markers[0]).await;
        let rejection = tokio::fs::read(markers[1]).await;
        if matches!(redirect.as_deref(), Ok(contents) if contents == REDIRECT_MARKER_CONTENTS)
            && matches!(rejection.as_deref(), Ok(contents) if contents == REJECTION_MARKER_CONTENTS)
        {
            return Ok(());
        }
        let observed = native_call(
            "state while waiting for network-enforcement markers",
            client.state(StateRequest {
                target: target.clone(),
            }),
        )
        .await?;
        if *observed.state.status() == ContainerState::Stopped {
            return Err("network-enforcement workload stopped before publishing evidence".into());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for network-enforcement workload evidence".into());
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn operation(nonce: &str, suffix: &str) -> Result<OperationContext, String> {
    OperationId::new(format!("native-oar01-{suffix}-{nonce}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct {suffix} operation identity: {error}"))
}

async fn native_call<T>(
    description: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{description} failed: {error}")),
        Err(_) => Err(format!("{description} timed out")),
    }
}

fn require(condition: bool, reason: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}
