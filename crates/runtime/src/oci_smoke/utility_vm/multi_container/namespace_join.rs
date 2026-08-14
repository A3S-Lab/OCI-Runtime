use std::path::Path;
use std::time::Duration;

use a3s_oci_agent_protocol::{AgentClient, AgentDeleteRequest, AgentWaitRequest, GuestPath};
use a3s_oci_sdk::{DeleteMode, ErrorCode, ExitStatus, OciBundle};
use tokio::time::timeout;

use super::super::remove_marker;
use super::lifecycle::{
    create_request, guest_call, kill_request, operation, require, require_created,
    require_kill_state, require_running, start_request, state_equals, state_is_missing, target,
    wait_request, wait_until_stopped, AgentStream,
};
use crate::namespace_join::build_bundles;
use crate::OciVmMultiContainerSmokeReport;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) async fn exercise<T: AgentStream>(
    client: &AgentClient<T>,
    donor_bundle: &OciBundle,
    joiner_bundle: &OciBundle,
    guest_bundles: [GuestPath; 2],
    nonce: &str,
    markers: [&Path; 2],
    report: &mut OciVmMultiContainerSmokeReport,
) -> Result<(), String> {
    remove_marker(markers[0]).await?;
    remove_marker(markers[1]).await?;

    let donor_target = target(nonce, "namespace-donor", 1)?;
    let donor_create = create_request(
        nonce,
        "namespace-donor-create",
        donor_target.clone(),
        donor_bundle,
        guest_bundles[0].clone(),
    )?;
    let donor = guest_call("create namespace donor", client.create(donor_create)).await?;
    require_created(&donor, "namespace donor")?;
    let donor_pid = donor
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "namespace donor did not report a positive PID".to_string())?;
    report.namespace_join.donor_pid = Some(donor_pid);

    let bundles = build_bundles(joiner_bundle, donor_pid)?;
    verify_wrong_type_rejection(client, &bundles.wrong_type, guest_bundles[1].clone(), nonce)
        .await?;
    report.namespace_join.wrong_type_rejected_before_state = true;

    let non_mount_target = target(nonce, "namespace-non-mount", 1)?;
    let non_mount_create = create_request(
        nonce,
        "namespace-non-mount-create",
        non_mount_target.clone(),
        &bundles.non_mount,
        guest_bundles[1].clone(),
    )?;
    let non_mount = guest_call(
        "create non-mount namespace joiner",
        client.create(non_mount_create),
    )
    .await?;
    require_created(&non_mount, "non-mount namespace joiner")?;
    report.namespace_join.joined_non_mount_namespaces = true;
    run_joiner(
        client,
        nonce,
        "namespace-non-mount",
        &non_mount_target,
        &bundles.non_mount,
    )
    .await?;
    report.namespace_join.joined_pid_time_workload_verified = true;
    report.namespace_join.joined_user_default_devices_verified = true;

    let mount_target = target(nonce, "namespace-mount", 1)?;
    let mount_create = create_request(
        nonce,
        "namespace-mount-create",
        mount_target.clone(),
        &bundles.mount,
        guest_bundles[1].clone(),
    )?;
    let mount = guest_call("create mount namespace joiner", client.create(mount_create)).await?;
    require_created(&mount, "mount namespace joiner")?;
    report.namespace_join.joined_mount_namespace = true;
    run_joiner(
        client,
        nonce,
        "namespace-mount",
        &mount_target,
        &bundles.mount,
    )
    .await?;
    report.namespace_join.retained_rootfs_verified = true;

    report.namespace_join.donor_unchanged_after_joins = state_equals(
        client,
        &donor_target,
        &donor,
        "namespace donor after joiners",
    )
    .await?;
    require(
        report.namespace_join.donor_unchanged_after_joins,
        "namespace joiners changed the prepared donor state",
    )?;

    guest_call(
        "delete namespace donor",
        client.delete(AgentDeleteRequest {
            context: operation(nonce, "namespace-donor-delete")?,
            target: donor_target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    report.namespace_join.all_state_removed =
        state_is_missing(client, &donor_target, "namespace donor after delete").await?
            && state_is_missing(
                client,
                &non_mount_target,
                "non-mount namespace joiner after delete",
            )
            .await?
            && state_is_missing(client, &mount_target, "mount namespace joiner after delete")
                .await?;
    require(
        report.namespace_join.all_state_removed,
        "namespace join qualification left container state",
    )
}

async fn verify_wrong_type_rejection<T: AgentStream>(
    client: &AgentClient<T>,
    bundle: &OciBundle,
    guest_bundle: GuestPath,
    nonce: &str,
) -> Result<(), String> {
    let target = target(nonce, "namespace-wrong-type", 1)?;
    let create = create_request(
        nonce,
        "namespace-wrong-type-create",
        target.clone(),
        bundle,
        guest_bundle,
    )?;
    match timeout(CALL_TIMEOUT, client.create(create)).await {
        Ok(Err(error)) if error.code == ErrorCode::InvalidArgument => {}
        Ok(Err(error)) => {
            return Err(format!(
                "wrong namespace type returned {:?}, expected InvalidArgument: {}",
                error.code, error.message
            ));
        }
        Ok(Ok(_)) => return Err("wrong namespace type unexpectedly created a container".into()),
        Err(_) => return Err("wrong namespace type create timed out".into()),
    }
    require(
        state_is_missing(client, &target, "wrong namespace type after rejection").await?,
        "wrong namespace type rejection left container state",
    )
}

async fn run_joiner<T: AgentStream>(
    client: &AgentClient<T>,
    nonce: &str,
    label: &str,
    target: &a3s_oci_sdk::ContainerTarget,
    bundle: &OciBundle,
) -> Result<(), String> {
    let started = guest_call(
        &format!("start {label} joiner"),
        client.start(start_request(
            nonce,
            &format!("{label}-start"),
            target.clone(),
            bundle,
        )?),
    )
    .await?;
    require_running(&started, label)?;
    match timeout(
        CALL_TIMEOUT,
        client.wait(AgentWaitRequest {
            target: target.clone(),
            timeout_ms: Some(300),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::DeadlineExceeded => {}
        Ok(Err(error)) => {
            return Err(format!(
                "{label} bounded running wait failed with {:?}: {}",
                error.code, error.message
            ));
        }
        Ok(Ok(status)) => {
            return Err(format!(
                "{label} exited during the running observation window: {status:?}"
            ));
        }
        Err(_) => return Err(format!("{label} bounded running wait call timed out")),
    }
    require(
        state_equals(
            client,
            target,
            &started,
            &format!("{label} after bounded running wait"),
        )
        .await?,
        format!("{label} did not remain running after exec"),
    )?;

    let killed = guest_call(
        &format!("kill {label} joiner"),
        client.kill(kill_request(
            nonce,
            &format!("{label}-kill"),
            target.clone(),
        )?),
    )
    .await?;
    require_kill_state(&killed, label)?;
    let waited = guest_call(
        &format!("wait for {label} joiner"),
        client.wait(wait_request(target.clone())),
    )
    .await?;
    require(
        waited
            == ExitStatus::exited(0)
                .map_err(|error| format!("failed to construct expected joiner exit: {error}"))?,
        format!("{label} joiner returned unexpected exit status {waited:?}"),
    )?;
    require(
        wait_until_stopped(client, target).await?,
        format!("{label} joiner did not stop"),
    )?;
    guest_call(
        &format!("delete {label} joiner"),
        client.delete(AgentDeleteRequest {
            context: operation(nonce, &format!("{label}-delete"))?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    require(
        state_is_missing(client, target, &format!("{label} after delete")).await?,
        format!("{label} joiner remained visible after delete"),
    )
}
