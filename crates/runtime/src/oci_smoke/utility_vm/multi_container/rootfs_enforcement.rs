use a3s_oci_agent_protocol::{AgentClient, AgentDeleteRequest, AgentWaitRequest, GuestPath};
use a3s_oci_sdk::{DeleteMode, ExitStatus};

use super::lifecycle::{
    create_request, guest_call, operation, require, require_created, require_running,
    start_request, state_is_missing, target, wait_until_stopped, AgentStream,
};
use crate::rootfs_enforcement::RootfsEnforcementFixture;
use crate::OciVmMultiContainerSmokeReport;

pub(super) async fn exercise<T: AgentStream>(
    client: &AgentClient<T>,
    fixture: &RootfsEnforcementFixture,
    guest_bundle: GuestPath,
    nonce: &str,
    report: &mut OciVmMultiContainerSmokeReport,
) -> Result<(), String> {
    let target = target(nonce, "rootfs-enforcement", 1)?;
    let create = create_request(
        nonce,
        "rootfs-enforcement-create",
        target.clone(),
        &fixture.bundle,
        guest_bundle,
    )?;
    let created = guest_call("create rootfs enforcement workload", client.create(create)).await?;
    require_created(&created, "rootfs enforcement workload")?;
    report.rootfs_mount.created_before_start = true;

    report.rootfs_mount.mount_targets_created_before_start = fixture.targets_created().await?;
    require(
        report.rootfs_mount.mount_targets_created_before_start,
        "rootfs enforcement create did not create every missing mount target",
    )?;
    report.rootfs_mount.evidence_absent_before_start = fixture.evidence_absent().await?;
    require(
        report.rootfs_mount.evidence_absent_before_start,
        "rootfs enforcement workload ran before start",
    )?;

    let started = guest_call(
        "start rootfs enforcement workload",
        client.start(start_request(
            nonce,
            "rootfs-enforcement-start",
            target.clone(),
            &fixture.bundle,
        )?),
    )
    .await?;
    require_running(&started, "rootfs enforcement workload")?;
    report.rootfs_mount.start_released = true;

    let waited = guest_call(
        "wait for rootfs enforcement workload",
        client.wait(AgentWaitRequest {
            target: target.clone(),
            timeout_ms: Some(15_000),
        }),
    )
    .await?;
    report.rootfs_mount.wait_status = Some(waited.clone());
    let evidence = fixture
        .collect_evidence(&mut report.rootfs_mount, &mut report.pid_supervision)
        .await?;
    let expected = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct expected rootfs exit: {error}"))?;
    require(
        waited == expected,
        format!(
            "rootfs enforcement workload returned unexpected status {waited:?}; \
             retained evidence: {evidence:?}"
        ),
    )?;
    require(
        report.rootfs_mount.exact_evidence,
        "rootfs enforcement workload did not emit exact complete evidence",
    )?;
    require(
        report.pid_supervision.is_success(),
        "rootfs enforcement workload did not prove PID 1 supervision and orphan reaping",
    )?;
    require(
        wait_until_stopped(client, &target).await?,
        "rootfs enforcement workload did not stop",
    )?;

    guest_call(
        "delete rootfs enforcement workload",
        client.delete(AgentDeleteRequest {
            context: operation(nonce, "rootfs-enforcement-delete")?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    report.rootfs_mount.state_removed =
        state_is_missing(client, &target, "rootfs enforcement workload after delete").await?;
    require(
        report.rootfs_mount.state_removed,
        "rootfs enforcement workload remained visible after delete",
    )
}
