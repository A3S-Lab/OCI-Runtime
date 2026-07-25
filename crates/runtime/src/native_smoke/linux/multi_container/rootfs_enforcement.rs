use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ExitStatus, RuntimeClient, StartRequest,
};

use super::lifecycle::{
    container_id, create_request, native_call, operation, require, require_created,
    require_running, state_is_missing, wait_request, wait_until_stopped,
};
use crate::rootfs_enforcement::RootfsEnforcementFixture;
use crate::NativeLinuxMultiContainerSmokeReport;

pub(super) async fn exercise(
    client: &RuntimeClient,
    fixture: &RootfsEnforcementFixture,
    nonce: &str,
    report: &mut NativeLinuxMultiContainerSmokeReport,
) -> Result<(), String> {
    let id = container_id(nonce, "rootfs-enforcement")?;
    let create = create_request(
        nonce,
        "rootfs-enforcement-create",
        id.clone(),
        &fixture.bundle,
    )?;
    let created = native_call("create rootfs enforcement workload", client.create(create)).await?;
    require_created(&created, "rootfs enforcement workload")?;
    report.rootfs_mount.created_before_start = true;
    let target = ContainerTarget::exact(id, created.generation);

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

    let started = native_call(
        "start rootfs enforcement workload",
        client.start(StartRequest {
            context: operation(nonce, "rootfs-enforcement-start")?,
            target: target.clone(),
        }),
    )
    .await?;
    require_running(&started, "rootfs enforcement workload")?;
    report.rootfs_mount.start_released = true;

    let waited = native_call(
        "wait for rootfs enforcement workload",
        client.wait(wait_request(target.clone())),
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

    native_call(
        "delete rootfs enforcement workload",
        client.delete(DeleteRequest {
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
