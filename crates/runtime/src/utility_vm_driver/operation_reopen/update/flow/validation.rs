use a3s_oci_agent_protocol::{AgentStatsRequest, AgentUpdateRequest};
use a3s_oci_sdk::{ErrorCode, OciRuntimeService, OperationContext, UpdateRequest};
use tokio::time::timeout;

use super::super::Qualification;
use super::support::{append_failure, changed_resources, stale_target, FirstOwnerOutcome};
use crate::oci_smoke::utility_vm::lifecycle::resource_stats_are_exact;
use crate::utility_vm_driver::operation_reopen::driver::QualificationKvmOperationDriver;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

use super::super::super::QUALIFICATION_TIMEOUT;

pub(super) async fn verify_update_effect_and_fences(
    driver: &QualificationKvmOperationDriver,
    service: &HostRuntimeService,
    qualification: &Qualification,
    first: &FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
    failure: &mut Option<String>,
) {
    let first_stats = match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_stats(AgentStatsRequest {
            target: first.target.clone(),
        }),
    )
    .await
    {
        Ok(Ok(stats)) => Some(stats),
        Ok(Err(error)) => {
            append_failure(
                failure,
                format!("first replacement KVM Guest Stats after Update failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(
                failure,
                "first replacement KVM Guest Stats after Update timed out",
            );
            None
        }
    };
    let second_stats = match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_stats(AgentStatsRequest {
            target: first.target.clone(),
        }),
    )
    .await
    {
        Ok(Ok(stats)) => Some(stats),
        Ok(Err(error)) => {
            append_failure(
                failure,
                format!("second replacement KVM Guest Stats after Update failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(
                failure,
                "second replacement KVM Guest Stats after Update timed out",
            );
            None
        }
    };
    if let (Some(first_stats), Some(second_stats)) = (&first_stats, &second_stats) {
        report.replacement_update_effect_verified =
            resource_stats_are_exact(first_stats, second_stats, &first.target);
        report.replacement_update_stats = Some(second_stats.clone());
        if !report.replacement_update_effect_verified {
            append_failure(
                failure,
                "replacement KVM Stats did not prove the exact updated cgroup profile",
            );
        }
    }

    let changed = match changed_resources(&first.update.resources) {
        Ok(resources) => resources,
        Err(reason) => {
            append_failure(failure, reason);
            first.update.resources.clone()
        }
    };
    let calls_before_changed_host = driver.update_calls();
    match service
        .update(UpdateRequest {
            context: first.update.context.clone(),
            target: first.update.target.clone(),
            resources: changed,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::FailedPrecondition
                && driver.update_calls() == calls_before_changed_host =>
        {
            report.host_changed_request_rejected = true;
        }
        Err(error) => append_failure(
            failure,
            format!("reopened KVM Host returned the wrong changed Update error: {error}"),
        ),
        Ok(_) => append_failure(failure, "reopened KVM Host accepted changed Update"),
    }

    let stale = match stale_target(&first.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(failure, reason);
            first.target.clone()
        }
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_update(AgentUpdateRequest {
            context: OperationContext::new(qualification.stale_guest_operation_id.clone()),
            target: stale.clone(),
            resources: first.update.resources.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            failure,
            format!("replacement KVM Guest returned the wrong stale Update error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(failure, "replacement KVM Guest accepted stale Update"),
        Err(_) => append_failure(
            failure,
            "replacement KVM Guest stale Update check timed out",
        ),
    }
    let calls_before_stale_host = driver.update_calls();
    match service
        .update(UpdateRequest {
            context: OperationContext::new(qualification.stale_host_operation_id.clone()),
            target: stale,
            resources: first.update.resources.clone(),
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.update_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            failure,
            format!("reopened KVM Host returned the wrong stale Update error: {error}"),
        ),
        Ok(_) => append_failure(failure, "reopened KVM Host accepted stale Update"),
    }
}
