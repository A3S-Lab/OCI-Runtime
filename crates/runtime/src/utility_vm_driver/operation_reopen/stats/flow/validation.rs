use a3s_oci_agent_protocol::AgentStatsRequest;
use a3s_oci_sdk::{ErrorCode, OciRuntimeService, StatsRequest};
use tokio::time::timeout;

use super::super::Qualification;
use super::support::{append_failure, stale_target, FirstOwnerOutcome};
use crate::oci_smoke::utility_vm::lifecycle::resource_stats_snapshot_is_exact;
use crate::utility_vm_driver::operation_reopen::driver::QualificationKvmOperationDriver;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

use super::super::super::QUALIFICATION_TIMEOUT;

pub(super) async fn verify_stats_and_fences(
    driver: &QualificationKvmOperationDriver,
    service: &HostRuntimeService,
    qualification: &Qualification,
    first: &FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
    failure: &mut Option<String>,
) {
    let calls_before_stats = driver.stats_calls();
    let replacement = match timeout(
        QUALIFICATION_TIMEOUT,
        service.stats(StatsRequest {
            target: qualification.stats_target.clone(),
        }),
    )
    .await
    {
        Ok(Ok(stats)) => {
            report.replacement_stats_verified =
                resource_stats_snapshot_is_exact(&stats, &first.target);
            report.operation_completed_after_reopen = report.replacement_stats_verified;
            report.generation_after_reopen = stats.target.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            report.stats_snapshot_rebound =
                report.first_stats_snapshot.as_ref().is_none_or(|original| {
                    stats.timestamp_unix_ns > original.timestamp_unix_ns && stats != *original
                });
            if !report.replacement_stats_verified {
                append_failure(
                    failure,
                    "replacement KVM Stats did not match the rebuilt updated resource profile",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    failure,
                    "replacement KVM Stats changed the durable generation",
                );
            }
            if !report.stats_snapshot_rebound {
                append_failure(failure, "replacement KVM Stats reused the first snapshot");
            }
            Some(stats)
        }
        Ok(Err(error)) => {
            append_failure(failure, format!("replacement KVM Stats failed: {error}"));
            None
        }
        Err(_) => {
            append_failure(failure, "replacement KVM Stats timed out");
            None
        }
    };
    report.replacement_stats_snapshot = replacement;
    report.operation_replayed_without_driver_dispatch = driver.stats_calls() == calls_before_stats;
    report.replacement_operation_dispatches = driver.stats_calls();
    if report.operation_replayed_without_driver_dispatch {
        append_failure(
            failure,
            "replacement KVM Stats did not reach the replacement driver",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            failure,
            format!(
                "replacement KVM driver recorded {} Stats dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
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
        driver.guest_stats(AgentStatsRequest {
            target: stale.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            failure,
            format!("replacement KVM Guest returned the wrong stale Stats error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(failure, "replacement KVM Guest accepted stale Stats"),
        Err(_) => append_failure(failure, "replacement KVM Guest stale Stats timed out"),
    }
    let calls_before_stale_host = driver.stats_calls();
    match service.stats(StatsRequest { target: stale }).await {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.stats_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            failure,
            format!("reopened KVM Host returned the wrong stale Stats error: {error}"),
        ),
        Ok(_) => append_failure(failure, "reopened KVM Host accepted stale Stats"),
    }
}
