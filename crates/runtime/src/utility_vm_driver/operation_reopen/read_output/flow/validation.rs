use a3s_oci_agent_protocol::AgentReadOutputRequest;
use a3s_oci_sdk::{ErrorCode, OciRuntimeService, ProcessTarget, ReadOutputRequest};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::QUALIFICATION_TIMEOUT;
use super::super::Qualification;
use super::support::{append_failure, stale_target, FirstOwnerOutcome};
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn verify_output_and_fences(
    driver: &QualificationKvmOperationDriver,
    service: &HostRuntimeService,
    qualification: &Qualification,
    first: &FirstOwnerOutcome,
    report: &mut OciVmOperationReopenReplacementReport,
    failure: &mut Option<String>,
) {
    let calls_before_read = driver.read_output_calls();
    let replacement = match timeout(
        QUALIFICATION_TIMEOUT,
        service.read_output(qualification.read_output.clone()),
    )
    .await
    {
        Ok(Ok(chunks)) => {
            report.replacement_output_verified = chunks == qualification.expected_output;
            report.output_response_rebound = report.replacement_output_verified
                && report.setup_create_response_rebound
                && report.setup_start_response_rebound
                && report.exec_response_rebound;
            report.operation_completed_after_reopen = report.replacement_output_verified;
            report.generation_after_reopen = first.target.generation;
            report.same_generation_reused =
                report.generation_before_reopen == report.generation_after_reopen;
            if !report.replacement_output_verified {
                append_failure(
                    failure,
                    "replacement KVM ReadOutput did not return the nonce-bound captured output",
                );
            }
            if !report.output_response_rebound {
                append_failure(
                    failure,
                    "replacement KVM ReadOutput was not bound to the rebuilt Exec process",
                );
            }
            if !report.same_generation_reused {
                append_failure(
                    failure,
                    "replacement KVM ReadOutput changed the durable generation",
                );
            }
            Some(chunks)
        }
        Ok(Err(error)) => {
            append_failure(
                failure,
                format!("replacement KVM ReadOutput failed: {error}"),
            );
            None
        }
        Err(_) => {
            append_failure(failure, "replacement KVM ReadOutput timed out");
            None
        }
    };
    report.replacement_output_chunks = replacement;
    report.operation_replayed_without_driver_dispatch =
        driver.read_output_calls() == calls_before_read;
    report.replacement_operation_dispatches = driver.read_output_calls();
    if report.operation_replayed_without_driver_dispatch {
        append_failure(
            failure,
            "replacement KVM ReadOutput did not reach the replacement driver",
        );
    }
    if report.replacement_operation_dispatches != 1 {
        append_failure(
            failure,
            format!(
                "replacement KVM driver recorded {} ReadOutput dispatches instead of one",
                report.replacement_operation_dispatches
            ),
        );
    }

    let stale_container = match stale_target(&first.target) {
        Ok(target) => target,
        Err(reason) => {
            append_failure(failure, reason);
            first.target.clone()
        }
    };
    let stale_process = ProcessTarget {
        container: stale_container,
        process_id: first.exec.process_id.clone(),
    };
    match timeout(
        QUALIFICATION_TIMEOUT,
        driver.guest_read_output(AgentReadOutputRequest {
            process: stale_process.clone(),
            after_sequence: qualification.read_output.after_sequence,
            max_bytes: qualification.read_output.max_bytes,
            wait_timeout_ms: qualification.read_output.wait_timeout_ms,
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Ok(Err(error)) => append_failure(
            failure,
            format!("replacement KVM Guest returned the wrong stale ReadOutput error: {error}"),
        ),
        Ok(Ok(_)) => append_failure(failure, "replacement KVM Guest accepted stale ReadOutput"),
        Err(_) => append_failure(failure, "replacement KVM Guest stale ReadOutput timed out"),
    }
    let calls_before_stale_host = driver.read_output_calls();
    match service
        .read_output(ReadOutputRequest {
            process: stale_process,
            after_sequence: qualification.read_output.after_sequence,
            max_bytes: qualification.read_output.max_bytes,
            wait_timeout_ms: qualification.read_output.wait_timeout_ms,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && driver.read_output_calls() == calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            failure,
            format!("reopened KVM Host returned the wrong stale ReadOutput error: {error}"),
        ),
        Ok(_) => append_failure(failure, "reopened KVM Host accepted stale ReadOutput"),
    }
}
