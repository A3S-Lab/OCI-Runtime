use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{ContainerTarget, OciRuntimeService, StateRequest};
use tokio::time::timeout;

use super::super::super::driver::QualificationKvmOperationDriver;
use super::super::super::QUALIFICATION_TIMEOUT;
use super::super::Qualification;
use super::support::{append_failure, record_interruption};
use crate::oci_smoke::utility_vm::transport_fault_cleanup::HostTransportFault;
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

pub(super) async fn run(
    service: &HostRuntimeService,
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    qualification: &Qualification,
    faults: &HostTransportFault,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Option<String> {
    let response_delivered =
        qualification.stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut failure = None;
    match timeout(
        QUALIFICATION_TIMEOUT,
        service.read_output(qualification.read_output.clone()),
    )
    .await
    {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, qualification.stage) {
                append_failure(&mut failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut failure,
            format!(
                "{} did not deliver its completed KVM ReadOutput response: {error}",
                qualification.stage.as_str()
            ),
        ),
        Ok(Ok(chunks)) if response_delivered => {
            report.first_operation_response_received = true;
            report.first_output_verified = chunks == qualification.expected_output;
            report.first_output_chunks = Some(chunks);
            if !report.first_output_verified {
                append_failure(
                    &mut failure,
                    "delivered first KVM ReadOutput response did not match the nonce-bound output",
                );
            }
            report.disconnect_probe_attempted = true;
            match timeout(
                QUALIFICATION_TIMEOUT,
                service.state(StateRequest {
                    target: target.clone(),
                }),
            )
            .await
            {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, qualification.stage) {
                        append_failure(&mut failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut failure,
                    format!(
                        "{} KVM ReadOutput disconnect probe unexpectedly succeeded",
                        qualification.stage.as_str()
                    ),
                ),
                Err(_) => append_failure(
                    &mut failure,
                    format!(
                        "{} KVM ReadOutput disconnect probe timed out",
                        qualification.stage.as_str()
                    ),
                ),
            }
        }
        Ok(Ok(chunks)) => append_failure(
            &mut failure,
            format!(
                "first KVM ReadOutput unexpectedly completed before owner replacement: {chunks:?}"
            ),
        ),
        Err(_) => append_failure(&mut failure, "first KVM ReadOutput timed out"),
    }
    report.first_operation_dispatches = driver.read_output_calls();
    if qualification.stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    failure
}
