#[cfg(any(target_os = "linux", test))]
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

#[cfg(any(target_os = "linux", test))]
use a3s_oci_agent_protocol::{
    AgentTransportFaultInjector, AgentTransportFaultPoint, AgentTransportQualificationEvidence,
    AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX, AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION,
};
use a3s_oci_agent_protocol::{
    AgentTransportQualificationRequest, AGENT_TRANSPORT_QUALIFICATION_ENV,
};
#[cfg(any(target_os = "linux", test))]
use a3s_oci_sdk::OperationId;
use a3s_oci_sdk::{Error, ErrorCode, Result};

pub(crate) fn take_request() -> Result<Option<AgentTransportQualificationRequest>> {
    let Some(encoded) = std::env::var_os(AGENT_TRANSPORT_QUALIFICATION_ENV) else {
        return Ok(None);
    };
    std::env::remove_var(AGENT_TRANSPORT_QUALIFICATION_ENV);
    let encoded = encoded.into_string().map_err(|_| {
        Error::new(
            ErrorCode::InvalidArgument,
            "guest transport qualification handoff is not valid UTF-8",
        )
        .for_operation("bootstrap-guest-agent")
    })?;
    AgentTransportQualificationRequest::from_json(&encoded)
        .map(Some)
        .map_err(|error| {
            Error::new(
                error.code,
                format!("guest transport qualification handoff is invalid: {error}"),
            )
            .for_operation("bootstrap-guest-agent")
        })
}

#[derive(Debug)]
#[cfg(any(target_os = "linux", test))]
pub(crate) struct GuestTransportQualificationFault {
    request: AgentTransportQualificationRequest,
    crossings: AtomicU32,
    protocol_version: AtomicU16,
}

#[cfg(any(target_os = "linux", test))]
impl GuestTransportQualificationFault {
    pub(crate) const fn new(request: AgentTransportQualificationRequest) -> Self {
        Self {
            request,
            crossings: AtomicU32::new(0),
            protocol_version: AtomicU16::new(0),
        }
    }

    fn protocol_version(&self) -> Option<u16> {
        match self.protocol_version.load(Ordering::SeqCst) {
            0 => None,
            version => Some(version),
        }
    }

    fn crossing_count(&self) -> u32 {
        self.crossings.load(Ordering::SeqCst)
    }
}

#[cfg(any(target_os = "linux", test))]
impl AgentTransportFaultInjector for GuestTransportQualificationFault {
    fn check(&self, _point: AgentTransportFaultPoint) -> Result<()> {
        Ok(())
    }

    fn check_operation(
        &self,
        point: AgentTransportFaultPoint,
        operation_id: Option<&OperationId>,
    ) -> Result<()> {
        let AgentTransportFaultPoint::Operation {
            protocol_version,
            operation,
            stage,
        } = point
        else {
            return Ok(());
        };
        let identity_matches = operation_id == Some(self.request.operation_id())
            || (operation_id.is_none() && !operation.requires_operation_id(protocol_version));
        if operation != self.request.operation()
            || stage != self.request.stage()
            || !identity_matches
        {
            return Ok(());
        }
        self.protocol_version
            .store(protocol_version, Ordering::SeqCst);
        let crossing = self.crossings.fetch_add(1, Ordering::SeqCst) + 1;
        if crossing != 1 {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::Unavailable,
            format!("injected real utility-VM guest transport fault at {point}"),
        )
        .for_operation(AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION)
        .retryable(true))
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn finish(
    serve_result: Result<()>,
    cleanup_result: Result<()>,
    fault: &GuestTransportQualificationFault,
) -> Result<()> {
    if let Err(cleanup) = cleanup_result {
        return match serve_result {
            Ok(()) => Err(cleanup),
            Err(error) => Err(Error::new(
                error.code,
                format!("{error}; guest executor cleanup also failed: {cleanup}"),
            )
            .for_operation("run-guest-agent")
            .retryable(error.retryable)),
        };
    }
    let error = serve_result.err().ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            "guest transport qualification connection ended without the armed fault",
        )
        .for_operation("run-guest-agent")
    })?;
    if error.code != ErrorCode::Unavailable
        || !error.retryable
        || error.operation.as_deref() != Some(AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION)
        || fault.crossing_count() != 1
    {
        return Err(error);
    }
    let protocol_version = fault.protocol_version().ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            "guest transport qualification fault did not retain a protocol version",
        )
        .for_operation("run-guest-agent")
    })?;
    let evidence = AgentTransportQualificationEvidence::new(
        &fault.request,
        protocol_version,
        fault.crossing_count(),
    );
    let encoded = evidence.to_json()?;
    eprintln!("{AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX}{encoded}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportFaultInjector, AgentTransportFaultPoint,
        AgentTransportOperationStage, AgentTransportQualificationRequest,
        AGENT_PROTOCOL_VERSION_MAX, AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION,
    };
    use a3s_oci_sdk::{Error, ErrorCode, OperationId};

    use super::{finish, GuestTransportQualificationFault};

    #[test]
    fn requires_the_exact_operation_id_and_successful_cleanup() {
        let operation_id = OperationId::new("guest-qualification-create").expect("operation ID");
        let request = AgentTransportQualificationRequest::new(
            operation_id.clone(),
            AgentOperation::Create,
            AgentTransportOperationStage::GuestBeforeResponseWrite,
        )
        .expect("qualification request");
        let fault = GuestTransportQualificationFault::new(request);
        let point = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Create,
            stage: AgentTransportOperationStage::GuestBeforeResponseWrite,
        };
        let unrelated = OperationId::new("unrelated-create").expect("operation ID");
        assert!(fault.check_operation(point, Some(&unrelated)).is_ok());
        let injected = fault
            .check_operation(point, Some(&operation_id))
            .expect_err("exact request must cross the fault once");
        assert_eq!(
            injected.operation.as_deref(),
            Some(AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION)
        );
        assert!(fault.check_operation(point, Some(&operation_id)).is_ok());
        assert!(finish(Err(injected.clone()), Ok(()), &fault).is_err());

        let exact_fault = GuestTransportQualificationFault::new(
            AgentTransportQualificationRequest::new(
                operation_id.clone(),
                AgentOperation::Create,
                AgentTransportOperationStage::GuestBeforeResponseWrite,
            )
            .expect("qualification request"),
        );
        let injected = exact_fault
            .check_operation(point, Some(&operation_id))
            .expect_err("exact request must cross the fault once");
        assert!(finish(Err(injected.clone()), Ok(()), &exact_fault).is_ok());
        let cleanup = Error::new(ErrorCode::Internal, "cleanup failed")
            .for_operation("shutdown-guest-executor");
        assert!(finish(Err(injected), Err(cleanup), &exact_fault).is_err());
    }

    #[test]
    fn context_free_observation_uses_the_handoff_nonce_and_exact_stage() {
        let operation_id = OperationId::new("guest-qualification-state").expect("operation ID");
        let selected = AgentTransportOperationStage::GuestAfterDispatch;
        let request =
            AgentTransportQualificationRequest::new(operation_id, AgentOperation::State, selected)
                .expect("qualification request");
        let fault = GuestTransportQualificationFault::new(request);
        let unrelated_operation = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Wait,
            stage: selected,
        };
        assert!(fault.check_operation(unrelated_operation, None).is_ok());
        let unrelated_stage = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::State,
            stage: AgentTransportOperationStage::GuestBeforeDispatch,
        };
        assert!(fault.check_operation(unrelated_stage, None).is_ok());

        let target = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::State,
            stage: selected,
        };
        let error = fault
            .check_operation(target, None)
            .expect_err("exact context-free observation must cross the fault once");
        assert_eq!(
            error.operation.as_deref(),
            Some(AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION)
        );
        assert!(fault.check_operation(target, None).is_ok());
    }
}
