use a3s_oci_sdk::{Error, ErrorCode, OperationId, Result};
use serde::{Deserialize, Serialize};

use crate::{AgentOperation, AgentTransportOperationStage};

/// Guest environment key used only by the explicit real-VM qualification path.
pub const AGENT_TRANSPORT_QUALIFICATION_ENV: &str = "A3S_OCI_AGENT_TRANSPORT_QUALIFICATION";
/// Prefix that identifies one bounded qualification evidence line on the guest console.
pub const AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX: &str =
    "A3S_OCI_AGENT_TRANSPORT_QUALIFICATION_EVIDENCE ";
/// Stable operation attached to the intentional guest-side interruption.
pub const AGENT_TRANSPORT_QUALIFICATION_FAULT_OPERATION: &str =
    "guest-agent-transport-qualification-fault";
/// Version of the qualification request contract.
pub const AGENT_TRANSPORT_QUALIFICATION_REQUEST_SCHEMA_VERSION: &str =
    "a3s.oci.agent-transport-qualification-request.v1";
/// Version of the cleanup evidence emitted by the fixed guest agent.
pub const AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_SCHEMA_VERSION: &str =
    "a3s.oci.agent-transport-qualification-evidence.v1";

const MAX_QUALIFICATION_JSON_BYTES: usize = 1_024;

/// One exact guest operation transition armed by a real-VM qualification run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentTransportQualificationRequest {
    schema_version: String,
    operation_id: OperationId,
    operation: AgentOperation,
    stage: AgentTransportOperationStage,
}

impl AgentTransportQualificationRequest {
    /// Construct and validate a guest-only qualification request.
    pub fn new(
        operation_id: OperationId,
        operation: AgentOperation,
        stage: AgentTransportOperationStage,
    ) -> Result<Self> {
        let request = Self {
            schema_version: AGENT_TRANSPORT_QUALIFICATION_REQUEST_SCHEMA_VERSION.to_string(),
            operation_id,
            operation,
            stage,
        };
        request.validate()?;
        Ok(request)
    }

    /// Decode a bounded, versioned request from the dedicated handoff value.
    pub fn from_json(encoded: &str) -> Result<Self> {
        require_bounded_json(encoded, "qualification request")?;
        let request: Self = serde_json::from_str(encoded).map_err(|error| {
            qualification_error(format!(
                "failed to decode guest transport qualification request: {error}"
            ))
        })?;
        request.validate()?;
        Ok(request)
    }

    /// Encode the validated request for the dedicated shim/guest handoff.
    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|error| {
            qualification_error(format!(
                "failed to encode guest transport qualification request: {error}"
            ))
        })
    }

    /// Idempotency identity that must be present on the selected request.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Operation selected for interruption.
    #[must_use]
    pub const fn operation(&self) -> AgentOperation {
        self.operation
    }

    /// Guest transition selected for interruption.
    #[must_use]
    pub const fn stage(&self) -> AgentTransportOperationStage {
        self.stage
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != AGENT_TRANSPORT_QUALIFICATION_REQUEST_SCHEMA_VERSION {
            return Err(qualification_error(format!(
                "unsupported guest transport qualification request schema {}",
                self.schema_version
            )));
        }
        if !self.stage.is_guest() {
            return Err(qualification_error(format!(
                "guest transport qualification cannot arm host stage {}",
                self.stage.as_str()
            )));
        }
        Ok(())
    }
}

/// Non-secret, nonce-bound evidence emitted only after guest executor cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentTransportQualificationEvidence {
    schema_version: String,
    operation_id: OperationId,
    operation: AgentOperation,
    stage: AgentTransportOperationStage,
    protocol_version: u16,
    fault_crossings: u32,
    executor_cleanup_succeeded: bool,
}

impl AgentTransportQualificationEvidence {
    /// Construct cleanup evidence for the exact armed request.
    #[must_use]
    pub fn new(
        request: &AgentTransportQualificationRequest,
        protocol_version: u16,
        fault_crossings: u32,
    ) -> Self {
        Self {
            schema_version: AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_SCHEMA_VERSION.to_string(),
            operation_id: request.operation_id.clone(),
            operation: request.operation,
            stage: request.stage,
            protocol_version,
            fault_crossings,
            executor_cleanup_succeeded: true,
        }
    }

    /// Decode one bounded console evidence payload.
    pub fn from_json(encoded: &str) -> Result<Self> {
        require_bounded_json(encoded, "qualification evidence")?;
        let evidence: Self = serde_json::from_str(encoded).map_err(|error| {
            qualification_error(format!(
                "failed to decode guest transport qualification evidence: {error}"
            ))
        })?;
        if evidence.schema_version != AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_SCHEMA_VERSION {
            return Err(qualification_error(format!(
                "unsupported guest transport qualification evidence schema {}",
                evidence.schema_version
            )));
        }
        if !evidence.stage.is_guest() {
            return Err(qualification_error(format!(
                "guest transport qualification evidence names host stage {}",
                evidence.stage.as_str()
            )));
        }
        Ok(evidence)
    }

    /// Encode one evidence payload for its prefixed guest-console line.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|error| {
            qualification_error(format!(
                "failed to encode guest transport qualification evidence: {error}"
            ))
        })
    }

    /// Whether this evidence exactly matches the armed request.
    #[must_use]
    pub fn matches_request(&self, request: &AgentTransportQualificationRequest) -> bool {
        self.schema_version == AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_SCHEMA_VERSION
            && self.operation_id == request.operation_id
            && self.operation == request.operation
            && self.stage == request.stage
            && self.executor_cleanup_succeeded
    }

    /// Request identity observed by the guest injector.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Negotiated protocol observed at the injected point.
    #[must_use]
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Exact number of selected transition crossings.
    #[must_use]
    pub const fn fault_crossings(&self) -> u32 {
        self.fault_crossings
    }

    /// Stable display identity for the injected transition.
    #[must_use]
    pub fn injected_point(&self) -> String {
        format!(
            "agent-v{}.{}-{}",
            self.protocol_version,
            self.operation.as_str(),
            self.stage.as_str()
        )
    }
}

fn require_bounded_json(encoded: &str, description: &str) -> Result<()> {
    if encoded.is_empty() || encoded.len() > MAX_QUALIFICATION_JSON_BYTES {
        return Err(qualification_error(format!(
            "guest transport {description} must contain 1..={MAX_QUALIFICATION_JSON_BYTES} bytes"
        )));
    }
    Ok(())
}

fn qualification_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
        .for_operation("validate-agent-transport-qualification")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::OperationId;

    use super::{
        AgentTransportQualificationEvidence, AgentTransportQualificationRequest,
        AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_SCHEMA_VERSION,
    };
    use crate::{AgentOperation, AgentTransportOperationStage};

    #[test]
    fn qualification_round_trip_binds_guest_stage_and_operation_id() {
        let request = AgentTransportQualificationRequest::new(
            OperationId::new("real-vm-guest-fault-create").expect("operation ID"),
            AgentOperation::Create,
            AgentTransportOperationStage::GuestAfterDispatch,
        )
        .expect("qualification request");
        let request = AgentTransportQualificationRequest::from_json(
            &request.to_json().expect("encode qualification request"),
        )
        .expect("decode qualification request");
        let evidence = AgentTransportQualificationEvidence::new(&request, 9, 1);
        let evidence = AgentTransportQualificationEvidence::from_json(
            &evidence.to_json().expect("encode evidence"),
        )
        .expect("decode evidence");

        assert!(evidence.matches_request(&request));
        assert_eq!(evidence.protocol_version(), 9);
        assert_eq!(evidence.fault_crossings(), 1);
        assert_eq!(
            evidence.injected_point(),
            "agent-v9.create-guest-after-dispatch"
        );
    }

    #[test]
    fn qualification_rejects_host_stages_and_unknown_evidence_schemas() {
        let error = AgentTransportQualificationRequest::new(
            OperationId::new("host-stage").expect("operation ID"),
            AgentOperation::Create,
            AgentTransportOperationStage::HostAfterRequestWrite,
        )
        .expect_err("host stage must fail guest qualification");
        assert!(error.message.contains("cannot arm host stage"));

        let encoded = format!(
            r#"{{"schemaVersion":"{AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_SCHEMA_VERSION}-future","operationId":"guest-stage","operation":"create","stage":"guest-after-dispatch","protocolVersion":9,"faultCrossings":1,"executorCleanupSucceeded":true}}"#
        );
        assert!(AgentTransportQualificationEvidence::from_json(&encoded).is_err());
    }
}
