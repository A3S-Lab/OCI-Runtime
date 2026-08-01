use a3s_oci_sdk::{ContainerTarget, Error, ErrorCode, ExitStatus, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::SessionToken;

/// Version of the authenticated guest shutdown report.
pub const AGENT_RECOVERY_REPORT_SCHEMA_VERSION: u16 = 1;
/// Guest environment key containing the one-time recovery report path.
pub const AGENT_RECOVERY_REPORT_ENV: &str = "A3S_OCI_AGENT_RECOVERY_REPORT";
/// Runtime-owned guest directory prefix for one recovery report.
pub const AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX: &str = ".a3s-oci-recovery-";
/// Fixed file name inside a one-time guest recovery directory.
pub const AGENT_RECOVERY_REPORT_FILE_NAME: &str = "report.json";
/// Maximum number of exact container generations in one report.
pub const AGENT_RECOVERY_REPORT_MAX_RECORDS: usize = 1_024;
/// Maximum encoded recovery report accepted from the guest.
pub const AGENT_RECOVERY_REPORT_MAX_BYTES: usize = 1024 * 1024;

const CONFIG_DIGEST_PREFIX: &str = "sha256:";
const SHA256_HEX_BYTES: usize = 64;
const HMAC_BLOCK_BYTES: usize = 64;
const HMAC_BYTES: usize = 32;
const AUTHENTICATION_DOMAIN: &[u8] = b"a3s-oci-agent-recovery-v1\0";

/// Exact init-process evidence retained while a utility VM shuts down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentRecoveryRecord {
    pub target: ContainerTarget,
    pub config_digest: String,
    pub init_exit_status: ExitStatus,
}

impl AgentRecoveryRecord {
    /// Construct and validate evidence for one exact container generation.
    pub fn new(
        target: ContainerTarget,
        config_digest: impl Into<String>,
        init_exit_status: ExitStatus,
    ) -> Result<Self> {
        let record = Self {
            target,
            config_digest: config_digest.into(),
            init_exit_status,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<()> {
        let generation = self.target.generation.ok_or_else(|| {
            recovery_error(
                ErrorCode::InvalidArgument,
                "recovery evidence requires an exact container generation",
            )
        })?;
        if generation.0 == 0 {
            return Err(recovery_error(
                ErrorCode::InvalidArgument,
                "recovery evidence requires a positive container generation",
            ));
        }
        validate_config_digest(&self.config_digest)?;
        self.init_exit_status.validate().map_err(|error| {
            recovery_error(
                error.code,
                format!("recovery evidence contains an invalid init exit status: {error}"),
            )
        })
    }

    fn key(&self) -> (&str, u64) {
        (
            self.target.id.as_str(),
            self.target.generation.map_or(0, |generation| generation.0),
        )
    }
}

/// Canonical, bounded recovery evidence produced by one guest-agent session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentRecoveryReport {
    schema_version: u16,
    records: Vec<AgentRecoveryRecord>,
}

impl AgentRecoveryReport {
    /// Build a deterministically ordered recovery report.
    pub fn new(mut records: Vec<AgentRecoveryRecord>) -> Result<Self> {
        records.sort_by(|left, right| left.key().cmp(&right.key()));
        let report = Self {
            schema_version: AGENT_RECOVERY_REPORT_SCHEMA_VERSION,
            records,
        };
        report.validate()?;
        Ok(report)
    }

    /// Exact container generations included in this report.
    #[must_use]
    pub fn records(&self) -> &[AgentRecoveryRecord] {
        &self.records
    }

    /// Encode a validated report after a trusted shim has authenticated it.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_bounded(self, "recovery report")
    }

    /// Decode a normalized report from protected host-only storage.
    pub fn from_json(encoded: &[u8]) -> Result<Self> {
        validate_encoded_size(encoded)?;
        let report: Self = serde_json::from_slice(encoded).map_err(|error| {
            recovery_error(
                ErrorCode::InvalidArgument,
                format!("failed to decode recovery report: {error}"),
            )
        })?;
        report.validate()?;
        Ok(report)
    }

    /// Authenticate this canonical report with the one-time session token.
    pub fn authenticate(self, token: &SessionToken) -> Result<AuthenticatedAgentRecoveryReport> {
        self.validate()?;
        let payload = canonical_payload(&self)?;
        let authentication_tag = encode_hex(&hmac_sha256(token.as_bytes(), &payload));
        Ok(AuthenticatedAgentRecoveryReport {
            report: self,
            authentication_tag,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != AGENT_RECOVERY_REPORT_SCHEMA_VERSION {
            return Err(recovery_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "unsupported recovery report schema {}; expected {}",
                    self.schema_version, AGENT_RECOVERY_REPORT_SCHEMA_VERSION
                ),
            ));
        }
        if self.records.len() > AGENT_RECOVERY_REPORT_MAX_RECORDS {
            return Err(recovery_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "recovery report contains {} records; maximum is {}",
                    self.records.len(),
                    AGENT_RECOVERY_REPORT_MAX_RECORDS
                ),
            ));
        }
        for record in &self.records {
            record.validate()?;
        }
        for pair in self.records.windows(2) {
            if pair[0].key() >= pair[1].key() {
                return Err(recovery_error(
                    ErrorCode::InvalidArgument,
                    "recovery records must be sorted and unique by exact container generation",
                ));
            }
        }
        Ok(())
    }
}

/// Recovery report plus a session-bound HMAC-SHA256 authentication tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuthenticatedAgentRecoveryReport {
    report: AgentRecoveryReport,
    authentication_tag: String,
}

impl AuthenticatedAgentRecoveryReport {
    /// Encode a bounded authenticated report for one-time file handoff.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        encode_bounded(self, "authenticated recovery report")
    }

    /// Decode, validate, and authenticate a one-time guest report.
    pub fn verify_json(encoded: &[u8], token: &SessionToken) -> Result<AgentRecoveryReport> {
        validate_encoded_size(encoded)?;
        let authenticated: Self = serde_json::from_slice(encoded).map_err(|error| {
            recovery_error(
                ErrorCode::InvalidArgument,
                format!("failed to decode authenticated recovery report: {error}"),
            )
        })?;
        authenticated.verify(token)
    }

    /// Validate and authenticate an already decoded report.
    pub fn verify(self, token: &SessionToken) -> Result<AgentRecoveryReport> {
        self.report.validate()?;
        let received = decode_authentication_tag(&self.authentication_tag)?;
        let payload = canonical_payload(&self.report)?;
        let expected = hmac_sha256(token.as_bytes(), &payload);
        if !constant_time_eq(&received, &expected) {
            return Err(recovery_error(
                ErrorCode::PermissionDenied,
                "recovery report authentication failed",
            ));
        }
        Ok(self.report)
    }
}

fn encode_bounded(value: &impl Serialize, label: &str) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(|error| {
        recovery_error(
            ErrorCode::Internal,
            format!("failed to encode {label}: {error}"),
        )
    })?;
    validate_encoded_size(&encoded)?;
    Ok(encoded)
}

fn validate_encoded_size(encoded: &[u8]) -> Result<()> {
    if encoded.len() > AGENT_RECOVERY_REPORT_MAX_BYTES {
        return Err(recovery_error(
            ErrorCode::ResourceExhausted,
            format!(
                "encoded recovery report is {} bytes; maximum is {}",
                encoded.len(),
                AGENT_RECOVERY_REPORT_MAX_BYTES
            ),
        ));
    }
    Ok(())
}

fn canonical_payload(report: &AgentRecoveryReport) -> Result<Vec<u8>> {
    serde_json::to_vec(report).map_err(|error| {
        recovery_error(
            ErrorCode::Internal,
            format!("failed to encode recovery report payload: {error}"),
        )
    })
}

fn validate_config_digest(digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix(CONFIG_DIGEST_PREFIX) else {
        return Err(invalid_config_digest());
    };
    if hex.len() != SHA256_HEX_BYTES
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid_config_digest());
    }
    Ok(())
}

fn invalid_config_digest() -> Error {
    recovery_error(
        ErrorCode::InvalidArgument,
        "recovery config digest must be canonical sha256:<64 lowercase hexadecimal bytes>",
    )
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_BYTES] {
    debug_assert!(key.len() <= HMAC_BLOCK_BYTES);
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(AUTHENTICATION_DOMAIN);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn decode_authentication_tag(encoded: &str) -> Result<[u8; HMAC_BYTES]> {
    if encoded.len() != HMAC_BYTES * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(recovery_error(
            ErrorCode::InvalidArgument,
            "recovery authentication tag must contain 64 lowercase hexadecimal characters",
        ));
    }
    let mut decoded = [0_u8; HMAC_BYTES];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).map_err(|error| {
            recovery_error(
                ErrorCode::InvalidArgument,
                format!("recovery authentication tag is invalid: {error}"),
            )
        })?;
    }
    Ok(decoded)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn recovery_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("authenticate-agent-recovery")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ContainerId, ContainerTarget, ExitStatus, Generation};

    use super::{
        AgentRecoveryRecord, AgentRecoveryReport, AuthenticatedAgentRecoveryReport,
        AGENT_RECOVERY_REPORT_MAX_BYTES,
    };
    use crate::SessionToken;

    fn token(byte: u8) -> SessionToken {
        SessionToken::from_bytes([byte; 32]).expect("nonzero test token")
    }

    fn record(id: &str, generation: u64, exit_code: i32) -> AgentRecoveryRecord {
        AgentRecoveryRecord::new(
            ContainerTarget::exact(
                ContainerId::new(id).expect("valid test ID"),
                Generation(generation),
            ),
            format!("sha256:{}", "a".repeat(64)),
            ExitStatus::exited(exit_code).expect("valid test exit status"),
        )
        .expect("valid recovery record")
    }

    #[test]
    fn report_is_sorted_authenticated_and_round_trips() {
        let report = AgentRecoveryReport::new(vec![record("two", 2, 17), record("one", 1, 0)])
            .expect("valid report");
        let authenticated = report
            .clone()
            .authenticate(&token(7))
            .expect("authenticate");
        let encoded = authenticated.to_json().expect("encode");
        let verified = AuthenticatedAgentRecoveryReport::verify_json(&encoded, &token(7))
            .expect("verify report");
        assert_eq!(verified, report);
        assert_eq!(
            AgentRecoveryReport::from_json(&verified.to_json().expect("normalize report"))
                .expect("decode normalized report"),
            report
        );
        assert_eq!(verified.records()[0].target.id.as_str(), "one");
        assert_eq!(verified.records()[1].target.id.as_str(), "two");
    }

    #[test]
    fn report_rejects_tampering_and_the_wrong_session() {
        let report = AgentRecoveryReport::new(vec![record("box", 3, 42)]).expect("valid report");
        let encoded = report.authenticate(&token(9)).unwrap().to_json().unwrap();
        assert!(AuthenticatedAgentRecoveryReport::verify_json(&encoded, &token(8)).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["report"]["records"][0]["initExitStatus"]["exit_code"] = 43.into();
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(AuthenticatedAgentRecoveryReport::verify_json(&tampered, &token(9)).is_err());
    }

    #[test]
    fn record_requires_an_exact_target_and_canonical_digest() {
        let id = ContainerId::new("box").expect("valid ID");
        let exit = ExitStatus::exited(0).expect("valid exit");
        assert!(AgentRecoveryRecord::new(
            ContainerTarget::current(id.clone()),
            format!("sha256:{}", "a".repeat(64)),
            exit.clone(),
        )
        .is_err());
        assert!(AgentRecoveryRecord::new(
            ContainerTarget::exact(id.clone(), Generation(0)),
            format!("sha256:{}", "a".repeat(64)),
            exit.clone(),
        )
        .is_err());
        assert!(AgentRecoveryRecord::new(
            ContainerTarget::exact(id, Generation(1)),
            format!("sha256:{}", "A".repeat(64)),
            exit,
        )
        .is_err());
    }

    #[test]
    fn decoder_enforces_the_wire_size_before_parsing() {
        let oversized = vec![b' '; AGENT_RECOVERY_REPORT_MAX_BYTES + 1];
        assert!(AuthenticatedAgentRecoveryReport::verify_json(&oversized, &token(1)).is_err());
    }
}
