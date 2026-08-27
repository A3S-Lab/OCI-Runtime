//! Policy-neutral trusted-execution-environment launch and attestation contracts.

use std::fmt;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{
    canonical_json_bytes, ContainerTarget, DriverKind, Error, ErrorCode, Result, RuntimeArtifact,
};

/// Required create-time extension for AMD SEV-SNP launch isolation.
pub const AMD_SEV_SNP_LAUNCH_EXTENSION: &str = "dev.a3s.tee.amd-sev-snp";
/// Required create-time extension for Intel TDX launch isolation.
pub const INTEL_TDX_LAUNCH_EXTENSION: &str = "dev.a3s.tee.intel-tdx";
/// First immutable TEE launch-extension contract.
pub const TEE_LAUNCH_EXTENSION_VERSION: u16 = 1;
/// First immutable TEE launch annotation schema.
pub const TEE_LAUNCH_SCHEMA_V1: &str = "a3s.oci.tee-launch.v1";
/// First immutable TEE attestation response schema.
pub const TEE_ATTESTATION_SCHEMA_V1: &str = "a3s.oci.tee-attestation.v1";
/// Exact size of the guest report-data field used by the v1 contract.
pub const TEE_REPORT_DATA_BYTES: usize = 64;
/// Maximum decoded evidence payload accepted from a runtime driver.
pub const MAX_TEE_EVIDENCE_BYTES: usize = 256 * 1024;
/// Maximum canonical launch annotation size.
pub const MAX_TEE_LAUNCH_ANNOTATION_BYTES: usize = 4 * 1024;

const SHA256_HEX_BYTES: usize = 64;
const SHA384_HEX_BYTES: usize = 96;
const MAX_EVIDENCE_MEDIA_TYPE_BYTES: usize = 128;

/// Hardware technology requested for one dedicated utility VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum TeeTechnology {
    AmdSevSnp,
    IntelTdx,
}

impl TeeTechnology {
    /// Exact required attachment extension for this technology.
    #[must_use]
    pub const fn extension_name(self) -> &'static str {
        match self {
            Self::AmdSevSnp => AMD_SEV_SNP_LAUNCH_EXTENSION,
            Self::IntelTdx => INTEL_TDX_LAUNCH_EXTENSION,
        }
    }

    /// Resolve one known TEE launch extension.
    #[must_use]
    pub fn from_extension_name(name: &str) -> Option<Self> {
        match name {
            AMD_SEV_SNP_LAUNCH_EXTENSION => Some(Self::AmdSevSnp),
            INTEL_TDX_LAUNCH_EXTENSION => Some(Self::IntelTdx),
            _ => None,
        }
    }
}

/// Whether a launch uses real TEE hardware or an explicitly non-production simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum TeeMode {
    Hardware,
    Simulated,
}

/// Immutable create-time TEE mechanism request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeeLaunchRequest {
    schema_version: String,
    technology: TeeTechnology,
    mode: TeeMode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeLaunchRequestWire {
    schema_version: String,
    technology: TeeTechnology,
    mode: TeeMode,
}

impl TeeLaunchRequest {
    /// Construct the first policy-neutral launch contract.
    #[must_use]
    pub fn new(technology: TeeTechnology, mode: TeeMode) -> Self {
        Self {
            schema_version: TEE_LAUNCH_SCHEMA_V1.to_string(),
            technology,
            mode,
        }
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub const fn technology(&self) -> TeeTechnology {
        self.technology
    }

    #[must_use]
    pub const fn mode(&self) -> TeeMode {
        self.mode
    }

    /// Encode the canonical JSON string stored in the matching OCI annotation.
    pub fn to_annotation_value(&self) -> Result<String> {
        self.validate()?;
        let encoded = canonical_json_bytes(self).map_err(|error| {
            tee_error(format!(
                "failed to encode canonical TEE launch annotation: {error}"
            ))
        })?;
        if encoded.len() > MAX_TEE_LAUNCH_ANNOTATION_BYTES {
            return Err(tee_error("TEE launch annotation exceeds its bounded size"));
        }
        String::from_utf8(encoded)
            .map_err(|error| tee_error(format!("TEE launch annotation is not UTF-8: {error}")))
    }

    /// Decode a canonical JSON OCI annotation value.
    pub fn from_annotation_value(encoded: &str) -> Result<Self> {
        if encoded.is_empty() || encoded.len() > MAX_TEE_LAUNCH_ANNOTATION_BYTES {
            return Err(tee_error(format!(
                "TEE launch annotation must contain between 1 and {MAX_TEE_LAUNCH_ANNOTATION_BYTES} bytes"
            )));
        }
        let request: Self = serde_json::from_str(encoded).map_err(|error| {
            tee_error(format!("TEE launch annotation is invalid JSON: {error}"))
        })?;
        request.validate()?;
        if request.to_annotation_value()?.as_bytes() != encoded.as_bytes() {
            return Err(tee_error("TEE launch annotation is not canonical JSON"));
        }
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != TEE_LAUNCH_SCHEMA_V1 {
            return Err(tee_error(format!(
                "unsupported TEE launch schema {:?}",
                self.schema_version
            )));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TeeLaunchRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TeeLaunchRequestWire::deserialize(deserializer)?;
        let request = Self {
            schema_version: wire.schema_version,
            technology: wire.technology,
            mode: wire.mode,
        };
        request.validate().map_err(de::Error::custom)?;
        Ok(request)
    }
}

/// Exact 64-byte challenge or caller binding copied into a TEE report.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TeeReportData([u8; TEE_REPORT_DATA_BYTES]);

impl TeeReportData {
    #[must_use]
    pub const fn new(bytes: [u8; TEE_REPORT_DATA_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; TEE_REPORT_DATA_BYTES] = bytes.try_into().map_err(|_| {
            tee_error(format!(
                "TEE report data must contain exactly {TEE_REPORT_DATA_BYTES} bytes"
            ))
        })?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TEE_REPORT_DATA_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TeeReportData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TeeReportData")
            .field(&STANDARD.encode(self.0))
            .finish()
    }
}

impl Serialize for TeeReportData {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for TeeReportData {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = STANDARD.decode(&encoded).map_err(de::Error::custom)?;
        let report_data = Self::from_bytes(&decoded).map_err(de::Error::custom)?;
        if STANDARD.encode(report_data.0) != encoded {
            return Err(de::Error::custom("TEE report data is not canonical base64"));
        }
        Ok(report_data)
    }
}

/// Canonical lowercase SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct TeeSha256Digest(String);

impl TeeSha256Digest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "sha256", SHA256_HEX_BYTES, "TEE SHA-256 digest")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TeeSha256Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Canonical lowercase SHA-384 launch measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TeeMeasurement(String);

impl TeeMeasurement {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "sha384", SHA384_HEX_BYTES, "TEE launch measurement")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TeeMeasurement {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Bounded, opaque provider evidence. Runtime does not interpret its claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeeEvidence {
    media_type: String,
    data: String,
    digest: TeeSha256Digest,
    size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeEvidenceWire {
    media_type: String,
    data: String,
    digest: TeeSha256Digest,
    size_bytes: u64,
}

impl TeeEvidence {
    /// Construct immutable evidence from its decoded provider payload.
    pub fn new(media_type: impl Into<String>, data: Vec<u8>) -> Result<Self> {
        if data.is_empty() || data.len() > MAX_TEE_EVIDENCE_BYTES {
            return Err(tee_error(format!(
                "TEE evidence must contain between 1 and {MAX_TEE_EVIDENCE_BYTES} decoded bytes"
            )));
        }
        let evidence = Self {
            media_type: media_type.into(),
            data: STANDARD.encode(&data),
            digest: TeeSha256Digest::for_bytes(&data),
            size_bytes: data.len() as u64,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    #[must_use]
    pub fn data_base64(&self) -> &str {
        &self.data
    }

    pub fn decode(&self) -> Result<Vec<u8>> {
        self.validate()
    }

    #[must_use]
    pub const fn digest(&self) -> &TeeSha256Digest {
        &self.digest
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    fn validate(&self) -> Result<Vec<u8>> {
        validate_media_type(&self.media_type)?;
        let decoded = STANDARD
            .decode(&self.data)
            .map_err(|error| tee_error(format!("TEE evidence is not valid base64: {error}")))?;
        if decoded.is_empty() || decoded.len() > MAX_TEE_EVIDENCE_BYTES {
            return Err(tee_error(format!(
                "TEE evidence must contain between 1 and {MAX_TEE_EVIDENCE_BYTES} decoded bytes"
            )));
        }
        if STANDARD.encode(&decoded) != self.data {
            return Err(tee_error("TEE evidence is not canonical base64"));
        }
        if self.size_bytes != decoded.len() as u64
            || self.digest != TeeSha256Digest::for_bytes(&decoded)
        {
            return Err(tee_error(
                "TEE evidence size or digest does not match its payload",
            ));
        }
        Ok(decoded)
    }
}

impl<'de> Deserialize<'de> for TeeEvidence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TeeEvidenceWire::deserialize(deserializer)?;
        let evidence = Self {
            media_type: wire.media_type,
            data: wire.data,
            digest: wire.digest,
            size_bytes: wire.size_bytes,
        };
        evidence.validate().map_err(de::Error::custom)?;
        Ok(evidence)
    }
}

/// Idempotent attestation request for one exact TEE-backed generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeeAttestationRequest {
    pub context: crate::OperationContext,
    pub target: ContainerTarget,
    pub report_data: TeeReportData,
}

impl TeeAttestationRequest {
    pub fn new(
        context: crate::OperationContext,
        target: ContainerTarget,
        report_data: TeeReportData,
    ) -> Result<Self> {
        let request = Self {
            context,
            target,
            report_data,
        };
        request.validate_contract()?;
        Ok(request)
    }

    pub(crate) fn validate_contract(&self) -> Result<()> {
        require_exact_target(&self.target)
    }
}

/// Driver evidence bound to one exact container generation and host artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TeeAttestationResponse {
    schema_version: String,
    target: ContainerTarget,
    launch: TeeLaunchRequest,
    report_data: TeeReportData,
    config_digest: TeeSha256Digest,
    attachments_digest: TeeSha256Digest,
    driver: DriverKind,
    runtime_artifact: RuntimeArtifact,
    driver_build_digest: TeeSha256Digest,
    measurement: TeeMeasurement,
    evidence: TeeEvidence,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeAttestationResponseWire {
    schema_version: String,
    target: ContainerTarget,
    launch: TeeLaunchRequest,
    report_data: TeeReportData,
    config_digest: TeeSha256Digest,
    attachments_digest: TeeSha256Digest,
    driver: DriverKind,
    runtime_artifact: RuntimeArtifact,
    driver_build_digest: TeeSha256Digest,
    measurement: TeeMeasurement,
    evidence: TeeEvidence,
}

impl TeeAttestationResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target: ContainerTarget,
        launch: TeeLaunchRequest,
        report_data: TeeReportData,
        config_digest: TeeSha256Digest,
        attachments_digest: TeeSha256Digest,
        driver: DriverKind,
        runtime_artifact: RuntimeArtifact,
        driver_build_digest: TeeSha256Digest,
        measurement: TeeMeasurement,
        evidence: TeeEvidence,
    ) -> Result<Self> {
        let response = Self {
            schema_version: TEE_ATTESTATION_SCHEMA_V1.to_string(),
            target,
            launch,
            report_data,
            config_digest,
            attachments_digest,
            driver,
            runtime_artifact,
            driver_build_digest,
            measurement,
            evidence,
        };
        response.validate()?;
        Ok(response)
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    #[must_use]
    pub const fn target(&self) -> &ContainerTarget {
        &self.target
    }
    #[must_use]
    pub const fn launch(&self) -> &TeeLaunchRequest {
        &self.launch
    }
    #[must_use]
    pub const fn report_data(&self) -> &TeeReportData {
        &self.report_data
    }
    #[must_use]
    pub const fn config_digest(&self) -> &TeeSha256Digest {
        &self.config_digest
    }
    #[must_use]
    pub const fn attachments_digest(&self) -> &TeeSha256Digest {
        &self.attachments_digest
    }
    #[must_use]
    pub const fn driver(&self) -> DriverKind {
        self.driver
    }
    #[must_use]
    pub const fn runtime_artifact(&self) -> &RuntimeArtifact {
        &self.runtime_artifact
    }
    #[must_use]
    pub const fn driver_build_digest(&self) -> &TeeSha256Digest {
        &self.driver_build_digest
    }
    #[must_use]
    pub const fn measurement(&self) -> &TeeMeasurement {
        &self.measurement
    }
    #[must_use]
    pub const fn evidence(&self) -> &TeeEvidence {
        &self.evidence
    }

    /// Revalidate exact target and report-data binding for a request replay.
    pub fn validate_for_request(&self, request: &TeeAttestationRequest) -> Result<()> {
        request.validate_contract()?;
        self.validate()?;
        if self.target != request.target || self.report_data != request.report_data {
            return Err(tee_error(
                "TEE attestation response does not match the exact request target and report data",
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != TEE_ATTESTATION_SCHEMA_V1 {
            return Err(tee_error(format!(
                "unsupported TEE attestation schema {:?}",
                self.schema_version
            )));
        }
        require_exact_target(&self.target)?;
        self.launch.validate()?;
        self.runtime_artifact.validate()?;
        self.evidence.validate()?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TeeAttestationResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TeeAttestationResponseWire::deserialize(deserializer)?;
        let response = Self {
            schema_version: wire.schema_version,
            target: wire.target,
            launch: wire.launch,
            report_data: wire.report_data,
            config_digest: wire.config_digest,
            attachments_digest: wire.attachments_digest,
            driver: wire.driver,
            runtime_artifact: wire.runtime_artifact,
            driver_build_digest: wire.driver_build_digest,
            measurement: wire.measurement,
            evidence: wire.evidence,
        };
        response.validate().map_err(de::Error::custom)?;
        Ok(response)
    }
}

fn require_exact_target(target: &ContainerTarget) -> Result<()> {
    let generation = target
        .generation
        .ok_or_else(|| tee_error("TEE attestation requires an exact container generation"))?;
    if generation.0 == 0 {
        return Err(tee_error(
            "TEE attestation generation must be greater than zero",
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, algorithm: &str, hex_bytes: usize, label: &str) -> Result<()> {
    let valid = value
        .strip_prefix(&format!("{algorithm}:"))
        .is_some_and(|hex| {
            hex.len() == hex_bytes
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if valid {
        Ok(())
    } else {
        Err(tee_error(format!(
            "{label} must be a canonical lowercase {algorithm} value"
        )))
    }
}

fn validate_media_type(value: &str) -> Result<()> {
    let valid_components = value.split_once('/').is_some_and(|(kind, subtype)| {
        !kind.is_empty()
            && !subtype.is_empty()
            && !subtype.contains('/')
            && kind.bytes().chain(subtype.bytes()).all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'+' | b'-')
            })
    });
    if value.is_empty()
        || value.len() > MAX_EVIDENCE_MEDIA_TYPE_BYTES
        || !value.is_ascii()
        || !valid_components
    {
        return Err(tee_error(format!(
            "TEE evidence media type must be at most {MAX_EVIDENCE_MEDIA_TYPE_BYTES} bytes of canonical lowercase ASCII"
        )));
    }
    Ok(())
}

fn tee_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-tee-contract")
}

#[cfg(test)]
mod tests;
