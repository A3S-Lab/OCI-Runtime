use a3s_oci_core::{DriverKind, HostPlatform, IsolationClass};
use oci_spec::runtime::ContainerState;
use serde::{de, Deserialize, Deserializer, Serialize};

use super::artifact::{CheckpointDigest, CheckpointFormat};
use super::{
    checkpoint_error, validate_token, CHECKPOINT_REFERENCE_SCHEMA_V1,
    MAX_CHECKPOINT_ARCHITECTURE_BYTES,
};
use crate::{ContainerId, ContainerRecord, ContainerTarget, Result, RuntimeArtifact};

/// Quiescence guaranteed by the first checkpoint contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointQuiesce {
    /// Capture only an already-paused running generation, leave the source
    /// paused, and restore a new generation in the paused state.
    #[default]
    Paused,
}

/// Exact execution stack required to consume one checkpoint artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointCompatibility {
    driver: DriverKind,
    isolation: IsolationClass,
    platform: HostPlatform,
    architecture: String,
    runtime_artifact: RuntimeArtifact,
    driver_build_digest: CheckpointDigest,
    format: CheckpointFormat,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointCompatibilityWire {
    driver: DriverKind,
    isolation: IsolationClass,
    platform: HostPlatform,
    architecture: String,
    runtime_artifact: RuntimeArtifact,
    driver_build_digest: CheckpointDigest,
    format: CheckpointFormat,
}

impl CheckpointCompatibility {
    /// Bind a checkpoint to one driver, platform, architecture, Host build,
    /// driver-stack build, and encoding.
    pub fn new(
        driver: DriverKind,
        isolation: IsolationClass,
        platform: HostPlatform,
        architecture: impl Into<String>,
        runtime_artifact: RuntimeArtifact,
        driver_build_digest: CheckpointDigest,
        format: CheckpointFormat,
    ) -> Result<Self> {
        let compatibility = Self {
            driver,
            isolation,
            platform,
            architecture: architecture.into(),
            runtime_artifact,
            driver_build_digest,
            format,
        };
        compatibility.validate()?;
        Ok(compatibility)
    }

    #[must_use]
    pub const fn driver(&self) -> DriverKind {
        self.driver
    }

    #[must_use]
    pub const fn isolation(&self) -> IsolationClass {
        self.isolation
    }

    #[must_use]
    pub const fn platform(&self) -> HostPlatform {
        self.platform
    }

    #[must_use]
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    #[must_use]
    pub const fn runtime_artifact(&self) -> &RuntimeArtifact {
        &self.runtime_artifact
    }

    #[must_use]
    pub const fn driver_build_digest(&self) -> &CheckpointDigest {
        &self.driver_build_digest
    }

    #[must_use]
    pub const fn format(&self) -> &CheckpointFormat {
        &self.format
    }

    pub(super) fn validate(&self) -> Result<()> {
        let expected_platform = match self.driver {
            DriverKind::NativeLinux | DriverKind::LibkrunKvm => HostPlatform::Linux,
            DriverKind::LibkrunHvf => HostPlatform::Macos,
            DriverKind::LibkrunWhpx => HostPlatform::Windows,
        };
        if self.platform != expected_platform {
            return Err(checkpoint_error(format!(
                "checkpoint driver {:?} requires platform {expected_platform:?}, not {:?}",
                self.driver, self.platform
            )));
        }
        if (self.driver == DriverKind::NativeLinux
            && self.isolation != IsolationClass::SharedHostKernel)
            || (self.driver != DriverKind::NativeLinux
                && self.isolation == IsolationClass::SharedHostKernel)
        {
            return Err(checkpoint_error(format!(
                "checkpoint driver {:?} is incompatible with isolation {:?}",
                self.driver, self.isolation
            )));
        }
        validate_token(
            &self.architecture,
            "checkpoint architecture",
            MAX_CHECKPOINT_ARCHITECTURE_BYTES,
        )?;
        self.runtime_artifact.validate()?;
        self.format.validate()
    }
}

impl<'de> Deserialize<'de> for CheckpointCompatibility {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CheckpointCompatibilityWire::deserialize(deserializer)?;
        Self::new(
            wire.driver,
            wire.isolation,
            wire.platform,
            wire.architecture,
            wire.runtime_artifact,
            wire.driver_build_digest,
            wire.format,
        )
        .map_err(de::Error::custom)
    }
}

/// Immutable, content-addressed evidence for one quiesced checkpoint artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointReference {
    schema_version: String,
    source: ContainerTarget,
    source_config_digest: CheckpointDigest,
    source_attachments_digest: CheckpointDigest,
    compatibility: CheckpointCompatibility,
    quiesce: CheckpointQuiesce,
    artifact_digest: CheckpointDigest,
    artifact_size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointReferenceWire {
    schema_version: String,
    source: ContainerTarget,
    source_config_digest: CheckpointDigest,
    source_attachments_digest: CheckpointDigest,
    compatibility: CheckpointCompatibility,
    quiesce: CheckpointQuiesce,
    artifact_digest: CheckpointDigest,
    artifact_size_bytes: u64,
}

impl CheckpointReference {
    /// Construct a reference from the exact paused source record and immutable
    /// artifact evidence returned by the selected driver.
    pub fn new(
        source: &ContainerRecord,
        compatibility: CheckpointCompatibility,
        artifact_digest: CheckpointDigest,
        artifact_size_bytes: u64,
    ) -> Result<Self> {
        require_paused_running(source, "checkpoint source")?;
        if source.driver != compatibility.driver() || source.isolation != compatibility.isolation()
        {
            return Err(checkpoint_error(
                "checkpoint compatibility does not match the paused source record",
            ));
        }
        let reference = Self {
            schema_version: CHECKPOINT_REFERENCE_SCHEMA_V1.to_string(),
            source: exact_record_target(source)?,
            source_config_digest: CheckpointDigest::new(source.config_digest.clone())?,
            source_attachments_digest: CheckpointDigest::new(
                source.attachments_digest.clone().ok_or_else(|| {
                    checkpoint_error("checkpoint source has no attachment-manifest digest")
                })?,
            )?,
            compatibility,
            quiesce: CheckpointQuiesce::Paused,
            artifact_digest,
            artifact_size_bytes,
        };
        reference.validate()?;
        Ok(reference)
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub const fn source(&self) -> &ContainerTarget {
        &self.source
    }

    #[must_use]
    pub const fn source_config_digest(&self) -> &CheckpointDigest {
        &self.source_config_digest
    }

    #[must_use]
    pub const fn source_attachments_digest(&self) -> &CheckpointDigest {
        &self.source_attachments_digest
    }

    #[must_use]
    pub const fn compatibility(&self) -> &CheckpointCompatibility {
        &self.compatibility
    }

    #[must_use]
    pub const fn quiesce(&self) -> CheckpointQuiesce {
        self.quiesce
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> &CheckpointDigest {
        &self.artifact_digest
    }

    #[must_use]
    pub const fn artifact_size_bytes(&self) -> u64 {
        self.artifact_size_bytes
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != CHECKPOINT_REFERENCE_SCHEMA_V1 {
            return Err(checkpoint_error(format!(
                "unsupported checkpoint reference schema {:?}",
                self.schema_version
            )));
        }
        require_exact_target(&self.source, "checkpoint reference source")?;
        self.compatibility.validate()?;
        if self.artifact_size_bytes == 0 {
            return Err(checkpoint_error(
                "checkpoint artifact size must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CheckpointReference {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CheckpointReferenceWire::deserialize(deserializer)?;
        let reference = Self {
            schema_version: wire.schema_version,
            source: wire.source,
            source_config_digest: wire.source_config_digest,
            source_attachments_digest: wire.source_attachments_digest,
            compatibility: wire.compatibility,
            quiesce: wire.quiesce,
            artifact_digest: wire.artifact_digest,
            artifact_size_bytes: wire.artifact_size_bytes,
        };
        reference.validate().map_err(de::Error::custom)?;
        Ok(reference)
    }
}

pub(super) fn exact_record_target(record: &ContainerRecord) -> Result<ContainerTarget> {
    if record.generation.0 == 0 {
        return Err(checkpoint_error(
            "checkpoint container generation must be greater than zero",
        ));
    }
    let id = ContainerId::new(record.state.id().to_string()).map_err(|error| {
        checkpoint_error(format!(
            "checkpoint container state has an invalid ID: {}",
            error.message
        ))
    })?;
    Ok(ContainerTarget::exact(id, record.generation))
}

pub(super) fn require_paused_running(record: &ContainerRecord, label: &str) -> Result<()> {
    if *record.state.status() != ContainerState::Running || !record.is_paused() {
        return Err(checkpoint_error(format!(
            "{label} must be a paused running container generation"
        )));
    }
    Ok(())
}

pub(super) fn require_exact_target(target: &ContainerTarget, label: &str) -> Result<()> {
    let generation = target
        .generation
        .ok_or_else(|| checkpoint_error(format!("{label} requires an exact generation")))?;
    if generation.0 == 0 {
        return Err(checkpoint_error(format!(
            "{label} generation must be greater than zero"
        )));
    }
    Ok(())
}
