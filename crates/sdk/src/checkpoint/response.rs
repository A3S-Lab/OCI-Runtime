use serde::{de, Deserialize, Deserializer, Serialize};

use super::artifact::CheckpointDigest;
use super::checkpoint_error;
use super::reference::{exact_record_target, require_paused_running, CheckpointReference};
use super::request::{CheckpointRequest, RestoreRequest};
use crate::{ContainerRecord, Result};

/// Successful checkpoint result retaining the unchanged paused source and its reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointResponse {
    source: ContainerRecord,
    reference: CheckpointReference,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointResponseWire {
    source: ContainerRecord,
    reference: CheckpointReference,
}

impl CheckpointResponse {
    /// Bind an unchanged paused source record to its immutable reference.
    pub fn new(source: ContainerRecord, reference: CheckpointReference) -> Result<Self> {
        validate_checkpoint_source(&source, &reference)?;
        Ok(Self { source, reference })
    }

    #[must_use]
    pub const fn source(&self) -> &ContainerRecord {
        &self.source
    }

    #[must_use]
    pub const fn reference(&self) -> &CheckpointReference {
        &self.reference
    }

    #[must_use]
    pub fn into_parts(self) -> (ContainerRecord, CheckpointReference) {
        (self.source, self.reference)
    }

    pub(crate) fn validate_for_request(&self, request: &CheckpointRequest) -> Result<()> {
        request.validate_contract()?;
        if &exact_record_target(&self.source)? != request.target()
            || self.reference.quiesce() != request.quiesce()
        {
            return Err(checkpoint_error(
                "checkpoint response does not match the exact request target and quiescence",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CheckpointResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CheckpointResponseWire::deserialize(deserializer)?;
        Self::new(wire.source, wire.reference).map_err(de::Error::custom)
    }
}

/// Successful restore result. Version 1 always returns a paused running generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreResponse {
    restored: ContainerRecord,
    reference: CheckpointReference,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RestoreResponseWire {
    restored: ContainerRecord,
    reference: CheckpointReference,
}

impl RestoreResponse {
    /// Bind a newly restored paused generation to the consumed reference.
    pub fn new(restored: ContainerRecord, reference: CheckpointReference) -> Result<Self> {
        validate_restored_record(&restored, &reference)?;
        Ok(Self {
            restored,
            reference,
        })
    }

    #[must_use]
    pub const fn restored(&self) -> &ContainerRecord {
        &self.restored
    }

    #[must_use]
    pub const fn reference(&self) -> &CheckpointReference {
        &self.reference
    }

    #[must_use]
    pub fn into_parts(self) -> (ContainerRecord, CheckpointReference) {
        (self.restored, self.reference)
    }

    pub(crate) fn validate_for_request(&self, request: &RestoreRequest) -> Result<()> {
        request.validate_contract()?;
        let expected_attachments = request.attachments().digest()?;
        if self.reference != *request.reference()?
            || self.restored.state.id() != request.id().as_str()
            || self.restored.state.bundle() != request.bundle().directory()
            || self.restored.attachments_digest.as_deref() != Some(expected_attachments.as_str())
        {
            return Err(checkpoint_error(
                "restore response does not match the requested reference, ID, bundle, and attachments",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RestoreResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RestoreResponseWire::deserialize(deserializer)?;
        Self::new(wire.restored, wire.reference).map_err(de::Error::custom)
    }
}

fn validate_checkpoint_source(
    source: &ContainerRecord,
    reference: &CheckpointReference,
) -> Result<()> {
    reference.validate()?;
    require_paused_running(source, "checkpoint source")?;
    if &exact_record_target(source)? != reference.source()
        || source.config_digest != reference.source_config_digest().as_str()
        || source.attachments_digest.as_deref()
            != Some(reference.source_attachments_digest().as_str())
        || source.driver != reference.compatibility().driver()
        || source.isolation != reference.compatibility().isolation()
    {
        return Err(checkpoint_error(
            "checkpoint reference does not match its exact paused source record",
        ));
    }
    Ok(())
}

fn validate_restored_record(
    restored: &ContainerRecord,
    reference: &CheckpointReference,
) -> Result<()> {
    reference.validate()?;
    require_paused_running(restored, "checkpoint restore result")?;
    let restored_target = exact_record_target(restored)?;
    if restored_target.id == reference.source().id
        && restored_target.generation <= reference.source().generation
    {
        return Err(checkpoint_error(
            "checkpoint restore must create a generation newer than its same-ID source",
        ));
    }
    let restored_attachments = restored.attachments_digest.as_deref().ok_or_else(|| {
        checkpoint_error("checkpoint restore result has no attachment-manifest digest")
    })?;
    CheckpointDigest::new(restored_attachments.to_string())?;
    if restored.config_digest != reference.source_config_digest().as_str()
        || restored.driver != reference.compatibility().driver()
        || restored.isolation != reference.compatibility().isolation()
    {
        return Err(checkpoint_error(
            "restored record does not match immutable checkpoint compatibility evidence",
        ));
    }
    Ok(())
}
