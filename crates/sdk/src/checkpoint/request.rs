use serde::{Deserialize, Serialize};

use super::artifact::CheckpointArtifactPath;
use super::checkpoint_error;
use super::reference::{require_exact_target, CheckpointQuiesce, CheckpointReference};
use crate::{
    ContainerId, ContainerTarget, CreateAttachments, IsolationRequest, OciBundle, OciSemanticPhase,
    OperationContext, Result,
};

/// Create one checkpoint artifact from an exact paused generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRequest {
    context: OperationContext,
    target: ContainerTarget,
    #[serde(alias = "directory")]
    artifact_path: CheckpointArtifactPath,
    #[serde(default)]
    quiesce: CheckpointQuiesce,
    #[serde(default, rename = "leave_running", skip_serializing)]
    legacy_leave_running: Option<bool>,
}

impl CheckpointRequest {
    /// Construct a paused-quiescence request for one exact source generation.
    pub fn new(
        context: OperationContext,
        target: ContainerTarget,
        artifact_path: CheckpointArtifactPath,
    ) -> Result<Self> {
        let request = Self {
            context,
            target,
            artifact_path,
            quiesce: CheckpointQuiesce::Paused,
            legacy_leave_running: None,
        };
        request.validate_contract()?;
        Ok(request)
    }

    #[must_use]
    pub const fn context(&self) -> &OperationContext {
        &self.context
    }

    #[must_use]
    pub const fn target(&self) -> &ContainerTarget {
        &self.target
    }

    #[must_use]
    pub const fn artifact_path(&self) -> &CheckpointArtifactPath {
        &self.artifact_path
    }

    #[must_use]
    pub const fn quiesce(&self) -> CheckpointQuiesce {
        self.quiesce
    }

    pub(crate) fn validate_contract(&self) -> Result<()> {
        require_exact_target(&self.target, "checkpoint request")?;
        if self.legacy_leave_running.is_some() {
            return Err(checkpoint_error(
                "legacy checkpoint leave_running semantics are unsupported; protocol v8 requires paused quiescence",
            ));
        }
        Ok(())
    }
}

/// Restore a paused generation from one exact immutable checkpoint artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    context: OperationContext,
    id: ContainerId,
    bundle: OciBundle,
    #[serde(alias = "checkpoint_directory")]
    artifact_path: CheckpointArtifactPath,
    isolation: IsolationRequest,
    attachments: CreateAttachments,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reference: Option<CheckpointReference>,
}

impl RestoreRequest {
    /// Construct and validate a restore request against one immutable reference.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: OperationContext,
        id: ContainerId,
        bundle: OciBundle,
        artifact_path: CheckpointArtifactPath,
        isolation: IsolationRequest,
        attachments: CreateAttachments,
        reference: CheckpointReference,
    ) -> Result<Self> {
        let request = Self {
            context,
            id,
            bundle,
            artifact_path,
            isolation,
            attachments,
            reference: Some(reference),
        };
        request.validate_contract()?;
        Ok(request)
    }

    #[must_use]
    pub const fn context(&self) -> &OperationContext {
        &self.context
    }

    #[must_use]
    pub const fn id(&self) -> &ContainerId {
        &self.id
    }

    #[must_use]
    pub const fn bundle(&self) -> &OciBundle {
        &self.bundle
    }

    #[must_use]
    pub const fn artifact_path(&self) -> &CheckpointArtifactPath {
        &self.artifact_path
    }

    #[must_use]
    pub const fn isolation(&self) -> &IsolationRequest {
        &self.isolation
    }

    #[must_use]
    pub const fn attachments(&self) -> &CreateAttachments {
        &self.attachments
    }

    /// Borrow the required immutable reference or reject a decoded legacy request.
    pub fn reference(&self) -> Result<&CheckpointReference> {
        self.reference.as_ref().ok_or_else(|| {
            checkpoint_error("restore request has no immutable checkpoint reference")
        })
    }

    pub(crate) fn validate_contract(&self) -> Result<()> {
        self.bundle.validate_for_phase(OciSemanticPhase::Create)?;
        self.attachments.validate(&self.bundle)?;
        self.attachments.validate_isolation(&self.isolation)?;
        match self.bundle.spec().process().as_ref() {
            Some(process) => self
                .attachments
                .process_io()
                .resolve_for_process(process)
                .map(|_| ())?,
            None => crate::process_io::validate_without_process(self.attachments.process_io())?,
        }
        let reference = self.reference()?;
        reference.validate()?;
        if self.bundle.config_digest() != reference.source_config_digest().as_str() {
            return Err(checkpoint_error(
                "restore bundle digest does not match the immutable checkpoint source",
            ));
        }
        if self.isolation.class() != reference.compatibility().isolation() {
            return Err(checkpoint_error(
                "restore isolation does not match the immutable checkpoint reference",
            ));
        }
        Ok(())
    }
}
