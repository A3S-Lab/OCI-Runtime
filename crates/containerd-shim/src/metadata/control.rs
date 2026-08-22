use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use a3s_oci_sdk::{canonical_json_bytes, Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{metadata_error, validate_sha256_digest, CONTROL_RESOURCES_SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ControlOperationKind {
    Pause,
    Resume,
    Update,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingControlOperation {
    sequence: u64,
    kind: ControlOperationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resources: Option<LinuxResources>,
}

impl PendingControlOperation {
    pub(crate) fn new(
        sequence: u64,
        kind: ControlOperationKind,
        request_digest: Option<String>,
        resources: Option<LinuxResources>,
    ) -> Result<Self> {
        let operation = Self {
            sequence,
            kind,
            request_digest,
            resources,
        };
        operation.validate_for_schema(CONTROL_RESOURCES_SCHEMA_VERSION)?;
        Ok(operation)
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn kind(&self) -> ControlOperationKind {
        self.kind
    }

    pub(crate) fn request_digest(&self) -> Option<&str> {
        self.request_digest.as_deref()
    }

    pub(crate) fn resources(&self) -> Option<&LinuxResources> {
        self.resources.as_ref()
    }

    pub(crate) fn with_update_resources(&self, resources: LinuxResources) -> Result<Self> {
        if self.kind != ControlOperationKind::Update {
            return Err(metadata_error(
                "Pause and Resume control operations must not record Linux resources",
            ));
        }
        let mut operation = self.clone();
        operation.resources = Some(resources);
        operation.validate_for_schema(CONTROL_RESOURCES_SCHEMA_VERSION)?;
        Ok(operation)
    }

    pub(super) fn validate_for_schema(&self, schema_version: u32) -> Result<()> {
        if self.sequence == 0 {
            return Err(metadata_error(
                "pending containerd control operation records sequence zero",
            ));
        }
        match self.kind {
            ControlOperationKind::Pause | ControlOperationKind::Resume => {
                if self.request_digest.is_some() {
                    return Err(metadata_error(
                        "Pause and Resume control operations must not record a request digest",
                    ));
                }
                if self.resources.is_some() {
                    return Err(metadata_error(
                        "Pause and Resume control operations must not record Linux resources",
                    ));
                }
            }
            ControlOperationKind::Update => {
                let digest = self.request_digest.as_deref().ok_or_else(|| {
                    metadata_error("pending Update control operation omitted its request digest")
                })?;
                validate_sha256_digest(digest, "pending Update request")?;
                if let Some(resources) = &self.resources {
                    let actual = update_request_digest(resources)?;
                    if actual != digest {
                        return Err(metadata_error(format!(
                            "pending Update resources digest {actual} does not match recorded request digest {digest}"
                        )));
                    }
                }
            }
        }
        if schema_version < CONTROL_RESOURCES_SCHEMA_VERSION && self.resources.is_some() {
            return Err(metadata_error(format!(
                "shim metadata schema {schema_version} cannot contain schema-v{CONTROL_RESOURCES_SCHEMA_VERSION} pending Update resources"
            )));
        }
        if schema_version >= CONTROL_RESOURCES_SCHEMA_VERSION
            && self.kind == ControlOperationKind::Update
            && self.resources.is_none()
        {
            return Err(metadata_error(format!(
                "shim metadata schema {schema_version} pending Update omitted its Linux resources"
            )));
        }
        Ok(())
    }
}

pub(crate) fn update_request_digest(resources: &LinuxResources) -> Result<String> {
    let encoded = canonical_json_bytes(resources).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to encode containerd Update resources: {error}"),
        )
        .for_operation("containerd-update-digest")
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
}
