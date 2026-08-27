use std::collections::BTreeSet;
use std::fmt;

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::{
    invalid_attachment, AttachmentSource, ConfigurationAttachment, NetworkAttachment,
    NetworkCleanup, RuntimeExtensionAttachment,
};
use crate::{NetworkEnforcementId, NetworkNamespaceId, NetworkRedirectId, Result};

/// Required extension carrying one opaque, pre-authorized network mechanism.
pub const NETWORK_ENFORCEMENT_EXTENSION: &str = "dev.a3s.network.enforcement";
/// First network-enforcement extension contract version.
pub const NETWORK_ENFORCEMENT_EXTENSION_VERSION: u16 = 1;
/// Typed annotation schema understood by extension version 1.
pub const NETWORK_ENFORCEMENT_SCHEMA_V1: &str = "a3s.oci.network-enforcement.v1";

const MAX_NETWORK_ENFORCEMENT_ANNOTATION_BYTES: usize = 16 * 1024;

/// Positive incarnation shared by one compiled enforcement or redirect mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct NetworkMechanismGeneration(u64);

impl NetworkMechanismGeneration {
    /// Construct a positive mechanism-generation fence.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            return Err(invalid_attachment(
                "network mechanism generation must be greater than zero",
            ));
        }
        Ok(Self(value))
    }

    /// Numeric generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for NetworkMechanismGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for NetworkMechanismGeneration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Lowercase SHA-256 identity of caller-compiled mechanism evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct NetworkMechanismDigest(String);

impl NetworkMechanismDigest {
    /// Validate one exact `sha256:<lowercase-hex>` digest.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(invalid_attachment(
                "network mechanism digest must use the sha256 algorithm",
            ));
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(invalid_attachment(
                "network mechanism digest must contain 64 lowercase hexadecimal digits",
            ));
        }
        Ok(Self(value))
    }

    /// Borrow the canonical digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkMechanismDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NetworkMechanismDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Authority retaining the compiled network mechanism and policy contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkEnforcementOwnership {
    /// The caller retains policy compilation, mutation, and backing-resource authority.
    Caller,
}

/// Cleanup permitted for a caller-owned enforcement or redirect mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkEnforcementCleanup {
    /// Leave the caller-owned namespace mechanism intact after container detach.
    PreserveCallerMechanism,
}

/// Optional caller-owned node-local redirect already installed in the namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalNetworkRedirectAttachment {
    identity: NetworkRedirectId,
    generation: NetworkMechanismGeneration,
    mechanism_digest: NetworkMechanismDigest,
    ownership: NetworkEnforcementOwnership,
    cleanup: NetworkEnforcementCleanup,
}

impl LocalNetworkRedirectAttachment {
    /// Bind one opaque local redirect incarnation without carrying endpoints or policy.
    #[must_use]
    pub const fn new(
        identity: NetworkRedirectId,
        generation: NetworkMechanismGeneration,
        mechanism_digest: NetworkMechanismDigest,
    ) -> Self {
        Self {
            identity,
            generation,
            mechanism_digest,
            ownership: NetworkEnforcementOwnership::Caller,
            cleanup: NetworkEnforcementCleanup::PreserveCallerMechanism,
        }
    }

    /// Caller-issued redirect allocation identity.
    #[must_use]
    pub const fn identity(&self) -> &NetworkRedirectId {
        &self.identity
    }

    /// Exact redirect incarnation.
    #[must_use]
    pub const fn generation(&self) -> NetworkMechanismGeneration {
        self.generation
    }

    /// Opaque digest of the caller-compiled redirect mechanism.
    #[must_use]
    pub const fn mechanism_digest(&self) -> &NetworkMechanismDigest {
        &self.mechanism_digest
    }

    /// Authority retaining redirect configuration and resources.
    #[must_use]
    pub const fn ownership(&self) -> NetworkEnforcementOwnership {
        self.ownership
    }

    /// Cleanup boundary for the caller-owned redirect.
    #[must_use]
    pub const fn cleanup(&self) -> NetworkEnforcementCleanup {
        self.cleanup
    }
}

/// Opaque compiled-policy identity bound to one exact caller-owned network namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEnforcementAttachment {
    schema_version: String,
    identity: NetworkEnforcementId,
    generation: NetworkMechanismGeneration,
    compiled_policy_digest: NetworkMechanismDigest,
    namespace: NetworkNamespaceId,
    ownership: NetworkEnforcementOwnership,
    cleanup: NetworkEnforcementCleanup,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_redirect: Option<LocalNetworkRedirectAttachment>,
}

impl NetworkEnforcementAttachment {
    /// Construct one policy-neutral enforcement attachment.
    #[must_use]
    pub fn new(
        identity: NetworkEnforcementId,
        generation: NetworkMechanismGeneration,
        compiled_policy_digest: NetworkMechanismDigest,
        namespace: NetworkNamespaceId,
        local_redirect: Option<LocalNetworkRedirectAttachment>,
    ) -> Self {
        Self {
            schema_version: NETWORK_ENFORCEMENT_SCHEMA_V1.to_string(),
            identity,
            generation,
            compiled_policy_digest,
            namespace,
            ownership: NetworkEnforcementOwnership::Caller,
            cleanup: NetworkEnforcementCleanup::PreserveCallerMechanism,
            local_redirect,
        }
    }

    /// Encode the bounded annotation value expected by the public extension.
    pub fn to_annotation_value(&self) -> Result<String> {
        self.validate_shape()?;
        let encoded = serde_json::to_string(self).map_err(|error| {
            invalid_attachment(format!(
                "failed to encode network enforcement attachment: {error}"
            ))
        })?;
        if encoded.len() > MAX_NETWORK_ENFORCEMENT_ANNOTATION_BYTES {
            return Err(invalid_attachment(
                "network enforcement annotation exceeds its bounded size",
            ));
        }
        Ok(encoded)
    }

    /// Decode and validate one annotation value without interpreting policy contents.
    pub fn from_annotation_value(encoded: &str) -> Result<Self> {
        if encoded.is_empty() || encoded.len() > MAX_NETWORK_ENFORCEMENT_ANNOTATION_BYTES {
            return Err(invalid_attachment(
                "network enforcement annotation is empty or exceeds its bounded size",
            ));
        }
        let attachment: Self = serde_json::from_str(encoded).map_err(|error| {
            invalid_attachment(format!(
                "failed to decode network enforcement attachment: {error}"
            ))
        })?;
        attachment.validate_shape()?;
        if attachment.to_annotation_value()? != encoded {
            return Err(invalid_attachment(
                "network enforcement annotation must use the canonical SDK encoding",
            ));
        }
        Ok(attachment)
    }

    /// Extension configuration schema.
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Caller-issued enforcement allocation identity.
    #[must_use]
    pub const fn identity(&self) -> &NetworkEnforcementId {
        &self.identity
    }

    /// Exact compiled-policy incarnation.
    #[must_use]
    pub const fn generation(&self) -> NetworkMechanismGeneration {
        self.generation
    }

    /// Opaque digest of the caller-compiled policy artifact.
    #[must_use]
    pub const fn compiled_policy_digest(&self) -> &NetworkMechanismDigest {
        &self.compiled_policy_digest
    }

    /// Caller-issued namespace identity already bound by attachment schema v3.
    #[must_use]
    pub const fn namespace(&self) -> &NetworkNamespaceId {
        &self.namespace
    }

    /// Authority retaining policy and namespace mechanism ownership.
    #[must_use]
    pub const fn ownership(&self) -> NetworkEnforcementOwnership {
        self.ownership
    }

    /// Cleanup boundary for the caller-owned mechanism.
    #[must_use]
    pub const fn cleanup(&self) -> NetworkEnforcementCleanup {
        self.cleanup
    }

    /// Optional caller-owned local redirect bound to this policy incarnation.
    #[must_use]
    pub const fn local_redirect(&self) -> Option<&LocalNetworkRedirectAttachment> {
        self.local_redirect.as_ref()
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != NETWORK_ENFORCEMENT_SCHEMA_V1 {
            return Err(invalid_attachment(format!(
                "unsupported network enforcement schema {}",
                self.schema_version
            )));
        }
        Ok(())
    }

    pub(super) fn validate_bindings(
        &self,
        attachments: &[NetworkAttachment],
        network_sources: &[AttachmentSource],
    ) -> Result<()> {
        self.validate_shape()?;
        if attachments.is_empty() {
            return Err(invalid_attachment(
                "network enforcement requires an authorized Linux network attachment",
            ));
        }
        if attachments.iter().any(|attachment| {
            attachment.identity().namespace() != &self.namespace
                || attachment.cleanup() != NetworkCleanup::PreserveCallerNamespace
        }) {
            return Err(invalid_attachment(format!(
                "network enforcement {} must bind every interface to joined caller-owned namespace {}",
                self.identity, self.namespace
            )));
        }

        let configured = network_sources
            .iter()
            .filter_map(|source| match source {
                AttachmentSource::OciConfiguration { configuration } => Some(configuration),
                AttachmentSource::RuntimeExtension { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        let covered = attachments
            .iter()
            .flat_map(|attachment| [attachment.namespace(), attachment.interface()])
            .collect::<BTreeSet<&ConfigurationAttachment>>();
        if configured != covered {
            return Err(invalid_attachment(
                "network enforcement requires every OCI network namespace and interface to be explicitly authorized",
            ));
        }
        Ok(())
    }
}

pub(super) fn decode_extension(
    extensions: &std::collections::BTreeMap<String, RuntimeExtensionAttachment>,
    network_sources: &[AttachmentSource],
    secret_sources: &[AttachmentSource],
    attachments: &[NetworkAttachment],
    configuration: &Value,
) -> Result<Option<NetworkEnforcementAttachment>> {
    let Some(extension) = extensions.get(NETWORK_ENFORCEMENT_EXTENSION) else {
        return Ok(None);
    };
    if extension.version != NETWORK_ENFORCEMENT_EXTENSION_VERSION || !extension.required {
        return Err(invalid_attachment(format!(
            "network enforcement must be required extension version {NETWORK_ENFORCEMENT_EXTENSION_VERSION}"
        )));
    }
    let classified_as_network = network_sources.iter().any(|source| {
        matches!(
            source,
            AttachmentSource::RuntimeExtension { name }
                if name == NETWORK_ENFORCEMENT_EXTENSION
        )
    });
    let classified_as_secret = secret_sources.iter().any(|source| {
        matches!(
            source,
            AttachmentSource::RuntimeExtension { name }
                if name == NETWORK_ENFORCEMENT_EXTENSION
        )
    });
    if !classified_as_network || classified_as_secret {
        return Err(invalid_attachment(
            "network enforcement must be classified only as a network mechanism",
        ));
    }
    let encoded = configuration
        .pointer(&format!("/annotations/{NETWORK_ENFORCEMENT_EXTENSION}"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_attachment(
                "network enforcement extension annotation must contain a JSON string",
            )
        })?;
    let attachment = NetworkEnforcementAttachment::from_annotation_value(encoded)?;
    attachment.validate_bindings(attachments, network_sources)?;
    Ok(Some(attachment))
}
