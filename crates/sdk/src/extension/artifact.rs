use serde::{Deserialize, Serialize};

use super::{negotiation_input_error, validate_bounded_text};
use crate::Result;

const MAX_ARTIFACT_NAME_BYTES: usize = 255;
const MAX_ARTIFACT_VERSION_BYTES: usize = 128;
const MAX_SOURCE_REVISION_BYTES: usize = 128;
const SHA256_HEX_BYTES: usize = 64;

/// Identity of the exact host executable that emitted a capability catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArtifact {
    name: String,
    version: String,
    digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_revision: Option<String>,
}

impl RuntimeArtifact {
    /// Construct and validate an exact executable identity.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        digest: impl Into<String>,
        source_revision: Option<String>,
    ) -> Result<Self> {
        let artifact = Self {
            name: name.into(),
            version: version.into(),
            digest: digest.into(),
            source_revision,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Runtime component name compiled into the host service.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runtime package version compiled into the host service.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Lowercase SHA-256 digest of the host executable.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Optional source revision injected by the release build.
    #[must_use]
    pub fn source_revision(&self) -> Option<&str> {
        self.source_revision.as_deref()
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_bounded_text(&self.name, "runtime artifact name", MAX_ARTIFACT_NAME_BYTES)?;
        validate_bounded_text(
            &self.version,
            "runtime artifact version",
            MAX_ARTIFACT_VERSION_BYTES,
        )?;
        semver::Version::parse(&self.version).map_err(|error| {
            negotiation_input_error(format!(
                "runtime artifact version is not semantic versioning: {error}"
            ))
        })?;
        validate_sha256(&self.digest)?;
        if let Some(revision) = &self.source_revision {
            validate_bounded_text(
                revision,
                "runtime artifact source revision",
                MAX_SOURCE_REVISION_BYTES,
            )?;
        }
        Ok(())
    }
}

fn validate_sha256(digest: &str) -> Result<()> {
    let valid = digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == SHA256_HEX_BYTES
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if valid {
        Ok(())
    } else {
        Err(negotiation_input_error(
            "runtime artifact digest must be a canonical lowercase SHA-256",
        ))
    }
}
