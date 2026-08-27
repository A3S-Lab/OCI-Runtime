use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{de, Deserialize, Deserializer, Serialize};

use super::{
    checkpoint_error, validate_token, MAX_CHECKPOINT_ARTIFACT_PATH_BYTES,
    MAX_CHECKPOINT_FORMAT_NAME_BYTES,
};
use crate::Result;

/// Canonical SHA-256 identity used by checkpoint content and compatibility evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CheckpointDigest(String);

impl CheckpointDigest {
    /// Validate one exact `sha256:<lowercase-hex>` identity.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if !valid {
            return Err(checkpoint_error(
                "checkpoint digest must be a canonical lowercase SHA-256",
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

impl fmt::Display for CheckpointDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CheckpointDigest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Exact already-authorized local file used to exchange one immutable artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct CheckpointArtifactPath(PathBuf);

impl CheckpointArtifactPath {
    /// Validate an absolute, normalized UTF-8 file path.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        validate_artifact_path(&path)?;
        Ok(Self(path))
    }

    /// Borrow the authorized artifact path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Consume the wrapper and return the path.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for CheckpointArtifactPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl<'de> Deserialize<'de> for CheckpointArtifactPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path = PathBuf::deserialize(deserializer)?;
        Self::new(path).map_err(de::Error::custom)
    }
}

/// Driver-owned checkpoint encoding and its public contract version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointFormat {
    name: String,
    version: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointFormatWire {
    name: String,
    version: u16,
}

impl CheckpointFormat {
    /// Construct one bounded format identity with a positive version.
    pub fn new(name: impl Into<String>, version: u16) -> Result<Self> {
        let format = Self {
            name: name.into(),
            version,
        };
        format.validate()?;
        Ok(format)
    }

    /// Driver-defined format name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Positive driver-defined format version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    pub(super) fn validate(&self) -> Result<()> {
        validate_token(
            &self.name,
            "checkpoint format name",
            MAX_CHECKPOINT_FORMAT_NAME_BYTES,
        )?;
        if self.version == 0 {
            return Err(checkpoint_error(
                "checkpoint format version must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CheckpointFormat {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CheckpointFormatWire::deserialize(deserializer)?;
        Self::new(wire.name, wire.version).map_err(de::Error::custom)
    }
}

fn validate_artifact_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(checkpoint_error(format!(
            "checkpoint artifact path must be absolute: {}",
            path.display()
        )));
    }
    let path_text = path.to_str().ok_or_else(|| {
        checkpoint_error("checkpoint artifact path must be valid UTF-8 for SDK transport")
    })?;
    if path_text.is_empty()
        || path_text.len() > MAX_CHECKPOINT_ARTIFACT_PATH_BYTES
        || path_text.as_bytes().contains(&0)
    {
        return Err(checkpoint_error(format!(
            "checkpoint artifact path must contain 1 through {MAX_CHECKPOINT_ARTIFACT_PATH_BYTES} non-NUL UTF-8 bytes"
        )));
    }
    let normalized = path.components().collect::<PathBuf>();
    if normalized.as_os_str() != path.as_os_str()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(checkpoint_error(
            "checkpoint artifact path must name one normalized file",
        ));
    }
    Ok(())
}
