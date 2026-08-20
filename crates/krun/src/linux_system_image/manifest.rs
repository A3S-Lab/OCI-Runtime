use a3s_oci_sdk::Result;
use serde::Deserialize;

use super::{
    image_error, AGENT_VERSION, ALPINE_ARCHIVE_SHA256, ALPINE_ARCHIVE_SIZE, ALPINE_URL,
    ALPINE_VERSION, ARCHITECTURE, COMPATIBILITY_LEVEL, DIRECTORY_HASH_SEED, FILESYSTEM,
    FILESYSTEM_LABEL, FILESYSTEM_UUID, IMAGE_NAME, IMAGE_SIZE, SCHEMA_VERSION, SOURCE_DATE_EPOCH,
};
use crate::runtime_assets::RuntimeBundle;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    schema_version: String,
    compatibility_level: String,
    architecture: String,
    pub(super) image: Image,
    pub(super) sources: Sources,
    runtime: RuntimeBundle,
}

impl Manifest {
    pub(super) fn validate(&self, runtime: &RuntimeBundle) -> Result<()> {
        require_equal("schema_version", &self.schema_version, SCHEMA_VERSION)?;
        require_equal(
            "compatibility_level",
            &self.compatibility_level,
            COMPATIBILITY_LEVEL,
        )?;
        require_equal("architecture", &self.architecture, ARCHITECTURE)?;
        self.image.validate()?;
        self.sources.validate()?;
        if &self.runtime != runtime {
            return Err(image_error(
                "manifest runtime bundle does not match the checked-in target bundle".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) sha256: String,
    archive_name: String,
    archive_size: u64,
    archive_sha256: String,
    filesystem: String,
    filesystem_uuid: String,
    filesystem_label: String,
    directory_hash_seed: String,
}

impl Image {
    fn validate(&self) -> Result<()> {
        require_equal("image.name", &self.name, IMAGE_NAME)?;
        require_number("image.size", self.size, IMAGE_SIZE)?;
        require_sha256("image.sha256", &self.sha256)?;
        require_equal(
            "image.archive_name",
            &self.archive_name,
            "a3s-oci-system.ext4.xz",
        )?;
        if self.archive_size == 0 {
            return Err(image_error(
                "manifest image.archive_size must be positive".to_string(),
            ));
        }
        require_sha256("image.archive_sha256", &self.archive_sha256)?;
        require_equal("image.filesystem", &self.filesystem, FILESYSTEM)?;
        require_equal(
            "image.filesystem_uuid",
            &self.filesystem_uuid,
            FILESYSTEM_UUID,
        )?;
        require_equal(
            "image.filesystem_label",
            &self.filesystem_label,
            FILESYSTEM_LABEL,
        )?;
        require_equal(
            "image.directory_hash_seed",
            &self.directory_hash_seed,
            DIRECTORY_HASH_SEED,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sources {
    alpine: AlpineSource,
    pub(super) agent: AgentSource,
    builder: BuilderSource,
}

impl Sources {
    fn validate(&self) -> Result<()> {
        self.alpine.validate()?;
        self.agent.validate()?;
        self.builder.validate()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlpineSource {
    version: String,
    url: String,
    archive_size: u64,
    archive_sha256: String,
}

impl AlpineSource {
    fn validate(&self) -> Result<()> {
        require_equal("sources.alpine.version", &self.version, ALPINE_VERSION)?;
        require_equal("sources.alpine.url", &self.url, ALPINE_URL)?;
        require_number(
            "sources.alpine.archive_size",
            self.archive_size,
            ALPINE_ARCHIVE_SIZE,
        )?;
        require_equal(
            "sources.alpine.archive_sha256",
            &self.archive_sha256,
            ALPINE_ARCHIVE_SHA256,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentSource {
    version: String,
    pub(super) size: u64,
    pub(super) sha256: String,
}

impl AgentSource {
    fn validate(&self) -> Result<()> {
        require_equal("sources.agent.version", &self.version, AGENT_VERSION)?;
        if self.size == 0 {
            return Err(image_error(
                "manifest sources.agent.size must be positive".to_string(),
            ));
        }
        require_sha256("sources.agent.sha256", &self.sha256)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuilderSource {
    source_date_epoch: u64,
    e2fsprogs_version: String,
}

impl BuilderSource {
    fn validate(&self) -> Result<()> {
        require_number(
            "sources.builder.source_date_epoch",
            self.source_date_epoch,
            SOURCE_DATE_EPOCH,
        )?;
        if self.e2fsprogs_version.is_empty()
            || self.e2fsprogs_version.len() > 128
            || self.e2fsprogs_version.chars().any(char::is_control)
        {
            return Err(image_error(
                "manifest sources.builder.e2fsprogs_version is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

pub(super) fn strict_json(bytes: &[u8]) -> Result<Manifest> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest = Manifest::deserialize(&mut deserializer)
        .map_err(|error| image_error(format!("Linux system-image manifest is invalid: {error}")))?;
    deserializer.end().map_err(|error| {
        image_error(format!(
            "Linux system-image manifest contains trailing data: {error}"
        ))
    })?;
    Ok(manifest)
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(image_error(format!(
            "manifest {field} mismatch: expected {expected:?}, found {actual:?}"
        )))
    }
}

fn require_number(field: &str, actual: u64, expected: u64) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(image_error(format!(
            "manifest {field} mismatch: expected {expected}, found {actual}"
        )))
    }
}

fn require_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(image_error(format!(
            "manifest {field} must be a lowercase SHA-256 digest"
        )))
    }
}
