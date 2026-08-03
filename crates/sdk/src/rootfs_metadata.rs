//! Portable guest-side rootfs metadata replay contract.

use serde::{Deserialize, Serialize};

/// Annotation requesting guest-side replay of a portable metadata manifest.
pub const PORTABLE_ROOTFS_METADATA_ANNOTATION: &str = "dev.a3s.oci.rootfs-metadata";
/// Current portable rootfs metadata schema and annotation value.
pub const PORTABLE_ROOTFS_METADATA_SCHEMA_V1: &str = "a3s.oci.rootfs-metadata.v1";
/// Fixed manifest file carried inside a prepared relative rootfs.
pub const PORTABLE_ROOTFS_METADATA_FILE: &str = ".a3s-oci-rootfs-metadata.v1.json";
/// Maximum encoded portable rootfs metadata accepted by the guest executor.
pub const PORTABLE_ROOTFS_METADATA_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum number of entries accepted in one portable rootfs metadata manifest.
pub const PORTABLE_ROOTFS_METADATA_MAX_ENTRIES: usize = 250_000;

/// Filesystem entry kinds supported by portable metadata replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableRootfsEntryKind {
    Directory,
    Regular,
    Symlink,
}

/// One guest-visible filesystem entry with a base64-encoded raw Linux path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRootfsMetadataEntry {
    pub path_base64: String,
    pub kind: PortableRootfsEntryKind,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target_base64: Option<String>,
}

/// Complete portable metadata snapshot consumed before OCI mount setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRootfsMetadataManifest {
    pub schema: String,
    pub entries: Vec<PortableRootfsMetadataEntry>,
}

impl PortableRootfsMetadataManifest {
    /// Construct a manifest using the current schema.
    #[must_use]
    pub fn new(entries: Vec<PortableRootfsMetadataEntry>) -> Self {
        Self {
            schema: PORTABLE_ROOTFS_METADATA_SCHEMA_V1.to_string(),
            entries,
        }
    }

    /// Validate schema identity and the public entry-count bound.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.schema != PORTABLE_ROOTFS_METADATA_SCHEMA_V1 {
            return Err(format!(
                "unsupported portable rootfs metadata schema: {}",
                self.schema
            ));
        }
        if self.entries.len() > PORTABLE_ROOTFS_METADATA_MAX_ENTRIES {
            return Err(format!(
                "portable rootfs metadata has {} entries, exceeding the {}-entry limit",
                self.entries.len(),
                PORTABLE_ROOTFS_METADATA_MAX_ENTRIES
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips_the_public_contract() {
        let manifest = PortableRootfsMetadataManifest::new(vec![PortableRootfsMetadataEntry {
            path_base64: "Lg==".to_string(),
            kind: PortableRootfsEntryKind::Directory,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            size: 0,
            link_target_base64: None,
        }]);
        manifest.validate().unwrap();
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: PortableRootfsMetadataManifest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, manifest);
    }
}
