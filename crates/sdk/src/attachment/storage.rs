use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{invalid_attachment, AttachmentSource, ConfigurationAttachment};
use crate::{Result, StorageAttachmentId};

/// Access granted by the caller for one already-authorized storage attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageAccessMode {
    /// The selected OCI mount and backing allocation are read-only.
    ReadOnly,
    /// The selected OCI mount and backing allocation are writable.
    ReadWrite,
}

/// Authority that retains ownership of an attached storage allocation.
///
/// Schema v2 deliberately supports only caller ownership. Runtime-owned
/// volumes and snapshots require a future contract with an implemented
/// allocation and deletion mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageOwnership {
    /// The caller retains ownership of the backing allocation.
    Caller,
}

/// Cleanup action the runtime may perform for an attached storage allocation.
///
/// Schema v2 allows the runtime to tear down its mount resources but never to
/// delete or mutate the caller-owned backing allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageCleanup {
    /// Detach the container mount and preserve the backing allocation.
    DetachOnly,
}

/// Immutable caller-issued identity and exact OCI mount binding for storage.
///
/// The identity names an already-authorized allocation incarnation, not a
/// mutable named-volume selector. The runtime never interprets it as a path or
/// chooses a volume or snapshot from it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageAttachment {
    identity: StorageAttachmentId,
    mount: ConfigurationAttachment,
    access_mode: StorageAccessMode,
    ownership: StorageOwnership,
    cleanup: StorageCleanup,
}

impl StorageAttachment {
    pub(super) const fn new(
        identity: StorageAttachmentId,
        mount: ConfigurationAttachment,
        access_mode: StorageAccessMode,
        ownership: StorageOwnership,
        cleanup: StorageCleanup,
    ) -> Self {
        Self {
            identity,
            mount,
            access_mode,
            ownership,
            cleanup,
        }
    }

    /// Caller-issued immutable allocation identity.
    #[must_use]
    pub const fn identity(&self) -> &StorageAttachmentId {
        &self.identity
    }

    /// Digest-bound OCI mount that carries the authorized allocation.
    #[must_use]
    pub const fn mount(&self) -> &ConfigurationAttachment {
        &self.mount
    }

    /// Exact read-only or read-write grant.
    #[must_use]
    pub const fn access_mode(&self) -> StorageAccessMode {
        self.access_mode
    }

    /// Authority that retains ownership of the backing allocation.
    #[must_use]
    pub const fn ownership(&self) -> StorageOwnership {
        self.ownership
    }

    /// Cleanup action permitted when the container is deleted.
    #[must_use]
    pub const fn cleanup(&self) -> StorageCleanup {
        self.cleanup
    }
}

pub(super) fn validate_attachments(
    storage: &[StorageAttachment],
    mounts: &[ConfigurationAttachment],
    secrets: &[AttachmentSource],
    configuration: &Value,
) -> Result<()> {
    if storage.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_attachment(
            "storage attachments must be unique and canonically ordered",
        ));
    }

    let mut identities = BTreeSet::new();
    let mut storage_mounts = BTreeSet::new();
    for attachment in storage {
        if !identities.insert(&attachment.identity) {
            return Err(invalid_attachment(format!(
                "storage attachment identity {} is declared more than once",
                attachment.identity
            )));
        }
        if !storage_mounts.insert(&attachment.mount) {
            return Err(invalid_attachment(format!(
                "storage attachment mount {} is declared more than once",
                attachment.mount.json_pointer()
            )));
        }
        let mount_index = mounts
            .iter()
            .position(|mount| mount == &attachment.mount)
            .ok_or_else(|| {
                invalid_attachment(format!(
                    "storage attachment {} does not reference an OCI mount",
                    attachment.identity
                ))
            })?;
        if secrets.iter().any(|source| {
            matches!(
                source,
                AttachmentSource::OciConfiguration { configuration }
                    if configuration == &attachment.mount
            )
        }) {
            return Err(invalid_attachment(format!(
                "OCI mount index {mount_index} cannot be both secret and storage"
            )));
        }
        attachment.mount.validate(configuration)?;
        let configured_access = mount_access_mode(configuration, mount_index)?;
        if attachment.access_mode != configured_access {
            return Err(invalid_attachment(format!(
                "storage attachment {} access mode {:?} differs from OCI mount index {mount_index} access mode {:?}",
                attachment.identity, attachment.access_mode, configured_access
            )));
        }
    }
    Ok(())
}

fn mount_access_mode(configuration: &Value, mount_index: usize) -> Result<StorageAccessMode> {
    let pointer = format!("/mounts/{mount_index}/options");
    let options: &[Value] = match configuration.pointer(&pointer) {
        Some(value) => value
            .as_array()
            .ok_or_else(|| {
                invalid_attachment(format!(
                    "OCI mount index {mount_index} options are not an array"
                ))
            })?
            .as_slice(),
        None => &[],
    };
    let read_only = options.iter().any(|option| option.as_str() == Some("ro"));
    let read_write = options.iter().any(|option| option.as_str() == Some("rw"));
    if read_only && read_write {
        return Err(invalid_attachment(format!(
            "OCI mount index {mount_index} declares contradictory ro and rw access modes"
        )));
    }
    Ok(if read_only {
        StorageAccessMode::ReadOnly
    } else {
        StorageAccessMode::ReadWrite
    })
}
