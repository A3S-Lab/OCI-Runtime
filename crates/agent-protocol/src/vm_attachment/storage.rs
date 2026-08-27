use a3s_oci_sdk::{
    ConfigurationAttachment, Result, StorageAccessMode, StorageAttachmentId, StorageCleanup,
    StorageOwnership,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{manifest_error, validate_configuration_attachment, validate_digest};

const TRANSPORT_BLOCK_ID_DOMAIN: &[u8] = b"a3s.oci.agent-vm-storage-block-id.v1\0";
const TRANSPORT_BLOCK_ID_PREFIX: &str = "a3s-oci-storage-";
const VIRTIO_BLOCK_ID_BYTES: usize = 20;
const KVM_STORAGE_FILESYSTEM: &str = "ext4";

/// Immutable Host file identity reproduced by libkrun's virtio-blk serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVmStorageSourceIdentity {
    device: u64,
    raw_device: u64,
    inode: u64,
    size: u64,
}

impl AgentVmStorageSourceIdentity {
    /// Bind a regular raw image to its exact Host inode and byte length.
    pub fn new(device: u64, raw_device: u64, inode: u64, size: u64) -> Result<Self> {
        let identity = Self {
            device,
            raw_device,
            inode,
            size,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Host filesystem device containing the image.
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    /// Host raw-device identity reported for the image.
    #[must_use]
    pub const fn raw_device(self) -> u64 {
        self.raw_device
    }

    /// Exact Host inode pinned by the shim.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    /// Fixed raw image size exposed to the Guest.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    /// Exact identifier returned by libkrun for `VIRTIO_BLK_T_GET_ID`.
    #[must_use]
    pub fn virtio_serial(self) -> String {
        Self::virtio_serial_for(self.device, self.raw_device, self.inode)
    }

    /// Reproduce libkrun's virtio-blk serial for arbitrary Host file metadata.
    #[must_use]
    pub fn virtio_serial_for(device: u64, raw_device: u64, inode: u64) -> String {
        let serial = format!("{device}{raw_device}{inode}");
        serial.chars().take(VIRTIO_BLOCK_ID_BYTES).collect()
    }

    fn validate(self) -> Result<()> {
        if self.inode == 0 || self.size == 0 || !self.size.is_multiple_of(512) {
            return Err(manifest_error(
                "utility-VM storage image must have a nonzero inode and a nonzero 512-byte-aligned size",
            ));
        }
        if self.virtio_serial().is_empty() {
            return Err(manifest_error(
                "utility-VM storage image has no stable virtio-blk serial",
            ));
        }
        Ok(())
    }
}

/// One caller-owned raw image carried as an independent virtio-blk device.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVmStorageAttachment {
    identity: StorageAttachmentId,
    mount: ConfigurationAttachment,
    access_mode: StorageAccessMode,
    ownership: StorageOwnership,
    cleanup: StorageCleanup,
    host_source: String,
    source_identity: AgentVmStorageSourceIdentity,
    block_id: String,
}

impl AgentVmStorageAttachment {
    /// Bind one exact public storage grant to a raw Host image.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: StorageAttachmentId,
        mount: ConfigurationAttachment,
        access_mode: StorageAccessMode,
        ownership: StorageOwnership,
        cleanup: StorageCleanup,
        host_source: impl Into<String>,
        source_identity: AgentVmStorageSourceIdentity,
        attachment_digest: &str,
    ) -> Result<Self> {
        let host_source = host_source.into();
        let block_id = derive_block_id(attachment_digest, &identity)?;
        let entry = Self {
            identity,
            mount,
            access_mode,
            ownership,
            cleanup,
            host_source,
            source_identity,
            block_id,
        };
        entry.validate_shape(attachment_digest)?;
        Ok(entry)
    }

    /// Immutable caller-issued allocation identity.
    #[must_use]
    pub const fn identity(&self) -> &StorageAttachmentId {
        &self.identity
    }

    /// Exact OCI mount descriptor receiving this disk.
    #[must_use]
    pub const fn mount(&self) -> &ConfigurationAttachment {
        &self.mount
    }

    /// Access enforced by both libkrun and the OCI filesystem mount.
    #[must_use]
    pub const fn access_mode(&self) -> StorageAccessMode {
        self.access_mode
    }

    /// Only caller ownership is valid for schema v2 storage.
    #[must_use]
    pub const fn ownership(&self) -> StorageOwnership {
        self.ownership
    }

    /// Only detach-only cleanup is valid for schema v2 storage.
    #[must_use]
    pub const fn cleanup(&self) -> StorageCleanup {
        self.cleanup
    }

    /// Exact absolute Host raw-image path reopened by the isolated shim.
    #[must_use]
    pub fn host_source(&self) -> &str {
        &self.host_source
    }

    /// Host inode and size expected when the shim reopens the raw image.
    #[must_use]
    pub const fn source_identity(&self) -> AgentVmStorageSourceIdentity {
        self.source_identity
    }

    /// Deterministic libkrun block configuration identifier.
    #[must_use]
    pub fn block_id(&self) -> &str {
        &self.block_id
    }

    /// Exact serial used to locate this disk independently of Guest enumeration order.
    #[must_use]
    pub fn virtio_serial(&self) -> String {
        self.source_identity.virtio_serial()
    }

    /// Zero-based OCI mount index selected by this attachment.
    pub fn mount_index(&self) -> Result<usize> {
        parse_mount_index(self.mount.json_pointer())
    }

    pub(super) fn validate_shape(&self, attachment_digest: &str) -> Result<()> {
        validate_digest(self.mount.value_digest(), "storage mount value digest")?;
        validate_host_source(&self.host_source)?;
        self.source_identity.validate()?;
        if self.ownership != StorageOwnership::Caller || self.cleanup != StorageCleanup::DetachOnly
        {
            return Err(manifest_error(
                "utility-VM storage transport requires caller ownership and detach-only cleanup",
            ));
        }
        self.mount_index()?;
        let expected = derive_block_id(attachment_digest, &self.identity)?;
        if self.block_id != expected {
            return Err(manifest_error(format!(
                "utility-VM storage block ID {} is not derived from immutable attachment evidence",
                self.block_id
            )));
        }
        Ok(())
    }

    pub(super) fn validate_configuration(&self, configuration: &Value) -> Result<()> {
        validate_configuration_attachment(configuration, &self.mount, "storage mount")?;
        let mount = configuration
            .pointer(self.mount.json_pointer())
            .and_then(Value::as_object)
            .ok_or_else(|| manifest_error("storage mount attachment is not an object"))?;
        if mount.get("source").and_then(Value::as_str) != Some(self.host_source.as_str()) {
            return Err(manifest_error(format!(
                "storage attachment {} does not bind Host source {}",
                self.identity, self.host_source
            )));
        }
        if mount.get("type").and_then(Value::as_str) != Some(KVM_STORAGE_FILESYSTEM) {
            return Err(manifest_error(format!(
                "KVM storage attachment {} requires filesystem type {KVM_STORAGE_FILESYSTEM}",
                self.identity
            )));
        }
        let options = match mount.get("options") {
            Some(Value::Array(options)) => options.as_slice(),
            None => &[],
            Some(_) => return Err(manifest_error("storage mount options are not an array")),
        };
        let mut read_only = false;
        let mut read_write = false;
        for option in options {
            let option = option
                .as_str()
                .ok_or_else(|| manifest_error("storage mount option is not a string"))?;
            match option {
                "ro" => read_only = true,
                "rw" => read_write = true,
                "bind" | "rbind" | "loop" => {
                    return Err(manifest_error(format!(
                        "KVM raw storage attachment {} cannot use OCI mount option {option}",
                        self.identity
                    )));
                }
                value if value.starts_with("offset=") || value.starts_with("sizelimit=") => {
                    return Err(manifest_error(format!(
                        "KVM raw storage attachment {} cannot transform its exact image with {value}",
                        self.identity
                    )));
                }
                _ => {}
            }
        }
        if read_only && read_write {
            return Err(manifest_error(
                "KVM raw storage mount declares contradictory ro and rw options",
            ));
        }
        let configured_access = if read_only {
            StorageAccessMode::ReadOnly
        } else {
            StorageAccessMode::ReadWrite
        };
        if configured_access != self.access_mode {
            return Err(manifest_error(format!(
                "KVM storage attachment {} access mode drifted from its OCI mount",
                self.identity
            )));
        }
        Ok(())
    }
}

fn derive_block_id(attachment_digest: &str, identity: &StorageAttachmentId) -> Result<String> {
    validate_digest(attachment_digest, "attachment digest")?;
    let mut hasher = Sha256::new();
    hasher.update(TRANSPORT_BLOCK_ID_DOMAIN);
    for value in [attachment_digest, identity.as_str()] {
        let length = u64::try_from(value.len()).map_err(|error| {
            manifest_error(format!(
                "utility-VM storage block evidence length is not portable: {error}"
            ))
        })?;
        hasher.update(length.to_le_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = format!("{:x}", hasher.finalize());
    Ok(format!("{TRANSPORT_BLOCK_ID_PREFIX}{}", &digest[..32]))
}

fn parse_mount_index(pointer: &str) -> Result<usize> {
    let encoded = pointer.strip_prefix("/mounts/").ok_or_else(|| {
        manifest_error(format!(
            "utility-VM storage attachment does not reference an OCI mount: {pointer}"
        ))
    })?;
    if encoded.is_empty()
        || (encoded.len() > 1 && encoded.starts_with('0'))
        || !encoded.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(manifest_error(format!(
            "utility-VM storage attachment has a non-canonical mount pointer: {pointer}"
        )));
    }
    encoded.parse::<usize>().map_err(|error| {
        manifest_error(format!(
            "utility-VM storage mount index in {pointer} is invalid: {error}"
        ))
    })
}

fn validate_host_source(source: &str) -> Result<()> {
    if source.len() < 2
        || source.len() > 4_096
        || !source.starts_with('/')
        || source.ends_with('/')
        || source.contains(['\\', '\0'])
        || source
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(manifest_error(format!(
            "utility-VM storage source must be a normalized absolute Linux file path: {source:?}"
        )));
    }
    Ok(())
}
