#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};

use a3s_oci_agent_protocol::AgentVmAttachmentManifest;
use a3s_oci_sdk::{Error, ErrorCode, Result, StorageAccessMode};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
const MAX_GUEST_BLOCK_DEVICES: usize = 1_024;
const MAX_ENCODED_STORAGE_SOURCES: usize = 64 * 1024;

/// One manifest-authorized OCI mount source rewritten to a verified Guest disk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UtilityVmStorageSource {
    mount_index: usize,
    configured_source: String,
    guest_source: String,
}

impl UtilityVmStorageSource {
    pub(crate) const fn mount_index(&self) -> usize {
        self.mount_index
    }

    pub(crate) fn configured_source(&self) -> &str {
        &self.configured_source
    }

    pub(crate) fn guest_source(&self) -> &str {
        &self.guest_source
    }

    fn validate(&self) -> Result<()> {
        if self.configured_source.len() < 2
            || !self.configured_source.starts_with('/')
            || self.configured_source.contains('\0')
        {
            return Err(storage_error(
                "VM storage source has an invalid configured Host path",
            ));
        }
        if !self.guest_source.starts_with("/dev/")
            || self.guest_source.len() <= "/dev/".len()
            || self.guest_source["/dev/".len()..]
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
        {
            return Err(storage_error(
                "VM storage source has an invalid Guest block-device path",
            ));
        }
        Ok(())
    }
}

/// Canonical exact-source rewrites inherited by one prepared container init.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct UtilityVmStorageSources(Vec<UtilityVmStorageSource>);

impl UtilityVmStorageSources {
    pub(crate) fn from_json(encoded: &str) -> Result<Self> {
        if encoded.len() > MAX_ENCODED_STORAGE_SOURCES {
            return Err(storage_error(
                "encoded VM storage sources exceed their bounded size",
            ));
        }
        let sources: Self = serde_json::from_str(encoded).map_err(|error| {
            storage_error(format!("failed to decode VM storage sources: {error}"))
        })?;
        sources.validate()?;
        Ok(sources)
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        self.validate()?;
        let encoded = serde_json::to_string(self).map_err(|error| {
            storage_error(format!("failed to encode VM storage sources: {error}"))
        })?;
        if encoded.len() > MAX_ENCODED_STORAGE_SOURCES {
            return Err(storage_error(
                "encoded VM storage sources exceed their bounded size",
            ));
        }
        Ok(encoded)
    }

    pub(crate) fn as_slice(&self) -> &[UtilityVmStorageSource] {
        &self.0
    }

    fn validate(&self) -> Result<()> {
        if self.0.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(storage_error(
                "VM storage source rewrites must be unique and canonically ordered",
            ));
        }
        let mut mount_indices = BTreeSet::new();
        let mut guest_sources = BTreeSet::new();
        for source in &self.0 {
            source.validate()?;
            if !mount_indices.insert(source.mount_index) {
                return Err(storage_error(format!(
                    "OCI mount index {} has more than one VM storage source",
                    source.mount_index
                )));
            }
            if !guest_sources.insert(source.guest_source.as_str()) {
                return Err(storage_error(format!(
                    "Guest storage source {} is assigned more than once",
                    source.guest_source
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestBlockDevice {
    name: String,
    serial: String,
    size: u64,
    read_only: bool,
}

#[cfg(target_os = "linux")]
pub(super) fn configure_guest_storage(
    manifest: &AgentVmAttachmentManifest,
) -> Result<UtilityVmStorageSources> {
    sources_from_inventory(manifest, &inventory_guest_block_devices()?)
}

fn sources_from_inventory(
    manifest: &AgentVmAttachmentManifest,
    inventory: &[GuestBlockDevice],
) -> Result<UtilityVmStorageSources> {
    let mut by_serial = BTreeMap::<&str, Vec<&GuestBlockDevice>>::new();
    for device in inventory {
        by_serial.entry(&device.serial).or_default().push(device);
    }

    let mut sources = Vec::with_capacity(manifest.storage().len());
    for attachment in manifest.storage() {
        let serial = attachment.virtio_serial();
        let matches = by_serial
            .get(serial.as_str())
            .map(Vec::as_slice)
            .unwrap_or_default();
        let [device] = matches else {
            return Err(storage_error(format!(
                "authorized KVM storage {} expected exactly one Guest disk with serial {serial}, found {}",
                attachment.identity(),
                matches.len()
            )));
        };
        if device.size != attachment.source_identity().size() {
            return Err(storage_error(format!(
                "Guest disk {} size {} differs from authorized storage {} size {}",
                device.name,
                device.size,
                attachment.identity(),
                attachment.source_identity().size()
            )));
        }
        let expected_read_only = attachment.access_mode() == StorageAccessMode::ReadOnly;
        if device.read_only != expected_read_only {
            return Err(storage_error(format!(
                "Guest disk {} read-only state {} differs from authorized storage {} access {:?}",
                device.name,
                device.read_only,
                attachment.identity(),
                attachment.access_mode()
            )));
        }
        sources.push(UtilityVmStorageSource {
            mount_index: attachment.mount_index()?,
            configured_source: attachment.host_source().to_string(),
            guest_source: format!("/dev/{}", device.name),
        });
    }
    sources.sort();
    let sources = UtilityVmStorageSources(sources);
    sources.validate()?;
    Ok(sources)
}

#[cfg(target_os = "linux")]
fn inventory_guest_block_devices() -> Result<Vec<GuestBlockDevice>> {
    use std::os::unix::fs::FileTypeExt;
    use std::path::Path;

    let root = Path::new("/sys/class/block");
    let entries = std::fs::read_dir(root).map_err(|error| {
        storage_error(format!(
            "failed to inventory Guest block devices at {}: {error}",
            root.display()
        ))
    })?;
    let mut devices = Vec::new();
    for entry in entries.take(MAX_GUEST_BLOCK_DEVICES + 1) {
        let entry = entry.map_err(|error| {
            storage_error(format!(
                "failed to read a Guest block-device entry: {error}"
            ))
        })?;
        if devices.len() == MAX_GUEST_BLOCK_DEVICES {
            return Err(storage_error(format!(
                "Guest exposes more than {MAX_GUEST_BLOCK_DEVICES} block devices"
            )));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| storage_error("Guest block-device inventory contains a non-UTF-8 name"))?;
        if entry.path().join("partition").exists() {
            continue;
        }
        let serial = match std::fs::read_to_string(entry.path().join("serial")) {
            Ok(serial) => serial
                .trim_matches(|character: char| character.is_whitespace() || character == '\0')
                .to_string(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(storage_error(format!(
                    "failed to read Guest block-device {name} serial: {error}"
                )));
            }
        };
        if serial.is_empty() {
            continue;
        }
        let sectors = read_u64(
            entry.path().join("size"),
            &format!("Guest disk {name} size"),
        )?;
        let size = sectors
            .checked_mul(512)
            .ok_or_else(|| storage_error(format!("Guest disk {name} byte size overflows u64")))?;
        let read_only = match read_u64(entry.path().join("ro"), &format!("Guest disk {name} ro"))? {
            0 => false,
            1 => true,
            value => {
                return Err(storage_error(format!(
                    "Guest disk {name} exposes invalid read-only state {value}"
                )));
            }
        };
        let device_path = Path::new("/dev").join(&name);
        let metadata = std::fs::symlink_metadata(&device_path).map_err(|error| {
            storage_error(format!(
                "Guest disk {name} has no matching device node {}: {error}",
                device_path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_block_device() {
            return Err(storage_error(format!(
                "Guest disk {name} does not map to a plain block device at {}",
                device_path.display()
            )));
        }
        devices.push(GuestBlockDevice {
            name,
            serial,
            size,
            read_only,
        });
    }
    Ok(devices)
}

#[cfg(target_os = "linux")]
fn read_u64(path: std::path::PathBuf, label: &str) -> Result<u64> {
    let encoded = std::fs::read_to_string(&path).map_err(|error| {
        storage_error(format!(
            "failed to read {label} at {}: {error}",
            path.display()
        ))
    })?;
    encoded
        .trim()
        .parse::<u64>()
        .map_err(|error| storage_error(format!("{label} is not an unsigned integer: {error}")))
}

fn storage_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("bootstrap-agent-vm-storage")
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentVmAttachmentManifest, AgentVmStorageAttachment, AgentVmStorageSourceIdentity,
        GuestPath,
    };
    use a3s_oci_sdk::{
        oci_spec::runtime::Spec, ContainerId, ContainerTarget, CreateAttachments, Generation,
        OciBundle, ProcessIo, StorageAccessMode, StorageAttachmentId, StorageCleanup,
        StorageOwnership,
    };
    use serde_json::json;

    use super::{sources_from_inventory, GuestBlockDevice, UtilityVmStorageSources};

    fn manifest() -> AgentVmAttachmentManifest {
        let mut value = serde_json::to_value(Spec::default()).expect("default spec");
        value["mounts"] = json!([{
            "destination": "/data",
            "type": "ext4",
            "source": "/srv/authorized.raw",
            "options": ["ro"]
        }]);
        let bundle = OciBundle::from_json(
            std::env::temp_dir().join("a3s-agent-storage-inventory"),
            value.to_string(),
        )
        .expect("bundle");
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("attachments")
            .attach_storage_mount(
                &bundle,
                0,
                StorageAttachmentId::new("volume-1").expect("identity"),
                StorageAccessMode::ReadOnly,
                StorageOwnership::Caller,
                StorageCleanup::DetachOnly,
            )
            .expect("storage attachment");
        let digest = attachments.digest().expect("digest");
        let public = &attachments.storage()[0];
        let storage = AgentVmStorageAttachment::new(
            public.identity().clone(),
            public.mount().clone(),
            public.access_mode(),
            public.ownership(),
            public.cleanup(),
            "/srv/authorized.raw",
            AgentVmStorageSourceIdentity::new(17, 0, 4_203, 4096).expect("identity"),
            &digest,
        )
        .expect("transport");
        AgentVmAttachmentManifest::new(
            ContainerTarget::exact(ContainerId::new("stored").unwrap(), Generation(1)),
            GuestPath::new("/run/a3s-oci-runtime/bundle").unwrap(),
            bundle.config_digest(),
            digest,
            Vec::new(),
            vec![storage],
        )
        .expect("manifest")
    }

    #[test]
    fn maps_serial_without_trusting_guest_enumeration_order() {
        let manifest = manifest();
        let sources = sources_from_inventory(
            &manifest,
            &[
                GuestBlockDevice {
                    name: "vda".into(),
                    serial: "system".into(),
                    size: 64 * 1024 * 1024,
                    read_only: true,
                },
                GuestBlockDevice {
                    name: "vdc".into(),
                    serial: "1704203".into(),
                    size: 4096,
                    read_only: true,
                },
            ],
        )
        .expect("mapped source");
        assert_eq!(sources.as_slice()[0].mount_index(), 0);
        assert_eq!(sources.as_slice()[0].guest_source(), "/dev/vdc");
        let encoded = sources.to_json().expect("encoded sources");
        assert_eq!(
            UtilityVmStorageSources::from_json(&encoded).unwrap(),
            sources
        );
    }

    #[test]
    fn rejects_missing_ambiguous_size_and_access_drift() {
        let manifest = manifest();
        assert!(sources_from_inventory(&manifest, &[]).is_err());
        let exact = GuestBlockDevice {
            name: "vdb".into(),
            serial: "1704203".into(),
            size: 4096,
            read_only: true,
        };
        assert!(sources_from_inventory(&manifest, &[exact.clone(), exact.clone()]).is_err());
        assert!(sources_from_inventory(
            &manifest,
            &[GuestBlockDevice {
                size: 8192,
                ..exact.clone()
            }]
        )
        .is_err());
        assert!(sources_from_inventory(
            &manifest,
            &[GuestBlockDevice {
                read_only: false,
                ..exact
            }]
        )
        .is_err());
    }
}
