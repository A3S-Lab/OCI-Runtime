use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{
    AgentVmAttachmentManifest, AGENT_RUNTIME_SHARE_GUEST_ROOT,
    AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME, AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES,
};
use a3s_oci_sdk::{Error, ErrorCode, Result, RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY};
use sha2::{Digest, Sha256};

use crate::linux_runtime_share::LinuxRuntimeShare;

const PRIVATE_FILE_MODE: u32 = 0o600;

/// Descriptor-bound attachment manifest retained through native VM entry.
pub(crate) struct LinuxVmAttachmentManifest {
    manifest: AgentVmAttachmentManifest,
    path: PathBuf,
    pinned_path: PathBuf,
    device: u64,
    inode: u64,
    expected_digest: String,
    file: File,
}

impl LinuxVmAttachmentManifest {
    pub(crate) fn open(
        runtime_share: &LinuxRuntimeShare,
        expected_digest: Option<&str>,
    ) -> Result<Option<Self>> {
        let path = runtime_share
            .path()
            .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
        let pinned_path = runtime_share
            .pinned_path()
            .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
        let present = std::fs::symlink_metadata(&pinned_path);
        let metadata = match (expected_digest, present) {
            (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            (None, Ok(_)) => {
                return Err(attachment_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "runtime share contains an unrequested VM attachment manifest: {}",
                        path.display()
                    ),
                ));
            }
            (None, Err(error)) => {
                return Err(attachment_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "failed to inspect VM attachment manifest {}: {error}",
                        path.display()
                    ),
                ));
            }
            (Some(_), Err(error)) => {
                return Err(attachment_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "requested VM attachment manifest is unavailable at {}: {error}",
                        path.display()
                    ),
                ));
            }
            (Some(_), Ok(metadata)) => metadata,
        };
        let expected_digest = expected_digest.ok_or_else(|| {
            attachment_error(
                ErrorCode::Internal,
                "VM attachment digest disappeared after manifest admission",
            )
        })?;
        validate_expected_digest(expected_digest)?;
        validate_metadata(&path, &metadata)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&pinned_path).map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open VM attachment manifest {}: {error}",
                    path.display()
                ),
            )
        })?;
        let opened = file.metadata().map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect opened VM attachment manifest {}: {error}",
                    path.display()
                ),
            )
        })?;
        validate_metadata(&path, &opened)?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(attachment_error(
                ErrorCode::FailedPrecondition,
                "VM attachment manifest changed while it was opened",
            ));
        }
        let encoded = read_bounded(&mut file, &path)?;
        verify_digest(&encoded, expected_digest)?;
        let manifest = AgentVmAttachmentManifest::from_bytes(&encoded).map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!("invalid VM attachment manifest {}: {error}", path.display()),
            )
        })?;
        let expected_guest_bundle =
            format!("{AGENT_RUNTIME_SHARE_GUEST_ROOT}/{RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY}");
        if manifest.guest_bundle().as_str() != expected_guest_bundle {
            return Err(attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "KVM attachment manifest must bind dedicated Guest bundle {expected_guest_bundle}"
                ),
            ));
        }
        Ok(Some(Self {
            manifest,
            path,
            pinned_path,
            device: opened.dev(),
            inode: opened.ino(),
            expected_digest: expected_digest.to_string(),
            file,
        }))
    }

    pub(crate) const fn manifest(&self) -> &AgentVmAttachmentManifest {
        &self.manifest
    }

    pub(crate) fn reverify(&mut self) -> Result<()> {
        let path_metadata = std::fs::symlink_metadata(&self.pinned_path).map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to re-open VM attachment manifest {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        validate_metadata(&self.path, &path_metadata)?;
        let opened = self.file.metadata().map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to re-inspect VM attachment manifest {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        if path_metadata.dev() != self.device
            || path_metadata.ino() != self.inode
            || opened.dev() != self.device
            || opened.ino() != self.inode
        {
            return Err(attachment_error(
                ErrorCode::FailedPrecondition,
                "VM attachment manifest identity changed before VM entry",
            ));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to rewind VM attachment manifest {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        let encoded = read_bounded(&mut self.file, &self.path)?;
        verify_digest(&encoded, &self.expected_digest)?;
        let retained = AgentVmAttachmentManifest::from_bytes(&encoded).map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "VM attachment manifest became invalid before entry {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        if retained != self.manifest {
            return Err(attachment_error(
                ErrorCode::FailedPrecondition,
                "VM attachment manifest content changed before VM entry",
            ));
        }
        Ok(())
    }
}

fn validate_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    // SAFETY: geteuid has no preconditions or failure return.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o777 != PRIVATE_FILE_MODE
        || metadata.len() == 0
        || metadata.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES as u64
    {
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "VM attachment manifest must be a bounded UID-{effective_uid} mode-0600 plain file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn read_bounded(file: &mut File, path: &Path) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    file.take((AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read VM attachment manifest {}: {error}",
                    path.display()
                ),
            )
        })?;
    if encoded.is_empty() || encoded.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES {
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            "VM attachment manifest exceeds its bounded size",
        ));
    }
    Ok(encoded)
}

fn verify_digest(encoded: &[u8], expected: &str) -> Result<()> {
    let actual = format!("sha256:{:x}", Sha256::digest(encoded));
    if actual != expected {
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!("VM attachment manifest digest mismatch: expected {expected}, found {actual}"),
        ));
    }
    Ok(())
}

fn validate_expected_digest(value: &str) -> Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    });
    if !valid {
        return Err(attachment_error(
            ErrorCode::InvalidArgument,
            "VM attachment manifest digest is not canonical SHA-256",
        ));
    }
    Ok(())
}

fn attachment_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("verify-linux-kvm-vm-attachments")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use a3s_oci_agent_protocol::{
        AgentVmMacAddress, AgentVmNetworkAttachment, GuestPath,
        AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME,
    };
    use a3s_oci_sdk::{
        oci_spec::runtime::Spec, ContainerId, ContainerTarget, CreateAttachments, Generation,
        NetworkAttachmentIdentity, NetworkCleanup, NetworkCleanupId, NetworkInterfaceId,
        NetworkNamespaceId, OciBundle, ProcessIo,
    };
    use serde_json::json;

    use super::{AgentVmAttachmentManifest, LinuxRuntimeShare, LinuxVmAttachmentManifest};

    fn private_directory(path: &Path) {
        std::fs::create_dir(path).expect("create private directory");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("protect private directory");
    }

    fn runtime_share(root: &Path) -> PathBuf {
        let share = root.join("share");
        private_directory(&share);
        private_directory(&share.join("run"));
        share
    }

    fn manifest() -> AgentVmAttachmentManifest {
        let mut value = serde_json::to_value(Spec::default()).expect("default OCI spec");
        value["linux"] = json!({
            "namespaces": [{"type": "network"}],
            "netDevices": {"tap0": {"name": "eth0"}}
        });
        let bundle = OciBundle::from_json(
            std::env::temp_dir().join("a3s-krun-vm-attachment"),
            serde_json::to_string(&value).expect("fixture JSON"),
        )
        .expect("valid bundle");
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("base attachments")
            .attach_linux_network_interface(
                &bundle,
                0,
                "tap0",
                NetworkAttachmentIdentity::new(
                    NetworkNamespaceId::new("namespace-1").expect("namespace ID"),
                    NetworkInterfaceId::new("interface-1").expect("interface ID"),
                    NetworkCleanupId::new("cleanup-1").expect("cleanup ID"),
                ),
                NetworkCleanup::ReleaseRuntimeNamespace,
            )
            .expect("network attachment");
        let attachment_digest = attachments.digest().expect("attachment digest");
        let attachment = &attachments.network_attachments()[0];
        let network = AgentVmNetworkAttachment::new(
            attachment.identity().clone(),
            "tap0",
            attachment.namespace().clone(),
            attachment.interface().clone(),
            attachment.cleanup(),
            AgentVmMacAddress::derive(&attachment_digest, attachment.identity(), "tap0")
                .expect("transport MAC"),
        )
        .expect("VM network attachment");
        AgentVmAttachmentManifest::new(
            ContainerTarget::exact(
                ContainerId::new("networked").expect("container ID"),
                Generation(1),
            ),
            GuestPath::new("/run/a3s-oci-runtime/bundle").expect("guest bundle"),
            bundle.config_digest(),
            attachment_digest,
            vec![network],
        )
        .expect("VM attachment manifest")
    }

    fn write_manifest(share: &Path, manifest: &AgentVmAttachmentManifest) -> PathBuf {
        let path = share.join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
        std::fs::write(&path, manifest.to_bytes().expect("manifest bytes"))
            .expect("write manifest");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect manifest");
        path
    }

    #[test]
    fn pins_and_reverifies_the_exact_manifest_in_the_exported_share() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let manifest = manifest();
        let path = write_manifest(&share, &manifest);
        let runtime_share = LinuxRuntimeShare::open(&share).expect("runtime share");
        let mut retained = LinuxVmAttachmentManifest::open(
            &runtime_share,
            Some(&manifest.digest().expect("manifest digest")),
        )
        .expect("open manifest")
        .expect("requested manifest");
        assert_eq!(retained.manifest(), &manifest);
        retained.reverify().expect("reverify manifest");

        std::fs::write(&path, b"{}").expect("mutate manifest in place");
        assert!(retained.reverify().is_err());
    }

    #[test]
    fn rejects_unrequested_or_replaced_manifest_evidence() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let share = runtime_share(temporary.path());
        let manifest = manifest();
        let path = write_manifest(&share, &manifest);
        let runtime_share = LinuxRuntimeShare::open(&share).expect("runtime share");
        assert!(LinuxVmAttachmentManifest::open(&runtime_share, None).is_err());

        let mut retained = LinuxVmAttachmentManifest::open(
            &runtime_share,
            Some(&manifest.digest().expect("manifest digest")),
        )
        .expect("open manifest")
        .expect("requested manifest");
        std::fs::rename(&path, share.join("displaced-manifest")).expect("displace manifest");
        write_manifest(&share, &manifest);
        assert!(retained.reverify().is_err());
    }
}
