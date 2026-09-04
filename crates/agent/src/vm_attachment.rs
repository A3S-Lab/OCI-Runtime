#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use a3s_oci_agent_protocol::AgentCreateRequest;
use a3s_oci_agent_protocol::AgentVmAttachmentManifest;
#[cfg(target_os = "linux")]
use a3s_oci_agent_protocol::{
    AGENT_RUNTIME_SHARE_GUEST_ROOT, AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME,
    AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES, AGENT_VM_ATTACHMENT_MANIFEST_SHA256_ENV,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
#[cfg(target_os = "linux")]
use a3s_oci_sdk::{OciBundle, CONFIG_FILE_NAME, MAX_CONFIG_BYTES};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

mod network;
mod storage;

pub(crate) use storage::UtilityVmStorageSources;

#[derive(Debug)]
#[cfg(any(target_os = "linux", test))]
pub struct UtilityVmAttachmentBinding {
    manifest: AgentVmAttachmentManifest,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    storage_sources: UtilityVmStorageSources,
}

#[cfg(any(target_os = "linux", test))]
impl UtilityVmAttachmentBinding {
    pub(crate) fn validate_create(&self, request: &AgentCreateRequest) -> Result<()> {
        if request.target != *self.manifest.target() {
            return Err(attachment_error(format!(
                "VM attachment manifest targets {:?}, not create target {:?}",
                self.manifest.target(),
                request.target
            )));
        }
        if request.bundle.guest_directory() != self.manifest.guest_bundle() {
            return Err(attachment_error(format!(
                "VM attachment manifest binds Guest bundle {}, not {}",
                self.manifest.guest_bundle().as_str(),
                request.bundle.guest_directory().as_str()
            )));
        }
        if request.bundle.config_digest() != self.manifest.config_digest() {
            return Err(attachment_error(format!(
                "VM attachment manifest binds configuration {}, not {}",
                self.manifest.config_digest(),
                request.bundle.config_digest()
            )));
        }
        let bundle = request.bundle.to_guest_bundle()?;
        self.manifest.validate_bundle(&bundle)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn storage_sources(&self) -> &UtilityVmStorageSources {
        &self.storage_sources
    }
}

/// Consume and apply the optional fixed KVM network-attachment bootstrap.
#[cfg(target_os = "linux")]
pub fn take_vm_attachment_manifest(
    runtime_parent: Option<&Path>,
) -> Result<Option<UtilityVmAttachmentBinding>> {
    let expected_digest = std::env::var_os(AGENT_VM_ATTACHMENT_MANIFEST_SHA256_ENV);
    std::env::remove_var(AGENT_VM_ATTACHMENT_MANIFEST_SHA256_ENV);
    let manifest_path =
        Path::new(AGENT_RUNTIME_SHARE_GUEST_ROOT).join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
    let present = std::fs::symlink_metadata(&manifest_path);
    let expected_digest = match (expected_digest, present) {
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        (None, Ok(_)) => {
            return Err(attachment_error(format!(
                "mounted runtime share contains an unrequested VM attachment manifest: {}",
                manifest_path.display()
            )));
        }
        (None, Err(error)) => {
            return Err(attachment_error(format!(
                "failed to inspect VM attachment manifest {}: {error}",
                manifest_path.display()
            )));
        }
        (Some(_), Err(error)) => {
            return Err(attachment_error(format!(
                "requested VM attachment manifest is unavailable at {}: {error}",
                manifest_path.display()
            )));
        }
        (Some(expected), Ok(metadata)) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() == 0
                || metadata.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES as u64
            {
                return Err(attachment_error(format!(
                    "VM attachment manifest is not a bounded plain file: {}",
                    manifest_path.display()
                )));
            }
            expected
        }
    };
    let expected_digest = expected_digest
        .into_string()
        .map_err(|_| attachment_error("VM attachment manifest digest is not valid UTF-8"))?;
    validate_digest(&expected_digest)?;
    let runtime_parent = runtime_parent.ok_or_else(|| {
        attachment_error("VM attachment manifest requires the protected runtime share")
    })?;
    if runtime_parent != Path::new(AGENT_RUNTIME_SHARE_GUEST_ROOT).join("run") {
        return Err(attachment_error(format!(
            "VM attachment manifest received an unexpected runtime-state root: {}",
            runtime_parent.display()
        )));
    }

    let encoded = read_bounded_file(
        &manifest_path,
        AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES as u64,
        "VM attachment manifest",
    )?;
    let actual_digest = format!("sha256:{:x}", Sha256::digest(&encoded));
    if actual_digest != expected_digest {
        return Err(attachment_error(format!(
            "VM attachment manifest digest mismatch: expected {expected_digest}, found {actual_digest}"
        )));
    }
    let manifest = AgentVmAttachmentManifest::from_bytes(&encoded)
        .map_err(|error| attachment_error(format!("invalid VM attachment manifest: {error}")))?;
    validate_guest_bundle(&manifest)?;
    let storage_sources = storage::configure_guest_storage(&manifest)?;
    network::configure_guest_interfaces(&manifest)?;
    Ok(Some(UtilityVmAttachmentBinding {
        manifest,
        storage_sources,
    }))
}

#[cfg(target_os = "linux")]
fn validate_guest_bundle(manifest: &AgentVmAttachmentManifest) -> Result<()> {
    let bundle_directory = manifest.guest_bundle().to_path_buf();
    if bundle_directory.parent() != Some(Path::new(AGENT_RUNTIME_SHARE_GUEST_ROOT)) {
        return Err(attachment_error(format!(
            "VM attachment bundle is not a direct child of the protected runtime share: {}",
            bundle_directory.display()
        )));
    }
    let metadata = std::fs::symlink_metadata(&bundle_directory).map_err(|error| {
        attachment_error(format!(
            "failed to inspect VM attachment bundle {}: {error}",
            bundle_directory.display()
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(attachment_error(format!(
            "VM attachment bundle must be a plain directory: {}",
            bundle_directory.display()
        )));
    }
    let config_path = bundle_directory.join(CONFIG_FILE_NAME);
    let encoded = read_bounded_file(
        &config_path,
        MAX_CONFIG_BYTES,
        "VM attachment OCI configuration",
    )?;
    let config_json = String::from_utf8(encoded).map_err(|error| {
        attachment_error(format!(
            "VM attachment OCI configuration is not UTF-8: {error}"
        ))
    })?;
    let bundle = OciBundle::from_json(bundle_directory, config_json)?;
    manifest.validate_bundle(&bundle)
}

#[cfg(target_os = "linux")]
fn read_bounded_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        attachment_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(attachment_error(format!(
            "{label} must be a bounded nonempty regular file: {}",
            path.display()
        )));
    }
    if path_metadata.len() == 0 || path_metadata.len() > maximum {
        return Err(attachment_error(format!(
            "{label} must be a bounded nonempty regular file: {}",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        attachment_error(format!(
            "failed to open {label} {}: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata().map_err(|error| {
        attachment_error(format!(
            "failed to inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
        || metadata.len() != path_metadata.len()
    {
        return Err(attachment_error(format!(
            "{label} changed while it was being opened: {}",
            path.display()
        )));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut encoded)
        .map_err(|error| {
            attachment_error(format!(
                "failed to read {label} {}: {error}",
                path.display()
            ))
        })?;
    if encoded.is_empty() || encoded.len() as u64 > maximum {
        return Err(attachment_error(format!(
            "{label} exceeds its bounded size: {}",
            path.display()
        )));
    }
    let file_metadata = file.metadata().map_err(|error| {
        attachment_error(format!(
            "failed to inspect {label} after reading {}: {error}",
            path.display()
        ))
    })?;
    let final_path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        attachment_error(format!(
            "failed to re-inspect {label} after reading {}: {error}",
            path.display()
        ))
    })?;
    if !file_metadata.is_file()
        || file_metadata.file_type().is_symlink()
        || file_metadata.dev() != path_metadata.dev()
        || file_metadata.ino() != path_metadata.ino()
        || file_metadata.len() != path_metadata.len()
        || encoded.len() as u64 != path_metadata.len()
        || !final_path_metadata.is_file()
        || final_path_metadata.file_type().is_symlink()
        || final_path_metadata.dev() != path_metadata.dev()
        || final_path_metadata.ino() != path_metadata.ino()
        || final_path_metadata.len() != path_metadata.len()
    {
        return Err(attachment_error(format!(
            "{label} changed while it was being read: {}",
            path.display()
        )));
    }
    Ok(encoded)
}

#[cfg(target_os = "linux")]
fn validate_digest(value: &str) -> Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    });
    if !valid {
        return Err(attachment_error(
            "VM attachment manifest digest is not canonical SHA-256",
        ));
    }
    Ok(())
}

fn attachment_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message)
        .for_operation("bootstrap-agent-vm-attachments")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use a3s_oci_agent_protocol::{
        AgentBundle, AgentCreateRequest, AgentVmAttachmentManifest, AgentVmMacAddress,
        AgentVmNetworkAttachment, GuestPath,
    };
    use a3s_oci_sdk::{
        oci_spec::runtime::Spec, ContainerId, ContainerTarget, CreateAttachments, Generation,
        NetworkAttachmentIdentity, NetworkCleanup, NetworkCleanupId, NetworkInterfaceId,
        NetworkNamespaceId, OciBundle, OperationContext, OperationId, ProcessIo,
    };
    use serde_json::json;

    use super::{network::rename_plan, UtilityVmAttachmentBinding, UtilityVmStorageSources};

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_attachment_read_rejects_a_final_component_symlink() {
        let temporary = tempfile::tempdir().expect("temporary attachment root");
        let target = temporary.path().join("target");
        let alias = temporary.path().join("manifest");
        std::fs::write(&target, b"manifest").expect("write target");
        std::os::unix::fs::symlink(&target, &alias).expect("create manifest symlink");

        let error = super::read_bounded_file(&alias, 64, "test attachment")
            .expect_err("final-component symlink must be rejected");
        assert!(error.message.contains("regular file"));
        assert_eq!(std::fs::read(&target).expect("read target"), b"manifest");
    }

    fn manifest(names: &[&str]) -> AgentVmAttachmentManifest {
        manifest_fixture(names).0
    }

    fn manifest_fixture(
        names: &[&str],
    ) -> (
        AgentVmAttachmentManifest,
        OciBundle,
        ContainerTarget,
        GuestPath,
    ) {
        let mut value = serde_json::to_value(Spec::default()).expect("default spec");
        value["linux"] = json!({
            "namespaces": [{"type": "network"}, {"type": "uts"}],
            "netDevices": names
                .iter()
                .map(|name| ((*name).to_string(), json!({})))
                .collect::<serde_json::Map<_, _>>()
        });
        let bundle = OciBundle::from_json(
            std::env::temp_dir().join("a3s-agent-rename-plan"),
            serde_json::to_string(&value).expect("fixture JSON"),
        )
        .expect("bundle");
        let mut attachments =
            CreateAttachments::from_bundle(&bundle, ProcessIo::default()).expect("attachments");
        for (index, name) in names.iter().enumerate() {
            attachments = attachments
                .attach_linux_network_interface(
                    &bundle,
                    0,
                    name,
                    NetworkAttachmentIdentity::new(
                        NetworkNamespaceId::new("namespace").expect("namespace"),
                        NetworkInterfaceId::new(format!("interface-{index}")).expect("interface"),
                        NetworkCleanupId::new("cleanup").expect("cleanup"),
                    ),
                    NetworkCleanup::ReleaseRuntimeNamespace,
                )
                .expect("network attachment");
        }
        let digest = attachments.digest().expect("attachment digest");
        let mut network = attachments
            .network_attachments()
            .iter()
            .map(|attachment| {
                let name = names
                    .iter()
                    .copied()
                    .find(|name| attachment.interface().json_pointer().ends_with(name))
                    .expect("interface name");
                AgentVmNetworkAttachment::new(
                    attachment.identity().clone(),
                    name,
                    attachment.namespace().clone(),
                    attachment.interface().clone(),
                    attachment.cleanup(),
                    AgentVmMacAddress::derive(&digest, attachment.identity(), name).expect("MAC"),
                )
                .expect("VM network attachment")
            })
            .collect::<Vec<_>>();
        network.sort();
        let target = ContainerTarget::exact(
            ContainerId::new("networked").expect("container ID"),
            Generation(1),
        );
        let guest_bundle = GuestPath::new("/run/a3s-oci-runtime/bundle").expect("guest bundle");
        let manifest = AgentVmAttachmentManifest::new(
            target.clone(),
            guest_bundle.clone(),
            bundle.config_digest(),
            digest,
            network,
            Vec::new(),
        )
        .expect("manifest");
        (manifest, bundle, target, guest_bundle)
    }

    #[test]
    fn stages_all_names_before_resolving_a_guest_name_cycle() {
        let manifest = manifest(&["eth0", "eth1"]);
        let inventory = BTreeMap::from([
            (
                "eth1".to_string(),
                *manifest.network()[0].mac_address().as_bytes(),
            ),
            (
                "eth0".to_string(),
                *manifest.network()[1].mac_address().as_bytes(),
            ),
        ]);
        let plan = rename_plan(&manifest, &inventory).expect("rename plan");
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].from, "eth1");
        assert!(plan[0].to.starts_with("a3svm"));
        assert_eq!(plan[1].from, "eth0");
        assert_eq!(plan[2].to, "eth0");
        assert_eq!(plan[3].to, "eth1");
    }

    #[test]
    fn rejects_missing_ambiguous_and_unrelated_interfaces() {
        let manifest = manifest(&["tap0"]);
        assert!(rename_plan(&manifest, &BTreeMap::new()).is_err());
        let mac = *manifest.network()[0].mac_address().as_bytes();
        let ambiguous = BTreeMap::from([("eth0".to_string(), mac), ("eth1".to_string(), mac)]);
        assert!(rename_plan(&manifest, &ambiguous).is_err());
        let occupied = BTreeMap::from([
            ("eth0".to_string(), mac),
            ("tap0".to_string(), [2, 1, 2, 3, 4, 5]),
        ]);
        assert!(rename_plan(&manifest, &occupied).is_err());
    }

    #[test]
    fn binding_accepts_only_the_manifest_target_bundle_and_configuration() {
        let (manifest, bundle, target, guest_bundle) = manifest_fixture(&["tap0"]);
        let binding = UtilityVmAttachmentBinding {
            manifest,
            storage_sources: UtilityVmStorageSources::default(),
        };
        let request = AgentCreateRequest {
            context: OperationContext::new(
                OperationId::new("network-create").expect("operation ID"),
            ),
            target: target.clone(),
            bundle: AgentBundle::new(&bundle, guest_bundle.clone()),
            io: ProcessIo::default(),
        };
        #[cfg(target_os = "linux")]
        binding.validate_create(&request).expect("bound create");

        let mut wrong_target = request.clone();
        wrong_target.target = ContainerTarget::exact(target.id.clone(), Generation(2));
        assert!(binding.validate_create(&wrong_target).is_err());

        let mut wrong_directory = request.clone();
        wrong_directory.bundle = AgentBundle::new(
            &bundle,
            GuestPath::new("/run/a3s-oci-runtime/other").expect("guest bundle"),
        );
        assert!(binding.validate_create(&wrong_directory).is_err());

        let different_bundle = OciBundle::from_json(
            std::env::temp_dir().join("a3s-agent-binding-drift"),
            serde_json::to_string(&Spec::default()).expect("fixture JSON"),
        )
        .expect("different bundle");
        let mut wrong_configuration = request;
        wrong_configuration.bundle = AgentBundle::new(&different_bundle, guest_bundle);
        assert!(binding.validate_create(&wrong_configuration).is_err());
    }
}
