use std::ffi::CString;
use std::path::Path;

use a3s_oci_agent_protocol::{
    AgentVmAttachmentManifest, AgentVmMacAddress, AgentVmNetworkAttachment,
    AGENT_RUNTIME_SHARE_GUEST_ROOT, AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME,
    AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES,
};
use a3s_oci_sdk::{
    Error, ErrorCode, NetworkAttachment, Result, RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY,
};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::layout::{is_private_file, path_metadata, PRIVATE_FILE_MODE};
use super::UtilityVmLaunchRequest;

const PENDING_MANIFEST_FILE_NAME: &str = ".a3s-oci-agent-vm-attachments.pending";
const TUN_FLAG: u32 = 0x0001;
const TAP_FLAG: u32 = 0x0002;

/// Prepare immutable TAP transport evidence before the shim can enter a VM.
pub(crate) async fn prepare(request: &UtilityVmLaunchRequest<'_>) -> Result<Option<String>> {
    let final_path = request
        .runtime_share
        .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
    let pending_path = request.runtime_share.join(PENDING_MANIFEST_FILE_NAME);
    if request.attachment_contract.network_attachments().is_empty() {
        ensure_absent(&final_path, &pending_path).await?;
        return Ok(None);
    }
    if request.attachment_contract.guest_session().is_some() {
        return Err(network_error(
            ErrorCode::Unsupported,
            "KVM network devices cannot be hot-plugged into a reusable Guest session",
        ));
    }
    request.attachment_contract.validate(request.bundle)?;

    let configuration: Value =
        serde_json::from_str(request.bundle.config_json()).map_err(|error| {
            network_error(
                ErrorCode::Internal,
                format!("validated OCI configuration could not be decoded: {error}"),
            )
        })?;
    let attachment_digest = request.attachment_contract.digest()?;
    let mut network = Vec::with_capacity(request.attachment_contract.network_attachments().len());
    for attachment in request.attachment_contract.network_attachments() {
        let tap_name = tap_name(&configuration, attachment)?;
        verify_host_tap(&tap_name).await?;
        let mac_address =
            AgentVmMacAddress::derive(&attachment_digest, attachment.identity(), &tap_name)?;
        network.push(AgentVmNetworkAttachment::new(
            attachment.identity().clone(),
            tap_name,
            attachment.namespace().clone(),
            attachment.interface().clone(),
            attachment.cleanup(),
            mac_address,
        )?);
    }
    network.sort();

    let manifest = AgentVmAttachmentManifest::new(
        request.target.clone(),
        request.guest_bundle.clone(),
        request.bundle.config_digest(),
        attachment_digest,
        network,
    )?;
    manifest.validate_bundle(request.bundle)?;
    ensure_dedicated_bundle_path(&manifest)?;
    persist_manifest(request.runtime_share, &manifest).await?;
    manifest.digest().map(Some)
}

fn tap_name(configuration: &Value, attachment: &NetworkAttachment) -> Result<String> {
    let devices = configuration
        .pointer("/linux/netDevices")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            network_error(
                ErrorCode::InvalidArgument,
                "KVM network attachment requires linux.netDevices",
            )
        })?;
    devices
        .keys()
        .find(|name| {
            format!("/linux/netDevices/{}", escape_json_pointer(name))
                == attachment.interface().json_pointer()
        })
        .cloned()
        .ok_or_else(|| {
            network_error(
                ErrorCode::InvalidArgument,
                format!(
                    "authorized KVM network interface does not select {}",
                    attachment.interface().json_pointer()
                ),
            )
        })
}

async fn verify_host_tap(name: &str) -> Result<()> {
    let name_c = CString::new(name).map_err(|error| {
        network_error(
            ErrorCode::InvalidArgument,
            format!("KVM TAP name is not a C string: {error}"),
        )
    })?;
    // SAFETY: `name_c` is NUL-terminated and remains live for the complete call.
    let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
    if index == 0 {
        return Err(network_error(
            ErrorCode::FailedPrecondition,
            format!(
                "authorized KVM TAP {name} is not visible in the runtime network namespace: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }

    let flags_path = Path::new("/sys/class/net").join(name).join("tun_flags");
    let encoded = tokio::fs::read_to_string(&flags_path)
        .await
        .map_err(|error| {
            network_error(
                ErrorCode::FailedPrecondition,
                format!(
                "authorized KVM interface {name} is not a readable TUN/TAP device at {}: {error}",
                flags_path.display()
            ),
            )
        })?;
    let encoded = encoded.trim();
    let flags = encoded
        .strip_prefix("0x")
        .map_or_else(
            || encoded.parse::<u32>(),
            |hex| u32::from_str_radix(hex, 16),
        )
        .map_err(|error| {
            network_error(
                ErrorCode::FailedPrecondition,
                format!("KVM TAP {name} exposes invalid tun_flags {encoded:?}: {error}"),
            )
        })?;
    if flags & (TUN_FLAG | TAP_FLAG) != TAP_FLAG {
        return Err(network_error(
            ErrorCode::FailedPrecondition,
            format!("authorized KVM interface {name} is not a TAP device"),
        ));
    }
    Ok(())
}

fn ensure_dedicated_bundle_path(manifest: &AgentVmAttachmentManifest) -> Result<()> {
    let expected =
        format!("{AGENT_RUNTIME_SHARE_GUEST_ROOT}/{RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY}");
    if manifest.guest_bundle().as_str() != expected {
        return Err(network_error(
            ErrorCode::FailedPrecondition,
            format!(
                "KVM network transport requires the dedicated Guest bundle path {expected}, received {}",
                manifest.guest_bundle().as_str()
            ),
        ));
    }
    Ok(())
}

async fn persist_manifest(
    runtime_share: &Path,
    manifest: &AgentVmAttachmentManifest,
) -> Result<()> {
    let final_path = runtime_share.join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
    let pending_path = runtime_share.join(PENDING_MANIFEST_FILE_NAME);
    if path_metadata(&final_path).await?.is_some() {
        let retained = read_manifest(&final_path).await?;
        if retained != *manifest {
            return Err(network_error(
                ErrorCode::Conflict,
                "existing KVM network transport manifest differs from this Create",
            ));
        }
        remove_private_file_if_present(&pending_path).await?;
        return Ok(());
    }

    remove_private_file_if_present(&pending_path).await?;
    let encoded = manifest.to_bytes()?;
    let mut options = tokio::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&pending_path).await.map_err(|error| {
        network_error(
            ErrorCode::Internal,
            format!(
                "failed to create KVM network transport manifest {}: {error}",
                pending_path.display()
            ),
        )
    })?;
    file.write_all(&encoded).await.map_err(|error| {
        network_error(
            ErrorCode::Internal,
            format!(
                "failed to write KVM network transport manifest {}: {error}",
                pending_path.display()
            ),
        )
    })?;
    file.flush().await.map_err(|error| {
        network_error(
            ErrorCode::Internal,
            format!(
                "failed to flush KVM network transport manifest {}: {error}",
                pending_path.display()
            ),
        )
    })?;
    file.sync_all().await.map_err(|error| {
        network_error(
            ErrorCode::Internal,
            format!(
                "failed to sync KVM network transport manifest {}: {error}",
                pending_path.display()
            ),
        )
    })?;
    drop(file);
    tokio::fs::rename(&pending_path, &final_path)
        .await
        .map_err(|error| {
            network_error(
                ErrorCode::Internal,
                format!(
                    "failed to commit KVM network transport manifest {}: {error}",
                    final_path.display()
                ),
            )
        })?;
    sync_directory(runtime_share).await
}

async fn read_manifest(path: &Path) -> Result<AgentVmAttachmentManifest> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        network_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect KVM network transport manifest {}: {error}",
                path.display()
            ),
        )
    })?;
    if !is_private_file(&metadata)
        || metadata.len() == 0
        || metadata.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES as u64
    {
        return Err(network_error(
            ErrorCode::FailedPrecondition,
            format!(
                "KVM network transport manifest is not a bounded private file: {}",
                path.display()
            ),
        ));
    }
    let mut options = tokio::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    options
        .open(path)
        .await
        .map_err(|error| {
            network_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open KVM network transport manifest {}: {error}",
                    path.display()
                ),
            )
        })?
        .take((AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| {
            network_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read KVM network transport manifest {}: {error}",
                    path.display()
                ),
            )
        })?;
    AgentVmAttachmentManifest::from_bytes(&encoded).map_err(|error| {
        network_error(
            ErrorCode::FailedPrecondition,
            format!(
                "invalid KVM network transport manifest {}: {error}",
                path.display()
            ),
        )
    })
}

async fn ensure_absent(final_path: &Path, pending_path: &Path) -> Result<()> {
    for path in [final_path, pending_path] {
        if path_metadata(path).await?.is_some() {
            return Err(network_error(
                ErrorCode::Conflict,
                format!(
                    "a Create without KVM network attachments found stale transport evidence: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

async fn remove_private_file_if_present(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    if !is_private_file(&metadata) {
        return Err(network_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to remove non-private KVM evidence: {}",
                path.display()
            ),
        ));
    }
    tokio::fs::remove_file(path).await.map_err(|error| {
        network_error(
            ErrorCode::Internal,
            format!("failed to remove {}: {error}", path.display()),
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        network_error(
            ErrorCode::Internal,
            format!("KVM evidence path has no parent: {}", path.display()),
        )
    })?;
    sync_directory(parent).await
}

async fn sync_directory(path: &Path) -> Result<()> {
    tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            network_error(
                ErrorCode::Internal,
                format!(
                    "failed to open directory {} for sync: {error}",
                    path.display()
                ),
            )
        })?
        .sync_all()
        .await
        .map_err(|error| {
            network_error(
                ErrorCode::Internal,
                format!("failed to sync directory {}: {error}", path.display()),
            )
        })
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn network_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-kvm-network-attachments")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use a3s_oci_agent_protocol::{AgentVmMacAddress, AgentVmNetworkAttachment, GuestPath};
    use a3s_oci_sdk::{
        oci_spec::runtime::Spec, ContainerId, ContainerTarget, CreateAttachments, Generation,
        NetworkAttachmentIdentity, NetworkCleanup, NetworkCleanupId, NetworkInterfaceId,
        NetworkNamespaceId, OciBundle, ProcessIo,
    };
    use serde_json::json;

    use super::{
        ensure_absent, persist_manifest, read_manifest, AgentVmAttachmentManifest, ErrorCode,
        AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME, PENDING_MANIFEST_FILE_NAME,
    };

    fn manifest(generation: u64) -> AgentVmAttachmentManifest {
        let mut value = serde_json::to_value(Spec::default()).expect("default OCI spec");
        value["linux"] = json!({
            "namespaces": [{"type": "network"}],
            "netDevices": {"tap0": {"name": "eth0"}}
        });
        let bundle = OciBundle::from_json(
            std::env::temp_dir().join("a3s-kvm-network-manifest"),
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
                Generation(generation),
            ),
            GuestPath::new("/run/a3s-oci-runtime/bundle").expect("guest bundle"),
            bundle.config_digest(),
            attachment_digest,
            vec![network],
        )
        .expect("VM attachment manifest")
    }

    #[tokio::test]
    async fn persists_exact_replay_and_rejects_drift_or_unrequested_evidence() {
        let temporary = tempfile::tempdir().expect("temporary runtime share");
        let first = manifest(1);
        persist_manifest(temporary.path(), &first)
            .await
            .expect("persist manifest");
        persist_manifest(temporary.path(), &first)
            .await
            .expect("replay exact manifest");

        let final_path = temporary
            .path()
            .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
        assert_eq!(
            read_manifest(&final_path).await.expect("read manifest"),
            first
        );
        let pending_path = temporary.path().join(PENDING_MANIFEST_FILE_NAME);
        let stale = ensure_absent(&final_path, &pending_path)
            .await
            .expect_err("unrequested evidence must fail closed");
        assert_eq!(stale.code, ErrorCode::Conflict);

        let drift = persist_manifest(temporary.path(), &manifest(2))
            .await
            .expect_err("different generation must conflict");
        assert_eq!(drift.code, ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn recovers_only_a_private_pending_manifest() {
        let temporary = tempfile::tempdir().expect("temporary runtime share");
        let pending_path = temporary.path().join(PENDING_MANIFEST_FILE_NAME);
        std::fs::write(&pending_path, b"interrupted").expect("write pending manifest");
        std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect pending manifest");

        persist_manifest(temporary.path(), &manifest(1))
            .await
            .expect("recover private pending manifest");
        assert!(!pending_path.exists());

        let other = tempfile::tempdir().expect("other runtime share");
        let public_pending = other.path().join(PENDING_MANIFEST_FILE_NAME);
        std::fs::write(&public_pending, b"untrusted").expect("write public pending manifest");
        std::fs::set_permissions(&public_pending, std::fs::Permissions::from_mode(0o644))
            .expect("make pending manifest public");
        let error = persist_manifest(other.path(), &manifest(1))
            .await
            .expect_err("non-private pending evidence must not be removed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(public_pending.exists());
    }
}
