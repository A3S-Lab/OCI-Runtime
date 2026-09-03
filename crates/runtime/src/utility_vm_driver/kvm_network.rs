use std::ffi::CString;
use std::io;
use std::os::unix::fs::MetadataExt;
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
use tokio::io::AsyncReadExt;

use super::atomic_publication;
use super::layout::{is_private_file, path_metadata};
use super::UtilityVmLaunchRequest;

mod storage;

const PENDING_MANIFEST_FILE_NAME: &str = ".a3s-oci-agent-vm-attachments.pending";
const STAGING_MANIFEST_PREFIX: &str = ".a3s-oci-agent-vm-attachments.pending.";
const PUBLISH_ATTEMPTS: usize = atomic_publication::PUBLISH_ATTEMPTS;
const TUN_FLAG: u32 = 0x0001;
const TAP_FLAG: u32 = 0x0002;

/// Prepare immutable raw-storage and TAP transport evidence before VM entry.
pub(crate) async fn prepare(request: &UtilityVmLaunchRequest<'_>) -> Result<Option<String>> {
    let final_path = request
        .runtime_share
        .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
    let pending_path = request.runtime_share.join(PENDING_MANIFEST_FILE_NAME);
    if request.attachment_contract.network_attachments().is_empty()
        && request.attachment_contract.storage().is_empty()
    {
        ensure_absent(&final_path, &pending_path).await?;
        return Ok(None);
    }
    if request.attachment_contract.guest_session().is_some() {
        return Err(attachment_error(
            ErrorCode::Unsupported,
            "KVM storage and network devices cannot be hot-plugged into a reusable Guest session",
        ));
    }
    request.attachment_contract.validate(request.bundle)?;

    let configuration: Value =
        serde_json::from_str(request.bundle.config_json()).map_err(|error| {
            attachment_error(
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

    let mut storage = Vec::with_capacity(request.attachment_contract.storage().len());
    for attachment in request.attachment_contract.storage() {
        storage
            .push(storage::prepare(request, &configuration, attachment, &attachment_digest).await?);
    }
    storage.sort();

    let manifest = AgentVmAttachmentManifest::new(
        request.target.clone(),
        request.guest_bundle.clone(),
        request.bundle.config_digest(),
        attachment_digest,
        network,
        storage,
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
            attachment_error(
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
            attachment_error(
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
        attachment_error(
            ErrorCode::InvalidArgument,
            format!("KVM TAP name is not a C string: {error}"),
        )
    })?;
    // SAFETY: `name_c` is NUL-terminated and remains live for the complete call.
    let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
    if index == 0 {
        return Err(attachment_error(
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
            attachment_error(
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
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!("KVM TAP {name} exposes invalid tun_flags {encoded:?}: {error}"),
            )
        })?;
    if flags & (TUN_FLAG | TAP_FLAG) != TAP_FLAG {
        return Err(attachment_error(
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
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "KVM attachment transport requires the dedicated Guest bundle path {expected}, received {}",
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
            return Err(attachment_error(
                ErrorCode::Conflict,
                "existing KVM attachment transport manifest differs from this Create",
            ));
        }
        remove_matching_pending(&pending_path, manifest).await?;
        sync_directory(runtime_share).await?;
        return Ok(());
    }

    let encoded = manifest.to_bytes()?;
    for attempt in 0..PUBLISH_ATTEMPTS {
        match create_or_reuse_pending(runtime_share, &pending_path, &encoded, manifest).await {
            Err(error) if error.retryable && attempt + 1 < PUBLISH_ATTEMPTS => continue,
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        match publish_manifest(runtime_share, &pending_path, &final_path, manifest).await {
            Err(error) if error.retryable && attempt + 1 < PUBLISH_ATTEMPTS => continue,
            result => return result,
        }
    }
    Err(attachment_error(
        ErrorCode::Unavailable,
        "KVM attachment transport manifest publication kept losing its concurrent owner",
    )
    .retryable(true))
}

async fn create_or_reuse_pending(
    runtime_share: &Path,
    pending: &Path,
    encoded: &[u8],
    expected: &AgentVmAttachmentManifest,
) -> Result<()> {
    if let Some(initial_metadata) = path_metadata(pending).await? {
        match read_manifest(pending).await {
            Ok(retained) if retained == *expected => return Ok(()),
            Ok(_) => return Err(manifest_conflict()),
            Err(error) if error.code == ErrorCode::FailedPrecondition => {
                // The new writer never exposes a partial pending inode: it
                // links a fully synced staging inode into this name. A
                // malformed private pending file therefore belongs to an
                // interrupted writer from the legacy path and may be
                // discarded. Non-private or disappearing files remain
                // fail-closed below.
                let Some(metadata) = path_metadata(pending).await? else {
                    return Err(error.retryable(true));
                };
                if metadata.dev() != initial_metadata.dev()
                    || metadata.ino() != initial_metadata.ino()
                {
                    return Err(error.retryable(true));
                }
                if !is_private_file(&metadata) {
                    return Err(error);
                }
                remove_private_file_if_present(pending).await?;
            }
            Err(error) => return Err(error),
        }
    }

    let staging = atomic_publication::create_complete_staging(
        runtime_share,
        pending,
        encoded,
        STAGING_MANIFEST_PREFIX,
    )
    .await
    .map_err(|error| {
        attachment_error(
            ErrorCode::Internal,
            format!(
                "failed to create KVM attachment transport staging manifest near {}: {error}",
                pending.display()
            ),
        )
    })?;
    match tokio::fs::hard_link(&staging, pending).await {
        Ok(()) => {
            atomic_publication::remove_file_if_present(&staging)
                .await
                .map_err(|error| {
                    attachment_error(
                        ErrorCode::Internal,
                        format!(
                            "failed to remove KVM attachment transport staging manifest {}: {error}",
                            staging.display()
                        ),
                    )
                })?;
            sync_directory(runtime_share).await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = atomic_publication::remove_file_if_present(&staging).await;
            ensure_pending_matches(pending, expected).await
        }
        Err(error) => {
            let _ = atomic_publication::remove_file_if_present(&staging).await;
            Err(attachment_error(
                ErrorCode::Internal,
                format!(
                    "failed to publish KVM attachment transport pending manifest {}: {error}",
                    pending.display()
                ),
            ))
        }
    }
}

async fn ensure_pending_matches(
    pending: &Path,
    expected: &AgentVmAttachmentManifest,
) -> Result<()> {
    match read_manifest_if_present(pending).await? {
        Some(retained) if retained == *expected => Ok(()),
        Some(_) => Err(manifest_conflict()),
        None => Err(attachment_error(
            ErrorCode::Unavailable,
            format!(
                "KVM attachment transport pending manifest disappeared before adoption: {}",
                pending.display()
            ),
        )
        .retryable(true)),
    }
}

async fn publish_manifest(
    runtime_share: &Path,
    pending: &Path,
    final_path: &Path,
    expected: &AgentVmAttachmentManifest,
) -> Result<()> {
    match tokio::fs::hard_link(pending, final_path).await {
        Ok(()) => {
            let retained = read_manifest(final_path).await?;
            if retained != *expected {
                return Err(manifest_conflict());
            }
            remove_matching_pending(pending, expected).await?;
            sync_directory(runtime_share).await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let retained = read_manifest(final_path).await?;
            if retained != *expected {
                return Err(manifest_conflict());
            }
            remove_matching_pending(pending, expected).await?;
            sync_directory(runtime_share).await
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match read_manifest_if_present(final_path).await? {
                Some(retained) if retained == *expected => sync_directory(runtime_share).await,
                Some(_) => Err(manifest_conflict()),
                None => Err(attachment_error(
                    ErrorCode::Unavailable,
                    format!(
                        "KVM attachment transport pending manifest disappeared before publication: {}",
                        pending.display()
                    ),
                )
                .retryable(true)),
            }
        }
        Err(error) => Err(attachment_error(
            ErrorCode::Internal,
            format!(
                "failed to commit KVM attachment transport manifest {}: {error}",
                final_path.display()
            ),
        )),
    }
}

async fn read_manifest_if_present(path: &Path) -> Result<Option<AgentVmAttachmentManifest>> {
    let Some(initial_metadata) = path_metadata(path).await? else {
        return Ok(None);
    };
    match read_manifest(path).await {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) => match path_metadata(path).await? {
            None => Ok(None),
            Some(current_metadata)
                if !atomic_publication::same_file_identity(
                    &initial_metadata,
                    &current_metadata,
                ) =>
            {
                Err(attachment_error(
                    ErrorCode::Unavailable,
                    format!(
                        "KVM attachment transport manifest changed while it was being read: {}",
                        path.display()
                    ),
                )
                .retryable(true))
            }
            Some(_) => Err(error),
        },
    }
}

async fn remove_matching_pending(
    pending: &Path,
    expected: &AgentVmAttachmentManifest,
) -> Result<()> {
    if let Some(retained) = read_manifest_if_present(pending).await? {
        if retained != *expected {
            return Err(manifest_conflict());
        }
        remove_private_file_if_present(pending).await?;
    }
    Ok(())
}

fn manifest_conflict() -> Error {
    attachment_error(
        ErrorCode::Conflict,
        "KVM attachment transport manifest differs from the requested Create",
    )
}

async fn read_manifest(path: &Path) -> Result<AgentVmAttachmentManifest> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect KVM attachment transport manifest {}: {error}",
                path.display()
            ),
        )
    })?;
    if !is_private_file(&metadata)
        || metadata.len() == 0
        || metadata.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES as u64
    {
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "KVM attachment transport manifest is not a bounded private file: {}",
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
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open KVM attachment transport manifest {}: {error}",
                    path.display()
                ),
            )
        })?
        .take((AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| {
            attachment_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read KVM attachment transport manifest {}: {error}",
                    path.display()
                ),
            )
        })?;
    AgentVmAttachmentManifest::from_bytes(&encoded).map_err(|error| {
        attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "invalid KVM attachment transport manifest {}: {error}",
                path.display()
            ),
        )
    })
}

async fn ensure_absent(final_path: &Path, pending_path: &Path) -> Result<()> {
    for path in [final_path, pending_path] {
        if path_metadata(path).await?.is_some() {
            return Err(attachment_error(
                ErrorCode::Conflict,
                format!(
                    "a Create without KVM attachments found stale transport evidence: {}",
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
        return Err(attachment_error(
            ErrorCode::FailedPrecondition,
            format!(
                "refusing to remove non-private KVM evidence: {}",
                path.display()
            ),
        ));
    }
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(attachment_error(
                ErrorCode::Internal,
                format!("failed to remove {}: {error}", path.display()),
            ));
        }
    }
    let parent = path.parent().ok_or_else(|| {
        attachment_error(
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
            attachment_error(
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
            attachment_error(
                ErrorCode::Internal,
                format!("failed to sync directory {}: {error}", path.display()),
            )
        })
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn attachment_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-kvm-vm-attachments")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use a3s_oci_agent_protocol::{AgentVmMacAddress, AgentVmNetworkAttachment, GuestPath};
    use a3s_oci_sdk::{
        oci_spec::runtime::Spec, ContainerId, ContainerTarget, CreateAttachments, Generation,
        NetworkAttachmentIdentity, NetworkCleanup, NetworkCleanupId, NetworkInterfaceId,
        NetworkNamespaceId, OciBundle, ProcessIo, StorageAccessMode, StorageAttachmentId,
        StorageCleanup, StorageOwnership,
    };
    use serde_json::json;

    use super::{
        ensure_absent, manifest_conflict, persist_manifest, prepare, publish_manifest,
        read_manifest, AgentVmAttachmentManifest, ErrorCode, UtilityVmLaunchRequest,
        AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME, PENDING_MANIFEST_FILE_NAME,
    };

    fn manifest(generation: u64) -> AgentVmAttachmentManifest {
        let mut value = serde_json::to_value(Spec::default()).expect("default OCI spec");
        value["linux"] = json!({
            "namespaces": [{"type": "network"}, {"type": "uts"}],
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
            Vec::new(),
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

    #[tokio::test]
    async fn partial_pending_manifest_is_discarded_as_legacy_interruption() {
        let temporary = tempfile::tempdir().expect("temporary runtime share");
        let pending_path = temporary.path().join(PENDING_MANIFEST_FILE_NAME);
        std::fs::write(&pending_path, br#"{"target":"partial""#)
            .expect("write partial pending manifest");
        std::fs::set_permissions(&pending_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect partial pending manifest");

        persist_manifest(temporary.path(), &manifest(1))
            .await
            .expect("discard legacy partial pending manifest");
        assert!(!pending_path.exists());
        assert!(temporary
            .path()
            .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME)
            .exists());
    }

    #[tokio::test]
    async fn no_replace_manifest_publication_preserves_an_incumbent() {
        let temporary = tempfile::tempdir().expect("temporary runtime share");
        let final_path = temporary
            .path()
            .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME);
        let pending_path = temporary.path().join(PENDING_MANIFEST_FILE_NAME);
        let incumbent = manifest(2);
        let expected = manifest(1);
        let incumbent_bytes = incumbent.to_bytes().expect("encode incumbent");
        let expected_bytes = expected.to_bytes().expect("encode expected");
        std::fs::write(&final_path, &incumbent_bytes).expect("write incumbent");
        std::fs::write(&pending_path, &expected_bytes).expect("write pending");
        for path in [&final_path, &pending_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("protect manifest");
        }

        let error = publish_manifest(temporary.path(), &pending_path, &final_path, &expected)
            .await
            .expect_err("occupied manifest must not be replaced");
        assert_eq!(error, manifest_conflict());
        assert_eq!(
            std::fs::read(&final_path).expect("read incumbent"),
            incumbent_bytes
        );
        assert_eq!(
            std::fs::read(&pending_path).expect("read pending"),
            expected_bytes
        );
    }

    #[tokio::test]
    async fn concurrent_manifest_persistence_publishes_one_complete_file() {
        let temporary = tempfile::tempdir().expect("temporary runtime share");
        let expected = manifest(1);
        let mut calls = Vec::new();
        for _ in 0..16 {
            let root = temporary.path().to_path_buf();
            let expected = expected.clone();
            calls.push(tokio::spawn(async move {
                persist_manifest(&root, &expected).await
            }));
        }
        for call in calls {
            call.await
                .expect("manifest task must not panic")
                .expect("concurrent manifest persistence must succeed");
        }

        assert_eq!(
            read_manifest(
                &temporary
                    .path()
                    .join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME)
            )
            .await
            .expect("read concurrent manifest"),
            expected
        );
        let mut entries = tokio::fs::read_dir(temporary.path())
            .await
            .expect("enumerate manifest root");
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.expect("read manifest entry") {
            names.push(entry.file_name());
        }
        assert_eq!(
            names,
            vec![std::ffi::OsString::from(
                AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME
            )]
        );
    }

    #[tokio::test]
    async fn prepares_caller_owned_raw_storage_without_absorbing_its_image() {
        let temporary = tempfile::tempdir().expect("temporary KVM storage fixture");
        let runtime_share = temporary.path().join("share");
        let bundle_directory = runtime_share.join("bundle");
        std::fs::create_dir_all(bundle_directory.join("rootfs")).expect("bundle rootfs");
        std::fs::create_dir(runtime_share.join("run")).expect("runtime state");
        let image = temporary.path().join("caller-owned.raw");
        let image_file = std::fs::File::create(&image).expect("raw image");
        image_file.set_len(4096).expect("aligned raw image");
        drop(image_file);

        let mut value = serde_json::to_value(Spec::default()).expect("default OCI spec");
        value["root"] = json!({"path": "rootfs", "readonly": false});
        value["mounts"] = json!([{
            "destination": "/data",
            "type": "ext4",
            "source": image.to_str().expect("UTF-8 image path"),
            "options": ["ro", "nodev"]
        }]);
        let bundle = OciBundle::from_json(
            bundle_directory,
            serde_json::to_string(&value).expect("storage config"),
        )
        .expect("storage bundle");
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("base attachments")
            .attach_storage_mount(
                &bundle,
                0,
                StorageAttachmentId::new("raw-volume-7").expect("storage identity"),
                StorageAccessMode::ReadOnly,
                StorageOwnership::Caller,
                StorageCleanup::DetachOnly,
            )
            .expect("storage attachments");
        let target = ContainerTarget::exact(
            ContainerId::new("stored").expect("container ID"),
            Generation(1),
        );
        let guest_bundle = GuestPath::new("/run/a3s-oci-runtime/bundle").unwrap();
        let digest = prepare(&UtilityVmLaunchRequest {
            target: &target,
            runtime_share: &runtime_share,
            bundle: &bundle,
            guest_bundle: &guest_bundle,
            attachment_contract: &attachments,
        })
        .await
        .expect("prepare storage manifest")
        .expect("manifest digest");

        let manifest = read_manifest(&runtime_share.join(AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME))
            .await
            .expect("persisted storage manifest");
        assert_eq!(manifest.digest().unwrap(), digest);
        assert_eq!(manifest.storage().len(), 1);
        assert_eq!(manifest.storage()[0].host_source(), image.to_str().unwrap());
        assert_eq!(manifest.storage()[0].source_identity().size(), 4096);
        assert!(image.exists(), "caller-owned raw image must be preserved");

        std::fs::hard_link(&image, temporary.path().join("image-alias.raw"))
            .expect("hard-link alias");
        let error = prepare(&UtilityVmLaunchRequest {
            target: &target,
            runtime_share: &runtime_share,
            bundle: &bundle,
            guest_bundle: &guest_bundle,
            attachment_contract: &attachments,
        })
        .await
        .expect_err("hard-linked raw image must fail closed");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn rejects_storage_images_inside_the_runtime_owned_share() {
        let temporary = tempfile::tempdir().expect("temporary KVM storage fixture");
        let runtime_share = temporary.path().join("share");
        let bundle_directory = runtime_share.join("bundle");
        std::fs::create_dir_all(bundle_directory.join("rootfs")).expect("bundle rootfs");
        std::fs::create_dir(runtime_share.join("run")).expect("runtime state");
        let image = runtime_share.join("owned.raw");
        let image_file = std::fs::File::create(&image).expect("raw image");
        image_file.set_len(4096).expect("aligned image");
        drop(image_file);
        let mut value = serde_json::to_value(Spec::default()).expect("default OCI spec");
        value["root"] = json!({"path": "rootfs", "readonly": false});
        value["mounts"] = json!([{
            "destination": "/data",
            "type": "ext4",
            "source": image.to_str().unwrap(),
            "options": ["rw"]
        }]);
        let bundle = OciBundle::from_json(bundle_directory, value.to_string()).unwrap();
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .unwrap()
            .attach_storage_mount(
                &bundle,
                0,
                StorageAttachmentId::new("owned-volume").unwrap(),
                StorageAccessMode::ReadWrite,
                StorageOwnership::Caller,
                StorageCleanup::DetachOnly,
            )
            .unwrap();
        let target = ContainerTarget::exact(ContainerId::new("stored").unwrap(), Generation(1));
        let guest_bundle = GuestPath::new("/run/a3s-oci-runtime/bundle").unwrap();

        let error = prepare(&UtilityVmLaunchRequest {
            target: &target,
            runtime_share: &runtime_share,
            bundle: &bundle,
            guest_bundle: &guest_bundle,
            attachment_contract: &attachments,
        })
        .await
        .expect_err("runtime-owned image must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }
}
