//! Prepare operation-scoped OCI bundle handoff for DedicatedVm creates.
//!
//! Utility-VM Hosts only accept bundles under
//! `bundle-handoffs/<container>/<create-operation>/bundle` with the
//! `dev.a3s.bundle-handoff=move-to-runtime-v1` annotation. containerd's task
//! bundle is caller-owned; this module materializes a private copy at the exact
//! handoff path before Create is dispatched.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{
    runtime_bundle_handoff_directory, ContainerId, CreateAttachments, Error, ErrorCode,
    IsolationRequest, OciBundle, OperationContext, ProcessIo, Result,
    RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};

const RUNTIME_ROOT_ENV: &str = "A3S_OCI_RUNTIME_ROOT";

pub(crate) fn requires_bundle_handoff(isolation: &IsolationRequest) -> bool {
    matches!(
        isolation,
        IsolationRequest::DedicatedVm | IsolationRequest::SharedGuestKernel { .. }
    )
}

pub(crate) async fn materialize_for_create(
    isolation: &IsolationRequest,
    container_id: &ContainerId,
    context: &OperationContext,
    source_bundle: &Path,
    io: ProcessIo,
) -> Result<(OciBundle, CreateAttachments)> {
    if !requires_bundle_handoff(isolation) {
        let bundle = OciBundle::load(source_bundle).await?;
        let attachments = CreateAttachments::from_bundle(&bundle, io)?;
        return Ok((bundle, attachments));
    }

    let runtime_root = runtime_root_from_environment()?;
    let handoff =
        runtime_bundle_handoff_directory(&runtime_root, container_id, &context.operation_id)?;
    prepare_private_handoff_tree(&runtime_root, &handoff).await?;
    copy_portable_bundle(source_bundle, &handoff).await?;
    write_handoff_config(source_bundle, &handoff).await?;

    let bundle = OciBundle::load(&handoff).await?;
    let attachments =
        CreateAttachments::from_bundle(&bundle, io)?.with_runtime_bundle_handoff(&bundle)?;
    Ok((bundle, attachments))
}

fn runtime_root_from_environment() -> Result<PathBuf> {
    let raw = std::env::var_os(RUNTIME_ROOT_ENV).ok_or_else(|| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "DedicatedVm containerd create requires {RUNTIME_ROOT_ENV} to match the Host driver runtime root (KVM: <service --root>/runtime)"
            ),
        )
    })?;
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(handoff_error(
            ErrorCode::InvalidArgument,
            format!(
                "{RUNTIME_ROOT_ENV} must be an absolute path: {}",
                path.display()
            ),
        ));
    }
    // Host stores the exact --root string; handoff validation rejects aliases.
    Ok(path)
}

async fn prepare_private_handoff_tree(runtime_root: &Path, handoff_bundle: &Path) -> Result<()> {
    let relative = handoff_bundle.strip_prefix(runtime_root).map_err(|_| {
        handoff_error(
            ErrorCode::Internal,
            format!(
                "bundle handoff {} is outside runtime root {}",
                handoff_bundle.display(),
                runtime_root.display()
            ),
        )
    })?;
    let mut current = runtime_root.to_path_buf();
    ensure_private_directory(&current).await?;
    for component in relative.components() {
        current.push(component);
        if tokio::fs::metadata(&current).await.is_err() {
            tokio::fs::create_dir(&current).await.map_err(|error| {
                handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "failed to create bundle handoff directory {}: {error}",
                        current.display()
                    ),
                )
                .retryable(true)
            })?;
        }
        ensure_private_directory(&current).await?;
    }
    Ok(())
}

async fn ensure_private_directory(path: &Path) -> Result<()> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect bundle handoff directory {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(handoff_error(
            ErrorCode::FailedPrecondition,
            format!(
                "bundle handoff path must be a real directory: {}",
                path.display()
            ),
        ));
    }
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to set mode 0700 on bundle handoff directory {}: {error}",
                    path.display()
                ),
            )
        })?;
    Ok(())
}

async fn copy_portable_bundle(source_bundle: &Path, destination: &Path) -> Result<()> {
    let source_rootfs = source_bundle.join("rootfs");
    let destination_rootfs = destination.join("rootfs");
    if tokio::fs::metadata(&destination_rootfs).await.is_ok() {
        tokio::fs::remove_dir_all(&destination_rootfs)
            .await
            .map_err(|error| {
                handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "failed to clear previous handoff rootfs {}: {error}",
                        destination_rootfs.display()
                    ),
                )
                .retryable(true)
            })?;
    }
    // containerd mounts the task rootfs before Create; copy the mounted tree.
    let status = tokio::process::Command::new("cp")
        .args(["-a", "--"])
        .arg(&source_rootfs)
        .arg(&destination_rootfs)
        .status()
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to copy containerd rootfs {} into handoff {}: {error}",
                    source_rootfs.display(),
                    destination_rootfs.display()
                ),
            )
            .retryable(true)
        })?;
    if !status.success() {
        return Err(handoff_error(
            ErrorCode::Unavailable,
            format!(
                "cp -a failed while preparing handoff rootfs from {} to {}",
                source_rootfs.display(),
                destination_rootfs.display()
            ),
        )
        .retryable(true));
    }
    ensure_private_directory(&destination_rootfs).await?;
    Ok(())
}

async fn write_handoff_config(source_bundle: &Path, destination: &Path) -> Result<()> {
    let source_config = source_bundle.join("config.json");
    let bytes = tokio::fs::read(&source_config).await.map_err(|error| {
        handoff_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to read containerd OCI config {}: {error}",
                source_config.display()
            ),
        )
    })?;
    let mut document: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        handoff_error(
            ErrorCode::InvalidArgument,
            format!(
                "invalid containerd OCI config {}: {error}",
                source_config.display()
            ),
        )
    })?;
    project_containerd_spec_for_dedicated_vm(&mut document)?;
    let annotations = document
        .as_object_mut()
        .ok_or_else(|| {
            handoff_error(
                ErrorCode::InvalidArgument,
                "OCI config must be a JSON object",
            )
        })?
        .entry("annotations")
        .or_insert_with(|| serde_json::json!({}));
    let annotations = annotations.as_object_mut().ok_or_else(|| {
        handoff_error(
            ErrorCode::InvalidArgument,
            "OCI config annotations must be a JSON object",
        )
    })?;
    annotations.insert(
        RUNTIME_BUNDLE_HANDOFF_EXTENSION.to_string(),
        serde_json::Value::String(RUNTIME_BUNDLE_HANDOFF_MOVE_V1.to_string()),
    );
    let encoded = serde_json::to_vec_pretty(&document).map_err(|error| {
        handoff_error(
            ErrorCode::Internal,
            format!("failed to encode handoff OCI config: {error}"),
        )
    })?;
    let config_path = destination.join("config.json");
    {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&config_path)
            .await
            .map_err(|error| {
                handoff_error(
                    ErrorCode::Unavailable,
                    format!(
                        "failed to create handoff OCI config {}: {error}",
                        config_path.display()
                    ),
                )
                .retryable(true)
            })?;
        use tokio::io::AsyncWriteExt;
        file.write_all(&encoded).await.map_err(|error| {
            handoff_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to write handoff OCI config {}: {error}",
                    config_path.display()
                ),
            )
            .retryable(true)
        })?;
        file.flush().await.map_err(|error| {
            handoff_error(
                ErrorCode::Unavailable,
                format!(
                    "failed to flush handoff OCI config {}: {error}",
                    config_path.display()
                ),
            )
            .retryable(true)
        })?;
    }
    tokio::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|error| {
            handoff_error(
                ErrorCode::PermissionDenied,
                format!(
                    "failed to set mode 0600 on handoff OCI config {}: {error}",
                    config_path.display()
                ),
            )
        })?;
    Ok(())
}

/// Project a containerd-generated host Spec onto the DedicatedVm guest contract.
///
/// containerd injects default mounts and an absolute `linux.cgroupsPath` aimed at
/// SharedHostKernel. The KVM guest kernel (libkrunfw) does not advertise POSIX
/// message queues, and guest cgroup authority is delegated by the Agent — absolute
/// host paths must become relative identities. Caller-requested bind mounts are
/// preserved; only known host-default filesystem types are dropped.
fn project_containerd_spec_for_dedicated_vm(document: &mut serde_json::Value) -> Result<()> {
    let root = document.as_object_mut().ok_or_else(|| {
        handoff_error(
            ErrorCode::InvalidArgument,
            "OCI config must be a JSON object",
        )
    })?;
    if let Some(mounts) = root
        .get_mut("mounts")
        .and_then(|value| value.as_array_mut())
    {
        mounts.retain(|mount| {
            !matches!(
                mount.get("type").and_then(|value| value.as_str()),
                Some("mqueue" | "cgroup" | "cgroup2")
            )
        });
    }
    if let Some(linux) = root
        .get_mut("linux")
        .and_then(|value| value.as_object_mut())
    {
        if let Some(path) = linux.get("cgroupsPath").and_then(|value| value.as_str()) {
            let relative = path.trim_start_matches('/');
            if relative.is_empty() {
                linux.remove("cgroupsPath");
            } else if relative != path {
                linux.insert(
                    "cgroupsPath".to_string(),
                    serde_json::Value::String(relative.to_string()),
                );
            }
        }
    }
    Ok(())
}

fn handoff_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("containerd-bundle-handoff")
}

#[cfg(test)]
mod tests {
    use super::{materialize_for_create, requires_bundle_handoff, RUNTIME_ROOT_ENV};
    use a3s_oci_sdk::{
        ContainerId, IsolationRequest, OperationContext, OperationId, ProcessIo,
        RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    #[test]
    fn dedicated_vm_requires_handoff_shared_host_does_not() {
        assert!(requires_bundle_handoff(&IsolationRequest::DedicatedVm));
        assert!(!requires_bundle_handoff(
            &IsolationRequest::SharedHostKernel
        ));
    }

    #[tokio::test]
    async fn shared_host_uses_caller_bundle_without_handoff_annotation() {
        let source = tempfile::tempdir().expect("source");
        write_source_bundle(source.path()).await;
        let (bundle, attachments) = materialize_for_create(
            &IsolationRequest::SharedHostKernel,
            &ContainerId::new("ctr-host").expect("id"),
            &OperationContext::new(OperationId::new("create-host").expect("op")),
            source.path(),
            ProcessIo::default(),
        )
        .await
        .expect("shared host create");
        assert_eq!(
            bundle.directory(),
            tokio::fs::canonicalize(source.path())
                .await
                .expect("canonical source")
        );
        assert!(!attachments.uses_runtime_bundle_handoff());
    }

    #[tokio::test]
    async fn dedicated_vm_handoff_requires_root_env_and_materializes_path() {
        // Keep env mutations serialized inside one test so parallel workers cannot
        // race on process-global A3S_OCI_RUNTIME_ROOT.
        let previous = std::env::var_os(RUNTIME_ROOT_ENV);
        std::env::remove_var(RUNTIME_ROOT_ENV);
        let source = tempfile::tempdir().expect("source");
        write_source_bundle(source.path()).await;
        let missing = materialize_for_create(
            &IsolationRequest::DedicatedVm,
            &ContainerId::new("ctr-1").expect("id"),
            &OperationContext::new(OperationId::new("create-1").expect("op")),
            source.path(),
            ProcessIo::default(),
        )
        .await
        .expect_err("missing runtime root must fail");
        assert_eq!(missing.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);

        let runtime_root = tempfile::tempdir().expect("runtime root");
        std::fs::set_permissions(runtime_root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        std::env::set_var(RUNTIME_ROOT_ENV, runtime_root.path());

        let container = ContainerId::new("ctr-vm").expect("id");
        let context = OperationContext::new(OperationId::new("create-vm").expect("op"));
        let (bundle, attachments) = materialize_for_create(
            &IsolationRequest::DedicatedVm,
            &container,
            &context,
            source.path(),
            ProcessIo::default(),
        )
        .await
        .expect("dedicated vm handoff");

        let expected = tokio::fs::canonicalize(
            runtime_root
                .path()
                .join("bundle-handoffs")
                .join(container.as_str())
                .join(context.operation_id.as_str())
                .join("bundle"),
        )
        .await
        .expect("canonical handoff");
        assert_eq!(bundle.directory(), expected);
        assert!(attachments.uses_runtime_bundle_handoff());
        let config = tokio::fs::read_to_string(expected.join("config.json"))
            .await
            .expect("config");
        assert!(config.contains(RUNTIME_BUNDLE_HANDOFF_EXTENSION));
        assert!(config.contains(RUNTIME_BUNDLE_HANDOFF_MOVE_V1));
        assert!(expected.join("rootfs/marker").is_file());
        assert!(!config.contains("mqueue"));
        assert!(!config.contains("\"/default/"));
        assert!(config.contains("default/guest-cgroup"));

        match previous {
            Some(value) => std::env::set_var(RUNTIME_ROOT_ENV, value),
            None => std::env::remove_var(RUNTIME_ROOT_ENV),
        }
    }

    async fn write_source_bundle(path: &Path) {
        let rootfs = path.join("rootfs");
        tokio::fs::create_dir_all(&rootfs).await.expect("rootfs");
        tokio::fs::write(rootfs.join("marker"), b"ok")
            .await
            .expect("marker");
        let config = serde_json::json!({
            "ociVersion": "1.0.2",
            "root": { "path": "rootfs" },
            "process": {
                "cwd": "/",
                "args": ["true"],
                "user": { "uid": 0, "gid": 0 }
            },
            "mounts": [
                {
                    "destination": "/proc",
                    "type": "proc",
                    "source": "proc",
                    "options": ["nosuid", "noexec", "nodev"]
                },
                {
                    "destination": "/dev/mqueue",
                    "type": "mqueue",
                    "source": "mqueue",
                    "options": ["nosuid", "noexec", "nodev"]
                },
                {
                    "destination": "/sys/fs/cgroup",
                    "type": "cgroup2",
                    "source": "cgroup",
                    "options": ["nosuid", "noexec", "nodev"]
                }
            ],
            "linux": {
                "cgroupsPath": "/default/guest-cgroup",
                "namespaces": [{ "type": "mount" }]
            },
            "annotations": {}
        });
        tokio::fs::write(
            path.join("config.json"),
            serde_json::to_vec_pretty(&config).expect("encode"),
        )
        .await
        .expect("config");
    }
}
