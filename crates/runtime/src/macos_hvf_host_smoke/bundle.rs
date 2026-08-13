use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use a3s_oci_sdk::{
    runtime_bundle_handoff_directory, ContainerId, CreateAttachments, OciBundle, OperationId,
    ProcessIo, RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
};
use serde_json::Value;
use tokio::process::Command;

pub(super) struct StagedBundle {
    pub(super) bundle: OciBundle,
    pub(super) attachments: CreateAttachments,
    pub(super) directory: PathBuf,
}

pub(super) async fn stage(
    source: &Path,
    runtime_root: &Path,
    container_id: &ContainerId,
    operation_id: &OperationId,
) -> Result<StagedBundle, String> {
    let source = canonical_plain_directory(source, "source OCI bundle").await?;
    let destination = runtime_bundle_handoff_directory(runtime_root, container_id, operation_id)
        .map_err(|error| format!("failed to resolve bundle handoff path: {error}"))?;
    create_private_ancestors(runtime_root, &destination)?;

    let status = Command::new("/usr/bin/ditto")
        .arg("--rsrc")
        .arg("--extattr")
        .arg("--acl")
        .arg(&source)
        .arg(&destination)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .map_err(|error| format!("failed to execute ditto for bundle handoff: {error}"))?;
    if !status.success() {
        return Err(format!(
            "ditto failed to stage bundle handoff with status {status}"
        ));
    }
    protect_bundle_root(&destination)?;
    write_handoff_annotation(&destination.join("config.json"))?;
    let bundle = OciBundle::load(&destination)
        .await
        .map_err(|error| format!("failed to load staged bundle handoff: {error}"))?;
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
        .and_then(|attachments| attachments.with_runtime_bundle_handoff(&bundle))
        .map_err(|error| format!("failed to derive bundle handoff attachments: {error}"))?;
    Ok(StagedBundle {
        bundle,
        attachments,
        directory: destination,
    })
}

fn create_private_ancestors(runtime_root: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "bundle handoff destination has no parent".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create bundle handoff ancestors {}: {error}",
            parent.display()
        )
    })?;
    let mut current = Some(parent);
    while let Some(path) = current {
        if path == runtime_root {
            break;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                format!(
                    "failed to protect bundle handoff path {}: {error}",
                    path.display()
                )
            },
        )?;
        current = path.parent();
    }
    Ok(())
}

fn protect_bundle_root(bundle: &Path) -> Result<(), String> {
    std::fs::set_permissions(bundle, std::fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "failed to protect staged bundle {}: {error}",
            bundle.display()
        )
    })?;
    std::fs::set_permissions(
        bundle.join("config.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .map_err(|error| format!("failed to protect staged config.json: {error}"))
}

fn write_handoff_annotation(config: &Path) -> Result<(), String> {
    let bytes = std::fs::read(config).map_err(|error| {
        format!(
            "failed to read staged config.json {}: {error}",
            config.display()
        )
    })?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("failed to decode staged config.json: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "staged config.json root is not an object".to_string())?;
    let annotations = object
        .entry("annotations")
        .or_insert_with(|| Value::Object(Default::default()))
        .as_object_mut()
        .ok_or_else(|| "staged config.json annotations are not an object".to_string())?;
    annotations.insert(
        RUNTIME_BUNDLE_HANDOFF_EXTENSION.to_string(),
        Value::String(RUNTIME_BUNDLE_HANDOFF_MOVE_V1.to_string()),
    );
    let mut encoded = serde_json::to_vec_pretty(&value)
        .map_err(|error| format!("failed to encode staged config.json: {error}"))?;
    encoded.push(b'\n');

    let pending = config.with_extension("json.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&pending)
        .map_err(|error| format!("failed to create staged config pending file: {error}"))?;
    use std::io::Write;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist staged config.json: {error}"))?;
    drop(file);
    std::fs::rename(&pending, config)
        .map_err(|error| format!("failed to publish staged config.json: {error}"))
}

async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} is not a plain directory: {}",
            path.display()
        ));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "{label} must be an absolute canonical path: {} -> {}",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}
