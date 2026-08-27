use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, GuestSessionAttachment, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::layout::{
    is_private_file, path_metadata, remove_directory_if_empty, PRIVATE_FILE_MODE,
    REUSABLE_GUEST_SESSION_DIRECTORY,
};

const MARKER_FILE: &str = ".a3s-oci-guest-session.json";
const PENDING_MARKER_FILE: &str = ".a3s-oci-guest-session.pending";
const MARKER_SCHEMA: &str = "a3s.oci.guest-session.v1";
const MAX_MARKER_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestSessionMarker {
    schema_version: String,
    attachment: GuestSessionAttachment,
}

pub(super) async fn ensure(session_root: &Path, attachment: &GuestSessionAttachment) -> Result<()> {
    let marker_path = session_root.join(MARKER_FILE);
    let expected = GuestSessionMarker {
        schema_version: MARKER_SCHEMA.to_string(),
        attachment: attachment.clone(),
    };
    if path_metadata(&marker_path).await?.is_some() {
        let retained = read(&marker_path).await?;
        if retained != expected {
            return Err(session_error(
                ErrorCode::Conflict,
                format!(
                    "reusable guest-session incarnation {} generation {} differs from its retained ownership marker",
                    attachment.id(),
                    attachment.generation()
                ),
            ));
        }
        remove_private_file_if_present(&session_root.join(PENDING_MARKER_FILE)).await?;
        return Ok(());
    }

    let encoded = serde_json::to_vec(&expected).map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!("failed to encode reusable guest-session marker: {error}"),
        )
    })?;
    if encoded.len() > MAX_MARKER_BYTES {
        return Err(session_error(
            ErrorCode::Internal,
            "reusable guest-session marker exceeds its fixed bound",
        ));
    }
    let pending = session_root.join(PENDING_MARKER_FILE);
    remove_private_file_if_present(&pending).await?;
    let mut options = tokio::fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&pending).await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to create reusable guest-session marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.write_all(&encoded).await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to write reusable guest-session marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.flush().await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to flush reusable guest-session marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    file.sync_all().await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to sync reusable guest-session marker {}: {error}",
                pending.display()
            ),
        )
    })?;
    drop(file);
    tokio::fs::rename(&pending, &marker_path)
        .await
        .map_err(|error| {
            session_error(
                ErrorCode::Internal,
                format!(
                    "failed to commit reusable guest-session marker {}: {error}",
                    marker_path.display()
                ),
            )
        })?;
    sync_directory(session_root).await
}

pub(super) async fn validate(
    session_root: &Path,
    attachment: &GuestSessionAttachment,
) -> Result<()> {
    let marker = read(&session_root.join(MARKER_FILE)).await?;
    if marker.attachment != *attachment {
        return Err(session_error(
            ErrorCode::Conflict,
            format!(
                "reusable guest-session incarnation {} generation {} differs from its retained ownership marker",
                attachment.id(),
                attachment.generation()
            ),
        ));
    }
    Ok(())
}

/// Remove an empty, unmounted session incarnation and its ownership marker.
///
/// Unknown entries mean another exact member still owns the root, so this is
/// deliberately a no-op rather than a recursive removal.
pub(super) async fn remove_if_empty(
    runtime_share_root: &Path,
    session_root: &Path,
    attachment: &GuestSessionAttachment,
) -> Result<bool> {
    validate_root_identity(runtime_share_root, session_root, attachment)?;
    validate(session_root, attachment).await?;
    let mut entries = tokio::fs::read_dir(session_root).await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to enumerate reusable guest-session root {}: {error}",
                session_root.display()
            ),
        )
    })?;
    while let Some(entry) = entries.next_entry().await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to enumerate reusable guest-session root {}: {error}",
                session_root.display()
            ),
        )
    })? {
        let name = entry.file_name();
        if name != MARKER_FILE && name != PENDING_MARKER_FILE {
            return Ok(false);
        }
    }
    drop(entries);

    remove_private_file_if_present(&session_root.join(PENDING_MARKER_FILE)).await?;
    remove_private_file_if_present(&session_root.join(MARKER_FILE)).await?;
    sync_directory(session_root).await?;

    let session_id_root = session_root
        .parent()
        .expect("validated session root has an identity parent")
        .to_path_buf();
    let reusable_root = session_id_root
        .parent()
        .expect("validated session identity has a namespace parent")
        .to_path_buf();
    remove_directory_if_empty(session_root).await?;
    remove_directory_if_empty(&session_id_root).await?;
    remove_directory_if_empty(&reusable_root).await?;
    Ok(true)
}

async fn read(path: &Path) -> Result<GuestSessionMarker> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        session_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect reusable guest-session marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if !is_private_file(&metadata) || metadata.len() > MAX_MARKER_BYTES as u64 {
        return Err(session_error(
            ErrorCode::FailedPrecondition,
            format!(
                "reusable guest-session marker is not a bounded private file: {}",
                path.display()
            ),
        ));
    }
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            session_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open reusable guest-session marker {}: {error}",
                    path.display()
                ),
            )
        })?
        .take((MAX_MARKER_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .await
        .map_err(|error| {
            session_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read reusable guest-session marker {}: {error}",
                    path.display()
                ),
            )
        })?;
    let marker: GuestSessionMarker = serde_json::from_slice(&encoded).map_err(|error| {
        session_error(
            ErrorCode::FailedPrecondition,
            format!(
                "invalid reusable guest-session marker {}: {error}",
                path.display()
            ),
        )
    })?;
    if marker.schema_version != MARKER_SCHEMA {
        return Err(session_error(
            ErrorCode::FailedPrecondition,
            format!(
                "unsupported reusable guest-session marker schema in {}",
                path.display()
            ),
        ));
    }
    Ok(marker)
}

fn validate_root_identity(
    runtime_share_root: &Path,
    session_root: &Path,
    attachment: &GuestSessionAttachment,
) -> Result<()> {
    let expected_generation = attachment.generation().get().to_string();
    let Some(session_id_root) = session_root.parent() else {
        return Err(invalid_root(session_root));
    };
    let Some(reusable_root) = session_id_root.parent() else {
        return Err(invalid_root(session_root));
    };
    if reusable_root.parent() != Some(runtime_share_root)
        || reusable_root.file_name().and_then(|name| name.to_str())
            != Some(REUSABLE_GUEST_SESSION_DIRECTORY)
        || session_id_root.file_name().and_then(|name| name.to_str())
            != Some(attachment.id().as_str())
        || session_root.file_name().and_then(|name| name.to_str())
            != Some(expected_generation.as_str())
    {
        return Err(invalid_root(session_root));
    }
    Ok(())
}

fn invalid_root(path: &Path) -> Error {
    session_error(
        ErrorCode::FailedPrecondition,
        format!(
            "reusable guest-session root escaped its exact incarnation path: {}",
            path.display()
        ),
    )
}

async fn remove_private_file_if_present(path: &Path) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    if !is_private_file(&metadata) {
        return Err(session_error(
            ErrorCode::FailedPrecondition,
            format!("refusing to remove a non-private file: {}", path.display()),
        ));
    }
    tokio::fs::remove_file(path).await.map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!("failed to remove {}: {error}", path.display()),
        )
    })
}

async fn sync_directory(path: &Path) -> Result<()> {
    tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            session_error(
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
            session_error(
                ErrorCode::Internal,
                format!("failed to sync directory {}: {error}", path.display()),
            )
        })
}

fn session_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("manage-utility-vm-guest-session")
}
