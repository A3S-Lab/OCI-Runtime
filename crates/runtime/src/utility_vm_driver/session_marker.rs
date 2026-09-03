use std::io;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, GuestSessionAttachment, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use super::atomic_publication;
use super::layout::{
    is_private_file, path_metadata, remove_directory_if_empty, REUSABLE_GUEST_SESSION_DIRECTORY,
};

const MARKER_FILE: &str = ".a3s-oci-guest-session.json";
const PENDING_MARKER_FILE: &str = ".a3s-oci-guest-session.pending";
const STAGING_MARKER_PREFIX: &str = ".a3s-oci-guest-session.pending.";
const MARKER_SCHEMA: &str = "a3s.oci.guest-session.v1";
const MAX_MARKER_BYTES: usize = 4 * 1024;
const PUBLISH_ATTEMPTS: usize = atomic_publication::PUBLISH_ATTEMPTS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GuestSessionMarker {
    schema_version: String,
    attachment: GuestSessionAttachment,
}

pub(super) async fn ensure(session_root: &Path, attachment: &GuestSessionAttachment) -> Result<()> {
    let marker_path = session_root.join(MARKER_FILE);
    let pending = session_root.join(PENDING_MARKER_FILE);
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
        remove_matching_pending(&pending, &expected).await?;
        sync_directory(session_root).await?;
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
    for attempt in 0..PUBLISH_ATTEMPTS {
        match create_or_reuse_pending(session_root, &pending, &encoded, &expected).await {
            Err(error) if error.retryable && attempt + 1 < PUBLISH_ATTEMPTS => continue,
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        match publish_marker(session_root, &pending, &marker_path, &expected).await {
            Err(error) if error.retryable && attempt + 1 < PUBLISH_ATTEMPTS => continue,
            result => return result,
        }
    }
    Err(session_error(
        ErrorCode::Unavailable,
        "reusable guest-session marker publication kept losing its concurrent owner",
    )
    .retryable(true))
}

/// Create and publish a complete pending marker without exposing a partially
/// written file under the authoritative name. A pending marker can survive a
/// process crash, so an exact matching file is safe to adopt while a different
/// or malformed file must fail closed.
async fn create_or_reuse_pending(
    session_root: &Path,
    pending: &Path,
    encoded: &[u8],
    expected: &GuestSessionMarker,
) -> Result<()> {
    if path_metadata(pending).await?.is_some() {
        ensure_pending_matches(pending, expected).await?;
        return Ok(());
    }

    let staging = create_complete_staging(session_root, pending, encoded).await?;
    match tokio::fs::hard_link(&staging, pending).await {
        Ok(()) => {
            // The hard link is the first publication of the complete inode.
            // Removing the private staging name leaves only the authoritative
            // pending name; a directory sync makes that publication durable.
            remove_private_file_if_present(&staging).await?;
            sync_directory(session_root).await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Another owner won the no-replace publication race. The staging
            // inode is no longer needed, and the winner's complete pending
            // contract is adopted only after an exact read-back.
            let _ = remove_private_file_if_present(&staging).await;
            ensure_pending_matches(pending, expected).await
        }
        Err(error) => {
            let _ = remove_private_file_if_present(&staging).await;
            Err(session_error(
                ErrorCode::Internal,
                format!(
                    "failed to publish reusable guest-session pending marker {}: {error}",
                    pending.display()
                ),
            ))
        }
    }
}

async fn create_complete_staging(
    session_root: &Path,
    pending: &Path,
    encoded: &[u8],
) -> Result<PathBuf> {
    atomic_publication::create_complete_staging(
        session_root,
        pending,
        encoded,
        STAGING_MARKER_PREFIX,
    )
    .await
    .map_err(|error| {
        session_error(
            ErrorCode::Internal,
            format!(
                "failed to create reusable guest-session marker staging file near {}: {error}",
                pending.display()
            ),
        )
    })
}

async fn ensure_pending_matches(pending: &Path, expected: &GuestSessionMarker) -> Result<()> {
    match read_if_present(pending).await? {
        Some(retained) if retained == *expected => Ok(()),
        Some(_) => Err(marker_conflict(expected)),
        None => Err(session_error(
            ErrorCode::Unavailable,
            format!(
                "reusable guest-session pending marker disappeared before adoption: {}",
                pending.display()
            ),
        )
        .retryable(true)),
    }
}

async fn read_if_present(path: &Path) -> Result<Option<GuestSessionMarker>> {
    let Some(initial_metadata) = path_metadata(path).await? else {
        return Ok(None);
    };
    match read(path).await {
        Ok(retained) => Ok(Some(retained)),
        Err(error) => match path_metadata(path).await? {
            None => Ok(None),
            Some(current_metadata)
                if !atomic_publication::same_file_identity(
                    &initial_metadata,
                    &current_metadata,
                ) =>
            {
                Err(session_error(
                    ErrorCode::Unavailable,
                    format!(
                        "reusable guest-session marker changed while it was being read: {}",
                        path.display()
                    ),
                )
                .retryable(true))
            }
            Some(_) => Err(error),
        },
    }
}

/// Publish a complete marker with no replacement semantics.
///
/// `rename` is intentionally not used here: on Unix it replaces an existing
/// destination, which could let a concurrent owner silently change the trust
/// domain or generation represented by a persisted session root. A hard link
/// publishes the already-synced inode atomically and returns `AlreadyExists`
/// without touching the incumbent marker.
async fn publish_marker(
    session_root: &Path,
    pending: &Path,
    marker_path: &Path,
    expected: &GuestSessionMarker,
) -> Result<()> {
    match tokio::fs::hard_link(pending, marker_path).await {
        Ok(()) => {
            // Validate the destination after publication as well. This keeps
            // a racing replacement of the pending name fail closed instead of
            // allowing a symlink or malformed inode to become authoritative.
            let retained = read(marker_path).await?;
            if retained != *expected {
                return Err(marker_conflict(expected));
            }
            remove_private_file_if_present(pending).await?;
            sync_directory(session_root).await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let retained = read(marker_path).await?;
            if retained != *expected {
                return Err(marker_conflict(expected));
            }
            // Only remove a pending file that carries the same complete
            // contract. A different pending owner remains intact for its own
            // retry and is surfaced as a conflict.
            remove_matching_pending(pending, expected).await?;
            sync_directory(session_root).await
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A concurrent owner may have consumed the pending inode just
            // before this link. Adopt its final marker when available;
            // otherwise the bounded caller loop rebuilds a complete pending
            // inode and retries the publication.
            match read_if_present(marker_path).await? {
                Some(retained) if retained == *expected => sync_directory(session_root).await,
                Some(_) => Err(marker_conflict(expected)),
                None => Err(session_error(
                    ErrorCode::Unavailable,
                    format!(
                        "reusable guest-session pending marker disappeared before publication: {}",
                        pending.display()
                    ),
                )
                .retryable(true)),
            }
        }
        Err(error) => Err(session_error(
            ErrorCode::Internal,
            format!(
                "failed to commit reusable guest-session marker {}: {error}",
                marker_path.display()
            ),
        )),
    }
}

async fn remove_matching_pending(pending: &Path, expected: &GuestSessionMarker) -> Result<()> {
    if let Some(retained) = read_if_present(pending).await? {
        if retained != *expected {
            return Err(marker_conflict(expected));
        }
        remove_private_file_if_present(pending).await?;
    }
    Ok(())
}

fn marker_conflict(expected: &GuestSessionMarker) -> Error {
    session_error(
        ErrorCode::Conflict,
        format!(
            "reusable guest-session incarnation {} generation {} has a different retained marker",
            expected.attachment.id(),
            expected.attachment.generation()
        ),
    )
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
    let (session_id_root, reusable_root) =
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
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
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
    Ok((session_id_root.to_path_buf(), reusable_root.to_path_buf()))
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
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(session_error(
            ErrorCode::Internal,
            format!("failed to remove {}: {error}", path.display()),
        )),
    }
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_sdk::{ErrorCode, GuestSessionAttachment};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    use super::super::layout::PRIVATE_FILE_MODE;
    use super::{
        ensure, marker_conflict, publish_marker, read, validate_root_identity, GuestSessionMarker,
        MARKER_FILE, MARKER_SCHEMA, PENDING_MARKER_FILE, REUSABLE_GUEST_SESSION_DIRECTORY,
    };

    fn attachment() -> GuestSessionAttachment {
        serde_json::from_value(serde_json::json!({
            "id": "marker-session",
            "generation": 7,
            "trustDomain": "marker-domain",
            "isolation": "shared-guest-kernel",
            "capacity": 2,
            "reset": "destroy-on-empty",
            "ownership": "runtime"
        }))
        .expect("valid guest-session attachment")
    }

    fn alternate_attachment() -> GuestSessionAttachment {
        serde_json::from_value(serde_json::json!({
            "id": "marker-session",
            "generation": 7,
            "trustDomain": "different-domain",
            "isolation": "shared-guest-kernel",
            "capacity": 2,
            "reset": "destroy-on-empty",
            "ownership": "runtime"
        }))
        .expect("valid alternate guest-session attachment")
    }

    fn marker(attachment: &GuestSessionAttachment) -> GuestSessionMarker {
        GuestSessionMarker {
            schema_version: MARKER_SCHEMA.to_string(),
            attachment: attachment.clone(),
        }
    }

    async fn write_private_file(path: &Path, bytes: &[u8]) {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .open(path)
            .await
            .expect("create private marker fixture");
        file.write_all(bytes)
            .await
            .expect("write private marker fixture");
        file.sync_all().await.expect("sync private marker fixture");
    }

    #[test]
    fn root_identity_returns_verified_cleanup_ancestors() {
        let root = Path::new("/run/a3s");
        let session = root
            .join(REUSABLE_GUEST_SESSION_DIRECTORY)
            .join("marker-session")
            .join("7");
        let (session_id_root, reusable_root) =
            validate_root_identity(root, &session, &attachment()).expect("valid root identity");
        assert_eq!(
            session_id_root,
            root.join(REUSABLE_GUEST_SESSION_DIRECTORY)
                .join("marker-session")
        );
        assert_eq!(reusable_root, root.join(REUSABLE_GUEST_SESSION_DIRECTORY));
    }

    #[test]
    fn root_identity_rejects_paths_without_verified_ancestors() {
        let error = validate_root_identity(Path::new("/run/a3s"), Path::new("7"), &attachment())
            .expect_err("malformed root must fail closed");
        assert!(error.message.contains("escaped"));
    }

    #[tokio::test]
    async fn ensure_publishes_a_complete_marker_without_a_pending_alias() {
        let temporary = tempdir().expect("temporary marker root");
        let session_root = temporary.path().join("session");
        tokio::fs::create_dir(&session_root)
            .await
            .expect("create session root");

        ensure(&session_root, &attachment())
            .await
            .expect("publish session marker");

        assert_eq!(
            read(&session_root.join(MARKER_FILE))
                .await
                .expect("read published marker"),
            marker(&attachment())
        );
        assert!(!session_root.join(PENDING_MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn pending_marker_contract_drift_is_rejected_without_overwrite() {
        let temporary = tempdir().expect("temporary marker root");
        let session_root = temporary.path().join("session");
        tokio::fs::create_dir(&session_root)
            .await
            .expect("create session root");
        let pending = session_root.join(PENDING_MARKER_FILE);
        let retained = serde_json::to_vec(&marker(&alternate_attachment()))
            .expect("encode alternate pending marker");
        write_private_file(&pending, &retained).await;

        let error = ensure(&session_root, &attachment())
            .await
            .expect_err("different pending marker must fail closed");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert_eq!(
            tokio::fs::read(&pending)
                .await
                .expect("read retained pending"),
            retained
        );
        assert!(!session_root.join(MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn partial_pending_marker_is_rejected_without_replacement() {
        let temporary = tempdir().expect("temporary marker root");
        let session_root = temporary.path().join("session");
        tokio::fs::create_dir(&session_root)
            .await
            .expect("create session root");
        let pending = session_root.join(PENDING_MARKER_FILE);
        let retained = br#"{"schemaVersion":"a3s.oci.guest-session.v1""#;
        write_private_file(&pending, retained).await;

        let error = ensure(&session_root, &attachment())
            .await
            .expect_err("partial pending marker must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            tokio::fs::read(&pending).await.expect("read pending"),
            retained
        );
        assert!(!session_root.join(MARKER_FILE).exists());
    }

    #[tokio::test]
    async fn no_replace_publication_preserves_an_incumbent_marker() {
        let temporary = tempdir().expect("temporary marker root");
        let session_root = temporary.path().join("session");
        tokio::fs::create_dir(&session_root)
            .await
            .expect("create session root");
        let marker_path = session_root.join(MARKER_FILE);
        let pending = session_root.join(PENDING_MARKER_FILE);
        let incumbent =
            serde_json::to_vec(&marker(&alternate_attachment())).expect("encode incumbent marker");
        let candidate = serde_json::to_vec(&marker(&attachment())).expect("encode candidate");
        write_private_file(&marker_path, &incumbent).await;
        write_private_file(&pending, &candidate).await;

        let error = publish_marker(
            &session_root,
            &pending,
            &marker_path,
            &marker(&attachment()),
        )
        .await
        .expect_err("an occupied marker must not be replaced");
        assert_eq!(error, marker_conflict(&marker(&attachment())));
        assert_eq!(
            tokio::fs::read(&marker_path).await.expect("read incumbent"),
            incumbent
        );
        assert_eq!(
            tokio::fs::read(&pending).await.expect("read candidate"),
            candidate
        );
    }

    #[tokio::test]
    async fn matching_incumbent_marker_only_cleans_matching_pending() {
        let temporary = tempdir().expect("temporary marker root");
        let session_root = temporary.path().join("session");
        tokio::fs::create_dir(&session_root)
            .await
            .expect("create session root");
        let marker_path = session_root.join(MARKER_FILE);
        let pending = session_root.join(PENDING_MARKER_FILE);
        let encoded = serde_json::to_vec(&marker(&attachment())).expect("encode marker");
        write_private_file(&marker_path, &encoded).await;
        write_private_file(&pending, &encoded).await;

        ensure(&session_root, &attachment())
            .await
            .expect("reuse matching marker");
        assert!(!pending.exists());
        assert_eq!(
            tokio::fs::read(&marker_path).await.expect("read marker"),
            encoded
        );
    }

    #[tokio::test]
    async fn concurrent_ensure_calls_publish_one_complete_marker() {
        let temporary = tempdir().expect("temporary marker root");
        let session_root = temporary.path().join("session");
        tokio::fs::create_dir(&session_root)
            .await
            .expect("create session root");

        let mut calls = Vec::new();
        for _ in 0..16 {
            let session_root = session_root.clone();
            calls.push(tokio::spawn(async move {
                ensure(&session_root, &attachment()).await
            }));
        }
        for call in calls {
            call.await
                .expect("marker ensure task must not panic")
                .expect("concurrent marker ensure must succeed");
        }

        assert_eq!(
            read(&session_root.join(MARKER_FILE))
                .await
                .expect("read concurrent marker"),
            marker(&attachment())
        );
        let mut entries = tokio::fs::read_dir(&session_root)
            .await
            .expect("enumerate marker root");
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await.expect("read marker entry") {
            names.push(entry.file_name());
        }
        assert_eq!(names, vec![std::ffi::OsString::from(MARKER_FILE)]);
    }
}
