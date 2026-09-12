use std::path::Path;

use a3s_oci_sdk::{ErrorCode, GuestSessionAttachment};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;

use super::super::layout::PRIVATE_FILE_MODE;
use super::{
    ensure, marker_conflict, publish_marker, read, read_bound, remove_private_file_bound,
    validate_root_identity, GuestSessionMarker, MARKER_FILE, MARKER_SCHEMA, PENDING_MARKER_FILE,
    REUSABLE_GUEST_SESSION_DIRECTORY,
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
async fn marker_reader_rejects_a_replaced_path_before_open() {
    let temporary = tempdir().expect("temporary marker root");
    let path = temporary.path().join(MARKER_FILE);
    let retained = temporary.path().join("retained-original");
    let replacement = temporary.path().join("replacement");
    write_private_file(&path, b"original").await;
    let original_metadata = tokio::fs::symlink_metadata(&path)
        .await
        .expect("inspect original marker");
    tokio::fs::hard_link(&path, &retained)
        .await
        .expect("retain original marker identity");
    write_private_file(&replacement, b"replacement").await;
    tokio::fs::remove_file(&path)
        .await
        .expect("remove original marker path");
    tokio::fs::hard_link(&replacement, &path)
        .await
        .expect("install replacement marker path");

    let error = read_bound(&path, &original_metadata)
        .await
        .expect_err("replacement marker must be rejected");
    assert!(error.retryable);
    assert_eq!(
        tokio::fs::read(&path)
            .await
            .expect("read replacement marker"),
        b"replacement"
    );
}

#[tokio::test]
async fn marker_cleanup_rejects_a_replaced_path_without_deleting_it() {
    let temporary = tempdir().expect("temporary marker root");
    let path = temporary.path().join(PENDING_MARKER_FILE);
    let retained = temporary.path().join("retained-original");
    let replacement = temporary.path().join("replacement");
    write_private_file(&path, b"original").await;
    let original_metadata = tokio::fs::symlink_metadata(&path)
        .await
        .expect("inspect original marker");
    tokio::fs::hard_link(&path, &retained)
        .await
        .expect("retain original marker identity");
    write_private_file(&replacement, b"replacement").await;
    tokio::fs::remove_file(&path)
        .await
        .expect("remove original marker path");
    tokio::fs::hard_link(&replacement, &path)
        .await
        .expect("install replacement marker path");

    let error = remove_private_file_bound(&path, &original_metadata)
        .await
        .expect_err("replacement marker must not be deleted");
    assert!(error.retryable);
    assert_eq!(
        tokio::fs::read(&path)
            .await
            .expect("read replacement marker"),
        b"replacement"
    );
}

#[tokio::test]
async fn marker_reader_rejects_a_final_component_symlink() {
    let temporary = tempdir().expect("temporary marker root");
    let victim = temporary.path().join("victim");
    let path = temporary.path().join(MARKER_FILE);
    write_private_file(&victim, b"victim").await;
    std::os::unix::fs::symlink(&victim, &path).expect("create marker symlink");

    let error = read(&path)
        .await
        .expect_err("symlink marker must be rejected");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(!error.retryable);
    assert_eq!(
        tokio::fs::read(&victim).await.expect("read marker victim"),
        b"victim"
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
