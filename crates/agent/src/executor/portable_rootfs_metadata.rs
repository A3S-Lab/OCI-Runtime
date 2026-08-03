use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{
    Error, ErrorCode, PortableRootfsEntryKind, PortableRootfsMetadataEntry,
    PortableRootfsMetadataManifest, Result, PORTABLE_ROOTFS_METADATA_ANNOTATION,
    PORTABLE_ROOTFS_METADATA_FILE, PORTABLE_ROOTFS_METADATA_MAX_BYTES,
    PORTABLE_ROOTFS_METADATA_SCHEMA_V1,
};
use base64::Engine;

const MAX_ENCODED_PATH_BYTES: usize = 16 * 1024;
const MAX_DECODED_PATH_BYTES: usize = 4_096;

const RUNTIME_INTERNAL_ROOT_ENTRIES: &[&str] = &[
    ".a3s-box-env",
    ".a3s-box-exec.json",
    ".a3s_exit_code",
    ".a3s_host_live_logs_drained",
    ".a3s_host_result_collected",
    ".a3s_image_metadata_v1.json",
    ".a3s_image_metadata_v1.json.tmp",
    ".a3s_rootfs_metadata_v1.json",
    ".a3s_rootfs_metadata_v1.json.tmp",
    ".a3s_rootfs_metadata_v1.previous.json",
    ".a3s-oci-rootfs-metadata.v1.json",
    ".a3s-oci-rootfs-metadata.v1.json.tmp",
    "guest-init.stderr.log",
    "guest-init.stdout.log",
    "init-rust.log",
    "init.krun.log",
    "init.trace.log",
];

#[derive(Debug)]
struct DecodedEntry {
    metadata: PortableRootfsMetadataEntry,
    relative: PathBuf,
    target: PathBuf,
    current_uid: u64,
    current_gid: u64,
    current_mode: u32,
}

pub(super) fn validate_plan(
    annotations: &BTreeMap<String, String>,
    root_path_is_absolute: bool,
    new_mount_namespace: bool,
    new_user_namespace: bool,
) -> Result<()> {
    if !extension_requested(annotations)? {
        return Ok(());
    }
    if root_path_is_absolute {
        return Err(invalid(
            "portable rootfs metadata replay requires a relative OCI root.path",
        ));
    }
    if !new_mount_namespace {
        return Err(invalid(
            "portable rootfs metadata replay requires a new mount namespace",
        ));
    }
    if new_user_namespace {
        return Err(invalid(
            "portable rootfs metadata replay does not allow a user namespace",
        ));
    }
    Ok(())
}

pub(super) fn replay_if_requested(
    annotations: &BTreeMap<String, String>,
    root: &Path,
) -> Result<()> {
    if !extension_requested(annotations)? {
        return Ok(());
    }
    replay(root)
}

fn extension_requested(annotations: &BTreeMap<String, String>) -> Result<bool> {
    match annotations
        .get(PORTABLE_ROOTFS_METADATA_ANNOTATION)
        .map(String::as_str)
    {
        None => Ok(false),
        Some(PORTABLE_ROOTFS_METADATA_SCHEMA_V1) => Ok(true),
        Some(value) => Err(invalid(format!(
            "unsupported {PORTABLE_ROOTFS_METADATA_ANNOTATION} value: {value}"
        ))),
    }
}

fn replay(root: &Path) -> Result<()> {
    let source = root.join(PORTABLE_ROOTFS_METADATA_FILE);
    let file = open_bounded_manifest(&source)?;
    let mut bytes = Vec::with_capacity(file.metadata().map_err(metadata_io)?.len() as usize);
    file.take(PORTABLE_ROOTFS_METADATA_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(metadata_io)?;
    if bytes.len() as u64 > PORTABLE_ROOTFS_METADATA_MAX_BYTES {
        return Err(precondition(format!(
            "portable rootfs metadata grew beyond the {PORTABLE_ROOTFS_METADATA_MAX_BYTES}-byte limit while reading"
        )));
    }
    let manifest: PortableRootfsMetadataManifest =
        serde_json::from_slice(&bytes).map_err(|error| {
            precondition(format!(
                "invalid portable rootfs metadata {}: {error}",
                source.display()
            ))
        })?;
    manifest.validate().map_err(precondition)?;

    let mut decoded = decode_and_validate(root, manifest.entries)?;
    apply_ownership(&decoded)?;
    decoded.sort_by_key(|entry| Reverse(entry.relative.components().count()));
    apply_modes(&decoded)?;

    std::fs::remove_file(&source).map_err(|error| {
        precondition(format!(
            "failed to consume portable rootfs metadata {}: {error}",
            source.display()
        ))
    })?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            precondition(format!(
                "failed to sync replayed portable rootfs metadata at {}: {error}",
                root.display()
            ))
        })?;
    Ok(())
}

fn open_bounded_manifest(path: &Path) -> Result<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            precondition(format!(
                "failed to open required portable rootfs metadata {} without following links: {error}",
                path.display()
            ))
        })?;
    let metadata = file.metadata().map_err(|error| {
        precondition(format!(
            "failed to inspect required portable rootfs metadata {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > PORTABLE_ROOTFS_METADATA_MAX_BYTES {
        return Err(precondition(format!(
            "portable rootfs metadata must be a plain file no larger than {PORTABLE_ROOTFS_METADATA_MAX_BYTES} bytes: {}",
            path.display()
        )));
    }
    Ok(file)
}

fn decode_and_validate(
    root: &Path,
    entries: Vec<PortableRootfsMetadataEntry>,
) -> Result<Vec<DecodedEntry>> {
    let mut decoded = Vec::with_capacity(entries.len());
    let mut unique = HashSet::with_capacity(entries.len());
    for entry in entries {
        if entry.uid > u32::MAX as u64 || entry.gid > u32::MAX as u64 {
            return Err(precondition(
                "portable rootfs metadata uid/gid exceeds the Linux ID range",
            ));
        }
        let relative = decode_relative_path(&entry.path_base64)?;
        if is_runtime_internal_path(&relative) || !unique.insert(relative.clone()) {
            return Err(precondition(
                "portable rootfs metadata contains a duplicate or runtime-internal path",
            ));
        }
        let target = resolve_without_symlink_parent(root, &relative)?;
        let current = std::fs::symlink_metadata(&target).map_err(|error| {
            precondition(format!(
                "failed to inspect portable rootfs metadata target {}: {error}",
                target.display()
            ))
        })?;
        let actual_kind = if current.file_type().is_dir() {
            PortableRootfsEntryKind::Directory
        } else if current.file_type().is_file() {
            PortableRootfsEntryKind::Regular
        } else if current.file_type().is_symlink() {
            PortableRootfsEntryKind::Symlink
        } else {
            return Err(precondition(format!(
                "portable rootfs metadata target has an unsupported type: {}",
                target.display()
            )));
        };
        if actual_kind != entry.kind {
            return Err(precondition(format!(
                "portable rootfs metadata type mismatch at {}",
                target.display()
            )));
        }
        validate_link_target(&entry, &target)?;
        decoded.push(DecodedEntry {
            metadata: entry,
            relative,
            target,
            current_uid: current.uid() as u64,
            current_gid: current.gid() as u64,
            current_mode: current.mode(),
        });
    }
    Ok(decoded)
}

fn decode_relative_path(encoded: &str) -> Result<PathBuf> {
    if encoded.len() > MAX_ENCODED_PATH_BYTES {
        return Err(precondition("portable rootfs metadata path is too large"));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| precondition(format!("invalid portable rootfs metadata path: {error}")))?;
    if raw.is_empty() || raw.len() > MAX_DECODED_PATH_BYTES || raw.contains(&0) {
        return Err(precondition(
            "portable rootfs metadata path is empty, too large, or contains NUL",
        ));
    }
    safe_relative_path(Path::new(&OsString::from_vec(raw)))
}

fn safe_relative_path(path: &Path) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(name) => result.push(name),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(precondition("unsafe path in portable rootfs metadata"));
            }
        }
    }
    Ok(result)
}

fn is_runtime_internal_path(path: &Path) -> bool {
    let Some(Component::Normal(first)) = path.components().next() else {
        return false;
    };
    RUNTIME_INTERNAL_ROOT_ENTRIES
        .iter()
        .any(|internal| first == *internal)
}

fn resolve_without_symlink_parent(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        if index + 1 < components.len() {
            let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
                precondition(format!(
                    "failed to inspect portable rootfs metadata parent {}: {error}",
                    current.display()
                ))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(precondition(format!(
                    "symlink parent in portable rootfs metadata path: {}",
                    current.display()
                )));
            }
        }
    }
    Ok(current)
}

fn validate_link_target(entry: &PortableRootfsMetadataEntry, target: &Path) -> Result<()> {
    if entry.kind != PortableRootfsEntryKind::Symlink {
        if entry.link_target_base64.is_some() {
            return Err(precondition(
                "non-symlink portable rootfs metadata contains a link target",
            ));
        }
        return Ok(());
    }
    let encoded = entry
        .link_target_base64
        .as_deref()
        .ok_or_else(|| precondition("portable rootfs symlink metadata is missing its target"))?;
    if encoded.len() > MAX_ENCODED_PATH_BYTES {
        return Err(precondition("portable rootfs symlink target is too large"));
    }
    let expected = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            precondition(format!("invalid portable rootfs symlink target: {error}"))
        })?;
    if expected.len() > MAX_DECODED_PATH_BYTES || expected.contains(&0) {
        return Err(precondition(
            "portable rootfs symlink target is too large or contains NUL",
        ));
    }
    if std::fs::read_link(target)
        .map_err(|error| {
            precondition(format!(
                "failed to read portable rootfs symlink {}: {error}",
                target.display()
            ))
        })?
        .as_os_str()
        .as_bytes()
        != expected
    {
        return Err(precondition(format!(
            "portable rootfs symlink target mismatch at {}",
            target.display()
        )));
    }
    Ok(())
}

fn apply_ownership(entries: &[DecodedEntry]) -> Result<()> {
    for entry in entries {
        if entry.metadata.uid == entry.current_uid && entry.metadata.gid == entry.current_gid {
            continue;
        }
        if entry.metadata.kind != PortableRootfsEntryKind::Symlink
            && entry.current_mode & 0o200 == 0
        {
            std::fs::set_permissions(
                &entry.target,
                std::fs::Permissions::from_mode((entry.current_mode & 0o7777) | 0o200),
            )
            .map_err(|error| {
                precondition(format!(
                    "failed to make {} writable for portable ownership replay: {error}",
                    entry.target.display()
                ))
            })?;
        }
        let target = CString::new(entry.target.as_os_str().as_bytes()).map_err(|error| {
            precondition(format!(
                "portable rootfs metadata target contains NUL at {}: {error}",
                entry.target.display()
            ))
        })?;
        // SAFETY: the path is a live NUL-terminated buffer, both IDs were
        // bounded to Linux uid_t/gid_t, and lchown does not follow symlinks.
        if unsafe {
            libc::lchown(
                target.as_ptr(),
                entry.metadata.uid as libc::uid_t,
                entry.metadata.gid as libc::gid_t,
            )
        } != 0
        {
            return Err(precondition(format!(
                "failed to restore portable rootfs ownership at {} to {}:{}: {}",
                entry.target.display(),
                entry.metadata.uid,
                entry.metadata.gid,
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn apply_modes(entries: &[DecodedEntry]) -> Result<()> {
    for entry in entries {
        if entry.metadata.kind == PortableRootfsEntryKind::Symlink {
            continue;
        }
        let desired = runtime_managed_mode(&entry.relative).unwrap_or(entry.metadata.mode & 0o7777);
        let current = std::fs::symlink_metadata(&entry.target)
            .map_err(metadata_io)?
            .mode()
            & 0o7777;
        if current != desired {
            std::fs::set_permissions(&entry.target, std::fs::Permissions::from_mode(desired))
                .map_err(|error| {
                    precondition(format!(
                        "failed to restore portable rootfs mode at {} to {desired:o}: {error}",
                        entry.target.display()
                    ))
                })?;
        }
    }
    Ok(())
}

fn runtime_managed_mode(path: &Path) -> Option<u32> {
    match path.to_str() {
        Some("etc/hostname" | "etc/hosts" | "etc/resolv.conf") => Some(0o644),
        Some("sbin/init" | "usr/sbin/init") => Some(0o755),
        Some(".a3s-box-env" | ".a3s-box-exec.json") => Some(0o600),
        _ => None,
    }
}

fn metadata_io(error: std::io::Error) -> Error {
    precondition(format!("portable rootfs metadata I/O failed: {error}"))
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("replay-portable-rootfs-metadata")
}

fn precondition(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message)
        .for_operation("replay-portable-rootfs-metadata")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn annotations() -> BTreeMap<String, String> {
        BTreeMap::from([(
            PORTABLE_ROOTFS_METADATA_ANNOTATION.to_string(),
            PORTABLE_ROOTFS_METADATA_SCHEMA_V1.to_string(),
        )])
    }

    fn encoded(value: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(value)
    }

    fn entry(path: &[u8], kind: &str, mode: u32, link: Option<&[u8]>) -> serde_json::Value {
        // SAFETY: geteuid/getegid are argument-free Linux system calls.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        json!({
            "path_base64": encoded(path),
            "kind": kind,
            "mode": mode,
            "uid": uid,
            "gid": gid,
            "mtime": 0,
            "size": 0,
            "link_target_base64": link.map(encoded),
        })
    }

    fn write_manifest(root: &Path, entries: Vec<serde_json::Value>) {
        std::fs::write(
            root.join(PORTABLE_ROOTFS_METADATA_FILE),
            serde_json::to_vec(&json!({
                "schema": PORTABLE_ROOTFS_METADATA_SCHEMA_V1,
                "entries": entries,
            }))
            .expect("encode manifest"),
        )
        .expect("write manifest");
    }

    #[test]
    fn exact_portable_contract_replays_modes_and_consumes_manifest() {
        let directory = tempfile::tempdir().expect("rootfs");
        let root = directory.path();
        std::fs::create_dir(root.join("bin")).expect("bin");
        std::fs::write(root.join("bin/tool"), b"tool").expect("tool");
        std::os::unix::fs::symlink("tool", root.join("bin/tool-link")).expect("link");
        std::fs::set_permissions(
            root.join("bin/tool"),
            std::fs::Permissions::from_mode(0o600),
        )
        .expect("initial mode");
        write_manifest(
            root,
            vec![
                entry(b"./bin/tool", "regular", 0o751, None),
                entry(b"./bin/tool-link", "symlink", 0o777, Some(b"tool")),
            ],
        );

        validate_plan(&annotations(), false, true, false).expect("valid contract");
        replay_if_requested(&annotations(), root).expect("metadata replay");

        assert_eq!(
            std::fs::symlink_metadata(root.join("bin/tool"))
                .expect("tool metadata")
                .mode()
                & 0o7777,
            0o751
        );
        assert_eq!(
            std::fs::read_link(root.join("bin/tool-link")).expect("link target"),
            Path::new("tool")
        );
        assert!(!root.join(PORTABLE_ROOTFS_METADATA_FILE).exists());
    }

    #[test]
    fn metadata_annotation_requires_the_exact_schema() {
        let annotations = BTreeMap::from([(
            PORTABLE_ROOTFS_METADATA_ANNOTATION.to_string(),
            "unsupported".to_string(),
        )]);
        let error = validate_plan(&annotations, false, true, false).expect_err("wrong schema");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains(PORTABLE_ROOTFS_METADATA_ANNOTATION));
    }

    #[test]
    fn metadata_annotation_rejects_absolute_or_user_namespaced_roots() {
        assert!(validate_plan(&annotations(), true, true, false).is_err());
        assert!(validate_plan(&annotations(), false, false, false).is_err());
        assert!(validate_plan(&annotations(), false, true, true).is_err());
    }

    #[test]
    fn unsafe_path_fails_before_any_mode_is_changed() {
        let directory = tempfile::tempdir().expect("rootfs");
        let root = directory.path();
        std::fs::write(root.join("safe"), b"safe").expect("safe file");
        std::fs::set_permissions(root.join("safe"), std::fs::Permissions::from_mode(0o600))
            .expect("initial mode");
        write_manifest(
            root,
            vec![
                entry(b"./safe", "regular", 0o755, None),
                entry(b"../escape", "regular", 0o777, None),
            ],
        );

        assert!(replay_if_requested(&annotations(), root).is_err());
        assert_eq!(
            std::fs::symlink_metadata(root.join("safe"))
                .expect("safe metadata")
                .mode()
                & 0o7777,
            0o600
        );
        assert!(root.join(PORTABLE_ROOTFS_METADATA_FILE).exists());
    }

    #[test]
    fn symlink_parent_cannot_redirect_metadata_outside_rootfs() {
        let directory = tempfile::tempdir().expect("rootfs");
        let outside = tempfile::tempdir().expect("outside");
        std::fs::write(outside.path().join("target"), b"outside").expect("outside target");
        std::os::unix::fs::symlink(outside.path(), directory.path().join("escape"))
            .expect("escaping link");
        write_manifest(
            directory.path(),
            vec![entry(b"./escape/target", "regular", 0o777, None)],
        );

        let error = replay_if_requested(&annotations(), directory.path())
            .expect_err("symlink parent rejection");
        assert!(error.message.contains("symlink parent"));
        assert_eq!(
            std::fs::read(outside.path().join("target")).expect("outside target"),
            b"outside"
        );
    }
}
