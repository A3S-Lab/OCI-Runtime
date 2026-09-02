//! Materialize Box's transient Secret environment bindings for direct OCI
//! process launches.
//!
//! The Box runtime keeps Secret bytes outside the OCI bundle and passes only a
//! manifest plus read-only files mounted below `/.a3s-box-secrets`. Guest-init
//! consumes this protocol for MicroVM launches. Native Sandbox launches are
//! owned directly by this executor, so it performs the same projection after
//! entering the container root and before dropping to the workload identity.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

const SECRET_ENVIRONMENT_MANIFEST: &str = "A3S_BOX_SECRET_ENV_V1";
const SECRET_GUEST_ROOT: &str = "/.a3s-box-secrets";
const MAX_BINDINGS: usize = 128;
const MAX_SECRET_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretEnvironmentBinding {
    variable: String,
    path: String,
}

/// Replace the non-sensitive Box Secret manifest with values read from the
/// read-only files mounted in the container root.
pub(super) fn materialize(environment: &mut Vec<String>) -> Result<()> {
    materialize_from(environment, Path::new("/"))
}

fn materialize_from(environment: &mut Vec<String>, root: &Path) -> Result<()> {
    let manifest_indices = environment
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (entry
                .split_once('=')
                .is_some_and(|(key, _)| key == SECRET_ENVIRONMENT_MANIFEST))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if manifest_indices.is_empty() {
        return Ok(());
    }
    if manifest_indices.len() != 1 {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "duplicate Box Secret environment manifests",
        ));
    }
    let manifest_index = manifest_indices[0];
    let (_, encoded) = environment[manifest_index].split_once('=').ok_or_else(|| {
        secret_error(
            ErrorCode::InvalidArgument,
            "Box Secret environment manifest is missing its value",
        )
    })?;
    let encoded = Zeroizing::new(encoded.to_owned());
    let bindings: Vec<SecretEnvironmentBinding> = serde_json::from_str(&encoded).map_err(|_| {
        secret_error(
            ErrorCode::InvalidArgument,
            "Box Secret environment manifest is not valid version-1 JSON",
        )
    })?;
    if bindings.is_empty() || bindings.len() > MAX_BINDINGS {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "Box Secret environment manifest has an invalid binding count",
        ));
    }

    let mut variables = environment
        .iter()
        .filter_map(|entry| entry.split_once('=').map(|(key, _)| key.to_owned()))
        .filter(|key| key != SECRET_ENVIRONMENT_MANIFEST)
        .collect::<BTreeSet<_>>();
    let mut paths = BTreeSet::new();
    let mut additions = Vec::with_capacity(bindings.len());
    for binding in bindings {
        validate_variable(&binding.variable)?;
        if !variables.insert(binding.variable.clone()) {
            return Err(secret_error(
                ErrorCode::InvalidArgument,
                "Box Secret environment binding conflicts with an existing value",
            ));
        }
        if !paths.insert(binding.path.clone()) {
            return Err(secret_error(
                ErrorCode::InvalidArgument,
                "Box Secret environment manifest contains duplicate paths",
            ));
        }

        let relative = validate_guest_path(&binding.path)?;
        let host_path = root.join(relative);
        let file = open_secret_file(&host_path)?;
        let metadata = file.metadata().map_err(|error| {
            secret_error(
                ErrorCode::FailedPrecondition,
                format!("could not inspect Box Secret environment file: {error}"),
            )
        })?;
        validate_secret_metadata(&metadata)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.take(MAX_SECRET_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                secret_error(
                    ErrorCode::FailedPrecondition,
                    format!("could not read Box Secret environment file: {error}"),
                )
            })?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_SECRET_BYTES {
            return Err(secret_error(
                ErrorCode::FailedPrecondition,
                "Box Secret environment value has an invalid size",
            ));
        }
        let mut value = std::str::from_utf8(&bytes)
            .map_err(|_| {
                secret_error(
                    ErrorCode::FailedPrecondition,
                    "Box Secret environment value is not UTF-8",
                )
            })?
            .to_owned();
        if value.contains('\0') {
            value.zeroize();
            return Err(secret_error(
                ErrorCode::FailedPrecondition,
                "Box Secret environment value contains a NUL byte",
            ));
        }
        additions.push((binding.variable, value));
    }

    environment.remove(manifest_index);
    environment.extend(
        additions
            .into_iter()
            .map(|(variable, value)| format!("{variable}={value}")),
    );
    Ok(())
}

fn validate_variable(variable: &str) -> Result<()> {
    let mut bytes = variable.bytes();
    let Some(first) = bytes.next() else {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "Secret environment variable name must not be empty",
        ));
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || variable.len() > 255
    {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "Secret environment variable name is invalid",
        ));
    }
    Ok(())
}

fn validate_guest_path(path: &str) -> Result<PathBuf> {
    let path_object = Path::new(path);
    let path_bytes = path_object.as_os_str().as_bytes();
    if !path_object.is_absolute()
        || path_bytes.len() > 4096
        || path_bytes.contains(&b':')
        || path_bytes.iter().any(u8::is_ascii_control)
        || !path_object.starts_with(SECRET_GUEST_ROOT)
    {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "Box Secret environment file path is invalid",
        ));
    }
    let relative = path_object.strip_prefix(SECRET_GUEST_ROOT).map_err(|_| {
        secret_error(
            ErrorCode::PermissionDenied,
            "Box Secret environment file escaped the reserved guest directory",
        )
    })?;
    let components = relative.components().collect::<Vec<_>>();
    let valid_identity = matches!(
        components.as_slice(),
        [Component::Normal(digest), Component::Normal(file)]
            if digest.as_bytes().len() == 64
                && digest.as_bytes().iter().all(u8::is_ascii_hexdigit)
                && file.as_bytes().len() == 10
                && file.as_bytes()[..3]
                    .iter()
                    .all(u8::is_ascii_digit)
                && &file.as_bytes()[3..] == b".secret"
    );
    if !valid_identity {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "Box Secret environment file has an invalid reserved identity",
        ));
    }
    let index = components[1].as_os_str().as_bytes()[..3]
        .iter()
        .fold(0usize, |value, byte| value * 10 + usize::from(byte - b'0'));
    if index >= MAX_BINDINGS {
        return Err(secret_error(
            ErrorCode::InvalidArgument,
            "Box Secret environment file index is out of range",
        ));
    }
    // Return a path relative to the chroot represented by `root`.  The
    // caller joins this with `root` before opening, so a real launch with
    // `root == /` addresses the guest path while tests can safely use a
    // temporary directory as a stand-in for the guest root.
    path_object
        .strip_prefix("/")
        .map(Path::to_path_buf)
        .map_err(|_| {
            secret_error(
                ErrorCode::InvalidArgument,
                "Box Secret environment file path is missing its root component",
            )
        })
}

fn open_secret_file(path: &Path) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            secret_error(
                ErrorCode::FailedPrecondition,
                format!("could not open Box Secret environment file: {error}"),
            )
        })
}

fn validate_secret_metadata(metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_SECRET_BYTES
        || metadata.permissions().mode() & 0o777 != 0o400
    {
        return Err(secret_error(
            ErrorCode::FailedPrecondition,
            "Box Secret environment file violates its regular-file, size, or mode contract",
        ));
    }
    Ok(())
}

fn secret_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("materialize-secret-environment")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn fixture(root: &Path, value: &[u8]) -> String {
        let digest = "a".repeat(64);
        let directory = root
            .join(SECRET_GUEST_ROOT.trim_start_matches('/'))
            .join(&digest);
        std::fs::create_dir_all(&directory).expect("create Secret directory");
        let path = directory.join("000.secret");
        std::fs::write(&path, value).expect("write Secret file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
            .expect("protect Secret file");
        format!(
            "{SECRET_ENVIRONMENT_MANIFEST}={}",
            serde_json::json!([{
                "variable": "PROVIDER_API_KEY",
                "path": format!("{SECRET_GUEST_ROOT}/{digest}/000.secret")
            }])
        )
    }

    #[test]
    fn materializes_manifest_without_leaking_it_to_the_workload() {
        let temporary = tempfile::tempdir().expect("create Secret fixture root");
        let mut environment = vec![
            "PATH=/usr/bin".to_string(),
            fixture(temporary.path(), b"key"),
        ];

        materialize_from(&mut environment, temporary.path()).expect("materialize Secret");

        assert!(!environment
            .iter()
            .any(|entry| entry.starts_with(SECRET_ENVIRONMENT_MANIFEST)));
        assert!(environment.contains(&"PROVIDER_API_KEY=key".to_string()));
    }

    #[test]
    fn rejects_secret_files_with_wrong_modes() {
        let temporary = tempfile::tempdir().expect("create Secret fixture root");
        let manifest = fixture(temporary.path(), b"key");
        let path = temporary
            .path()
            .join(SECRET_GUEST_ROOT.trim_start_matches('/'))
            .join("a".repeat(64))
            .join("000.secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("weaken Secret mode");
        let mut environment = vec![manifest];
        assert!(materialize_from(&mut environment, temporary.path()).is_err());
    }

    #[test]
    fn rejects_existing_environment_collisions() {
        let temporary = tempfile::tempdir().expect("create Secret fixture root");
        let mut environment = vec![
            "PROVIDER_API_KEY=literal".to_string(),
            fixture(temporary.path(), b"key"),
        ];
        let error = materialize_from(&mut environment, temporary.path()).expect_err("collision");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn rejects_paths_outside_the_reserved_guest_directory() {
        let temporary = tempfile::tempdir().expect("create Secret fixture root");
        let manifest = format!(
            "{SECRET_ENVIRONMENT_MANIFEST}={}",
            serde_json::json!([{
                "variable": "PROVIDER_API_KEY",
                "path": "/etc/passwd"
            }])
        );
        let mut environment = vec![manifest];
        let error = materialize_from(&mut environment, temporary.path())
            .expect_err("escaped Secret path must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_secret_files() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("create Secret fixture root");
        let digest = "b".repeat(64);
        let directory = temporary
            .path()
            .join(SECRET_GUEST_ROOT.trim_start_matches('/'))
            .join(&digest);
        std::fs::create_dir_all(&directory).expect("create Secret directory");
        let target = directory.join("target");
        std::fs::write(&target, b"key").expect("write Secret target");
        let path = directory.join("000.secret");
        symlink(&target, &path).expect("create Secret symlink");
        let manifest = format!(
            "{SECRET_ENVIRONMENT_MANIFEST}={}",
            serde_json::json!([{
                "variable": "PROVIDER_API_KEY",
                "path": format!("{SECRET_GUEST_ROOT}/{digest}/000.secret")
            }])
        );
        let mut environment = vec![manifest];
        assert!(materialize_from(&mut environment, temporary.path()).is_err());
    }
}
