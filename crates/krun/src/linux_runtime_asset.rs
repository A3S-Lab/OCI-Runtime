use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use sha2::{Digest, Sha256};

use crate::runtime_assets::{RuntimeFile, RuntimeFileRole};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// A manifest-bound runtime object retained through the native loading
/// boundary.
///
/// The descriptor is opened with `O_NOFOLLOW` and is the source used for
/// hashing and dynamic loading.  Keeping it alive prevents a replacement of
/// the directory entry from redirecting the loader to a different object.
#[derive(Debug)]
pub(crate) struct PinnedRuntimeFile {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    size: u64,
    sha256: String,
    role: RuntimeFileRole,
}

impl PinnedRuntimeFile {
    pub(crate) fn open(path: &Path, expected: &RuntimeFile) -> Result<Self> {
        let path = canonical_plain_file(path, expected.role)?;
        let initial_metadata = fs::symlink_metadata(&path).map_err(|error| {
            asset_error(
                expected.role,
                format!(
                    "failed to inspect runtime asset {}: {error}",
                    path.display()
                ),
            )
        })?;
        ensure_plain_file(&initial_metadata, &path, expected.role)?;

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                asset_error(
                    expected.role,
                    format!(
                        "failed to pin runtime asset {} read-only: {error}",
                        path.display()
                    ),
                )
            })?;
        let file_metadata = file.metadata().map_err(|error| {
            asset_error(
                expected.role,
                format!(
                    "failed to inspect pinned runtime asset {}: {error}",
                    path.display()
                ),
            )
        })?;
        ensure_plain_file(&file_metadata, &path, expected.role)?;
        let identity = FileIdentity::from_metadata(&file_metadata);
        if FileIdentity::from_metadata(&initial_metadata) != identity {
            return Err(asset_error(
                expected.role,
                format!(
                    "runtime asset changed while its descriptor was being pinned: {}",
                    path.display()
                ),
            ));
        }
        if file_metadata.len() != expected.size {
            return Err(asset_error(
                expected.role,
                format!(
                    "size mismatch for {}: expected {}, found {}",
                    path.display(),
                    expected.size,
                    file_metadata.len()
                ),
            ));
        }

        let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
            asset_error(
                expected.role,
                format!(
                    "failed to re-inspect runtime asset {} after pinning: {error}",
                    path.display()
                ),
            )
        })?;
        ensure_plain_file(&path_metadata, &path, expected.role)?;
        if FileIdentity::from_metadata(&path_metadata) != identity
            || path_metadata.len() != expected.size
        {
            return Err(asset_error(
                expected.role,
                format!(
                    "runtime asset changed while its descriptor was being pinned: {}",
                    path.display()
                ),
            ));
        }

        let sha256 = hash_file(&file, expected.size, expected.role, &path)?;
        if sha256 != expected.sha256 {
            return Err(asset_error(
                expected.role,
                format!(
                    "SHA-256 mismatch for {}: expected {}, found {sha256}",
                    path.display(),
                    expected.sha256
                ),
            ));
        }

        let pinned = Self {
            path,
            file,
            identity,
            size: expected.size,
            sha256,
            role: expected.role,
        };
        pinned.verify_metadata("descriptor pinning")?;
        Ok(pinned)
    }

    /// Path accepted by `dlopen` that resolves to this exact open descriptor.
    pub(crate) fn loader_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    /// Revalidate both the directory entry and the bytes read through the
    /// retained descriptor immediately before a native API boundary.
    pub(crate) fn reverify(&self) -> Result<()> {
        self.verify_metadata("native API use")?;
        let sha256 = hash_file(&self.file, self.size, self.role, &self.path)?;
        self.verify_metadata("native API use")?;
        if sha256 != self.sha256 {
            return Err(asset_error(
                self.role,
                format!(
                    "runtime asset SHA-256 changed before native API use: expected {}, found {sha256}",
                    self.sha256
                ),
            ));
        }
        Ok(())
    }

    fn verify_metadata(&self, boundary: &'static str) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            asset_error(
                self.role,
                format!(
                    "failed to re-inspect runtime asset {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        ensure_plain_file(&path_metadata, &self.path, self.role)?;
        let file_metadata = self.file.metadata().map_err(|error| {
            asset_error(
                self.role,
                format!(
                    "failed to re-inspect pinned runtime asset {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        if FileIdentity::from_metadata(&path_metadata) != self.identity
            || FileIdentity::from_metadata(&file_metadata) != self.identity
            || path_metadata.len() != self.size
            || file_metadata.len() != self.size
        {
            return Err(asset_error(
                self.role,
                format!(
                    "runtime asset identity changed before {boundary}: {}",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

fn canonical_plain_file(path: &Path, role: RuntimeFileRole) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(asset_error(
            role,
            format!("runtime asset path must be absolute: {}", path.display()),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        asset_error(
            role,
            format!(
                "failed to inspect runtime asset {}: {error}",
                path.display()
            ),
        )
    })?;
    ensure_plain_file(&metadata, path, role)?;
    let canonical = path.canonicalize().map_err(|error| {
        asset_error(
            role,
            format!(
                "failed to canonicalize runtime asset {}: {error}",
                path.display()
            ),
        )
    })?;
    if canonical != path {
        return Err(asset_error(
            role,
            format!(
                "runtime asset path must not traverse symbolic links or aliases: {}",
                path.display()
            ),
        ));
    }
    Ok(canonical)
}

fn ensure_plain_file(metadata: &Metadata, path: &Path, role: RuntimeFileRole) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(asset_error(
            role,
            format!(
                "Linux {} runtime asset must be a real regular file, not a symlink: {}",
                role.as_str(),
                path.display()
            ),
        ));
    }
    Ok(())
}

fn hash_file(file: &File, size: u64, role: RuntimeFileRole, path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_SIZE];
    let mut offset = 0_u64;
    while offset < size {
        let remaining = size - offset;
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            asset_error(
                role,
                format!("runtime asset is too large: {}", path.display()),
            )
        })?;
        let read = file
            .read_at(&mut buffer[..limit], offset)
            .map_err(|error| {
                asset_error(
                    role,
                    format!("failed to hash runtime asset {}: {error}", path.display()),
                )
            })?;
        if read == 0 {
            return Err(asset_error(
                role,
                format!(
                    "runtime asset became shorter while it was hashed: {}",
                    path.display()
                ),
            ));
        }
        hasher.update(&buffer[..read]);
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            asset_error(
                role,
                format!("runtime asset is too large: {}", path.display()),
            )
        })?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn asset_error(role: RuntimeFileRole, message: String) -> Error {
    Error::new(ErrorCode::Unavailable, message).for_operation(match role {
        RuntimeFileRole::Library => "verify-linux-libkrun-library",
        RuntimeFileRole::Firmware => "verify-linux-libkrun-firmware",
        RuntimeFileRole::ImportLibrary => "verify-linux-libkrun-import-library",
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::symlink;

    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::PinnedRuntimeFile;
    use crate::runtime_assets::{RuntimeFile, RuntimeFileRole};

    #[test]
    fn loader_path_stays_bound_after_directory_entry_replacement() {
        let fixture = Fixture::new(b"original-runtime");
        let expected = fixture.manifest();
        let pinned = PinnedRuntimeFile::open(&fixture.path, &expected).expect("pin asset");
        let loader_path = pinned.loader_path();

        let moved = fixture.path.with_file_name("runtime-moved");
        fs::rename(&fixture.path, &moved).expect("move original asset");
        fs::write(&fixture.path, b"replacement-runtime")
            .expect("create replacement directory entry");

        assert_eq!(
            fs::read(&loader_path).expect("read descriptor path"),
            fixture.bytes
        );
        assert!(pinned
            .reverify()
            .expect_err("replacement must be rejected")
            .to_string()
            .contains("identity changed"));
    }

    #[test]
    fn same_size_mutation_is_detected_through_the_retained_descriptor() {
        let fixture = Fixture::new(b"original-runtime");
        let expected = fixture.manifest();
        let pinned = PinnedRuntimeFile::open(&fixture.path, &expected).expect("pin asset");
        let mut file = File::options()
            .write(true)
            .open(&fixture.path)
            .expect("open asset for mutation");
        file.write_all(b"mutated-runtime!").expect("mutate asset");
        file.flush().expect("flush mutation");

        assert!(pinned
            .reverify()
            .expect_err("content mutation must be rejected")
            .to_string()
            .contains("SHA-256 changed"));
    }

    #[test]
    fn symlinked_runtime_assets_fail_closed() {
        let fixture = Fixture::new(b"runtime");
        let link = fixture.path.with_file_name("runtime-link");
        symlink(&fixture.path, &link).expect("create symlink");

        let error = PinnedRuntimeFile::open(&link, &fixture.manifest())
            .expect_err("symlink must not cross the runtime trust boundary");
        assert!(error.to_string().contains("not a symlink"));
    }

    struct Fixture {
        _directory: TempDir,
        path: std::path::PathBuf,
        bytes: Vec<u8>,
    }

    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let directory = tempfile::tempdir().expect("create fixture directory");
            let path = directory.path().join("runtime");
            File::create(&path)
                .and_then(|mut file| file.write_all(bytes))
                .expect("write fixture");
            Self {
                _directory: directory,
                path,
                bytes: bytes.to_vec(),
            }
        }

        fn manifest(&self) -> RuntimeFile {
            RuntimeFile {
                role: RuntimeFileRole::Library,
                name: "runtime".to_string(),
                size: self.bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&self.bytes)),
            }
        }
    }
}
