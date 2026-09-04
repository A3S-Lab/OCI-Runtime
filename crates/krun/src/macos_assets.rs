use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use sha2::{Digest, Sha256};

pub(crate) const MACOS_RUNTIME_ARCHIVE_SHA256: &str =
    "5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56";
pub(crate) const LIBKRUN_NAME: &str = "libkrun.1.17.0.dylib";
pub(crate) const LIBKRUN_SIZE: u64 = 4_557_488;
pub(crate) const LIBKRUN_SHA256: &str =
    "c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d";
pub(crate) const LIBKRUNFW_NAME: &str = "libkrunfw.5.dylib";
pub(crate) const LIBKRUNFW_SIZE: u64 = 22_952_096;
pub(crate) const LIBKRUNFW_SHA256: &str =
    "841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4";
pub(crate) const KERNEL_BUNDLE_SIZE: usize = 22_740_992;
pub(crate) const KERNEL_BUNDLE_SHA256: &str =
    "b1180b50148ed14f5fbeadf17288ce8abcf245daa468255b7ff41113bbf01199";
pub(crate) const KERNEL_GUEST_LOAD_ADDRESS: u64 = 0x0000_0000_8000_0000;
pub(crate) const KERNEL_ENTRY_ADDRESS: u64 = 0x0000_0000_8000_0000;
const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosRuntimeProvenance {
    pub(crate) runtime_archive_sha256: String,
    pub(crate) libkrun_sha256: String,
    pub(crate) firmware_sha256: String,
    pub(crate) kernel_bundle_size: u64,
    pub(crate) kernel_bundle_sha256: String,
    pub(crate) kernel_guest_load_address: u64,
    pub(crate) kernel_entry_address: u64,
}

impl MacosRuntimeProvenance {
    pub(crate) fn pinned(kernel_sha256: String) -> Self {
        Self {
            runtime_archive_sha256: MACOS_RUNTIME_ARCHIVE_SHA256.to_string(),
            libkrun_sha256: LIBKRUN_SHA256.to_string(),
            firmware_sha256: LIBKRUNFW_SHA256.to_string(),
            kernel_bundle_size: KERNEL_BUNDLE_SIZE as u64,
            kernel_bundle_sha256: kernel_sha256,
            kernel_guest_load_address: KERNEL_GUEST_LOAD_ADDRESS,
            kernel_entry_address: KERNEL_ENTRY_ADDRESS,
        }
    }
}

/// A regular file opened with no-follow semantics and retained across trust
/// boundaries.  Hashing and reads always use this descriptor rather than
/// reopening the path, so replacement of the directory entry is observable.
#[derive(Debug)]
pub(crate) struct PinnedFile {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    size: u64,
    sha256: String,
    description: &'static str,
}

impl PinnedFile {
    pub(crate) fn open(path: &Path, description: &'static str) -> Result<Self> {
        Self::open_with_limit(path, description, None)
    }

    pub(crate) fn open_bounded(
        path: &Path,
        description: &'static str,
        max_size: u64,
    ) -> Result<Self> {
        Self::open_with_limit(path, description, Some(max_size))
    }

    fn open_with_limit(
        path: &Path,
        description: &'static str,
        max_size: Option<u64>,
    ) -> Result<Self> {
        let path = canonical_plain_file(path, description)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                asset_error(
                    description,
                    format!("failed to pin asset {} read-only: {error}", path.display()),
                )
            })?;
        let metadata = file.metadata().map_err(|error| {
            asset_error(
                description,
                format!("failed to inspect pinned asset {}: {error}", path.display()),
            )
        })?;
        ensure_plain_file(&metadata, &path, description)?;
        let identity = FileIdentity::from_metadata(&metadata);
        let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
            asset_error(
                description,
                format!(
                    "failed to re-inspect asset {} after pinning: {error}",
                    path.display()
                ),
            )
        })?;
        ensure_plain_file(&path_metadata, &path, description)?;
        if FileIdentity::from_metadata(&path_metadata) != identity
            || path_metadata.len() != metadata.len()
        {
            return Err(asset_error(
                description,
                format!(
                    "asset changed while its descriptor was being pinned: {}",
                    path.display()
                ),
            ));
        }

        let size = metadata.len();
        if let Some(max_size) = max_size {
            if size > max_size {
                return Err(asset_error(
                    description,
                    format!("{description} exceeds {max_size} bytes: {}", path.display()),
                ));
            }
        }
        let sha256 = hash_file(&file, size, description, &path)?;
        let pinned = Self {
            path,
            file,
            identity,
            size,
            sha256,
            description,
        };
        pinned.verify_metadata("descriptor pinning")?;
        Ok(pinned)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Return the Darwin fdesc path backed by this retained file descriptor.
    ///
    /// `dlopen` receives this path instead of reopening the mutable runtime
    /// directory entry.  The descriptor remains owned by the `PinnedFile`
    /// for the lifetime of the loaded native object.
    pub(crate) fn loader_path(&self) -> PathBuf {
        PathBuf::from(format!("/dev/fd/{}", self.file.as_raw_fd()))
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn require(&self, size: u64, sha256: &str) -> Result<()> {
        if self.size == size && self.sha256 == sha256 {
            Ok(())
        } else {
            Err(asset_error(
                self.description,
                format!(
                    "asset does not match manifest: expected {size} bytes and SHA-256 {sha256}, found {} bytes and {}",
                    self.size, self.sha256
                ),
            ))
        }
    }

    pub(crate) fn read_bounded(&self, limit: u64) -> Result<Vec<u8>> {
        if self.size > limit {
            return Err(asset_error(
                self.description,
                format!(
                    "{} exceeds {limit} bytes: {}",
                    self.description,
                    self.path.display()
                ),
            ));
        }
        let length = usize::try_from(self.size).map_err(|_| {
            asset_error(
                self.description,
                format!("asset is too large for this host: {}", self.path.display()),
            )
        })?;
        let mut bytes = vec![0_u8; length];
        read_exact_at(&self.file, &mut bytes, 0).map_err(|error| {
            asset_error(
                self.description,
                format!("failed to read asset {}: {error}", self.path.display()),
            )
        })?;
        self.verify_metadata("read")?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if digest != self.sha256 {
            return Err(asset_error(
                self.description,
                format!(
                    "{} SHA-256 changed while it was read: {}",
                    self.description,
                    self.path.display()
                ),
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn reverify(&self, boundary: &'static str) -> Result<()> {
        self.verify_metadata(boundary)?;
        let sha256 = hash_file(&self.file, self.size, self.description, &self.path)?;
        self.verify_metadata(boundary)?;
        if sha256 != self.sha256 {
            return Err(asset_error(
                self.description,
                format!(
                    "{} SHA-256 changed before {boundary}: expected {}, found {sha256}",
                    self.description, self.sha256
                ),
            ));
        }
        Ok(())
    }

    fn verify_metadata(&self, boundary: &'static str) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            asset_error(
                self.description,
                format!(
                    "failed to re-inspect asset {}: {error}",
                    self.path.display()
                ),
            )
        })?;
        ensure_plain_file(&path_metadata, &self.path, self.description)?;
        let file_metadata = self.file.metadata().map_err(|error| {
            asset_error(
                self.description,
                format!(
                    "failed to re-inspect pinned asset {}: {error}",
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
                self.description,
                format!(
                    "{} identity changed before {boundary}: {}",
                    self.description,
                    self.path.display(),
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

fn canonical_plain_file(path: &Path, description: &'static str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(asset_error(
            description,
            format!("asset path must be absolute: {}", path.display()),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        asset_error(
            description,
            format!(
                "failed to inspect {description} {}: {error}",
                path.display()
            ),
        )
    })?;
    ensure_plain_file(&metadata, path, description)?;
    path.canonicalize().map_err(|error| {
        asset_error(
            description,
            format!(
                "failed to canonicalize {description} {}: {error}",
                path.display()
            ),
        )
    })
}

fn ensure_plain_file(metadata: &Metadata, path: &Path, description: &'static str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(asset_error(
            description,
            format!(
                "{description} must be a real regular file, not a symlink: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn hash_file(file: &File, size: u64, operation: &'static str, path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_SIZE];
    let mut offset = 0_u64;
    while offset < size {
        let remaining = size - offset;
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            asset_error(operation, format!("asset is too large: {}", path.display()))
        })?;
        let read = file
            .read_at(&mut buffer[..limit], offset)
            .map_err(|error| {
                asset_error(
                    operation,
                    format!("failed to read asset {}: {error}", path.display()),
                )
            })?;
        if read == 0 {
            return Err(asset_error(
                operation,
                format!(
                    "asset became shorter while it was hashed: {}",
                    path.display()
                ),
            ));
        }
        hasher.update(&buffer[..read]);
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            asset_error(operation, format!("asset is too large: {}", path.display()))
        })?;
    }
    let metadata = file.metadata().map_err(|error| {
        asset_error(
            operation,
            format!("failed to inspect hashed asset {}: {error}", path.display()),
        )
    })?;
    if metadata.len() != size {
        return Err(asset_error(
            operation,
            format!("asset size changed while it was hashed: {}", path.display()),
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let read = file.read_at(bytes, offset)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "asset became shorter while it was read",
            ));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("file offset overflow"))?;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

pub(crate) fn asset_error(operation: &'static str, message: String) -> Error {
    Error::new(ErrorCode::Unavailable, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::symlink;

    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::PinnedFile;

    #[test]
    fn hashes_and_reads_the_pinned_file() {
        let fixture = Fixture::new(b"macos-runtime-asset");
        let pinned = PinnedFile::open(&fixture.path, "test asset").expect("pin asset");
        let expected = digest(fixture.bytes.as_slice());

        assert_eq!(pinned.path(), fixture.path.canonicalize().unwrap());
        assert_eq!(pinned.size(), fixture.bytes.len() as u64);
        assert_eq!(pinned.sha256(), expected);
        assert_eq!(pinned.read_bounded(64).unwrap(), fixture.bytes);
        pinned.reverify("VM entry").expect("unchanged asset");

        let second = PinnedFile::open(&fixture.path, "test asset hash").unwrap();
        assert_eq!(second.sha256(), expected);
        assert_eq!(second.size(), fixture.bytes.len() as u64);
    }

    #[test]
    fn loader_path_reads_the_retained_descriptor_after_path_replacement() {
        let fixture = Fixture::new(b"macos-runtime-asset");
        let pinned = PinnedFile::open(&fixture.path, "test asset").expect("pin asset");
        let loader_path = pinned.loader_path();
        let moved = fixture.path.with_file_name("asset-moved");
        fs::rename(&fixture.path, &moved).expect("move original asset");
        fs::write(&fixture.path, b"replacement-asset").expect("create replacement asset");

        assert_eq!(
            fs::read(loader_path).expect("read descriptor-backed asset"),
            fixture.bytes
        );
        assert!(pinned
            .reverify("VM entry")
            .expect_err("replacement must be rejected")
            .to_string()
            .contains("identity changed"));
    }

    #[test]
    fn rejects_symlinked_assets() {
        let fixture = Fixture::new(b"asset");
        let link = fixture.path.with_file_name("asset-link");
        symlink(&fixture.path, &link).expect("create symlink");

        let error = PinnedFile::open(&link, "test asset")
            .expect_err("symlink must not cross the trust boundary");
        assert!(error.to_string().contains("not a symlink"));
    }

    #[test]
    fn missing_asset_error_keeps_the_typed_description() {
        let fixture = tempfile::tempdir().expect("create fixture directory");
        let missing = fixture.path().join("missing");

        let error = PinnedFile::open(&missing, "system-image manifest")
            .expect_err("missing asset must be rejected");

        assert!(error.to_string().contains("system-image manifest"));
    }

    #[test]
    fn detects_replacement_through_the_path() {
        let fixture = Fixture::new(b"original");
        let pinned = PinnedFile::open(&fixture.path, "test asset").expect("pin asset");
        let moved = fixture.path.with_file_name("asset-moved");
        fs::rename(&fixture.path, &moved).expect("move original");
        fs::write(&fixture.path, b"replacement").expect("create replacement");

        let error = pinned
            .reverify("VM entry")
            .expect_err("replacement must be rejected");
        assert!(error
            .to_string()
            .contains("identity changed before VM entry"));
    }

    #[test]
    fn detects_same_size_content_mutation() {
        let fixture = Fixture::new(b"original");
        let pinned = PinnedFile::open(&fixture.path, "test asset").expect("pin asset");
        let mut file = OpenOptions::new()
            .write(true)
            .open(&fixture.path)
            .expect("open asset for mutation");
        file.write_all(b"mutated!").expect("mutate asset");
        file.flush().expect("flush mutation");

        let error = pinned
            .reverify("VM entry")
            .expect_err("same-size mutation must be rejected");
        assert!(error
            .to_string()
            .contains("SHA-256 changed before VM entry"));
    }

    #[test]
    fn detects_growth_and_enforces_read_bound() {
        let fixture = Fixture::new(b"asset");
        assert!(PinnedFile::open_bounded(&fixture.path, "test asset", 4).is_err());
        let pinned = PinnedFile::open(&fixture.path, "test asset").expect("pin asset");
        assert!(pinned.read_bounded(4).is_err());

        let mut file = OpenOptions::new()
            .append(true)
            .open(&fixture.path)
            .expect("open asset for growth");
        file.write_all(b"-growth").expect("grow asset");
        file.flush().expect("flush growth");

        let error = pinned
            .reverify("VM entry")
            .expect_err("growth must be rejected");
        assert!(error
            .to_string()
            .contains("identity changed before VM entry"));
    }

    struct Fixture {
        _directory: TempDir,
        path: std::path::PathBuf,
        bytes: Vec<u8>,
    }

    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let directory = tempfile::tempdir().expect("create fixture directory");
            let path = directory.path().join("asset");
            File::create(&path)
                .and_then(|mut file| file.write_all(bytes))
                .expect("write fixture");
            Self {
                _directory: directory,
                path,
                bytes: bytes.to_vec(),
            }
        }
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}
