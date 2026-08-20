use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::Result;
use sha2::{Digest, Sha256};

use super::image_error;

#[derive(Debug)]
pub(super) struct PinnedFile {
    pub(super) path: PathBuf,
    pub(super) file: File,
    identity: FileIdentity,
    pub(super) size: u64,
    pub(super) sha256: String,
    description: &'static str,
}

impl PinnedFile {
    pub(super) fn open(path: &Path, description: &'static str) -> Result<Self> {
        let path = canonical_plain_file(path, description)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| {
                image_error(format!(
                    "failed to pin {description} {} read-only: {error}",
                    path.display()
                ))
            })?;
        let metadata = file.metadata().map_err(|error| {
            image_error(format!(
                "failed to inspect pinned {description} {}: {error}",
                path.display()
            ))
        })?;
        ensure_plain_file(&metadata, &path, description)?;
        let identity = FileIdentity::from_metadata(&metadata);
        let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
            image_error(format!(
                "failed to re-inspect {description} {} after pinning: {error}",
                path.display()
            ))
        })?;
        ensure_plain_file(&path_metadata, &path, description)?;
        if FileIdentity::from_metadata(&path_metadata) != identity {
            return Err(image_error(format!(
                "{description} changed while its descriptor was being pinned: {}",
                path.display()
            )));
        }
        let size = metadata.len();
        let sha256 = sha256_file(&file, size, description, &path)?;
        Ok(Self {
            path,
            file,
            identity,
            size,
            sha256,
            description,
        })
    }

    pub(super) fn require(&self, size: u64, sha256: &str) -> Result<()> {
        if self.size == size && self.sha256 == sha256 {
            Ok(())
        } else {
            Err(image_error(format!(
                "{} does not match manifest: expected {size} bytes and SHA-256 {sha256}, found {} bytes and {}",
                self.description, self.size, self.sha256
            )))
        }
    }

    pub(super) fn read_bounded(&self, limit: u64) -> Result<Vec<u8>> {
        if self.size > limit {
            return Err(image_error(format!(
                "{} exceeds {limit} bytes: {}",
                self.description,
                self.path.display()
            )));
        }
        let length = usize::try_from(self.size).map_err(|_| {
            image_error(format!(
                "{} is too large for this host: {}",
                self.description,
                self.path.display()
            ))
        })?;
        let mut bytes = vec![0_u8; length];
        read_exact_at(&self.file, &mut bytes, 0).map_err(|error| {
            image_error(format!(
                "failed to read {} {}: {error}",
                self.description,
                self.path.display()
            ))
        })?;
        Ok(bytes)
    }

    pub(super) fn reverify(&self) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            image_error(format!(
                "failed to re-inspect {} {}: {error}",
                self.description,
                self.path.display()
            ))
        })?;
        ensure_plain_file(&path_metadata, &self.path, self.description)?;
        let file_metadata = self.file.metadata().map_err(|error| {
            image_error(format!(
                "failed to re-inspect pinned {} {}: {error}",
                self.description,
                self.path.display()
            ))
        })?;
        if FileIdentity::from_metadata(&path_metadata) != self.identity
            || FileIdentity::from_metadata(&file_metadata) != self.identity
            || path_metadata.len() != self.size
            || file_metadata.len() != self.size
        {
            return Err(image_error(format!(
                "{} identity changed before native API use: {}",
                self.description,
                self.path.display()
            )));
        }
        let sha256 = sha256_file(&self.file, self.size, self.description, &self.path)?;
        if sha256 != self.sha256 {
            return Err(image_error(format!(
                "{} SHA-256 changed before native API use: expected {}, found {sha256}",
                self.description, self.sha256
            )));
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

pub(super) fn resolve_sibling(parent: &Path, name: &str, description: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(image_error(format!(
            "manifest image.name must be one plain file name: {name:?}"
        )));
    }
    let candidate = parent.join(path);
    let canonical = canonical_plain_file(&candidate, description)?;
    if canonical.parent() != Some(parent) {
        return Err(image_error(format!(
            "{description} must be a sibling of its manifest: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn canonical_plain_file(path: &Path, description: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(image_error(format!(
            "{description} path must be absolute: {}",
            path.display()
        )));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        image_error(format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        ))
    })?;
    ensure_plain_file(&metadata, path, description)?;
    let canonical = path.canonicalize().map_err(|error| {
        image_error(format!(
            "failed to canonicalize {description} {}: {error}",
            path.display()
        ))
    })?;
    if canonical != path {
        return Err(image_error(format!(
            "{description} path must not traverse symbolic links or aliases: {}",
            path.display()
        )));
    }
    Ok(canonical)
}

fn ensure_plain_file(metadata: &Metadata, path: &Path, description: &str) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(image_error(format!(
            "{description} must be a real regular file, not a symbolic link: {}",
            path.display()
        )));
    }
    Ok(())
}

fn sha256_file(file: &File, size: u64, description: &str, path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;
    while offset < size {
        let remaining = size - offset;
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| image_error(format!("{description} is too large: {}", path.display())))?;
        let read = file
            .read_at(&mut buffer[..limit], offset)
            .map_err(|error| {
                image_error(format!(
                    "failed to hash {description} {}: {error}",
                    path.display()
                ))
            })?;
        if read == 0 {
            return Err(image_error(format!(
                "{description} became shorter while it was hashed: {}",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
        offset = offset.checked_add(read as u64).ok_or_else(|| {
            image_error(format!("{description} is too large: {}", path.display()))
        })?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let read = file.read_at(bytes, offset)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "file became shorter while it was read",
            ));
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("file offset overflow"))?;
        bytes = &mut bytes[read..];
    }
    Ok(())
}
