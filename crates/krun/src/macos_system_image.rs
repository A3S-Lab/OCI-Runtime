use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::macos_assets::{sha256_file, MacosRuntimeProvenance};
use crate::MacosBootAssetsEvidence;

const SCHEMA_VERSION: &str = "a3s.oci.macos-system-image.v1";
const COMPATIBILITY_LEVEL: &str = "a3s-oci-runtime-0.2.0-agent-protocol-v10";
const IMAGE_NAME: &str = "a3s-oci-system.ext4";
const IMAGE_SIZE: u64 = 67_108_864;
const ARCHITECTURE: &str = "aarch64";
const FILESYSTEM: &str = "ext4";
const FILESYSTEM_UUID: &str = "a3a30c1a-2026-4000-8000-000000000001";
const FILESYSTEM_LABEL: &str = "a3s-oci-system";
const DIRECTORY_HASH_SEED: &str = "a3a30c1a-2026-4000-8000-000000000002";
const ALPINE_VERSION: &str = "3.22.5";
const ALPINE_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz";
const ALPINE_ARCHIVE_SIZE: u64 = 3_966_256;
const ALPINE_ARCHIVE_SHA256: &str =
    "3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const SOURCE_DATE_EPOCH: u64 = 1_735_689_600;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosSystemImage {
    manifest_path: PathBuf,
    manifest_sha256: String,
    manifest_size: u64,
    manifest_device: u64,
    manifest_inode: u64,
    image_path: PathBuf,
    image_sha256: String,
    image_size: u64,
    image_device: u64,
    image_inode: u64,
    runtime: MacosRuntimeProvenance,
}

impl MacosSystemImage {
    pub(crate) fn load(manifest_path: &Path, runtime: &MacosRuntimeProvenance) -> Result<Self> {
        let manifest_path = canonical_plain_file(manifest_path, "system-image manifest")?;
        let metadata = fs::symlink_metadata(&manifest_path).map_err(|error| {
            image_error(format!(
                "failed to inspect system-image manifest {}: {error}",
                manifest_path.display()
            ))
        })?;
        if metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
            return Err(image_error(format!(
                "system-image manifest size must be between 1 and {MAX_MANIFEST_BYTES} bytes: {}",
                manifest_path.display()
            )));
        }

        let bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
        let manifest_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let manifest: Manifest = strict_json(&bytes)?;
        manifest.validate(runtime)?;

        let parent = manifest_path.parent().ok_or_else(|| {
            image_error(format!(
                "system-image manifest has no parent directory: {}",
                manifest_path.display()
            ))
        })?;
        let image_path = resolve_manifest_sibling(parent, &manifest.image.name)?;
        let image_metadata = fs::symlink_metadata(&image_path).map_err(|error| {
            image_error(format!(
                "failed to inspect raw system image {}: {error}",
                image_path.display()
            ))
        })?;
        if image_metadata.file_type().is_symlink() || !image_metadata.file_type().is_file() {
            return Err(image_error(format!(
                "raw system image must be a real regular file, not a symlink: {}",
                image_path.display()
            )));
        }
        let (image_sha256, image_size) = sha256_file(&image_path, "verify-macos-system-image")?;
        if image_size != manifest.image.size || image_sha256 != manifest.image.sha256 {
            return Err(image_error(format!(
                "raw system image does not match manifest: expected {} bytes and SHA-256 {}, found {} bytes and {}",
                manifest.image.size, manifest.image.sha256, image_size, image_sha256
            )));
        }

        Ok(Self {
            manifest_path,
            manifest_sha256,
            manifest_size: metadata.len(),
            manifest_device: metadata.dev(),
            manifest_inode: metadata.ino(),
            image_path,
            image_sha256,
            image_size,
            image_device: image_metadata.dev(),
            image_inode: image_metadata.ino(),
            runtime: runtime.clone(),
        })
    }

    pub(crate) fn reverify(&self, runtime: &MacosRuntimeProvenance) -> Result<()> {
        if runtime != &self.runtime {
            return Err(image_error(
                "loaded macOS runtime provenance changed before VM entry".to_string(),
            ));
        }
        verify_identity(
            &self.manifest_path,
            self.manifest_device,
            self.manifest_inode,
            self.manifest_size,
            "system-image manifest",
        )?;
        let (manifest_sha256, _) = sha256_file(&self.manifest_path, "reverify-macos-system-image")?;
        if manifest_sha256 != self.manifest_sha256 {
            return Err(image_error(format!(
                "system-image manifest SHA-256 changed before VM entry: expected {}, found {manifest_sha256}",
                self.manifest_sha256
            )));
        }

        verify_identity(
            &self.image_path,
            self.image_device,
            self.image_inode,
            self.image_size,
            "raw system image",
        )?;
        let (image_sha256, _) = sha256_file(&self.image_path, "reverify-macos-system-image")?;
        if image_sha256 != self.image_sha256 {
            return Err(image_error(format!(
                "raw system image SHA-256 changed before VM entry: expected {}, found {image_sha256}",
                self.image_sha256
            )));
        }
        Ok(())
    }

    pub(crate) fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub(crate) fn image_path(&self) -> &Path {
        &self.image_path
    }

    pub(crate) fn evidence(&self, runtime_share_separate: bool) -> MacosBootAssetsEvidence {
        MacosBootAssetsEvidence {
            manifest_sha256: self.manifest_sha256.clone(),
            system_image_sha256: self.image_sha256.clone(),
            system_image_size: self.image_size,
            runtime_archive_sha256: self.runtime.runtime_archive_sha256.clone(),
            libkrun_sha256: self.runtime.libkrun_sha256.clone(),
            firmware_sha256: self.runtime.firmware_sha256.clone(),
            kernel_bundle_sha256: self.runtime.kernel_bundle_sha256.clone(),
            kernel_bundle_size: self.runtime.kernel_bundle_size,
            kernel_guest_load_address: format!("0x{:016x}", self.runtime.kernel_guest_load_address),
            kernel_entry_address: format!("0x{:016x}", self.runtime.kernel_entry_address),
            root_disk_read_only: true,
            runtime_share_separate,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    compatibility_level: String,
    architecture: String,
    image: Image,
    sources: Sources,
    runtime: Runtime,
}

impl Manifest {
    fn validate(&self, runtime: &MacosRuntimeProvenance) -> Result<()> {
        require_equal("schema_version", &self.schema_version, SCHEMA_VERSION)?;
        require_equal(
            "compatibility_level",
            &self.compatibility_level,
            COMPATIBILITY_LEVEL,
        )?;
        require_equal("architecture", &self.architecture, ARCHITECTURE)?;
        self.image.validate()?;
        self.sources.validate()?;
        self.runtime.validate(runtime)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Image {
    name: String,
    size: u64,
    sha256: String,
    archive_name: String,
    archive_size: u64,
    archive_sha256: String,
    filesystem: String,
    filesystem_uuid: String,
    filesystem_label: String,
    directory_hash_seed: String,
}

impl Image {
    fn validate(&self) -> Result<()> {
        require_equal("image.name", &self.name, IMAGE_NAME)?;
        require_number("image.size", self.size, IMAGE_SIZE)?;
        require_sha256("image.sha256", &self.sha256)?;
        require_equal(
            "image.archive_name",
            &self.archive_name,
            "a3s-oci-system.ext4.xz",
        )?;
        if self.archive_size == 0 {
            return Err(image_error(
                "manifest image.archive_size must be positive".to_string(),
            ));
        }
        require_sha256("image.archive_sha256", &self.archive_sha256)?;
        require_equal("image.filesystem", &self.filesystem, FILESYSTEM)?;
        require_equal(
            "image.filesystem_uuid",
            &self.filesystem_uuid,
            FILESYSTEM_UUID,
        )?;
        require_equal(
            "image.filesystem_label",
            &self.filesystem_label,
            FILESYSTEM_LABEL,
        )?;
        require_equal(
            "image.directory_hash_seed",
            &self.directory_hash_seed,
            DIRECTORY_HASH_SEED,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    alpine: Alpine,
    agent: Agent,
    builder: Builder,
}

impl Sources {
    fn validate(&self) -> Result<()> {
        self.alpine.validate()?;
        self.agent.validate()?;
        self.builder.validate()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Alpine {
    version: String,
    url: String,
    archive_size: u64,
    archive_sha256: String,
}

impl Alpine {
    fn validate(&self) -> Result<()> {
        require_equal("sources.alpine.version", &self.version, ALPINE_VERSION)?;
        require_equal("sources.alpine.url", &self.url, ALPINE_URL)?;
        require_number(
            "sources.alpine.archive_size",
            self.archive_size,
            ALPINE_ARCHIVE_SIZE,
        )?;
        require_equal(
            "sources.alpine.archive_sha256",
            &self.archive_sha256,
            ALPINE_ARCHIVE_SHA256,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Agent {
    version: String,
    size: u64,
    sha256: String,
}

impl Agent {
    fn validate(&self) -> Result<()> {
        require_equal("sources.agent.version", &self.version, AGENT_VERSION)?;
        if self.size == 0 {
            return Err(image_error(
                "manifest sources.agent.size must be positive".to_string(),
            ));
        }
        require_sha256("sources.agent.sha256", &self.sha256)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Builder {
    source_date_epoch: u64,
    e2fsprogs_version: String,
}

impl Builder {
    fn validate(&self) -> Result<()> {
        require_number(
            "sources.builder.source_date_epoch",
            self.source_date_epoch,
            SOURCE_DATE_EPOCH,
        )?;
        if self.e2fsprogs_version.is_empty() || self.e2fsprogs_version.len() > 64 {
            return Err(image_error(
                "manifest sources.builder.e2fsprogs_version is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    archive_sha256: String,
    libkrun_sha256: String,
    firmware_sha256: String,
    kernel_bundle_size: u64,
    kernel_bundle_sha256: String,
    kernel_guest_load_address: String,
    kernel_entry_address: String,
}

impl Runtime {
    fn validate(&self, runtime: &MacosRuntimeProvenance) -> Result<()> {
        require_equal(
            "runtime.archive_sha256",
            &self.archive_sha256,
            &runtime.runtime_archive_sha256,
        )?;
        require_equal(
            "runtime.libkrun_sha256",
            &self.libkrun_sha256,
            &runtime.libkrun_sha256,
        )?;
        require_equal(
            "runtime.firmware_sha256",
            &self.firmware_sha256,
            &runtime.firmware_sha256,
        )?;
        require_number(
            "runtime.kernel_bundle_size",
            self.kernel_bundle_size,
            runtime.kernel_bundle_size,
        )?;
        require_equal(
            "runtime.kernel_bundle_sha256",
            &self.kernel_bundle_sha256,
            &runtime.kernel_bundle_sha256,
        )?;
        require_equal(
            "runtime.kernel_guest_load_address",
            &self.kernel_guest_load_address,
            &format!("0x{:016x}", runtime.kernel_guest_load_address),
        )?;
        require_equal(
            "runtime.kernel_entry_address",
            &self.kernel_entry_address,
            &format!("0x{:016x}", runtime.kernel_entry_address),
        )
    }
}

fn strict_json(bytes: &[u8]) -> Result<Manifest> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest = Manifest::deserialize(&mut deserializer)
        .map_err(|error| image_error(format!("system-image manifest is invalid: {error}")))?;
    deserializer.end().map_err(|error| {
        image_error(format!(
            "system-image manifest contains trailing data: {error}"
        ))
    })?;
    Ok(manifest)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|error| {
            image_error(format!(
                "failed to read system-image manifest {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() as u64 > limit {
        return Err(image_error(format!(
            "system-image manifest exceeds {limit} bytes: {}",
            path.display()
        )));
    }
    Ok(bytes)
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
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(image_error(format!(
            "{description} must be a real regular file, not a symlink: {}",
            path.display()
        )));
    }
    path.canonicalize().map_err(|error| {
        image_error(format!(
            "failed to canonicalize {description} {}: {error}",
            path.display()
        ))
    })
}

fn resolve_manifest_sibling(parent: &Path, name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(image_error(format!(
            "manifest image.name must be one plain file name: {name:?}"
        )));
    }
    let candidate = parent.join(path);
    let canonical = canonical_plain_file(&candidate, "raw system image")?;
    if canonical.parent() != Some(parent) {
        return Err(image_error(format!(
            "raw system image must be a sibling of its manifest: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn verify_identity(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
    expected_size: u64,
    description: &str,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        image_error(format!(
            "failed to re-inspect {description} {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
        || metadata.len() != expected_size
    {
        return Err(image_error(format!(
            "{description} identity changed before VM entry: {}",
            path.display()
        )));
    }
    Ok(())
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(image_error(format!(
            "manifest {field} mismatch: expected {expected:?}, found {actual:?}"
        )))
    }
}

fn require_number(field: &str, actual: u64, expected: u64) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(image_error(format!(
            "manifest {field} mismatch: expected {expected}, found {actual}"
        )))
    }
}

fn require_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(image_error(format!(
            "manifest {field} must be a lowercase SHA-256 digest"
        )))
    }
}

fn image_error(message: String) -> Error {
    Error::new(ErrorCode::Unavailable, message).for_operation("verify-macos-system-image")
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::{
        require_sha256, strict_json, MacosSystemImage, AGENT_VERSION, ALPINE_ARCHIVE_SHA256,
        ALPINE_ARCHIVE_SIZE, ALPINE_URL, ALPINE_VERSION, ARCHITECTURE, COMPATIBILITY_LEVEL,
        DIRECTORY_HASH_SEED, FILESYSTEM, FILESYSTEM_LABEL, FILESYSTEM_UUID, IMAGE_NAME, IMAGE_SIZE,
        SCHEMA_VERSION, SOURCE_DATE_EPOCH,
    };
    use crate::macos_assets::{
        MacosRuntimeProvenance, KERNEL_BUNDLE_SHA256, KERNEL_BUNDLE_SIZE, KERNEL_ENTRY_ADDRESS,
        KERNEL_GUEST_LOAD_ADDRESS,
    };

    struct Fixture {
        _directory: TempDir,
        manifest: PathBuf,
        image: PathBuf,
        runtime: MacosRuntimeProvenance,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create system-image fixture directory");
            let image = directory.path().join(IMAGE_NAME);
            let image_file = File::create(&image).expect("create sparse system image");
            image_file
                .set_len(IMAGE_SIZE)
                .expect("size sparse system image");
            drop(image_file);

            let runtime = MacosRuntimeProvenance::pinned(KERNEL_BUNDLE_SHA256.to_string());
            let manifest = directory.path().join("system-image.json");
            write_manifest(&manifest, &runtime, zero_image_sha256());
            Self {
                _directory: directory,
                manifest,
                image,
                runtime,
            }
        }

        fn load(&self) -> MacosSystemImage {
            MacosSystemImage::load(&self.manifest, &self.runtime)
                .expect("valid system-image fixture must load")
        }
    }

    #[test]
    fn rejects_unknown_manifest_fields() {
        let error = strict_json(br#"{"schema_version":"x","unexpected":true}"#)
            .expect_err("unknown fields must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_noncanonical_digests() {
        assert!(require_sha256("test", &"A".repeat(64)).is_err());
        assert!(require_sha256("test", &"0".repeat(63)).is_err());
        assert!(require_sha256("test", &"f".repeat(64)).is_ok());
    }

    #[test]
    fn rejects_manifest_and_image_symlinks() {
        let fixture = Fixture::new();
        let manifest_link = fixture
            .manifest
            .parent()
            .expect("manifest parent")
            .join("manifest-link.json");
        symlink(&fixture.manifest, &manifest_link).expect("create manifest symlink");
        let error = MacosSystemImage::load(&manifest_link, &fixture.runtime)
            .expect_err("manifest symlink must fail closed");
        assert!(error.to_string().contains("not a symlink"));

        let image_target = fixture
            .image
            .parent()
            .expect("image parent")
            .join("image-target.ext4");
        fs::rename(&fixture.image, &image_target).expect("move real image");
        symlink(&image_target, &fixture.image).expect("replace image with symlink");
        let error = MacosSystemImage::load(&fixture.manifest, &fixture.runtime)
            .expect_err("image symlink must fail closed");
        assert!(error.to_string().contains("not a symlink"));
    }

    #[test]
    fn rejects_raw_image_content_tampering() {
        let fixture = Fixture::new();
        overwrite_first_byte(&fixture.image, 1);
        let error = MacosSystemImage::load(&fixture.manifest, &fixture.runtime)
            .expect_err("tampered image must fail closed at load");
        assert!(error.to_string().contains("does not match manifest"));
    }

    #[test]
    fn detects_manifest_and_image_changes_before_vm_entry() {
        let fixture = Fixture::new();
        let image = fixture.load();
        replace_same_size(&fixture.manifest, b"aarch64", b"aarch65");
        let error = image
            .reverify(&fixture.runtime)
            .expect_err("manifest content drift must fail closed");
        assert!(error.to_string().contains("manifest SHA-256 changed"));

        let fixture = Fixture::new();
        let image = fixture.load();
        overwrite_first_byte(&fixture.image, 1);
        let error = image
            .reverify(&fixture.runtime)
            .expect_err("image content drift must fail closed");
        assert!(error.to_string().contains("image SHA-256 changed"));
    }

    #[test]
    fn detects_image_replacement_before_vm_entry() {
        let fixture = Fixture::new();
        let image = fixture.load();
        let replaced = fixture.image.with_extension("replaced");
        fs::rename(&fixture.image, &replaced).expect("move verified image");
        let replacement = File::create(&fixture.image).expect("create replacement image");
        replacement
            .set_len(IMAGE_SIZE)
            .expect("size replacement image");
        drop(replacement);

        let error = image
            .reverify(&fixture.runtime)
            .expect_err("image inode drift must fail closed");
        assert!(error
            .to_string()
            .contains("identity changed before VM entry"));
    }

    #[test]
    fn detects_every_runtime_provenance_drift_before_vm_entry() {
        let fixture = Fixture::new();
        let image = fixture.load();

        let mut libkrun_drift = fixture.runtime.clone();
        libkrun_drift.libkrun_sha256 = "1".repeat(64);
        assert!(image.reverify(&libkrun_drift).is_err());

        let mut firmware_drift = fixture.runtime.clone();
        firmware_drift.firmware_sha256 = "2".repeat(64);
        assert!(image.reverify(&firmware_drift).is_err());

        let mut kernel_drift = fixture.runtime.clone();
        kernel_drift.kernel_bundle_sha256 = "3".repeat(64);
        assert!(image.reverify(&kernel_drift).is_err());
    }

    fn write_manifest(path: &Path, runtime: &MacosRuntimeProvenance, image_sha256: String) {
        let manifest = json!({
            "schema_version": SCHEMA_VERSION,
            "compatibility_level": COMPATIBILITY_LEVEL,
            "architecture": ARCHITECTURE,
            "image": {
                "name": IMAGE_NAME,
                "size": IMAGE_SIZE,
                "sha256": image_sha256,
                "archive_name": "a3s-oci-system.ext4.xz",
                "archive_size": 1,
                "archive_sha256": "0".repeat(64),
                "filesystem": FILESYSTEM,
                "filesystem_uuid": FILESYSTEM_UUID,
                "filesystem_label": FILESYSTEM_LABEL,
                "directory_hash_seed": DIRECTORY_HASH_SEED
            },
            "sources": {
                "alpine": {
                    "version": ALPINE_VERSION,
                    "url": ALPINE_URL,
                    "archive_size": ALPINE_ARCHIVE_SIZE,
                    "archive_sha256": ALPINE_ARCHIVE_SHA256
                },
                "agent": {
                    "version": AGENT_VERSION,
                    "size": 1,
                    "sha256": "4".repeat(64)
                },
                "builder": {
                    "source_date_epoch": SOURCE_DATE_EPOCH,
                    "e2fsprogs_version": "1.47.0"
                }
            },
            "runtime": {
                "archive_sha256": runtime.runtime_archive_sha256,
                "libkrun_sha256": runtime.libkrun_sha256,
                "firmware_sha256": runtime.firmware_sha256,
                "kernel_bundle_size": KERNEL_BUNDLE_SIZE,
                "kernel_bundle_sha256": runtime.kernel_bundle_sha256,
                "kernel_guest_load_address": format!("0x{KERNEL_GUEST_LOAD_ADDRESS:016x}"),
                "kernel_entry_address": format!("0x{KERNEL_ENTRY_ADDRESS:016x}")
            }
        });
        fs::write(
            path,
            serde_json::to_vec(&manifest).expect("serialize system-image fixture manifest"),
        )
        .expect("write system-image fixture manifest");
    }

    fn zero_image_sha256() -> String {
        let mut hasher = Sha256::new();
        let block = [0_u8; 64 * 1024];
        for _ in 0..(IMAGE_SIZE / block.len() as u64) {
            hasher.update(block);
        }
        format!("{:x}", hasher.finalize())
    }

    fn overwrite_first_byte(path: &Path, byte: u8) {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open fixture for tampering");
        file.seek(SeekFrom::Start(0)).expect("seek fixture");
        file.write_all(&[byte]).expect("tamper fixture");
        file.flush().expect("flush tampered fixture");
    }

    fn replace_same_size(path: &Path, from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .expect("read fixture for tampering");
        let position = bytes
            .windows(from.len())
            .position(|window| window == from)
            .expect("fixture contains replacement target");
        bytes[position..position + from.len()].copy_from_slice(to);
        fs::write(path, bytes).expect("write same-size tampered fixture");
    }
}
