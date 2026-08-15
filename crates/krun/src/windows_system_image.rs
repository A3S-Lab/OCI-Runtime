use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

use crate::WindowsBootAssetsEvidence;

const SCHEMA_VERSION: &str = "a3s.oci.windows-system-image.v1";
const COMPATIBILITY_LEVEL: &str = "a3s-oci-runtime-0.2.0-agent-protocol-v10";
const ARCHITECTURE: &str = "x86_64";
const IMAGE_NAME: &str = "a3s-oci-system.ext4";
const IMAGE_SIZE: u64 = 67_108_864;
const FILESYSTEM: &str = "ext4";
const FILESYSTEM_UUID: &str = "a3a30c1a-2026-4000-8000-000000000011";
const FILESYSTEM_LABEL: &str = "a3s-oci-system";
const DIRECTORY_HASH_SEED: &str = "a3a30c1a-2026-4000-8000-000000000012";
const ALPINE_VERSION: &str = "3.22.5";
const ALPINE_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.5-x86_64.tar.gz";
const ALPINE_ARCHIVE_SIZE: u64 = 3_638_276;
const ALPINE_ARCHIVE_SHA256: &str =
    "4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const SOURCE_DATE_EPOCH: u64 = 1_735_689_600;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

const RUNTIME_ARCHIVE_SIZE: u64 = 8_108_976;
const RUNTIME_ARCHIVE_SHA256: &str =
    "734f69936e5c6caee5f67ff5daf68a52d90d7f6f0be3dae41907f009db39c847";
const KRUN_DLL_NAME: &str = "krun.dll";
const KRUN_DLL_SIZE: u64 = 7_433_728;
const KRUN_DLL_SHA256: &str = "ac7724209635505c4ae7b3ba36edeb7fc5597353e6ffcc7351fbf97af1e0d5e5";
const KRUN_IMPORT_LIBRARY_NAME: &str = "krun.lib";
const KRUN_IMPORT_LIBRARY_SIZE: u64 = 11_870;
const KRUN_IMPORT_LIBRARY_SHA256: &str =
    "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d";
const FIRMWARE_NAME: &str = "libkrunfw.dll";
const FIRMWARE_SIZE: u64 = 21_473_280;
const FIRMWARE_SHA256: &str = "44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077";
const BOX_REVISION: &str = "93fc281a798cdfd8ee463f69add3f6989d561ee3";
const LIBKRUN_REVISION: &str = "75ec19097a337a60076a2ebff7cdad6acf8ca69c";
const FIRMWARE_WRAPPER_REVISION: &str = "2692169b7567363244fdd21cb83de3220ebf3021";
const LIBKRUNFW_REVISION: &str = "ec4b297964877d83432f9ccda6dad8ff6e9de3e4";
const KERNEL_VERSION: &str = "6.12.91";
const KERNEL_SOURCE_SHA256: &str =
    "0ff2ab9e169f9f1948557471fbb450d3018f8c5b77caf288e1a3982582597969";
const KERNEL_BUNDLE_SIZE: u64 = 21_364_736;
const KERNEL_BUNDLE_SHA256: &str =
    "781375ea09f4279ec5bfeab26ecc7067358a3fc98190467e2ab01cc6e98936dd";
const KERNEL_GUEST_LOAD_ADDRESS: &str = "0x0000000001000000";
const KERNEL_ENTRY_ADDRESS: &str = "0x0000000001000123";

/// Pinned Windows system image and the native boot assets that consume it.
///
/// Every retained handle allows read sharing only. Windows therefore refuses
/// writes, deletes, and replacements until libkrun has consumed the image and
/// the shim process exits.
#[derive(Debug)]
pub(crate) struct WindowsSystemImage {
    manifest: PinnedFile,
    image: PinnedFile,
    krun_dll: PinnedFile,
    firmware: PinnedFile,
    evidence: WindowsBootAssetsEvidence,
}

impl WindowsSystemImage {
    pub(crate) fn load(manifest_path: &Path) -> Result<Self> {
        let manifest = PinnedFile::open(manifest_path, "Windows system-image manifest")?;
        if manifest.size == 0 || manifest.size > MAX_MANIFEST_BYTES {
            return Err(image_error(format!(
                "Windows system-image manifest size must be between 1 and {MAX_MANIFEST_BYTES} bytes: {}",
                manifest.path.display()
            )));
        }
        let bytes = manifest.read_bounded(MAX_MANIFEST_BYTES)?;
        let decoded = strict_json(&bytes)?;
        decoded.validate()?;

        let parent = manifest.path.parent().ok_or_else(|| {
            image_error(format!(
                "Windows system-image manifest has no parent directory: {}",
                manifest.path.display()
            ))
        })?;
        let image_path = resolve_sibling(parent, &decoded.image.name, "raw Windows system image")?;
        let image = PinnedFile::open(&image_path, "raw Windows system image")?;
        image.require(decoded.image.size, &decoded.image.sha256)?;

        let executable = std::env::current_exe().map_err(|error| {
            image_error(format!(
                "failed to resolve the libkrun shim executable: {error}"
            ))
        })?;
        let executable = canonical_plain_file(&executable, "libkrun shim executable")?;
        let runtime_directory = executable.parent().ok_or_else(|| {
            image_error(format!(
                "libkrun shim executable has no parent directory: {}",
                executable.display()
            ))
        })?;
        if runtime_directory == parent
            || runtime_directory.starts_with(parent)
            || parent.starts_with(runtime_directory)
        {
            return Err(image_error(
                "Windows system-image assets and the executable runtime directory must be disjoint"
                    .to_string(),
            ));
        }

        let krun_dll_path = resolve_sibling(
            runtime_directory,
            &decoded.runtime.krun_dll.name,
            "adjacent krun.dll",
        )?;
        let krun_dll = PinnedFile::open(&krun_dll_path, "adjacent krun.dll")?;
        krun_dll.require(
            decoded.runtime.krun_dll.size,
            &decoded.runtime.krun_dll.sha256,
        )?;

        let firmware_path = resolve_sibling(
            runtime_directory,
            &decoded.runtime.firmware.name,
            "adjacent libkrunfw.dll",
        )?;
        let firmware = PinnedFile::open(&firmware_path, "adjacent libkrunfw.dll")?;
        firmware.require(
            decoded.runtime.firmware.size,
            &decoded.runtime.firmware.sha256,
        )?;

        verify_loaded_module(KRUN_DLL_NAME, &krun_dll)?;

        let evidence = WindowsBootAssetsEvidence {
            manifest_sha256: manifest.sha256.clone(),
            system_image_sha256: image.sha256.clone(),
            system_image_size: image.size,
            runtime_archive_sha256: decoded.runtime.archive_sha256.clone(),
            krun_dll_sha256: krun_dll.sha256.clone(),
            firmware_sha256: firmware.sha256.clone(),
            box_revision: decoded.runtime.sources.box_revision.clone(),
            libkrun_revision: decoded.runtime.sources.libkrun_revision.clone(),
            firmware_wrapper_revision: decoded.runtime.sources.firmware_wrapper_revision.clone(),
            libkrunfw_revision: decoded.runtime.sources.libkrunfw_revision.clone(),
            kernel_version: decoded.runtime.sources.kernel_version.clone(),
            kernel_source_sha256: decoded.runtime.sources.kernel_source_sha256.clone(),
            kernel_bundle_sha256: decoded.runtime.kernel.bundle_sha256.clone(),
            kernel_bundle_size: decoded.runtime.kernel.bundle_size,
            kernel_guest_load_address: decoded.runtime.kernel.guest_load_address.clone(),
            kernel_entry_address: decoded.runtime.kernel.entry_address.clone(),
            root_disk_read_only: true,
            runtime_share_separate: true,
        };
        if !evidence.is_success() {
            return Err(image_error(
                "Windows immutable boot-asset evidence is incomplete".to_string(),
            ));
        }

        Ok(Self {
            manifest,
            image,
            krun_dll,
            firmware,
            evidence,
        })
    }

    /// Revalidate every pinned byte and loaded module immediately before VM entry.
    pub(crate) fn reverify(&self) -> Result<()> {
        self.manifest.reverify()?;
        self.image.reverify()?;
        self.krun_dll.reverify()?;
        self.firmware.reverify()?;
        verify_loaded_module(KRUN_DLL_NAME, &self.krun_dll)?;
        verify_loaded_module(FIRMWARE_NAME, &self.firmware)
    }

    pub(crate) fn image_path(&self) -> &Path {
        &self.image.path
    }

    pub(crate) fn evidence(&self) -> WindowsBootAssetsEvidence {
        self.evidence.clone()
    }
}

#[derive(Debug)]
struct PinnedFile {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    size: u64,
    sha256: String,
    description: &'static str,
}

impl PinnedFile {
    fn open(path: &Path, description: &'static str) -> Result<Self> {
        let path = canonical_plain_file(path, description)?;
        let file = open_read_pinned(&path, description)?;
        let metadata = file.metadata().map_err(|error| {
            image_error(format!(
                "failed to inspect pinned {description} {}: {error}",
                path.display()
            ))
        })?;
        ensure_plain_file_metadata(&metadata, &path, description)?;
        let identity = FileIdentity::from_file(&file, &path, description)?;
        let path_identity = path_identity(&path, description)?;
        if path_identity != identity {
            return Err(image_error(format!(
                "{description} changed while its read-only handle was being pinned: {}",
                path.display()
            )));
        }
        let size = metadata.file_size();
        let sha256 = sha256_handle(&file, &path, description)?;
        Ok(Self {
            path,
            file,
            identity,
            size,
            sha256,
            description,
        })
    }

    fn require(&self, expected_size: u64, expected_sha256: &str) -> Result<()> {
        if self.size == expected_size && self.sha256 == expected_sha256 {
            Ok(())
        } else {
            Err(image_error(format!(
                "{} does not match the manifest: expected {expected_size} bytes and SHA-256 {expected_sha256}, found {} bytes and {}",
                self.description, self.size, self.sha256
            )))
        }
    }

    fn read_bounded(&self, limit: u64) -> Result<Vec<u8>> {
        let mut file = &self.file;
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            image_error(format!(
                "failed to seek {} {}: {error}",
                self.description,
                self.path.display()
            ))
        })?;
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                image_error(format!(
                    "failed to read {} {}: {error}",
                    self.description,
                    self.path.display()
                ))
            })?;
        if bytes.len() as u64 > limit {
            return Err(image_error(format!(
                "{} exceeds {limit} bytes: {}",
                self.description,
                self.path.display()
            )));
        }
        Ok(bytes)
    }

    fn reverify(&self) -> Result<()> {
        let reopened = open_read_pinned(&self.path, self.description)?;
        let metadata = reopened.metadata().map_err(|error| {
            image_error(format!(
                "failed to re-inspect {} {}: {error}",
                self.description,
                self.path.display()
            ))
        })?;
        ensure_plain_file_metadata(&metadata, &self.path, self.description)?;
        let identity = FileIdentity::from_file(&reopened, &self.path, self.description)?;
        if identity != self.identity || metadata.file_size() != self.size {
            return Err(image_error(format!(
                "{} identity changed before VM entry: {}",
                self.description,
                self.path.display()
            )));
        }
        let sha256 = sha256_handle(&self.file, &self.path, self.description)?;
        if sha256 != self.sha256 {
            return Err(image_error(format!(
                "{} SHA-256 changed before VM entry: expected {}, found {sha256}",
                self.description, self.sha256
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

impl FileIdentity {
    fn from_file(file: &File, path: &Path, description: &str) -> Result<Self> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: file owns a valid handle for the duration of the call and
        // information points to writable storage of the exact required type.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if succeeded == 0 {
            return Err(image_error(format!(
                "failed to obtain the file identity for {description} {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: GetFileInformationByHandle returned success and initialized
        // the complete BY_HANDLE_FILE_INFORMATION value.
        let information = unsafe { information.assume_init() };
        Ok(Self {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
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
    fn validate(&self) -> Result<()> {
        require_equal("schema_version", &self.schema_version, SCHEMA_VERSION)?;
        require_equal(
            "compatibility_level",
            &self.compatibility_level,
            COMPATIBILITY_LEVEL,
        )?;
        require_equal("architecture", &self.architecture, ARCHITECTURE)?;
        self.image.validate()?;
        self.sources.validate()?;
        self.runtime.validate()
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
    archive_size: u64,
    archive_sha256: String,
    krun_dll: RuntimeFile,
    import_library: RuntimeFile,
    firmware: RuntimeFile,
    sources: RuntimeSources,
    kernel: Kernel,
}

impl Runtime {
    fn validate(&self) -> Result<()> {
        require_number(
            "runtime.archive_size",
            self.archive_size,
            RUNTIME_ARCHIVE_SIZE,
        )?;
        require_equal(
            "runtime.archive_sha256",
            &self.archive_sha256,
            RUNTIME_ARCHIVE_SHA256,
        )?;
        self.krun_dll.validate(
            "runtime.krun_dll",
            KRUN_DLL_NAME,
            KRUN_DLL_SIZE,
            KRUN_DLL_SHA256,
        )?;
        self.import_library.validate(
            "runtime.import_library",
            KRUN_IMPORT_LIBRARY_NAME,
            KRUN_IMPORT_LIBRARY_SIZE,
            KRUN_IMPORT_LIBRARY_SHA256,
        )?;
        self.firmware.validate(
            "runtime.firmware",
            FIRMWARE_NAME,
            FIRMWARE_SIZE,
            FIRMWARE_SHA256,
        )?;
        self.sources.validate()?;
        self.kernel.validate()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFile {
    name: String,
    size: u64,
    sha256: String,
}

impl RuntimeFile {
    fn validate(&self, field: &str, name: &str, size: u64, sha256: &str) -> Result<()> {
        require_equal(&format!("{field}.name"), &self.name, name)?;
        require_number(&format!("{field}.size"), self.size, size)?;
        require_equal(&format!("{field}.sha256"), &self.sha256, sha256)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSources {
    box_revision: String,
    libkrun_revision: String,
    firmware_wrapper_revision: String,
    libkrunfw_revision: String,
    kernel_version: String,
    kernel_source_sha256: String,
}

impl RuntimeSources {
    fn validate(&self) -> Result<()> {
        require_equal(
            "runtime.sources.box_revision",
            &self.box_revision,
            BOX_REVISION,
        )?;
        require_equal(
            "runtime.sources.libkrun_revision",
            &self.libkrun_revision,
            LIBKRUN_REVISION,
        )?;
        require_equal(
            "runtime.sources.firmware_wrapper_revision",
            &self.firmware_wrapper_revision,
            FIRMWARE_WRAPPER_REVISION,
        )?;
        require_equal(
            "runtime.sources.libkrunfw_revision",
            &self.libkrunfw_revision,
            LIBKRUNFW_REVISION,
        )?;
        require_equal(
            "runtime.sources.kernel_version",
            &self.kernel_version,
            KERNEL_VERSION,
        )?;
        require_equal(
            "runtime.sources.kernel_source_sha256",
            &self.kernel_source_sha256,
            KERNEL_SOURCE_SHA256,
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Kernel {
    bundle_size: u64,
    bundle_sha256: String,
    guest_load_address: String,
    entry_address: String,
}

impl Kernel {
    fn validate(&self) -> Result<()> {
        require_number(
            "runtime.kernel.bundle_size",
            self.bundle_size,
            KERNEL_BUNDLE_SIZE,
        )?;
        require_equal(
            "runtime.kernel.bundle_sha256",
            &self.bundle_sha256,
            KERNEL_BUNDLE_SHA256,
        )?;
        require_equal(
            "runtime.kernel.guest_load_address",
            &self.guest_load_address,
            KERNEL_GUEST_LOAD_ADDRESS,
        )?;
        require_equal(
            "runtime.kernel.entry_address",
            &self.entry_address,
            KERNEL_ENTRY_ADDRESS,
        )
    }
}

fn strict_json(bytes: &[u8]) -> Result<Manifest> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest = Manifest::deserialize(&mut deserializer).map_err(|error| {
        image_error(format!("Windows system-image manifest is invalid: {error}"))
    })?;
    deserializer.end().map_err(|error| {
        image_error(format!(
            "Windows system-image manifest contains trailing data: {error}"
        ))
    })?;
    Ok(manifest)
}

fn canonical_plain_file(path: &Path, description: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(image_error(format!(
            "{description} path must be absolute: {}",
            path.display()
        )));
    }
    reject_reparse_ancestors(path, description)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        image_error(format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        ))
    })?;
    ensure_plain_file_metadata(&metadata, path, description)?;
    let canonical = path.canonicalize().map_err(|error| {
        image_error(format!(
            "failed to canonicalize {description} {}: {error}",
            path.display()
        ))
    })?;
    reject_reparse_ancestors(&canonical, description)?;
    Ok(canonical)
}

fn reject_reparse_ancestors(path: &Path, description: &str) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.parent().is_none() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| {
            image_error(format!(
                "failed to inspect {description} ancestor {}: {error}",
                ancestor.display()
            ))
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(image_error(format!(
                "{description} path must not traverse a reparse point: {}",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

fn ensure_plain_file_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    description: &str,
) -> Result<()> {
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(image_error(format!(
            "{description} must be a real regular file, not a reparse point: {}",
            path.display()
        )));
    }
    Ok(())
}

fn open_read_pinned(path: &Path, description: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
        .map_err(|error| {
            image_error(format!(
                "failed to pin {description} {} for read-only VM use: {error}",
                path.display()
            ))
        })
}

fn path_identity(path: &Path, description: &str) -> Result<FileIdentity> {
    let file = open_read_pinned(path, description)?;
    let metadata = file.metadata().map_err(|error| {
        image_error(format!(
            "failed to inspect {description} identity {}: {error}",
            path.display()
        ))
    })?;
    ensure_plain_file_metadata(&metadata, path, description)?;
    FileIdentity::from_file(&file, path, description)
}

fn resolve_sibling(parent: &Path, name: &str, description: &'static str) -> Result<PathBuf> {
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(image_error(format!(
            "{description} name must be one plain file name: {name:?}"
        )));
    }
    let candidate = parent.join(path);
    let canonical = canonical_plain_file(&candidate, description)?;
    if canonical.parent() != Some(parent) {
        return Err(image_error(format!(
            "{description} must remain in its trusted directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn sha256_handle(file: &File, path: &Path, description: &str) -> Result<String> {
    let mut file = file;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        image_error(format!(
            "failed to seek {description} {}: {error}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            image_error(format!(
                "failed to hash {description} {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_loaded_module(name: &str, expected: &PinnedFile) -> Result<()> {
    let wide_name = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: wide_name is NUL terminated and remains live for the call.
    let module = unsafe { GetModuleHandleW(wide_name.as_ptr()) };
    if module.is_null() {
        return Err(image_error(format!(
            "the pinned Windows runtime module is not loaded: {name}"
        )));
    }
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: module is owned by the current process and buffer is writable for
    // exactly the supplied number of UTF-16 code units.
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(image_error(format!(
            "failed to resolve the loaded Windows runtime module path: {name}"
        )));
    }
    let loaded = PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
    let loaded = canonical_plain_file(&loaded, "loaded Windows runtime module")?;
    let loaded_identity = path_identity(&loaded, "loaded Windows runtime module")?;
    if loaded != expected.path || loaded_identity != expected.identity {
        return Err(image_error(format!(
            "loaded Windows runtime module does not match the pinned adjacent file: expected {}, found {}",
            expected.path.display(),
            loaded.display()
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
    Error::new(ErrorCode::Unavailable, message).for_operation("verify-windows-system-image")
}

#[cfg(test)]
mod tests;
