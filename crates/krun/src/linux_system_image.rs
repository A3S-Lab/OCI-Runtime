use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

use crate::runtime_assets::{RuntimeBundle, RuntimeFileRole};
use crate::LinuxBootAssetsEvidence;

mod manifest;
mod pinned_file;

use manifest::strict_json;
use pinned_file::{resolve_sibling, PinnedFile};

const SCHEMA_VERSION: &str = "a3s.oci.linux-kvm-system-image.v1";
const COMPATIBILITY_LEVEL: &str = "a3s-oci-runtime-0.2.0-agent-protocol-v10";
const IMAGE_NAME: &str = "a3s-oci-system.ext4";
const IMAGE_SIZE: u64 = 67_108_864;
const FILESYSTEM: &str = "ext4";
const FILESYSTEM_LABEL: &str = "a3s-oci-system";
const ALPINE_VERSION: &str = "3.22.5";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const SOURCE_DATE_EPOCH: u64 = 1_735_689_600;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[cfg(target_arch = "x86_64")]
const ARCHITECTURE: &str = "x86_64";
#[cfg(target_arch = "x86_64")]
const FILESYSTEM_UUID: &str = "a3a30c1a-2026-4000-8000-000000000021";
#[cfg(target_arch = "x86_64")]
const DIRECTORY_HASH_SEED: &str = "a3a30c1a-2026-4000-8000-000000000022";
#[cfg(target_arch = "x86_64")]
const ALPINE_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.5-x86_64.tar.gz";
#[cfg(target_arch = "x86_64")]
const ALPINE_ARCHIVE_SIZE: u64 = 3_638_276;
#[cfg(target_arch = "x86_64")]
const ALPINE_ARCHIVE_SHA256: &str =
    "4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282";

#[cfg(target_arch = "aarch64")]
const ARCHITECTURE: &str = "aarch64";
#[cfg(target_arch = "aarch64")]
const FILESYSTEM_UUID: &str = "a3a30c1a-2026-4000-8000-000000000031";
#[cfg(target_arch = "aarch64")]
const DIRECTORY_HASH_SEED: &str = "a3a30c1a-2026-4000-8000-000000000032";
#[cfg(target_arch = "aarch64")]
const ALPINE_URL: &str =
    "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz";
#[cfg(target_arch = "aarch64")]
const ALPINE_ARCHIVE_SIZE: u64 = 3_966_256;
#[cfg(target_arch = "aarch64")]
const ALPINE_ARCHIVE_SHA256: &str =
    "3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70";

/// Manifest-verified immutable Linux root disk retained by the shim.
#[derive(Debug)]
pub(crate) struct LinuxSystemImage {
    manifest: PinnedFile,
    image: PinnedFile,
    runtime: RuntimeBundle,
    evidence: LinuxBootAssetsEvidence,
}

impl LinuxSystemImage {
    pub(crate) fn load(manifest_path: &Path, runtime: &RuntimeBundle) -> Result<Self> {
        if runtime.target_os != "linux" || runtime.target_arch != ARCHITECTURE {
            return Err(image_error(format!(
                "runtime target must be linux {ARCHITECTURE}, found {} {}",
                runtime.target_os, runtime.target_arch
            )));
        }

        let manifest = PinnedFile::open(manifest_path, "Linux system-image manifest")?;
        if manifest.size == 0 || manifest.size > MAX_MANIFEST_BYTES {
            return Err(image_error(format!(
                "Linux system-image manifest size must be between 1 and {MAX_MANIFEST_BYTES} bytes: {}",
                manifest.path.display()
            )));
        }
        let decoded = strict_json(&manifest.read_bounded(MAX_MANIFEST_BYTES)?)?;
        decoded.validate(runtime)?;

        let parent = manifest.path.parent().ok_or_else(|| {
            image_error(format!(
                "Linux system-image manifest has no parent directory: {}",
                manifest.path.display()
            ))
        })?;
        let image_path = resolve_sibling(parent, &decoded.image.name, "raw Linux system image")?;
        let image = PinnedFile::open(&image_path, "raw Linux system image")?;
        image.require(decoded.image.size, &decoded.image.sha256)?;

        let library = runtime.file(RuntimeFileRole::Library).ok_or_else(|| {
            image_error("validated Linux runtime has no library role".to_string())
        })?;
        let firmware = runtime.file(RuntimeFileRole::Firmware).ok_or_else(|| {
            image_error("validated Linux runtime has no firmware role".to_string())
        })?;
        let evidence = LinuxBootAssetsEvidence {
            target_arch: ARCHITECTURE.to_string(),
            manifest_sha256: manifest.sha256.clone(),
            system_image_sha256: image.sha256.clone(),
            system_image_size: image.size,
            guest_agent_sha256: decoded.sources.agent.sha256.clone(),
            guest_agent_size: decoded.sources.agent.size,
            runtime_archive_sha256: runtime.archive_sha256.clone(),
            libkrun_sha256: library.sha256.clone(),
            firmware_sha256: firmware.sha256.clone(),
            kernel_bundle_sha256: runtime.kernel.sha256.clone(),
            kernel_bundle_size: runtime.kernel.size,
            kernel_guest_load_address: format!("0x{:016x}", runtime.kernel.guest_load_address),
            kernel_entry_address: format!("0x{:016x}", runtime.kernel.entry_address),
            root_disk_read_only: true,
        };
        if !evidence.is_success() {
            return Err(image_error(
                "Linux immutable boot-asset evidence is incomplete".to_string(),
            ));
        }

        Ok(Self {
            manifest,
            image,
            runtime: runtime.clone(),
            evidence,
        })
    }

    /// Revalidate every pinned byte immediately before native API use.
    pub(crate) fn reverify(&self, runtime: &RuntimeBundle) -> Result<()> {
        if runtime != &self.runtime {
            return Err(image_error(
                "loaded Linux runtime provenance changed before native API use".to_string(),
            ));
        }
        self.manifest.reverify()?;
        self.image.reverify()
    }

    /// Stable procfs path backed by the retained read-only image descriptor.
    pub(crate) fn pinned_image_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.image.file.as_raw_fd()))
    }

    pub(crate) fn manifest_path(&self) -> &Path {
        &self.manifest.path
    }

    pub(crate) fn image_path(&self) -> &Path {
        &self.image.path
    }

    pub(crate) fn evidence(&self) -> LinuxBootAssetsEvidence {
        self.evidence.clone()
    }
}

fn image_error(message: String) -> Error {
    Error::new(ErrorCode::Unavailable, message).for_operation("verify-linux-kvm-system-image")
}

#[cfg(test)]
mod tests;
