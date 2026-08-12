use std::fs::File;
use std::io::Read;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use sha2::{Digest, Sha256};

pub(crate) const MACOS_RUNTIME_ARCHIVE_SHA256: &str =
    "5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56";
pub(crate) const LIBKRUN_NAME: &str = "libkrun.1.17.0.dylib";
pub(crate) const LIBKRUN_SHA256: &str =
    "c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d";
pub(crate) const LIBKRUNFW_NAME: &str = "libkrunfw.5.dylib";
pub(crate) const LIBKRUNFW_SHA256: &str =
    "841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4";
pub(crate) const KERNEL_BUNDLE_SIZE: usize = 22_740_992;
pub(crate) const KERNEL_BUNDLE_SHA256: &str =
    "b1180b50148ed14f5fbeadf17288ce8abcf245daa468255b7ff41113bbf01199";
pub(crate) const KERNEL_GUEST_LOAD_ADDRESS: u64 = 0x0000_0000_8000_0000;
pub(crate) const KERNEL_ENTRY_ADDRESS: u64 = 0x0000_0000_8000_0000;

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

pub(crate) fn sha256_file(path: &Path, operation: &'static str) -> Result<(String, u64)> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        asset_error(
            operation,
            format!("failed to inspect asset {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(asset_error(
            operation,
            format!(
                "asset must be a real regular file, not a symlink: {}",
                path.display()
            ),
        ));
    }

    let mut file = File::open(path).map_err(|error| {
        asset_error(
            operation,
            format!("failed to open asset {}: {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            asset_error(
                operation,
                format!("failed to read asset {}: {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        size = size.checked_add(read as u64).ok_or_else(|| {
            asset_error(operation, format!("asset is too large: {}", path.display()))
        })?;
        hasher.update(&buffer[..read]);
    }
    if size != metadata.len() {
        return Err(asset_error(
            operation,
            format!("asset size changed while it was hashed: {}", path.display()),
        ));
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

pub(crate) fn asset_error(operation: &'static str, message: String) -> Error {
    Error::new(ErrorCode::Unavailable, message).for_operation(operation)
}
