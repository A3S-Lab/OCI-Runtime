use std::io;

use a3s_oci_sdk::{Error, ErrorCode};

mod access;
mod console;
mod manifest;
mod mount_source;
mod node;
mod plan;
mod types;

pub(super) use access::LoadedDeviceProgram;
pub(super) use manifest::{cleanup_device_target_manifest, load_device_target_manifest};
pub(super) use types::{DevicePlan, PreparedDeviceSources, ROOTLESS_DEVICE_MOUNT_COUNT};

#[cfg(test)]
use console::verify_ptmx_from_root;
#[cfg(test)]
use manifest::{
    load_device_target_manifest_from, write_device_target_manifest, DEVICE_TARGETS_RECORD_NAME,
    DEVICE_TARGETS_SCHEMA_VERSION,
};
#[cfg(test)]
use mount_source::canonical_device_source_directory;
#[cfg(test)]
use types::{
    DeviceKind, DeviceNode, DeviceRootfsRecord, DeviceTargetManifest, DeviceTargetRecord,
    PreparedDeviceSource, TargetMetadata,
};

fn invalid(message: impl Into<String>) -> Error {
    device_error(ErrorCode::InvalidArgument, message)
}

fn unsupported(field: &str, reason: &str) -> Error {
    device_error(ErrorCode::Unsupported, format!("{field}: {reason}"))
}

fn last_os_error(operation: impl Into<String>) -> Error {
    device_error(
        ErrorCode::PermissionDenied,
        format!(
            "failed to {}: {}",
            operation.into(),
            io::Error::last_os_error()
        ),
    )
}

fn device_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("configure-container-devices")
}

#[cfg(test)]
mod tests;
