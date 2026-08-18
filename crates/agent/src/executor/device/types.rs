use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::access::DeviceAccessPolicy;

pub(in crate::executor) const ROOTLESS_DEVICE_MOUNT_COUNT: usize =
    crate::OCI_LINUX_DEFAULT_DEVICE_NODES.len();

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::executor) struct DevicePlan {
    pub(super) nodes: Vec<DeviceNode>,
    pub(super) access_policy: Option<DeviceAccessPolicy>,
    pub(super) terminal: bool,
    #[serde(default)]
    pub(super) create_nodes: bool,
}

#[derive(Debug)]
pub(in crate::executor) struct PreparedDeviceSources {
    pub(super) sources: Option<Vec<PreparedDeviceSource>>,
    pub(super) console: Option<PreparedConsoleSource>,
    pub(super) verify_ownership: bool,
    pub(super) target_host_owner: Option<(u32, u32)>,
    pub(super) manifest: Mutex<Option<DeviceTargetManifest>>,
    pub(super) manifest_file: Mutex<Option<File>>,
    pub(super) manifest_path: Option<PathBuf>,
}

#[derive(Debug)]
pub(super) enum PreparedDeviceSource {
    DetachedMount(OwnedFd),
}

#[derive(Debug)]
pub(super) struct PreparedConsoleSource {
    pub(super) mount: OwnedFd,
    pub(super) metadata: TargetMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceTargetRecord {
    pub(super) relative_path: PathBuf,
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::executor) struct DeviceTargetManifest {
    pub(super) schema_version: String,
    pub(super) rootfs: DeviceRootfsRecord,
    pub(super) targets: Vec<DeviceTargetRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceRootfsRecord {
    pub(super) canonical_path: PathBuf,
    pub(super) dev: u64,
    pub(super) ino: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TargetMetadata {
    pub(super) file_type: u32,
    pub(super) dev: u64,
    pub(super) rdev: u64,
    pub(super) ino: u64,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeviceNode {
    pub(super) path: PathBuf,
    pub(super) kind: DeviceKind,
    pub(super) major: u32,
    pub(super) minor: u32,
    pub(super) mode: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum DeviceKind {
    Block,
    Character,
    Fifo,
}
