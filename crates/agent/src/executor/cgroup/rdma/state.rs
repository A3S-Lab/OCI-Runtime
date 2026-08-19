use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{operation_error, RdmaDevice, RdmaLimit, RdmaLimits, MAX_FILE};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RdmaState(BTreeMap<RdmaDevice, RdmaLimits>);

impl RdmaState {
    pub(super) fn get(&self, device: &RdmaDevice) -> Option<RdmaLimits> {
        self.0.get(device).copied()
    }
}

pub(super) fn parse_state(value: &str) -> std::result::Result<RdmaState, String> {
    let mut state = BTreeMap::new();
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let device_text = fields
            .next()
            .ok_or_else(|| "empty RDMA state entry".to_string())?;
        let device = RdmaDevice::parse(device_text)
            .map_err(|reason| format!("invalid RDMA state device {device_text:?}: {reason}"))?;
        let mut limits = RdmaLimits::default();
        for item in fields {
            let (name, value) = item
                .split_once('=')
                .ok_or_else(|| format!("RDMA state entry {item:?} has no value"))?;
            if name.is_empty() || value.is_empty() {
                return Err(format!("RDMA state entry {item:?} is empty"));
            }
            let destination = match name {
                "hca_handle" => &mut limits.hca_handles,
                "hca_object" => &mut limits.hca_objects,
                _ => continue,
            };
            if destination.replace(RdmaLimit::parse(value)?).is_some() {
                return Err(format!(
                    "duplicate RDMA state field {name} for device {device}"
                ));
            }
        }
        if limits.hca_handles.is_none() || limits.hca_objects.is_none() {
            return Err(format!(
                "RDMA state for device {device} does not expose both OCI resource fields"
            ));
        }
        if state.insert(device.clone(), limits).is_some() {
            return Err(format!("duplicate RDMA state device {device}"));
        }
    }
    Ok(RdmaState(state))
}

pub(super) fn read_state(path: &Path, operation: &'static str) -> Result<RdmaState> {
    let source = path.join(MAX_FILE);
    let value = std::fs::read_to_string(&source).map_err(|error| {
        operation_error(
            operation,
            if error.kind() == io::ErrorKind::NotFound {
                ErrorCode::Unsupported
            } else {
                ErrorCode::FailedPrecondition
            },
            format!(
                "failed to read cgroup RDMA limits {}: {error}",
                source.display()
            ),
        )
    })?;
    parse_state(&value).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", source.display()),
        )
    })
}

pub(super) async fn read_state_async(path: &Path, operation: &'static str) -> Result<RdmaState> {
    let source = path.join(MAX_FILE);
    let value = tokio::fs::read_to_string(&source).await.map_err(|error| {
        operation_error(
            operation,
            if error.kind() == io::ErrorKind::NotFound {
                ErrorCode::Unsupported
            } else {
                ErrorCode::FailedPrecondition
            },
            format!(
                "failed to read cgroup RDMA limits {}: {error}",
                source.display()
            ),
        )
    })?;
    parse_state(&value).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", source.display()),
        )
    })
}
