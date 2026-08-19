use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::PathBuf;

use a3s_oci_sdk::oci_spec::runtime::LinuxRdma;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::cgroup_error;

mod state;
mod update;

const CREATE_OPERATION: &str = "configure-container-cgroup";
const UPDATE_OPERATION: &str = "update-container-cgroup";
const MAX_FILE: &str = "rdma.max";
const RDMA_DEVICE_NAME_MAX_BYTES: usize = 63;
const KERNEL_FINITE_LIMIT_MAX: u32 = i32::MAX as u32 - 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RdmaPlan {
    limits: BTreeMap<RdmaDevice, RdmaLimits>,
}

impl RdmaPlan {
    pub(super) fn from_oci(rdma: Option<&HashMap<String, LinuxRdma>>) -> Result<Self> {
        let Some(rdma) = rdma else {
            return Ok(Self::default());
        };
        let mut limits = BTreeMap::new();
        for (device, value) in rdma {
            let device = RdmaDevice::from_oci(device)?;
            let limits_for_device = RdmaLimits::from_oci(&device, value)?;
            limits.insert(device, limits_for_device);
        }
        Ok(Self { limits })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.limits.is_empty()
    }

    fn mutations(&self) -> Vec<RdmaMutation> {
        self.limits
            .iter()
            .map(|(device, limits)| RdmaMutation {
                device: device.clone(),
                limits: *limits,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RdmaDevice(String);

impl RdmaDevice {
    fn from_oci(value: &str) -> Result<Self> {
        Self::parse(value).map_err(|reason| {
            invalid(format!(
                "linux.resources.rdma device {value:?} is invalid: {reason}"
            ))
        })
    }

    fn parse(value: &str) -> std::result::Result<Self, String> {
        if value.is_empty() {
            return Err("the device name is empty".to_string());
        }
        if value.len() > RDMA_DEVICE_NAME_MAX_BYTES {
            return Err(format!(
                "the device name exceeds {RDMA_DEVICE_NAME_MAX_BYTES} bytes"
            ));
        }
        if value == "."
            || value == ".."
            || value.contains('/')
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(
                "the device name must be one bounded cgroup token without whitespace, controls, or `/`"
                    .to_string(),
            );
        }
        Ok(Self(value.to_string()))
    }
}

impl fmt::Display for RdmaDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RdmaLimit {
    Max,
    Value(u32),
}

impl RdmaLimit {
    fn from_oci(value: u32) -> Self {
        if value > KERNEL_FINITE_LIMIT_MAX {
            Self::Max
        } else {
            Self::Value(value)
        }
    }

    fn parse(value: &str) -> std::result::Result<Self, String> {
        if value == "max" {
            return Ok(Self::Max);
        }
        let value = value
            .parse::<u32>()
            .map_err(|error| format!("invalid RDMA limit {value:?}: {error}"))?;
        if value > KERNEL_FINITE_LIMIT_MAX {
            return Err(format!(
                "finite RDMA limit {value} exceeds the kernel signed-counter range"
            ));
        }
        Ok(Self::Value(value))
    }
}

impl fmt::Display for RdmaLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Max => formatter.write_str("max"),
            Self::Value(value) => value.fmt(formatter),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RdmaLimits {
    hca_handles: Option<RdmaLimit>,
    hca_objects: Option<RdmaLimit>,
}

impl RdmaLimits {
    fn from_oci(device: &RdmaDevice, value: &LinuxRdma) -> Result<Self> {
        let limits = Self {
            hca_handles: value.hca_handles().map(RdmaLimit::from_oci),
            hca_objects: value.hca_objects().map(RdmaLimit::from_oci),
        };
        if limits.is_empty() {
            return Err(invalid(format!(
                "linux.resources.rdma.{device} must specify hcaHandles, hcaObjects, or both"
            )));
        }
        Ok(limits)
    }

    fn is_empty(self) -> bool {
        self.hca_handles.is_none() && self.hca_objects.is_none()
    }

    fn write_value(self) -> String {
        let mut fields = Vec::with_capacity(2);
        if let Some(value) = self.hca_handles {
            fields.push(format!("hca_handle={value}"));
        }
        if let Some(value) = self.hca_objects {
            fields.push(format!("hca_object={value}"));
        }
        fields.join(" ")
    }

    fn matches_requested(self, actual: Self) -> bool {
        self.hca_handles
            .is_none_or(|expected| actual.hca_handles == Some(expected))
            && self
                .hca_objects
                .is_none_or(|expected| actual.hca_objects == Some(expected))
    }

    fn previous_for(self, current: Self) -> std::result::Result<Self, String> {
        let hca_handles = self
            .hca_handles
            .map(|_| {
                current
                    .hca_handles
                    .ok_or_else(|| "RDMA state has no hca_handle value".to_string())
            })
            .transpose()?;
        let hca_objects = self
            .hca_objects
            .map(|_| {
                current
                    .hca_objects
                    .ok_or_else(|| "RDMA state has no hca_object value".to_string())
            })
            .transpose()?;
        Ok(Self {
            hca_handles,
            hca_objects,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RdmaMutation {
    device: RdmaDevice,
    limits: RdmaLimits,
}

impl RdmaMutation {
    fn write_value(&self) -> String {
        format!("{} {}", self.device, self.limits.write_value())
    }
}

#[derive(Debug, Clone)]
struct PreparedRdmaMutation {
    mutation: RdmaMutation,
    previous: RdmaLimits,
}

impl PreparedRdmaMutation {
    fn is_noop(&self) -> bool {
        self.mutation.limits.matches_requested(self.previous)
    }

    fn rollback_mutation(&self) -> RdmaMutation {
        RdmaMutation {
            device: self.mutation.device.clone(),
            limits: self.previous,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct PreparedRdmaUpdate {
    path: PathBuf,
    prepared: Vec<PreparedRdmaMutation>,
}

#[derive(Debug, Default)]
pub(super) struct AppliedRdmaUpdate {
    path: PathBuf,
    applied: Vec<PreparedRdmaMutation>,
}

fn invalid(message: impl Into<String>) -> Error {
    cgroup_error(ErrorCode::InvalidArgument, message)
}

fn update_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation(UPDATE_OPERATION)
}

fn operation_error(operation: &'static str, code: ErrorCode, message: impl Into<String>) -> Error {
    if operation == CREATE_OPERATION {
        cgroup_error(code, message)
    } else {
        Error::new(code, message).for_operation(operation)
    }
}

#[cfg(test)]
mod tests;
