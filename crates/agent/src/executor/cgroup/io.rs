use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use a3s_oci_sdk::oci_spec::runtime::{LinuxBlockIo, LinuxThrottleDevice};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::cgroup_error;

mod state;
mod update;

const CREATE_OPERATION: &str = "configure-container-cgroup";
const UPDATE_OPERATION: &str = "update-container-cgroup";
const BFQ_WEIGHT_FILE: &str = "io.bfq.weight";
const GENERIC_WEIGHT_FILE: &str = "io.weight";
const MAX_FILE: &str = "io.max";
const OCI_WEIGHT_MIN: u16 = 10;
const OCI_WEIGHT_MAX: u16 = 1_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct BlockIoPlan {
    default_weight: Option<u16>,
    device_weights: BTreeMap<BlockDevice, u16>,
    max: BTreeMap<BlockDevice, IoMaxValues>,
}

impl BlockIoPlan {
    pub(super) fn from_oci(block_io: Option<&LinuxBlockIo>) -> Result<Self> {
        let Some(block_io) = block_io else {
            return Ok(Self::default());
        };
        if block_io.leaf_weight().is_some() {
            return Err(unsupported(
                "linux.resources.blockIO.leafWeight",
                "cgroup v2 has no leaf-weight control",
            ));
        }

        let default_weight = block_io
            .weight()
            .map(|weight| validate_weight("linux.resources.blockIO.weight", weight))
            .transpose()?;
        let mut device_weights = BTreeMap::new();
        if let Some(devices) = block_io.weight_device().as_deref() {
            for (index, device) in devices.iter().enumerate() {
                let field = format!("linux.resources.blockIO.weightDevice[{index}]");
                let key = BlockDevice::from_oci(&field, device.major(), device.minor())?;
                if device.leaf_weight().is_some() {
                    return Err(unsupported(
                        &format!("{field}.leafWeight"),
                        "cgroup v2 has no leaf-weight control",
                    ));
                }
                let weight = device.weight().ok_or_else(|| {
                    invalid(format!(
                        "{field} must specify weight when leafWeight is unavailable on cgroup v2"
                    ))
                })?;
                let weight = validate_weight(&format!("{field}.weight"), weight)?;
                if device_weights.insert(key, weight).is_some() {
                    return Err(invalid(format!(
                        "linux.resources.blockIO.weightDevice contains duplicate device {key}"
                    )));
                }
            }
        }

        let mut max = BTreeMap::new();
        collect_throttles(
            block_io.throttle_read_bps_device().as_deref(),
            "throttleReadBpsDevice",
            IoMaxField::ReadBytes,
            &mut max,
        )?;
        collect_throttles(
            block_io.throttle_write_bps_device().as_deref(),
            "throttleWriteBpsDevice",
            IoMaxField::WriteBytes,
            &mut max,
        )?;
        collect_throttles(
            block_io.throttle_read_iops_device().as_deref(),
            "throttleReadIOPSDevice",
            IoMaxField::ReadOperations,
            &mut max,
        )?;
        collect_throttles(
            block_io.throttle_write_iops_device().as_deref(),
            "throttleWriteIOPSDevice",
            IoMaxField::WriteOperations,
            &mut max,
        )?;

        Ok(Self {
            default_weight,
            device_weights,
            max,
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.default_weight.is_none() && self.device_weights.is_empty() && self.max.is_empty()
    }

    fn mutations(&self, backend: Option<WeightBackend>) -> Vec<IoMutation> {
        let mut mutations = Vec::new();
        if let Some(backend) = backend {
            if let Some(weight) = self.default_weight {
                mutations.push(IoMutation::Weight {
                    backend,
                    key: WeightKey::Default,
                    value: backend.encode(weight),
                });
            }
            mutations.extend(self.device_weights.iter().map(|(device, weight)| {
                IoMutation::Weight {
                    backend,
                    key: WeightKey::Device(*device),
                    value: backend.encode(*weight),
                }
            }));
        }
        mutations.extend(self.max.iter().map(|(device, values)| IoMutation::Max {
            device: *device,
            values: values.clone(),
        }));
        mutations
    }
}

#[derive(Debug, Default)]
pub(super) struct PreparedBlockIoUpdate {
    path: PathBuf,
    prepared: Vec<PreparedIoMutation>,
}

#[derive(Debug, Default)]
pub(super) struct AppliedBlockIoUpdate {
    path: PathBuf,
    applied: Vec<PreparedIoMutation>,
}

#[derive(Debug, Clone)]
struct PreparedIoMutation {
    mutation: IoMutation,
    previous: PreviousValue,
}

impl PreparedIoMutation {
    fn is_noop(&self) -> bool {
        match (&self.mutation, &self.previous) {
            (IoMutation::Weight { value, .. }, PreviousValue::Weight(previous)) => {
                *previous == Some(*value)
            }
            (IoMutation::Max { values, .. }, PreviousValue::Max(previous)) => values
                .iter()
                .all(|(field, value)| previous.get(field) == Some(value)),
            _ => false,
        }
    }

    fn rollback_mutation(&self) -> Result<IoMutation> {
        match (&self.mutation, &self.previous) {
            (IoMutation::Weight { backend, key, .. }, PreviousValue::Weight(previous)) => {
                Ok(IoMutation::WeightRollback {
                    backend: *backend,
                    key: *key,
                    value: *previous,
                })
            }
            (IoMutation::Max { device, .. }, PreviousValue::Max(previous)) => {
                Ok(IoMutation::MaxRollback {
                    device: *device,
                    values: previous.clone(),
                })
            }
            _ => Err(update_error(
                ErrorCode::Internal,
                "block I/O update retained incompatible rollback state",
            )),
        }
    }
}

#[derive(Debug, Clone)]
enum PreviousValue {
    Weight(Option<u64>),
    Max(BTreeMap<IoMaxField, IoLimit>),
}

#[derive(Debug, Clone)]
enum IoMutation {
    Weight {
        backend: WeightBackend,
        key: WeightKey,
        value: u64,
    },
    Max {
        device: BlockDevice,
        values: IoMaxValues,
    },
    WeightRollback {
        backend: WeightBackend,
        key: WeightKey,
        value: Option<u64>,
    },
    MaxRollback {
        device: BlockDevice,
        values: BTreeMap<IoMaxField, IoLimit>,
    },
}

impl IoMutation {
    fn file(&self) -> &'static str {
        match self {
            Self::Weight { backend, .. } | Self::WeightRollback { backend, .. } => backend.file(),
            Self::Max { .. } | Self::MaxRollback { .. } => MAX_FILE,
        }
    }

    fn write_value(&self) -> Result<String> {
        match self {
            Self::Weight { key, value, .. } => Ok(key.write_value(&value.to_string())),
            Self::Max { device, values } => Ok(format!("{device} {}", values.write_value())),
            Self::WeightRollback { key, value, .. } => match (key, value) {
                (WeightKey::Default, Some(value)) => Ok(value.to_string()),
                (WeightKey::Default, None) => Err(update_error(
                    ErrorCode::Internal,
                    "block I/O default weight has no rollback value",
                )),
                (WeightKey::Device(device), Some(value)) => Ok(format!("{device} {value}")),
                (WeightKey::Device(device), None) => Ok(format!("{device} default")),
            },
            Self::MaxRollback { device, values } => Ok(format!(
                "{device} {}",
                values
                    .iter()
                    .map(|(field, value)| format!("{}={value}", field.name()))
                    .collect::<Vec<_>>()
                    .join(" ")
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeightBackend {
    Bfq,
    Generic,
}

impl WeightBackend {
    fn file(self) -> &'static str {
        match self {
            Self::Bfq => BFQ_WEIGHT_FILE,
            Self::Generic => GENERIC_WEIGHT_FILE,
        }
    }

    fn encode(self, weight: u16) -> u64 {
        match self {
            Self::Bfq => u64::from(weight),
            Self::Generic => 1 + (u64::from(weight - OCI_WEIGHT_MIN) * 9_999) / 990,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WeightKey {
    Default,
    Device(BlockDevice),
}

impl WeightKey {
    fn write_value(self, value: &str) -> String {
        match self {
            Self::Default => value.to_string(),
            Self::Device(device) => format!("{device} {value}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BlockDevice {
    major: u32,
    minor: u32,
}

impl BlockDevice {
    fn from_oci(field: &str, major: i64, minor: i64) -> Result<Self> {
        let major = u32::try_from(major)
            .map_err(|_| invalid(format!("{field}.major must be a non-negative u32")))?;
        let minor = u32::try_from(minor)
            .map_err(|_| invalid(format!("{field}.minor must be a non-negative u32")))?;
        Ok(Self { major, minor })
    }

    fn parse(value: &str) -> std::result::Result<Self, String> {
        let (major, minor) = value
            .split_once(':')
            .ok_or_else(|| format!("invalid block-device key {value:?}"))?;
        let major = major
            .parse::<u32>()
            .map_err(|error| format!("invalid block-device major in {value:?}: {error}"))?;
        let minor = minor
            .parse::<u32>()
            .map_err(|error| format!("invalid block-device minor in {value:?}: {error}"))?;
        Ok(Self { major, minor })
    }
}

impl fmt::Display for BlockDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.major, self.minor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IoMaxField {
    ReadBytes,
    WriteBytes,
    ReadOperations,
    WriteOperations,
}

impl IoMaxField {
    const ALL: [Self; 4] = [
        Self::ReadBytes,
        Self::WriteBytes,
        Self::ReadOperations,
        Self::WriteOperations,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::ReadBytes => "rbps",
            Self::WriteBytes => "wbps",
            Self::ReadOperations => "riops",
            Self::WriteOperations => "wiops",
        }
    }

    fn from_name(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.name() == value)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IoMaxValues(BTreeMap<IoMaxField, IoLimit>);

impl IoMaxValues {
    fn insert(&mut self, field: IoMaxField, value: IoLimit) -> Option<IoLimit> {
        self.0.insert(field, value)
    }

    fn iter(&self) -> impl Iterator<Item = (&IoMaxField, &IoLimit)> {
        self.0.iter()
    }

    fn write_value(&self) -> String {
        self.0
            .iter()
            .map(|(field, value)| format!("{}={value}", field.name()))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoLimit {
    Max,
    Value(u64),
}

impl fmt::Display for IoLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Max => formatter.write_str("max"),
            Self::Value(value) => value.fmt(formatter),
        }
    }
}

fn collect_throttles(
    devices: Option<&[LinuxThrottleDevice]>,
    field: &str,
    max_field: IoMaxField,
    max: &mut BTreeMap<BlockDevice, IoMaxValues>,
) -> Result<()> {
    let Some(devices) = devices else {
        return Ok(());
    };
    for (index, device) in devices.iter().enumerate() {
        let entry = format!("linux.resources.blockIO.{field}[{index}]");
        let key = BlockDevice::from_oci(&entry, device.major(), device.minor())?;
        // OCI retains the cgroup v1 numeric interface, where zero removes a
        // throttle. Cgroup v2 rejects numeric zero and uses `max` instead.
        let value = match device.rate() {
            0 => IoLimit::Max,
            value => IoLimit::Value(value),
        };
        if max
            .entry(key)
            .or_default()
            .insert(max_field, value)
            .is_some()
        {
            return Err(invalid(format!(
                "linux.resources.blockIO.{field} contains duplicate device {key}"
            )));
        }
    }
    Ok(())
}

fn validate_weight(field: &str, weight: u16) -> Result<u16> {
    if (OCI_WEIGHT_MIN..=OCI_WEIGHT_MAX).contains(&weight) {
        Ok(weight)
    } else {
        Err(invalid(format!(
            "{field} must be between {OCI_WEIGHT_MIN} and {OCI_WEIGHT_MAX}"
        )))
    }
}

fn invalid(message: impl Into<String>) -> Error {
    cgroup_error(ErrorCode::InvalidArgument, message)
}

fn unsupported(field: &str, reason: &str) -> Error {
    cgroup_error(ErrorCode::Unsupported, format!("{field}: {reason}"))
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
