use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{operation_error, BlockDevice, IoLimit, IoMaxField, WeightBackend, MAX_FILE};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WeightState {
    pub(super) default: Option<u64>,
    pub(super) devices: BTreeMap<BlockDevice, u64>,
    pub(super) device_overrides_supported: bool,
}

pub(super) fn parse_weight_state(value: &str) -> std::result::Result<WeightState, String> {
    let mut state = WeightState::default();
    let lines = value
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.len() == 1 {
        let fields = lines[0].split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() == 1 {
            state.default = Some(parse_weight(fields[0])?);
            return Ok(state);
        }
    }
    state.device_overrides_supported = true;
    for line in lines {
        let mut fields = line.split_ascii_whitespace();
        let key = fields
            .next()
            .ok_or_else(|| "empty weight entry".to_string())?;
        let value = fields
            .next()
            .ok_or_else(|| format!("weight entry {line:?} has no value"))?;
        if fields.next().is_some() {
            return Err(format!("weight entry {line:?} has unexpected fields"));
        }
        let value = parse_weight(value)?;
        if key == "default" {
            if state.default.replace(value).is_some() {
                return Err("duplicate default weight entry".to_string());
            }
        } else {
            let device = BlockDevice::parse(key)?;
            if state.devices.insert(device, value).is_some() {
                return Err(format!("duplicate weight entry for device {device}"));
            }
        }
    }
    if state.default.is_none() {
        return Err("weight state has no default entry".to_string());
    }
    Ok(state)
}

fn parse_weight(value: &str) -> std::result::Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid weight {value:?}: {error}"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct IoMaxState(BTreeMap<BlockDevice, BTreeMap<IoMaxField, IoLimit>>);

impl IoMaxState {
    pub(super) fn value(&self, device: BlockDevice, field: IoMaxField) -> IoLimit {
        self.0
            .get(&device)
            .and_then(|values| values.get(&field))
            .copied()
            .unwrap_or(IoLimit::Max)
    }
}

pub(super) fn parse_max_state(value: &str) -> std::result::Result<IoMaxState, String> {
    let mut state = BTreeMap::<BlockDevice, BTreeMap<IoMaxField, IoLimit>>::new();
    for line in value.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let device_text = fields
            .next()
            .ok_or_else(|| "empty io.max entry".to_string())?;
        let device = BlockDevice::parse(device_text)?;
        let values = state.entry(device).or_default();
        for item in fields {
            let (name, value) = item
                .split_once('=')
                .ok_or_else(|| format!("io.max entry {item:?} has no value"))?;
            let Some(field) = IoMaxField::from_name(name) else {
                continue;
            };
            let value = if value == "max" {
                IoLimit::Max
            } else {
                IoLimit::Value(value.parse::<u64>().map_err(|error| {
                    format!("invalid io.max value {value:?} for {device} {name}: {error}")
                })?)
            };
            if values.insert(field, value).is_some() {
                return Err(format!("duplicate io.max field {name} for device {device}"));
            }
        }
    }
    Ok(IoMaxState(state))
}

pub(super) fn read_optional(
    path: &Path,
    file: &str,
    operation: &'static str,
) -> Result<Option<String>> {
    match std::fs::read_to_string(path.join(file)) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!(
                "failed to read cgroup file {}: {error}",
                path.join(file).display()
            ),
        )),
    }
}

pub(super) async fn read_optional_async(
    path: &Path,
    file: &str,
    operation: &'static str,
) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path.join(file)).await {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!(
                "failed to read cgroup file {}: {error}",
                path.join(file).display()
            ),
        )),
    }
}

pub(super) fn read_weight_state(
    path: &Path,
    backend: WeightBackend,
    operation: &'static str,
) -> Result<WeightState> {
    let source = path.join(backend.file());
    let value = std::fs::read_to_string(&source).map_err(|error| {
        operation_error(
            operation,
            if error.kind() == io::ErrorKind::NotFound {
                ErrorCode::Unsupported
            } else {
                ErrorCode::FailedPrecondition
            },
            format!(
                "failed to read cgroup block I/O weight {}: {error}",
                source.display()
            ),
        )
    })?;
    parse_weight_state(&value).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", source.display()),
        )
    })
}

pub(super) async fn read_weight_state_async(
    path: &Path,
    backend: WeightBackend,
    operation: &'static str,
) -> Result<WeightState> {
    let source = path.join(backend.file());
    let value = tokio::fs::read_to_string(&source).await.map_err(|error| {
        operation_error(
            operation,
            if error.kind() == io::ErrorKind::NotFound {
                ErrorCode::Unsupported
            } else {
                ErrorCode::FailedPrecondition
            },
            format!(
                "failed to read cgroup block I/O weight {}: {error}",
                source.display()
            ),
        )
    })?;
    parse_weight_state(&value).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", source.display()),
        )
    })
}

pub(super) fn read_max_state(path: &Path, operation: &'static str) -> Result<IoMaxState> {
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
                "failed to read cgroup block I/O limits {}: {error}",
                source.display()
            ),
        )
    })?;
    parse_max_state(&value).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", source.display()),
        )
    })
}

pub(super) async fn read_max_state_async(
    path: &Path,
    operation: &'static str,
) -> Result<IoMaxState> {
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
                "failed to read cgroup block I/O limits {}: {error}",
                source.display()
            ),
        )
    })?;
    parse_max_state(&value).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", source.display()),
        )
    })
}
