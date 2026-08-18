use std::io;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::state::{
    parse_weight_state, read_max_state, read_max_state_async, read_optional, read_optional_async,
    read_weight_state, read_weight_state_async, IoMaxState, WeightState,
};
use super::*;

impl BlockIoPlan {
    pub(in crate::executor::cgroup) fn apply_create(&self, path: &Path) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let weight_backend = self.select_weight_backend(path, CREATE_OPERATION)?;
        if !self.max.is_empty() {
            read_max_state(path, CREATE_OPERATION)?;
        }
        for mutation in self.mutations(weight_backend) {
            write_mutation(path, &mutation, CREATE_OPERATION)?;
            verify_mutation(path, &mutation, CREATE_OPERATION)?;
        }
        Ok(())
    }

    pub(in crate::executor::cgroup) async fn prepare_update(
        &self,
        path: &Path,
    ) -> Result<PreparedBlockIoUpdate> {
        if self.is_empty() {
            return Ok(PreparedBlockIoUpdate {
                path: path.to_path_buf(),
                prepared: Vec::new(),
            });
        }
        let weight_backend = self
            .select_weight_backend_async(path, UPDATE_OPERATION)
            .await?;
        let weight_state = match weight_backend {
            Some(backend) => Some(read_weight_state_async(path, backend, UPDATE_OPERATION).await?),
            None => None,
        };
        let max_state = if self.max.is_empty() {
            None
        } else {
            Some(read_max_state_async(path, UPDATE_OPERATION).await?)
        };
        let mut prepared = Vec::new();
        for mutation in self.mutations(weight_backend) {
            let previous = match &mutation {
                IoMutation::Weight { key, .. } => {
                    let state = weight_state.as_ref().ok_or_else(|| {
                        update_error(
                            ErrorCode::Internal,
                            "block I/O weight mutation has no prepared weight state",
                        )
                    })?;
                    PreviousValue::Weight(match key {
                        WeightKey::Default => state.default,
                        WeightKey::Device(device) => state.devices.get(device).copied(),
                    })
                }
                IoMutation::Max { device, values } => {
                    let state = max_state.as_ref().ok_or_else(|| {
                        update_error(
                            ErrorCode::Internal,
                            "block I/O throttle mutation has no prepared io.max state",
                        )
                    })?;
                    PreviousValue::Max(
                        values
                            .iter()
                            .map(|(field, _)| (*field, state.value(*device, *field)))
                            .collect(),
                    )
                }
                IoMutation::WeightRollback { .. } | IoMutation::MaxRollback { .. } => {
                    return Err(update_error(
                        ErrorCode::Internal,
                        "new block I/O plan unexpectedly contains rollback mutations",
                    ));
                }
            };
            prepared.push(PreparedIoMutation { mutation, previous });
        }
        Ok(PreparedBlockIoUpdate {
            path: path.to_path_buf(),
            prepared,
        })
    }

    fn select_weight_backend(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<WeightBackend>> {
        if self.default_weight.is_none() && self.device_weights.is_empty() {
            return Ok(None);
        }
        if let Some(contents) = read_optional(path, BFQ_WEIGHT_FILE, operation)? {
            let state = parse_weight_file(path, BFQ_WEIGHT_FILE, &contents, operation)?;
            if self.device_weights.is_empty() || state.device_overrides_supported {
                return Ok(Some(WeightBackend::Bfq));
            }
        }
        match read_optional(path, GENERIC_WEIGHT_FILE, operation)? {
            Some(contents) => {
                parse_weight_file(path, GENERIC_WEIGHT_FILE, &contents, operation)?;
                Ok(Some(WeightBackend::Generic))
            }
            None => Err(weight_unavailable(
                operation,
                !self.device_weights.is_empty(),
            )),
        }
    }

    async fn select_weight_backend_async(
        &self,
        path: &Path,
        operation: &'static str,
    ) -> Result<Option<WeightBackend>> {
        if self.default_weight.is_none() && self.device_weights.is_empty() {
            return Ok(None);
        }
        if let Some(contents) = read_optional_async(path, BFQ_WEIGHT_FILE, operation).await? {
            let state = parse_weight_file(path, BFQ_WEIGHT_FILE, &contents, operation)?;
            if self.device_weights.is_empty() || state.device_overrides_supported {
                return Ok(Some(WeightBackend::Bfq));
            }
        }
        match read_optional_async(path, GENERIC_WEIGHT_FILE, operation).await? {
            Some(contents) => {
                parse_weight_file(path, GENERIC_WEIGHT_FILE, &contents, operation)?;
                Ok(Some(WeightBackend::Generic))
            }
            None => Err(weight_unavailable(
                operation,
                !self.device_weights.is_empty(),
            )),
        }
    }
}

impl PreparedBlockIoUpdate {
    pub(in crate::executor::cgroup) async fn apply(self) -> Result<AppliedBlockIoUpdate> {
        let path = self.path;
        let mut applied = Vec::new();
        for prepared in self.prepared {
            if prepared.is_noop() {
                continue;
            }
            if let Err(error) =
                write_mutation_async(&path, &prepared.mutation, UPDATE_OPERATION).await
            {
                return Err(rollback_after_failure(&path, &applied, error).await);
            }
            applied.push(prepared);
            if let Err(error) = verify_mutation_async(
                &path,
                &applied.last().expect("applied mutation").mutation,
                UPDATE_OPERATION,
            )
            .await
            {
                return Err(rollback_after_failure(&path, &applied, error).await);
            }
        }
        Ok(AppliedBlockIoUpdate { path, applied })
    }
}

impl AppliedBlockIoUpdate {
    pub(in crate::executor::cgroup) async fn rollback(&self) -> Vec<String> {
        rollback_mutations(&self.path, &self.applied).await
    }
}

fn parse_weight_file(
    path: &Path,
    file: &'static str,
    contents: &str,
    operation: &'static str,
) -> Result<WeightState> {
    parse_weight_state(contents).map_err(|message| {
        operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("failed to parse {}: {message}", path.join(file).display()),
        )
    })
}

fn weight_unavailable(operation: &'static str, device_weights: bool) -> Error {
    operation_error(
        operation,
        ErrorCode::Unsupported,
        if device_weights {
            "cgroup v2 per-device block I/O weight control is unavailable"
        } else {
            "cgroup v2 block I/O weight control is unavailable"
        },
    )
}

fn write_mutation(path: &Path, mutation: &IoMutation, operation: &'static str) -> Result<()> {
    let destination = path.join(mutation.file());
    let value = mutation.write_value()?;
    std::fs::write(&destination, value.as_bytes()).map_err(|error| {
        operation_error(
            operation,
            if error.kind() == io::ErrorKind::NotFound {
                ErrorCode::Unsupported
            } else {
                ErrorCode::PermissionDenied
            },
            format!(
                "failed to apply cgroup block I/O setting {}={value}: {error}",
                destination.display()
            ),
        )
    })
}

async fn write_mutation_async(
    path: &Path,
    mutation: &IoMutation,
    operation: &'static str,
) -> Result<()> {
    let destination = path.join(mutation.file());
    let value = mutation.write_value()?;
    tokio::fs::write(&destination, value.as_bytes())
        .await
        .map_err(|error| {
            operation_error(
                operation,
                if error.kind() == io::ErrorKind::NotFound {
                    ErrorCode::Unsupported
                } else {
                    ErrorCode::PermissionDenied
                },
                format!(
                    "failed to apply cgroup block I/O setting {}={value}: {error}",
                    destination.display()
                ),
            )
        })
}

fn verify_mutation(path: &Path, mutation: &IoMutation, operation: &'static str) -> Result<()> {
    match mutation {
        IoMutation::Weight {
            backend,
            key,
            value,
        } => {
            let state = read_weight_state(path, *backend, operation)?;
            verify_weight(&state, *key, Some(*value), operation)
        }
        IoMutation::Max { device, values } => {
            let state = read_max_state(path, operation)?;
            verify_max_values(
                &state,
                *device,
                values
                    .iter()
                    .map(|(field, value)| (*field, IoLimit::Value(*value))),
                operation,
            )
        }
        IoMutation::WeightRollback {
            backend,
            key,
            value,
        } => {
            let state = read_weight_state(path, *backend, operation)?;
            verify_weight(&state, *key, *value, operation)
        }
        IoMutation::MaxRollback { device, values } => {
            let state = read_max_state(path, operation)?;
            verify_max_values(
                &state,
                *device,
                values.iter().map(|(field, value)| (*field, *value)),
                operation,
            )
        }
    }
}

async fn verify_mutation_async(
    path: &Path,
    mutation: &IoMutation,
    operation: &'static str,
) -> Result<()> {
    match mutation {
        IoMutation::Weight {
            backend,
            key,
            value,
        } => {
            let state = read_weight_state_async(path, *backend, operation).await?;
            verify_weight(&state, *key, Some(*value), operation)
        }
        IoMutation::Max { device, values } => {
            let state = read_max_state_async(path, operation).await?;
            verify_max_values(
                &state,
                *device,
                values
                    .iter()
                    .map(|(field, value)| (*field, IoLimit::Value(*value))),
                operation,
            )
        }
        IoMutation::WeightRollback {
            backend,
            key,
            value,
        } => {
            let state = read_weight_state_async(path, *backend, operation).await?;
            verify_weight(&state, *key, *value, operation)
        }
        IoMutation::MaxRollback { device, values } => {
            let state = read_max_state_async(path, operation).await?;
            verify_max_values(
                &state,
                *device,
                values.iter().map(|(field, value)| (*field, *value)),
                operation,
            )
        }
    }
}

fn verify_weight(
    state: &WeightState,
    key: WeightKey,
    expected: Option<u64>,
    operation: &'static str,
) -> Result<()> {
    let actual = match key {
        WeightKey::Default => state.default,
        WeightKey::Device(device) => state.devices.get(&device).copied(),
    };
    if actual == expected {
        Ok(())
    } else {
        Err(operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!("cgroup block I/O weight read back as {actual:?}, expected {expected:?}"),
        ))
    }
}

fn verify_max_values(
    state: &IoMaxState,
    device: BlockDevice,
    expected: impl IntoIterator<Item = (IoMaxField, IoLimit)>,
    operation: &'static str,
) -> Result<()> {
    for (field, expected) in expected {
        let actual = state.value(device, field);
        if actual != expected {
            return Err(operation_error(
                operation,
                ErrorCode::FailedPrecondition,
                format!(
                    "cgroup block I/O limit {device} {} read back as {actual}, expected {expected}",
                    field.name()
                ),
            ));
        }
    }
    Ok(())
}

async fn rollback_after_failure(
    path: &Path,
    applied: &[PreparedIoMutation],
    original: Error,
) -> Error {
    let failures = rollback_mutations(path, applied).await;
    if failures.is_empty() {
        original
    } else {
        update_error(
            ErrorCode::Internal,
            format!(
                "{}; block I/O rollback also failed: {}",
                original.message,
                failures.join("; ")
            ),
        )
    }
}

async fn rollback_mutations(path: &Path, applied: &[PreparedIoMutation]) -> Vec<String> {
    let mut failures = Vec::new();
    for prepared in applied.iter().rev() {
        let rollback = match prepared.rollback_mutation() {
            Ok(rollback) => rollback,
            Err(error) => {
                failures.push(error.message);
                continue;
            }
        };
        if let Err(error) = write_mutation_async(path, &rollback, UPDATE_OPERATION).await {
            failures.push(error.message);
            continue;
        }
        if let Err(error) = verify_mutation_async(path, &rollback, UPDATE_OPERATION).await {
            failures.push(error.message);
        }
    }
    failures
}
