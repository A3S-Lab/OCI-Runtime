use std::io;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::state::{read_state, read_state_async, RdmaState};
use super::*;

impl RdmaPlan {
    pub(in crate::executor::cgroup) fn preflight_create(&self, path: &Path) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let state = read_state(path, CREATE_OPERATION)?;
        ensure_devices(&state, self.limits.keys(), CREATE_OPERATION)
    }

    pub(in crate::executor::cgroup) fn apply_create(&self, path: &Path) -> Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        self.preflight_create(path)?;
        for mutation in self.mutations() {
            write_mutation(path, &mutation, CREATE_OPERATION)?;
            verify_mutation(path, &mutation, CREATE_OPERATION)?;
        }
        Ok(())
    }

    pub(in crate::executor::cgroup) async fn prepare_update(
        &self,
        path: &Path,
    ) -> Result<PreparedRdmaUpdate> {
        if self.is_empty() {
            return Ok(PreparedRdmaUpdate {
                path: path.to_path_buf(),
                prepared: Vec::new(),
            });
        }
        let state = read_state_async(path, UPDATE_OPERATION).await?;
        ensure_devices(&state, self.limits.keys(), UPDATE_OPERATION)?;
        let prepared = self.prepare_from_state(&state)?;
        Ok(PreparedRdmaUpdate {
            path: path.to_path_buf(),
            prepared,
        })
    }

    pub(super) fn prepare_from_state(
        &self,
        state: &RdmaState,
    ) -> Result<Vec<PreparedRdmaMutation>> {
        self.mutations()
            .into_iter()
            .map(|mutation| {
                let current = state.get(&mutation.device).ok_or_else(|| {
                    update_error(
                        ErrorCode::Unsupported,
                        format!("cgroup RDMA device {} is unavailable", mutation.device),
                    )
                })?;
                let previous = mutation
                    .limits
                    .previous_for(current)
                    .map_err(|message| update_error(ErrorCode::FailedPrecondition, message))?;
                Ok(PreparedRdmaMutation { mutation, previous })
            })
            .collect()
    }
}

impl PreparedRdmaUpdate {
    pub(in crate::executor::cgroup) async fn apply(self) -> Result<AppliedRdmaUpdate> {
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
            if let Err(error) =
                verify_mutation_async(&path, &prepared.mutation, UPDATE_OPERATION).await
            {
                applied.push(prepared);
                return Err(rollback_after_failure(&path, &applied, error).await);
            }
            applied.push(prepared);
        }
        Ok(AppliedRdmaUpdate { path, applied })
    }
}

impl AppliedRdmaUpdate {
    pub(in crate::executor::cgroup) async fn rollback(&self) -> Vec<String> {
        rollback_mutations(&self.path, &self.applied).await
    }
}

fn ensure_devices<'a>(
    state: &RdmaState,
    devices: impl IntoIterator<Item = &'a RdmaDevice>,
    operation: &'static str,
) -> Result<()> {
    for device in devices {
        if state.get(device).is_none() {
            return Err(operation_error(
                operation,
                ErrorCode::Unsupported,
                format!("cgroup RDMA device {device} is unavailable"),
            ));
        }
    }
    Ok(())
}

fn write_mutation(path: &Path, mutation: &RdmaMutation, operation: &'static str) -> Result<()> {
    let destination = path.join(MAX_FILE);
    let value = mutation.write_value();
    std::fs::write(&destination, value.as_bytes()).map_err(|error| {
        operation_error(
            operation,
            write_error_code(&error),
            format!(
                "failed to apply cgroup RDMA setting {}={value}: {error}",
                destination.display()
            ),
        )
    })
}

async fn write_mutation_async(
    path: &Path,
    mutation: &RdmaMutation,
    operation: &'static str,
) -> Result<()> {
    let destination = path.join(MAX_FILE);
    let value = mutation.write_value();
    tokio::fs::write(&destination, value.as_bytes())
        .await
        .map_err(|error| {
            operation_error(
                operation,
                write_error_code(&error),
                format!(
                    "failed to apply cgroup RDMA setting {}={value}: {error}",
                    destination.display()
                ),
            )
        })
}

fn write_error_code(error: &io::Error) -> ErrorCode {
    if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENODEV) {
        ErrorCode::Unsupported
    } else {
        ErrorCode::PermissionDenied
    }
}

fn verify_mutation(path: &Path, mutation: &RdmaMutation, operation: &'static str) -> Result<()> {
    let state = read_state(path, operation)?;
    verify_state(&state, mutation, operation)
}

async fn verify_mutation_async(
    path: &Path,
    mutation: &RdmaMutation,
    operation: &'static str,
) -> Result<()> {
    let state = read_state_async(path, operation).await?;
    verify_state(&state, mutation, operation)
}

fn verify_state(state: &RdmaState, mutation: &RdmaMutation, operation: &'static str) -> Result<()> {
    let Some(actual) = state.get(&mutation.device) else {
        return Err(operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!(
                "cgroup RDMA device {} disappeared during read-back",
                mutation.device
            ),
        ));
    };
    if mutation.limits.matches_requested(actual) {
        Ok(())
    } else {
        Err(operation_error(
            operation,
            ErrorCode::FailedPrecondition,
            format!(
                "cgroup RDMA limits for {} read back differently",
                mutation.device
            ),
        ))
    }
}

async fn rollback_after_failure(
    path: &Path,
    applied: &[PreparedRdmaMutation],
    original: Error,
) -> Error {
    let failures = rollback_mutations(path, applied).await;
    if failures.is_empty() {
        original
    } else {
        update_error(
            ErrorCode::Internal,
            format!(
                "{}; RDMA rollback also failed: {}",
                original.message,
                failures.join("; ")
            ),
        )
    }
}

async fn rollback_mutations(path: &Path, applied: &[PreparedRdmaMutation]) -> Vec<String> {
    let mut failures = Vec::new();
    for prepared in applied.iter().rev() {
        let rollback = prepared.rollback_mutation();
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
