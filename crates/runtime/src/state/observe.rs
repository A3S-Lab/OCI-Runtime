use std::collections::BTreeMap;

use a3s_oci_core::{LifecycleEvent, LifecycleState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ErrorCode, OciSchemaValidator, Result, RuntimeEventKind,
};

use crate::driver::{DriverState, RecreatedProcess};
use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{StoredOperation, StoredOperationKind, StoredOperationStatus};
use super::oci_state::{container_state, is_paused, rebuild_paused_state, rebuild_state};
use super::{generation_conflict, DurableStateStore};

impl DurableStateStore {
    pub(crate) async fn observe_state(
        &self,
        target: &ContainerTarget,
        status: ContainerState,
        pid: Option<i32>,
    ) -> Result<ContainerRecord> {
        self.observe_state_with_pause(target, status, pid, false)
            .await
    }

    pub(crate) async fn observe_state_with_pause(
        &self,
        target: &ContainerTarget,
        status: ContainerState,
        pid: Option<i32>,
        paused: bool,
    ) -> Result<ContainerRecord> {
        self.observe_state_inner(target, status, pid, paused, RecreatedProcess::None)
            .await
    }

    pub(crate) async fn observe_recreated_created_process(
        &self,
        target: &ContainerTarget,
        observation: DriverState,
    ) -> Result<ContainerRecord> {
        if observation.status() != ContainerState::Created || observation.paused() {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "observe-recreated-created-process",
                "replacement-owner recovery requires an unpaused created state",
            ));
        }
        self.observe_state_inner(
            target,
            observation.status(),
            observation.pid(),
            observation.paused(),
            RecreatedProcess::Created,
        )
        .await
    }

    pub(crate) async fn observe_recreated_running_process(
        &self,
        target: &ContainerTarget,
        observation: DriverState,
    ) -> Result<ContainerRecord> {
        if observation.status() != ContainerState::Running || observation.paused() {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "observe-recreated-running-process",
                "replacement-owner recovery requires an unpaused running state",
            ));
        }
        self.observe_state_inner(
            target,
            observation.status(),
            observation.pid(),
            observation.paused(),
            RecreatedProcess::Running,
        )
        .await
    }

    pub(crate) async fn observe_recreated_paused_running_process(
        &self,
        target: &ContainerTarget,
        observation: DriverState,
    ) -> Result<ContainerRecord> {
        if observation.status() != ContainerState::Running || !observation.paused() {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "observe-recreated-paused-running-process",
                "replacement-owner paused recovery requires a paused running state",
            ));
        }
        self.observe_state_inner(
            target,
            observation.status(),
            observation.pid(),
            observation.paused(),
            RecreatedProcess::RunningPaused,
        )
        .await
    }

    async fn observe_state_inner(
        &self,
        target: &ContainerTarget,
        status: ContainerState,
        pid: Option<i32>,
        paused: bool,
        recreated_process: RecreatedProcess,
    ) -> Result<ContainerRecord> {
        validate_observation(status, pid, paused)?;
        let _guard = self.gate.lock().await;
        let mut stored = self.load_stored_container(&target.id).await?;
        if let Some(expected) = target.generation {
            if stored.record.generation != expected {
                return Err(generation_conflict(
                    &target.id,
                    expected,
                    stored.record.generation,
                    "observe-state",
                ));
            }
        }

        let current = *stored.record.state.status();
        let mut active = if let Some(operation_id) = stored.active_operation.as_ref() {
            let operation = self.load_operation(operation_id).await?;
            validate_active_operation(&stored, &operation)?;
            Some(operation)
        } else {
            None
        };
        if recreated_process == RecreatedProcess::Running
            && current == ContainerState::Running
            && is_paused(&stored.record.state)
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "observe-recreated-running-process",
                format!(
                    "container {} is paused and cannot use unpaused running-process recovery",
                    target.id
                ),
            ));
        }
        if recreated_process == RecreatedProcess::RunningPaused
            && (current != ContainerState::Running || !is_paused(&stored.record.state))
        {
            return Err(state_error(
                ErrorCode::Conflict,
                "observe-recreated-paused-running-process",
                format!(
                    "container {} is not durably paused and cannot use paused running-process recovery",
                    target.id
                ),
            ));
        }
        let completes_active = active
            .as_ref()
            .is_some_and(|operation| observation_completes(operation.kind, status, paused));
        let mut state_changed = false;
        match (current, status) {
            (ContainerState::Created, ContainerState::Created)
            | (ContainerState::Running, ContainerState::Running) => {
                if *stored.record.state.pid() != pid {
                    let replacement_matches = matches!(
                        (recreated_process, current),
                        (RecreatedProcess::Created, ContainerState::Created)
                            | (RecreatedProcess::Running, ContainerState::Running)
                            | (RecreatedProcess::RunningPaused, ContainerState::Running)
                    );
                    let active_allows_replacement = active.is_none()
                        || matches!(
                            (
                                recreated_process,
                                current,
                                active.as_ref().map(|operation| operation.kind)
                            ),
                            (
                                RecreatedProcess::Created,
                                ContainerState::Created,
                                Some(StoredOperationKind::Start)
                            ) | (
                                RecreatedProcess::Running,
                                ContainerState::Running,
                                Some(
                                    StoredOperationKind::Kill
                                        | StoredOperationKind::Pause
                                        | StoredOperationKind::Resume
                                        | StoredOperationKind::Update
                                        | StoredOperationKind::File
                                        | StoredOperationKind::Filesystem
                                )
                            ) | (
                                RecreatedProcess::RunningPaused,
                                ContainerState::Running,
                                Some(StoredOperationKind::Pause | StoredOperationKind::Resume)
                            )
                        );
                    let freezer_matches = match recreated_process {
                        RecreatedProcess::RunningPaused => is_paused(&stored.record.state),
                        RecreatedProcess::Created | RecreatedProcess::Running => {
                            !is_paused(&stored.record.state)
                        }
                        RecreatedProcess::None => false,
                    };
                    if replacement_matches && active_allows_replacement && freezer_matches {
                        stored.record.state = rebuild_state(&stored.record.state, current, pid)?;
                        OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
                        state_changed = true;
                    } else {
                        return Err(state_error(
                            ErrorCode::Conflict,
                            "observe-state",
                            format!(
                                "container {} PID mismatch: durable {:?}, driver {pid:?}",
                                target.id,
                                stored.record.state.pid()
                            ),
                        ));
                    }
                }
                if is_paused(&stored.record.state) != paused {
                    stored.record.state = rebuild_paused_state(&stored.record.state, paused)?;
                    OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
                    state_changed = true;
                }
            }
            (ContainerState::Created, ContainerState::Running)
                if active
                    .as_ref()
                    .is_some_and(|operation| operation.kind == StoredOperationKind::Start) =>
            {
                let running = LifecycleState::Created
                    .transition(LifecycleEvent::StartCompleted)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "observe-state",
                            error.to_string(),
                        )
                    })?;
                stored.record.state =
                    rebuild_state(&stored.record.state, container_state(running), pid)?;
                if paused {
                    stored.record.state = rebuild_paused_state(&stored.record.state, true)?;
                }
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
                state_changed = true;
            }
            (ContainerState::Created | ContainerState::Running, ContainerState::Stopped) => {
                let lifecycle = lifecycle_state(current)
                    .transition(LifecycleEvent::ProcessExited)
                    .map_err(|error| {
                        state_error(
                            ErrorCode::FailedPrecondition,
                            "observe-state",
                            error.to_string(),
                        )
                    })?;
                stored.record.state =
                    rebuild_state(&stored.record.state, container_state(lifecycle), None)?;
                OciSchemaValidator::new()?.validate_state(&stored.record.state)?;
                state_changed = true;
            }
            (ContainerState::Stopped, ContainerState::Stopped) => {}
            (_, observed) => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "observe-state",
                    format!(
                        "container {} cannot reconcile durable {current} with driver {observed}",
                        target.id
                    ),
                ));
            }
        }

        if completes_active {
            stored.active_operation = None;
            state_changed = true;
        }
        if state_changed {
            self.write_json(
                DurableMutation::ObserveContainer,
                &self
                    .container_directory(&target.id)
                    .join(super::CONTAINER_RECORD_FILE),
                &stored,
            )
            .await?;
        }
        let exact_target = ContainerTarget::exact(stored.id.clone(), stored.record.generation);
        if completes_active {
            let operation = active.as_ref().ok_or_else(|| {
                state_error(
                    ErrorCode::Internal,
                    "observe-state",
                    "active operation disappeared before event reconciliation",
                )
            })?;
            match operation.kind {
                StoredOperationKind::Start => {
                    self.append_container_event(
                        "started",
                        &exact_target,
                        RuntimeEventKind::ContainerStarted,
                        BTreeMap::new(),
                    )
                    .await?;
                }
                StoredOperationKind::Pause | StoredOperationKind::Resume => {
                    let (suffix, kind) = if operation.kind == StoredOperationKind::Pause {
                        ("pause", RuntimeEventKind::ContainerPaused)
                    } else {
                        ("resume", RuntimeEventKind::ContainerResumed)
                    };
                    self.append_operation_event(
                        &operation.operation_id,
                        suffix,
                        &exact_target,
                        None,
                        kind,
                        BTreeMap::from([(
                            "operation-id".to_string(),
                            operation.operation_id.as_str().to_string(),
                        )]),
                    )
                    .await?;
                }
                StoredOperationKind::Kill | StoredOperationKind::SignalProcess => {}
                StoredOperationKind::Create
                | StoredOperationKind::Delete
                | StoredOperationKind::Exec
                | StoredOperationKind::WriteStdin
                | StoredOperationKind::CloseStdin
                | StoredOperationKind::Resize
                | StoredOperationKind::Update
                | StoredOperationKind::File
                | StoredOperationKind::Filesystem
                | StoredOperationKind::Checkpoint
                | StoredOperationKind::Restore
                | StoredOperationKind::Attest => {}
            }
        }
        if status == ContainerState::Stopped && current != ContainerState::Stopped {
            self.append_container_event(
                "stopped",
                &exact_target,
                RuntimeEventKind::ContainerStopped,
                BTreeMap::new(),
            )
            .await?;
        }
        if completes_active {
            let mut operation = active.take().ok_or_else(|| {
                state_error(
                    ErrorCode::Internal,
                    "observe-state",
                    "active operation disappeared during state reconciliation",
                )
            })?;
            operation.outcome = match operation.kind {
                StoredOperationKind::SignalProcess => StoredOperationStatus::SucceededEmpty,
                StoredOperationKind::Start
                | StoredOperationKind::Kill
                | StoredOperationKind::Pause
                | StoredOperationKind::Resume => StoredOperationStatus::Succeeded {
                    response: stored.record.clone(),
                },
                StoredOperationKind::Create
                | StoredOperationKind::Delete
                | StoredOperationKind::Exec
                | StoredOperationKind::WriteStdin
                | StoredOperationKind::CloseStdin
                | StoredOperationKind::Resize
                | StoredOperationKind::Update
                | StoredOperationKind::File
                | StoredOperationKind::Filesystem
                | StoredOperationKind::Checkpoint
                | StoredOperationKind::Restore
                | StoredOperationKind::Attest => {
                    return Err(state_error(
                        ErrorCode::Internal,
                        "observe-state",
                        format!(
                            "operation {} cannot complete from a container observation",
                            operation.operation_id
                        ),
                    ));
                }
            };
            self.write_json(
                DurableMutation::CompleteObservedOperation,
                &self.operation_path(&operation.operation_id),
                &operation,
            )
            .await?;
        }
        Ok(stored.record)
    }
}

fn validate_active_operation(
    stored: &super::model::StoredContainer,
    operation: &StoredOperation,
) -> Result<()> {
    if operation.container_id != stored.id
        || operation.generation != stored.record.generation
        || !matches!(operation.outcome, StoredOperationStatus::Prepared)
    {
        return Err(state_error(
            ErrorCode::Conflict,
            "observe-state",
            format!(
                "container {} active operation {} does not match its durable record",
                stored.id, operation.operation_id
            ),
        ));
    }
    Ok(())
}

fn observation_completes(kind: StoredOperationKind, status: ContainerState, paused: bool) -> bool {
    match kind {
        StoredOperationKind::Start => {
            matches!(status, ContainerState::Running | ContainerState::Stopped)
        }
        StoredOperationKind::Kill | StoredOperationKind::SignalProcess => {
            matches!(status, ContainerState::Stopped)
        }
        StoredOperationKind::Pause => status == ContainerState::Running && paused,
        StoredOperationKind::Resume => status == ContainerState::Running && !paused,
        StoredOperationKind::Create
        | StoredOperationKind::Delete
        | StoredOperationKind::Exec
        | StoredOperationKind::WriteStdin
        | StoredOperationKind::CloseStdin
        | StoredOperationKind::Resize
        | StoredOperationKind::Update
        | StoredOperationKind::File
        | StoredOperationKind::Filesystem
        | StoredOperationKind::Checkpoint
        | StoredOperationKind::Restore
        | StoredOperationKind::Attest => false,
    }
}

fn validate_observation(status: ContainerState, pid: Option<i32>, paused: bool) -> Result<()> {
    match (status, pid, paused) {
        (ContainerState::Created, Some(pid), false) if pid > 0 => Ok(()),
        (ContainerState::Running, Some(pid), _) if pid > 0 => Ok(()),
        (ContainerState::Stopped, None, false) => Ok(()),
        _ => Err(state_error(
            ErrorCode::InvalidArgument,
            "observe-state",
            format!(
                "driver returned invalid OCI state {status} with PID {pid:?} and paused={paused}"
            ),
        )),
    }
}

const fn lifecycle_state(status: ContainerState) -> LifecycleState {
    match status {
        ContainerState::Creating => LifecycleState::Creating,
        ContainerState::Created => LifecycleState::Created,
        ContainerState::Running => LifecycleState::Running,
        ContainerState::Stopped => LifecycleState::Stopped,
    }
}
