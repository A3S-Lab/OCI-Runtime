use std::collections::BTreeMap;
use std::path::PathBuf;

use a3s_oci_agent_protocol::{
    AgentInheritedDescriptorSchema, AgentProcess, AgentRecoveryRecord, AgentState,
};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    canonical_json_bytes, ContainerStats, ErrorCode, ExitStatus, FileResponse, FilesystemResponse,
    OperationId, ProcessId, ProcessRecord, ProcessTarget, Result,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::cgroup::CgroupManager;
use super::exec_process::ExecProcess;
use super::pidfd::SignalOutcome;
use super::process::PreparedProcess;
use super::{executor_error, MAX_OPERATION_RECORDS};

#[derive(Debug, Default)]
pub(super) struct ExecutorState {
    pub(super) containers: BTreeMap<ContainerKey, ContainerRecord>,
    pub(super) highest_generations: BTreeMap<String, u64>,
    operations: BTreeMap<OperationId, OperationRecord>,
    pending_state_operations: BTreeMap<OperationId, PendingStateOperation>,
    pending_unit_operations: BTreeMap<OperationId, PendingUnitOperation>,
    pending_process_operations: BTreeMap<OperationId, PendingProcessOperation>,
    pending_file_operations: BTreeMap<OperationId, PendingFileOperation>,
    pending_filesystem_operations: BTreeMap<OperationId, PendingFilesystemOperation>,
    pub(super) next_slot: u64,
    pub(super) cgroup_manager: Option<CgroupManager>,
}

impl ExecutorState {
    pub(super) fn acknowledge_operations(&mut self, operation_ids: &[OperationId]) -> Result<()> {
        if operation_ids.len() > MAX_OPERATION_RECORDS {
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                format!(
                    "guest operation acknowledgement contains {} entries; maximum is {MAX_OPERATION_RECORDS}",
                    operation_ids.len()
                ),
            ));
        }
        if let Some(operation_id) = operation_ids
            .iter()
            .find(|operation_id| self.has_pending_operation(operation_id))
        {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "guest operation {operation_id} cannot be acknowledged while it is still pending"
                ),
            ));
        }
        for operation_id in operation_ids {
            self.operations.remove(operation_id);
        }
        Ok(())
    }

    pub(super) fn reserve_operation(&self, operation_id: &OperationId) -> Result<()> {
        if self.has_pending_operation(operation_id) {
            return Err(reused_operation(operation_id));
        }
        if self
            .operations
            .len()
            .saturating_add(self.pending_state_operations.len())
            .saturating_add(self.pending_unit_operations.len())
            .saturating_add(self.pending_process_operations.len())
            .saturating_add(self.pending_file_operations.len())
            .saturating_add(self.pending_filesystem_operations.len())
            >= MAX_OPERATION_RECORDS
        {
            Err(executor_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "guest operation journal reached {MAX_OPERATION_RECORDS} entries before \
                     operation {operation_id}"
                ),
            ))
        } else {
            Ok(())
        }
    }

    fn has_pending_operation(&self, operation_id: &OperationId) -> bool {
        self.pending_state_operations.contains_key(operation_id)
            || self.pending_unit_operations.contains_key(operation_id)
            || self.pending_process_operations.contains_key(operation_id)
            || self.pending_file_operations.contains_key(operation_id)
            || self
                .pending_filesystem_operations
                .contains_key(operation_id)
    }

    pub(super) fn replay_state(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<AgentState>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::State(result) => result.clone(),
                _ => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn replay_unit(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<()>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::Unit(result) => result.clone(),
                _ => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn prepare_state_operation(
        &mut self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Result<StateOperationPreparation> {
        if let Some(result) = self.replay_state(operation_id, request) {
            return Ok(StateOperationPreparation::Completed(result));
        }
        if let Some(pending) = self.pending_state_operations.get(operation_id) {
            pending.validate_request(request)?;
            return Ok(StateOperationPreparation::Pending(
                pending.completion.subscribe(),
            ));
        }
        self.reserve_operation(operation_id)?;
        let (completion, receiver) = watch::channel(None);
        self.pending_state_operations.insert(
            operation_id.clone(),
            PendingStateOperation {
                request: request.clone(),
                completion,
            },
        );
        Ok(StateOperationPreparation::Claimed(receiver))
    }

    pub(super) fn complete_state_operation(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        result: Result<AgentState>,
    ) -> Result<()> {
        let Some(pending) = self.pending_state_operations.remove(&operation_id) else {
            return Err(executor_error(
                ErrorCode::Internal,
                format!("guest state operation {operation_id} completed without an active claim"),
            ));
        };
        if let Err(error) = pending.validate_request(&request) {
            self.record(
                operation_id,
                pending.request.clone(),
                RecordedOutcome::State(Err(error.clone())),
            );
            pending.completion.send_replace(Some(Err(error.clone())));
            return Err(error);
        }
        self.record(
            operation_id,
            request,
            RecordedOutcome::State(result.clone()),
        );
        pending.completion.send_replace(Some(result));
        Ok(())
    }

    pub(super) fn prepare_unit_operation(
        &mut self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Result<UnitOperationPreparation> {
        if let Some(result) = self.replay_unit(operation_id, request) {
            return Ok(UnitOperationPreparation::Completed(result));
        }
        if let Some(pending) = self.pending_unit_operations.get(operation_id) {
            pending.validate_request(request)?;
            return Ok(UnitOperationPreparation::Pending(
                pending.completion.subscribe(),
            ));
        }
        self.reserve_operation(operation_id)?;
        let (completion, receiver) = watch::channel(None);
        self.pending_unit_operations.insert(
            operation_id.clone(),
            PendingUnitOperation {
                request: request.clone(),
                completion,
            },
        );
        Ok(UnitOperationPreparation::Claimed(receiver))
    }

    pub(super) fn complete_unit_operation(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        result: Result<()>,
    ) -> Result<()> {
        let Some(pending) = self.pending_unit_operations.remove(&operation_id) else {
            return Err(executor_error(
                ErrorCode::Internal,
                format!("guest operation {operation_id} completed without an active unit claim"),
            ));
        };
        if let Err(error) = pending.validate_request(&request) {
            self.record(
                operation_id,
                pending.request.clone(),
                RecordedOutcome::Unit(Err(error.clone())),
            );
            pending.completion.send_replace(Some(Err(error.clone())));
            return Err(error);
        }
        self.record(operation_id, request, RecordedOutcome::Unit(result.clone()));
        pending.completion.send_replace(Some(result.clone()));
        Ok(())
    }

    pub(super) fn replay_process(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<AgentProcess>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::Process(result) => result.clone(),
                _ => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn prepare_process_operation(
        &mut self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Result<ProcessOperationPreparation> {
        if let Some(result) = self.replay_process(operation_id, request) {
            return Ok(ProcessOperationPreparation::Completed(result));
        }
        if let Some(pending) = self.pending_process_operations.get(operation_id) {
            pending.validate_request(request)?;
            return Ok(ProcessOperationPreparation::Pending(
                pending.completion.subscribe(),
            ));
        }
        self.reserve_operation(operation_id)?;
        let (completion, receiver) = watch::channel(None);
        self.pending_process_operations.insert(
            operation_id.clone(),
            PendingProcessOperation {
                request: request.clone(),
                completion,
            },
        );
        Ok(ProcessOperationPreparation::Claimed(receiver))
    }

    pub(super) fn complete_process_operation(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        result: Result<AgentProcess>,
    ) -> Result<()> {
        let Some(pending) = self.pending_process_operations.remove(&operation_id) else {
            return Err(executor_error(
                ErrorCode::Internal,
                format!("guest process operation {operation_id} completed without an active claim"),
            ));
        };
        if let Err(error) = pending.validate_request(&request) {
            self.record(
                operation_id,
                pending.request.clone(),
                RecordedOutcome::Process(Err(error.clone())),
            );
            pending.completion.send_replace(Some(Err(error.clone())));
            return Err(error);
        }
        self.record(
            operation_id,
            request,
            RecordedOutcome::Process(result.clone()),
        );
        pending.completion.send_replace(Some(result));
        Ok(())
    }

    pub(super) fn prepare_file_operation(
        &mut self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Result<FileOperationPreparation> {
        if let Some(result) = self.replay_file(operation_id, request) {
            return Ok(FileOperationPreparation::Completed(result));
        }
        if let Some(pending) = self.pending_file_operations.get(operation_id) {
            pending.validate_request(request)?;
            return Ok(FileOperationPreparation::Pending(
                pending.completion.subscribe(),
            ));
        }
        self.reserve_operation(operation_id)?;
        let (completion, receiver) = watch::channel(None);
        self.pending_file_operations.insert(
            operation_id.clone(),
            PendingFileOperation {
                request: request.clone(),
                completion,
            },
        );
        Ok(FileOperationPreparation::Claimed(receiver))
    }

    pub(super) fn complete_file_operation(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        result: Result<FileResponse>,
    ) -> Result<()> {
        let Some(pending) = self.pending_file_operations.remove(&operation_id) else {
            return Err(executor_error(
                ErrorCode::Internal,
                format!("guest file operation {operation_id} completed without an active claim"),
            ));
        };
        if let Err(error) = pending.validate_request(&request) {
            self.record(
                operation_id,
                pending.request.clone(),
                RecordedOutcome::File(Err(error.clone())),
            );
            pending.completion.send_replace(Some(Err(error.clone())));
            return Err(error);
        }
        self.record(operation_id, request, RecordedOutcome::File(result.clone()));
        pending.completion.send_replace(Some(result));
        Ok(())
    }

    pub(super) fn prepare_filesystem_operation(
        &mut self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Result<FilesystemOperationPreparation> {
        if let Some(result) = self.replay_filesystem(operation_id, request) {
            return Ok(FilesystemOperationPreparation::Completed(Box::new(result)));
        }
        if let Some(pending) = self.pending_filesystem_operations.get(operation_id) {
            pending.validate_request(request)?;
            return Ok(FilesystemOperationPreparation::Pending(
                pending.completion.subscribe(),
            ));
        }
        self.reserve_operation(operation_id)?;
        let (completion, receiver) = watch::channel(None);
        self.pending_filesystem_operations.insert(
            operation_id.clone(),
            PendingFilesystemOperation {
                request: request.clone(),
                completion,
            },
        );
        Ok(FilesystemOperationPreparation::Claimed(receiver))
    }

    pub(super) fn complete_filesystem_operation(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        result: Result<FilesystemResponse>,
    ) -> Result<()> {
        let Some(pending) = self.pending_filesystem_operations.remove(&operation_id) else {
            return Err(executor_error(
                ErrorCode::Internal,
                format!(
                    "guest filesystem operation {operation_id} completed without an active claim"
                ),
            ));
        };
        if let Err(error) = pending.validate_request(&request) {
            self.record(
                operation_id,
                pending.request.clone(),
                RecordedOutcome::Filesystem(Err(error.clone())),
            );
            pending.completion.send_replace(Some(Err(error.clone())));
            return Err(error);
        }
        self.record(
            operation_id,
            request,
            RecordedOutcome::Filesystem(result.clone()),
        );
        pending.completion.send_replace(Some(result));
        Ok(())
    }

    pub(super) fn replay_file(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<FileResponse>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::File(result) => result.clone(),
                _ => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn replay_filesystem(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<FilesystemResponse>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::Filesystem(result) => result.clone(),
                _ => Err(reused_operation(operation_id)),
            }
        })
    }

    pub(super) fn record(
        &mut self,
        operation_id: OperationId,
        request: RecordedRequest,
        outcome: RecordedOutcome,
    ) {
        self.operations
            .insert(operation_id, OperationRecord { request, outcome });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ContainerKey {
    pub(super) id: String,
    pub(super) generation: u64,
}

impl ContainerKey {
    pub(super) fn from_target(target: &a3s_oci_sdk::ContainerTarget) -> Result<Self> {
        let generation = target.generation.ok_or_else(|| {
            executor_error(
                ErrorCode::InvalidArgument,
                "guest executor requires an exact container generation",
            )
        })?;
        if generation.0 == 0 {
            return Err(executor_error(
                ErrorCode::InvalidArgument,
                "guest executor requires a positive container generation",
            ));
        }
        Ok(Self {
            id: target.id.as_str().to_string(),
            generation: generation.0,
        })
    }
}

#[derive(Debug)]
pub(super) struct ContainerRecord {
    pub(super) target: a3s_oci_sdk::ContainerTarget,
    pub(super) config_digest: String,
    pub(super) status: ContainerState,
    pub(super) paused: bool,
    pub(super) process: PreparedProcess,
    pub(super) processes: BTreeMap<ProcessId, ExecProcess>,
    pub(super) runtime_directory: PathBuf,
}

impl ContainerRecord {
    pub(super) fn refresh(&mut self) -> Result<()> {
        self.poll_wait()?;
        for process in self.processes.values_mut() {
            process.try_wait()?;
        }
        Ok(())
    }

    pub(super) fn poll_wait(&mut self) -> Result<Option<ExitStatus>> {
        let status = self.process.try_wait()?;
        if status.is_some() {
            self.status = ContainerState::Stopped;
            self.paused = false;
        }
        Ok(status)
    }

    pub(super) fn state(&self) -> Result<AgentState> {
        AgentState::new_with_pause(
            self.target.clone(),
            self.status,
            if self.status == ContainerState::Stopped {
                None
            } else {
                Some(self.process.pid())
            },
            self.config_digest.clone(),
            self.paused,
        )
    }

    pub(super) async fn set_frozen(&mut self, frozen: bool) -> Result<()> {
        self.refresh()?;
        if self.status != ContainerState::Running {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "container cannot change freezer state while {}",
                    self.status
                ),
            ));
        }
        if self.paused == frozen {
            return Ok(());
        }
        self.process.set_frozen(frozen).await?;
        self.paused = frozen;
        Ok(())
    }

    pub(super) async fn update_resources(&mut self, resources: &LinuxResources) -> Result<()> {
        self.refresh()?;
        if !matches!(
            self.status,
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(executor_error(
                ErrorCode::FailedPrecondition,
                format!("container cannot update resources while {}", self.status),
            ));
        }
        self.process.update_resources(resources).await
    }

    pub(super) async fn stats(&mut self) -> Result<ContainerStats> {
        self.refresh()?;
        self.process.stats(self.target.clone()).await
    }

    pub(super) fn live_processes(&mut self) -> Result<Vec<ProcessRecord>> {
        self.refresh()?;
        let mut records = Vec::new();
        if self.status != ContainerState::Stopped {
            records.push(process_record(
                &self.target,
                ProcessId::init(),
                self.process.pid(),
                false,
            )?);
        }
        for (process_id, process) in &mut self.processes {
            if process.try_wait()?.is_none() {
                records.push(process_record(
                    &self.target,
                    process_id.clone(),
                    process.pid(),
                    process.terminal(),
                )?);
            }
        }
        Ok(records)
    }

    pub(super) async fn force_stop_all(&mut self) -> Result<()> {
        let mut first_error = None;
        if self.paused {
            if let Err(error) = self.process.set_frozen(false).await {
                first_error.get_or_insert(error);
            } else {
                self.paused = false;
            }
        }
        for process in self.processes.values_mut() {
            if let Err(error) = process.force_stop().await {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.process.force_stop().await {
            first_error.get_or_insert(error);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn recovery_record(&mut self) -> Result<AgentRecoveryRecord> {
        let init_exit_status = self.poll_wait()?.ok_or_else(|| {
            executor_error(
                ErrorCode::Internal,
                format!(
                    "init process for container {} has no terminal result after forced shutdown",
                    self.target.id
                ),
            )
        })?;
        AgentRecoveryRecord::new(
            self.target.clone(),
            self.config_digest.clone(),
            init_exit_status,
        )
    }

    pub(super) fn signal_all(&self, signal: i32) -> Result<SignalOutcome> {
        let mut first_error = None;
        for process in self.processes.values() {
            if let Err(error) = process.signal_all(signal) {
                first_error.get_or_insert(error);
            }
        }
        let init_outcome = match self.process.signal_all(signal) {
            Ok(outcome) => outcome,
            Err(error) => {
                first_error.get_or_insert(error);
                SignalOutcome::Exited
            }
        };
        match first_error {
            Some(error) => Err(error),
            None => Ok(init_outcome),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MutationKind {
    Create,
    Start,
    Kill,
    Delete,
    Exec,
    SignalProcess,
    Pause,
    Resume,
    Update,
    WriteStdin,
    CloseStdin,
    Resize,
    File,
    Filesystem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordedRequest {
    kind: MutationKind,
    digest: [u8; 32],
}

impl RecordedRequest {
    pub(super) fn new(kind: MutationKind, request: &impl Serialize) -> Result<Self> {
        let encoded = canonical_json_bytes(request).map_err(|error| {
            executor_error(
                ErrorCode::Internal,
                format!("failed to fingerprint guest operation request: {error}"),
            )
        })?;
        Ok(Self {
            kind,
            digest: Sha256::digest(encoded).into(),
        })
    }

    pub(super) fn create(
        request: &impl Serialize,
        inherited_descriptors: Option<&AgentInheritedDescriptorSchema>,
    ) -> Result<Self> {
        #[derive(Serialize)]
        struct CreateFingerprint<'a, T> {
            request: &'a T,
            #[serde(skip_serializing_if = "Option::is_none")]
            inherited_descriptors: Option<&'a AgentInheritedDescriptorSchema>,
        }

        Self::new(
            MutationKind::Create,
            &CreateFingerprint {
                request,
                inherited_descriptors,
            },
        )
    }
}

#[derive(Debug, Clone)]
struct OperationRecord {
    request: RecordedRequest,
    outcome: RecordedOutcome,
}

#[derive(Debug)]
struct PendingStateOperation {
    request: RecordedRequest,
    completion: watch::Sender<Option<Result<AgentState>>>,
}

impl PendingStateOperation {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

#[derive(Debug)]
struct PendingUnitOperation {
    request: RecordedRequest,
    completion: watch::Sender<Option<Result<()>>>,
}

impl PendingUnitOperation {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

#[derive(Debug)]
struct PendingProcessOperation {
    request: RecordedRequest,
    completion: watch::Sender<Option<Result<AgentProcess>>>,
}

impl PendingProcessOperation {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

#[derive(Debug)]
struct PendingFileOperation {
    request: RecordedRequest,
    completion: watch::Sender<Option<Result<FileResponse>>>,
}

impl PendingFileOperation {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

#[derive(Debug)]
struct PendingFilesystemOperation {
    request: RecordedRequest,
    completion: watch::Sender<Option<Result<FilesystemResponse>>>,
}

impl PendingFilesystemOperation {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

pub(super) enum UnitOperationPreparation {
    Completed(Result<()>),
    Pending(watch::Receiver<Option<Result<()>>>),
    Claimed(watch::Receiver<Option<Result<()>>>),
}

pub(super) enum StateOperationPreparation {
    Completed(Result<AgentState>),
    Pending(watch::Receiver<Option<Result<AgentState>>>),
    Claimed(watch::Receiver<Option<Result<AgentState>>>),
}

pub(super) enum ProcessOperationPreparation {
    Completed(Result<AgentProcess>),
    Pending(watch::Receiver<Option<Result<AgentProcess>>>),
    Claimed(watch::Receiver<Option<Result<AgentProcess>>>),
}

#[derive(Debug)]
pub(super) enum FileOperationPreparation {
    Completed(Result<FileResponse>),
    Pending(watch::Receiver<Option<Result<FileResponse>>>),
    Claimed(watch::Receiver<Option<Result<FileResponse>>>),
}

#[derive(Debug)]
pub(super) enum FilesystemOperationPreparation {
    Completed(Box<Result<FilesystemResponse>>),
    Pending(watch::Receiver<Option<Result<FilesystemResponse>>>),
    Claimed(watch::Receiver<Option<Result<FilesystemResponse>>>),
}

impl OperationRecord {
    fn validate_request(&self, request: &RecordedRequest) -> Result<()> {
        if &self.request == request {
            Ok(())
        } else {
            Err(executor_error(
                ErrorCode::Conflict,
                "guest operation ID was reused for a different request",
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum RecordedOutcome {
    State(Result<AgentState>),
    Unit(Result<()>),
    Process(Result<AgentProcess>),
    File(Result<FileResponse>),
    Filesystem(Result<FilesystemResponse>),
}

fn reused_operation(operation_id: &OperationId) -> a3s_oci_sdk::Error {
    executor_error(
        ErrorCode::Conflict,
        format!("guest operation ID {operation_id} was reused across operation kinds"),
    )
}

fn process_record(
    container: &a3s_oci_sdk::ContainerTarget,
    process_id: ProcessId,
    pid: i32,
    terminal: bool,
) -> Result<ProcessRecord> {
    let pid = u32::try_from(pid).map_err(|error| {
        executor_error(
            ErrorCode::Internal,
            format!("live process PID {pid} does not fit the SDK process model: {error}"),
        )
    })?;
    if pid == 0 {
        return Err(executor_error(
            ErrorCode::Internal,
            "live process inventory contained PID zero",
        ));
    }
    Ok(ProcessRecord {
        target: ProcessTarget {
            container: container.clone(),
            process_id,
        },
        pid: Some(pid),
        terminal,
    })
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{AgentInheritedDescriptorSchema, AgentProcess, AgentState};
    use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, ErrorCode, FileResponse, FilesystemResponse, Generation,
        OperationId, ProcessId, ProcessTarget,
    };
    use serde_json::json;

    use super::{
        ExecutorState, FileOperationPreparation, FilesystemOperationPreparation, MutationKind,
        ProcessOperationPreparation, RecordedOutcome, RecordedRequest, StateOperationPreparation,
        UnitOperationPreparation,
    };

    #[test]
    fn guest_operation_journal_replays_only_the_exact_request() {
        for (index, kind) in [
            MutationKind::Delete,
            MutationKind::WriteStdin,
            MutationKind::CloseStdin,
            MutationKind::Resize,
        ]
        .into_iter()
        .enumerate()
        {
            let operation_id =
                OperationId::new(format!("guest-mutation-{index}")).expect("valid operation ID");
            let request =
                RecordedRequest::new(kind, &json!({"target": "one"})).expect("fingerprint request");
            let mut state = ExecutorState::default();
            state.record(
                operation_id.clone(),
                request.clone(),
                RecordedOutcome::Unit(Ok(())),
            );

            assert_eq!(state.replay_unit(&operation_id, &request), Some(Ok(())));
            let changed = RecordedRequest::new(kind, &json!({"target": "two"}))
                .expect("fingerprint changed request");
            let error = state
                .replay_unit(&operation_id, &changed)
                .expect("operation exists")
                .expect_err("changed request must fail");
            assert_eq!(error.code, ErrorCode::Conflict);
        }

        let operation_id = OperationId::new("guest-cross-kind").expect("valid operation ID");
        let write = RecordedRequest::new(MutationKind::WriteStdin, &json!({"target": "one"}))
            .expect("fingerprint stdin write");
        let close = RecordedRequest::new(MutationKind::CloseStdin, &json!({"target": "one"}))
            .expect("fingerprint stdin close");
        let mut state = ExecutorState::default();
        state.record(operation_id.clone(), write, RecordedOutcome::Unit(Ok(())));
        let error = state
            .replay_unit(&operation_id, &close)
            .expect("operation exists")
            .expect_err("cross-kind reuse must fail");
        assert_eq!(error.code, ErrorCode::Conflict);
    }

    #[test]
    fn guest_operation_fingerprint_is_stable_across_resource_map_reconstruction() {
        let first: LinuxResources =
            serde_json::from_str(r#"{"unified":{"memory.low":"0","memory.high":"1"}}"#)
                .expect("first Linux resources");
        let reopened: LinuxResources =
            serde_json::from_str(r#"{"unified":{"memory.high":"1","memory.low":"0"}}"#)
                .expect("reopened Linux resources");

        assert_eq!(
            RecordedRequest::new(MutationKind::Update, &first).expect("first Update fingerprint"),
            RecordedRequest::new(MutationKind::Update, &reopened)
                .expect("reopened Update fingerprint")
        );
    }

    #[tokio::test]
    async fn concurrent_unit_retries_join_one_claim_and_replay_one_result() {
        let operation_id = OperationId::new("guest-pending-write").expect("operation ID");
        let request = RecordedRequest::new(
            MutationKind::WriteStdin,
            &json!({"target": "init", "data": "large"}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();

        let UnitOperationPreparation::Claimed(mut owner) = state
            .prepare_unit_operation(&operation_id, &request)
            .expect("claim operation")
        else {
            panic!("first request must own the operation");
        };
        let UnitOperationPreparation::Pending(mut retry) = state
            .prepare_unit_operation(&operation_id, &request)
            .expect("join operation")
        else {
            panic!("concurrent retry must join the operation");
        };
        let changed = RecordedRequest::new(
            MutationKind::WriteStdin,
            &json!({"target": "init", "data": "changed"}),
        )
        .expect("fingerprint changed request");
        assert_eq!(
            state
                .prepare_unit_operation(&operation_id, &changed)
                .err()
                .expect("changed pending request must conflict")
                .code,
            ErrorCode::Conflict
        );

        state
            .complete_unit_operation(operation_id.clone(), request.clone(), Ok(()))
            .expect("complete exact operation");
        owner.changed().await.expect("owner result notification");
        retry.changed().await.expect("retry result notification");
        assert_eq!(owner.borrow().clone(), Some(Ok(())));
        assert_eq!(retry.borrow().clone(), Some(Ok(())));
        assert!(matches!(
            state
                .prepare_unit_operation(&operation_id, &request)
                .expect("replay operation"),
            UnitOperationPreparation::Completed(Ok(()))
        ));
    }

    #[tokio::test]
    async fn concurrent_state_retries_join_one_claim_and_replay_one_result() {
        let operation_id = OperationId::new("guest-pending-start").expect("operation ID");
        let digest = format!("sha256:{}", "a".repeat(64));
        let request = RecordedRequest::new(
            MutationKind::Start,
            &json!({"target": "worker", "digest": digest}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();

        let StateOperationPreparation::Claimed(mut owner) = state
            .prepare_state_operation(&operation_id, &request)
            .expect("claim state operation")
        else {
            panic!("first request must own the state operation");
        };
        let StateOperationPreparation::Pending(mut retry) = state
            .prepare_state_operation(&operation_id, &request)
            .expect("join state operation")
        else {
            panic!("concurrent retry must join the state operation");
        };
        let changed = RecordedRequest::new(
            MutationKind::Start,
            &json!({"target": "worker", "digest": "sha256:changed"}),
        )
        .expect("fingerprint changed request");
        assert_eq!(
            state
                .prepare_state_operation(&operation_id, &changed)
                .err()
                .expect("changed pending request must conflict")
                .code,
            ErrorCode::Conflict
        );

        let target = ContainerTarget::exact(
            ContainerId::new("guest-pending-start").expect("container ID"),
            Generation(1),
        );
        let result = AgentState::new(
            target,
            a3s_oci_sdk::oci_spec::runtime::ContainerState::Running,
            Some(1234),
            format!("sha256:{}", "a".repeat(64)),
        )
        .expect("state result");
        state
            .complete_state_operation(operation_id.clone(), request.clone(), Ok(result.clone()))
            .expect("complete exact state operation");
        owner.changed().await.expect("owner result notification");
        retry.changed().await.expect("retry result notification");
        assert_eq!(owner.borrow().clone(), Some(Ok(result.clone())));
        assert_eq!(retry.borrow().clone(), Some(Ok(result)));
        assert!(matches!(
            state
                .prepare_state_operation(&operation_id, &request)
                .expect("replay state operation"),
            StateOperationPreparation::Completed(Ok(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_process_retries_join_one_claim_and_replay_one_result() {
        let operation_id = OperationId::new("guest-pending-exec").expect("operation ID");
        let request = RecordedRequest::new(
            MutationKind::Exec,
            &json!({"target": "worker", "args": ["/bin/true"]}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();

        let ProcessOperationPreparation::Claimed(mut owner) = state
            .prepare_process_operation(&operation_id, &request)
            .expect("claim process operation")
        else {
            panic!("first request must own the process operation");
        };
        let ProcessOperationPreparation::Pending(mut retry) = state
            .prepare_process_operation(&operation_id, &request)
            .expect("join process operation")
        else {
            panic!("concurrent retry must join the process operation");
        };
        let changed = RecordedRequest::new(
            MutationKind::Exec,
            &json!({"target": "worker", "args": ["/bin/sh"]}),
        )
        .expect("fingerprint changed request");
        assert_eq!(
            state
                .prepare_process_operation(&operation_id, &changed)
                .err()
                .expect("changed pending request must conflict")
                .code,
            ErrorCode::Conflict
        );

        let process_target = ProcessTarget {
            container: ContainerTarget::exact(
                ContainerId::new("guest-pending-exec").expect("container ID"),
                Generation(1),
            ),
            process_id: ProcessId::new("worker").expect("process ID"),
        };
        let process = AgentProcess::new(process_target, 1234, false).expect("process result");
        state
            .complete_process_operation(operation_id.clone(), request.clone(), Ok(process.clone()))
            .expect("complete exact process operation");
        owner.changed().await.expect("owner result notification");
        retry.changed().await.expect("retry result notification");
        assert_eq!(owner.borrow().clone(), Some(Ok(process.clone())));
        assert_eq!(retry.borrow().clone(), Some(Ok(process)));
        assert!(matches!(
            state
                .prepare_process_operation(&operation_id, &request)
                .expect("replay process operation"),
            ProcessOperationPreparation::Completed(Ok(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_file_retries_join_one_claim_and_replay_one_result() {
        let operation_id = OperationId::new("guest-pending-upload").expect("operation ID");
        let request = RecordedRequest::new(
            MutationKind::File,
            &json!({"target": "worker", "op": "upload", "path": "/tmp/state", "data": "YQ=="}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();

        let FileOperationPreparation::Claimed(mut owner) = state
            .prepare_file_operation(&operation_id, &request)
            .expect("claim file operation")
        else {
            panic!("first request must own the file operation");
        };
        let FileOperationPreparation::Pending(mut retry) = state
            .prepare_file_operation(&operation_id, &request)
            .expect("join file operation")
        else {
            panic!("concurrent retry must join the file operation");
        };

        let target = ContainerTarget::exact(
            ContainerId::new("guest-pending-upload").expect("container ID"),
            Generation(1),
        );
        let result = FileResponse {
            target,
            data: None,
            size: 1,
        };
        state
            .complete_file_operation(operation_id.clone(), request.clone(), Ok(result.clone()))
            .expect("complete exact file operation");
        owner.changed().await.expect("owner result notification");
        retry.changed().await.expect("retry result notification");
        assert_eq!(owner.borrow().clone(), Some(Ok(result.clone())));
        assert_eq!(retry.borrow().clone(), Some(Ok(result)));
        assert!(matches!(
            state
                .prepare_file_operation(&operation_id, &request)
                .expect("replay file operation"),
            FileOperationPreparation::Completed(Ok(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_filesystem_retries_join_one_claim_and_replay_one_result() {
        let operation_id = OperationId::new("guest-pending-mkdir").expect("operation ID");
        let request = RecordedRequest::new(
            MutationKind::Filesystem,
            &json!({"target": "worker", "op": "make-dir", "path": "/tmp/state"}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();

        let FilesystemOperationPreparation::Claimed(mut owner) = state
            .prepare_filesystem_operation(&operation_id, &request)
            .expect("claim filesystem operation")
        else {
            panic!("first request must own the filesystem operation");
        };
        let FilesystemOperationPreparation::Pending(mut retry) = state
            .prepare_filesystem_operation(&operation_id, &request)
            .expect("join filesystem operation")
        else {
            panic!("concurrent retry must join the filesystem operation");
        };

        let target = ContainerTarget::exact(
            ContainerId::new("guest-pending-mkdir").expect("container ID"),
            Generation(1),
        );
        let result = FilesystemResponse {
            target,
            entry: None,
            entries: Vec::new(),
        };
        state
            .complete_filesystem_operation(
                operation_id.clone(),
                request.clone(),
                Ok(result.clone()),
            )
            .expect("complete exact filesystem operation");
        owner.changed().await.expect("owner result notification");
        retry.changed().await.expect("retry result notification");
        assert_eq!(owner.borrow().clone(), Some(Ok(result.clone())));
        assert_eq!(retry.borrow().clone(), Some(Ok(result)));
        assert!(matches!(
            state
                .prepare_filesystem_operation(&operation_id, &request)
                .expect("replay filesystem operation"),
            FilesystemOperationPreparation::Completed(result) if result.is_ok()
        ));
    }

    #[test]
    fn pending_operation_ids_are_reserved_across_all_operation_kinds() {
        let operation_id = OperationId::new("guest-pending-cross-kind").expect("operation ID");
        let file_request = RecordedRequest::new(
            MutationKind::File,
            &json!({"path": "/tmp/state", "data": "YQ=="}),
        )
        .expect("file fingerprint");
        let filesystem_request = RecordedRequest::new(
            MutationKind::Filesystem,
            &json!({"path": "/tmp/state", "op": "remove"}),
        )
        .expect("filesystem fingerprint");
        let mut state = ExecutorState::default();
        assert!(matches!(
            state
                .prepare_file_operation(&operation_id, &file_request)
                .expect("claim file operation"),
            FileOperationPreparation::Claimed(_)
        ));
        assert_eq!(
            state
                .prepare_filesystem_operation(&operation_id, &filesystem_request)
                .expect_err("cross-kind pending reuse must fail")
                .code,
            ErrorCode::Conflict
        );
    }

    #[test]
    fn durable_host_acknowledgement_releases_completed_journal_capacity() {
        let request = RecordedRequest::new(
            MutationKind::WriteStdin,
            &json!({"target": "init", "data": "bounded"}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();
        let mut completed = Vec::with_capacity(super::super::MAX_OPERATION_RECORDS);
        for index in 0..super::super::MAX_OPERATION_RECORDS {
            let operation_id =
                OperationId::new(format!("completed-{index}")).expect("operation ID");
            state
                .reserve_operation(&operation_id)
                .expect("journal capacity before its bound");
            state.record(
                operation_id.clone(),
                request.clone(),
                RecordedOutcome::Unit(Ok(())),
            );
            completed.push(operation_id);
        }
        let next = OperationId::new("after-capacity").expect("next operation ID");
        assert_eq!(
            state
                .reserve_operation(&next)
                .expect_err("full journal must fail closed")
                .code,
            ErrorCode::ResourceExhausted
        );

        state
            .acknowledge_operations(&completed)
            .expect("acknowledge durably committed host operations");

        assert!(state.operations.is_empty());
        assert_eq!(state.replay_unit(&completed[0], &request), None);
        state
            .reserve_operation(&next)
            .expect("acknowledgement must restore capacity");
    }

    #[test]
    fn acknowledgement_is_atomic_when_one_operation_is_still_pending() {
        let completed_id = OperationId::new("completed-operation").expect("completed ID");
        let pending_id = OperationId::new("pending-operation").expect("pending ID");
        let request = RecordedRequest::new(
            MutationKind::WriteStdin,
            &json!({"target": "init", "data": "bounded"}),
        )
        .expect("fingerprint request");
        let mut state = ExecutorState::default();
        state.record(
            completed_id.clone(),
            request.clone(),
            RecordedOutcome::Unit(Ok(())),
        );
        assert!(matches!(
            state
                .prepare_unit_operation(&pending_id, &request)
                .expect("claim pending operation"),
            UnitOperationPreparation::Claimed(_)
        ));

        let error = state
            .acknowledge_operations(&[completed_id.clone(), pending_id])
            .expect_err("pending operation acknowledgement must fail");

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            state.replay_unit(&completed_id, &request),
            Some(Ok(())),
            "a rejected batch must not partially release completed records"
        );
    }

    #[test]
    fn create_fingerprint_includes_only_the_stable_descriptor_schema() {
        let request = json!({"target": "container-1"});
        let first_schema = AgentInheritedDescriptorSchema::a3s_box_control_v1();
        let reopened_equivalent = AgentInheritedDescriptorSchema::a3s_box_control_v1();
        let first = RecordedRequest::create(&request, Some(&first_schema))
            .expect("fingerprint descriptor create");
        let retry = RecordedRequest::create(&request, Some(&reopened_equivalent))
            .expect("fingerprint equivalent descriptor create");
        let without_descriptors =
            RecordedRequest::create(&request, None).expect("fingerprint ordinary create");
        assert_eq!(first, retry);
        assert_ne!(first, without_descriptors);

        let mut changed_schema = reopened_equivalent;
        changed_schema.slots[0].target = 6;
        let changed = RecordedRequest::create(&request, Some(&changed_schema))
            .expect("fingerprint changed descriptor schema");
        assert_ne!(first, changed);
    }
}
