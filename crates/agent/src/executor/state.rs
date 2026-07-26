use std::collections::BTreeMap;
use std::path::PathBuf;

use a3s_oci_agent_protocol::{AgentInheritedDescriptorSchema, AgentProcess, AgentState};
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, LinuxResources};
use a3s_oci_sdk::{
    ContainerStats, ErrorCode, ExitStatus, OperationId, ProcessId, ProcessRecord, ProcessTarget,
    Result,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::cgroup::CgroupManager;
use super::exec_process::ExecProcess;
use super::process::PreparedProcess;
use super::{executor_error, MAX_OPERATION_RECORDS};

#[derive(Debug, Default)]
pub(super) struct ExecutorState {
    pub(super) containers: BTreeMap<ContainerKey, ContainerRecord>,
    pub(super) highest_generations: BTreeMap<String, u64>,
    operations: BTreeMap<OperationId, OperationRecord>,
    pub(super) next_slot: u64,
    pub(super) cgroup_manager: Option<CgroupManager>,
}

impl ExecutorState {
    pub(super) fn reserve_operation(&self, operation_id: &OperationId) -> Result<()> {
        if self.operations.len() >= MAX_OPERATION_RECORDS {
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

    pub(super) fn replay_state(
        &self,
        operation_id: &OperationId,
        request: &RecordedRequest,
    ) -> Option<Result<AgentState>> {
        self.operations.get(operation_id).map(|record| {
            record.validate_request(request)?;
            match &record.outcome {
                RecordedOutcome::State(result) => result.clone(),
                RecordedOutcome::Unit(_) | RecordedOutcome::Process(_) => {
                    Err(reused_operation(operation_id))
                }
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
                RecordedOutcome::State(_) | RecordedOutcome::Process(_) => {
                    Err(reused_operation(operation_id))
                }
            }
        })
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
                RecordedOutcome::State(_) | RecordedOutcome::Unit(_) => {
                    Err(reused_operation(operation_id))
                }
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordedRequest {
    kind: MutationKind,
    digest: [u8; 32],
}

impl RecordedRequest {
    pub(super) fn new(kind: MutationKind, request: &impl Serialize) -> Result<Self> {
        let encoded = serde_json::to_vec(request).map_err(|error| {
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
    use a3s_oci_agent_protocol::AgentInheritedDescriptorSchema;
    use a3s_oci_sdk::{ErrorCode, OperationId};
    use serde_json::json;

    use super::{ExecutorState, MutationKind, RecordedOutcome, RecordedRequest};

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
