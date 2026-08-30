use std::sync::atomic::Ordering;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ErrorCode, OciBundle, ProcessRecord, ProcessTarget, Result,
};

use super::{qualification_error, QualificationKvmOperationDriver};
use crate::driver::{
    DriverCreateAttachments, DriverCreateRequest, DriverExecRequest, DriverKillRequest,
    DriverStartRequest,
};
use crate::DriverRecovery;

impl QualificationKvmOperationDriver {
    pub(in crate::utility_vm_driver::operation_reopen) async fn launch_replacement_owner_without_workload(
        &self,
        target: &ContainerTarget,
    ) -> Result<()> {
        if target.id != self.retained_create.id || target.generation.is_none() {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "completed KVM Delete replacement requires the retained exact-generation target",
            ));
        }
        if self
            .recovery
            .load_exit(target, self.retained_create.bundle.config_digest(), None)
            .await?
            .is_some()
        {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "completed KVM Delete recovery report retained a deleted workload",
            ));
        }
        self.recovery.remove(target, None).await?;
        let request = self.prepared_create_request(target.clone()).await?;
        self.ensure_session(&request).await?;
        Ok(())
    }

    pub(super) async fn recover_record(&self, record: &ContainerRecord) -> Result<DriverRecovery> {
        let recovery_state_supported = matches!(
            record.state.status(),
            ContainerState::Creating | ContainerState::Created
        ) || (*record.state.status() == ContainerState::Running
            && self.retained_start.is_some())
            || (*record.state.status() == ContainerState::Stopped
                && self.retained_start.is_some()
                && self.retained_kill.is_some()
                && self.recovery_marker.is_some());
        if !recovery_state_supported {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "KVM operation-reopen qualification accepts only its creating, created, retained running, or retained stopped durable state",
            ));
        }
        if self.recovery_calls.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "KVM operation-reopen qualification recovered more than one durable record",
            ));
        }
        let request = self.recovery_request(record).await?;
        let recovery_bundle = request.bundle.clone();
        self.recovery.recover(&request.target, record, None).await?;
        self.recovery.remove(&request.target, None).await?;
        if *record.state.status() == ContainerState::Creating {
            return Ok(DriverRecovery::none());
        }
        let observed = self.dispatch_create(request).await?;
        if observed.status() != ContainerState::Created {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "replacement KVM owner did not recreate OCI created state",
            ));
        }
        self.rehydrated_created_record.store(true, Ordering::SeqCst);
        if *record.state.status() == ContainerState::Created {
            return DriverRecovery::recreated_created(observed);
        }
        let running = self
            .dispatch_start(self.recovery_start_request(record, recovery_bundle)?)
            .await?;
        if running.status() != ContainerState::Running || running.paused() {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "replacement KVM owner did not recreate an active OCI running state",
            ));
        }
        let running_pid = running.pid().filter(|pid| *pid > 0).ok_or_else(|| {
            qualification_error(
                ErrorCode::Conflict,
                "replacement KVM owner recreated running state without a positive PID",
            )
        })?;
        self.rehydrated_running_pid
            .store(running_pid, Ordering::SeqCst);
        self.rehydrated_running_record.store(true, Ordering::SeqCst);
        if *record.state.status() == ContainerState::Running {
            if self.retained_exec.is_some() {
                let request = self.recovery_exec_request(record)?;
                let target = request.target.clone();
                let process = self.dispatch_exec(request).await?;
                let pid = process.pid();
                let durable_pid = u32::try_from(pid).map_err(|error| {
                    qualification_error(
                        ErrorCode::Conflict,
                        format!("replacement KVM Guest returned invalid Exec PID {pid}: {error}"),
                    )
                })?;
                self.rehydrated_exec_pid.store(pid, Ordering::SeqCst);
                self.rehydrated_exec_record.store(true, Ordering::SeqCst);
                return DriverRecovery::recreated_running_with_processes(
                    running,
                    vec![ProcessRecord {
                        target,
                        pid: Some(durable_pid),
                        terminal: process.terminal(),
                    }],
                );
            }
            return DriverRecovery::recreated_running(running);
        }

        let marker = self.recovery_marker.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "KVM stopped recovery has no workload marker",
            )
        })?;
        super::super::workload_marker::wait_for_replacement_marker(marker)
            .await
            .map_err(|reason| qualification_error(ErrorCode::FailedPrecondition, reason))?;
        let stopped = self
            .dispatch_kill(self.recovery_kill_request(record)?)
            .await?;
        if stopped.status() != ContainerState::Stopped || stopped.pid().is_some() {
            return Err(qualification_error(
                ErrorCode::Conflict,
                "replacement KVM owner did not recreate OCI stopped state",
            ));
        }
        self.rehydrated_stopped_record.store(true, Ordering::SeqCst);
        Ok(DriverRecovery::observed(stopped))
    }

    async fn recovery_request(&self, record: &ContainerRecord) -> Result<DriverCreateRequest> {
        let attachment_digest = self.retained_create.attachments.digest()?;
        if record.driver != DriverKind::LibkrunKvm
            || record.isolation != IsolationClass::DedicatedVm
            || record.state.id() != self.retained_create.id.as_str()
            || record.config_digest != self.retained_create.bundle.config_digest()
            || record.attachments_digest.as_deref() != Some(attachment_digest.as_str())
        {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "durable KVM Create record differs from the retained qualification request",
            ));
        }
        let target = ContainerTarget::exact(self.retained_create.id.clone(), record.generation);
        self.prepared_create_request(target).await
    }

    async fn prepared_create_request(
        &self,
        target: ContainerTarget,
    ) -> Result<DriverCreateRequest> {
        let mut request = DriverCreateRequest {
            context: self.retained_create.context.clone(),
            target,
            bundle: self.retained_create.bundle.clone(),
            isolation: self.retained_create.isolation.clone(),
            io: self.retained_create.attachments.process_io().clone(),
            attachment_contract: self.retained_create.attachments.clone(),
            tee_launch: None,
            attachments: DriverCreateAttachments::None,
        };
        request.bundle = self.handoff.prepare(&request).await?;
        Ok(request)
    }

    fn recovery_start_request(
        &self,
        record: &ContainerRecord,
        bundle: OciBundle,
    ) -> Result<DriverStartRequest> {
        let request = self.retained_start.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained Start request",
            )
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.retained_create.id {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery Start target differs from the durable record",
            ));
        }
        Ok(DriverStartRequest {
            context: request.context.clone(),
            target: exact_target,
            bundle,
        })
    }

    fn recovery_kill_request(&self, record: &ContainerRecord) -> Result<DriverKillRequest> {
        let request = self.retained_kill.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained Kill request",
            )
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.retained_create.id {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery Kill target differs from the durable record",
            ));
        }
        Ok(DriverKillRequest {
            context: request.context.clone(),
            target: exact_target,
            signal: request.signal,
            all: request.all,
        })
    }

    fn recovery_exec_request(&self, record: &ContainerRecord) -> Result<DriverExecRequest> {
        let request = self.retained_exec.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained Exec request",
            )
        })?;
        let exact_container =
            ContainerTarget::exact(request.container.id.clone(), record.generation);
        if request.container != exact_container || request.container.id != self.retained_create.id {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery Exec target differs from the durable record",
            ));
        }
        Ok(DriverExecRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process_id.clone(),
            },
            process: request.process.clone(),
            io: request.io.clone(),
        })
    }
}
