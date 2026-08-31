use std::sync::atomic::Ordering;

use a3s_oci_core::{DriverKind, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, ErrorCode, OciBundle, ProcessRecord, ProcessTarget, Result,
};

use super::{qualification_error, QualificationKvmOperationDriver};
use crate::driver::{
    DriverCloseStdinRequest, DriverContainerOperationRequest, DriverCreateAttachments,
    DriverCreateRequest, DriverExecRequest, DriverKillRequest, DriverSignalProcessRequest,
    DriverStartRequest, DriverUpdateRequest, DriverWriteStdinRequest,
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
        let recovery_rebuilds_paused_state =
            self.retained_pause.is_some() && self.retained_resume.is_none();
        if *record.state.status() == ContainerState::Running
            && record.is_paused() != recovery_rebuilds_paused_state
        {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM freezer recovery history does not match the durable state",
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
            if self.retained_update.is_some() {
                let (marker, expected) =
                    self.retained_update_ready_marker.as_ref().ok_or_else(|| {
                        qualification_error(
                            ErrorCode::FailedPrecondition,
                            "KVM Update recovery has no init readiness marker",
                        )
                    })?;
                super::super::exec::wait_for_exact_marker(
                    marker,
                    expected,
                    "replacement KVM Update init readiness",
                )
                .await
                .map_err(|reason| qualification_error(ErrorCode::FailedPrecondition, reason))?;
                let updated = self
                    .dispatch_update(self.recovery_update_request(record)?)
                    .await?;
                if updated.status() != ContainerState::Running
                    || updated.paused()
                    || updated.pid() != Some(running_pid)
                {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        format!(
                            "replacement KVM Guest rebuilt Update as {} with PID {:?} and paused={}; durable state requires unpaused running PID {running_pid}",
                            updated.status(),
                            updated.pid(),
                            updated.paused()
                        ),
                    ));
                }
                self.rehydrated_update.store(true, Ordering::SeqCst);
                return DriverRecovery::recreated_running(updated);
            }
            if self.retained_pause.is_some() {
                let (marker, expected) =
                    self.retained_pause_ready_marker.as_ref().ok_or_else(|| {
                        qualification_error(
                            ErrorCode::FailedPrecondition,
                            "KVM Pause recovery has no init readiness marker",
                        )
                    })?;
                super::super::exec::wait_for_exact_marker(
                    marker,
                    expected,
                    "replacement KVM Pause init readiness",
                )
                .await
                .map_err(|reason| qualification_error(ErrorCode::FailedPrecondition, reason))?;
                let paused = self
                    .dispatch_pause(self.recovery_pause_request(record)?)
                    .await?;
                if paused.status() != ContainerState::Running
                    || !paused.paused()
                    || paused.pid() != Some(running_pid)
                {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        format!(
                            "replacement KVM Guest rebuilt Pause as {} with PID {:?} and paused={}; durable state requires paused running PID {running_pid}",
                            paused.status(),
                            paused.pid(),
                            paused.paused()
                        ),
                    ));
                }
                self.rehydrated_paused_record.store(true, Ordering::SeqCst);
                if self.retained_resume.is_some() {
                    let resumed = self
                        .dispatch_resume(self.recovery_resume_request(record)?)
                        .await?;
                    if resumed.status() != ContainerState::Running
                        || resumed.paused()
                        || resumed.pid() != Some(running_pid)
                    {
                        return Err(qualification_error(
                            ErrorCode::Conflict,
                            format!(
                                "replacement KVM Guest rebuilt Resume as {} with PID {:?} and paused={}; durable state requires unpaused running PID {running_pid}",
                                resumed.status(),
                                resumed.pid(),
                                resumed.paused()
                            ),
                        ));
                    }
                    self.rehydrated_resumed_record.store(true, Ordering::SeqCst);
                    return DriverRecovery::recreated_running(resumed);
                }
                return DriverRecovery::recreated_paused_running(paused);
            }
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
                if self.retained_signal_process.is_some() {
                    let (marker, expected) =
                        self.retained_signal_ready_marker.as_ref().ok_or_else(|| {
                            qualification_error(
                                ErrorCode::FailedPrecondition,
                                "KVM SignalProcess recovery has no Exec readiness marker",
                            )
                        })?;
                    super::super::exec::wait_for_exact_marker(
                        marker,
                        expected,
                        "replacement KVM signalable Exec readiness",
                    )
                    .await
                    .map_err(|reason| qualification_error(ErrorCode::FailedPrecondition, reason))?;
                    let request = self.recovery_signal_process_request(record)?;
                    self.dispatch_signal_process(request).await?;
                    self.rehydrated_signal_process.store(true, Ordering::SeqCst);
                }
                if self.retained_write_stdin.is_some() {
                    let (marker, expected) =
                        self.retained_write_ready_marker.as_ref().ok_or_else(|| {
                            qualification_error(
                                ErrorCode::FailedPrecondition,
                                "KVM WriteStdin recovery has no Exec readiness marker",
                            )
                        })?;
                    super::super::exec::wait_for_exact_marker(
                        marker,
                        expected,
                        "replacement KVM stdin Exec readiness",
                    )
                    .await
                    .map_err(|reason| qualification_error(ErrorCode::FailedPrecondition, reason))?;
                    let request = self.recovery_write_stdin_request(record)?;
                    self.dispatch_write_stdin(request).await?;
                    self.rehydrated_write_stdin.store(true, Ordering::SeqCst);
                }
                if self.retained_close_stdin.is_some() {
                    let (marker, expected) =
                        self.retained_close_ready_marker.as_ref().ok_or_else(|| {
                            qualification_error(
                                ErrorCode::FailedPrecondition,
                                "KVM CloseStdin recovery has no Exec readiness marker",
                            )
                        })?;
                    super::super::exec::wait_for_exact_marker(
                        marker,
                        expected,
                        "replacement KVM stdin-close Exec readiness",
                    )
                    .await
                    .map_err(|reason| qualification_error(ErrorCode::FailedPrecondition, reason))?;
                    let request = self.recovery_close_stdin_request(record)?;
                    self.dispatch_close_stdin(request).await?;
                    self.rehydrated_close_stdin.store(true, Ordering::SeqCst);
                }
                if self.recovery_exec_is_live {
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

    fn recovery_signal_process_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverSignalProcessRequest> {
        let request = self.retained_signal_process.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained SignalProcess request",
            )
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .retained_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                qualification_error(
                    ErrorCode::FailedPrecondition,
                    "KVM SignalProcess recovery has no retained Exec request",
                )
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.retained_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery SignalProcess target differs from the durable Exec process",
            ));
        }
        Ok(DriverSignalProcessRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
            signal: request.signal,
        })
    }

    fn recovery_write_stdin_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverWriteStdinRequest> {
        let request = self.retained_write_stdin.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained WriteStdin request",
            )
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .retained_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                qualification_error(
                    ErrorCode::FailedPrecondition,
                    "KVM WriteStdin recovery has no retained Exec request",
                )
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.retained_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery WriteStdin target differs from the durable Exec process",
            ));
        }
        Ok(DriverWriteStdinRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
            data: request.data.clone(),
        })
    }

    fn recovery_close_stdin_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverCloseStdinRequest> {
        let request = self.retained_close_stdin.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained CloseStdin request",
            )
        })?;
        let exact_container =
            ContainerTarget::exact(request.process.container.id.clone(), record.generation);
        let expected_process_id = self
            .retained_exec
            .as_ref()
            .map(|exec| &exec.process_id)
            .ok_or_else(|| {
                qualification_error(
                    ErrorCode::FailedPrecondition,
                    "KVM CloseStdin recovery has no retained Exec request",
                )
            })?;
        if request.process.container != exact_container
            || request.process.container.id != self.retained_create.id
            || &request.process.process_id != expected_process_id
        {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery CloseStdin target differs from the durable Exec process",
            ));
        }
        Ok(DriverCloseStdinRequest {
            context: request.context.clone(),
            target: ProcessTarget {
                container: exact_container,
                process_id: request.process.process_id.clone(),
            },
        })
    }

    fn recovery_pause_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverContainerOperationRequest> {
        let request = self.retained_pause.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained Pause request",
            )
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.retained_create.id {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery Pause target differs from the durable record",
            ));
        }
        Ok(DriverContainerOperationRequest {
            context: request.context.clone(),
            target: exact_target,
        })
    }

    fn recovery_resume_request(
        &self,
        record: &ContainerRecord,
    ) -> Result<DriverContainerOperationRequest> {
        let request = self.retained_resume.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained Resume request",
            )
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.retained_create.id {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery Resume target differs from the durable record",
            ));
        }
        Ok(DriverContainerOperationRequest {
            context: request.context.clone(),
            target: exact_target,
        })
    }

    fn recovery_update_request(&self, record: &ContainerRecord) -> Result<DriverUpdateRequest> {
        let request = self.retained_update.as_ref().ok_or_else(|| {
            qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM replacement has no retained Update request",
            )
        })?;
        let exact_target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        if request.target != exact_target || request.target.id != self.retained_create.id {
            return Err(qualification_error(
                ErrorCode::FailedPrecondition,
                "qualification KVM recovery Update target differs from the durable record",
            ));
        }
        Ok(DriverUpdateRequest {
            context: request.context.clone(),
            target: exact_target,
            resources: request.resources.clone(),
        })
    }
}
