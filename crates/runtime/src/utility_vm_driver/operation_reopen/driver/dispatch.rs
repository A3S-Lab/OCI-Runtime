use std::sync::atomic::Ordering;

use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, ErrorCode, ExitStatus, OutputChunk, ProcessRecord, Result,
};

use super::{qualification_error, QualificationKvmOperationDriver};
use crate::driver::{
    DriverContainerOperationRequest, DriverCreateRequest, DriverDeleteRequest, DriverExecRequest,
    DriverKillRequest, DriverProcess, DriverReadOutputRequest, DriverSignalProcessRequest,
    DriverStartRequest, DriverState, DriverUpdateRequest, DriverWaitProcessRequest,
    DriverWaitRequest,
};

impl QualificationKvmOperationDriver {
    pub(super) async fn dispatch_create(
        &self,
        request: DriverCreateRequest,
    ) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.create_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM create identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Create identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        let active = self.ensure_session(&request).await?;
        let guest_bundle = self
            .handoff
            .guest_bundle_path(
                &request.target,
                request.bundle.directory(),
                request.attachment_contract.guest_session(),
            )
            .await?;
        active.client.create(request, guest_bundle).await
    }

    pub(super) async fn dispatch_start(&self, request: DriverStartRequest) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.start_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM start identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Start identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .start(request)
            .await
    }

    pub(super) async fn dispatch_kill(&self, request: DriverKillRequest) -> Result<DriverState> {
        let identity = (
            request.context.operation_id.clone(),
            request.target.clone(),
            request.signal,
            request.all,
        );
        {
            let mut retained = self.kill_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM kill identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Kill identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.kill_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .kill(request)
            .await
    }

    pub(super) async fn dispatch_delete(&self, request: DriverDeleteRequest) -> Result<()> {
        let identity = (
            request.context.operation_id.clone(),
            request.target.clone(),
            request.mode,
        );
        {
            let mut retained = self.delete_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM delete identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Delete identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .delete(request)
            .await
    }

    pub(super) async fn dispatch_wait(&self, request: DriverWaitRequest) -> Result<ExitStatus> {
        let identity = (request.target.clone(), request.timeout_ms);
        {
            let mut retained = self.wait_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM wait identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Wait identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.wait_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .wait(request)
            .await
    }

    pub(super) async fn dispatch_exec(&self, request: DriverExecRequest) -> Result<DriverProcess> {
        {
            let mut retained = self.exec_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM exec identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Exec request",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.exec_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target.container)
            .await?
            .client
            .exec(request)
            .await
    }

    pub(super) async fn dispatch_signal_process(
        &self,
        request: DriverSignalProcessRequest,
    ) -> Result<()> {
        {
            let mut retained = self.signal_process_identity.lock().map_err(|_| {
                qualification_error(
                    ErrorCode::Internal,
                    "KVM SignalProcess identity lock was poisoned",
                )
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed SignalProcess request",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.signal_process_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target.container)
            .await?
            .client
            .signal_process(request)
            .await
    }

    pub(super) async fn dispatch_wait_process(
        &self,
        request: DriverWaitProcessRequest,
    ) -> Result<ExitStatus> {
        let identity = (request.target.clone(), request.timeout_ms);
        {
            let mut retained = self.wait_process_identity.lock().map_err(|_| {
                qualification_error(
                    ErrorCode::Internal,
                    "KVM WaitProcess identity lock was poisoned",
                )
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed WaitProcess identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.wait_process_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target.container)
            .await?
            .client
            .wait_process(request)
            .await
    }

    pub(super) async fn dispatch_pause(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.pause_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM Pause identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Pause identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.pause_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .pause(request)
            .await
    }

    pub(super) async fn dispatch_resume(
        &self,
        request: DriverContainerOperationRequest,
    ) -> Result<DriverState> {
        let identity = (request.context.operation_id.clone(), request.target.clone());
        {
            let mut retained = self.resume_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM Resume identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &identity => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Resume identity",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(identity),
            }
        }
        self.resume_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .resume(request)
            .await
    }

    pub(super) async fn dispatch_processes(
        &self,
        target: ContainerTarget,
    ) -> Result<Vec<ProcessRecord>> {
        {
            let mut retained = self.processes_identity.lock().map_err(|_| {
                qualification_error(
                    ErrorCode::Internal,
                    "KVM Processes identity lock was poisoned",
                )
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &target => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Processes target",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(target.clone()),
            }
        }
        self.processes_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&target)
            .await?
            .client
            .processes(target)
            .await
    }

    pub(super) async fn dispatch_update(
        &self,
        request: DriverUpdateRequest,
    ) -> Result<DriverState> {
        {
            let mut retained = self.update_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM Update identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Update request",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.update_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target)
            .await?
            .client
            .update(request)
            .await
    }

    pub(super) async fn dispatch_stats(&self, target: ContainerTarget) -> Result<ContainerStats> {
        {
            let mut retained = self.stats_identity.lock().map_err(|_| {
                qualification_error(ErrorCode::Internal, "KVM Stats identity lock was poisoned")
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &target => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed Stats target",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(target.clone()),
            }
        }
        self.stats_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&target).await?.client.stats(target).await
    }

    pub(super) async fn dispatch_read_output(
        &self,
        request: DriverReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        {
            let mut retained = self.read_output_identity.lock().map_err(|_| {
                qualification_error(
                    ErrorCode::Internal,
                    "KVM ReadOutput identity lock was poisoned",
                )
            })?;
            match retained.as_ref() {
                Some(existing) if existing != &request => {
                    return Err(qualification_error(
                        ErrorCode::Conflict,
                        "qualification KVM owner received a changed ReadOutput request",
                    ));
                }
                Some(_) => {}
                None => *retained = Some(request.clone()),
            }
        }
        self.read_output_calls.fetch_add(1, Ordering::SeqCst);
        self.live_session(&request.target.container)
            .await?
            .client
            .read_output(request)
            .await
    }
}
