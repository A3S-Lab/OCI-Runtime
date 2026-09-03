use a3s_oci_agent_protocol::{
    AgentCloseStdinRequest, AgentContainerOperationRequest, AgentExecRequest, AgentProcess,
    AgentProcessesRequest, AgentReadOutputRequest, AgentResizeRequest, AgentSignalProcessRequest,
    AgentStatsRequest, AgentUpdateRequest, AgentWaitProcessRequest, AgentWaitRequest,
    AgentWriteStdinRequest,
};
use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, ErrorCode, ExitStatus, FileRequest, FileResponse,
    FilesystemRequest, FilesystemResponse, OutputChunk, ProcessRecord, Result,
};

use super::{qualification_error, ActiveSession, QualificationKvmOperationDriver};

impl QualificationKvmOperationDriver {
    pub(super) async fn live_session(&self, target: &ContainerTarget) -> Result<ActiveSession> {
        self.session
            .lock()
            .await
            .as_ref()
            .filter(|active| &active.target == target)
            .cloned()
            .ok_or_else(|| {
                qualification_error(
                    ErrorCode::NotFound,
                    "qualification KVM owner has no live exact-generation session",
                )
            })
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_wait(
        &self,
        request: AgentWaitRequest,
    ) -> Result<ExitStatus> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .wait(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_exec(
        &self,
        request: AgentExecRequest,
    ) -> Result<AgentProcess> {
        self.live_session(&request.target.container)
            .await?
            .owner
            .client()
            .exec(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_signal_process(
        &self,
        request: AgentSignalProcessRequest,
    ) -> Result<()> {
        self.live_session(&request.target.container)
            .await?
            .owner
            .client()
            .signal_process(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_wait_process(
        &self,
        request: AgentWaitProcessRequest,
    ) -> Result<ExitStatus> {
        self.live_session(&request.target.container)
            .await?
            .owner
            .client()
            .wait_process(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_pause(
        &self,
        request: AgentContainerOperationRequest,
    ) -> Result<a3s_oci_agent_protocol::AgentState> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .pause(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_resume(
        &self,
        request: AgentContainerOperationRequest,
    ) -> Result<a3s_oci_agent_protocol::AgentState> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .resume(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_processes(
        &self,
        request: AgentProcessesRequest,
    ) -> Result<Vec<ProcessRecord>> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .processes(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_update(
        &self,
        request: AgentUpdateRequest,
    ) -> Result<a3s_oci_agent_protocol::AgentState> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .update(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_stats(
        &self,
        request: AgentStatsRequest,
    ) -> Result<ContainerStats> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .stats(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_read_output(
        &self,
        request: AgentReadOutputRequest,
    ) -> Result<Vec<OutputChunk>> {
        self.live_session(&request.process.container)
            .await?
            .owner
            .client()
            .read_output(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_write_stdin(
        &self,
        request: AgentWriteStdinRequest,
    ) -> Result<()> {
        self.live_session(&request.process.container)
            .await?
            .owner
            .client()
            .write_stdin(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_close_stdin(
        &self,
        request: AgentCloseStdinRequest,
    ) -> Result<()> {
        self.live_session(&request.process.container)
            .await?
            .owner
            .client()
            .close_stdin(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_resize(
        &self,
        request: AgentResizeRequest,
    ) -> Result<()> {
        self.live_session(&request.process.container)
            .await?
            .owner
            .client()
            .resize(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_file(
        &self,
        request: FileRequest,
    ) -> Result<FileResponse> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .file(request)
            .await
    }

    pub(in crate::utility_vm_driver::operation_reopen) async fn guest_filesystem(
        &self,
        request: FilesystemRequest,
    ) -> Result<FilesystemResponse> {
        self.live_session(&request.target)
            .await?
            .owner
            .client()
            .filesystem(request)
            .await
    }
}
