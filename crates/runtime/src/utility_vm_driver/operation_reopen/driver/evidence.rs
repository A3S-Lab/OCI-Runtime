use std::sync::atomic::Ordering;

use a3s_oci_sdk::{ContainerTarget, DeleteMode, OperationId, ProcessTarget, Signal};

use super::QualificationKvmOperationDriver;
use crate::driver::{
    DriverCloseStdinRequest, DriverExecRequest, DriverReadOutputRequest, DriverResizeRequest,
    DriverSignalProcessRequest, DriverUpdateRequest, DriverWriteStdinRequest,
};

impl QualificationKvmOperationDriver {
    pub(in crate::utility_vm_driver::operation_reopen) fn create_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.create_identity
            .lock()
            .map_err(|_| "KVM create identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Create dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn start_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.start_identity
            .lock()
            .map_err(|_| "KVM start identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Start dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn start_calls(&self) -> u32 {
        self.start_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn kill_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget, Signal, bool), String> {
        self.kill_identity
            .lock()
            .map_err(|_| "KVM kill identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Kill dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn kill_calls(&self) -> u32 {
        self.kill_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn delete_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget, DeleteMode), String> {
        self.delete_identity
            .lock()
            .map_err(|_| "KVM delete identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Delete dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn delete_calls(&self) -> u32 {
        self.delete_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn wait_identity(
        &self,
    ) -> std::result::Result<(ContainerTarget, Option<u64>), String> {
        self.wait_identity
            .lock()
            .map_err(|_| "KVM wait identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Wait dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn wait_calls(&self) -> u32 {
        self.wait_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn wait_process_identity(
        &self,
    ) -> std::result::Result<(ProcessTarget, Option<u64>), String> {
        self.wait_process_identity
            .lock()
            .map_err(|_| "KVM WaitProcess identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no WaitProcess dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn wait_process_calls(&self) -> u32 {
        self.wait_process_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn exec_identity(
        &self,
    ) -> std::result::Result<DriverExecRequest, String> {
        self.exec_identity
            .lock()
            .map_err(|_| "KVM exec identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Exec dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn exec_calls(&self) -> u32 {
        self.exec_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn signal_process_identity(
        &self,
    ) -> std::result::Result<DriverSignalProcessRequest, String> {
        self.signal_process_identity
            .lock()
            .map_err(|_| "KVM SignalProcess identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no SignalProcess dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn signal_process_calls(&self) -> u32 {
        self.signal_process_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn pause_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.pause_identity
            .lock()
            .map_err(|_| "KVM Pause identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Pause dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn pause_calls(&self) -> u32 {
        self.pause_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn resume_identity(
        &self,
    ) -> std::result::Result<(OperationId, ContainerTarget), String> {
        self.resume_identity
            .lock()
            .map_err(|_| "KVM Resume identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Resume dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn resume_calls(&self) -> u32 {
        self.resume_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn processes_identity(
        &self,
    ) -> std::result::Result<ContainerTarget, String> {
        self.processes_identity
            .lock()
            .map_err(|_| "KVM Processes identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Processes dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn processes_calls(&self) -> u32 {
        self.processes_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn update_identity(
        &self,
    ) -> std::result::Result<DriverUpdateRequest, String> {
        self.update_identity
            .lock()
            .map_err(|_| "KVM Update identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Update dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn update_calls(&self) -> u32 {
        self.update_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn stats_identity(
        &self,
    ) -> std::result::Result<ContainerTarget, String> {
        self.stats_identity
            .lock()
            .map_err(|_| "KVM Stats identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Stats dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn stats_calls(&self) -> u32 {
        self.stats_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn read_output_identity(
        &self,
    ) -> std::result::Result<DriverReadOutputRequest, String> {
        self.read_output_identity
            .lock()
            .map_err(|_| "KVM ReadOutput identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no ReadOutput dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn read_output_calls(&self) -> u32 {
        self.read_output_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn write_stdin_identity(
        &self,
    ) -> std::result::Result<DriverWriteStdinRequest, String> {
        self.write_stdin_identity
            .lock()
            .map_err(|_| "KVM WriteStdin identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no WriteStdin dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn write_stdin_calls(&self) -> u32 {
        self.write_stdin_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn close_stdin_identity(
        &self,
    ) -> std::result::Result<DriverCloseStdinRequest, String> {
        self.close_stdin_identity
            .lock()
            .map_err(|_| "KVM CloseStdin identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no CloseStdin dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn close_stdin_calls(&self) -> u32 {
        self.close_stdin_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn resize_identity(
        &self,
    ) -> std::result::Result<DriverResizeRequest, String> {
        self.resize_identity
            .lock()
            .map_err(|_| "KVM Resize identity lock was poisoned".to_string())?
            .clone()
            .ok_or_else(|| "qualification KVM owner recorded no Resize dispatch".to_string())
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn resize_calls(&self) -> u32 {
        self.resize_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn recovery_calls(&self) -> u32 {
        self.recovery_calls.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_created_record(&self) -> bool {
        self.rehydrated_created_record.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_running_record(&self) -> bool {
        self.rehydrated_running_record.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_stopped_record(&self) -> bool {
        self.rehydrated_stopped_record.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_exec_record(&self) -> bool {
        self.rehydrated_exec_record.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_signal_process(&self) -> bool {
        self.rehydrated_signal_process.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_write_stdin(&self) -> bool {
        self.rehydrated_write_stdin.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_close_stdin(&self) -> bool {
        self.rehydrated_close_stdin.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_resize(&self) -> bool {
        self.rehydrated_resize.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_paused_record(&self) -> bool {
        self.rehydrated_paused_record.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_resumed_record(&self) -> bool {
        self.rehydrated_resumed_record.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_update(&self) -> bool {
        self.rehydrated_update.load(Ordering::SeqCst)
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_running_pid(
        &self,
    ) -> Option<i32> {
        match self.rehydrated_running_pid.load(Ordering::SeqCst) {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }

    pub(in crate::utility_vm_driver::operation_reopen) fn rehydrated_exec_pid(
        &self,
    ) -> Option<i32> {
        match self.rehydrated_exec_pid.load(Ordering::SeqCst) {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }
}
