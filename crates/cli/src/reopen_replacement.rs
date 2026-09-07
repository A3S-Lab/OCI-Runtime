use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args as ClapArgs, ValueEnum};

#[derive(Debug, ClapArgs)]
pub(crate) struct Args {
    /// Isolated, entitlement-signed libkrun shim executable.
    #[arg(long, value_name = "FILE")]
    shim: PathBuf,
    /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
    #[arg(long, value_name = "DIR")]
    vm_rootfs: PathBuf,
    /// Immutable system-image manifest bound to both macOS HVF owners.
    #[arg(long, value_name = "FILE")]
    system_image_manifest: PathBuf,
    /// OCI bundle contained by the VM root filesystem.
    #[arg(long, value_name = "DIR")]
    bundle: PathBuf,
    /// Existing directory for two console logs and isolated durable state.
    #[arg(long, value_name = "DIR")]
    console_dir: PathBuf,
    /// Durable operation to interrupt and reissue through the replacement owner.
    #[arg(long, value_enum, default_value = "create")]
    operation: OperationArg,
    /// Host- or Guest-side request/response transition to interrupt.
    #[arg(long, value_enum, default_value = "host-before-request-write")]
    fault_at: FaultStageArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OperationArg {
    Create,
    CloseStdin,
    Delete,
    Exec,
    File,
    Filesystem,
    Kill,
    Pause,
    Processes,
    ReadOutput,
    Resize,
    Resume,
    SignalProcess,
    State,
    Start,
    Stats,
    Update,
    Wait,
    WaitProcess,
    WriteStdin,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum FaultStageArg {
    #[value(name = "host-before-request-write")]
    BeforeRequestWrite,
    #[value(name = "host-after-request-write")]
    AfterRequestWrite,
    #[value(name = "host-before-response-read")]
    BeforeResponseRead,
    #[value(name = "host-after-response-read")]
    AfterResponseRead,
    #[value(name = "guest-after-request-read")]
    GuestAfterRequestRead,
    #[value(name = "guest-before-dispatch")]
    GuestBeforeDispatch,
    #[value(name = "guest-after-dispatch")]
    GuestAfterDispatch,
    #[value(name = "guest-before-response-write")]
    GuestBeforeResponseWrite,
    #[value(name = "guest-after-response-write")]
    GuestAfterResponseWrite,
    #[value(name = "host-before-shutdown")]
    HostBeforeShutdown,
    #[value(name = "host-after-shutdown")]
    HostAfterShutdown,
}

impl From<FaultStageArg> for a3s_oci_runtime::AgentTransportFaultStage {
    fn from(value: FaultStageArg) -> Self {
        match value {
            FaultStageArg::BeforeRequestWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostBeforeRequestWrite,
            ),
            FaultStageArg::AfterRequestWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostAfterRequestWrite,
            ),
            FaultStageArg::BeforeResponseRead => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostBeforeResponseRead,
            ),
            FaultStageArg::AfterResponseRead => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostAfterResponseRead,
            ),
            FaultStageArg::GuestAfterRequestRead => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::GuestAfterRequestRead,
            ),
            FaultStageArg::GuestBeforeDispatch => {
                Self::Operation(a3s_oci_runtime::AgentTransportOperationStage::GuestBeforeDispatch)
            }
            FaultStageArg::GuestAfterDispatch => {
                Self::Operation(a3s_oci_runtime::AgentTransportOperationStage::GuestAfterDispatch)
            }
            FaultStageArg::GuestBeforeResponseWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::GuestBeforeResponseWrite,
            ),
            FaultStageArg::GuestAfterResponseWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::GuestAfterResponseWrite,
            ),
            FaultStageArg::HostBeforeShutdown => {
                Self::Shutdown(a3s_oci_runtime::AgentTransportShutdownStage::HostBeforeShutdown)
            }
            FaultStageArg::HostAfterShutdown => {
                Self::Shutdown(a3s_oci_runtime::AgentTransportShutdownStage::HostAfterShutdown)
            }
        }
    }
}

impl TryFrom<FaultStageArg> for a3s_oci_runtime::AgentTransportOperationStage {
    type Error = String;

    fn try_from(value: FaultStageArg) -> Result<Self, Self::Error> {
        let fault_stage = a3s_oci_runtime::AgentTransportFaultStage::from(value);
        match fault_stage.operation() {
            Some(stage) => Ok(stage),
            None => Err(format!(
                "operation reopen does not accept Host-shutdown stage {}",
                fault_stage.as_str()
            )),
        }
    }
}

pub(crate) async fn run(arguments: Args) -> Result<ExitCode, super::CliError> {
    let succeeded = match arguments.operation {
        OperationArg::Create => {
            let fault_stage = a3s_oci_runtime::AgentTransportFaultStage::from(arguments.fault_at);
            let report = a3s_oci_runtime::oci_vm_reopen_replacement_at(
                &arguments.shim,
                &arguments.vm_rootfs,
                &arguments.system_image_manifest,
                &arguments.bundle,
                &arguments.console_dir,
                fault_stage,
            )
            .await;
            let succeeded = report.is_success();
            super::write_json(&report)?;
            succeeded
        }
        operation => {
            let stage = a3s_oci_runtime::AgentTransportOperationStage::try_from(arguments.fault_at)
                .map_err(super::CliError::Message)?;
            match operation {
                OperationArg::Create => unreachable!("Create handled above"),
                OperationArg::CloseStdin => {
                    let report = a3s_oci_runtime::oci_vm_close_stdin_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Delete => {
                    let report = a3s_oci_runtime::oci_vm_delete_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Exec => {
                    let report = a3s_oci_runtime::oci_vm_exec_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::File => {
                    let report = a3s_oci_runtime::oci_vm_file_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Filesystem => {
                    let report = a3s_oci_runtime::oci_vm_filesystem_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Kill => {
                    let report = a3s_oci_runtime::oci_vm_kill_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Pause => {
                    let report = a3s_oci_runtime::oci_vm_pause_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Processes => {
                    let report = a3s_oci_runtime::oci_vm_processes_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::ReadOutput => {
                    let report = a3s_oci_runtime::oci_vm_read_output_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Resize => {
                    let report = a3s_oci_runtime::oci_vm_resize_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Resume => {
                    let report = a3s_oci_runtime::oci_vm_resume_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::SignalProcess => {
                    let report = a3s_oci_runtime::oci_vm_signal_process_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::State => {
                    let report = a3s_oci_runtime::oci_vm_state_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Start => {
                    let report = a3s_oci_runtime::oci_vm_start_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Stats => {
                    let report = a3s_oci_runtime::oci_vm_stats_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Update => {
                    let report = a3s_oci_runtime::oci_vm_update_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::Wait => {
                    let report = a3s_oci_runtime::oci_vm_wait_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::WaitProcess => {
                    let report = a3s_oci_runtime::oci_vm_wait_process_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
                OperationArg::WriteStdin => {
                    let report = a3s_oci_runtime::oci_vm_write_stdin_reopen_replacement_at(
                        &arguments.shim,
                        &arguments.vm_rootfs,
                        &arguments.system_image_manifest,
                        &arguments.bundle,
                        &arguments.console_dir,
                        stage,
                    )
                    .await;
                    let succeeded = report.is_success();
                    super::write_json(&report)?;
                    succeeded
                }
            }
        }
    };
    Ok(if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}
