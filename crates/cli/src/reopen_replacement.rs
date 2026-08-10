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
    Delete,
    Kill,
    State,
    Start,
    Wait,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FaultStageArg {
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
}

impl From<FaultStageArg> for a3s_oci_runtime::AgentTransportOperationStage {
    fn from(value: FaultStageArg) -> Self {
        match value {
            FaultStageArg::BeforeRequestWrite => Self::HostBeforeRequestWrite,
            FaultStageArg::AfterRequestWrite => Self::HostAfterRequestWrite,
            FaultStageArg::BeforeResponseRead => Self::HostBeforeResponseRead,
            FaultStageArg::AfterResponseRead => Self::HostAfterResponseRead,
            FaultStageArg::GuestAfterRequestRead => Self::GuestAfterRequestRead,
            FaultStageArg::GuestBeforeDispatch => Self::GuestBeforeDispatch,
            FaultStageArg::GuestAfterDispatch => Self::GuestAfterDispatch,
            FaultStageArg::GuestBeforeResponseWrite => Self::GuestBeforeResponseWrite,
            FaultStageArg::GuestAfterResponseWrite => Self::GuestAfterResponseWrite,
        }
    }
}

pub(crate) async fn run(arguments: Args) -> Result<ExitCode, super::CliError> {
    let stage = arguments.fault_at.into();
    let succeeded = match arguments.operation {
        OperationArg::Create => {
            let report = a3s_oci_runtime::oci_vm_reopen_replacement_at(
                &arguments.shim,
                &arguments.vm_rootfs,
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
                &arguments.bundle,
                &arguments.console_dir,
                stage,
            )
            .await;
            let succeeded = report.is_success();
            super::write_json(&report)?;
            succeeded
        }
    };
    Ok(if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}
