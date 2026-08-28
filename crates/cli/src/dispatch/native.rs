use std::path::PathBuf;
use std::process::ExitCode;

use super::CommandFuture;
use crate::write_json;

pub(super) fn smoke(agent: PathBuf, bundle: PathBuf, work_parent: PathBuf) -> CommandFuture {
    Box::pin(async move {
        let report = a3s_oci_runtime::native_linux_smoke(&agent, &bundle, &work_parent).await;
        let succeeded = report.is_success();
        write_json(&report)?;
        Ok(success_exit(succeeded))
    })
}

pub(super) fn checkpoint(
    agent: PathBuf,
    criu: PathBuf,
    bundle: PathBuf,
    work_parent: PathBuf,
    source_revision: String,
) -> CommandFuture {
    Box::pin(async move {
        let report = a3s_oci_runtime::native_linux_checkpoint_smoke(
            &agent,
            &criu,
            &bundle,
            &work_parent,
            source_revision,
        )
        .await;
        let succeeded = report.is_success();
        write_json(&report)?;
        Ok(success_exit(succeeded))
    })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(super) fn checkpoint_restore_owner(
    agent: PathBuf,
    criu: PathBuf,
    state_root: PathBuf,
    executor_parent: PathBuf,
    request_file: PathBuf,
    ready_file: PathBuf,
    crash_point: crate::NativeLinuxCheckpointRestoreCrashPointArg,
) -> CommandFuture {
    Box::pin(async move {
        a3s_oci_runtime::native_linux_checkpoint_restore_owner(
            &agent,
            &criu,
            &state_root,
            &executor_parent,
            &request_file,
            &ready_file,
            crash_point.into(),
        )
        .await?;
        Ok(ExitCode::SUCCESS)
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn network_enforcement(
    agent: PathBuf,
    bundle: PathBuf,
    work_parent: PathBuf,
    source_interface: String,
    interface_id: String,
    cleanup_id: String,
    redirect_port: u16,
    rejected_port: u16,
) -> CommandFuture {
    Box::pin(async move {
        let configuration = a3s_oci_runtime::NativeLinuxNetworkEnforcementSmokeConfig::new(
            source_interface,
            a3s_oci_sdk::NetworkInterfaceId::new(interface_id)?,
            a3s_oci_sdk::NetworkCleanupId::new(cleanup_id)?,
            redirect_port,
            rejected_port,
        )?;
        let report = a3s_oci_runtime::native_linux_network_enforcement_smoke(
            &agent,
            &bundle,
            &work_parent,
            configuration,
        )
        .await;
        let succeeded = report.is_success();
        write_json(&report)?;
        Ok(success_exit(succeeded))
    })
}

fn success_exit(succeeded: bool) -> ExitCode {
    if succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}
