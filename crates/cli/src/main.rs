use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use a3s_oci_sdk::RuntimeClient;
use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use thiserror::Error;

#[cfg(target_os = "linux")]
mod native_service;

#[derive(Debug, Parser)]
#[command(name = "a3s-oci", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print machine-readable runtime driver capabilities.
    Features,
    /// Query WHPX and create then delete one partition object.
    WhpxSmoke,
    /// Create then destroy one real Hypervisor.framework VM object.
    HvfSmoke,
    /// Run the experimental native Linux core lifecycle through the Rust SDK.
    NativeLinuxSmoke {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing directory beneath which isolated smoke state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
    },
    /// Prove helper-backed native Linux execution as an unprivileged user.
    NativeLinuxRootlessSmoke {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// Rootless OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing user-owned directory beneath which smoke state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
    },
    /// Serve multiple native Linux containers through one durable SDK owner.
    #[cfg(target_os = "linux")]
    NativeLinuxHostService {
        /// Private absolute root containing runtime.sock, state, and executor data.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Absolute matching a3s-oci-agent executable used for prepared init.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
    },
    /// Own one A3S Box container through the native Linux SDK service.
    #[cfg(target_os = "linux")]
    NativeLinuxService {
        /// Private absolute root containing runtime.sock, state, and executor data.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Absolute matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// Exact A3S Box container identity allowed to consume the inherited descriptors.
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        /// Require A3S Box exec, PTY, and init-log handles on descriptors 3, 4, and 5.
        #[arg(long, action = clap::ArgAction::SetTrue, required = true)]
        a3s_box_control_fds: bool,
    },
    /// Prove the complete native lifecycle over the packaged Unix SDK service.
    NativeLinuxServiceSmoke {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing directory beneath which isolated service state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
    },
    /// Prove two native Linux containers remain independently fenced.
    NativeLinuxMultiContainerSmoke {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// First OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle_b: PathBuf,
        /// Existing directory beneath which isolated smoke state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
    },
    /// Run repeated concurrent native Linux lifecycle and leak checks.
    NativeLinuxSoak {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// Distinct writable OCI bundle; repeat once per available soak slot.
        #[arg(long = "bundle", value_name = "DIR", required = true)]
        bundles: Vec<PathBuf>,
        /// Existing directory beneath which isolated soak state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Number of complete concurrent create-to-delete waves.
        #[arg(long, default_value_t = 25)]
        iterations: u32,
        /// Number of supplied bundles kept live during every wave.
        #[arg(long, default_value_t = 2)]
        concurrent_containers: u32,
        /// Independent outer deadline for each SDK operation.
        #[arg(long, default_value_t = 15_000)]
        operation_timeout_ms: u64,
    },
    /// Interrupt native Linux lifecycle and prove cleanup without OCI delete.
    NativeLinuxFaultCleanup {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing directory beneath which isolated diagnostic state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Successful lifecycle boundary after which normal flow is interrupted.
        #[arg(long, value_enum)]
        fault_after: FaultPointArg,
    },
    /// Boot and authenticate the Linux agent at its fixed guest path.
    AgentVmSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Run a fixed OCI core lifecycle inside one utility VM.
    OciVmSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// OCI bundle contained by the VM root filesystem.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Run one exact lifecycle through the qualification-only WHPX driver.
    WhpxDriverSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Protected runtime root containing system, shares, console, and recovery.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Extracted Linux system root containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// OCI bundle below `shares/<container>/<generation>`.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact path-safe container identity used by the candidate driver.
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        /// Exact container generation represented by the share.
        #[arg(long, default_value_t = 1)]
        generation: u64,
    },
    /// Hold one durable WHPX service alive for the owner-death qualification parent.
    #[command(hide = true)]
    WhpxRecoveryOwner {
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        #[arg(long, value_name = "DIR")]
        state_root: PathBuf,
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        #[arg(long, value_name = "FILE")]
        ready_file: PathBuf,
    },
    /// Reopen a killed WHPX owner and emit exact recovery qualification evidence.
    #[command(hide = true)]
    WhpxRecoveryResume {
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        #[arg(long, value_name = "DIR")]
        state_root: PathBuf,
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        #[arg(long)]
        generation: u64,
    },
    /// Prove two containers remain independently fenced inside one utility VM.
    OciVmMultiContainerSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// First OCI bundle contained by the VM root filesystem.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct OCI bundle contained by the VM root filesystem.
        #[arg(long, value_name = "DIR")]
        bundle_b: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Run repeated macOS HVF utility-VM lifecycle and leak checks.
    MacosHvfSoak {
        /// Isolated, entitlement-signed libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// First OCI bundle contained by the VM root filesystem.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct OCI bundle contained by the VM root filesystem.
        #[arg(long, value_name = "DIR")]
        bundle_b: PathBuf,
        /// Existing empty directory that receives one console per VM wave.
        #[arg(long, value_name = "DIR")]
        console_dir: PathBuf,
        /// Number of complete utility-VM waves.
        #[arg(long, default_value_t = 25)]
        iterations: u32,
    },
    /// Prove lifecycle isolation for two containers in the Windows WHPX bootstrap profile.
    WindowsOciVmMultiContainerSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// First Windows-profile OCI bundle contained by the VM rootfs.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct Windows-profile OCI bundle contained by the VM rootfs.
        #[arg(long, value_name = "DIR")]
        bundle_b: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Interrupt a utility-VM lifecycle and prove cleanup without OCI delete.
    OciVmFaultCleanup {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// OCI bundle contained by the VM root filesystem.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        /// Successful lifecycle boundary after which normal flow is interrupted.
        #[arg(long, value_enum)]
        fault_after: FaultPointArg,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FaultPointArg {
    #[value(name = "after-create")]
    Create,
    #[value(name = "after-start")]
    Start,
    #[value(name = "after-kill")]
    Kill,
}

impl From<FaultPointArg> for a3s_oci_runtime::LifecycleFaultPoint {
    fn from(value: FaultPointArg) -> Self {
        match value {
            FaultPointArg::Create => Self::AfterCreate,
            FaultPointArg::Start => Self::AfterStart,
            FaultPointArg::Kill => Self::AfterKill,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("runtime request failed: {0}")]
    Runtime(#[from] a3s_oci_sdk::Error),
    #[error("failed to serialize command output: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("a3s-oci: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Command::Features => {
            let client = RuntimeClient::new(a3s_oci_runtime::HostRuntimeService::new());
            let info = client.features().await?;
            write_json(&info.drivers)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::WhpxSmoke => {
            let report = a3s_oci_runtime::whpx_smoke();
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::HvfSmoke => {
            let report = a3s_oci_runtime::hvf_smoke();
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::NativeLinuxSmoke {
            agent,
            bundle,
            work_parent,
        } => {
            let report = a3s_oci_runtime::native_linux_smoke(&agent, &bundle, &work_parent).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::NativeLinuxRootlessSmoke {
            agent,
            bundle,
            work_parent,
        } => {
            let report =
                a3s_oci_runtime::native_linux_rootless_smoke(&agent, &bundle, &work_parent).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        #[cfg(target_os = "linux")]
        Command::NativeLinuxHostService { root, agent } => {
            native_service::run_host(root, agent).await?;
            Ok(ExitCode::SUCCESS)
        }
        #[cfg(target_os = "linux")]
        Command::NativeLinuxService {
            root,
            agent,
            container_id,
            a3s_box_control_fds: _,
        } => {
            native_service::run(root, agent, container_id).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::NativeLinuxServiceSmoke {
            agent,
            bundle,
            work_parent,
        } => {
            let report =
                a3s_oci_runtime::native_linux_service_smoke(&agent, &bundle, &work_parent).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::NativeLinuxMultiContainerSmoke {
            agent,
            bundle_a,
            bundle_b,
            work_parent,
        } => {
            let report = a3s_oci_runtime::native_linux_multi_container_smoke(
                &agent,
                &bundle_a,
                &bundle_b,
                &work_parent,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::NativeLinuxSoak {
            agent,
            bundles,
            work_parent,
            iterations,
            concurrent_containers,
            operation_timeout_ms,
        } => {
            let report = a3s_oci_runtime::native_linux_soak(
                &agent,
                &bundles,
                &work_parent,
                a3s_oci_runtime::NativeLinuxSoakConfig::new(
                    iterations,
                    concurrent_containers,
                    operation_timeout_ms,
                ),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::NativeLinuxFaultCleanup {
            agent,
            bundle,
            work_parent,
            fault_after,
        } => {
            let report = a3s_oci_runtime::native_linux_fault_cleanup(
                &agent,
                &bundle,
                &work_parent,
                fault_after.into(),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::AgentVmSmoke {
            shim,
            rootfs,
            console,
        } => {
            let report = a3s_oci_runtime::agent_vm_smoke(&shim, &rootfs, &console).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::OciVmSmoke {
            shim,
            vm_rootfs,
            bundle,
            console,
        } => {
            let report = a3s_oci_runtime::oci_vm_smoke(&shim, &vm_rootfs, &bundle, &console).await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::WhpxDriverSmoke {
            shim,
            runtime_root,
            vm_rootfs,
            bundle,
            container_id,
            generation,
        } => {
            let target = a3s_oci_sdk::ContainerTarget::exact(
                container_id,
                a3s_oci_sdk::Generation(generation),
            );
            let report = a3s_oci_runtime::whpx_driver_smoke(
                &shim,
                &runtime_root,
                &vm_rootfs,
                &bundle,
                target,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::WhpxRecoveryOwner {
            shim,
            runtime_root,
            vm_rootfs,
            state_root,
            bundle,
            container_id,
            ready_file,
        } => {
            a3s_oci_runtime::whpx_recovery_owner(
                &shim,
                &runtime_root,
                &vm_rootfs,
                &state_root,
                &bundle,
                container_id,
                &ready_file,
            )
            .await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::WhpxRecoveryResume {
            shim,
            runtime_root,
            vm_rootfs,
            state_root,
            bundle,
            container_id,
            generation,
        } => {
            let target = a3s_oci_sdk::ContainerTarget::exact(
                container_id,
                a3s_oci_sdk::Generation(generation),
            );
            let report = a3s_oci_runtime::whpx_recovery_resume(
                &shim,
                &runtime_root,
                &vm_rootfs,
                &state_root,
                &bundle,
                target,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::OciVmMultiContainerSmoke {
            shim,
            vm_rootfs,
            bundle_a,
            bundle_b,
            console,
        } => {
            let report = a3s_oci_runtime::oci_vm_multi_container_smoke(
                &shim, &vm_rootfs, &bundle_a, &bundle_b, &console,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::MacosHvfSoak {
            shim,
            vm_rootfs,
            bundle_a,
            bundle_b,
            console_dir,
            iterations,
        } => {
            let report = a3s_oci_runtime::macos_hvf_soak(
                &shim,
                &vm_rootfs,
                &bundle_a,
                &bundle_b,
                &console_dir,
                a3s_oci_runtime::MacosHvfSoakConfig::new(iterations),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::WindowsOciVmMultiContainerSmoke {
            shim,
            vm_rootfs,
            bundle_a,
            bundle_b,
            console,
        } => {
            let report = a3s_oci_runtime::windows_oci_vm_multi_container_smoke(
                &shim, &vm_rootfs, &bundle_a, &bundle_b, &console,
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::OciVmFaultCleanup {
            shim,
            vm_rootfs,
            bundle,
            console,
            fault_after,
        } => {
            let report = a3s_oci_runtime::oci_vm_fault_cleanup(
                &shim,
                &vm_rootfs,
                &bundle,
                &console,
                fault_after.into(),
            )
            .await;
            let succeeded = report.is_success();
            write_json(&report)?;
            Ok(if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}

fn write_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    println!();
    Ok(())
}
