use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use a3s_oci_sdk::RuntimeClient;
use clap::{Parser, Subcommand};
use serde::Serialize;
use thiserror::Error;

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
    /// Run a fixed OCI create/start lifecycle inside one WHPX utility VM.
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
    }
}

fn write_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    println!();
    Ok(())
}
