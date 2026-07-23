use std::io;
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
    }
}

fn write_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    println!();
    Ok(())
}
