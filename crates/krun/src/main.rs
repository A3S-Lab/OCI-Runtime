use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "a3s-oci-krun-shim", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create, configure, and release one libkrun context without booting a VM.
    ContextSmoke,
    /// Boot a utility VM and verify a command ran inside the supplied rootfs.
    VmSmoke {
        /// Extracted Linux root filesystem presented as the guest root.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// Host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::ContextSmoke => {
            let report = a3s_oci_krun::context_smoke();
            let succeeded = report.is_success();
            if let Err(error) = write_json(&report) {
                eprintln!("a3s-oci-krun-shim: failed to serialize report: {error}");
                return ExitCode::FAILURE;
            }
            if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Command::VmSmoke { rootfs, console } => {
            let report = a3s_oci_krun::vm_smoke(&rootfs, &console);
            let succeeded = report.is_success();
            if let Err(error) = write_json(&report) {
                eprintln!("a3s-oci-krun-shim: failed to serialize report: {error}");
                return ExitCode::FAILURE;
            }
            if succeeded {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
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
