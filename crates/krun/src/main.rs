use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "a3s-oci-krun-shim", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::enum_variant_names)] // The stable shim diagnostics intentionally use a `*-smoke` suffix.
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
    /// Boot the Linux agent at its fixed guest path and bridge its control vsock.
    AgentVmSmoke {
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// Host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        /// Bare Windows pipe name shared with the host runtime.
        #[arg(long, value_name = "NAME")]
        pipe_name: String,
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
        Command::AgentVmSmoke {
            rootfs,
            console,
            pipe_name,
        } => {
            let endpoint = match a3s_oci_krun::AgentVsockEndpoint::new(pipe_name) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: invalid agent endpoint: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let encoded = match std::env::var(a3s_oci_agent_protocol::AGENT_SESSION_TOKEN_ENV) {
                Ok(encoded) => Zeroizing::new(encoded),
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: guest bootstrap token is unavailable: {error}");
                    return ExitCode::FAILURE;
                }
            };
            std::env::remove_var(a3s_oci_agent_protocol::AGENT_SESSION_TOKEN_ENV);
            let token = match a3s_oci_agent_protocol::SessionToken::from_hex(encoded.as_str()) {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: guest bootstrap token is invalid: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let report = a3s_oci_krun::agent_vm_smoke(&rootfs, &console, &endpoint, &token);
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
