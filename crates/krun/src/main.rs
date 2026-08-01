use std::io;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod bootstrap_token;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod owner_process;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod recovery_report;

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
        /// Portable endpoint name used as the pipe or private-directory basename.
        #[arg(long, value_name = "NAME")]
        pipe_name: String,
        /// Private host Unix socket mapped to the guest control port.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
        /// Runtime process whose exit must terminate this shim and its VM.
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        #[arg(long, value_name = "PID")]
        owner_pid: NonZeroU32,
        /// Protected host-only destination for verified shutdown evidence.
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        #[arg(long, value_name = "FILE")]
        recovery_report: Option<PathBuf>,
    },
    /// Internal process-takeover boundary for the macOS VM smoke.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[command(name = "__macos-vm-smoke-worker", hide = true)]
    MacosVmSmokeWorker {
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        #[arg(long, value_name = "NAME")]
        marker_name: String,
    },
    /// Internal process-takeover boundary for the macOS guest-agent VM.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[command(name = "__macos-agent-vm-worker", hide = true)]
    MacosAgentVmWorker {
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
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
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            socket_path,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            owner_pid,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            recovery_report,
        } => {
            let endpoint = match a3s_oci_krun::AgentVsockEndpoint::new(pipe_name) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: invalid agent endpoint: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let token = match take_session_token() {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: {error}");
                    return ExitCode::FAILURE;
                }
            };
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let socket_path = Some(socket_path.as_path());
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            let socket_path = None;
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            let report = {
                let bootstrap =
                    match bootstrap_token::BootstrapTokenFile::create(&rootfs, &endpoint, &token) {
                        Ok(bootstrap) => bootstrap,
                        Err(error) => {
                            eprintln!(
                                "a3s-oci-krun-shim: failed to stage guest bootstrap token: {error}"
                            );
                            return ExitCode::FAILURE;
                        }
                    };
                let recovery = match recovery_report {
                    Some(destination) => match recovery_report::RecoveryReportHandoff::create(
                        &rootfs,
                        &endpoint,
                        &destination,
                    ) {
                        Ok(recovery) => Some(recovery),
                        Err(error) => {
                            eprintln!(
                                "a3s-oci-krun-shim: failed to stage guest recovery report: {error}"
                            );
                            return ExitCode::FAILURE;
                        }
                    },
                    None => None,
                };
                let owner_monitor = match owner_process::start(
                    owner_pid,
                    bootstrap.cleanup_paths(),
                    recovery.as_ref().map(|recovery| recovery.cleanup_paths()),
                ) {
                    Ok(owner_monitor) => owner_monitor,
                    Err(error) => {
                        eprintln!("a3s-oci-krun-shim: failed to monitor runtime owner: {error}");
                        return ExitCode::FAILURE;
                    }
                };
                let mut report = a3s_oci_krun::agent_vm_smoke(
                    &rootfs,
                    &console,
                    &endpoint,
                    socket_path,
                    &token,
                    Some(bootstrap.guest_path()),
                    recovery.as_ref().map(|recovery| recovery.guest_path()),
                );
                let recovery_result = recovery.map(|recovery| recovery.persist(&token));
                if let Err(error) = bootstrap.cleanup() {
                    report.status = a3s_oci_core::CapabilityStatus::Unavailable;
                    report.reason = Some(format!(
                        "failed to clean one-time guest bootstrap token: {error}"
                    ));
                }
                if let Some(Err(error)) = recovery_result {
                    report.status = a3s_oci_core::CapabilityStatus::Unavailable;
                    report.reason = Some(format!(
                        "failed to retain authenticated guest recovery report: {error}"
                    ));
                }
                owner_monitor.mark_vm_finished();
                report
            };
            #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
            let report = a3s_oci_krun::agent_vm_smoke(
                &rootfs,
                &console,
                &endpoint,
                socket_path,
                &token,
                None,
                None,
            );
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
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Command::MacosVmSmokeWorker {
            rootfs,
            console,
            marker_name,
        } => {
            if a3s_oci_krun::run_macos_vm_smoke_worker(&rootfs, &console, &marker_name) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Command::MacosAgentVmWorker {
            rootfs,
            console,
            socket_path,
        } => {
            let token = match take_session_token() {
                Ok(token) => token,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if a3s_oci_krun::run_macos_agent_vm_worker(&rootfs, &console, &socket_path, &token) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
    }
}

fn take_session_token() -> Result<a3s_oci_agent_protocol::SessionToken, String> {
    let encoded = Zeroizing::new(
        std::env::var(a3s_oci_agent_protocol::AGENT_SESSION_TOKEN_ENV)
            .map_err(|error| format!("guest bootstrap token is unavailable: {error}"))?,
    );
    std::env::remove_var(a3s_oci_agent_protocol::AGENT_SESSION_TOKEN_ENV);
    a3s_oci_agent_protocol::SessionToken::from_hex(encoded.as_str())
        .map_err(|error| format!("guest bootstrap token is invalid: {error}"))
}

fn write_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    println!();
    Ok(())
}
