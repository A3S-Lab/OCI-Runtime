use std::io;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod bootstrap_token;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod owner_process;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
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
        /// Exact immutable system-image manifest required by macOS HVF.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Separate writable host directory exported to the macOS guest.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        /// Host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Boot the Linux agent at its fixed guest path and bridge its control vsock.
    AgentVmSmoke {
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// Exact immutable system-image manifest required by macOS HVF.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
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
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        ))]
        #[arg(long, value_name = "PID")]
        owner_pid: NonZeroU32,
        /// Protected host-only destination for verified shutdown evidence.
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64")
        ))]
        #[arg(long, value_name = "FILE")]
        recovery_report: Option<PathBuf>,
        /// Optional exact-generation host directory exported to the Windows guest.
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        #[arg(long, value_name = "DIR")]
        runtime_share: Option<PathBuf>,
        /// Writable host directory exported to the macOS guest.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
    },
    /// Internal process-takeover boundary for the macOS VM smoke.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[command(name = "__macos-vm-smoke-worker", hide = true)]
    MacosVmSmokeWorker {
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        #[arg(long, value_name = "NAME")]
        marker_name: String,
    },
    /// Internal process-takeover boundary for the macOS guest-agent VM.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[command(name = "__macos-agent-vm-worker", hide = true)]
    MacosAgentVmWorker {
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        #[arg(long, value_name = "FILE")]
        guest_token_file: String,
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
        #[arg(long, value_name = "FILE")]
        guest_recovery_report: Option<String>,
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
        Command::VmSmoke {
            rootfs,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            system_image_manifest,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            runtime_share,
            console,
        } => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let (system_image_manifest, runtime_share) = (
                Some(system_image_manifest.as_path()),
                Some(runtime_share.as_path()),
            );
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            let (system_image_manifest, runtime_share) = (None, None);
            let report =
                a3s_oci_krun::vm_smoke(&rootfs, system_image_manifest, runtime_share, &console);
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
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            system_image_manifest,
            console,
            pipe_name,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            socket_path,
            #[cfg(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64")
            ))]
            owner_pid,
            #[cfg(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64")
            ))]
            recovery_report,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            runtime_share,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            runtime_share,
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
            let transport_qualification = match take_transport_qualification() {
                Ok(request) => request,
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
                let handoff_root = runtime_share.as_deref().unwrap_or(&rootfs);
                let guest_handoff_root = if runtime_share.is_some() {
                    a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT
                } else {
                    "/"
                };
                let bootstrap = match bootstrap_token::BootstrapTokenFile::create(
                    handoff_root,
                    guest_handoff_root,
                    &endpoint,
                    &token,
                ) {
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
                        handoff_root,
                        guest_handoff_root,
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
                    None,
                    &console,
                    &endpoint,
                    socket_path,
                    &token,
                    a3s_oci_krun::AgentVmHandoff::new(
                        runtime_share.as_deref(),
                        Some(bootstrap.guest_path()),
                        recovery.as_ref().map(|recovery| recovery.guest_path()),
                    )
                    .with_transport_qualification(transport_qualification.as_ref()),
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
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let report = {
                let bootstrap = match bootstrap_token::BootstrapTokenFile::create(
                    &runtime_share,
                    a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT,
                    &endpoint,
                    &token,
                ) {
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
                        &runtime_share,
                        a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT,
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
                    Some(&system_image_manifest),
                    &console,
                    &endpoint,
                    socket_path,
                    &token,
                    a3s_oci_krun::AgentVmHandoff::new(
                        Some(&runtime_share),
                        Some(bootstrap.guest_path()),
                        recovery.as_ref().map(|recovery| recovery.guest_path()),
                    )
                    .with_transport_qualification(transport_qualification.as_ref()),
                );
                if let Err(error) = bootstrap.cleanup() {
                    report.status = a3s_oci_core::CapabilityStatus::Unavailable;
                    report.reason = Some(format!(
                        "failed to clean one-time guest bootstrap token: {error}"
                    ));
                }
                if let Some(Err(error)) = recovery.map(|recovery| recovery.persist(&token)) {
                    report.status = a3s_oci_core::CapabilityStatus::Unavailable;
                    report.reason = Some(format!(
                        "failed to retain authenticated guest recovery report: {error}"
                    ));
                }
                owner_monitor.mark_vm_finished();
                report
            };
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
            system_image_manifest,
            runtime_share,
            console,
            marker_name,
        } => {
            if a3s_oci_krun::run_macos_vm_smoke_worker(
                &system_image_manifest,
                &runtime_share,
                &console,
                &marker_name,
            ) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        Command::MacosAgentVmWorker {
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            socket_path,
            guest_recovery_report,
        } => {
            let transport_qualification = match take_transport_qualification() {
                Ok(request) => request,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if a3s_oci_krun::run_macos_agent_vm_worker(
                &system_image_manifest,
                &runtime_share,
                &guest_token_file,
                &console,
                &socket_path,
                guest_recovery_report.as_deref(),
                transport_qualification.as_ref(),
            ) {
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

fn take_transport_qualification(
) -> Result<Option<a3s_oci_agent_protocol::AgentTransportQualificationRequest>, String> {
    let Some(encoded) = std::env::var_os(a3s_oci_agent_protocol::AGENT_TRANSPORT_QUALIFICATION_ENV)
    else {
        return Ok(None);
    };
    std::env::remove_var(a3s_oci_agent_protocol::AGENT_TRANSPORT_QUALIFICATION_ENV);
    let encoded = encoded
        .into_string()
        .map_err(|_| "guest transport qualification handoff is not valid UTF-8".to_string())?;
    a3s_oci_agent_protocol::AgentTransportQualificationRequest::from_json(&encoded)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn write_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    println!();
    Ok(())
}
