use std::io;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod bootstrap_token;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod owner_process;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
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
    /// Repeatedly boot WHPX VMs in this process and verify native handle cleanup.
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    WhpxHandleReclamationSmoke {
        /// Extracted portable OCI root filesystem presented to every VM.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// Exact immutable Windows system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Writable host directory exported to every qualification VM.
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        /// Existing directory that receives one console log per VM.
        #[arg(long, value_name = "DIR")]
        console_directory: PathBuf,
        /// Number of measured VM lifecycles after one warmup lifecycle.
        #[arg(long, default_value_t = 8, value_name = "COUNT")]
        iterations: u16,
    },
    /// Bind and verify the complete immutable Linux KVM boot compatibility set.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    SystemImageContextSmoke {
        /// Exact immutable Linux KVM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
    },
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
    /// Opt-in durable session owner: become the shim's direct parent so Host
    /// SIGKILL does not tear down the Guest (Linux KVM Live reopen path).
    ///
    /// Default Host-bound ownership is unchanged. This helper setsid()'s, injects
    /// `--owner-pid` as its own PID, spawns the trailing shim argv as a new
    /// process group, and publishes the shim PID to `--ready-file`.
    ///
    /// When `--host-control` is set, this process also owns the guest agent
    /// Unix socket (from shim `--socket-path`) and proxies Host↔guest so a
    /// replacement Host can reconnect after the first Host dies.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    SessionOwner {
        /// Host path that receives one line `<shim_pid>\n` after spawn.
        #[arg(long, value_name = "FILE")]
        ready_file: PathBuf,
        /// Optional Host-facing control socket for Live reattach proxying.
        #[arg(long, value_name = "FILE")]
        host_control: Option<PathBuf>,
        /// Shim argv (for example `agent-vm-smoke ...`). Must not include
        /// `--owner-pid`; this process injects it.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        shim_argv: Vec<std::ffi::OsString>,
    },
    /// Qualification-only child used under `session-owner` to prove parentage.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    SessionOwnerProbe {
        /// Injected by `session-owner`; must equal this process's getppid().
        #[arg(long, value_name = "PID")]
        owner_pid: NonZeroU32,
        /// How long to sleep after the parentage check succeeds.
        #[arg(long, default_value_t = 3_600_000, value_name = "MS")]
        sleep_ms: u64,
    },
    /// Qualification-only child: connect to the guest agent socket and echo
    /// until EOF, then reconnect (simulates Guest Host-reconnect without KVM).
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    SessionOwnerBridgeEcho {
        /// Injected by `session-owner`; must equal this process's getppid().
        #[arg(long, value_name = "PID")]
        owner_pid: NonZeroU32,
        /// Guest agent Unix socket bound by `session-owner` bridge mode.
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
    },
    /// Boot the Linux agent at its fixed guest path and bridge its control vsock.
    AgentVmSmoke {
        /// Extracted Linux root filesystem containing /usr/bin/a3s-oci-agent.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// Exact immutable system-image manifest required by the utility VM.
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        /// Device number of the atomically reserved Unix console file.
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, hide = true, value_name = "DEVICE")]
        console_device: Option<u64>,
        /// Inode number of the atomically reserved Unix console file.
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, hide = true, value_name = "INODE")]
        console_inode: Option<u64>,
        /// Portable endpoint name used as the pipe or private-directory basename.
        #[arg(long, value_name = "NAME")]
        pipe_name: String,
        /// Private host Unix socket mapped to the guest control port.
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
        /// Runtime process whose exit must terminate this shim and its VM.
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, value_name = "PID")]
        owner_pid: NonZeroU32,
        /// Protected host-only destination for verified shutdown evidence.
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, value_name = "FILE")]
        recovery_report: Option<PathBuf>,
        /// Exact-generation host directory exported to the Windows guest.
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        /// Writable host directory exported to the Unix-hosted utility VM.
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        /// Stop after real KVM device/API verification and before VM entry.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[arg(long, hide = true, conflicts_with = "qualify_kvm_compatibility_drift")]
        qualify_kvm_post_probe_failure: bool,
        /// Pause before KVM access for one qualification-only asset mutation.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[arg(
            long,
            hide = true,
            value_name = "CASE",
            conflicts_with = "qualify_kvm_post_probe_failure"
        )]
        qualify_kvm_compatibility_drift: Option<String>,
        /// SHA-256 digest of the fixed network-attachment manifest in the runtime share.
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[arg(long, value_name = "SHA256")]
        vm_attachment_manifest_sha256: Option<String>,
    },
    /// Internal process-takeover boundary for the macOS VM smoke.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[command(name = "__macos-vm-smoke-worker", hide = true)]
    MacosVmSmokeWorker {
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        #[arg(long, hide = true, value_name = "DEVICE")]
        runtime_share_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        runtime_share_inode: Option<u64>,
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
        #[arg(long, hide = true, value_name = "DEVICE")]
        runtime_share_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        runtime_share_inode: Option<u64>,
        #[arg(long, hide = true, value_name = "DEVICE")]
        runtime_state_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        runtime_state_inode: Option<u64>,
        #[arg(long, value_name = "FILE")]
        guest_token_file: String,
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        #[arg(long, hide = true, value_name = "DEVICE")]
        console_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        console_inode: Option<u64>,
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
        #[arg(long, value_name = "FILE")]
        guest_recovery_report: Option<String>,
    },
    /// Internal process-takeover boundary for the Linux KVM guest-agent VM.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(name = "__linux-agent-vm-worker", hide = true)]
    LinuxAgentVmWorker {
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        #[arg(long, hide = true, value_name = "DEVICE")]
        runtime_share_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        runtime_share_inode: Option<u64>,
        #[arg(long, hide = true, value_name = "DEVICE")]
        runtime_state_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        runtime_state_inode: Option<u64>,
        #[arg(long, value_name = "FILE")]
        guest_token_file: String,
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        #[arg(long, hide = true, value_name = "DEVICE")]
        console_device: Option<u64>,
        #[arg(long, hide = true, value_name = "INODE")]
        console_inode: Option<u64>,
        #[arg(long, value_name = "FILE")]
        socket_path: PathBuf,
        #[arg(long, value_name = "FILE")]
        guest_recovery_report: Option<String>,
        #[arg(long, hide = true, conflicts_with = "qualify_kvm_compatibility_drift")]
        qualify_kvm_post_probe_failure: bool,
        #[arg(
            long,
            hide = true,
            value_name = "CASE",
            conflicts_with = "qualify_kvm_post_probe_failure"
        )]
        qualify_kvm_compatibility_drift: Option<String>,
        #[arg(long, value_name = "SHA256")]
        vm_attachment_manifest_sha256: Option<String>,
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
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        Command::WhpxHandleReclamationSmoke {
            rootfs,
            system_image_manifest,
            runtime_share,
            console_directory,
            iterations,
        } => {
            let report = a3s_oci_krun::whpx_handle_reclamation_smoke(
                &rootfs,
                &system_image_manifest,
                &runtime_share,
                &console_directory,
                iterations,
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
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Command::SystemImageContextSmoke {
            system_image_manifest,
        } => {
            let report = a3s_oci_krun::system_image_context_smoke(&system_image_manifest);
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
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Command::SessionOwner {
            ready_file,
            host_control,
            shim_argv,
        } => match run_session_owner(ready_file, host_control, shim_argv) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("a3s-oci-krun-shim: session-owner failed: {error}");
                ExitCode::FAILURE
            }
        },
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Command::SessionOwnerProbe {
            owner_pid,
            sleep_ms,
        } => match run_session_owner_probe(owner_pid, sleep_ms) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("a3s-oci-krun-shim: session-owner-probe failed: {error}");
                ExitCode::FAILURE
            }
        },
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Command::SessionOwnerBridgeEcho {
            owner_pid,
            socket_path,
        } => match run_session_owner_bridge_echo(owner_pid, socket_path) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("a3s-oci-krun-shim: session-owner-bridge-echo failed: {error}");
                ExitCode::FAILURE
            }
        },
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
            #[cfg(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            system_image_manifest,
            console,
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            console_device,
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            console_inode,
            pipe_name,
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            socket_path,
            #[cfg(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            owner_pid,
            #[cfg(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            recovery_report,
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            runtime_share,
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            runtime_share,
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            qualify_kvm_post_probe_failure,
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            qualify_kvm_compatibility_drift,
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            vm_attachment_manifest_sha256,
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
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            let console_identity = match parse_console_identity(console_device, console_inode) {
                Ok(identity) => identity,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: {error}");
                    return ExitCode::FAILURE;
                }
            };
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            let socket_path = Some(socket_path.as_path());
            #[cfg(not(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            )))]
            let socket_path = None;
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
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
                if let Err(error) = bootstrap.reverify() {
                    eprintln!(
                        "a3s-oci-krun-shim: refusing VM entry because the guest bootstrap token changed: {error}"
                    );
                    owner_monitor.mark_vm_finished();
                    return ExitCode::FAILURE;
                }
                if let Some(recovery) = recovery.as_ref() {
                    if let Err(error) = recovery.reverify() {
                        eprintln!(
                            "a3s-oci-krun-shim: refusing VM entry because the guest recovery handoff changed: {error}"
                        );
                        owner_monitor.mark_vm_finished();
                        return ExitCode::FAILURE;
                    }
                }
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
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
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
                let handoff = a3s_oci_krun::AgentVmHandoff::new(
                    Some(&runtime_share),
                    Some(bootstrap.guest_path()),
                    recovery.as_ref().map(|recovery| recovery.guest_path()),
                )
                .with_transport_qualification(transport_qualification.as_ref());
                #[cfg(any(
                    all(target_os = "macos", target_arch = "aarch64"),
                    all(
                        target_os = "linux",
                        any(target_arch = "x86_64", target_arch = "aarch64")
                    )
                ))]
                let handoff = if let Some((device, inode)) = console_identity {
                    handoff.with_console_identity(device, inode)
                } else {
                    handoff
                };
                #[cfg(all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                let handoff = handoff.with_kvm_post_probe_failure(qualify_kvm_post_probe_failure);
                #[cfg(all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                let handoff = handoff
                    .with_kvm_compatibility_drift(qualify_kvm_compatibility_drift.as_deref());
                #[cfg(all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                ))]
                let handoff = handoff
                    .with_vm_attachment_manifest_sha256(vm_attachment_manifest_sha256.as_deref());
                if let Err(error) = bootstrap.reverify() {
                    eprintln!(
                        "a3s-oci-krun-shim: refusing VM entry because the guest bootstrap token changed: {error}"
                    );
                    owner_monitor.mark_vm_finished();
                    return ExitCode::FAILURE;
                }
                if let Some(recovery) = recovery.as_ref() {
                    if let Err(error) = recovery.reverify() {
                        eprintln!(
                            "a3s-oci-krun-shim: refusing VM entry because the guest recovery handoff changed: {error}"
                        );
                        owner_monitor.mark_vm_finished();
                        return ExitCode::FAILURE;
                    }
                }
                let mut report = a3s_oci_krun::agent_vm_smoke(
                    &rootfs,
                    Some(&system_image_manifest),
                    &console,
                    &endpoint,
                    socket_path,
                    &token,
                    handoff,
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
            #[cfg(not(any(
                all(target_os = "windows", target_arch = "x86_64"),
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            )))]
            let report = a3s_oci_krun::agent_vm_smoke(
                &rootfs,
                None,
                &console,
                &endpoint,
                socket_path,
                &token,
                a3s_oci_krun::AgentVmHandoff::default()
                    .with_transport_qualification(transport_qualification.as_ref()),
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
            system_image_manifest,
            runtime_share,
            runtime_share_device,
            runtime_share_inode,
            console,
            marker_name,
        } => {
            let runtime_share_identity =
                match parse_runtime_share_identity(runtime_share_device, runtime_share_inode) {
                    Ok(identity) => identity,
                    Err(error) => {
                        eprintln!("a3s-oci-krun-shim: {error}");
                        return ExitCode::FAILURE;
                    }
                };
            if a3s_oci_krun::run_macos_vm_smoke_worker_with_runtime_share_identity_from_stdin(
                &system_image_manifest,
                &runtime_share,
                &console,
                &marker_name,
                Some(runtime_share_identity),
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
            runtime_share_device,
            runtime_share_inode,
            runtime_state_device,
            runtime_state_inode,
            guest_token_file,
            console,
            console_device,
            console_inode,
            socket_path,
            guest_recovery_report,
        } => {
            let (runtime_share_identity, runtime_state_identity) =
                match parse_runtime_share_identities(
                    runtime_share_device,
                    runtime_share_inode,
                    runtime_state_device,
                    runtime_state_inode,
                ) {
                    Ok(identities) => identities,
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
            let console_identity = match parse_console_identity(console_device, console_inode) {
                Ok(identity) => identity,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let handoff = a3s_oci_krun::MacosAgentVmWorkerHandoff::new(
                &system_image_manifest,
                &runtime_share,
                &guest_token_file,
                &console,
                &socket_path,
            );
            let handoff = if let Some((device, inode)) = console_identity {
                handoff.with_console_identity(device, inode)
            } else {
                handoff
            }
            .with_runtime_share_identity(runtime_share_identity.0, runtime_share_identity.1)
            .with_runtime_state_identity(runtime_state_identity.0, runtime_state_identity.1)
            .with_guest_recovery_report(guest_recovery_report.as_deref())
            .with_transport_qualification(transport_qualification.as_ref());
            if a3s_oci_krun::run_macos_agent_vm_worker_handoff(handoff) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        Command::LinuxAgentVmWorker {
            system_image_manifest,
            runtime_share,
            runtime_share_device,
            runtime_share_inode,
            runtime_state_device,
            runtime_state_inode,
            guest_token_file,
            console,
            console_device,
            console_inode,
            socket_path,
            guest_recovery_report,
            qualify_kvm_post_probe_failure,
            qualify_kvm_compatibility_drift,
            vm_attachment_manifest_sha256,
        } => {
            let (runtime_share_identity, runtime_state_identity) =
                match parse_runtime_share_identities(
                    runtime_share_device,
                    runtime_share_inode,
                    runtime_state_device,
                    runtime_state_inode,
                ) {
                    Ok(identities) => identities,
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
            let console_identity = match parse_console_identity(console_device, console_inode) {
                Ok(identity) => identity,
                Err(error) => {
                    eprintln!("a3s-oci-krun-shim: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let handoff = a3s_oci_krun::LinuxAgentVmWorkerHandoff::new(
                &system_image_manifest,
                &runtime_share,
                &guest_token_file,
                &console,
                &socket_path,
            );
            let handoff = if let Some((device, inode)) = console_identity {
                handoff.with_console_identity(device, inode)
            } else {
                handoff
            }
            .with_runtime_share_identity(runtime_share_identity.0, runtime_share_identity.1)
            .with_runtime_state_identity(runtime_state_identity.0, runtime_state_identity.1)
            .with_guest_recovery_report(guest_recovery_report.as_deref())
            .with_vm_attachment_manifest_sha256(vm_attachment_manifest_sha256.as_deref())
            .with_transport_qualification(transport_qualification.as_ref());
            let handoff = if let Some(case) = qualify_kvm_compatibility_drift.as_deref() {
                handoff.with_kvm_compatibility_drift(case)
            } else if qualify_kvm_post_probe_failure {
                handoff.with_kvm_post_probe_failure()
            } else {
                handoff
            };
            let succeeded = a3s_oci_krun::run_linux_agent_vm_worker_handoff(handoff);
            if succeeded {
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

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn parse_console_identity(
    device: Option<u64>,
    inode: Option<u64>,
) -> Result<Option<(u64, u64)>, String> {
    match (device, inode) {
        (Some(device), Some(inode)) => Ok(Some((device, inode))),
        (None, None) => Ok(None),
        _ => Err(
            "console reservation identity requires both --console-device and --console-inode"
                .to_string(),
        ),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn parse_runtime_share_identity(
    device: Option<u64>,
    inode: Option<u64>,
) -> Result<(u64, u64), String> {
    match (device, inode) {
        (Some(device), Some(inode)) => Ok((device, inode)),
        _ => Err(
            "runtime-share reservation identity requires both --runtime-share-device and \
             --runtime-share-inode"
                .to_string(),
        ),
    }
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
type RuntimeShareIdentities = ((u64, u64), (u64, u64));

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn parse_runtime_share_identities(
    share_device: Option<u64>,
    share_inode: Option<u64>,
    state_device: Option<u64>,
    state_inode: Option<u64>,
) -> Result<RuntimeShareIdentities, String> {
    match (share_device, share_inode, state_device, state_inode) {
        (Some(share_device), Some(share_inode), Some(state_device), Some(state_inode)) => {
            Ok(((share_device, share_inode), (state_device, state_inode)))
        }
        _ => Err(
            "runtime-share reservation identity requires --runtime-share-device and \
             --runtime-share-inode plus --runtime-state-device and --runtime-state-inode"
                .to_string(),
        ),
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run_session_owner_probe(owner_pid: NonZeroU32, sleep_ms: u64) -> Result<ExitCode, String> {
    // SAFETY: getppid has no failure mode.
    let parent = unsafe { libc::getppid() };
    let expected = libc::pid_t::try_from(owner_pid.get())
        .map_err(|error| format!("owner_pid does not fit pid_t: {error}"))?;
    if parent != expected {
        return Err(format!(
            "session-owner-probe parentage mismatch: getppid={parent} owner_pid={expected}"
        ));
    }
    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    Ok(ExitCode::SUCCESS)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run_session_owner(
    ready_file: PathBuf,
    host_control: Option<PathBuf>,
    shim_argv: Vec<std::ffi::OsString>,
) -> Result<ExitCode, String> {
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    if shim_argv.is_empty() {
        return Err("session-owner requires a non-empty shim argv after the subcommand".into());
    }
    if shim_argv.iter().any(|arg| arg == "--owner-pid") {
        return Err("session-owner shim argv must not include --owner-pid".into());
    }

    // Detach from the Host session so Host teardown does not SIGHUP this owner.
    // SAFETY: setsid requires a non-leader; Command::spawn children are.
    if unsafe { libc::setsid() } < 0 {
        return Err(format!(
            "session-owner setsid failed: {}",
            io::Error::last_os_error()
        ));
    }

    let guest_socket = host_control
        .as_ref()
        .map(|_| extract_shim_socket_path(&shim_argv))
        .transpose()?;

    let guest_listener = match guest_socket.as_ref() {
        Some(path) => Some(bind_private_unix_listener(path)?),
        None => None,
    };
    let host_listener = match host_control.as_ref() {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    return Err(format!(
                        "session-owner host-control parent directory must exist: {}",
                        parent.display()
                    ));
                }
            }
            let _ = fs::remove_file(path);
            Some(bind_private_unix_listener(path)?)
        }
        None => None,
    };

    let owner_pid = std::process::id();
    let owner_pid = NonZeroU32::new(owner_pid)
        .ok_or_else(|| "session-owner observed a zero process ID".to_string())?;
    let exe = std::env::current_exe()
        .map_err(|error| format!("resolve session-owner executable: {error}"))?;

    let mut child = Command::new(&exe);
    child.args(&shim_argv);
    child.arg("--owner-pid").arg(owner_pid.to_string());
    child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut spawned = child
        .spawn()
        .map_err(|error| format!("spawn shim under session-owner: {error}"))?;
    let shim_pid = NonZeroU32::new(spawned.id())
        .ok_or_else(|| "shim under session-owner has no process ID".to_string())?;

    let tmp = ready_file.with_extension("tmp");
    fs::write(&tmp, format!("{}\n", shim_pid.get()))
        .map_err(|error| format!("write session-owner ready tmp: {error}"))?;
    fs::rename(&tmp, &ready_file)
        .map_err(|error| format!("publish session-owner ready file: {error}"))?;

    let (Some(guest_listener), Some(host_listener)) = (guest_listener, host_listener) else {
        return match spawned.wait() {
            Ok(status) if status.success() => Ok(ExitCode::SUCCESS),
            Ok(status) => Ok(ExitCode::from(status.code().unwrap_or(1) as u8)),
            Err(error) => Err(format!("wait for session-owner shim: {error}")),
        };
    };

    guest_listener
        .set_nonblocking(true)
        .map_err(|error| format!("guest listener nonblocking: {error}"))?;
    host_listener
        .set_nonblocking(true)
        .map_err(|error| format!("host-control listener nonblocking: {error}"))?;

    loop {
        if let Some(status) = spawned
            .try_wait()
            .map_err(|error| format!("poll session-owner shim: {error}"))?
        {
            let _ = fs::remove_file(&ready_file);
            if let Some(path) = host_control.as_ref() {
                let _ = fs::remove_file(path);
                if let Some(parent) = path.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            if let Some(path) = guest_socket.as_ref() {
                let _ = fs::remove_file(path);
                if let Some(parent) = path.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            return if status.success() {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
            };
        }

        let guest = match accept_nonblocking(&guest_listener) {
            Ok(Some(stream)) => stream,
            Ok(None) => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(error) => return Err(format!("accept guest agent bridge: {error}")),
        };
        guest
            .set_nonblocking(false)
            .map_err(|error| format!("guest stream blocking: {error}"))?;

        let host = loop {
            if let Some(status) = spawned
                .try_wait()
                .map_err(|error| format!("poll session-owner shim while waiting Host: {error}"))?
            {
                drop(guest);
                return if status.success() {
                    Ok(ExitCode::SUCCESS)
                } else {
                    Ok(ExitCode::from(status.code().unwrap_or(1) as u8))
                };
            }
            match accept_nonblocking(&host_listener) {
                Ok(Some(stream)) => {
                    if let Err(error) = require_same_uid_peer(&stream) {
                        eprintln!(
                            "a3s-oci-krun-shim: session-owner rejected host-control peer: {error}"
                        );
                        continue;
                    }
                    break stream;
                }
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(error) => return Err(format!("accept Host control bridge: {error}")),
            }
        };
        host.set_nonblocking(false)
            .map_err(|error| format!("host stream blocking: {error}"))?;

        proxy_unix_streams(guest, host);
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn extract_shim_socket_path(shim_argv: &[std::ffi::OsString]) -> Result<PathBuf, String> {
    let mut iter = shim_argv.iter();
    while let Some(arg) = iter.next() {
        if arg == "--socket-path" {
            let path = iter
                .next()
                .ok_or_else(|| "session-owner --socket-path is missing a value".to_string())?;
            return Ok(PathBuf::from(path));
        }
    }
    Err("session-owner bridge mode requires shim argv --socket-path".into())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn bind_private_unix_listener(
    path: &std::path::Path,
) -> Result<std::os::unix::net::UnixListener, String> {
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    if let Some(parent) = path.parent() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(parent).map_err(|error| {
            format!(
                "create session-owner socket parent {}: {error}",
                parent.display()
            )
        })?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .map_err(|error| format!("bind session-owner socket {}: {error}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("protect session-owner socket {}: {error}", path.display()))?;
    Ok(listener)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn accept_nonblocking(
    listener: &std::os::unix::net::UnixListener,
) -> io::Result<Option<std::os::unix::net::UnixStream>> {
    match listener.accept() {
        Ok((stream, _)) => Ok(Some(stream)),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn require_same_uid_peer(stream: &std::os::unix::net::UnixStream) -> Result<(), String> {
    use std::mem::MaybeUninit;
    use std::os::unix::io::AsRawFd;

    let expected_uid = unsafe { libc::geteuid() };
    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "SO_PEERCRED failed: {}",
            io::Error::last_os_error()
        ));
    }
    let cred = unsafe { cred.assume_init() };
    if cred.uid != expected_uid {
        return Err(format!(
            "host-control peer uid {} does not match session-owner uid {expected_uid}",
            cred.uid
        ));
    }
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn run_session_owner_bridge_echo(
    owner_pid: NonZeroU32,
    socket_path: PathBuf,
) -> Result<ExitCode, String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    // SAFETY: getppid has no failure mode.
    let parent = unsafe { libc::getppid() };
    let expected = libc::pid_t::try_from(owner_pid.get())
        .map_err(|error| format!("owner_pid does not fit pid_t: {error}"))?;
    if parent != expected {
        return Err(format!(
            "session-owner-bridge-echo parentage mismatch: getppid={parent} owner_pid={expected}"
        ));
    }

    loop {
        let mut stream = {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                match UnixStream::connect(&socket_path) {
                    Ok(stream) => break stream,
                    Err(error) if Instant::now() >= deadline => {
                        return Err(format!(
                            "timed out connecting bridge-echo to {}: {error}",
                            socket_path.display()
                        ));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        };
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    stream
                        .write_all(&buffer[..n])
                        .map_err(|error| format!("bridge-echo write failed: {error}"))?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Clean Host disconnect: reconnect like Guest Host-reconnect mode.
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn proxy_unix_streams(left: std::os::unix::net::UnixStream, right: std::os::unix::net::UnixStream) {
    use std::io::{Read, Write};
    use std::thread;

    let (mut left_read, mut left_write) = match left.try_clone() {
        Ok(clone) => (left, clone),
        Err(_) => return,
    };
    let (mut right_read, mut right_write) = match right.try_clone() {
        Ok(clone) => (right, clone),
        Err(_) => return,
    };

    let forward = thread::spawn(move || {
        let mut buffer = [0_u8; 8192];
        loop {
            match left_read.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if right_write.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = right_write.shutdown(std::net::Shutdown::Both);
    });
    let mut buffer = [0_u8; 8192];
    loop {
        match right_read.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if left_write.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = left_write.shutdown(std::net::Shutdown::Both);
    let _ = forward.join();
}

fn write_json(value: &impl Serialize) -> Result<(), serde_json::Error> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    println!();
    Ok(())
}

#[cfg(all(
    test,
    any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod tests {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    use super::parse_runtime_share_identity;
    use super::{parse_console_identity, parse_runtime_share_identities};

    #[test]
    fn console_identity_requires_both_kernel_components() {
        assert_eq!(parse_console_identity(None, None), Ok(None));
        assert_eq!(parse_console_identity(Some(7), Some(11)), Ok(Some((7, 11))));
        assert!(parse_console_identity(Some(7), None).is_err());
        assert!(parse_console_identity(None, Some(11)).is_err());
    }

    #[test]
    fn runtime_share_identities_require_all_kernel_components() {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            assert_eq!(parse_runtime_share_identity(Some(7), Some(11)), Ok((7, 11)));
            assert!(parse_runtime_share_identity(None, None).is_err());
            assert!(parse_runtime_share_identity(Some(7), None).is_err());
            assert!(parse_runtime_share_identity(None, Some(11)).is_err());
        }
        assert_eq!(
            parse_runtime_share_identities(Some(7), Some(11), Some(13), Some(17)),
            Ok(((7, 11), (13, 17)))
        );
        assert!(parse_runtime_share_identities(None, None, None, None).is_err());
        assert!(parse_runtime_share_identities(Some(7), None, Some(13), Some(17)).is_err());
        assert!(parse_runtime_share_identities(Some(7), Some(11), None, Some(17)).is_err());
        assert!(parse_runtime_share_identities(Some(7), Some(11), Some(13), None).is_err());
    }
}
