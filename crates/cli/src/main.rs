use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use thiserror::Error;

mod dispatch;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_kvm_service;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_hvf_service;
#[cfg(target_os = "linux")]
mod native_service;
mod oci_cli;
mod reopen_replacement;

#[derive(Debug, Parser)]
#[command(name = "a3s-oci", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[cfg(test)]
fn try_parse_cli_for_test(args: &[&str]) -> Result<Cli, clap::Error> {
    // Rust test workers reserve less stack than a Unix main thread. Exercise
    // the production-sized Clap graph under the same explicit 8 MiB bound.
    let args = args
        .iter()
        .map(|argument| (*argument).to_string())
        .collect::<Vec<_>>();
    std::thread::Builder::new()
        .name("main-sized-cli-parser".to_string())
        .stack_size(CLI_THREAD_STACK_BYTES)
        .spawn(move || Cli::try_parse_from(args))
        .expect("spawn main-sized CLI parser")
        .join()
        .expect("main-sized CLI parser must not panic")
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum NativeLinuxCheckpointRestoreCrashPointArg {
    #[value(name = "after-call")]
    AfterDriverCall,
    #[value(name = "after-commit")]
    AfterHostCommit,
}

#[cfg(target_os = "linux")]
impl From<NativeLinuxCheckpointRestoreCrashPointArg>
    for a3s_oci_runtime::NativeLinuxCheckpointRestoreCrashPoint
{
    fn from(value: NativeLinuxCheckpointRestoreCrashPointArg) -> Self {
        match value {
            NativeLinuxCheckpointRestoreCrashPointArg::AfterDriverCall => Self::AfterDriverCall,
            NativeLinuxCheckpointRestoreCrashPointArg::AfterHostCommit => Self::AfterHostCommit,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print machine-readable runtime driver capabilities.
    Features,
    /// Create an OCI container through the configured long-lived Host Service.
    Create {
        /// OCI bundle containing config.json and rootfs (defaults to the current directory).
        #[arg(long, value_name = "DIR", default_value = ".")]
        bundle: PathBuf,
        /// File that receives the created container's init PID.
        #[arg(long, value_name = "PATH")]
        pid_file: Option<PathBuf>,
        /// OCI terminal handoff socket. Terminal handoff is not yet supported.
        #[arg(long, value_name = "PATH")]
        console_socket: Option<PathBuf>,
        /// Unique OCI container ID.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Print the standard OCI state for one container.
    State {
        /// OCI container ID.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Start the configured init process for one created container.
    Start {
        /// OCI container ID.
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Send a Linux signal to one created or running container.
    Kill {
        /// OCI container ID.
        #[arg(value_name = "ID")]
        id: String,
        /// Runc-compatible positional signal accepted by upstream Runtime Tools.
        #[arg(value_name = "SIGNAL", conflicts_with = "signal_option")]
        positional_signal: Option<String>,
        /// Signal name or positive number (defaults to TERM).
        #[arg(long = "signal", value_name = "SIGNAL")]
        signal_option: Option<String>,
        /// Deliver the signal to every process in the container.
        #[arg(long)]
        all: bool,
    },
    /// Delete one stopped container, or force its cleanup.
    Delete {
        /// Stop remaining processes before cleanup.
        #[arg(long)]
        force: bool,
        /// OCI container ID.
        #[arg(value_name = "ID")]
        id: String,
    },
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
    /// Qualify immutable Native Linux checkpoints with one exact CRIU binary.
    NativeLinuxCheckpointSmoke {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// Exact root-owned CRIU executable qualified by this run.
        #[arg(long, value_name = "FILE")]
        criu: PathBuf,
        /// OCI bundle containing config.json and rootfs.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing directory beneath which isolated smoke state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Exact source revision embedded in qualification evidence.
        #[arg(long, value_name = "REVISION")]
        source_revision: String,
    },
    /// Own one restore until a qualification-only process crash boundary.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    NativeLinuxCheckpointRestoreOwner {
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        #[arg(long, value_name = "FILE")]
        criu: PathBuf,
        #[arg(long, value_name = "DIR")]
        state_root: PathBuf,
        #[arg(long, value_name = "DIR")]
        executor_parent: PathBuf,
        #[arg(long, value_name = "FILE")]
        request_file: PathBuf,
        #[arg(long, value_name = "FILE")]
        ready_file: PathBuf,
        #[arg(long, value_enum)]
        crash_point: NativeLinuxCheckpointRestoreCrashPointArg,
    },
    /// Qualify one opaque caller-owned network enforcement and redirect mechanism.
    NativeLinuxNetworkEnforcementSmoke {
        /// Matching a3s-oci-agent executable used for the prepared init mode.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// OCI bundle bound to one joined namespace and exact interface.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing directory beneath which isolated smoke state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Exact host interface selected by linux.netDevices.
        #[arg(long)]
        source_interface: String,
        /// Opaque caller-issued interface allocation incarnation.
        #[arg(long)]
        interface_id: String,
        /// Opaque caller-issued cleanup obligation incarnation.
        #[arg(long)]
        cleanup_id: String,
        /// Qualification-only port whose traffic is locally redirected.
        #[arg(long)]
        redirect_port: u16,
        /// Qualification-only port rejected by the caller-owned mechanism.
        #[arg(long)]
        rejected_port: u16,
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
        /// User-owned cgroup-v2 delegation for an explicit path or device isolation.
        #[arg(long, value_name = "DIR")]
        delegated_cgroup_root: Option<PathBuf>,
        /// Bootstrap the bounded helper required for rootless default devices.
        #[arg(long, requires = "delegated_cgroup_root")]
        rootless_device_bootstrap: bool,
        /// Publish after delegation open and pause before the first mutation.
        #[arg(
            long,
            value_name = "FILE",
            hide = true,
            requires = "post_open_continue_file"
        )]
        post_open_ready_file: Option<PathBuf>,
        /// Continue a qualification paused by --post-open-ready-file.
        #[arg(
            long,
            value_name = "FILE",
            hide = true,
            requires = "post_open_ready_file"
        )]
        post_open_continue_file: Option<PathBuf>,
    },
    /// Qualify rootless cgroup-device policy through the parent-bound helper.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    NativeLinuxRootlessDevicePolicySmoke {
        /// Matching a3s-oci-agent executable used for prepared init.
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        /// Rootless OCI bundle containing the bounded device profile.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing user-owned directory beneath which smoke state is created.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Exact user-owned cgroup-v2 delegation retained before privilege drop.
        #[arg(long, value_name = "DIR")]
        delegated_cgroup_root: PathBuf,
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
    /// Serve the KVM candidate only for owner-death/restart qualification.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmRecoveryHostService {
        /// Private absolute root containing runtime.sock, state, and runtime data.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
    },
    /// Serve the KVM candidate only for bounded-soak qualification.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmSoakHostService {
        /// Private absolute root containing runtime.sock, state, and runtime data.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
    },
    /// Qualify KVM owner SIGKILL and replacement Host Service recovery.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmRecoverySmoke {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// OCI bundle copied into the private runtime-owned handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing private directory that retains recovery evidence.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Exact source revision embedded in the qualification report.
        #[arg(long, value_name = "REVISION")]
        source_revision: String,
    },
    /// Qualify all Host/Guest Create interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmCreateReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Create transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest State interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmStateReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side State transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Start interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmStartReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Start transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Kill interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmKillReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Kill transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Delete interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmDeleteReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Delete transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest init Wait interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmWaitReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Wait transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest terminal Exec interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmExecReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Exec transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest terminal SignalProcess interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmSignalProcessReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side SignalProcess transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest non-init WaitProcess interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmWaitProcessReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side WaitProcess transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Pause interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmPauseReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Pause transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Resume interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmResumeReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Resume transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Processes interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmProcessesReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Processes transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Qualify all Host/Guest Update interruption stages through real KVM owners.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmUpdateReopen {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// New or empty private root for durable state, shares, and consoles.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Source OCI bundle copied into the protected runtime handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Exact Host- or Guest-side Update transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: reopen_replacement::FaultStageArg,
    },
    /// Run a bounded fresh-generation KVM soak through the qualification owner.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[command(hide = true)]
    LinuxKvmSoak {
        /// Absolute isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Absolute immutable Linux KVM utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// OCI bundle copied into each private runtime-owned handoff.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing private directory that retains soak evidence.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Exact source revision embedded in the qualification report.
        #[arg(long, value_name = "REVISION")]
        source_revision: String,
        /// Number of fresh KVM generations exercised by this bounded run.
        #[arg(long, default_value_t = 25)]
        iterations: u32,
    },
    /// Serve dedicated Apple Silicon HVF VMs through one durable SDK owner.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    MacosHvfHostService {
        /// Private absolute root containing runtime.sock, state, and runtime data.
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        /// Absolute entitlement-signed isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Absolute immutable macOS utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
    },
    /// Qualify the complete public Apple Silicon HVF Host Service product path.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    MacosHvfHostServiceSmoke {
        /// Absolute entitlement-signed isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Absolute immutable macOS utility-VM system-image manifest.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// OCI bundle copied into a private runtime-owned handoff for every generation.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// Existing private directory that retains report.json and all phase evidence.
        #[arg(long, value_name = "DIR")]
        work_parent: PathBuf,
        /// Number of sequential fresh-VM generations in the final public-service soak.
        #[arg(long, default_value_t = 25)]
        iterations: u32,
        /// Source revision embedded in qualification provenance.
        #[arg(long, value_name = "REVISION")]
        source_revision: String,
    },
    /// Hold one real Native Linux workload for owner-death qualification.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    NativeLinuxRecoveryOwner {
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        #[arg(long, value_name = "FILE")]
        ready_file: PathBuf,
        /// Explicit user-owned cgroup-v2 delegation for rootless recovery.
        #[arg(long, value_name = "DIR")]
        delegated_cgroup_root: Option<PathBuf>,
        /// Bootstrap the bounded helper required for rootless default devices.
        #[arg(long, requires = "delegated_cgroup_root")]
        rootless_device_bootstrap: bool,
    },
    /// Reopen a killed Native Linux owner and emit safe-recovery evidence.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    NativeLinuxRecoveryResume {
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        #[arg(long)]
        generation: u64,
        /// Exact cgroup-v2 delegation used by the killed rootless owner.
        #[arg(long, value_name = "DIR")]
        delegated_cgroup_root: Option<PathBuf>,
        /// Recreate the bounded helper required for rootless recovery.
        #[arg(long, requires = "delegated_cgroup_root")]
        rootless_device_bootstrap: bool,
    },
    /// Hold a Native startContainer Hook for exact owner-death qualification.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    NativeLinuxHookOwnerDeathOwner {
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        #[arg(long, value_name = "FILE")]
        ready_file: PathBuf,
    },
    /// Reconcile a Native owner killed inside startContainer and retain Hook evidence.
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    NativeLinuxHookOwnerDeathResume {
        #[arg(long, value_name = "FILE")]
        agent: PathBuf,
        #[arg(long, value_name = "DIR")]
        root: PathBuf,
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        #[arg(long, value_name = "ID")]
        container_id: a3s_oci_sdk::ContainerId,
        #[arg(long)]
        generation: u64,
        /// Root-owned JSON captured while the Hook process group was live.
        #[arg(long, value_name = "FILE")]
        evidence: PathBuf,
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
        /// Bootstrap directory kept separate from the immutable system image.
        #[arg(long, value_name = "DIR")]
        rootfs: PathBuf,
        /// Immutable system-image manifest required by each utility-VM host path.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: Option<PathBuf>,
        /// Writable directory exported separately from the immutable system root.
        #[arg(long, value_name = "DIR")]
        runtime_share: Option<PathBuf>,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
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
    },
    /// Run a fixed OCI core lifecycle inside one utility VM.
    OciVmSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Platform bootstrap root; Windows requires an empty `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Immutable system-image manifest required by macOS HVF and Windows WHPX.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: Option<PathBuf>,
        /// Writable directory exported separately from the immutable system root.
        #[arg(long, value_name = "DIR")]
        runtime_share: Option<PathBuf>,
        /// OCI bundle contained by the writable runtime tree.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Qualify hostile Guest paths inside one real utility VM.
    OciVmGuestIsolationSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Empty immutable bootstrap root, disjoint from the runtime share.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Immutable system-image manifest required by KVM and HVF.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: Option<PathBuf>,
        /// Writable runtime share containing `run/` and the known-good bundle.
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        /// Known-good OCI bundle contained by the writable runtime share.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// New host file that receives the Guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
    },
    /// Run one exact lifecycle through the qualification-only WHPX driver.
    WhpxDriverSmoke {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Protected runtime root containing bootstrap, shares, console, and recovery.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Protected init.krun bootstrap root; the driver owns its `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Manifest for the pinned read-only x86_64 ext4 system image.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
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
    /// Serve the explicit A3S Box lifecycle qualification over a protected Windows pipe.
    BoxWhpxQualificationService {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Protected runtime root containing bootstrap, shares, console, and handoffs.
        #[arg(long, value_name = "DIR")]
        runtime_root: PathBuf,
        /// Protected init.krun bootstrap root; the driver owns its `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Manifest for the pinned read-only x86_64 ext4 system image.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Durable runtime service state root.
        #[arg(long, value_name = "DIR")]
        state_root: PathBuf,
        /// Local named-pipe path below \\.\pipe\.
        #[arg(long, value_name = "PIPE")]
        pipe: String,
        /// Optional new file published after the protected endpoint is bound.
        #[arg(long, value_name = "FILE")]
        ready_file: Option<PathBuf>,
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
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
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
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
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
        /// Platform bootstrap root; Windows requires an empty `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Immutable system-image manifest required by macOS HVF and Windows WHPX.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: Option<PathBuf>,
        /// Writable directory containing both OCI bundles.
        #[arg(long, value_name = "DIR")]
        runtime_share: Option<PathBuf>,
        /// First OCI bundle contained by the writable runtime tree.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct OCI bundle contained by the writable runtime tree.
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
        /// Writable runtime tree shared with each immutable-image VM wave.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Immutable system-image manifest bound to every soak wave.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// First OCI bundle contained by the writable runtime tree.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct OCI bundle contained by the writable runtime tree.
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
        /// Bootstrap root containing the empty init.krun `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Manifest for the pinned read-only x86_64 ext4 system image.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: PathBuf,
        /// Writable directory exported through the fixed runtime-share tag.
        #[arg(long, value_name = "DIR")]
        runtime_share: PathBuf,
        /// First Windows-profile OCI bundle contained by the runtime share.
        #[arg(long, value_name = "DIR")]
        bundle_a: PathBuf,
        /// Second distinct Windows-profile OCI bundle contained by the runtime share.
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
        /// Platform bootstrap root; Windows requires an empty `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Immutable system-image manifest required by macOS HVF and Windows WHPX.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: Option<PathBuf>,
        /// Writable directory containing the OCI bundle.
        #[arg(long, value_name = "DIR")]
        runtime_share: Option<PathBuf>,
        /// OCI bundle contained by the writable runtime tree.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        /// Successful lifecycle boundary after which normal flow is interrupted.
        #[arg(long, value_enum)]
        fault_after: FaultPointArg,
    },
    /// Interrupt one real utility-VM transport stage and prove cleanup.
    OciVmTransportFaultCleanup {
        /// Isolated libkrun shim executable.
        #[arg(long, value_name = "FILE")]
        shim: PathBuf,
        /// Platform bootstrap root; Windows requires an empty `dev` mount point.
        #[arg(long, value_name = "DIR")]
        vm_rootfs: PathBuf,
        /// Immutable system-image manifest required by macOS HVF and Windows WHPX.
        #[arg(long, value_name = "FILE")]
        system_image_manifest: Option<PathBuf>,
        /// Writable directory containing the OCI bundle.
        #[arg(long, value_name = "DIR")]
        runtime_share: Option<PathBuf>,
        /// OCI bundle contained by the writable runtime tree.
        #[arg(long, value_name = "DIR")]
        bundle: PathBuf,
        /// New host file that receives the guest console stream.
        #[arg(long, value_name = "FILE")]
        console: PathBuf,
        /// Exact Host/Guest request-response or Host shutdown transition to interrupt.
        #[arg(long, value_enum)]
        fault_at: TransportFaultStageArg,
    },
    /// Reopen durable operation state through a fresh macOS HVF VM owner.
    OciVmReopenReplacement(reopen_replacement::Args),
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportFaultStageArg {
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
    #[value(name = "host-before-shutdown")]
    HostBeforeShutdown,
    #[value(name = "host-after-shutdown")]
    HostAfterShutdown,
}

impl From<TransportFaultStageArg> for a3s_oci_runtime::AgentTransportFaultStage {
    fn from(value: TransportFaultStageArg) -> Self {
        match value {
            TransportFaultStageArg::BeforeRequestWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostBeforeRequestWrite,
            ),
            TransportFaultStageArg::AfterRequestWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostAfterRequestWrite,
            ),
            TransportFaultStageArg::BeforeResponseRead => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostBeforeResponseRead,
            ),
            TransportFaultStageArg::AfterResponseRead => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::HostAfterResponseRead,
            ),
            TransportFaultStageArg::GuestAfterRequestRead => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::GuestAfterRequestRead,
            ),
            TransportFaultStageArg::GuestBeforeDispatch => {
                Self::Operation(a3s_oci_runtime::AgentTransportOperationStage::GuestBeforeDispatch)
            }
            TransportFaultStageArg::GuestAfterDispatch => {
                Self::Operation(a3s_oci_runtime::AgentTransportOperationStage::GuestAfterDispatch)
            }
            TransportFaultStageArg::GuestBeforeResponseWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::GuestBeforeResponseWrite,
            ),
            TransportFaultStageArg::GuestAfterResponseWrite => Self::Operation(
                a3s_oci_runtime::AgentTransportOperationStage::GuestAfterResponseWrite,
            ),
            TransportFaultStageArg::HostBeforeShutdown => {
                Self::Shutdown(a3s_oci_runtime::AgentTransportShutdownStage::HostBeforeShutdown)
            }
            TransportFaultStageArg::HostAfterShutdown => {
                Self::Shutdown(a3s_oci_runtime::AgentTransportShutdownStage::HostAfterShutdown)
            }
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("runtime request failed: {0}")]
    Runtime(#[from] a3s_oci_sdk::Error),
    #[error("failed to serialize command output: {0}")]
    Serialize(#[from] serde_json::Error),
    #[cfg(target_os = "linux")]
    #[error("failed to read Hook owner-death evidence {path}: {source}")]
    ReadHookOwnerDeathEvidence {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("failed to parse Hook owner-death evidence {path}: {source}")]
    ParseHookOwnerDeathEvidence {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[error("failed to resolve the current a3s-oci executable: {0}")]
    CurrentExecutable(std::io::Error),
}

// Windows reserves only 1 MiB for the process main thread. Keep Clap parsing,
// the Tokio runtime, and concrete command futures on an explicitly sized stack
// that matches the common Unix main-thread reservation.
#[cfg(any(test, target_os = "windows"))]
const CLI_THREAD_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(target_os = "windows")]
fn main() -> ExitCode {
    let worker = match std::thread::Builder::new()
        .name("a3s-oci-command".to_string())
        .stack_size(CLI_THREAD_STACK_BYTES)
        .spawn(cli_main)
    {
        Ok(worker) => worker,
        Err(error) => {
            eprintln!("a3s-oci: failed to start command worker: {error}");
            return ExitCode::FAILURE;
        }
    };
    match worker.join() {
        Ok(code) => code,
        Err(_) => {
            eprintln!("a3s-oci: command worker panicked");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() -> ExitCode {
    cli_main()
}

#[inline(never)]
fn cli_main() -> ExitCode {
    let cli = Cli::parse();
    #[cfg(target_os = "linux")]
    let bootstrap_root = match &cli.command {
        Command::NativeLinuxRootlessSmoke {
            delegated_cgroup_root,
            rootless_device_bootstrap: true,
            ..
        }
        | Command::NativeLinuxRecoveryOwner {
            delegated_cgroup_root,
            rootless_device_bootstrap: true,
            ..
        }
        | Command::NativeLinuxRecoveryResume {
            delegated_cgroup_root,
            rootless_device_bootstrap: true,
            ..
        } => delegated_cgroup_root.as_deref(),
        #[cfg(target_os = "linux")]
        Command::NativeLinuxRootlessDevicePolicySmoke {
            delegated_cgroup_root,
            ..
        } => Some(delegated_cgroup_root.as_path()),
        _ => None,
    };
    #[cfg(target_os = "linux")]
    let rootless_device_policy_bootstrap = match bootstrap_root {
        Some(delegated_cgroup_root) => {
            match a3s_oci_runtime::RootlessDevicePolicyBootstrap::start(delegated_cgroup_root) {
                Ok(bootstrap) => Some(bootstrap),
                Err(error) => {
                    eprintln!("a3s-oci: runtime request failed: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };
    #[cfg(not(target_os = "linux"))]
    let rootless_device_policy_bootstrap = None;
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("a3s-oci: failed to create async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(dispatch::run(cli, rootless_device_policy_bootstrap)) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("a3s-oci: {error}");
            ExitCode::FAILURE
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
