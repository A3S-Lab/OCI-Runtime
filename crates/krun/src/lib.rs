//! Isolated libkrun boundary used by the utility-VM owner process.
//!
//! The main runtime, CLI, and SDK do not link libkrun. Only the dedicated shim
//! process depends on the native library, so feature inspection and native
//! Linux execution remain independent of KVM, HVF, or WHPX.

use std::path::Path;

mod agent_smoke;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod context;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod ffi;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_agent_smoke;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_compatibility_drift;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_context;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_kvm_device;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_runtime_asset;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_runtime_share;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_system_image;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux_vm_attachment;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_agent_smoke;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_assets;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_context;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_runtime_share;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_system_image;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_vm_marker;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos_vm_smoke;
mod report;
#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod runtime_assets;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod unix_process;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows_handle_baseline;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows_system_image;

pub use a3s_oci_agent_protocol::{AgentVsockEndpoint, AGENT_VSOCK_PORT};
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::{Error, ErrorCode, Result};
pub use agent_smoke::{agent_vm_smoke, AgentVmHandoff};
pub use report::{
    KrunAgentVmSmokeReport, KrunContextSmokeReport, KrunSystemImageContextSmokeReport,
    KrunVmSmokeReport, LinuxBootAssetsEvidence, MacosBootAssetsEvidence, WindowsBootAssetsEvidence,
    KRUN_AGENT_VM_SMOKE_SCHEMA_VERSION, KRUN_CONTEXT_SMOKE_SCHEMA_VERSION,
    KRUN_SYSTEM_IMAGE_CONTEXT_SMOKE_SCHEMA_VERSION, KRUN_VM_SMOKE_SCHEMA_VERSION,
};

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const VM_SMOKE_TOKEN: &str = "a3s-oci-whpx-vm-smoke-v1";

/// Validated utility-VM resource configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmConfig {
    vcpus: u8,
    memory_mib: u32,
}

impl VmConfig {
    /// Validate a libkrun VM resource request.
    pub fn new(vcpus: u8, memory_mib: u32) -> Result<Self> {
        if vcpus == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "virtual CPU count must be at least 1",
            ));
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if vcpus != 1 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "the certified Windows WHPX path currently supports exactly 1 vCPU; \
                     requested {vcpus}"
                ),
            ));
        }
        if memory_mib == 0 {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "VM memory must be at least 1 MiB",
            ));
        }

        Ok(Self { vcpus, memory_mib })
    }

    /// Virtual CPU count accepted by libkrun.
    #[must_use]
    pub const fn vcpus(self) -> u8 {
        self.vcpus
    }

    /// Guest memory in MiB.
    #[must_use]
    pub const fn memory_mib(self) -> u32 {
        self.memory_mib
    }
}

/// Create, configure, and release one real libkrun context.
#[must_use]
pub fn context_smoke() -> KrunContextSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        context_smoke_windows()
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        context_smoke_macos()
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        context_smoke_linux()
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        KrunContextSmokeReport {
            schema_version: KRUN_CONTEXT_SMOKE_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::current(),
            status: CapabilityStatus::Unsupported,
            runtime_bundle_loaded: false,
            context_created: false,
            vm_configured: false,
            agent_vsock_configured: false,
            context_released: false,
            vcpus: 1,
            memory_mib: 128,
            reason: Some(
                "the current context smoke is implemented only for Linux x86_64/aarch64 KVM, \
                 Windows x86_64/WHPX, and macOS aarch64/HVF"
                    .into(),
            ),
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn context_smoke_windows() -> KrunContextSmokeReport {
    use context::KrunContext;

    let config = match VmConfig::new(1, 128) {
        Ok(config) => config,
        Err(error) => return KrunContextSmokeReport::failed(error.to_string()),
    };
    let mut report = KrunContextSmokeReport::windows(config);

    let mut context = match KrunContext::create() {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    if let Err(error) = context.set_vm_config(config) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    let endpoint =
        match AgentVsockEndpoint::new(format!("a3s-oci-context-smoke-{}", std::process::id())) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                report.context_released = context.close().is_ok();
                report.reason = Some(error.to_string());
                return report;
            }
        };
    if let Err(error) = context.set_agent_vsock(&endpoint) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;

    match context.close() {
        Ok(()) => {
            report.context_released = true;
            report.status = CapabilityStatus::Available;
        }
        Err(error) => report.reason = Some(error.to_string()),
    }
    report
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn context_smoke_macos() -> KrunContextSmokeReport {
    use std::path::Path;

    use macos_context::{KrunContext, MacosKrunApi};

    let config = match VmConfig::new(1, 128) {
        Ok(config) => config,
        Err(error) => {
            let mut report = KrunContextSmokeReport::macos(fallback_context_config());
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let mut report = KrunContextSmokeReport::macos(config);

    let api = match MacosKrunApi::load() {
        Ok(api) => {
            report.runtime_bundle_loaded = true;
            api
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    let mut context = match KrunContext::create(api) {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    if let Err(error) = context.set_vm_config(config) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    let endpoint = match AgentVsockEndpoint::generate() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            report.context_released = context.close().is_ok();
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let socket_path = Path::new("/tmp").join(format!("{}.sock", endpoint.pipe_name()));
    if let Err(error) = context.set_agent_vsock(&socket_path, endpoint.port()) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;

    match context.close() {
        Ok(()) => {
            report.context_released = true;
            report.status = CapabilityStatus::Available;
        }
        Err(error) => report.reason = Some(error.to_string()),
    }
    report
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn context_smoke_linux() -> KrunContextSmokeReport {
    use linux_context::{KrunContext, LinuxKrunApi};

    let config = match VmConfig::new(1, 128) {
        Ok(config) => config,
        Err(error) => {
            let mut report = KrunContextSmokeReport::linux(fallback_context_config());
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let mut report = KrunContextSmokeReport::linux(config);

    let api = match LinuxKrunApi::load() {
        Ok(api) => {
            report.runtime_bundle_loaded = true;
            api
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    let mut context = match KrunContext::create(api) {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    if let Err(error) = context.set_vm_config(config) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    let endpoint = match AgentVsockEndpoint::generate() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            report.context_released = context.close().is_ok();
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let socket_path = std::env::temp_dir().join(format!("{}.sock", endpoint.pipe_name()));
    if let Err(error) = context.set_agent_vsock(&socket_path, endpoint.port()) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;

    match context.close() {
        Ok(()) => {
            report.context_released = true;
            report.status = CapabilityStatus::Available;
        }
        Err(error) => report.reason = Some(error.to_string()),
    }
    report
}

/// Bind the exact Linux runtime, firmware kernel, immutable root, and guest
/// agent to one libkrun context without entering a VM.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[must_use]
pub fn system_image_context_smoke(manifest_path: &Path) -> KrunSystemImageContextSmokeReport {
    use linux_context::{KrunContext, LinuxKrunApi};
    use linux_system_image::LinuxSystemImage;

    let config = match VmConfig::new(1, 128) {
        Ok(config) => config,
        Err(error) => {
            let mut report = KrunSystemImageContextSmokeReport::linux(fallback_context_config());
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let mut report = KrunSystemImageContextSmokeReport::linux(config);

    let api = match LinuxKrunApi::load() {
        Ok(api) => {
            report.runtime_bundle_loaded = true;
            api
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let system_image = match LinuxSystemImage::load(manifest_path, api.runtime_bundle()) {
        Ok(system_image) => {
            report.system_image_verified = true;
            report.boot_assets = Some(system_image.evidence());
            system_image
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    let mut context = match KrunContext::create(api) {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };
    if let Err(error) = context.set_vm_config(config) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    if let Err(error) = context.set_read_only_system_image(system_image) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.root_disk_configured = true;

    let endpoint = match AgentVsockEndpoint::generate() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            report.context_released = context.close().is_ok();
            report.reason = Some(error.to_string());
            return report;
        }
    };
    let socket_path = std::env::temp_dir().join(format!("{}.sock", endpoint.pipe_name()));
    if let Err(error) = context.set_agent_vsock(&socket_path, endpoint.port()) {
        report.context_released = context.close().is_ok();
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;

    match context.close() {
        Ok(()) => {
            report.context_released = true;
            report.status = CapabilityStatus::Available;
        }
        Err(error) => report.reason = Some(error.to_string()),
    }
    report
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const fn fallback_context_config() -> VmConfig {
    VmConfig {
        vcpus: 1,
        memory_mib: 128,
    }
}

/// Enter a real utility VM, execute `/bin/sh`, and verify a guest-written marker.
///
/// This is intentionally a shim-only validation API. `krun_start_enter`
/// consumes the process-local libkrun context and must never run inside an SDK
/// client process.
#[must_use]
pub fn vm_smoke(
    rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: Option<&Path>,
    console: &Path,
) -> KrunVmSmokeReport {
    let config = match VmConfig::new(1, 512) {
        Ok(config) => config,
        Err(error) => {
            let mut report = KrunVmSmokeReport::initial(HostPlatform::current(), fallback_config());
            report.reason = Some(error.to_string());
            return report;
        }
    };

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let _ = (system_image_manifest, runtime_share);
        vm_smoke_windows(rootfs, console, config)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let Some(system_image_manifest) = system_image_manifest else {
            let mut report = KrunVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason =
                Some("macOS VM smoke requires an explicit system-image manifest".into());
            return report;
        };
        let Some(runtime_share) = runtime_share else {
            let mut report = KrunVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason =
                Some("macOS VM smoke requires a separate writable runtime share".into());
            return report;
        };
        let _ = rootfs;
        macos_vm_smoke::vm_smoke(system_image_manifest, runtime_share, console, config)
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (rootfs, system_image_manifest, runtime_share, console);
        KrunVmSmokeReport::unsupported(HostPlatform::current(), config)
    }
}

/// Run the private macOS VM-entry worker used by [`vm_smoke`].
///
/// This is exported only so the isolated shim binary can cross the
/// process-takeover boundary. It is not an SDK or driver API.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
#[must_use]
pub fn run_macos_vm_smoke_worker(
    system_image_manifest: &Path,
    runtime_share: &Path,
    console: &Path,
    marker_name: &str,
) -> bool {
    let runtime_share_identity = match macos_runtime_share_identity(runtime_share) {
        Some(identity) => identity,
        None => return false,
    };
    run_macos_vm_smoke_worker_with_runtime_share_identity(
        system_image_manifest,
        runtime_share,
        console,
        marker_name,
        Some(runtime_share_identity),
    )
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn macos_runtime_share_identity(path: &Path) -> Option<(u64, u64)> {
    macos_runtime_share::MacosRuntimeShare::open(path)
        .ok()
        .map(|share| share.identity())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn macos_runtime_share_identities(path: &Path) -> Option<((u64, u64), (u64, u64))> {
    let mut share = macos_runtime_share::MacosRuntimeShare::open(path).ok()?;
    share.require_state_directory().ok()?;
    Some((share.identity(), share.state_identity()?))
}

/// Run the private macOS VM-entry worker while binding its runtime share to a
/// directory identity captured by the launching process.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
#[must_use]
pub fn run_macos_vm_smoke_worker_with_runtime_share_identity(
    system_image_manifest: &Path,
    runtime_share: &Path,
    console: &Path,
    marker_name: &str,
    runtime_share_identity: Option<(u64, u64)>,
) -> bool {
    let marker_token = match a3s_oci_agent_protocol::SessionToken::generate() {
        Ok(token) => token.expose_hex(),
        Err(_) => return false,
    };
    run_macos_vm_smoke_worker_with_runtime_share_identity_and_marker_token(
        system_image_manifest,
        runtime_share,
        console,
        marker_name,
        marker_token.as_str(),
        runtime_share_identity,
    )
}

/// Run the private macOS VM-entry worker with a marker nonce received from
/// its parent over the one-shot stdin handoff.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
#[must_use]
pub fn run_macos_vm_smoke_worker_with_runtime_share_identity_from_stdin(
    system_image_manifest: &Path,
    runtime_share: &Path,
    console: &Path,
    marker_name: &str,
    runtime_share_identity: Option<(u64, u64)>,
) -> bool {
    let marker_token = match macos_vm_marker::read_marker_token_from_stdin() {
        Ok(token) => token,
        Err(_) => return false,
    };
    run_macos_vm_smoke_worker_with_runtime_share_identity_and_marker_token(
        system_image_manifest,
        runtime_share,
        console,
        marker_name,
        marker_token.as_str(),
        runtime_share_identity,
    )
}

/// Run the private macOS VM-entry worker with an explicit, validated marker
/// nonce. This remains hidden because the nonce is part of the shim-only
/// parent/worker protocol rather than the public SDK.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
#[must_use]
pub fn run_macos_vm_smoke_worker_with_runtime_share_identity_and_marker_token(
    system_image_manifest: &Path,
    runtime_share: &Path,
    console: &Path,
    marker_name: &str,
    marker_token: &str,
    runtime_share_identity: Option<(u64, u64)>,
) -> bool {
    let Some(runtime_share_identity) = runtime_share_identity else {
        return false;
    };
    macos_vm_smoke::run_worker(
        system_image_manifest,
        runtime_share,
        console,
        marker_name,
        marker_token,
        Some(runtime_share_identity),
    )
}

/// Private macOS guest-agent worker handoff.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub struct MacosAgentVmWorkerHandoff<'a> {
    system_image_manifest: &'a Path,
    runtime_share: &'a Path,
    runtime_share_identity: Option<(u64, u64)>,
    runtime_state_identity: Option<(u64, u64)>,
    guest_token_file: &'a str,
    console: &'a Path,
    console_identity: Option<(u64, u64)>,
    socket: &'a Path,
    guest_recovery_report: Option<&'a str>,
    transport_qualification: Option<&'a a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
impl<'a> MacosAgentVmWorkerHandoff<'a> {
    #[must_use]
    pub const fn new(
        system_image_manifest: &'a Path,
        runtime_share: &'a Path,
        guest_token_file: &'a str,
        console: &'a Path,
        socket: &'a Path,
    ) -> Self {
        Self {
            system_image_manifest,
            runtime_share,
            runtime_share_identity: None,
            runtime_state_identity: None,
            guest_token_file,
            console,
            console_identity: None,
            socket,
            guest_recovery_report: None,
            transport_qualification: None,
        }
    }

    #[must_use]
    pub const fn with_console_identity(mut self, device: u64, inode: u64) -> Self {
        self.console_identity = Some((device, inode));
        self
    }

    /// Bind the worker to the exact runtime-share directory opened by its
    /// launching process.
    #[must_use]
    pub const fn with_runtime_share_identity(mut self, device: u64, inode: u64) -> Self {
        self.runtime_share_identity = Some((device, inode));
        self
    }

    /// Bind the worker to the exact `run/` state directory opened by its
    /// launching process.
    #[must_use]
    pub const fn with_runtime_state_identity(mut self, device: u64, inode: u64) -> Self {
        self.runtime_state_identity = Some((device, inode));
        self
    }

    #[must_use]
    pub const fn with_guest_recovery_report(mut self, path: Option<&'a str>) -> Self {
        self.guest_recovery_report = path;
        self
    }

    #[must_use]
    pub const fn with_transport_qualification(
        mut self,
        request: Option<&'a a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
    ) -> Self {
        self.transport_qualification = request;
        self
    }
}

/// Run one exact private macOS guest-agent worker handoff.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
#[must_use]
pub fn run_macos_agent_vm_worker_handoff(handoff: MacosAgentVmWorkerHandoff<'_>) -> bool {
    let MacosAgentVmWorkerHandoff {
        system_image_manifest,
        runtime_share,
        runtime_share_identity,
        runtime_state_identity,
        guest_token_file,
        console,
        console_identity,
        socket,
        guest_recovery_report,
        transport_qualification,
    } = handoff;
    let (Some(runtime_share_identity), Some(runtime_state_identity)) =
        (runtime_share_identity, runtime_state_identity)
    else {
        return false;
    };
    macos_agent_smoke::run_worker(macos_agent_smoke::MacosAgentVmWorkerConfig {
        system_image_manifest,
        runtime_share,
        runtime_share_identity: Some(runtime_share_identity),
        runtime_state_identity: Some(runtime_state_identity),
        guest_token_file,
        console,
        console_identity,
        socket,
        guest_recovery_report,
        transport_qualification,
    })
}

/// Run the private macOS guest-agent VM worker without a host console identity.
///
/// This compatibility entry point is retained for existing hidden shim callers.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
#[must_use]
pub fn run_macos_agent_vm_worker(
    system_image_manifest: &Path,
    runtime_share: &Path,
    guest_token_file: &str,
    console: &Path,
    socket: &Path,
    guest_recovery_report: Option<&str>,
    transport_qualification: Option<&a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
) -> bool {
    let (runtime_share_identity, runtime_state_identity) =
        match macos_runtime_share_identities(runtime_share) {
            Some(identities) => identities,
            None => return false,
        };
    run_macos_agent_vm_worker_handoff(
        MacosAgentVmWorkerHandoff::new(
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            socket,
        )
        .with_runtime_share_identity(runtime_share_identity.0, runtime_share_identity.1)
        .with_runtime_state_identity(runtime_state_identity.0, runtime_state_identity.1)
        .with_guest_recovery_report(guest_recovery_report)
        .with_transport_qualification(transport_qualification),
    )
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
pub struct LinuxAgentVmWorkerHandoff<'a> {
    system_image_manifest: &'a Path,
    runtime_share: &'a Path,
    runtime_share_identity: Option<(u64, u64)>,
    runtime_state_identity: Option<(u64, u64)>,
    guest_token_file: &'a str,
    console: &'a Path,
    console_identity: Option<(u64, u64)>,
    socket: &'a Path,
    guest_recovery_report: Option<&'a str>,
    vm_attachment_manifest_sha256: Option<&'a str>,
    transport_qualification: Option<&'a a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
    qualify_kvm_post_probe_failure: bool,
    qualify_kvm_compatibility_drift: Option<&'a str>,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
impl<'a> LinuxAgentVmWorkerHandoff<'a> {
    #[must_use]
    pub const fn new(
        system_image_manifest: &'a Path,
        runtime_share: &'a Path,
        guest_token_file: &'a str,
        console: &'a Path,
        socket: &'a Path,
    ) -> Self {
        Self {
            system_image_manifest,
            runtime_share,
            runtime_share_identity: None,
            runtime_state_identity: None,
            guest_token_file,
            console,
            console_identity: None,
            socket,
            guest_recovery_report: None,
            vm_attachment_manifest_sha256: None,
            transport_qualification: None,
            qualify_kvm_post_probe_failure: false,
            qualify_kvm_compatibility_drift: None,
        }
    }

    /// Bind the worker to the host's atomically reserved console inode.
    #[must_use]
    pub const fn with_console_identity(mut self, device: u64, inode: u64) -> Self {
        self.console_identity = Some((device, inode));
        self
    }

    /// Bind the worker to the exact runtime-share directory opened by its
    /// launching process.
    #[must_use]
    pub const fn with_runtime_share_identity(mut self, device: u64, inode: u64) -> Self {
        self.runtime_share_identity = Some((device, inode));
        self
    }

    /// Bind the worker to the exact `run/` state directory opened by its
    /// launching process.
    #[must_use]
    pub const fn with_runtime_state_identity(mut self, device: u64, inode: u64) -> Self {
        self.runtime_state_identity = Some((device, inode));
        self
    }

    #[must_use]
    pub const fn with_guest_recovery_report(mut self, path: Option<&'a str>) -> Self {
        self.guest_recovery_report = path;
        self
    }

    #[must_use]
    pub const fn with_vm_attachment_manifest_sha256(mut self, digest: Option<&'a str>) -> Self {
        self.vm_attachment_manifest_sha256 = digest;
        self
    }

    #[must_use]
    pub const fn with_transport_qualification(
        mut self,
        request: Option<&'a a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
    ) -> Self {
        self.transport_qualification = request;
        self.qualify_kvm_compatibility_drift = None;
        self
    }

    #[must_use]
    pub const fn with_kvm_post_probe_failure(mut self) -> Self {
        self.qualify_kvm_post_probe_failure = true;
        self.qualify_kvm_compatibility_drift = None;
        self
    }

    #[must_use]
    pub const fn with_kvm_compatibility_drift(mut self, case: &'a str) -> Self {
        self.transport_qualification = None;
        self.qualify_kvm_post_probe_failure = false;
        self.qualify_kvm_compatibility_drift = Some(case);
        self
    }
}

/// Run one exact private Linux KVM guest-agent worker handoff.
///
/// This is exported only for the hidden shim process boundary.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
#[must_use]
pub fn run_linux_agent_vm_worker_handoff(handoff: LinuxAgentVmWorkerHandoff<'_>) -> bool {
    let LinuxAgentVmWorkerHandoff {
        system_image_manifest,
        runtime_share,
        runtime_share_identity,
        runtime_state_identity,
        guest_token_file,
        console,
        console_identity,
        socket,
        guest_recovery_report,
        vm_attachment_manifest_sha256,
        transport_qualification,
        qualify_kvm_post_probe_failure,
        qualify_kvm_compatibility_drift,
    } = handoff;
    let (Some(runtime_share_identity), Some(runtime_state_identity)) =
        (runtime_share_identity, runtime_state_identity)
    else {
        return false;
    };
    linux_agent_smoke::run_worker(linux_agent_smoke::LinuxAgentVmWorkerConfig {
        system_image_manifest,
        runtime_share,
        runtime_share_identity: Some(runtime_share_identity),
        runtime_state_identity: Some(runtime_state_identity),
        guest_token_file,
        console,
        console_identity,
        socket,
        guest_recovery_report,
        vm_attachment_manifest_sha256,
        transport_qualification,
        qualify_kvm_post_probe_failure,
        qualify_kvm_compatibility_drift,
    })
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn linux_runtime_share_identities(path: &Path) -> Option<((u64, u64), (u64, u64))> {
    let share = linux_runtime_share::LinuxRuntimeShare::open(path).ok()?;
    Some((share.identity(), share.state_identity()))
}

/// Run the private Linux KVM guest-agent VM worker.
///
/// This compatibility entry point omits production VM attachments.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
#[must_use]
pub fn run_linux_agent_vm_worker(
    system_image_manifest: &Path,
    runtime_share: &Path,
    guest_token_file: &str,
    console: &Path,
    socket: &Path,
    guest_recovery_report: Option<&str>,
    transport_qualification: Option<&a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
) -> bool {
    let (runtime_share_identity, runtime_state_identity) =
        match linux_runtime_share_identities(runtime_share) {
            Some(identities) => identities,
            None => return false,
        };
    run_linux_agent_vm_worker_handoff(
        LinuxAgentVmWorkerHandoff::new(
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            socket,
        )
        .with_runtime_share_identity(runtime_share_identity.0, runtime_share_identity.1)
        .with_runtime_state_identity(runtime_state_identity.0, runtime_state_identity.1)
        .with_guest_recovery_report(guest_recovery_report)
        .with_transport_qualification(transport_qualification),
    )
}

/// Run the private Linux KVM guest-agent worker with the qualification-only
/// post-probe failure enabled.
///
/// This is exported only for the hidden shim process boundary.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
#[must_use]
pub fn run_linux_agent_vm_worker_with_kvm_post_probe_failure(
    system_image_manifest: &Path,
    runtime_share: &Path,
    guest_token_file: &str,
    console: &Path,
    socket: &Path,
    guest_recovery_report: Option<&str>,
    transport_qualification: Option<&a3s_oci_agent_protocol::AgentTransportQualificationRequest>,
) -> bool {
    let (runtime_share_identity, runtime_state_identity) =
        match linux_runtime_share_identities(runtime_share) {
            Some(identities) => identities,
            None => return false,
        };
    run_linux_agent_vm_worker_handoff(
        LinuxAgentVmWorkerHandoff::new(
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            socket,
        )
        .with_runtime_share_identity(runtime_share_identity.0, runtime_share_identity.1)
        .with_runtime_state_identity(runtime_state_identity.0, runtime_state_identity.1)
        .with_guest_recovery_report(guest_recovery_report)
        .with_transport_qualification(transport_qualification)
        .with_kvm_post_probe_failure(),
    )
}

/// Run the private Linux KVM guest-agent worker with a qualification-only
/// compatibility mutation barrier before KVM-device access.
///
/// This is exported only for the hidden shim process boundary.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[doc(hidden)]
#[must_use]
pub fn run_linux_agent_vm_worker_with_compatibility_drift(
    system_image_manifest: &Path,
    runtime_share: &Path,
    guest_token_file: &str,
    console: &Path,
    socket: &Path,
    guest_recovery_report: Option<&str>,
    case: &str,
) -> bool {
    let (runtime_share_identity, runtime_state_identity) =
        match linux_runtime_share_identities(runtime_share) {
            Some(identities) => identities,
            None => return false,
        };
    run_linux_agent_vm_worker_handoff(
        LinuxAgentVmWorkerHandoff::new(
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            socket,
        )
        .with_runtime_share_identity(runtime_share_identity.0, runtime_share_identity.1)
        .with_runtime_state_identity(runtime_state_identity.0, runtime_state_identity.1)
        .with_guest_recovery_report(guest_recovery_report)
        .with_kvm_compatibility_drift(case),
    )
}

pub(crate) fn fallback_config() -> VmConfig {
    VmConfig {
        vcpus: 1,
        memory_mib: 512,
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn vm_smoke_windows(rootfs: &Path, console: &Path, config: VmConfig) -> KrunVmSmokeReport {
    use std::fs;

    use context::KrunContext;

    let mut report = KrunVmSmokeReport::initial(HostPlatform::Windows, config);
    let rootfs = match rootfs.canonicalize() {
        Ok(path) if path.is_dir() => path,
        Ok(path) => {
            report.reason = Some(format!("rootfs is not a directory: {}", path.display()));
            return report;
        }
        Err(error) => {
            report.reason = Some(format!(
                "failed to resolve rootfs {}: {error}",
                rootfs.display()
            ));
            return report;
        }
    };

    let console_parent = match console.parent() {
        Some(parent) => parent,
        None => {
            report.reason = Some(format!(
                "console path has no parent directory: {}",
                console.display()
            ));
            return report;
        }
    };
    if let Err(error) = fs::create_dir_all(console_parent) {
        report.reason = Some(format!(
            "failed to create console directory {}: {error}",
            console_parent.display()
        ));
        return report;
    }

    let marker_name = format!(".a3s-oci-vm-smoke-{}", std::process::id());
    let marker_host_path = rootfs.join(&marker_name);
    if marker_host_path.exists() {
        report.reason = Some(format!(
            "refusing to overwrite an existing smoke marker: {}",
            marker_host_path.display()
        ));
        return report;
    }

    let mut context = match KrunContext::create() {
        Ok(context) => {
            report.context_created = true;
            context
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };

    if let Err(error) = context.set_vm_config(config) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.vm_configured = true;

    if let Err(error) = context.set_root(&rootfs) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.rootfs_configured = true;

    if let Err(error) = context.set_workdir("/") {
        report.reason = Some(error.to_string());
        return report;
    }

    let marker_guest_path = format!("/{marker_name}");
    let command = format!(
        "printf '%s\\n' '{VM_SMOKE_TOKEN}' > '{marker_guest_path}' && \
         printf '%s\\n' '{VM_SMOKE_TOKEN}'"
    );
    let arguments = vec!["-c".to_string(), command];
    if let Err(error) = context.set_exec("/bin/sh", &arguments, &[]) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.workload_configured = true;

    if let Err(error) = context.set_console_output(console) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.console_configured = true;

    // A3S's Windows libkrun build exposes an opt-in return path so this
    // one-shot diagnostic can verify guest effects before the shim exits.
    std::env::set_var("LIBKRUN_WINDOWS_RETURN_ON_EXIT", "1");
    match context.start_enter() {
        Ok(exit_code) => {
            report.vm_entered = true;
            report.guest_exit_code = Some(exit_code);
            if exit_code != 0 {
                report.reason = Some(format!(
                    "guest workload returned non-zero exit code {exit_code}"
                ));
            }
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    }

    report.console_created = console.is_file();
    match fs::read_to_string(&marker_host_path) {
        Ok(contents) if contents == format!("{VM_SMOKE_TOKEN}\n") => {
            report.marker_verified = true;
        }
        Ok(contents) => {
            report.reason = Some(format!(
                "guest marker had unexpected contents ({} bytes)",
                contents.len()
            ));
        }
        Err(error) => {
            report.reason = Some(format!(
                "failed to read guest marker {}: {error}",
                marker_host_path.display()
            ));
        }
    }

    if marker_host_path.exists() {
        match fs::remove_file(&marker_host_path) {
            Ok(()) => report.marker_removed = true,
            Err(error) => {
                report.reason.get_or_insert_with(|| {
                    format!(
                        "failed to remove guest marker {}: {error}",
                        marker_host_path.display()
                    )
                });
            }
        }
    }

    if report.guest_exit_code == Some(0)
        && report.marker_verified
        && report.marker_removed
        && report.console_created
    {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    } else if report.reason.is_none() {
        report.reason = Some("guest workload did not satisfy the smoke-test contract".into());
    }

    report
}

#[cfg(test)]
mod tests {
    use super::{fallback_config, VmConfig};

    #[test]
    fn rejects_zero_resources() {
        assert!(VmConfig::new(0, 128).is_err());
        assert!(VmConfig::new(1, 0).is_err());
    }

    #[test]
    fn accepts_certified_smoke_configuration() {
        let config = VmConfig::new(1, 128).expect("smoke config must be valid");
        assert_eq!(config.vcpus(), 1);
        assert_eq!(config.memory_mib(), 128);
    }

    #[test]
    fn fallback_config_matches_vm_smoke_resources() {
        let config = fallback_config();
        assert_eq!(config.vcpus(), 1);
        assert_eq!(config.memory_mib(), 512);
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn rejects_uncertified_windows_smp_configuration() {
        let error = VmConfig::new(2, 128).expect_err("Windows SMP must remain gated");
        assert!(error.to_string().contains("exactly 1 vCPU"));
    }
}
