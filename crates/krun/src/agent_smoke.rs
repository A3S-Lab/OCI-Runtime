use std::path::Path;

use a3s_oci_agent_protocol::{
    AgentTransportQualificationRequest, AgentVsockEndpoint, SessionToken,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use a3s_oci_agent_protocol::{
    AGENT_RECOVERY_REPORT_ENV, AGENT_RUNTIME_SHARE_ENV, AGENT_RUNTIME_SHARE_TAG,
    AGENT_SESSION_TOKEN_FILE_ENV,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;

use crate::{fallback_config, KrunAgentVmSmokeReport, VmConfig};

/// Optional host/guest handoff paths used by a driver-owned utility VM.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentVmHandoff<'a> {
    runtime_share: Option<&'a Path>,
    guest_token_file: Option<&'a str>,
    guest_recovery_report: Option<&'a str>,
    transport_qualification: Option<&'a AgentTransportQualificationRequest>,
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    qualify_kvm_post_probe_failure: bool,
}

impl<'a> AgentVmHandoff<'a> {
    /// Bind an optional runtime share to its one-time guest handoff paths.
    #[must_use]
    pub const fn new(
        runtime_share: Option<&'a Path>,
        guest_token_file: Option<&'a str>,
        guest_recovery_report: Option<&'a str>,
    ) -> Self {
        Self {
            runtime_share,
            guest_token_file,
            guest_recovery_report,
            transport_qualification: None,
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            qualify_kvm_post_probe_failure: false,
        }
    }

    /// Attach an explicit guest transport qualification request.
    #[must_use]
    pub const fn with_transport_qualification(
        mut self,
        request: Option<&'a AgentTransportQualificationRequest>,
    ) -> Self {
        self.transport_qualification = request;
        self
    }

    /// Stop a Linux KVM qualification after real device/API verification and
    /// before the native VM-entry function is called.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[must_use]
    pub const fn with_kvm_post_probe_failure(mut self, enabled: bool) -> Self {
        self.qualify_kvm_post_probe_failure = enabled;
        self
    }
}

/// Boot the fixed Linux guest-agent path through the shim-local libkrun context.
#[must_use]
pub fn agent_vm_smoke(
    rootfs: &Path,
    system_image_manifest: Option<&Path>,
    console: &Path,
    endpoint: &AgentVsockEndpoint,
    socket_path: Option<&Path>,
    token: &SessionToken,
    handoff: AgentVmHandoff<'_>,
) -> KrunAgentVmSmokeReport {
    let config = match VmConfig::new(1, 512) {
        Ok(config) => config,
        Err(error) => {
            let mut report =
                KrunAgentVmSmokeReport::initial(HostPlatform::current(), fallback_config());
            report.reason = Some(error.to_string());
            return report;
        }
    };

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        let _ = (socket_path, token);
        let Some(system_image_manifest) = system_image_manifest else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Windows, config);
            report.reason =
                Some("the Windows guest-agent bridge requires a system-image manifest".into());
            return report;
        };
        agent_vm_smoke_windows(
            rootfs,
            system_image_manifest,
            console,
            endpoint,
            handoff,
            config,
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let Some(system_image_manifest) = system_image_manifest else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason =
                Some("the macOS guest-agent bridge requires a system-image manifest".into());
            return report;
        };
        let Some(runtime_share) = handoff.runtime_share else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason =
                Some("the macOS guest-agent bridge requires a writable runtime share".into());
            return report;
        };
        let Some(guest_token_file) = handoff.guest_token_file else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason =
                Some("the macOS guest-agent bridge requires a protected guest token file".into());
            return report;
        };
        let _ = (rootfs, token);
        let Some(socket_path) = socket_path else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason = Some("the macOS guest-agent bridge requires a Unix socket path".into());
            return report;
        };
        crate::macos_agent_smoke::agent_vm_smoke(crate::macos_agent_smoke::MacosAgentVmConfig {
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            endpoint,
            socket: socket_path,
            guest_recovery_report: handoff.guest_recovery_report,
            transport_qualification: handoff.transport_qualification,
            vm: config,
        })
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let Some(system_image_manifest) = system_image_manifest else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Linux, config);
            report.reason =
                Some("the Linux KVM guest-agent bridge requires a system-image manifest".into());
            return report;
        };
        let Some(runtime_share) = handoff.runtime_share else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Linux, config);
            report.reason =
                Some("the Linux KVM guest-agent bridge requires a protected runtime share".into());
            return report;
        };
        let Some(guest_token_file) = handoff.guest_token_file else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Linux, config);
            report.reason = Some(
                "the Linux KVM guest-agent bridge requires a protected guest token file".into(),
            );
            return report;
        };
        let Some(socket_path) = socket_path else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Linux, config);
            report.reason =
                Some("the Linux KVM guest-agent bridge requires a Unix socket path".into());
            return report;
        };
        let _ = (rootfs, token);
        crate::linux_agent_smoke::agent_vm_smoke(crate::linux_agent_smoke::LinuxAgentVmConfig {
            system_image_manifest,
            runtime_share,
            guest_token_file,
            console,
            endpoint,
            socket: socket_path,
            guest_recovery_report: handoff.guest_recovery_report,
            transport_qualification: handoff.transport_qualification,
            qualify_kvm_post_probe_failure: handoff.qualify_kvm_post_probe_failure,
            vm: config,
        })
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
        let _ = (
            rootfs,
            system_image_manifest,
            console,
            endpoint,
            socket_path,
            token,
            handoff.runtime_share,
            handoff.guest_token_file,
            handoff.guest_recovery_report,
            handoff.transport_qualification,
        );
        KrunAgentVmSmokeReport::unsupported(HostPlatform::current(), config)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn agent_vm_smoke_windows(
    rootfs: &Path,
    system_image_manifest: &Path,
    console: &Path,
    endpoint: &AgentVsockEndpoint,
    handoff: AgentVmHandoff<'_>,
    config: VmConfig,
) -> KrunAgentVmSmokeReport {
    use std::fs;

    use crate::context::KrunContext;
    use crate::windows_system_image::WindowsSystemImage;
    let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Windows, config);
    let Some(guest_token_file) = handoff.guest_token_file else {
        report.reason = Some("the Windows guest-agent bridge requires a token file".into());
        return report;
    };
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
    let system_image = match WindowsSystemImage::load(system_image_manifest) {
        Ok(image) => image,
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };
    report.agent_binary_present = true;

    let Some(runtime_share) = handoff.runtime_share else {
        report.reason =
            Some("the Windows guest-agent bridge requires a writable runtime share".into());
        return report;
    };
    let runtime_share = match runtime_share.canonicalize() {
        Ok(path) if path.is_dir() => path,
        Ok(path) => {
            report.reason = Some(format!(
                "runtime share is not a directory: {}",
                path.display()
            ));
            return report;
        }
        Err(error) => {
            report.reason = Some(format!(
                "failed to resolve runtime share {}: {error}",
                runtime_share.display()
            ));
            return report;
        }
    };

    let Some(console_parent) = console.parent() else {
        report.reason = Some(format!(
            "console path has no parent directory: {}",
            console.display()
        ));
        return report;
    };
    if let Err(error) = fs::create_dir_all(console_parent) {
        report.reason = Some(format!(
            "failed to create console directory {}: {error}",
            console_parent.display()
        ));
        return report;
    }

    let handles_before = match current_process_handle_count() {
        Ok(count) => count,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    report.windows_handles_before_vm = Some(handles_before);

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
    if let Err(error) = context.set_root_disk(system_image.image_path()) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.rootfs_configured = true;
    if let Err(error) = context.add_virtiofs(AGENT_RUNTIME_SHARE_TAG, &runtime_share) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.runtime_share_configured = true;
    if let Err(error) = context.set_agent_vsock(endpoint) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;
    if let Err(error) = context.set_workdir("/") {
        report.reason = Some(error.to_string());
        return report;
    }

    let mut environment = vec![(
        AGENT_SESSION_TOKEN_FILE_ENV.to_string(),
        guest_token_file.to_string(),
    )];
    environment.push((
        AGENT_RUNTIME_SHARE_ENV.to_string(),
        AGENT_RUNTIME_SHARE_TAG.to_string(),
    ));
    if let Some(path) = handoff.guest_recovery_report {
        environment.push((AGENT_RECOVERY_REPORT_ENV.to_string(), path.to_string()));
    }
    if let Some(request) = handoff.transport_qualification {
        let encoded = match request.to_json() {
            Ok(encoded) => encoded,
            Err(error) => {
                report.reason = Some(error.to_string());
                return report;
            }
        };
        environment.push((
            a3s_oci_agent_protocol::AGENT_TRANSPORT_QUALIFICATION_ENV.to_string(),
            encoded,
        ));
    }
    if let Err(error) = context.set_exec("/usr/bin/a3s-oci-agent", &[], &environment) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.workload_configured = true;
    if let Err(error) = context.set_console_output(console) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.console_configured = true;

    if let Err(error) = system_image.reverify() {
        report.reason = Some(error.to_string());
        return report;
    }
    report.windows_boot_assets = Some(system_image.evidence());

    std::env::set_var("LIBKRUN_WINDOWS_RETURN_ON_EXIT", "1");
    let enter_result = context.start_enter();
    let handles_after = match current_process_handle_count() {
        Ok(count) => count,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    report.windows_handles_after_vm = Some(handles_after);
    report.windows_handle_inventory_restored = Some(handles_after == handles_before);
    if handles_after != handles_before {
        report.reason = Some(format!(
            "Windows handle inventory changed across VM entry before shim teardown: \
             {handles_before} to {handles_after}"
        ));
        return report;
    }

    match enter_result {
        Ok(exit_code) => {
            report.vm_entered = true;
            report.guest_exit_code = Some(exit_code);
            if exit_code != 0 {
                report.reason = Some(format!(
                    "guest agent returned non-zero exit code {exit_code}"
                ));
            }
        }
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    }
    report.console_created = console.is_file();
    if report.guest_exit_code == Some(0) && report.console_created {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    } else if report.reason.is_none() {
        report.reason = Some("guest agent did not satisfy the shim smoke contract".into());
    }
    report
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn current_process_handle_count() -> Result<u32, String> {
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

    let mut count = 0;
    // SAFETY: `GetCurrentProcess` returns a process pseudo-handle valid in this
    // process and `count` is a writable `u32` for the duration of the call.
    let succeeded = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
    if succeeded == 0 {
        return Err(format!(
            "failed to capture the in-process Windows handle inventory: {}",
            std::io::Error::last_os_error()
        ));
    }
    if count == 0 {
        return Err("Windows reported an empty in-process handle inventory".to_string());
    }
    Ok(count)
}
