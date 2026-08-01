use std::path::Path;

use a3s_oci_agent_protocol::{AgentVsockEndpoint, SessionToken};
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
        }
    }
}

/// Boot the fixed Linux guest-agent path through the shim-local libkrun context.
#[must_use]
pub fn agent_vm_smoke(
    rootfs: &Path,
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
        let _ = socket_path;
        let Some(guest_token_file) = handoff.guest_token_file else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Windows, config);
            report.reason = Some("the Windows guest-agent bridge requires a token file".into());
            return report;
        };
        let _ = token;
        agent_vm_smoke_windows(
            rootfs,
            handoff.runtime_share,
            console,
            endpoint,
            guest_token_file,
            handoff.guest_recovery_report,
            config,
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let _ = (
            handoff.runtime_share,
            handoff.guest_token_file,
            handoff.guest_recovery_report,
        );
        let Some(socket_path) = socket_path else {
            let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Macos, config);
            report.reason = Some("the macOS guest-agent bridge requires a Unix socket path".into());
            return report;
        };
        crate::macos_agent_smoke::agent_vm_smoke(
            rootfs,
            console,
            endpoint,
            socket_path,
            token,
            config,
        )
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    {
        let _ = (
            rootfs,
            console,
            endpoint,
            socket_path,
            token,
            handoff.runtime_share,
            handoff.guest_token_file,
            handoff.guest_recovery_report,
        );
        KrunAgentVmSmokeReport::unsupported(HostPlatform::current(), config)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn agent_vm_smoke_windows(
    rootfs: &Path,
    runtime_share: Option<&Path>,
    console: &Path,
    endpoint: &AgentVsockEndpoint,
    guest_token_file: &str,
    guest_recovery_report: Option<&str>,
    config: VmConfig,
) -> KrunAgentVmSmokeReport {
    use std::fs;

    use crate::context::KrunContext;
    let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Windows, config);
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
    let agent = rootfs.join("usr").join("bin").join("a3s-oci-agent");
    if !agent.is_file() {
        report.reason = Some(format!(
            "fixed guest agent is not a regular file: {}",
            agent.display()
        ));
        return report;
    }
    report.agent_binary_present = true;

    let runtime_share = match runtime_share {
        Some(path) => match path.canonicalize() {
            Ok(path) if path.is_dir() => Some(path),
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
                    path.display()
                ));
                return report;
            }
        },
        None => None,
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
    if let Some(runtime_share) = &runtime_share {
        if let Err(error) = context.add_virtiofs(AGENT_RUNTIME_SHARE_TAG, runtime_share) {
            report.reason = Some(error.to_string());
            return report;
        }
        report.runtime_share_configured = true;
    }
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
    if runtime_share.is_some() {
        environment.push((
            AGENT_RUNTIME_SHARE_ENV.to_string(),
            AGENT_RUNTIME_SHARE_TAG.to_string(),
        ));
    }
    if let Some(path) = guest_recovery_report {
        environment.push((AGENT_RECOVERY_REPORT_ENV.to_string(), path.to_string()));
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

    std::env::set_var("LIBKRUN_WINDOWS_RETURN_ON_EXIT", "1");
    match context.start_enter() {
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
