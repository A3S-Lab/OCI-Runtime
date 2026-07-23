use std::path::Path;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use a3s_oci_agent_protocol::AGENT_SESSION_TOKEN_ENV;
use a3s_oci_agent_protocol::{AgentVsockEndpoint, SessionToken};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;

use crate::{fallback_config, KrunAgentVmSmokeReport, VmConfig};

/// Boot the fixed Linux guest-agent path through the shim-local libkrun context.
#[must_use]
pub fn agent_vm_smoke(
    rootfs: &Path,
    console: &Path,
    endpoint: &AgentVsockEndpoint,
    token: &SessionToken,
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
        agent_vm_smoke_windows(rootfs, console, endpoint, token, config)
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (rootfs, console, endpoint, token);
        KrunAgentVmSmokeReport::unsupported(HostPlatform::current(), config)
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn agent_vm_smoke_windows(
    rootfs: &Path,
    console: &Path,
    endpoint: &AgentVsockEndpoint,
    token: &SessionToken,
    config: VmConfig,
) -> KrunAgentVmSmokeReport {
    use std::fs;

    use crate::context::KrunContext;
    use zeroize::Zeroizing;

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
    if let Err(error) = context.set_agent_vsock(endpoint) {
        report.reason = Some(error.to_string());
        return report;
    }
    report.agent_vsock_configured = true;
    if let Err(error) = context.set_workdir("/") {
        report.reason = Some(error.to_string());
        return report;
    }

    let token_hex = token.expose_hex();
    let environment = Zeroizing::new(vec![(
        AGENT_SESSION_TOKEN_ENV.to_string(),
        token_hex.as_str().to_string(),
    )]);
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
