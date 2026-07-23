use std::path::Path;

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
use a3s_oci_core::HostPlatform;

use crate::report::AgentVmSmokeReport;

/// Boot the fixed guest-agent path and verify the authenticated host-to-guest path.
///
/// The runtime binds the protected endpoint before starting the isolated
/// libkrun shim. The endpoint accepts only that shim process, then protocol
/// negotiation authenticates the supplied guest agent with a one-time token.
#[must_use]
pub async fn agent_vm_smoke(shim: &Path, rootfs: &Path, console: &Path) -> AgentVmSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        agent_vm_smoke_windows(shim, rootfs, console).await
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    {
        let _ = (shim, rootfs, console);
        AgentVmSmokeReport::unsupported(HostPlatform::current())
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{ExitStatus, Stdio};
    use std::time::Duration;

    use a3s_oci_agent_protocol::{
        AgentClient, AgentVsockEndpoint, SessionToken, AGENT_PROTOCOL_VERSION_MAX,
        AGENT_SESSION_TOKEN_ENV,
    };
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use serde_json::Value;
    use tokio::process::Command;
    use tokio::time::timeout;

    use crate::agent_pipe::WindowsAgentPipeListener;
    use crate::agent_smoke_process::{
        BoundedOutput, CompletedShim, RunningShim, MAX_CAPTURE_BYTES,
    };
    use crate::report::AgentVmSmokeReport;

    const BRIDGE_TIMEOUT: Duration = Duration::from_secs(60);
    const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);
    const MAX_DIAGNOSTIC_CHARS: usize = 2_048;
    const SHIM_REPORT_SCHEMA_VERSION: &str = "a3s.oci.krun-agent-vm-smoke.v1";
    const SHIM_TRUE_FIELDS: &[&str] = &[
        "runtime_bundle_loaded",
        "context_created",
        "vm_configured",
        "rootfs_configured",
        "agent_binary_present",
        "agent_vsock_configured",
        "workload_configured",
        "console_configured",
        "vm_entered",
        "console_created",
    ];

    pub(super) async fn run(shim: &Path, rootfs: &Path, console: &Path) -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Windows);
        let shim = match canonical_file(shim, "libkrun shim").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        let rootfs = match canonical_directory(rootfs, "guest rootfs").await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };
        let console = match prepare_console_path(console).await {
            Ok(path) => path,
            Err(reason) => return failed(report, reason),
        };

        let endpoint = match AgentVsockEndpoint::generate() {
            Ok(endpoint) => endpoint,
            Err(error) => return failed(report, error.to_string()),
        };
        let listener = match WindowsAgentPipeListener::bind(endpoint.clone()) {
            Ok(listener) => {
                report.endpoint_bound = true;
                listener
            }
            Err(error) => return failed(report, error.to_string()),
        };
        let token = match SessionToken::generate() {
            Ok(token) => token,
            Err(error) => return failed(report, error.to_string()),
        };

        let encoded_token = token.expose_hex();
        let mut command = Command::new(&shim);
        command
            .arg("agent-vm-smoke")
            .arg("--rootfs")
            .arg(&rootfs)
            .arg("--console")
            .arg(&console)
            .arg("--pipe-name")
            .arg(endpoint.pipe_name())
            .env(AGENT_SESSION_TOKEN_ENV, encoded_token.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut running = match RunningShim::spawn(&mut command) {
            Ok(running) => running,
            Err(error) => {
                return failed(
                    report,
                    format!("failed to start libkrun shim {}: {error}", shim.display()),
                );
            }
        };
        drop(command);
        drop(encoded_token);
        report.shim_spawned = true;

        let Some(shim_process_id) = running.process_id() else {
            let completed = running.terminate_and_collect().await;
            apply_completed(&mut report, &completed);
            return failed_with_output(
                report,
                "spawned libkrun shim has no live process ID",
                &completed,
            );
        };
        report.shim_process_id = Some(shim_process_id);

        enum BridgeOutcome {
            Connected(a3s_oci_sdk::Result<tokio::net::windows::named_pipe::NamedPipeServer>),
            ShimExited(io::Result<ExitStatus>),
        }

        let accept = listener.accept_from_process(shim_process_id);
        tokio::pin!(accept);
        let bridge_outcome = timeout(BRIDGE_TIMEOUT, async {
            tokio::select! {
                result = &mut accept => BridgeOutcome::Connected(result),
                status = running.child_mut().wait() => BridgeOutcome::ShimExited(status),
            }
        })
        .await;
        let stream = match bridge_outcome {
            Ok(BridgeOutcome::Connected(Ok(stream))) => {
                report.shim_client_verified = true;
                stream
            }
            Ok(BridgeOutcome::Connected(Err(error))) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return failed_with_output(report, &error.to_string(), &completed);
            }
            Ok(BridgeOutcome::ShimExited(status)) => {
                let completed = running.collect_after_wait(status).await;
                apply_completed(&mut report, &completed);
                return failed_with_output(
                    report,
                    "libkrun shim exited before connecting the authenticated agent bridge",
                    &completed,
                );
            }
            Err(_) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return failed_with_output(
                    report,
                    "timed out waiting for the libkrun shim to connect the agent bridge",
                    &completed,
                );
            }
        };

        let client = match timeout(NEGOTIATION_TIMEOUT, AgentClient::connect(stream, token)).await {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return failed_with_output(report, &error.to_string(), &completed);
            }
            Err(_) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return failed_with_output(
                    report,
                    "timed out authenticating and negotiating with the fixed guest agent",
                    &completed,
                );
            }
        };
        report.protocol_negotiated = true;
        report.selected_protocol = Some(client.hello().selected_version());
        report.agent_version = Some(client.hello().capabilities().agent_version().to_string());
        report.guest_architecture = Some(client.hello().capabilities().architecture().to_string());
        report.advertised_operations = client.hello().capabilities().operations().to_vec();
        drop(client);

        let completed = running.wait_and_collect().await;
        apply_completed(&mut report, &completed);
        if completed.timed_out {
            return failed_with_output(
                report,
                "guest agent did not exit after the host closed the negotiated connection",
                &completed,
            );
        }
        if !completed.status.as_ref().is_some_and(ExitStatus::success) {
            return failed_with_output(
                report,
                "libkrun shim returned an unsuccessful status",
                &completed,
            );
        }
        if report.selected_protocol != Some(AGENT_PROTOCOL_VERSION_MAX) {
            return failed_with_output(
                report,
                "guest selected an unexpected protocol version",
                &completed,
            );
        }
        if !report.advertised_operations.is_empty() {
            return failed_with_output(
                report,
                "negotiation-only guest unexpectedly advertised OCI executor operations",
                &completed,
            );
        }
        if report.agent_version.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
            return failed_with_output(
                report,
                "guest agent version does not match the host runtime version",
                &completed,
            );
        }
        if report.guest_architecture.as_deref() != Some("x86_64") {
            return failed_with_output(
                report,
                "guest agent did not report the required x86_64 architecture",
                &completed,
            );
        }

        let shim_report = match parse_shim_report(&completed.stdout) {
            Ok(shim_report) => shim_report,
            Err(reason) => return failed_with_output(report, &reason, &completed),
        };
        report.shim_report_verified = true;
        report.shim_report = Some(shim_report);
        report.console_created = tokio::fs::metadata(&console)
            .await
            .is_ok_and(|metadata| metadata.is_file());
        if !report.console_created {
            return failed_with_output(
                report,
                &format!(
                    "libkrun did not create the requested guest console file {}",
                    console.display()
                ),
                &completed,
            );
        }

        report.status = CapabilityStatus::Available;
        report.reason = None;
        report
    }

    async fn canonical_file(path: &Path, description: &str) -> Result<PathBuf, String> {
        canonical_path(path, description, true).await
    }

    async fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, String> {
        canonical_path(path, description, false).await
    }

    async fn canonical_path(
        path: &Path,
        description: &str,
        require_file: bool,
    ) -> Result<PathBuf, String> {
        let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
            format!(
                "failed to resolve {description} {}: {error}",
                path.display()
            )
        })?;
        let metadata = tokio::fs::metadata(&canonical).await.map_err(|error| {
            format!(
                "failed to inspect {description} {}: {error}",
                canonical.display()
            )
        })?;
        let expected_kind = if require_file { "file" } else { "directory" };
        let kind_matches = if require_file {
            metadata.is_file()
        } else {
            metadata.is_dir()
        };
        if !kind_matches {
            return Err(format!(
                "{description} is not a regular {expected_kind}: {}",
                canonical.display()
            ));
        }
        Ok(canonical)
    }

    async fn prepare_console_path(path: &Path) -> Result<PathBuf, String> {
        let absolute = std::path::absolute(path).map_err(|error| {
            format!(
                "failed to make console path {} absolute: {error}",
                path.display()
            )
        })?;
        let file_name = absolute.file_name().ok_or_else(|| {
            format!(
                "console path must name a file rather than a root directory: {}",
                absolute.display()
            )
        })?;
        let parent = absolute
            .parent()
            .ok_or_else(|| format!("console path has no parent: {}", absolute.display()))?;
        tokio::fs::create_dir_all(parent).await.map_err(|error| {
            format!(
                "failed to create console directory {}: {error}",
                parent.display()
            )
        })?;
        let parent = tokio::fs::canonicalize(parent).await.map_err(|error| {
            format!(
                "failed to resolve console directory {}: {error}",
                parent.display()
            )
        })?;
        let console = parent.join(file_name);
        if tokio::fs::try_exists(&console).await.map_err(|error| {
            format!(
                "failed to inspect console destination {}: {error}",
                console.display()
            )
        })? {
            return Err(format!(
                "refusing to overwrite an existing console destination: {}",
                console.display()
            ));
        }
        Ok(console)
    }

    fn parse_shim_report(output: &BoundedOutput) -> Result<Value, String> {
        if output.truncated {
            return Err(format!(
                "libkrun shim report exceeded the {MAX_CAPTURE_BYTES}-byte evidence limit"
            ));
        }
        let report: Value = serde_json::from_slice(&output.bytes)
            .map_err(|error| format!("libkrun shim emitted invalid JSON evidence: {error}"))?;
        let object = report
            .as_object()
            .ok_or_else(|| "libkrun shim evidence must be a JSON object".to_string())?;
        if object.get("schema_version").and_then(Value::as_str) != Some(SHIM_REPORT_SCHEMA_VERSION)
        {
            return Err("libkrun shim evidence has an unexpected schema version".into());
        }
        if object.get("status").and_then(Value::as_str) != Some("available") {
            return Err("libkrun shim did not report the guest-agent VM path available".into());
        }
        if object.get("platform").and_then(Value::as_str) != Some("windows") {
            return Err("libkrun shim evidence did not identify the Windows host".into());
        }
        for field in SHIM_TRUE_FIELDS {
            if object.get(*field).and_then(Value::as_bool) != Some(true) {
                return Err(format!("libkrun shim evidence field `{field}` is not true"));
            }
        }
        if object.get("guest_exit_code").and_then(Value::as_i64) != Some(0) {
            return Err("libkrun shim did not report a zero guest-agent exit code".into());
        }
        if object.get("reason").is_some_and(|reason| !reason.is_null()) {
            return Err("successful libkrun shim evidence unexpectedly contains a reason".into());
        }
        if object.get("vcpus").and_then(Value::as_u64) != Some(1)
            || object.get("memory_mib").and_then(Value::as_u64) != Some(512)
        {
            return Err("libkrun shim evidence has unexpected VM resources".into());
        }
        Ok(report)
    }

    fn apply_completed(report: &mut AgentVmSmokeReport, completed: &CompletedShim) {
        report.shim_exit_code = completed.status.as_ref().and_then(ExitStatus::code);
    }

    fn failed(mut report: AgentVmSmokeReport, reason: impl Into<String>) -> AgentVmSmokeReport {
        report.reason = Some(reason.into());
        report
    }

    fn failed_with_output(
        report: AgentVmSmokeReport,
        reason: &str,
        completed: &CompletedShim,
    ) -> AgentVmSmokeReport {
        let mut details = Vec::new();
        details.extend(completed.collection_errors.iter().cloned());
        if let Some(stderr) = diagnostic(&completed.stderr) {
            details.push(format!("shim stderr: {stderr}"));
        }
        if let Some(stdout) = diagnostic(&completed.stdout) {
            details.push(format!("shim stdout: {stdout}"));
        }
        let reason = if details.is_empty() {
            reason.to_string()
        } else {
            format!("{reason}; {}", details.join("; "))
        };
        failed(report, reason)
    }

    fn diagnostic(output: &BoundedOutput) -> Option<String> {
        if output.bytes.is_empty() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.bytes);
        let mut diagnostic = text
            .trim()
            .chars()
            .take(MAX_DIAGNOSTIC_CHARS)
            .collect::<String>();
        if output.truncated || text.trim().chars().count() > MAX_DIAGNOSTIC_CHARS {
            diagnostic.push_str("...[truncated]");
        }
        Some(diagnostic)
    }

    #[cfg(test)]
    mod tests {
        use serde_json::json;

        use super::{parse_shim_report, BoundedOutput};

        fn valid_output() -> BoundedOutput {
            BoundedOutput {
                bytes: serde_json::to_vec(&json!({
                    "schema_version": "a3s.oci.krun-agent-vm-smoke.v1",
                    "platform": "windows",
                    "status": "available",
                    "runtime_bundle_loaded": true,
                    "context_created": true,
                    "vm_configured": true,
                    "rootfs_configured": true,
                    "agent_binary_present": true,
                    "agent_vsock_configured": true,
                    "workload_configured": true,
                    "console_configured": true,
                    "vm_entered": true,
                    "guest_exit_code": 0,
                    "console_created": true,
                    "vcpus": 1,
                    "memory_mib": 512
                }))
                .expect("serialize test evidence"),
                truncated: false,
            }
        }

        #[test]
        fn accepts_complete_shim_evidence() {
            let report = parse_shim_report(&valid_output()).expect("valid shim evidence");
            assert_eq!(report["guest_exit_code"], 0);
        }

        #[test]
        fn rejects_incomplete_or_truncated_shim_evidence() {
            let mut incomplete = valid_output();
            let mut value: serde_json::Value =
                serde_json::from_slice(&incomplete.bytes).expect("decode test evidence");
            value["agent_vsock_configured"] = json!(false);
            incomplete.bytes = serde_json::to_vec(&value).expect("serialize test evidence");
            assert!(parse_shim_report(&incomplete).is_err());

            let mut truncated = valid_output();
            truncated.truncated = true;
            assert!(parse_shim_report(&truncated).is_err());
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
async fn agent_vm_smoke_windows(shim: &Path, rootfs: &Path, console: &Path) -> AgentVmSmokeReport {
    windows::run(shim, rootfs, console).await
}
