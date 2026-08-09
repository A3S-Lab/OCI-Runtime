use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentTransportQualificationRequest, AgentVsockEndpoint, SessionToken, AGENT_SESSION_TOKEN_ENV,
    AGENT_TRANSPORT_QUALIFICATION_ENV, AGENT_VSOCK_PORT,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::macos_context::{KrunContext, MacosKrunApi};
use crate::macos_process::{
    canonical_rootfs, read_bounded_worker_output, resolve_agent_socket, resolve_console,
    resolve_guest_regular_file, terminate_and_wait, wait_for_worker,
};
use crate::{KrunAgentVmSmokeReport, VmConfig};

const AGENT_GUEST_PATH: &str = "/usr/bin/a3s-oci-agent";
const WORKER_COMMAND: &str = "__macos-agent-vm-worker";
const WORKER_SCHEMA_VERSION: &str = "a3s.oci.macos-agent-vm-worker.v1";
const WORKER_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerEvidence {
    schema_version: String,
    runtime_bundle_loaded: bool,
    context_created: bool,
    vm_configured: bool,
    rootfs_configured: bool,
    agent_binary_present: bool,
    agent_vsock_configured: bool,
    workload_configured: bool,
    console_configured: bool,
    enter_attempted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl WorkerEvidence {
    fn initial() -> Self {
        Self {
            schema_version: WORKER_SCHEMA_VERSION.to_string(),
            runtime_bundle_loaded: false,
            context_created: false,
            vm_configured: false,
            rootfs_configured: false,
            agent_binary_present: false,
            agent_vsock_configured: false,
            workload_configured: false,
            console_configured: false,
            enter_attempted: false,
            reason: None,
        }
    }
}

pub(crate) fn agent_vm_smoke(
    rootfs: &Path,
    console: &Path,
    endpoint: &AgentVsockEndpoint,
    socket: &Path,
    token: &SessionToken,
    transport_qualification: Option<&AgentTransportQualificationRequest>,
    config: VmConfig,
) -> KrunAgentVmSmokeReport {
    let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Macos, config);
    // The parent intentionally does not load libkrun. Only bounded worker
    // evidence may advance the native setup fields.
    report.runtime_bundle_loaded = false;
    let rootfs = match resolve_rootfs(rootfs) {
        Ok(rootfs) => {
            report.agent_binary_present = true;
            rootfs
        }
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    let console = match resolve_console(console) {
        Ok(console) => console,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    let socket = match resolve_agent_socket(socket) {
        Ok(socket) => socket,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    if socket.parent().and_then(Path::file_name) != Some(std::ffi::OsStr::new(endpoint.pipe_name()))
    {
        report.reason = Some(format!(
            "agent socket directory does not match endpoint {}: {}",
            endpoint.pipe_name(),
            socket.display()
        ));
        return report;
    }
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            report.reason = Some(format!(
                "failed to resolve the current shim executable: {error}"
            ));
            return report;
        }
    };

    let encoded_token = token.expose_hex();
    let mut command = Command::new(executable);
    command
        .arg(WORKER_COMMAND)
        .arg("--rootfs")
        .arg(&rootfs)
        .arg("--console")
        .arg(&console)
        .arg("--socket-path")
        .arg(&socket)
        .env_remove(AGENT_TRANSPORT_QUALIFICATION_ENV)
        .env(AGENT_SESSION_TOKEN_ENV, encoded_token.as_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let encoded_qualification = match transport_qualification
        .map(AgentTransportQualificationRequest::to_json)
        .transpose()
    {
        Ok(encoded) => encoded,
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };
    if let Some(encoded) = &encoded_qualification {
        command.env(AGENT_TRANSPORT_QUALIFICATION_ENV, encoded);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report.reason = Some(format!(
                "failed to start the macOS guest-agent VM worker: {error}"
            ));
            return report;
        }
    };
    drop(command);
    drop(encoded_token);

    let output_reader = child.stdout.take().map(|stdout| {
        thread::spawn(move || read_bounded_worker_output(stdout, MAX_WORKER_OUTPUT_BYTES))
    });
    let worker_exit = match wait_for_worker(&mut child, WORKER_TIMEOUT) {
        Ok(worker_exit) => Some(worker_exit),
        Err(error) => {
            let cleanup_error = terminate_and_wait(&mut child).err();
            report.reason = Some(match cleanup_error {
                Some(cleanup_error) => format!(
                    "failed to wait for the macOS guest-agent VM worker: {error}; \
                     worker cleanup also failed: {cleanup_error}"
                ),
                None => format!("failed to wait for the macOS guest-agent VM worker: {error}"),
            });
            None
        }
    };

    let evidence = match collect_worker_evidence(output_reader) {
        Ok(evidence) => {
            report.runtime_bundle_loaded = evidence.runtime_bundle_loaded;
            report.context_created = evidence.context_created;
            report.vm_configured = evidence.vm_configured;
            report.rootfs_configured = evidence.rootfs_configured;
            report.agent_binary_present = evidence.agent_binary_present;
            report.agent_vsock_configured = evidence.agent_vsock_configured;
            report.workload_configured = evidence.workload_configured;
            report.console_configured = evidence.console_configured;
            if let Some(reason) = evidence.reason.clone() {
                report.reason.get_or_insert(reason);
            }
            Some(evidence)
        }
        Err(reason) => {
            report.reason.get_or_insert(reason);
            None
        }
    };

    if let Some(worker_exit) = &worker_exit {
        if worker_exit.timed_out {
            report.reason.get_or_insert_with(|| {
                format!(
                    "macOS guest-agent VM worker exceeded the {} second timeout and was \
                     terminated",
                    WORKER_TIMEOUT.as_secs()
                )
            });
        } else if evidence
            .as_ref()
            .is_some_and(|evidence| evidence.enter_attempted && evidence.reason.is_none())
        {
            report.guest_exit_code = worker_exit.status.code();
            report.vm_entered = report.guest_exit_code.is_some();
            if report.guest_exit_code.is_none() {
                report.reason.get_or_insert_with(|| {
                    format!(
                        "macOS guest-agent VM worker exited without a guest status: {}",
                        worker_exit.status
                    )
                });
            }
        }
    }

    report.console_created =
        fs::symlink_metadata(&console).is_ok_and(|metadata| metadata.file_type().is_file());
    if let Some(exit_code) = report.guest_exit_code {
        if exit_code != 0 {
            report.reason.get_or_insert_with(|| {
                format!("guest agent returned non-zero exit code {exit_code}")
            });
        }
    }

    if report.runtime_bundle_loaded
        && report.context_created
        && report.vm_configured
        && report.rootfs_configured
        && report.agent_binary_present
        && report.agent_vsock_configured
        && report.workload_configured
        && report.console_configured
        && report.vm_entered
        && report.guest_exit_code == Some(0)
        && report.console_created
    {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    } else if report.reason.is_none() {
        report.reason = Some("guest agent did not satisfy the shim smoke contract".into());
    }
    report
}

pub(crate) fn run_worker(
    rootfs: &Path,
    console: &Path,
    socket: &Path,
    token: &SessionToken,
    transport_qualification: Option<&AgentTransportQualificationRequest>,
) -> bool {
    let mut evidence = WorkerEvidence::initial();
    let rootfs = match resolve_rootfs(rootfs) {
        Ok(rootfs) => {
            evidence.agent_binary_present = true;
            rootfs
        }
        Err(reason) => return fail_worker(&mut evidence, reason),
    };
    let console = match resolve_console(console) {
        Ok(console) => console,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };
    let socket = match resolve_agent_socket(socket) {
        Ok(socket) => socket,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };

    let api = match MacosKrunApi::load() {
        Ok(api) => {
            evidence.runtime_bundle_loaded = true;
            api
        }
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    let config = crate::fallback_config();
    let mut context = match KrunContext::create(api) {
        Ok(context) => {
            evidence.context_created = true;
            context
        }
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    if let Err(error) = context.set_vm_config(config) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.vm_configured = true;
    if let Err(error) = context.set_root(&rootfs) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.rootfs_configured = true;
    if let Err(error) = context.set_agent_vsock(&socket, AGENT_VSOCK_PORT) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.agent_vsock_configured = true;
    if let Err(error) = context.set_workdir("/") {
        return fail_worker(&mut evidence, error.to_string());
    }

    let token_hex = token.expose_hex();
    let mut environment = vec![(
        AGENT_SESSION_TOKEN_ENV.to_string(),
        token_hex.as_str().to_string(),
    )];
    if let Some(request) = transport_qualification {
        let encoded = match request.to_json() {
            Ok(encoded) => encoded,
            Err(error) => return fail_worker(&mut evidence, error.to_string()),
        };
        environment.push((AGENT_TRANSPORT_QUALIFICATION_ENV.to_string(), encoded));
    }
    let environment = Zeroizing::new(environment);
    if let Err(error) = context.set_exec(AGENT_GUEST_PATH, &[], &environment) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.workload_configured = true;
    if let Err(error) = context.set_console_output(&console) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.console_configured = true;
    evidence.enter_attempted = true;

    if let Err(error) = emit_worker_evidence(&evidence) {
        evidence.reason = Some(format!("failed to emit pre-entry worker evidence: {error}"));
        return false;
    }
    match context.start_enter() {
        Ok(status) => fail_worker(
            &mut evidence,
            format!("krun_start_enter unexpectedly returned status {status}"),
        ),
        Err(error) => fail_worker(&mut evidence, error.to_string()),
    }
}

fn resolve_rootfs(rootfs: &Path) -> Result<std::path::PathBuf, String> {
    let rootfs = canonical_rootfs(rootfs)?;
    resolve_guest_regular_file(&rootfs, Path::new(AGENT_GUEST_PATH), "fixed guest agent")?;
    Ok(rootfs)
}

fn collect_worker_evidence(
    output_reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
) -> Result<WorkerEvidence, String> {
    let output_reader = output_reader
        .ok_or_else(|| "macOS guest-agent VM worker stdout was unavailable".to_string())?;
    let output = output_reader
        .join()
        .map_err(|_| "macOS guest-agent VM worker output reader panicked".to_string())?
        .map_err(|error| format!("failed to read macOS guest-agent VM worker evidence: {error}"))?;
    parse_worker_evidence(&output)
}

fn parse_worker_evidence(output: &[u8]) -> Result<WorkerEvidence, String> {
    let mut latest = None;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let evidence: WorkerEvidence = serde_json::from_slice(line).map_err(|error| {
            format!("macOS guest-agent VM worker emitted invalid evidence: {error}")
        })?;
        if evidence.schema_version != WORKER_SCHEMA_VERSION {
            return Err(format!(
                "macOS guest-agent VM worker emitted unsupported schema {}",
                evidence.schema_version
            ));
        }
        latest = Some(evidence);
    }
    latest.ok_or_else(|| "macOS guest-agent VM worker emitted no setup evidence".to_string())
}

fn emit_worker_evidence(evidence: &WorkerEvidence) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, evidence).map_err(io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn fail_worker(evidence: &mut WorkerEvidence, reason: String) -> bool {
    evidence.reason = Some(reason);
    if let Err(error) = emit_worker_evidence(evidence) {
        eprintln!("a3s-oci-krun-shim: failed to emit worker failure evidence: {error}");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{parse_worker_evidence, WorkerEvidence, WORKER_SCHEMA_VERSION};

    #[test]
    fn worker_evidence_uses_the_latest_valid_record() {
        let mut entering = WorkerEvidence::initial();
        entering.enter_attempted = true;
        let mut failed = entering.clone();
        failed.reason = Some("entry failed".into());
        let output = format!(
            "{}\n{}\n",
            serde_json::to_string(&entering).expect("entering evidence must serialize"),
            serde_json::to_string(&failed).expect("failure evidence must serialize")
        );

        let parsed = parse_worker_evidence(output.as_bytes()).expect("worker evidence must parse");
        assert_eq!(parsed.schema_version, WORKER_SCHEMA_VERSION);
        assert_eq!(parsed.reason.as_deref(), Some("entry failed"));
    }
}
