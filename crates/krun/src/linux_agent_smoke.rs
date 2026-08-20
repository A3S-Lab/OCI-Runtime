use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentTransportQualificationRequest, AgentVsockEndpoint, AGENT_RECOVERY_REPORT_ENV,
    AGENT_RUNTIME_SHARE_ENV, AGENT_RUNTIME_SHARE_TAG, AGENT_SESSION_TOKEN_FILE_ENV,
    AGENT_TRANSPORT_QUALIFICATION_ENV, AGENT_VSOCK_PORT,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

use crate::linux_context::{KrunContext, LinuxKrunApi};
use crate::linux_kvm_device::LinuxKvmDevice;
use crate::linux_runtime_share::LinuxRuntimeShare;
use crate::linux_system_image::LinuxSystemImage;
use crate::unix_process::{
    read_bounded_worker_output, resolve_agent_socket, resolve_console, terminate_and_wait,
    wait_for_worker,
};
use crate::{KrunAgentVmSmokeReport, LinuxBootAssetsEvidence, VmConfig};

const AGENT_GUEST_PATH: &str = "/usr/bin/a3s-oci-agent";
const WORKER_COMMAND: &str = "__linux-agent-vm-worker";
const WORKER_SCHEMA_VERSION: &str = "a3s.oci.linux-kvm-agent-vm-worker.v2";
const POST_PROBE_FAILURE_REASON: &str =
    "injected Linux KVM failure after device verification and before native VM entry";
const WORKER_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerEvidence {
    schema_version: String,
    runtime_bundle_loaded: bool,
    context_created: bool,
    vm_configured: bool,
    rootfs_configured: bool,
    runtime_share_configured: bool,
    kvm_device_opened: bool,
    kvm_api_verified: bool,
    kvm_post_probe_failure_injected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    linux_boot_assets: Option<LinuxBootAssetsEvidence>,
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
            runtime_share_configured: false,
            kvm_device_opened: false,
            kvm_api_verified: false,
            kvm_post_probe_failure_injected: false,
            linux_boot_assets: None,
            agent_binary_present: false,
            agent_vsock_configured: false,
            workload_configured: false,
            console_configured: false,
            enter_attempted: false,
            reason: None,
        }
    }
}

pub(crate) struct LinuxAgentVmConfig<'a> {
    pub(crate) system_image_manifest: &'a Path,
    pub(crate) runtime_share: &'a Path,
    pub(crate) guest_token_file: &'a str,
    pub(crate) console: &'a Path,
    pub(crate) endpoint: &'a AgentVsockEndpoint,
    pub(crate) socket: &'a Path,
    pub(crate) guest_recovery_report: Option<&'a str>,
    pub(crate) transport_qualification: Option<&'a AgentTransportQualificationRequest>,
    pub(crate) qualify_kvm_post_probe_failure: bool,
    pub(crate) vm: VmConfig,
}

pub(crate) fn agent_vm_smoke(configuration: LinuxAgentVmConfig<'_>) -> KrunAgentVmSmokeReport {
    let LinuxAgentVmConfig {
        system_image_manifest,
        runtime_share,
        guest_token_file,
        console,
        endpoint,
        socket,
        guest_recovery_report,
        transport_qualification,
        qualify_kvm_post_probe_failure,
        vm: config,
    } = configuration;
    let mut report = KrunAgentVmSmokeReport::initial(HostPlatform::Linux, config);
    // Native libraries are loaded only in the bounded worker, never in this
    // public shim parent or the host runtime.
    report.runtime_bundle_loaded = false;
    let runtime_share = match LinuxRuntimeShare::open(runtime_share) {
        Ok(runtime_share) => runtime_share.path().to_path_buf(),
        Err(error) => {
            report.reason = Some(error.to_string());
            return report;
        }
    };
    report.runtime_share_configured = true;
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

    let mut command = Command::new(executable);
    command
        .arg(WORKER_COMMAND)
        .arg("--system-image-manifest")
        .arg(system_image_manifest)
        .arg("--runtime-share")
        .arg(&runtime_share)
        .arg("--guest-token-file")
        .arg(guest_token_file)
        .arg("--console")
        .arg(&console)
        .arg("--socket-path")
        .arg(&socket)
        .env_remove(AGENT_TRANSPORT_QUALIFICATION_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(path) = guest_recovery_report {
        command.arg("--guest-recovery-report").arg(path);
    }
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
    if qualify_kvm_post_probe_failure {
        command.arg("--qualify-kvm-post-probe-failure");
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report.reason = Some(format!(
                "failed to start the Linux KVM guest-agent worker: {error}"
            ));
            return report;
        }
    };
    drop(command);

    let output_reader = child.stdout.take().map(|stdout| {
        thread::spawn(move || read_bounded_worker_output(stdout, MAX_WORKER_OUTPUT_BYTES))
    });
    let worker_exit = match wait_for_worker(&mut child, WORKER_TIMEOUT) {
        Ok(worker_exit) => Some(worker_exit),
        Err(error) => {
            let cleanup_error = terminate_and_wait(&mut child).err();
            report.reason = Some(match cleanup_error {
                Some(cleanup_error) => format!(
                    "failed to wait for the Linux KVM guest-agent worker: {error}; worker cleanup also failed: {cleanup_error}"
                ),
                None => format!(
                    "failed to wait for the Linux KVM guest-agent worker: {error}"
                ),
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
            report.runtime_share_configured = evidence.runtime_share_configured;
            report.kvm_device_opened = evidence.kvm_device_opened;
            report.kvm_api_verified = evidence.kvm_api_verified;
            report.kvm_post_probe_failure_injected = evidence.kvm_post_probe_failure_injected;
            report.linux_boot_assets = evidence.linux_boot_assets.clone();
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
                    "Linux KVM guest-agent worker exceeded the {} second timeout and was terminated",
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
                        "Linux KVM guest-agent worker exited without a guest status: {}",
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
        && report.runtime_share_configured
        && report.kvm_device_opened
        && report.kvm_api_verified
        && !report.kvm_post_probe_failure_injected
        && report
            .linux_boot_assets
            .as_ref()
            .is_some_and(LinuxBootAssetsEvidence::is_success)
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
        report.reason = Some("guest agent did not satisfy the Linux KVM shim contract".into());
    }
    report
}

pub(crate) struct LinuxAgentVmWorkerConfig<'a> {
    pub(crate) system_image_manifest: &'a Path,
    pub(crate) runtime_share: &'a Path,
    pub(crate) guest_token_file: &'a str,
    pub(crate) console: &'a Path,
    pub(crate) socket: &'a Path,
    pub(crate) guest_recovery_report: Option<&'a str>,
    pub(crate) transport_qualification: Option<&'a AgentTransportQualificationRequest>,
    pub(crate) qualify_kvm_post_probe_failure: bool,
}

pub(crate) fn run_worker(configuration: LinuxAgentVmWorkerConfig<'_>) -> bool {
    let LinuxAgentVmWorkerConfig {
        system_image_manifest,
        runtime_share,
        guest_token_file,
        console,
        socket,
        guest_recovery_report,
        transport_qualification,
        qualify_kvm_post_probe_failure,
    } = configuration;
    let mut evidence = WorkerEvidence::initial();
    let runtime_share = match LinuxRuntimeShare::open(runtime_share) {
        Ok(runtime_share) => runtime_share,
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    let console = match resolve_console(console) {
        Ok(console) => console,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };
    let socket = match resolve_agent_socket(socket) {
        Ok(socket) => socket,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };

    let api = match LinuxKrunApi::load() {
        Ok(api) => {
            evidence.runtime_bundle_loaded = true;
            api
        }
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    let system_image = match LinuxSystemImage::load(system_image_manifest, api.runtime_bundle()) {
        Ok(system_image) => system_image,
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    if paths_overlap(system_image.manifest_path(), runtime_share.path())
        || paths_overlap(system_image.image_path(), runtime_share.path())
    {
        return fail_worker(
            &mut evidence,
            "immutable Linux KVM system assets and writable runtime share must be disjoint"
                .to_string(),
        );
    }
    evidence.agent_binary_present = true;
    evidence.linux_boot_assets = Some(system_image.evidence());

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
    if let Err(error) = context.set_read_only_system_image(system_image) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.rootfs_configured = true;
    if let Err(error) = context.add_runtime_share(AGENT_RUNTIME_SHARE_TAG, runtime_share) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.runtime_share_configured = true;
    if let Err(error) = context.set_agent_vsock(&socket, AGENT_VSOCK_PORT) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.agent_vsock_configured = true;
    if let Err(error) = context.set_workdir("/") {
        return fail_worker(&mut evidence, error.to_string());
    }

    let mut environment = vec![
        (
            AGENT_SESSION_TOKEN_FILE_ENV.to_string(),
            guest_token_file.to_string(),
        ),
        (
            AGENT_RUNTIME_SHARE_ENV.to_string(),
            AGENT_RUNTIME_SHARE_TAG.to_string(),
        ),
    ];
    if let Some(path) = guest_recovery_report {
        environment.push((AGENT_RECOVERY_REPORT_ENV.to_string(), path.to_string()));
    }
    if let Some(request) = transport_qualification {
        let encoded = match request.to_json() {
            Ok(encoded) => encoded,
            Err(error) => return fail_worker(&mut evidence, error.to_string()),
        };
        environment.push((AGENT_TRANSPORT_QUALIFICATION_ENV.to_string(), encoded));
    }
    if let Err(error) = context.set_exec(AGENT_GUEST_PATH, &[], &environment) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.workload_configured = true;
    if let Err(error) = context.set_console_output(&console) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.console_configured = true;
    let kvm_device = match LinuxKvmDevice::open() {
        Ok(device) => {
            evidence.kvm_device_opened = true;
            device
        }
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    if let Err(error) = kvm_device.verify_api() {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.kvm_api_verified = true;
    if let Err(reason) = inject_post_probe_failure(&mut evidence, qualify_kvm_post_probe_failure) {
        return fail_worker(&mut evidence, reason);
    }
    evidence.enter_attempted = true;

    if let Err(error) = emit_worker_evidence(&evidence) {
        evidence.reason = Some(format!("failed to emit pre-entry worker evidence: {error}"));
        return false;
    }
    match context.start_enter(&kvm_device) {
        Ok(0) => emit_worker_evidence(&evidence).is_ok(),
        Ok(status) => fail_worker(
            &mut evidence,
            format!("Linux KVM guest agent returned non-zero status {status}"),
        ),
        Err(error) => fail_worker(&mut evidence, error.to_string()),
    }
}

fn inject_post_probe_failure(evidence: &mut WorkerEvidence, requested: bool) -> Result<(), String> {
    if !requested {
        return Ok(());
    }
    if !evidence.kvm_device_opened || !evidence.kvm_api_verified {
        return Err(
            "Linux KVM post-probe failure qualification requires a verified KVM device".to_string(),
        );
    }
    evidence.kvm_post_probe_failure_injected = true;
    Err(POST_PROBE_FAILURE_REASON.to_string())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn collect_worker_evidence(
    output_reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
) -> Result<WorkerEvidence, String> {
    let output_reader = output_reader
        .ok_or_else(|| "Linux KVM guest-agent worker stdout was unavailable".to_string())?;
    let output = output_reader
        .join()
        .map_err(|_| "Linux KVM guest-agent worker output reader panicked".to_string())?
        .map_err(|error| format!("failed to read Linux KVM worker evidence: {error}"))?;
    parse_worker_evidence(&output)
}

fn parse_worker_evidence(output: &[u8]) -> Result<WorkerEvidence, String> {
    let mut latest = None;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let evidence: WorkerEvidence = serde_json::from_slice(line)
            .map_err(|error| format!("Linux KVM worker emitted invalid evidence: {error}"))?;
        if evidence.schema_version != WORKER_SCHEMA_VERSION {
            return Err(format!(
                "Linux KVM worker emitted unsupported schema {}",
                evidence.schema_version
            ));
        }
        latest = Some(evidence);
    }
    latest.ok_or_else(|| "Linux KVM worker emitted no setup evidence".to_string())
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
        eprintln!("a3s-oci-krun-shim: failed to emit Linux KVM worker failure: {error}");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        inject_post_probe_failure, parse_worker_evidence, WorkerEvidence,
        POST_PROBE_FAILURE_REASON, WORKER_SCHEMA_VERSION,
    };

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

    #[test]
    fn post_probe_qualification_fails_before_native_vm_entry() {
        let mut evidence = WorkerEvidence::initial();
        evidence.kvm_device_opened = true;
        evidence.kvm_api_verified = true;

        inject_post_probe_failure(&mut evidence, false)
            .expect("normal VM entry must not inject a qualification failure");
        assert!(!evidence.kvm_post_probe_failure_injected);

        let error = inject_post_probe_failure(&mut evidence, true)
            .expect_err("qualification must stop after the verified KVM probe");
        assert_eq!(error, POST_PROBE_FAILURE_REASON);
        assert!(evidence.kvm_post_probe_failure_injected);
        assert!(!evidence.enter_attempted);
    }
}
