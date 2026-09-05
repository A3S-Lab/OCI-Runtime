use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

use crate::macos_context::{KrunContext, MacosKrunApi};
use crate::macos_runtime_share::MacosRuntimeShare;
use crate::macos_system_image::MacosSystemImage;
use crate::unix_process::{
    prepare_console_output, read_bounded_worker_output, require_absent, resolve_console,
    terminate_and_wait, wait_for_worker,
};
use crate::{KrunVmSmokeReport, MacosBootAssetsEvidence, VmConfig};
use a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_TAG;

const MACOS_VM_SMOKE_TOKEN: &str = "a3s-oci-hvf-vm-smoke-v1";
const WORKER_COMMAND: &str = "__macos-vm-smoke-worker";
const WORKER_SCHEMA_VERSION: &str = "a3s.oci.macos-vm-smoke-worker.v1";
const WORKER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024;
const MARKER_PREFIX: &str = ".a3s-oci-hvf-vm-smoke-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerEvidence {
    schema_version: String,
    runtime_bundle_loaded: bool,
    context_created: bool,
    vm_configured: bool,
    rootfs_configured: bool,
    runtime_share_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    macos_boot_assets: Option<MacosBootAssetsEvidence>,
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
            macos_boot_assets: None,
            workload_configured: false,
            console_configured: false,
            enter_attempted: false,
            reason: None,
        }
    }
}

pub(crate) fn vm_smoke(
    system_image_manifest: &Path,
    runtime_share: &Path,
    console: &Path,
    config: VmConfig,
) -> KrunVmSmokeReport {
    let mut report = KrunVmSmokeReport::initial(HostPlatform::Macos, config);
    // The parent does not load libkrun. Only bounded evidence from the private
    // worker may advance this field from staged-at-build-time to loaded.
    report.runtime_bundle_loaded = false;
    let runtime_share = match MacosRuntimeShare::open(runtime_share) {
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

    let marker_name = format!("{MARKER_PREFIX}{}", std::process::id());
    let marker_path = runtime_share.join(&marker_name);
    if let Err(reason) = require_absent(&marker_path, "smoke marker") {
        report.reason = Some(reason);
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

    let mut child = match Command::new(executable)
        .arg(WORKER_COMMAND)
        .arg("--system-image-manifest")
        .arg(system_image_manifest)
        .arg("--runtime-share")
        .arg(&runtime_share)
        .arg("--console")
        .arg(&console)
        .arg("--marker-name")
        .arg(&marker_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            report.reason = Some(format!("failed to start the macOS VM worker: {error}"));
            return report;
        }
    };

    let output_reader = child.stdout.take().map(|stdout| {
        thread::spawn(move || read_bounded_worker_output(stdout, MAX_WORKER_OUTPUT_BYTES))
    });
    let worker_exit = match wait_for_worker(&mut child, WORKER_TIMEOUT) {
        Ok(worker_exit) => Some(worker_exit),
        Err(error) => {
            let cleanup_error = terminate_and_wait(&mut child).err();
            report.reason = Some(match cleanup_error {
                Some(cleanup_error) => format!(
                    "failed to wait for the macOS VM worker: {error}; \
                     worker cleanup also failed: {cleanup_error}"
                ),
                None => format!("failed to wait for the macOS VM worker: {error}"),
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
            report.macos_boot_assets = evidence.macos_boot_assets.clone();
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
                    "macOS VM worker exceeded the {} second startup timeout and was terminated",
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
                        "macOS VM worker exited without a guest status: {}",
                        worker_exit.status
                    )
                });
            }
        }
    }

    verify_and_remove_marker(&marker_path, &mut report);
    report.vm_entered |= report.marker_verified;
    report.console_created =
        fs::symlink_metadata(&console).is_ok_and(|metadata| metadata.file_type().is_file());

    if let Some(exit_code) = report.guest_exit_code {
        if exit_code != 0 {
            report.reason.get_or_insert_with(|| {
                format!("guest workload returned non-zero exit code {exit_code}")
            });
        }
    }

    if report.runtime_bundle_loaded
        && report.context_created
        && report.vm_configured
        && report.rootfs_configured
        && report.runtime_share_configured
        && report
            .macos_boot_assets
            .as_ref()
            .is_some_and(MacosBootAssetsEvidence::is_success)
        && report.workload_configured
        && report.console_configured
        && report.vm_entered
        && report.guest_exit_code == Some(0)
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

pub(crate) fn run_worker(
    system_image_manifest: &Path,
    runtime_share: &Path,
    console: &Path,
    marker_name: &str,
) -> bool {
    let mut evidence = WorkerEvidence::initial();
    let runtime_share = match MacosRuntimeShare::open(runtime_share) {
        Ok(runtime_share) => runtime_share,
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    let prepared_console = match prepare_console_output(console, None) {
        Ok(console) => console,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };
    let console_path = prepared_console.pinned_path();
    if let Err(reason) = validate_marker_name(marker_name) {
        return fail_worker(&mut evidence, reason);
    }
    let marker_path = runtime_share.path().join(marker_name);
    if let Err(reason) = require_absent(&marker_path, "smoke marker") {
        return fail_worker(&mut evidence, reason);
    }

    let api = match MacosKrunApi::load() {
        Ok(api) => {
            evidence.runtime_bundle_loaded = true;
            api
        }
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    let system_image = match MacosSystemImage::load(system_image_manifest, api.runtime_provenance())
    {
        Ok(system_image) => system_image,
        Err(error) => return fail_worker(&mut evidence, error.to_string()),
    };
    if system_image.image_path().starts_with(runtime_share.path())
        || runtime_share.path().starts_with(system_image.image_path())
        || system_image
            .manifest_path()
            .starts_with(runtime_share.path())
        || runtime_share
            .path()
            .starts_with(system_image.manifest_path())
    {
        return fail_worker(
            &mut evidence,
            "immutable system image, manifest, and writable runtime share must be disjoint"
                .to_string(),
        );
    }
    evidence.macos_boot_assets = Some(system_image.evidence(true));
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
    if let Err(error) = context.set_workdir("/") {
        return fail_worker(&mut evidence, error.to_string());
    }

    let marker_guest_path = format!("/run/a3s-oci-runtime/{marker_name}");
    let command = format!(
        "mount -t virtiofs {AGENT_RUNTIME_SHARE_TAG} /run/a3s-oci-runtime && \
         printf '%s\\n' '{MACOS_VM_SMOKE_TOKEN}' > '{marker_guest_path}' && \
         printf '%s\\n' '{MACOS_VM_SMOKE_TOKEN}'"
    );
    let arguments = vec!["-c".to_string(), command];
    if let Err(error) = context.set_exec("/bin/sh", &arguments, &[]) {
        return fail_worker(&mut evidence, error.to_string());
    }
    evidence.workload_configured = true;
    if let Err(error) = context.set_console_output(&console_path) {
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

fn validate_marker_name(marker_name: &str) -> Result<(), String> {
    let suffix = marker_name
        .strip_prefix(MARKER_PREFIX)
        .ok_or_else(|| "macOS VM smoke marker has an invalid prefix".to_string())?;
    if suffix.is_empty() || suffix.len() > 20 || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("macOS VM smoke marker has an invalid process identifier".into());
    }
    Ok(())
}

fn collect_worker_evidence(
    output_reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
) -> Result<WorkerEvidence, String> {
    let output_reader =
        output_reader.ok_or_else(|| "macOS VM worker stdout was unavailable".to_string())?;
    let output = output_reader
        .join()
        .map_err(|_| "macOS VM worker output reader panicked".to_string())?
        .map_err(|error| format!("failed to read macOS VM worker evidence: {error}"))?;
    parse_worker_evidence(&output)
}

fn parse_worker_evidence(output: &[u8]) -> Result<WorkerEvidence, String> {
    let mut latest = None;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let evidence: WorkerEvidence = serde_json::from_slice(line)
            .map_err(|error| format!("macOS VM worker emitted invalid evidence: {error}"))?;
        if evidence.schema_version != WORKER_SCHEMA_VERSION {
            return Err(format!(
                "macOS VM worker emitted unsupported schema {}",
                evidence.schema_version
            ));
        }
        latest = Some(evidence);
    }
    latest.ok_or_else(|| "macOS VM worker emitted no setup evidence".to_string())
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

fn verify_and_remove_marker(marker_path: &Path, report: &mut KrunVmSmokeReport) {
    match fs::read_to_string(marker_path) {
        Ok(contents) if contents == format!("{MACOS_VM_SMOKE_TOKEN}\n") => {
            report.marker_verified = true;
        }
        Ok(contents) => {
            report.reason.get_or_insert_with(|| {
                format!(
                    "guest marker had unexpected contents ({} bytes)",
                    contents.len()
                )
            });
        }
        Err(error) => {
            report.reason.get_or_insert_with(|| {
                format!(
                    "failed to read guest marker {}: {error}",
                    marker_path.display()
                )
            });
        }
    }

    match fs::symlink_metadata(marker_path) {
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            match fs::remove_file(marker_path) {
                Ok(()) => report.marker_removed = true,
                Err(error) => {
                    report.reason.get_or_insert_with(|| {
                        format!(
                            "failed to remove guest marker {}: {error}",
                            marker_path.display()
                        )
                    });
                }
            }
        }
        Ok(_) => {
            report.reason.get_or_insert_with(|| {
                format!(
                    "guest marker is not a removable file: {}",
                    marker_path.display()
                )
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            report.reason.get_or_insert_with(|| {
                format!(
                    "failed to inspect guest marker {} for cleanup: {error}",
                    marker_path.display()
                )
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_worker_evidence, validate_marker_name, WorkerEvidence, WORKER_SCHEMA_VERSION,
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
    fn marker_name_rejects_path_and_shell_injection() {
        validate_marker_name(".a3s-oci-hvf-vm-smoke-123").expect("generated marker must pass");
        assert!(validate_marker_name("../marker").is_err());
        assert!(validate_marker_name(".a3s-oci-hvf-vm-smoke-1';reboot").is_err());
    }
}
