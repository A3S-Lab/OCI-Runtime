use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

use crate::macos_context::{KrunContext, MacosKrunApi};
use crate::{KrunVmSmokeReport, VmConfig};

const MACOS_VM_SMOKE_TOKEN: &str = "a3s-oci-hvf-vm-smoke-v1";
const WORKER_COMMAND: &str = "__macos-vm-smoke-worker";
const WORKER_SCHEMA_VERSION: &str = "a3s.oci.macos-vm-smoke-worker.v1";
const WORKER_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_WORKER_OUTPUT_BYTES: u64 = 64 * 1024;
const MARKER_PREFIX: &str = ".a3s-oci-hvf-vm-smoke-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkerEvidence {
    schema_version: String,
    runtime_bundle_loaded: bool,
    context_created: bool,
    vm_configured: bool,
    rootfs_configured: bool,
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
            workload_configured: false,
            console_configured: false,
            enter_attempted: false,
            reason: None,
        }
    }
}

struct WorkerExit {
    status: ExitStatus,
    timed_out: bool,
}

pub(crate) fn vm_smoke(rootfs: &Path, console: &Path, config: VmConfig) -> KrunVmSmokeReport {
    let mut report = KrunVmSmokeReport::initial(HostPlatform::Macos, config);
    // The parent does not load libkrun. Only bounded evidence from the private
    // worker may advance this field from staged-at-build-time to loaded.
    report.runtime_bundle_loaded = false;
    let rootfs = match resolve_rootfs(rootfs) {
        Ok(rootfs) => rootfs,
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

    let marker_name = format!("{MARKER_PREFIX}{}", std::process::id());
    let marker_path = rootfs.join(&marker_name);
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
        .arg("--rootfs")
        .arg(&rootfs)
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

pub(crate) fn run_worker(rootfs: &Path, console: &Path, marker_name: &str) -> bool {
    let mut evidence = WorkerEvidence::initial();
    let rootfs = match resolve_rootfs(rootfs) {
        Ok(rootfs) => rootfs,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };
    let console = match resolve_console(console) {
        Ok(console) => console,
        Err(reason) => return fail_worker(&mut evidence, reason),
    };
    if let Err(reason) = validate_marker_name(marker_name) {
        return fail_worker(&mut evidence, reason);
    }
    let marker_path = rootfs.join(marker_name);
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
    if let Err(error) = context.set_workdir("/") {
        return fail_worker(&mut evidence, error.to_string());
    }

    let marker_guest_path = format!("/{marker_name}");
    let command = format!(
        "printf '%s\\n' '{MACOS_VM_SMOKE_TOKEN}' > '{marker_guest_path}' && \
         printf '%s\\n' '{MACOS_VM_SMOKE_TOKEN}'"
    );
    let arguments = vec!["-c".to_string(), command];
    if let Err(error) = context.set_exec("/bin/sh", &arguments, &[]) {
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

fn resolve_rootfs(rootfs: &Path) -> Result<PathBuf, String> {
    let rootfs = rootfs
        .canonicalize()
        .map_err(|error| format!("failed to resolve rootfs {}: {error}", rootfs.display()))?;
    if !rootfs.is_dir() {
        return Err(format!("rootfs is not a directory: {}", rootfs.display()));
    }

    let resolved_shell = resolve_guest_path(&rootfs, Path::new("/bin/sh")).map_err(|reason| {
        format!(
            "rootfs does not contain a usable /bin/sh below {}: {reason}",
            rootfs.display()
        )
    })?;
    if !fs::symlink_metadata(&resolved_shell).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(format!(
            "rootfs /bin/sh must resolve to a regular file inside {}",
            rootfs.display()
        ));
    }
    Ok(rootfs)
}

#[derive(Debug)]
enum GuestComponent {
    Parent,
    Normal(OsString),
}

fn resolve_guest_path(rootfs: &Path, guest_path: &Path) -> Result<PathBuf, String> {
    let mut pending = VecDeque::new();
    prepend_guest_components(guest_path, &mut pending)?;
    let mut resolved = PathBuf::new();
    let mut followed_links = 0_u8;

    while let Some(component) = pending.pop_front() {
        match component {
            GuestComponent::Parent => {
                if !resolved.pop() {
                    return Err(format!(
                        "guest path escapes the root filesystem: {}",
                        guest_path.display()
                    ));
                }
            }
            GuestComponent::Normal(component) => {
                let candidate = rootfs.join(&resolved).join(&component);
                let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
                    format!("failed to inspect {}: {error}", candidate.display())
                })?;
                if metadata.file_type().is_symlink() {
                    followed_links = followed_links.saturating_add(1);
                    if followed_links > 40 {
                        return Err(format!(
                            "guest path contains too many symbolic links: {}",
                            guest_path.display()
                        ));
                    }
                    let target = fs::read_link(&candidate).map_err(|error| {
                        format!(
                            "failed to read symbolic link {}: {error}",
                            candidate.display()
                        )
                    })?;
                    if target.is_absolute() {
                        resolved.clear();
                    }
                    prepend_guest_components(&target, &mut pending)?;
                } else {
                    resolved.push(component);
                }
            }
        }
    }

    Ok(rootfs.join(resolved))
}

fn prepend_guest_components(
    path: &Path,
    pending: &mut VecDeque<GuestComponent>,
) -> Result<(), String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => components.push(GuestComponent::Parent),
            Component::Normal(component) => {
                components.push(GuestComponent::Normal(component.to_os_string()));
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "guest path contains a host path prefix: {}",
                    path.display()
                ));
            }
        }
    }
    for component in components.into_iter().rev() {
        pending.push_front(component);
    }
    Ok(())
}

fn resolve_console(console: &Path) -> Result<PathBuf, String> {
    let file_name = console
        .file_name()
        .ok_or_else(|| format!("console path has no file name: {}", console.display()))?;
    let parent = console
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create console directory {}: {error}",
            parent.display()
        )
    })?;
    let parent = parent.canonicalize().map_err(|error| {
        format!(
            "failed to resolve console directory {}: {error}",
            parent.display()
        )
    })?;
    let console = parent.join(file_name);
    require_absent(&console, "console output")?;
    Ok(console)
}

fn require_absent(path: &Path, description: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "refusing to overwrite existing {description}: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )),
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

fn wait_for_worker(child: &mut Child, timeout: Duration) -> io::Result<WorkerExit> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(WorkerExit {
                status,
                timed_out: false,
            });
        }
        if Instant::now() >= deadline {
            return match child.kill() {
                Ok(()) => child.wait().map(|status| WorkerExit {
                    status,
                    timed_out: true,
                }),
                Err(kill_error) => match child.try_wait()? {
                    Some(status) => Ok(WorkerExit {
                        status,
                        timed_out: false,
                    }),
                    None => Err(kill_error),
                },
            };
        }
        thread::sleep(WORKER_POLL_INTERVAL);
    }
}

fn terminate_and_wait(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    match child.kill() {
        Ok(()) => child.wait(),
        Err(kill_error) => child.try_wait()?.ok_or(kill_error),
    }
}

fn read_bounded_worker_output(mut stdout: ChildStdout, limit: u64) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    stdout.by_ref().take(limit + 1).read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("macOS VM worker output exceeds {limit} bytes"),
        ));
    }
    Ok(output)
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
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::{
        parse_worker_evidence, validate_marker_name, wait_for_worker, WorkerEvidence,
        WORKER_SCHEMA_VERSION,
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

    #[test]
    fn timed_out_worker_is_killed_and_reaped() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 10"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test worker must start");

        let result =
            wait_for_worker(&mut child, Duration::from_millis(10)).expect("worker must be reaped");
        assert!(result.timed_out);
        assert!(child
            .try_wait()
            .expect("reaped child must be queryable")
            .is_some());
    }
}
