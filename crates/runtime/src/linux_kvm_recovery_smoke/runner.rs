use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_agent_protocol::AgentRecoveryReport;
use a3s_oci_core::{CapabilityStatus, DriverKind, DriverReadiness};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    ExitStatus, FileOp, FileRequest, IsolationRequest, ListRequest, OciBundle, OperationContext,
    OperationId, ProcessesRequest, RuntimeClient, StartRequest, StateRequest, WaitRequest,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout, Instant};

use super::bundle;
use super::host::{self, HostServiceProcess};
use super::report::{
    canonical_git_revision, LinuxKvmRecoveryArtifacts, LinuxKvmRecoveryEvidence,
    LinuxKvmRecoverySmokeReport,
};
use crate::unix_service::validate_unix_socket_path;

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MARKER_PATH: &str = "/.a3s-oci-create-start-smoke";
const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
const QUALIFICATION_SCOPE: &str = "linux-kvm-owner-death-restart-only-v1";

/// Exact artifacts and private parent for one real KVM recovery run.
#[derive(Debug, Clone)]
pub struct LinuxKvmRecoverySmokeConfig {
    pub host_service_executable: PathBuf,
    pub shim: PathBuf,
    pub system_image_manifest: PathBuf,
    pub bundle: PathBuf,
    pub work_parent: PathBuf,
    pub source_revision: Option<String>,
}

/// Kill one live KVM Host Service, then recover through a distinct owner.
pub async fn run(config: LinuxKvmRecoverySmokeConfig) -> LinuxKvmRecoverySmokeReport {
    let architecture = std::env::consts::ARCH.to_string();
    let mut report = LinuxKvmRecoverySmokeReport::initial(config.work_parent.clone(), architecture);
    let prepared = match PreparedRun::open(config).await {
        Ok(prepared) => prepared,
        Err(reason) => {
            report.reason = Some(reason);
            return report;
        }
    };
    report.evidence_root = prepared.evidence_root.clone();
    report.artifacts = prepared.artifacts.clone();
    if let Err(reason) = persist_report(&report) {
        report.reason = Some(reason);
        return report;
    }

    if let Err(reason) = run_recovery(&prepared, &mut report.recovery).await {
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        let _ = persist_report(&report);
        return report;
    }
    if !report.recovery.is_success() {
        let reason = "Linux KVM recovery evidence failed its completeness audit".to_string();
        report.recovery.reason = Some(reason.clone());
        report.reason = Some(reason);
        let _ = persist_report(&report);
        return report;
    }
    report.status = CapabilityStatus::Available;
    report.case_count = 1;
    if !report.is_success() {
        report.status = CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some("Linux KVM recovery report failed its final audit".to_string());
    }
    if let Err(reason) = persist_report(&report) {
        report.status = CapabilityStatus::Unavailable;
        report.case_count = 0;
        report.reason = Some(reason);
    }
    report
}

struct PreparedRun {
    executable: PathBuf,
    shim: PathBuf,
    manifest: PathBuf,
    bundle: PathBuf,
    service_root: PathBuf,
    evidence_root: PathBuf,
    nonce: String,
    artifacts: LinuxKvmRecoveryArtifacts,
}

impl PreparedRun {
    async fn open(config: LinuxKvmRecoverySmokeConfig) -> Result<Self, String> {
        if !matches!(std::env::consts::ARCH, "x86_64" | "aarch64") {
            return Err(format!(
                "unsupported Linux KVM recovery architecture: {}",
                std::env::consts::ARCH
            ));
        }
        let work_parent = canonical_plain_directory(&config.work_parent, "work parent").await?;
        let executable = canonical_plain_file(
            &config.host_service_executable,
            "Host Service executable",
            true,
        )?;
        let shim = canonical_plain_file(&config.shim, "isolated libkrun shim", true)?;
        let manifest = canonical_plain_file(
            &config.system_image_manifest,
            "Linux KVM system-image manifest",
            false,
        )?;
        let bundle = canonical_plain_directory(&config.bundle, "source OCI bundle").await?;
        let loaded = OciBundle::load(&bundle)
            .await
            .map_err(|error| format!("failed to validate source OCI bundle: {error}"))?;
        let source_revision = config
            .source_revision
            .filter(|revision| canonical_git_revision(revision))
            .ok_or_else(|| "source revision must be 40 lowercase hexadecimal digits".to_string())?;
        let nonce = unique_nonce()?;
        let evidence_root = work_parent.join(format!("kvm-recovery-{nonce}"));
        let service_root = evidence_root.join("service");
        validate_unix_socket_path(
            &service_root.join("runtime.sock"),
            "Linux KVM recovery qualification endpoint",
        )
        .map_err(|error| error.to_string())?;
        create_private_directory(&evidence_root)?;
        create_private_directory(&service_root)?;
        let artifacts = LinuxKvmRecoveryArtifacts {
            host_service_executable: executable.clone(),
            host_service_executable_sha256: sha256_file(&executable)?,
            shim: shim.clone(),
            shim_sha256: sha256_file(&shim)?,
            system_image_manifest: manifest.clone(),
            system_image_manifest_sha256: sha256_file(&manifest)?,
            source_bundle: bundle.clone(),
            source_bundle_config_digest: loaded.config_digest().to_string(),
            source_revision,
        };
        Ok(Self {
            executable,
            shim,
            manifest,
            bundle,
            service_root,
            evidence_root,
            nonce,
            artifacts,
        })
    }
}

async fn run_recovery(
    prepared: &PreparedRun,
    evidence: &mut LinuxKvmRecoveryEvidence,
) -> Result<(), String> {
    let runtime_root = prepared.service_root.join("runtime");
    let endpoint_baseline = host::endpoint_inventory()?;
    let mut first = HostServiceProcess::spawn(
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("first.stdout.log"),
        &prepared.evidence_root.join("first.stderr.log"),
    )
    .await?;
    let first_result = run_first_owner(
        prepared,
        &runtime_root,
        &endpoint_baseline,
        &first,
        evidence,
    )
    .await;
    if first_result.is_err() {
        first.emergency_stop().await;
    }
    first_result?;

    let first_socket = host::socket_identity(first.socket_path())?;
    first.sigkill().await?;
    evidence.host_service_sigkill_delivered = true;
    evidence.first_host_service_reaped = true;
    evidence.stale_socket_retained = host::socket_identity(first.socket_path())? == first_socket;
    if !evidence.stale_socket_retained {
        return Err("SIGKILLed Host Service did not leave its exact stale socket".to_string());
    }
    evidence.live_vm_processes_reaped =
        host::wait_for_processes_reaped(&evidence.live_vm_processes).await?;
    evidence.endpoint_inventory_restored =
        host::wait_for_endpoint_inventory(&endpoint_baseline).await?;
    if !evidence.live_vm_processes_reaped || !evidence.endpoint_inventory_restored {
        return Err("owner death left a KVM process or guest-agent endpoint behind".to_string());
    }
    let target = evidence
        .target
        .as_ref()
        .ok_or_else(|| "owner-death target was not retained".to_string())?;
    let digest = evidence
        .created_config_digest
        .as_deref()
        .ok_or_else(|| "owner-death config digest was not retained".to_string())?;
    evidence.authenticated_recovery_report_retained = verify_recovery_report(
        &recovery_report_path(&runtime_root, target)?,
        target,
        digest,
    )
    .await?;
    if !evidence.authenticated_recovery_report_retained {
        return Err("authenticated KVM recovery report was not retained".to_string());
    }

    let mut replacement = HostServiceProcess::spawn(
        &prepared.executable,
        &prepared.service_root,
        &prepared.shim,
        &prepared.manifest,
        &prepared.evidence_root.join("replacement.stdout.log"),
        &prepared.evidence_root.join("replacement.stderr.log"),
    )
    .await?;
    let replacement_result = run_replacement(
        prepared,
        &runtime_root,
        &endpoint_baseline,
        &mut replacement,
        evidence,
    )
    .await;
    if replacement_result.is_err() {
        replacement.emergency_stop().await;
    }
    replacement_result
}

async fn run_first_owner(
    prepared: &PreparedRun,
    runtime_root: &Path,
    endpoint_baseline: &std::collections::BTreeSet<PathBuf>,
    first: &HostServiceProcess,
    evidence: &mut LinuxKvmRecoveryEvidence,
) -> Result<(), String> {
    let identity = first.identity()?;
    evidence.first_host_service = Some(identity);
    evidence.first_socket_peer = Some(first.socket_peer()?.clone());
    let client = first.connect().await?;
    verify_qualification_scope(&client).await?;
    evidence.qualification_scope_verified = true;
    let id = ContainerId::new(format!("kvm-owner-death-{}", prepared.nonce))
        .map_err(|error| format!("failed to construct recovery container ID: {error}"))?;
    let context = operation(&prepared.nonce, "create")?;
    let staged = bundle::stage(&prepared.bundle, runtime_root, &id, &context.operation_id).await?;
    let create = CreateRequest {
        context,
        id: id.clone(),
        bundle: staged.bundle,
        isolation: IsolationRequest::DedicatedVm,
        attachments: staged.attachments,
    };
    let created = call("KVM recovery create", client.create(create.clone())).await?;
    let replayed = call("KVM recovery replayed create", client.create(create)).await?;
    evidence.create_replayed = created == replayed && !staged.directory.exists();
    if !evidence.create_replayed || *created.state.status() != ContainerState::Created {
        return Err("KVM recovery Create did not replay the exact created state".to_string());
    }
    let target = ContainerTarget::exact(id, created.generation);
    evidence.target = Some(target.clone());
    evidence.created_config_digest = Some(created.config_digest);
    let started = call(
        "KVM recovery start",
        client.start(StartRequest {
            context: operation(&prepared.nonce, "start")?,
            target: target.clone(),
        }),
    )
    .await?;
    evidence.start_returned_running = *started.state.status() == ContainerState::Running;
    if !evidence.start_returned_running {
        return Err("KVM recovery Start did not return running state".to_string());
    }
    wait_for_marker(&client, &target).await?;
    evidence.init_marker_verified = true;
    evidence.live_vm_processes = wait_for_vm_descendants(first.pid()?).await?;
    evidence.authenticated_endpoint_consumed =
        host::wait_for_endpoint_inventory(endpoint_baseline).await?;
    if !evidence.authenticated_endpoint_consumed {
        return Err("live KVM session retained its one-shot endpoint".to_string());
    }
    drop(client);
    Ok(())
}

async fn run_replacement(
    prepared: &PreparedRun,
    runtime_root: &Path,
    endpoint_baseline: &std::collections::BTreeSet<PathBuf>,
    replacement: &mut HostServiceProcess,
    evidence: &mut LinuxKvmRecoveryEvidence,
) -> Result<(), String> {
    let identity = replacement.identity()?;
    evidence.replacement_host_service = Some(identity);
    evidence.replacement_socket_peer = Some(replacement.socket_peer()?.clone());
    evidence.replacement_socket_new_owner =
        evidence.first_socket_peer != evidence.replacement_socket_peer;
    if !evidence.replacement_socket_new_owner {
        return Err("replacement socket kept the first owner identity".to_string());
    }
    let client = replacement.connect().await?;
    evidence.replacement_connected = true;
    verify_qualification_scope(&client).await?;
    let descriptors_before = host::descriptor_inventory(replacement.pid()?)?;
    evidence.open_descriptors_before = u32::try_from(descriptors_before.len()).ok();
    let target = evidence
        .target
        .clone()
        .ok_or_else(|| "recovery target disappeared before replacement".to_string())?;
    let recovered = call(
        "replacement KVM state",
        client.state(StateRequest {
            target: target.clone(),
        }),
    )
    .await?;
    evidence.exact_stopped_state_recovered = *recovered.state.status() == ContainerState::Stopped
        && recovered.generation == target.generation.expect("target is exact")
        && evidence
            .created_config_digest
            .as_deref()
            .is_some_and(|digest| recovered.config_digest == digest)
        && recovered.state.pid().is_none();
    evidence.process_inventory_empty = call(
        "replacement KVM process inventory",
        client.processes(ProcessesRequest {
            target: target.clone(),
        }),
    )
    .await?
    .is_empty();
    let wait = WaitRequest {
        target: target.clone(),
        timeout_ms: Some(20_000),
    };
    let status = call("replacement KVM wait", client.wait(wait.clone())).await?;
    evidence.recovered_wait_status = Some(status.clone());
    evidence.recovered_wait_replayed =
        call("replacement replayed KVM wait", client.wait(wait)).await? == status;
    let expected = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct SIGKILL status: {error}"))?;
    if !evidence.exact_stopped_state_recovered
        || !evidence.process_inventory_empty
        || status != expected
        || !evidence.recovered_wait_replayed
    {
        return Err("replacement did not recover exact stopped/SIGKILL state".to_string());
    }
    call(
        "replacement stopped-only delete",
        client.delete(DeleteRequest {
            context: operation(&prepared.nonce, "delete")?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    evidence.stopped_delete_succeeded = true;
    evidence.durable_state_removed = !prepared
        .service_root
        .join("state/containers")
        .join(target.id.as_str())
        .exists()
        && call(
            "replacement list after delete",
            client.list(ListRequest::default()),
        )
        .await?
        .is_empty();
    evidence.replacement_descriptor_inventory_restored =
        host::wait_for_descriptor_inventory(replacement.pid()?, &descriptors_before).await?;
    let descriptors_after = host::descriptor_inventory(replacement.pid()?)?;
    evidence.open_descriptors_after = u32::try_from(descriptors_after.len()).ok();
    let inventory = bundle::runtime_inventory(runtime_root)?;
    evidence.bundle_handoffs_clean = inventory.bundle_handoffs_clean;
    evidence.runtime_shares_clean = inventory.runtime_shares_clean;
    evidence.recovery_reports_clean = inventory.recovery_reports_clean;
    evidence.console_files_retained = inventory.console_files;
    if !evidence.durable_state_removed
        || !evidence.replacement_descriptor_inventory_restored
        || !evidence.bundle_handoffs_clean
        || !evidence.runtime_shares_clean
        || !evidence.recovery_reports_clean
        || !host::wait_for_endpoint_inventory(endpoint_baseline).await?
    {
        return Err("replacement delete did not restore cleanup baselines".to_string());
    }
    drop(client);
    evidence.replacement_exit_success = replacement.terminate().await?;
    evidence.replacement_socket_removed = !prepared.service_root.join("runtime.sock").exists();
    evidence.service_restart_recovered = evidence.replacement_exit_success
        && evidence.replacement_socket_removed
        && evidence.exact_stopped_state_recovered;
    if !evidence.service_restart_recovered {
        return Err("replacement Host Service did not shut down cleanly".to_string());
    }
    Ok(())
}

async fn verify_qualification_scope(client: &RuntimeClient) -> Result<(), String> {
    let features = call("KVM recovery features", client.features()).await?;
    let launchable = features
        .drivers
        .drivers
        .iter()
        .filter(|capability| capability.can_launch())
        .collect::<Vec<_>>();
    if launchable.len() != 1 {
        return Err(format!(
            "KVM recovery Host Service advertised {} launchable drivers, expected one",
            launchable.len()
        ));
    }
    let capability = launchable[0];
    if capability.driver != DriverKind::LibkrunKvm
        || capability.status != CapabilityStatus::Available
        || capability.readiness != DriverReadiness::Experimental
        || capability
            .evidence
            .get("qualification_scope")
            .map(String::as_str)
            != Some(QUALIFICATION_SCOPE)
    {
        return Err("KVM recovery Host Service did not retain its narrow scope".to_string());
    }
    Ok(())
}

async fn wait_for_marker(client: &RuntimeClient, target: &ContainerTarget) -> Result<(), String> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        match client
            .file(FileRequest {
                target: target.clone(),
                op: FileOp::Download,
                path: MARKER_PATH.to_string(),
                data: None,
                user: None,
                context: None,
            })
            .await
        {
            Ok(response) => {
                let decoded = response
                    .data
                    .as_deref()
                    .map(|value| STANDARD.decode(value))
                    .transpose()
                    .map_err(|error| format!("KVM marker was not base64: {error}"))?;
                return if decoded.as_deref() == Some(MARKER_CONTENTS) {
                    Ok(())
                } else {
                    Err("KVM marker contents were unexpected".to_string())
                };
            }
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(call_error("read KVM marker", &error)),
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for KVM init marker".to_string());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_vm_descendants(
    host_pid: u32,
) -> Result<Vec<super::report::LinuxProcessIdentity>, String> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        let processes = host::process_descendants(host_pid)?;
        if processes.len() >= 2 {
            return Ok(processes);
        }
        if Instant::now() >= deadline {
            return Err("Host Service did not expose KVM shim and worker descendants".to_string());
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn verify_recovery_report(
    path: &Path,
    target: &ContainerTarget,
    expected_digest: &str,
) -> Result<bool, String> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                // SAFETY: geteuid has no preconditions or failure result.
                let uid = unsafe { libc::geteuid() };
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != uid
                    || metadata.permissions().mode() & 0o777 != 0o600
                {
                    return Ok(false);
                }
                let report = AgentRecoveryReport::from_json(
                    &std::fs::read(path)
                        .map_err(|error| format!("failed to read recovery report: {error}"))?,
                )
                .map_err(|error| format!("retained recovery report is invalid: {error}"))?;
                return Ok(report.records().iter().any(|record| {
                    record.target == *target
                        && record.config_digest == expected_digest
                        && record.init_exit_status
                            == ExitStatus::signaled(libc::SIGKILL, false)
                                .expect("fixed SIGKILL status")
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("failed to inspect recovery report: {error}")),
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn recovery_report_path(runtime_root: &Path, target: &ContainerTarget) -> Result<PathBuf, String> {
    let generation = target
        .generation
        .ok_or_else(|| "recovery report requires an exact generation".to_string())?;
    Ok(runtime_root
        .join("recovery")
        .join(format!("{}-{}.json", target.id, generation.0)))
}

fn operation(nonce: &str, suffix: &str) -> Result<OperationContext, String> {
    OperationId::new(format!("kvm-recovery-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct recovery operation ID: {error}"))
}

async fn call<T>(
    label: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(call_error(label, &error)),
        Err(_) => Err(format!("{label} timed out")),
    }
}

fn call_error(label: &str, error: &Error) -> String {
    format!("{label} failed with {:?}: {}", error.code, error.message)
}

fn persist_report(report: &LinuxKvmRecoverySmokeReport) -> Result<(), String> {
    let encoded = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("failed to encode KVM recovery report: {error}"))?;
    let path = report.evidence_root.join("report.json");
    let pending = report.evidence_root.join("report.json.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&pending)
        .map_err(|error| format!("failed to create report pending file: {error}"))?;
    file.write_all(&encoded)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to persist KVM recovery report: {error}"))?;
    drop(file);
    std::fs::rename(&pending, &path)
        .map_err(|error| format!("failed to publish KVM recovery report: {error}"))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("failed to open {} for hashing: {error}", path.display()))?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)
        .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn canonical_plain_file(path: &Path, label: &str, executable: bool) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a plain file: {}", path.display()));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!("{label} is not executable: {}", path.display()));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "{label} must be an absolute canonical path: {} -> {}",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

async fn canonical_plain_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|error| format!("failed to inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} is not a plain directory: {}",
            path.display()
        ));
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|error| format!("failed to resolve {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "{label} must be an absolute canonical path: {} -> {}",
            path.display(),
            canonical.display()
        ));
    }
    Ok(canonical)
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))
}

fn unique_nonce() -> Result<String, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?
        .as_nanos();
    Ok(format!("{}-{nanos}", std::process::id()))
}
