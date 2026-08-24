use std::path::Path;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentClient, AgentCreateRequest, AgentDeleteRequest, AgentStateRequest, GuestPath,
    AGENT_RUNTIME_SHARE_STATE_GUEST_ROOT,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerId, ContainerTarget, DeleteMode, Error, ErrorCode, FileOp, FileRequest, FilesystemOp,
    FilesystemRequest, Generation, IoMode, OciBundle, OperationContext, OperationId, ProcessIo,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

use super::{
    canonical_directory, fixed_rootfs, guest_path, runtime_entries, unique_nonce,
    GUEST_RUNTIME_PREFIX,
};
use crate::agent_session::UtilityVmSession;
use crate::{OciVmGuestIsolationCaseEvidence, OciVmGuestIsolationSmokeReport};

mod fixture;

use fixture::IsolationFixture;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const CANARY_CONTENTS: &[u8] = b"a3s-oci-guest-isolation-canary-v1\n";
const TAMPER_CONTENTS: &[u8] = b"guest-isolation-escape-must-not-write\n";
const FILESYSTEM_OPERATION: &str = "linux-container-filesystem";

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: Option<&Path>,
    runtime_share: &Path,
    bundle_directory: &Path,
    console: &Path,
) -> OciVmGuestIsolationSmokeReport {
    let mut report = OciVmGuestIsolationSmokeReport::initial(HostPlatform::current());
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM bootstrap root").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let runtime_share = match canonical_directory(runtime_share, "VM runtime share").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if paths_overlap(&vm_rootfs, &runtime_share) {
        return failed(
            report,
            "Guest isolation qualification requires disjoint VM bootstrap and runtime-share roots",
        );
    }
    report.separate_runtime_share = true;

    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if bundle_directory == runtime_share || !bundle_directory.starts_with(&runtime_share) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM runtime share {}: {}",
                runtime_share.display(),
                bundle_directory.display()
            ),
        );
    }
    let bundle = match OciBundle::load(&bundle_directory).await {
        Ok(bundle) => {
            report.bundle_loaded = true;
            bundle
        }
        Err(error) => return failed(report, format!("failed to load OCI bundle: {error}")),
    };
    if let Err(reason) = fixed_rootfs(&bundle).await {
        return failed(report, reason);
    }
    let base_guest_bundle = match guest_path(&runtime_share, &bundle_directory) {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let baseline_runtime_entries = match runtime_entries(&runtime_share).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let fixture = match IsolationFixture::prepare(&runtime_share, &bundle, &nonce).await {
        Ok(fixture) => fixture,
        Err(reason) => return failed(report, reason),
    };

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let host_cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
    let session = match UtilityVmSession::connect_with_separate_runtime_share(
        shim,
        &vm_rootfs,
        system_image_manifest,
        &runtime_share,
        console,
    )
    .await
    {
        Ok(session) => session,
        Err(bridge) => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let bridge = {
                let mut bridge = bridge;
                host_cleanup.apply(&mut bridge).await;
                bridge
            };
            report.reason = bridge.reason.clone();
            report.bridge = bridge;
            finish_fixture_cleanup(&mut report, fixture).await;
            finish_runtime_inventory(&mut report, &runtime_share, &baseline_runtime_entries).await;
            return report;
        }
    };

    let client = session.client();
    let exercise = exercise(&client, base_guest_bundle, &fixture, &nonce, &mut report).await;
    report.bridge = match &exercise {
        Ok(()) => session.shutdown().await,
        Err(reason) => session.shutdown_with_failure(reason).await,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    host_cleanup.apply(&mut report.bridge).await;

    finish_fixture_cleanup(&mut report, fixture).await;
    finish_runtime_inventory(&mut report, &runtime_share, &baseline_runtime_entries).await;
    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    } else if !report.bridge.is_success() {
        let reason = report
            .bridge
            .reason
            .clone()
            .unwrap_or_else(|| "authenticated Guest bridge cleanup failed".to_string());
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

async fn exercise<T>(
    client: &AgentClient<T>,
    base_guest_bundle: GuestPath,
    fixture: &IsolationFixture,
    nonce: &str,
    report: &mut OciVmGuestIsolationSmokeReport,
) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    for (index, case) in fixture.create_cases.iter().enumerate() {
        let target = case_target(nonce, index)?;
        let evidence = reject_create(
            client,
            CreateRejectionCase {
                target: &target,
                bundle: &case.bundle,
                guest_directory: case.guest_directory.clone(),
                name: &case.name,
                expected_operation: case.expected_operation,
                nonce,
                canary: &fixture.canary,
            },
        )
        .await;
        report.cases.push(evidence);
    }

    let file_index = report.cases.len();
    report.cases.push(
        reject_container_api(
            client,
            ContainerApiRejectionCase {
                target: &case_target(nonce, file_index)?,
                bundle: &fixture.container_api_bundle,
                guest_directory: base_guest_bundle.clone(),
                name: "file-intermediate-magic-link-escape",
                case: ContainerApiCase::FileUpload,
                nonce,
                fixture,
            },
        )
        .await,
    );
    let filesystem_index = report.cases.len();
    report.cases.push(
        reject_container_api(
            client,
            ContainerApiRejectionCase {
                target: &case_target(nonce, filesystem_index)?,
                bundle: &fixture.container_api_bundle,
                guest_directory: base_guest_bundle,
                name: "filesystem-intermediate-magic-link-escape",
                case: ContainerApiCase::FilesystemRemove,
                nonce,
                fixture,
            },
        )
        .await,
    );

    let failed_cases = report
        .cases
        .iter()
        .filter(|case| !case.is_success())
        .map(|case| case.name.as_str())
        .collect::<Vec<_>>();
    if failed_cases.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Guest isolation cases failed: {}",
            failed_cases.join(", ")
        ))
    }
}

struct CreateRejectionCase<'a> {
    target: &'a ContainerTarget,
    bundle: &'a OciBundle,
    guest_directory: GuestPath,
    name: &'a str,
    expected_operation: &'static str,
    nonce: &'a str,
    canary: &'a Path,
}

async fn reject_create<T>(
    client: &AgentClient<T>,
    case: CreateRejectionCase<'_>,
) -> OciVmGuestIsolationCaseEvidence
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let CreateRejectionCase {
        target,
        bundle,
        guest_directory,
        name,
        expected_operation,
        nonce,
        canary,
    } = case;
    let mut evidence = OciVmGuestIsolationCaseEvidence::initial(name, expected_operation);
    let operation = match operation(nonce, name, "create") {
        Ok(operation) => operation,
        Err(reason) => {
            evidence.observed_error_message = Some(reason);
            return evidence;
        }
    };
    match timeout(
        CALL_TIMEOUT,
        client.create(AgentCreateRequest {
            context: operation,
            target: target.clone(),
            bundle: AgentBundle::new(bundle, guest_directory),
            io: null_io(),
        }),
    )
    .await
    {
        Ok(Err(error)) => record_rejection(&mut evidence, error),
        Ok(Ok(state)) => {
            evidence.observed_error_message = Some(format!(
                "hostile create unexpectedly returned container state {:?}",
                state.status()
            ));
        }
        Err(_) => {
            evidence.observed_error_message =
                Some("hostile create exceeded its bounded call timeout".to_string());
        }
    }
    evidence.container_state_absent_after_case =
        cleanup_and_require_absent(client, target, nonce, name).await;
    evidence.canary_unchanged = canary_unchanged(canary).await;
    evidence
}

enum ContainerApiCase {
    FileUpload,
    FilesystemRemove,
}

struct ContainerApiRejectionCase<'a> {
    target: &'a ContainerTarget,
    bundle: &'a OciBundle,
    guest_directory: GuestPath,
    name: &'a str,
    case: ContainerApiCase,
    nonce: &'a str,
    fixture: &'a IsolationFixture,
}

async fn reject_container_api<T>(
    client: &AgentClient<T>,
    rejection: ContainerApiRejectionCase<'_>,
) -> OciVmGuestIsolationCaseEvidence
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ContainerApiRejectionCase {
        target,
        bundle,
        guest_directory,
        name,
        case,
        nonce,
        fixture,
    } = rejection;
    let mut evidence = OciVmGuestIsolationCaseEvidence::initial(name, FILESYSTEM_OPERATION);
    let create_context = match operation(nonce, name, "create") {
        Ok(context) => context,
        Err(reason) => {
            evidence.observed_error_message = Some(reason);
            return evidence;
        }
    };
    let created = timeout(
        CALL_TIMEOUT,
        client.create(AgentCreateRequest {
            context: create_context,
            target: target.clone(),
            bundle: AgentBundle::new(bundle, guest_directory),
            io: null_io(),
        }),
    )
    .await;
    match created {
        Ok(Ok(state)) if state.status() == ContainerState::Created => {}
        Ok(Ok(state)) => {
            evidence.observed_error_message = Some(format!(
                "API isolation setup returned unexpected container state {:?}",
                state.status()
            ));
            evidence.container_state_absent_after_case =
                cleanup_and_require_absent(client, target, nonce, name).await;
            evidence.canary_unchanged = canary_unchanged(&fixture.canary).await;
            return evidence;
        }
        Ok(Err(error)) => {
            evidence.observed_error_message =
                Some(format!("API isolation setup create failed: {error}"));
            evidence.container_state_absent_after_case =
                cleanup_and_require_absent(client, target, nonce, name).await;
            evidence.canary_unchanged = canary_unchanged(&fixture.canary).await;
            return evidence;
        }
        Err(_) => {
            evidence.observed_error_message =
                Some("API isolation setup create timed out".to_string());
            evidence.container_state_absent_after_case =
                cleanup_and_require_absent(client, target, nonce, name).await;
            evidence.canary_unchanged = canary_unchanged(&fixture.canary).await;
            return evidence;
        }
    }

    let hostile_path = format!(
        "/proc/self/root{}/{}",
        AGENT_RUNTIME_SHARE_STATE_GUEST_ROOT, fixture.canary_name
    );
    let result = match case {
        ContainerApiCase::FileUpload => {
            let context = match operation(nonce, name, "file") {
                Ok(context) => context,
                Err(reason) => {
                    evidence.observed_error_message = Some(reason);
                    evidence.container_state_absent_after_case =
                        cleanup_and_require_absent(client, target, nonce, name).await;
                    evidence.canary_unchanged = canary_unchanged(&fixture.canary).await;
                    return evidence;
                }
            };
            timeout(
                CALL_TIMEOUT,
                client.file(FileRequest {
                    target: target.clone(),
                    op: FileOp::Upload,
                    path: hostile_path,
                    data: Some(STANDARD.encode(TAMPER_CONTENTS)),
                    user: None,
                    context: Some(context),
                }),
            )
            .await
            .map(|result| result.map(|_| ()))
        }
        ContainerApiCase::FilesystemRemove => {
            let context = match operation(nonce, name, "filesystem") {
                Ok(context) => context,
                Err(reason) => {
                    evidence.observed_error_message = Some(reason);
                    evidence.container_state_absent_after_case =
                        cleanup_and_require_absent(client, target, nonce, name).await;
                    evidence.canary_unchanged = canary_unchanged(&fixture.canary).await;
                    return evidence;
                }
            };
            timeout(
                CALL_TIMEOUT,
                client.filesystem(FilesystemRequest {
                    target: target.clone(),
                    op: FilesystemOp::Remove,
                    path: hostile_path,
                    destination: None,
                    depth: 0,
                    user: None,
                    context: Some(context),
                }),
            )
            .await
            .map(|result| result.map(|_| ()))
        }
    };
    match result {
        Ok(Err(error)) => record_rejection(&mut evidence, error),
        Ok(Ok(())) => {
            evidence.observed_error_message =
                Some("hostile container filesystem request unexpectedly succeeded".to_string());
        }
        Err(_) => {
            evidence.observed_error_message =
                Some("hostile container filesystem request timed out".to_string());
        }
    }
    evidence.container_state_absent_after_case =
        cleanup_and_require_absent(client, target, nonce, name).await;
    evidence.canary_unchanged = canary_unchanged(&fixture.canary).await;
    evidence
}

fn record_rejection(evidence: &mut OciVmGuestIsolationCaseEvidence, error: Error) {
    evidence.request_rejected = true;
    evidence.observed_error_code = Some(error.code);
    evidence.observed_error_operation = error.operation;
    evidence.observed_error_message = Some(error.message);
    evidence.observed_error_retryable = error.retryable;
}

async fn cleanup_and_require_absent<T>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    nonce: &str,
    case: &str,
) -> bool
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    match timeout(
        CLEANUP_TIMEOUT,
        client.state(AgentStateRequest {
            target: target.clone(),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::NotFound => return true,
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => return false,
    }
    let context = match operation(nonce, case, "cleanup") {
        Ok(context) => context,
        Err(_) => return false,
    };
    let _ = timeout(
        CLEANUP_TIMEOUT,
        client.delete(AgentDeleteRequest {
            context,
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await;
    matches!(
        timeout(
            CLEANUP_TIMEOUT,
            client.state(AgentStateRequest {
                target: target.clone(),
            })
        )
        .await,
        Ok(Err(error)) if error.code == ErrorCode::NotFound
    )
}

fn case_target(nonce: &str, index: usize) -> Result<ContainerTarget, String> {
    let id = ContainerId::new(format!("guest-isolation-{index}-{nonce}"))
        .map_err(|error| format!("failed to construct Guest isolation container ID: {error}"))?;
    Ok(ContainerTarget::exact(id, Generation(1)))
}

fn operation(nonce: &str, case: &str, phase: &str) -> Result<OperationContext, String> {
    let operation_id = OperationId::new(format!("guest-isolation-{nonce}-{case}-{phase}"))
        .map_err(|error| format!("failed to construct Guest isolation operation ID: {error}"))?;
    Ok(OperationContext::new(operation_id))
}

fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    }
}

async fn canary_unchanged(path: &Path) -> bool {
    tokio::fs::read(path)
        .await
        .is_ok_and(|contents| contents == CANARY_CONTENTS)
}

async fn finish_fixture_cleanup(
    report: &mut OciVmGuestIsolationSmokeReport,
    fixture: IsolationFixture,
) {
    match fixture.cleanup().await {
        Ok(()) => {
            report.fixture_removed = true;
            report.canary_removed = true;
        }
        Err(reason) => append_reason(report, reason),
    }
}

async fn finish_runtime_inventory(
    report: &mut OciVmGuestIsolationSmokeReport,
    runtime_share: &Path,
    baseline: &std::collections::BTreeSet<String>,
) {
    match runtime_entries(runtime_share).await {
        Ok(entries) => {
            report.guest_runtime_clean = &entries == baseline;
            if !report.guest_runtime_clean {
                append_reason(
                    report,
                    format!(
                        "Guest Agent left {GUEST_RUNTIME_PREFIX} runtime directories after isolation qualification"
                    ),
                );
            }
        }
        Err(reason) => append_reason(report, reason),
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn append_reason(report: &mut OciVmGuestIsolationSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmGuestIsolationSmokeReport,
    reason: impl Into<String>,
) -> OciVmGuestIsolationSmokeReport {
    append_reason(&mut report, reason);
    report
}
