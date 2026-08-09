use std::path::Path;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentCreateRequest, AgentOperation, AgentStateRequest,
    AgentTransportFaultInjector, AgentTransportFaultPoint, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationEvidence,
    AgentTransportQualificationRequest, AGENT_PROTOCOL_VERSION_MAX,
    AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{Error, ErrorCode, IoMode, OciBundle, OperationContext, OperationId, ProcessIo};
use tokio::time::timeout;

use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, remove_marker, runtime_entries,
    target, unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_session::UtilityVmSession;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{is_supported_transport_fault_stage, OciVmTransportFaultCleanupReport};

const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(15);
const FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";
const MAX_GUEST_CONSOLE_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
struct HostTransportFault {
    stage: AgentTransportFaultStage,
    crossings: AtomicU32,
    protocol_version: AtomicU16,
}

impl HostTransportFault {
    const fn new(stage: AgentTransportFaultStage) -> Self {
        Self {
            stage,
            crossings: AtomicU32::new(0),
            protocol_version: AtomicU16::new(0),
        }
    }

    fn crossing_count(&self) -> u32 {
        self.crossings.load(Ordering::SeqCst)
    }

    fn protocol_version(&self) -> Option<u16> {
        match self.protocol_version.load(Ordering::SeqCst) {
            0 => None,
            version => Some(version),
        }
    }

    fn injected_point(&self) -> Option<String> {
        self.protocol_version().map(|protocol_version| {
            match self.stage {
                AgentTransportFaultStage::Operation(stage) => AgentTransportFaultPoint::Operation {
                    protocol_version,
                    operation: AgentOperation::Create,
                    stage,
                },
                AgentTransportFaultStage::Shutdown(stage) => AgentTransportFaultPoint::Shutdown {
                    protocol_version,
                    stage,
                },
            }
            .to_string()
        })
    }
}

impl AgentTransportFaultInjector for HostTransportFault {
    fn check(&self, point: AgentTransportFaultPoint) -> a3s_oci_sdk::Result<()> {
        let protocol_version = match (self.stage, point) {
            (
                AgentTransportFaultStage::Operation(selected),
                AgentTransportFaultPoint::Operation {
                    protocol_version,
                    operation: AgentOperation::Create,
                    stage,
                },
            ) if stage == selected => protocol_version,
            (
                AgentTransportFaultStage::Shutdown(selected),
                AgentTransportFaultPoint::Shutdown {
                    protocol_version,
                    stage,
                },
            ) if stage == selected => protocol_version,
            _ => return Ok(()),
        };
        self.protocol_version
            .store(protocol_version, Ordering::SeqCst);
        let crossing = self.crossings.fetch_add(1, Ordering::SeqCst) + 1;
        if crossing != 1 {
            return Ok(());
        }
        Err(Error::new(
            ErrorCode::Unavailable,
            format!("injected real utility-VM transport fault at {point}"),
        )
        .for_operation(FAULT_OPERATION)
        .retryable(true))
    }
}

pub(super) async fn run(
    shim: &Path,
    vm_rootfs: &Path,
    bundle_directory: &Path,
    console: &Path,
    stage: AgentTransportFaultStage,
) -> OciVmTransportFaultCleanupReport {
    let mut report = OciVmTransportFaultCleanupReport::initial(HostPlatform::current(), stage);
    if !is_supported_transport_fault_stage(stage) {
        return failed(
            report,
            format!(
                "real utility-VM transport cleanup does not implement stage {}",
                stage.as_str()
            ),
        );
    }
    let vm_rootfs = match canonical_directory(vm_rootfs, "VM rootfs").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let bundle_directory = match canonical_directory(bundle_directory, "OCI bundle").await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    if bundle_directory == vm_rootfs || !bundle_directory.starts_with(&vm_rootfs) {
        return failed(
            report,
            format!(
                "OCI bundle must be a strict descendant of VM rootfs {}: {}",
                vm_rootfs.display(),
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
    let rootfs = match fixed_rootfs(&bundle).await {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let marker = rootfs.join(MARKER_NAME);
    match path_exists(&marker).await {
        Ok(false) => {}
        Ok(true) => {
            return failed(
                report,
                format!(
                    "refusing to overwrite an existing OCI transport-cleanup marker: {}",
                    marker.display()
                ),
            );
        }
        Err(reason) => return failed(report, reason),
    }

    let guest_bundle = match guest_path(&vm_rootfs, &bundle_directory) {
        Ok(path) => path,
        Err(reason) => return failed(report, reason),
    };
    let baseline_runtime_entries = match runtime_entries(&vm_rootfs).await {
        Ok(entries) => entries,
        Err(reason) => return failed(report, reason),
    };
    let nonce = match unique_nonce() {
        Ok(nonce) => nonce,
        Err(reason) => return failed(report, reason),
    };
    let target = match target(&format!("transport-fault-{nonce}")) {
        Ok(target) => target,
        Err(reason) => return failed(report, reason),
    };
    let operation_id = match OperationId::new(format!("transport-fault-{nonce}-create")) {
        Ok(operation_id) => operation_id,
        Err(error) => {
            return failed(
                report,
                format!("failed to construct transport-fault operation ID: {error}"),
            )
        }
    };
    report.qualification_operation_id = Some(operation_id.clone());
    let context = OperationContext::new(operation_id.clone());
    let guest_qualification = match stage {
        AgentTransportFaultStage::Operation(stage) if stage.is_guest() => {
            match AgentTransportQualificationRequest::new(
                operation_id,
                AgentOperation::Create,
                stage,
            ) {
                Ok(request) => Some(request),
                Err(error) => {
                    return failed(
                        report,
                        format!("failed to construct guest transport qualification: {error}"),
                    )
                }
            }
        }
        _ => None,
    };

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
    let faults = Arc::new(HostTransportFault::new(stage));
    let session_result = match &guest_qualification {
        Some(qualification) => {
            UtilityVmSession::connect_with_guest_qualification(
                shim,
                &vm_rootfs,
                console,
                qualification,
            )
            .await
        }
        None => {
            UtilityVmSession::connect_with_host_fault_injector(
                shim,
                &vm_rootfs,
                console,
                Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
            )
            .await
        }
    };
    let session = match session_result {
        Ok(session) => session,
        Err(bridge) => {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let bridge = {
                let mut bridge = bridge;
                cleanup.apply(&mut bridge).await;
                bridge
            };
            report.reason = bridge.reason.clone();
            report.bridge = bridge;
            return report;
        }
    };

    let client = session.client();
    let request = AgentCreateRequest {
        context,
        target: target.clone(),
        bundle: AgentBundle::new(&bundle, guest_bundle),
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    };
    let exercise = match stage {
        AgentTransportFaultStage::Operation(stage) if stage.is_host() => {
            match timeout(QUALIFICATION_TIMEOUT, client.create(request)).await {
                Ok(Err(error)) => record_host_interruption(&mut report, error),
                Ok(Ok(_)) => {
                    Err("transport-fault create unexpectedly returned success".to_string())
                }
                Err(_) => Err(format!(
                    "transport-fault create exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                )),
            }
        }
        AgentTransportFaultStage::Operation(
            AgentTransportOperationStage::GuestAfterResponseWrite,
        ) => match timeout(QUALIFICATION_TIMEOUT, client.create(request)).await {
            Ok(Ok(_)) => {
                report.primary_response_received = true;
                report.disconnect_probe_attempted = true;
                match timeout(
                    QUALIFICATION_TIMEOUT,
                    client.state(AgentStateRequest {
                        target: target.clone(),
                    }),
                )
                .await
                {
                    Ok(Err(error)) => record_guest_disconnect(&mut report, error),
                    Ok(Ok(_)) => Err(
                        "guest-after-response-write disconnect probe unexpectedly succeeded"
                            .to_string(),
                    ),
                    Err(_) => Err(format!(
                        "guest-after-response-write disconnect probe exceeded the {} second timeout",
                        QUALIFICATION_TIMEOUT.as_secs()
                    )),
                }
            }
            Ok(Err(error)) => Err(format!(
                "guest-after-response-write create did not deliver its completed response: {error}"
            )),
            Err(_) => Err(format!(
                "guest-after-response-write create exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            )),
        },
        AgentTransportFaultStage::Operation(stage) => {
            match timeout(QUALIFICATION_TIMEOUT, client.create(request)).await {
                Ok(Err(error)) => record_guest_disconnect(&mut report, error),
                Ok(Ok(_)) => Err(format!(
                    "{} create unexpectedly returned success",
                    stage.as_str()
                )),
                Err(_) => Err(format!(
                    "{} create exceeded the {} second timeout",
                    stage.as_str(),
                    QUALIFICATION_TIMEOUT.as_secs()
                )),
            }
        }
        AgentTransportFaultStage::Shutdown(stage) => {
            match timeout(QUALIFICATION_TIMEOUT, client.create(request)).await {
                Ok(Ok(_)) => {
                    report.primary_response_received = true;
                    match timeout(QUALIFICATION_TIMEOUT, client.close()).await {
                        Ok(Err(error)) => record_host_interruption(&mut report, error),
                        Ok(Ok(())) => Err(format!(
                            "{} close unexpectedly returned success",
                            stage.as_str()
                        )),
                        Err(_) => Err(format!(
                            "{} close exceeded the {} second timeout",
                            stage.as_str(),
                            QUALIFICATION_TIMEOUT.as_secs()
                        )),
                    }
                }
                Ok(Err(error)) => Err(format!(
                    "{} setup create returned an unexpected error: {error}",
                    stage.as_str()
                )),
                Err(_) => Err(format!(
                    "{} setup create exceeded the {} second timeout",
                    stage.as_str(),
                    QUALIFICATION_TIMEOUT.as_secs()
                )),
            }
        }
    };
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }

    report.bridge = match &exercise {
        Ok(()) => session.shutdown().await,
        Err(reason) => session.shutdown_with_failure(reason).await,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    cleanup.apply(&mut report.bridge).await;

    if let Some(qualification) = &guest_qualification {
        match read_guest_qualification_evidence(console, qualification).await {
            Ok(evidence) => {
                report.negotiated_protocol = Some(evidence.protocol_version());
                report.injected_point = Some(evidence.injected_point());
                report.fault_crossings = evidence.fault_crossings();
                report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
                report.guest_evidence_verified = evidence.matches_request(qualification)
                    && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
                    && evidence.fault_crossings() == 1;
                if !report.guest_evidence_verified {
                    append_reason(
                        &mut report,
                        "guest transport qualification evidence did not match the exact request",
                    );
                }
            }
            Err(reason) => append_reason(&mut report, reason),
        }
    }

    match path_exists(&marker).await {
        Ok(false) => report.marker_absent_after_cleanup = true,
        Ok(true) => {
            append_reason(
                &mut report,
                format!(
                    "OCI workload marker appeared despite create transport interruption: {}",
                    marker.display()
                ),
            );
            if let Err(reason) = remove_marker(&marker).await {
                append_reason(&mut report, reason);
            }
        }
        Err(reason) => append_reason(&mut report, reason),
    }
    match runtime_entries(&vm_rootfs).await {
        Ok(entries) => {
            report.guest_runtime_clean = entries == baseline_runtime_entries;
            if !report.guest_runtime_clean {
                append_reason(
                    &mut report,
                    format!(
                        "guest agent left {GUEST_RUNTIME_PREFIX} runtime directories after \
                         transport fault cleanup"
                    ),
                );
            }
        }
        Err(reason) => append_reason(&mut report, reason),
    }

    if let Err(reason) = exercise {
        append_reason(&mut report, reason);
    } else if report.fault_crossings != 1 {
        let fault_crossings = report.fault_crossings;
        append_reason(
            &mut report,
            format!(
                "selected transport point crossed {} times instead of once",
                fault_crossings
            ),
        );
    } else if !report.bridge.is_success() {
        let reason = report
            .bridge
            .reason
            .clone()
            .unwrap_or_else(|| "authenticated guest bridge cleanup failed".into());
        append_reason(&mut report, reason);
    }
    if report.evidence_succeeded() {
        report.status = CapabilityStatus::Available;
        report.reason = None;
    }
    report
}

fn record_host_interruption(
    report: &mut OciVmTransportFaultCleanupReport,
    error: Error,
) -> Result<(), String> {
    report.observed_error_code = Some(error.code);
    report.observed_error_operation = error.operation.clone();
    report.observed_error_retryable = error.retryable;
    if error.code == ErrorCode::Unavailable
        && error.operation.as_deref() == Some(FAULT_OPERATION)
        && error.retryable
    {
        Ok(())
    } else {
        Err(format!(
            "transport qualification returned an unexpected injected error: {error}"
        ))
    }
}

fn record_guest_disconnect(
    report: &mut OciVmTransportFaultCleanupReport,
    error: Error,
) -> Result<(), String> {
    report.observed_error_code = Some(error.code);
    report.observed_error_operation = error.operation.clone();
    report.observed_error_retryable = error.retryable;
    let expected_operation = error
        .operation
        .as_deref()
        .is_some_and(is_retryable_disconnect_operation);
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "guest transport fault returned an unexpected disconnect error: {error}"
        ))
    }
}

async fn read_guest_qualification_evidence(
    console: &Path,
    request: &AgentTransportQualificationRequest,
) -> Result<AgentTransportQualificationEvidence, String> {
    let metadata = tokio::fs::symlink_metadata(console)
        .await
        .map_err(|error| {
            format!(
                "failed to inspect guest qualification console {}: {error}",
                console.display()
            )
        })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "guest qualification console is not a regular file: {}",
            console.display()
        ));
    }
    if metadata.len() > MAX_GUEST_CONSOLE_BYTES {
        return Err(format!(
            "guest qualification console contains {} bytes; maximum is {}",
            metadata.len(),
            MAX_GUEST_CONSOLE_BYTES
        ));
    }
    let content = tokio::fs::read(console).await.map_err(|error| {
        format!(
            "failed to read guest qualification console {}: {error}",
            console.display()
        )
    })?;
    let mut evidence = None;
    for line in content.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(payload) =
            line.strip_prefix(AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX.as_bytes())
        else {
            continue;
        };
        if evidence.is_some() {
            return Err(
                "guest console emitted more than one transport qualification evidence line"
                    .to_string(),
            );
        }
        let payload = std::str::from_utf8(payload).map_err(|error| {
            format!("guest transport qualification evidence is not UTF-8: {error}")
        })?;
        evidence = Some(
            AgentTransportQualificationEvidence::from_json(payload)
                .map_err(|error| error.to_string())?,
        );
    }
    let evidence = evidence
        .ok_or_else(|| "guest console emitted no transport qualification evidence".to_string())?;
    if !evidence.matches_request(request) {
        return Err(
            "guest transport qualification evidence does not match the armed operation ID and stage"
                .to_string(),
        );
    }
    Ok(evidence)
}

fn append_reason(report: &mut OciVmTransportFaultCleanupReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

fn failed(
    mut report: OciVmTransportFaultCleanupReport,
    reason: impl Into<String>,
) -> OciVmTransportFaultCleanupReport {
    append_reason(&mut report, reason);
    report
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{
        AgentOperation, AgentTransportFaultInjector, AgentTransportFaultPoint,
        AgentTransportOperationStage, AgentTransportQualificationEvidence,
        AgentTransportQualificationRequest, AgentTransportShutdownStage,
        AGENT_PROTOCOL_VERSION_MAX, AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX,
    };
    use a3s_oci_sdk::{ErrorCode, OperationId};

    use super::{read_guest_qualification_evidence, HostTransportFault};

    #[test]
    fn real_host_fault_injector_fires_once_only_at_the_selected_create_stage() {
        let selected = AgentTransportOperationStage::HostBeforeResponseRead;
        let injector = HostTransportFault::new(selected.into());
        let other = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::State,
            stage: selected,
        };
        assert!(injector.check(other).is_ok());

        let target = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Create,
            stage: selected,
        };
        let error = injector
            .check(target)
            .expect_err("selected point must fail once");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        assert!(injector.check(target).is_ok());
        assert_eq!(injector.crossing_count(), 2);
        assert_eq!(
            injector.protocol_version(),
            Some(AGENT_PROTOCOL_VERSION_MAX)
        );
        assert_eq!(injector.injected_point(), Some(target.to_string()));
    }

    #[test]
    fn real_host_fault_injector_fires_once_only_at_the_selected_shutdown_stage() {
        let selected = AgentTransportShutdownStage::HostAfterShutdown;
        let injector = HostTransportFault::new(selected.into());
        let other = AgentTransportFaultPoint::Operation {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            operation: AgentOperation::Create,
            stage: AgentTransportOperationStage::HostAfterResponseRead,
        };
        assert!(injector.check(other).is_ok());

        let target = AgentTransportFaultPoint::Shutdown {
            protocol_version: AGENT_PROTOCOL_VERSION_MAX,
            stage: selected,
        };
        let error = injector
            .check(target)
            .expect_err("selected shutdown point must fail once");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert!(error.retryable);
        assert!(injector.check(target).is_ok());
        assert_eq!(injector.crossing_count(), 2);
        assert_eq!(injector.injected_point(), Some(target.to_string()));
    }

    #[tokio::test]
    async fn console_evidence_is_bounded_unique_and_nonce_bound() {
        let request = AgentTransportQualificationRequest::new(
            OperationId::new("console-evidence-create").expect("operation ID"),
            AgentOperation::Create,
            AgentTransportOperationStage::GuestAfterDispatch,
        )
        .expect("qualification request");
        let evidence =
            AgentTransportQualificationEvidence::new(&request, AGENT_PROTOCOL_VERSION_MAX, 1)
                .to_json()
                .expect("encode evidence");
        let temporary = tempfile::tempdir().expect("temporary directory");
        let console = temporary.path().join("console.log");
        std::fs::write(
            &console,
            format!(
                "kernel booted\r\n{AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX}{evidence}\r\n"
            ),
        )
        .expect("write console");
        let parsed = read_guest_qualification_evidence(&console, &request)
            .await
            .expect("parse exact evidence");
        assert!(parsed.matches_request(&request));

        std::fs::write(
            &console,
            format!(
                "{AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX}{evidence}\n\
                 {AGENT_TRANSPORT_QUALIFICATION_EVIDENCE_PREFIX}{evidence}\n"
            ),
        )
        .expect("write duplicate evidence");
        let error = read_guest_qualification_evidence(&console, &request)
            .await
            .expect_err("duplicate evidence must fail closed");
        assert!(error.contains("more than one"));
    }
}
