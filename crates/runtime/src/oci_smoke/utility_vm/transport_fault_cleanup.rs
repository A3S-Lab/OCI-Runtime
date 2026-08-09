use std::path::Path;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentBundle, AgentCreateRequest, AgentOperation, AgentTransportFaultInjector,
    AgentTransportFaultPoint, AgentTransportOperationStage,
};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{Error, ErrorCode, IoMode, OciBundle, OperationContext, OperationId, ProcessIo};
use tokio::time::timeout;

use super::{
    canonical_directory, fixed_rootfs, guest_path, path_exists, remove_marker, runtime_entries,
    target, unique_nonce, GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use crate::agent_session::UtilityVmSession;
use crate::{is_supported_host_stage, OciVmTransportFaultCleanupReport};

const CREATE_TIMEOUT: Duration = Duration::from_secs(15);
const FAULT_OPERATION: &str = "oci-vm-transport-qualification-fault";

#[derive(Debug)]
struct HostCreateTransportFault {
    stage: AgentTransportOperationStage,
    crossings: AtomicU32,
    protocol_version: AtomicU16,
}

impl HostCreateTransportFault {
    const fn new(stage: AgentTransportOperationStage) -> Self {
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
            AgentTransportFaultPoint::Operation {
                protocol_version,
                operation: AgentOperation::Create,
                stage: self.stage,
            }
            .to_string()
        })
    }
}

impl AgentTransportFaultInjector for HostCreateTransportFault {
    fn check(&self, point: AgentTransportFaultPoint) -> a3s_oci_sdk::Result<()> {
        let AgentTransportFaultPoint::Operation {
            protocol_version,
            operation: AgentOperation::Create,
            stage,
        } = point
        else {
            return Ok(());
        };
        if stage != self.stage {
            return Ok(());
        }
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
    stage: AgentTransportOperationStage,
) -> OciVmTransportFaultCleanupReport {
    let mut report = OciVmTransportFaultCleanupReport::initial(HostPlatform::current(), stage);
    if !is_supported_host_stage(stage) {
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
    let context = match OperationId::new(format!("transport-fault-{nonce}-create")) {
        Ok(operation_id) => OperationContext::new(operation_id),
        Err(error) => {
            return failed(
                report,
                format!("failed to construct transport-fault operation ID: {error}"),
            )
        }
    };

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let cleanup = crate::host_cleanup::MacosHostCleanupTracker::capture();
    let faults = Arc::new(HostCreateTransportFault::new(stage));
    let session = match UtilityVmSession::connect_with_host_fault_injector(
        shim,
        &vm_rootfs,
        console,
        Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
    )
    .await
    {
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
        target,
        bundle: AgentBundle::new(&bundle, guest_bundle),
        io: ProcessIo {
            stdin: IoMode::Null,
            stdout: IoMode::Null,
            stderr: IoMode::Null,
            terminal_size: None,
        },
    };
    let exercise = match timeout(CREATE_TIMEOUT, client.create(request)).await {
        Ok(Err(error)) => {
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
                    "transport-fault create returned an unexpected error: {error}"
                ))
            }
        }
        Ok(Ok(_)) => Err("transport-fault create unexpectedly returned success".to_string()),
        Err(_) => Err(format!(
            "transport-fault create exceeded the {} second timeout",
            CREATE_TIMEOUT.as_secs()
        )),
    };
    report.negotiated_protocol = faults.protocol_version();
    report.injected_point = faults.injected_point();
    report.fault_crossings = faults.crossing_count();

    report.bridge = match &exercise {
        Ok(()) => session.shutdown().await,
        Err(reason) => session.shutdown_with_failure(reason).await,
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    cleanup.apply(&mut report.bridge).await;

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
        AgentTransportOperationStage, AGENT_PROTOCOL_VERSION_MAX,
    };
    use a3s_oci_sdk::ErrorCode;

    use super::HostCreateTransportFault;

    #[test]
    fn real_host_fault_injector_fires_once_only_at_the_selected_create_stage() {
        let selected = AgentTransportOperationStage::HostBeforeResponseRead;
        let injector = HostCreateTransportFault::new(selected);
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
}
