use std::path::Path;
use std::sync::Arc;

use a3s_oci_agent_protocol::{
    AgentOperation, AgentTransportFaultInjector, AgentTransportFaultStage,
    AgentTransportOperationStage, AgentTransportQualificationRequest, AgentWaitRequest,
    AGENT_PROTOCOL_VERSION_MAX,
};
use a3s_oci_core::{CapabilityStatus, DriverKind, HostPlatform, IsolationClass};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    ContainerTarget, CreateAttachments, CreateRequest, DeleteMode, DeleteRequest, Error, ErrorCode,
    ExitStatus, IoMode, IsolationRequest, KillRequest, ListRequest, OciBundle, OciRuntimeService,
    OperationContext, OperationId, ProcessIo, Signal, StartRequest, StateRequest, WaitRequest,
};
use tokio::time::timeout;

use super::super::transport_fault_cleanup::{
    read_guest_qualification_evidence, HostTransportFault,
};
use super::super::{
    canonical_directory, fixed_rootfs, path_exists, runtime_entries, target, unique_nonce,
    GUEST_RUNTIME_PREFIX, MARKER_NAME,
};
use super::delete_support::{
    append_reason, failed, record_recovery_evidence, remove_marker_if_present, reset_marker,
};
use super::{
    append_failure, create_qualification_state_root, owner_identities_are_distinct,
    wait_for_replacement_marker, QualificationHvfDriver, FAULT_OPERATION, QUALIFICATION_TIMEOUT,
};
use crate::agent_session::UtilityVmSession;
use crate::host_cleanup::MacosHostCleanupTracker;
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::{OciVmOperationReopenReplacementReport, RuntimeDriver};

const KILL_SIGNAL: i32 = 9;
const WAIT_TIMEOUT_MS: u64 = 15_000;

mod entry;
pub(in crate::oci_smoke::utility_vm) use entry::run;
mod support;
use support::{
    identity_or_expected, init_exit_cache, operation_id, record_interruption,
    shutdown_setup_failure,
};

#[allow(clippy::too_many_arguments)]
async fn exercise(
    shim: &Path,
    vm_rootfs: &Path,
    system_image_manifest: &Path,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    marker: &Path,
    create: &CreateRequest,
    start_operation_id: &OperationId,
    kill_operation_id: &OperationId,
    delete_operation_id: &OperationId,
    baseline_runtime_entries: &std::collections::BTreeSet<String>,
    stage: AgentTransportOperationStage,
    guest_qualification: Option<&AgentTransportQualificationRequest>,
    report: &mut OciVmOperationReopenReplacementReport,
) -> std::result::Result<(), String> {
    let faults = Arc::new(HostTransportFault::for_operation(
        AgentOperation::Wait,
        AgentTransportFaultStage::from(stage),
    ));
    let first_cleanup = MacosHostCleanupTracker::capture();
    let first_session_result = match guest_qualification {
        Some(qualification) => {
            UtilityVmSession::connect_with_guest_qualification(
                shim,
                vm_rootfs,
                Some(system_image_manifest),
                first_console,
                qualification,
            )
            .await
        }
        None => {
            UtilityVmSession::connect_with_host_fault_injector(
                shim,
                vm_rootfs,
                Some(system_image_manifest),
                first_console,
                Arc::clone(&faults) as Arc<dyn AgentTransportFaultInjector>,
            )
            .await
        }
    };
    let first_session = match first_session_result {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            first_cleanup.apply(&mut bridge).await;
            let reason = bridge
                .reason
                .clone()
                .unwrap_or_else(|| "failed to launch the first Wait qualification VM".to_string());
            report.first_vm = bridge;
            return Err(reason);
        }
    };
    let first_driver = Arc::new(QualificationHvfDriver::new(
        Arc::clone(&first_session),
        vm_rootfs.to_path_buf(),
        create.clone(),
    ));
    let first_service = match crate::HostRuntimeService::open(
        state_root,
        Arc::clone(&first_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => service,
        Err(error) => {
            report.first_vm = first_driver.shutdown().await;
            first_cleanup.apply(&mut report.first_vm).await;
            return Err(format!(
                "failed to open the first durable Host service for Wait: {error}"
            ));
        }
    };

    let created = match timeout(QUALIFICATION_TIMEOUT, first_service.create(create.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Created
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Wait setup Create returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!("Wait setup Create failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Wait setup Create exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };
    let start = StartRequest {
        context: OperationContext::new(start_operation_id.clone()),
        target: ContainerTarget::exact(create.id.clone(), created.generation),
    };
    let started = match timeout(QUALIFICATION_TIMEOUT, first_service.start(start.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Running
                && record.state.id() == create.id.as_str()
                && record.state.pid().is_some_and(|pid| pid > 0) =>
        {
            record
        }
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Wait setup Start returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!("Wait setup Start failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Wait setup Start exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };
    if let Err(reason) = wait_for_replacement_marker(marker).await {
        return shutdown_setup_failure(
            first_service,
            first_driver,
            first_cleanup,
            report,
            format!("Wait setup workload failed: {reason}"),
        )
        .await;
    }
    report.first_created_pid = *started.state.pid();
    let signal = Signal::new(KILL_SIGNAL)
        .map_err(|error| format!("failed to construct Wait setup signal: {error}"))?;
    let kill = KillRequest {
        context: OperationContext::new(kill_operation_id.clone()),
        target: start.target.clone(),
        signal,
        all: true,
    };
    match timeout(QUALIFICATION_TIMEOUT, first_service.kill(kill.clone())).await {
        Ok(Ok(record))
            if *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none() => {}
        Ok(Ok(record)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Wait setup Kill returned invalid {} record with PID {:?}",
                    record.state.status(),
                    record.state.pid()
                ),
            )
            .await;
        }
        Ok(Err(error)) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!("Wait setup Kill failed: {error}"),
            )
            .await;
        }
        Err(_) => {
            return shutdown_setup_failure(
                first_service,
                first_driver,
                first_cleanup,
                report,
                format!(
                    "Wait setup Kill exceeded the {} second timeout",
                    QUALIFICATION_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    }
    let first_create_identity = first_driver.create_identity();
    let first_start_identity = first_driver.start_identity();
    let first_kill_identity = first_driver.kill_identity();
    let wait = WaitRequest {
        target: ContainerTarget::current(create.id.clone()),
        timeout_ms: Some(WAIT_TIMEOUT_MS),
    };
    let expected_exit = ExitStatus::signaled(KILL_SIGNAL, false)
        .map_err(|error| format!("failed to construct Wait exit status: {error}"))?;
    let response_delivered = stage == AgentTransportOperationStage::GuestAfterResponseWrite;
    let mut first_failure = None;
    match timeout(QUALIFICATION_TIMEOUT, first_service.wait(wait.clone())).await {
        Ok(Err(error)) if !response_delivered => {
            if let Err(reason) = record_interruption(report, error, stage) {
                append_failure(&mut first_failure, reason);
            }
        }
        Ok(Err(error)) => append_failure(
            &mut first_failure,
            format!(
                "{} did not deliver its completed Wait response: {error}",
                stage.as_str()
            ),
        ),
        Ok(Ok(status)) if response_delivered => {
            report.first_operation_response_received = true;
            report.first_wait_exit_status = Some(status.clone());
            report.first_response_matches_expected_exit = status == expected_exit;
            if !report.first_response_matches_expected_exit {
                append_failure(
                    &mut first_failure,
                    format!(
                        "{} returned unexpected Wait status {status:?}",
                        stage.as_str()
                    ),
                );
            }
            report.disconnect_probe_attempted = true;
            match timeout(
                QUALIFICATION_TIMEOUT,
                first_service.state(StateRequest {
                    target: ContainerTarget::exact(create.id.clone(), created.generation),
                }),
            )
            .await
            {
                Ok(Err(error)) => {
                    if let Err(reason) = record_interruption(report, error, stage) {
                        append_failure(&mut first_failure, reason);
                    }
                }
                Ok(Ok(_)) => append_failure(
                    &mut first_failure,
                    format!("{} disconnect probe unexpectedly succeeded", stage.as_str()),
                ),
                Err(_) => append_failure(
                    &mut first_failure,
                    format!(
                        "{} disconnect probe exceeded the {} second timeout",
                        stage.as_str(),
                        QUALIFICATION_TIMEOUT.as_secs()
                    ),
                ),
            }
        }
        Ok(Ok(status)) => append_failure(
            &mut first_failure,
            format!("first Wait unexpectedly completed with {status:?} before owner replacement"),
        ),
        Err(_) => append_failure(
            &mut first_failure,
            format!(
                "first Wait exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.first_operation_dispatches = first_driver.wait_calls();
    if stage.is_host() {
        report.negotiated_protocol = faults.protocol_version();
        report.injected_point = faults.injected_point();
        report.fault_crossings = faults.crossing_count();
    }
    let exact_target = ContainerTarget::exact(create.id.clone(), created.generation);
    match first_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_before_reopen = Some(record.generation);
            report.durable_stopped_retained = record.state.id() == create.id.as_str()
                && record.driver == DriverKind::LibkrunHvf
                && record.isolation == IsolationClass::DedicatedVm
                && record.generation == created.generation
                && record.config_digest == created.config_digest
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            if !report.durable_stopped_retained {
                append_failure(
                    &mut first_failure,
                    "interrupted Wait did not retain the exact durable stopped record",
                );
            }
        }
        Ok(records) => append_failure(
            &mut first_failure,
            format!(
                "interrupted Wait retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut first_failure,
            format!("failed to inspect durable state after interrupted Wait: {error}"),
        ),
    }
    match init_exit_cache(state_root, &exact_target).await {
        Ok(cache) => {
            report.init_exit_cached_before_reopen = cache.as_ref() == Some(&expected_exit);
            let expected_cache = response_delivered.then_some(&expected_exit);
            if cache.as_ref() != expected_cache {
                append_failure(
                    &mut first_failure,
                    "durable init exit cache before reopen did not match Wait response delivery",
                );
            }
        }
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    let first_wait_identity = first_driver.wait_identity();
    drop(first_service);
    report.first_vm = first_driver.shutdown().await;
    first_cleanup.apply(&mut report.first_vm).await;
    report.first_guest_runtime_clean = runtime_entries(vm_rootfs)
        .await
        .is_ok_and(|entries| &entries == baseline_runtime_entries);
    if let Some(qualification) = guest_qualification {
        match read_guest_qualification_evidence(first_console, qualification).await {
            Ok(evidence) => {
                report.negotiated_protocol = Some(evidence.protocol_version());
                report.injected_point = Some(evidence.injected_point());
                report.fault_crossings = evidence.fault_crossings();
                report.guest_evidence_operation_id = Some(evidence.operation_id().clone());
                report.guest_evidence_verified = evidence.matches_request(qualification)
                    && evidence.protocol_version() == AGENT_PROTOCOL_VERSION_MAX
                    && evidence.fault_crossings() == 1;
                if !report.guest_evidence_verified {
                    append_failure(
                        &mut first_failure,
                        "Guest Wait evidence did not match the exact qualification",
                    );
                }
            }
            Err(reason) => append_failure(&mut first_failure, reason),
        }
    }
    match reset_marker(marker).await {
        Ok(()) => report.marker_reset_before_replacement = true,
        Err(reason) => append_failure(&mut first_failure, reason),
    }
    if !report.first_vm.is_success() {
        append_failure(
            &mut first_failure,
            report
                .first_vm
                .reason
                .clone()
                .unwrap_or_else(|| "first VM cleanup evidence failed".to_string()),
        );
    }
    if !report.first_guest_runtime_clean {
        append_failure(
            &mut first_failure,
            format!("first VM left {GUEST_RUNTIME_PREFIX} guest runtime state"),
        );
    }
    if first_driver.start_calls() != 1 || first_driver.kill_calls() != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "first driver recorded {} Start and {} Kill setup dispatches instead of one each",
                first_driver.start_calls(),
                first_driver.kill_calls()
            ),
        );
    }
    if report.first_operation_dispatches != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "first driver recorded {} Wait dispatches instead of one",
                report.first_operation_dispatches
            ),
        );
    }
    if report.fault_crossings != 1 {
        append_failure(
            &mut first_failure,
            format!(
                "selected Wait transport point crossed {} times instead of once",
                report.fault_crossings
            ),
        );
    }
    let first_create_identity = identity_or_expected(
        first_create_identity,
        &mut first_failure,
        (create.context.operation_id.clone(), exact_target.clone()),
    );
    let first_start_identity = identity_or_expected(
        first_start_identity,
        &mut first_failure,
        (start.context.operation_id.clone(), exact_target.clone()),
    );
    let first_kill_identity = match first_kill_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut first_failure, reason);
            (
                kill.context.operation_id.clone(),
                exact_target.clone(),
                kill.signal,
                kill.all,
            )
        }
    };
    let first_wait_identity = match first_wait_identity {
        Ok(identity) => identity,
        Err(reason) => {
            append_failure(&mut first_failure, reason);
            (exact_target.clone(), wait.timeout_ms)
        }
    };
    if first_wait_identity != (exact_target.clone(), wait.timeout_ms) {
        append_failure(
            &mut first_failure,
            "first Wait dispatch did not resolve the current target to the exact generation",
        );
    }
    if let Some(reason) = first_failure {
        return Err(reason);
    }
    drop(first_driver);
    drop(first_session);

    let replacement_cleanup = MacosHostCleanupTracker::capture();
    let replacement_session = match UtilityVmSession::connect(
        shim,
        vm_rootfs,
        Some(system_image_manifest),
        replacement_console,
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(mut bridge) => {
            replacement_cleanup.apply(&mut bridge).await;
            let reason = bridge.reason.clone().unwrap_or_else(|| {
                "failed to launch the replacement Wait qualification VM".to_string()
            });
            report.replacement_vm = bridge;
            return Err(reason);
        }
    };
    let replacement_driver = Arc::new(QualificationHvfDriver::with_kill_recovery(
        Arc::clone(&replacement_session),
        vm_rootfs.to_path_buf(),
        create.clone(),
        start.clone(),
        kill.clone(),
        marker.to_path_buf(),
    ));
    let replacement_service = match crate::HostRuntimeService::open(
        state_root,
        Arc::clone(&replacement_driver) as Arc<dyn RuntimeDriver>,
    )
    .await
    {
        Ok(service) => {
            report.host_service_reopened = true;
            record_recovery_evidence(report, &replacement_driver);
            service
        }
        Err(error) => {
            record_recovery_evidence(report, &replacement_driver);
            report.replacement_vm = replacement_driver.shutdown().await;
            replacement_cleanup.apply(&mut report.replacement_vm).await;
            return Err(format!(
                "failed to reopen durable Host service around the replacement VM: {error}"
            ));
        }
    };

    let mut replacement_failure = None;
    if report.replacement_recovery_calls != 1 {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recovered {} durable records instead of one",
                report.replacement_recovery_calls
            ),
        );
    }
    if !report.replacement_rehydrated_created_record
        || !report.replacement_rehydrated_running_record
        || !report.replacement_rehydrated_stopped_record
    {
        append_failure(
            &mut replacement_failure,
            "replacement driver did not rebuild the complete stopped Guest tombstone",
        );
    }
    if report.replacement_created_pid.is_none() {
        append_failure(
            &mut replacement_failure,
            "replacement recovery did not retain its positive running PID",
        );
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            if record.state.id() != create.id.as_str()
                || record.generation != created.generation
                || record.driver != DriverKind::LibkrunHvf
                || record.isolation != IsolationClass::DedicatedVm
                || *record.state.status() != ContainerState::Stopped
                || record.state.pid().is_some()
            {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement recovery retained invalid {} record with PID {:?}",
                        record.state.status(),
                        record.state.pid()
                    ),
                );
            }
        }
        Ok(records) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement recovery retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to inspect recovered durable Wait record: {error}"),
        ),
    }
    match init_exit_cache(state_root, &exact_target).await {
        Ok(cache) => {
            let expected_cache = response_delivered.then_some(&expected_exit);
            if cache.as_ref() != expected_cache {
                append_failure(
                    &mut replacement_failure,
                    "reopened Host did not preserve the exact preexisting init exit cache",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    match wait_for_replacement_marker(marker).await {
        Ok(()) => report.replacement_workload_verified = true,
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }

    let wait_calls_before = replacement_driver.wait_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.wait(wait.clone()),
    )
    .await
    {
        Ok(Ok(status)) => {
            report.replacement_wait_exit_status = Some(status.clone());
            report.replacement_response_matches_expected_exit = status == expected_exit;
            report.operation_completed_after_reopen =
                report.replacement_response_matches_expected_exit;
            if !report.replacement_response_matches_expected_exit {
                append_failure(
                    &mut replacement_failure,
                    format!("replacement Wait returned unexpected status {status:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement Wait failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement Wait exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.operation_replayed_without_driver_dispatch =
        replacement_driver.wait_calls() == wait_calls_before;
    match init_exit_cache(state_root, &exact_target).await {
        Ok(cache) => {
            report.init_exit_cached_after_reopen = cache.as_ref() == Some(&expected_exit);
            if !report.init_exit_cached_after_reopen {
                append_failure(
                    &mut replacement_failure,
                    "replacement Wait did not persist the exact init exit cache",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) if records.len() == 1 => {
            let record = &records[0];
            report.generation_after_reopen = Some(record.generation);
            report.same_generation_reused = record.generation == created.generation
                && *record.state.status() == ContainerState::Stopped
                && record.state.pid().is_none();
            if !report.same_generation_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement Wait did not retain the exact stopped generation",
                );
            }
        }
        Ok(records) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement Wait retained {} durable records instead of one",
                records.len()
            ),
        ),
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to inspect durable state after replacement Wait: {error}"),
        ),
    }

    let wait_calls_before_cache = replacement_driver.wait_calls();
    match timeout(
        QUALIFICATION_TIMEOUT,
        replacement_service.wait(wait.clone()),
    )
    .await
    {
        Ok(Ok(status)) => {
            report.cached_wait_exit_status = Some(status.clone());
            report.cached_response_matches_expected_exit = status == expected_exit;
            if !report.cached_response_matches_expected_exit {
                append_failure(
                    &mut replacement_failure,
                    format!("cached Wait returned unexpected status {status:?}"),
                );
            }
        }
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("cached Wait replay failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            format!(
                "cached Wait replay exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    report.cached_wait_replayed_without_driver_dispatch =
        replacement_driver.wait_calls() == wait_calls_before_cache;
    report.replacement_operation_dispatches = replacement_driver.wait_calls();
    if report.operation_replayed_without_driver_dispatch != response_delivered {
        append_failure(
            &mut replacement_failure,
            "replacement Wait dispatch did not match the durable cache state",
        );
    }
    let expected_replacement_dispatches = u32::from(!response_delivered);
    if report.replacement_operation_dispatches != expected_replacement_dispatches {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement driver recorded {} Wait dispatches instead of {}",
                report.replacement_operation_dispatches, expected_replacement_dispatches
            ),
        );
    }
    if !report.cached_wait_replayed_without_driver_dispatch {
        append_failure(
            &mut replacement_failure,
            "later Wait did not replay directly from the durable terminal cache",
        );
    }
    match replacement_driver.wait_identity() {
        Ok(identity) if !response_delivered => {
            if identity != first_wait_identity {
                append_failure(
                    &mut replacement_failure,
                    "replacement Wait did not reuse the exact resolved target and timeout",
                );
            }
        }
        Ok(_) => append_failure(
            &mut replacement_failure,
            "cache-backed replacement Wait unexpectedly reached the driver",
        ),
        Err(_) if response_delivered => {}
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    if replacement_driver.start_calls() != 1 || replacement_driver.kill_calls() != 1 {
        append_failure(
            &mut replacement_failure,
            format!(
                "replacement recovery recorded {} Start and {} Kill dispatches instead of one each",
                replacement_driver.start_calls(),
                replacement_driver.kill_calls()
            ),
        );
    }
    match replacement_driver.create_identity() {
        Ok(identity) => {
            report.setup_create_identity_reused = identity == first_create_identity;
            if !report.setup_create_identity_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement recovery did not reuse the setup Create identity",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    match replacement_driver.start_identity() {
        Ok(identity) => {
            report.setup_start_identity_reused = identity == first_start_identity;
            if !report.setup_start_identity_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement recovery did not reuse the setup Start identity",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }
    match replacement_driver.kill_identity() {
        Ok(identity) => {
            report.setup_kill_identity_reused = identity == first_kill_identity;
            if !report.setup_kill_identity_reused {
                append_failure(
                    &mut replacement_failure,
                    "replacement recovery did not reuse the setup Kill identity",
                );
            }
        }
        Err(reason) => append_failure(&mut replacement_failure, reason),
    }

    let stale_target = ContainerTarget::exact(
        create.id.clone(),
        a3s_oci_sdk::Generation(created.generation.0 + 1),
    );
    match replacement_session
        .client()
        .wait(AgentWaitRequest {
            target: stale_target.clone(),
            timeout_ms: wait.timeout_ms,
        })
        .await
    {
        Err(error) if error.code == ErrorCode::NotFound => {
            report.guest_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("replacement Guest returned the wrong stale Wait error: {error}"),
        ),
        Ok(status) => append_failure(
            &mut replacement_failure,
            format!("replacement Guest accepted stale Wait and returned {status:?}"),
        ),
    }
    let wait_calls_before_stale_host = replacement_driver.wait_calls();
    match replacement_service
        .wait(WaitRequest {
            target: stale_target,
            timeout_ms: wait.timeout_ms,
        })
        .await
    {
        Err(error)
            if error.code == ErrorCode::Conflict
                && replacement_driver.wait_calls() == wait_calls_before_stale_host =>
        {
            report.host_stale_generation_rejected = true;
        }
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("reopened Host returned the wrong stale Wait error: {error}"),
        ),
        Ok(status) => append_failure(
            &mut replacement_failure,
            format!("reopened Host accepted stale Wait and returned {status:?}"),
        ),
    }

    let delete = DeleteRequest {
        context: OperationContext::new(delete_operation_id.clone()),
        target: exact_target,
        mode: DeleteMode::StoppedOnly,
    };
    match timeout(QUALIFICATION_TIMEOUT, replacement_service.delete(delete)).await {
        Ok(Ok(())) => report.stopped_only_delete_completed = true,
        Ok(Err(error)) => append_failure(
            &mut replacement_failure,
            format!("replacement stopped-only delete failed: {error}"),
        ),
        Err(_) => append_failure(
            &mut replacement_failure,
            format!(
                "replacement stopped-only delete exceeded the {} second timeout",
                QUALIFICATION_TIMEOUT.as_secs()
            ),
        ),
    }
    match replacement_service.list(ListRequest::default()).await {
        Ok(records) => {
            report.durable_records_empty = records.is_empty();
            if !report.durable_records_empty {
                append_failure(
                    &mut replacement_failure,
                    format!(
                        "replacement delete retained {} durable container records",
                        records.len()
                    ),
                );
            }
        }
        Err(error) => append_failure(
            &mut replacement_failure,
            format!("failed to inspect durable state after replacement delete: {error}"),
        ),
    }
    drop(replacement_service);
    report.replacement_vm = replacement_driver.shutdown().await;
    replacement_cleanup.apply(&mut report.replacement_vm).await;
    report.replacement_guest_runtime_clean = runtime_entries(vm_rootfs)
        .await
        .is_ok_and(|entries| &entries == baseline_runtime_entries);
    report.owners_distinct =
        owner_identities_are_distinct(&report.first_vm, &report.replacement_vm);
    if !report.replacement_vm.is_success() {
        append_failure(
            &mut replacement_failure,
            report
                .replacement_vm
                .reason
                .clone()
                .unwrap_or_else(|| "replacement VM cleanup evidence failed".to_string()),
        );
    }
    if !report.replacement_guest_runtime_clean {
        append_failure(
            &mut replacement_failure,
            format!("replacement VM left {GUEST_RUNTIME_PREFIX} guest runtime state"),
        );
    }
    if !report.owners_distinct {
        append_failure(
            &mut replacement_failure,
            "first and replacement VM owner identities were not distinct",
        );
    }
    replacement_failure.map_or(Ok(()), Err)
}
