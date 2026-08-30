use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_agent_protocol::AgentTransportOperationStage;
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, OciBundle, OperationId, StartRequest,
    RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY,
};
use tokio::time::{sleep, Instant};

use super::super::super::{bundle_marker, QUALIFICATION_TIMEOUT};
use crate::marker::{exact_marker_state, ExactMarkerState};
use crate::transport_cleanup_report::is_retryable_disconnect_operation;
use crate::OciVmOperationReopenReplacementReport;

const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
const MARKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_MARKER_BYTES: u64 = 1_024;

pub(super) struct FirstOwnerOutcome {
    pub(super) target: ContainerTarget,
    pub(super) mount_root: PathBuf,
    pub(super) marker: PathBuf,
    pub(super) create_identity: (OperationId, ContainerTarget),
    pub(super) start_identity: (OperationId, ContainerTarget),
    pub(super) start: StartRequest,
    pub(super) response_delivered: bool,
}

pub(super) async fn runtime_marker(mount_root: &Path) -> Result<PathBuf, String> {
    let bundle_directory = mount_root.join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY);
    let bundle = OciBundle::load(&bundle_directory).await.map_err(|error| {
        format!(
            "failed to load exact-generation KVM bundle {}: {error}",
            bundle_directory.display()
        )
    })?;
    bundle_marker(&bundle)
}

pub(super) async fn reset_marker(marker: &Path) -> Result<(), String> {
    match tokio::fs::symlink_metadata(marker).await {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.len() > MAX_MARKER_BYTES {
                return Err(format!(
                    "refusing to remove a non-plain or oversized KVM Start marker: {}",
                    marker.display()
                ));
            }
            tokio::fs::remove_file(marker).await.map_err(|error| {
                format!(
                    "failed to reset first-owner KVM Start marker {}: {error}",
                    marker.display()
                )
            })?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect first-owner KVM Start marker {}: {error}",
                marker.display()
            ));
        }
    }
    if !path_absent(marker).await? {
        return Err(format!(
            "first-owner KVM Start marker remained before replacement: {}",
            marker.display()
        ));
    }
    Ok(())
}

pub(super) async fn wait_for_replacement_marker(marker: &Path) -> Result<(), String> {
    let deadline = Instant::now() + QUALIFICATION_TIMEOUT;
    loop {
        match tokio::fs::symlink_metadata(marker).await {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.len() > MAX_MARKER_BYTES {
                    return Err(format!(
                        "replacement KVM Start marker is not a bounded plain file: {}",
                        marker.display()
                    ));
                }
                let contents = tokio::fs::read(marker).await.map_err(|error| {
                    format!(
                        "failed to read replacement KVM Start marker {}: {error}",
                        marker.display()
                    )
                })?;
                match exact_marker_state(&contents, MARKER_CONTENTS) {
                    ExactMarkerState::Complete => return Ok(()),
                    ExactMarkerState::InProgress => {}
                    ExactMarkerState::Mismatch => {
                        return Err(
                            "replacement KVM Start workload produced unexpected marker contents"
                                .to_string(),
                        );
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect replacement KVM Start marker {}: {error}",
                    marker.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for replacement KVM Start workload marker".to_string());
        }
        sleep(MARKER_POLL_INTERVAL).await;
    }
}

pub(super) async fn path_absent(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

pub(super) fn record_interruption(
    report: &mut OciVmOperationReopenReplacementReport,
    error: Error,
    stage: AgentTransportOperationStage,
) -> Result<(), String> {
    report.first_operation_error_code = Some(error.code);
    report.first_operation_error_operation = error.operation.clone();
    report.first_operation_error_retryable = error.retryable;
    let expected_operation = if stage.is_guest() {
        error
            .operation
            .as_deref()
            .is_some_and(is_retryable_disconnect_operation)
    } else {
        error.operation.as_deref() == Some(super::super::super::QUALIFICATION_FAULT_OPERATION)
    };
    if error.code == ErrorCode::Unavailable && error.retryable && expected_operation {
        Ok(())
    } else {
        Err(format!(
            "first KVM owner returned an unexpected Start transport error at {}: {error}",
            stage.as_str()
        ))
    }
}

pub(super) fn append_failure(failure: &mut Option<String>, reason: impl Into<String>) {
    let reason = reason.into();
    *failure = Some(match failure.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}
