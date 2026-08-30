use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::{OciBundle, RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY};
use tokio::time::{sleep, Instant};

use super::{bundle_marker, QUALIFICATION_TIMEOUT};
use crate::marker::{exact_marker_state, ExactMarkerState};

const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";
const MARKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_MARKER_BYTES: u64 = 1_024;

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
                    "refusing to remove a non-plain or oversized KVM workload marker: {}",
                    marker.display()
                ));
            }
            tokio::fs::remove_file(marker).await.map_err(|error| {
                format!(
                    "failed to reset first-owner KVM workload marker {}: {error}",
                    marker.display()
                )
            })?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "failed to inspect first-owner KVM workload marker {}: {error}",
                marker.display()
            ));
        }
    }
    if !path_absent(marker).await? {
        return Err(format!(
            "first-owner KVM workload marker remained before replacement: {}",
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
                        "replacement KVM workload marker is not a bounded plain file: {}",
                        marker.display()
                    ));
                }
                let contents = tokio::fs::read(marker).await.map_err(|error| {
                    format!(
                        "failed to read replacement KVM workload marker {}: {error}",
                        marker.display()
                    )
                })?;
                match exact_marker_state(&contents, MARKER_CONTENTS) {
                    ExactMarkerState::Complete => return Ok(()),
                    ExactMarkerState::InProgress => {}
                    ExactMarkerState::Mismatch => {
                        return Err(
                            "replacement KVM workload produced unexpected marker contents"
                                .to_string(),
                        );
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect replacement KVM workload marker {}: {error}",
                    marker.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for replacement KVM workload marker".to_string());
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
