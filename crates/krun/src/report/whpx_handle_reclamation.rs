use std::path::PathBuf;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde::{Deserialize, Serialize};

use super::WindowsBootAssetsEvidence;

/// Schema emitted by the same-process Windows WHPX handle-reclamation gate.
pub const WHPX_HANDLE_RECLAMATION_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.krun-whpx-handle-reclamation-smoke.v1";
/// Fixed process-handle margin allowed after the warmed WHPX lifecycle.
pub const WHPX_HANDLE_RECLAMATION_ALLOWED_FINAL_DELTA: u32 = 2;

/// Evidence for one VM lifecycle in the same-process WHPX reclamation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxHandleReclamationSample {
    pub iteration: u16,
    pub warmup: bool,
    pub console_file: PathBuf,
    pub guest_exit_code: Option<i32>,
    pub marker_verified: bool,
    pub marker_removed: bool,
    pub console_created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_handle_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_delta_from_baseline: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxHandleReclamationSample {
    /// Return whether the guest lifecycle and host-side cleanup both completed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.guest_exit_code == Some(0)
            && self.marker_verified
            && self.marker_removed
            && self.console_created
            && self.process_handle_count.is_some()
            && self.reason.is_none()
    }
}

/// Same-process Windows WHPX native-handle reclamation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxHandleReclamationSmokeReport {
    pub schema_version: String,
    pub platform: HostPlatform,
    pub status: CapabilityStatus,
    pub runtime_bundle_loaded: bool,
    pub process_id: u32,
    pub requested_iterations: u16,
    pub completed_iterations: u16,
    pub allowed_final_handle_delta: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cold_handle_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_handle_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_post_cycle_handle_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_handle_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_handle_delta: Option<i64>,
    pub runtime_share_restored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_boot_assets: Option<WindowsBootAssetsEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warmup: Option<WhpxHandleReclamationSample>,
    pub samples: Vec<WhpxHandleReclamationSample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxHandleReclamationSmokeReport {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) fn initial(requested_iterations: u16, allowed_final_handle_delta: u32) -> Self {
        Self {
            schema_version: WHPX_HANDLE_RECLAMATION_SMOKE_SCHEMA_VERSION.to_string(),
            platform: HostPlatform::Windows,
            status: CapabilityStatus::Unavailable,
            runtime_bundle_loaded: option_env!("A3S_OCI_KRUN_RUNTIME_DIR").is_some(),
            process_id: std::process::id(),
            requested_iterations,
            completed_iterations: 0,
            allowed_final_handle_delta,
            cold_handle_count: None,
            baseline_handle_count: None,
            peak_post_cycle_handle_count: None,
            final_handle_count: None,
            final_handle_delta: None,
            runtime_share_restored: false,
            windows_boot_assets: None,
            warmup: None,
            samples: Vec::new(),
            reason: None,
        }
    }

    /// Return whether every VM completed and the warmed handle baseline was restored.
    #[must_use]
    pub fn is_success(&self) -> bool {
        let Some((cold, baseline, peak, final_count)) = self
            .cold_handle_count
            .zip(self.baseline_handle_count)
            .zip(self.peak_post_cycle_handle_count)
            .zip(self.final_handle_count)
            .map(|(((cold, baseline), peak), final_count)| (cold, baseline, peak, final_count))
        else {
            return false;
        };
        let final_delta = i64::from(final_count) - i64::from(baseline);
        let warmup_succeeded = self.warmup.as_ref().is_some_and(|sample| {
            sample.iteration == 0
                && sample.warmup
                && sample.process_handle_count == Some(baseline)
                && sample.handle_delta_from_baseline == Some(0)
                && sample.is_success()
        });
        let samples_succeeded = self.samples.iter().enumerate().all(|(index, sample)| {
            let expected_iteration = u16::try_from(index + 1).ok();
            let handle_count = sample.process_handle_count;
            expected_iteration == Some(sample.iteration)
                && !sample.warmup
                && sample.handle_delta_from_baseline
                    == handle_count.map(|count| i64::from(count) - i64::from(baseline))
                && sample.is_success()
        });
        let observed_peak = self
            .samples
            .iter()
            .filter_map(|sample| sample.process_handle_count)
            .fold(baseline.max(final_count), u32::max);

        self.schema_version == WHPX_HANDLE_RECLAMATION_SMOKE_SCHEMA_VERSION
            && matches!(self.platform, HostPlatform::Windows)
            && matches!(self.status, CapabilityStatus::Available)
            && self.runtime_bundle_loaded
            && self.process_id != 0
            && self.requested_iterations > 0
            && self.completed_iterations == self.requested_iterations
            && self.allowed_final_handle_delta == WHPX_HANDLE_RECLAMATION_ALLOWED_FINAL_DELTA
            && cold > 0
            && baseline > 0
            && peak == observed_peak
            && self.final_handle_delta == Some(final_delta)
            && self
                .windows_boot_assets
                .as_ref()
                .is_some_and(WindowsBootAssetsEvidence::is_success)
            && warmup_succeeded
            && self.samples.len() == usize::from(self.requested_iterations)
            && samples_succeeded
            && final_count <= baseline.saturating_add(self.allowed_final_handle_delta)
            && self.runtime_share_restored
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use a3s_oci_core::{CapabilityStatus, HostPlatform};

    use super::{
        WhpxHandleReclamationSample, WhpxHandleReclamationSmokeReport,
        WHPX_HANDLE_RECLAMATION_ALLOWED_FINAL_DELTA, WHPX_HANDLE_RECLAMATION_SMOKE_SCHEMA_VERSION,
    };
    use crate::WindowsBootAssetsEvidence;

    fn sample(iteration: u16, warmup: bool, handle_count: u32) -> WhpxHandleReclamationSample {
        WhpxHandleReclamationSample {
            iteration,
            warmup,
            console_file: PathBuf::from(format!("iteration-{iteration}.console.log")),
            guest_exit_code: Some(0),
            marker_verified: true,
            marker_removed: true,
            console_created: true,
            process_handle_count: Some(handle_count),
            handle_delta_from_baseline: Some(i64::from(handle_count) - 20),
            reason: None,
        }
    }

    fn boot_assets() -> WindowsBootAssetsEvidence {
        WindowsBootAssetsEvidence {
            manifest_sha256: "a".repeat(64),
            system_image_sha256: "b".repeat(64),
            system_image_size: 1,
            runtime_archive_sha256: "c".repeat(64),
            krun_dll_sha256: "d".repeat(64),
            firmware_sha256: "e".repeat(64),
            box_revision: "1".repeat(40),
            libkrun_revision: "2".repeat(40),
            firmware_wrapper_revision: "3".repeat(40),
            libkrunfw_revision: "4".repeat(40),
            kernel_version: "6.12.91".into(),
            kernel_source_sha256: "5".repeat(64),
            kernel_bundle_sha256: "6".repeat(64),
            kernel_bundle_size: 1,
            kernel_guest_load_address: "0x1000000".into(),
            kernel_entry_address: "0x1000123".into(),
            root_disk_read_only: true,
            runtime_share_separate: true,
        }
    }

    fn complete_report(final_handle_count: u32) -> WhpxHandleReclamationSmokeReport {
        WhpxHandleReclamationSmokeReport {
            schema_version: WHPX_HANDLE_RECLAMATION_SMOKE_SCHEMA_VERSION.into(),
            platform: HostPlatform::Windows,
            status: CapabilityStatus::Available,
            runtime_bundle_loaded: true,
            process_id: 42,
            requested_iterations: 1,
            completed_iterations: 1,
            allowed_final_handle_delta: WHPX_HANDLE_RECLAMATION_ALLOWED_FINAL_DELTA,
            cold_handle_count: Some(18),
            baseline_handle_count: Some(20),
            peak_post_cycle_handle_count: Some(final_handle_count),
            final_handle_count: Some(final_handle_count),
            final_handle_delta: Some(i64::from(final_handle_count) - 20),
            runtime_share_restored: true,
            windows_boot_assets: Some(boot_assets()),
            warmup: Some(sample(0, true, 20)),
            samples: vec![sample(1, false, final_handle_count)],
            reason: None,
        }
    }

    #[test]
    fn accepts_the_two_handle_runtime_margin() {
        assert!(complete_report(22).is_success());
    }

    #[test]
    fn rejects_a_final_count_above_the_runtime_margin() {
        assert!(!complete_report(23).is_success());
    }
}
