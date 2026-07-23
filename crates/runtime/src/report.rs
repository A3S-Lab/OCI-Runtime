use a3s_oci_core::CapabilityStatus;
use serde::{Deserialize, Serialize};

/// Schema emitted by the WHPX smoke command.
pub const WHPX_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.whpx-smoke.v1";

/// Result of querying WHPX and creating then deleting a partition object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host status of the Windows Hypervisor Platform prerequisite.
    pub status: CapabilityStatus,
    /// Whether `WinHvPlatform.dll` loaded from the system search scope.
    pub dll_loaded: bool,
    /// Whether WHPX reported the Windows hypervisor present.
    pub hypervisor_present: bool,
    /// Whether a partition object was created and deleted successfully.
    pub partition_object_round_trip: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxSmokeReport {
    #[cfg(windows)]
    pub(crate) fn unavailable(
        dll_loaded: bool,
        hypervisor_present: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            dll_loaded,
            hypervisor_present,
            partition_object_round_trip: false,
            reason: Some(reason.into()),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unsupported,
            dll_loaded: false,
            hypervisor_present: false,
            partition_object_round_trip: false,
            reason: Some(reason.into()),
        }
    }

    #[cfg(windows)]
    pub(crate) fn success() -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Available,
            dll_loaded: true,
            hypervisor_present: true,
            partition_object_round_trip: true,
            reason: None,
        }
    }

    /// Return whether every smoke step succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.dll_loaded
            && self.hypervisor_present
            && self.partition_object_round_trip
    }
}
