use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::AgentVmSmokeReport;

/// Schema emitted by the real utility-VM Guest isolation diagnostic.
pub const OCI_VM_GUEST_ISOLATION_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.oci-vm-guest-isolation.v1";
/// Exact number of negative isolation boundaries qualified by one run.
pub const OCI_VM_GUEST_ISOLATION_CASE_COUNT: usize = 10;

/// Retained evidence for one rejected Guest isolation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmGuestIsolationCaseEvidence {
    /// Stable case name used by CI and retained qualification reports.
    pub name: String,
    /// Error class required from the Guest boundary.
    pub expected_error_code: ErrorCode,
    /// Exact component required to own the rejection.
    pub expected_error_operation: String,
    /// Whether the hostile request returned an error instead of succeeding.
    pub request_rejected: bool,
    /// Error class actually returned by the Guest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_error_code: Option<ErrorCode>,
    /// Component attached to the returned Guest error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_error_operation: Option<String>,
    /// Human-readable Guest diagnostic retained for audit evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_error_message: Option<String>,
    /// Whether the Guest classified the policy rejection as retryable.
    pub observed_error_retryable: bool,
    /// Whether no container state remained after the case cleanup boundary.
    pub container_state_absent_after_case: bool,
    /// Whether the Agent-state canary retained its exact original bytes.
    pub canary_unchanged: bool,
}

impl OciVmGuestIsolationCaseEvidence {
    pub(crate) fn initial(
        name: impl Into<String>,
        expected_error_operation: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            expected_error_code: ErrorCode::PermissionDenied,
            expected_error_operation: expected_error_operation.into(),
            request_rejected: false,
            observed_error_code: None,
            observed_error_operation: None,
            observed_error_message: None,
            observed_error_retryable: false,
            container_state_absent_after_case: false,
            canary_unchanged: false,
        }
    }

    /// Return whether this request failed at the exact typed boundary and cleaned up.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.request_rejected
            && self.observed_error_code == Some(self.expected_error_code)
            && self.observed_error_operation.as_deref()
                == Some(self.expected_error_operation.as_str())
            && !self.observed_error_retryable
            && self.container_state_absent_after_case
            && self.canary_unchanged
    }
}

/// End-to-end evidence for hostile path rejection inside a real utility VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmGuestIsolationSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this exact isolation qualification.
    pub status: CapabilityStatus,
    /// Number of cases required by this schema version.
    pub expected_case_count: usize,
    /// Whether the host loaded the known-good OCI bundle used by the cases.
    pub bundle_loaded: bool,
    /// Whether the writable share was distinct from the immutable VM bootstrap root.
    pub separate_runtime_share: bool,
    /// Ordered evidence for every hostile path case.
    pub cases: Vec<OciVmGuestIsolationCaseEvidence>,
    /// Whether all temporary hostile bundles were removed by the diagnostic.
    pub fixture_removed: bool,
    /// Whether the Agent-state canary was removed after its bytes were verified.
    pub canary_removed: bool,
    /// Whether VM shutdown restored the Guest executor runtime inventory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated bridge, VM-exit, and host cleanup evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the evidence was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmGuestIsolationSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: OCI_VM_GUEST_ISOLATION_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            expected_case_count: OCI_VM_GUEST_ISOLATION_CASE_COUNT,
            bundle_loaded: false,
            separate_runtime_share: false,
            cases: Vec::new(),
            fixture_removed: false,
            canary_removed: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.bridge.status = CapabilityStatus::Unsupported;
        report.bridge.reason = Some("the Linux Guest executor was not attempted".to_string());
        report.reason = Some(
            "real utility-VM Guest isolation qualification requires Linux x86_64/aarch64 KVM \
             or macOS aarch64/HVF"
                .to_string(),
        );
        report
    }

    /// Return whether all ten hostile requests failed closed and cleanup completed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.evidence_succeeded()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.bundle_loaded
            && self.separate_runtime_share
            && self.expected_case_count == OCI_VM_GUEST_ISOLATION_CASE_COUNT
            && self.cases.len() == OCI_VM_GUEST_ISOLATION_CASE_COUNT
            && self
                .cases
                .iter()
                .all(OciVmGuestIsolationCaseEvidence::is_success)
            && self.fixture_removed
            && self.canary_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
            && self.reason.is_none()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::ErrorCode;

    use super::OciVmGuestIsolationCaseEvidence;

    #[test]
    fn case_success_requires_exact_typed_boundary_and_cleanup() {
        let mut evidence = OciVmGuestIsolationCaseEvidence::initial(
            "bundle-system-directory",
            "validate-utility-vm-bundle-scope",
        );
        evidence.request_rejected = true;
        evidence.observed_error_code = Some(ErrorCode::PermissionDenied);
        evidence.observed_error_operation = Some("validate-utility-vm-bundle-scope".to_string());
        evidence.observed_error_message = Some("outside exact runtime share".to_string());
        evidence.container_state_absent_after_case = true;
        evidence.canary_unchanged = true;

        assert!(evidence.is_success());
        evidence.observed_error_operation = Some("linux-guest-executor".to_string());
        assert!(!evidence.is_success());
    }
}
