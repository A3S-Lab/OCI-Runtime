#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    RuntimeFeatures,
};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use std::collections::BTreeMap;

use crate::WhpxSmokeReport;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn features() -> RuntimeFeatures {
    RuntimeFeatures::current(vec![DriverCapability {
        driver: DriverKind::LibkrunWhpx,
        status: CapabilityStatus::Unsupported,
        readiness: DriverReadiness::ProbeOnly,
        isolation_classes: vec![
            IsolationClass::DedicatedVm,
            IsolationClass::SharedGuestKernel,
        ],
        reason: Some("WHPX is available only on Windows hosts".to_string()),
        evidence: BTreeMap::from([("whpx_api".to_string(), "not-applicable".to_string())]),
    }])
}

pub(crate) fn whpx_smoke() -> WhpxSmokeReport {
    WhpxSmokeReport::unsupported("WHPX smoke is available only on Windows hosts")
}
