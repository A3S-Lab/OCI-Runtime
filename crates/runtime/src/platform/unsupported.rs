use std::collections::BTreeMap;

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    RuntimeFeatures,
};

use crate::WhpxSmokeReport;

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
