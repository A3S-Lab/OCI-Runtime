use std::collections::BTreeMap;
use std::mem;
use std::ptr;

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    RuntimeFeatures,
};

#[derive(Debug)]
struct HvfObservation {
    apple_silicon: bool,
    hypervisor_supported: Option<bool>,
    reason: Option<String>,
}

pub(crate) fn features() -> RuntimeFeatures {
    RuntimeFeatures::current(vec![capability_from_observation(observe_hvf())])
}

fn observe_hvf() -> HvfObservation {
    if !cfg!(target_arch = "aarch64") {
        return HvfObservation {
            apple_silicon: false,
            hypervisor_supported: None,
            reason: Some(
                "A3S OCI Runtime supports Hypervisor.framework only on Apple Silicon".into(),
            ),
        };
    }

    let mut supported = 0_i32;
    let mut size = mem::size_of_val(&supported);
    // SAFETY: the sysctl name is a static NUL-terminated byte string. The old
    // value buffer points to one writable `i32`, and this read-only query has
    // no new-value pointer.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.hv_support".as_ptr(),
            ptr::from_mut(&mut supported).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return HvfObservation {
            apple_silicon: true,
            hypervisor_supported: None,
            reason: Some(format!(
                "failed to query kern.hv_support: {}",
                std::io::Error::last_os_error()
            )),
        };
    }
    if size != mem::size_of_val(&supported) {
        return HvfObservation {
            apple_silicon: true,
            hypervisor_supported: None,
            reason: Some(format!(
                "kern.hv_support returned {size} bytes; expected {}",
                mem::size_of_val(&supported)
            )),
        };
    }

    let hypervisor_supported = supported == 1;
    HvfObservation {
        apple_silicon: true,
        hypervisor_supported: Some(hypervisor_supported),
        reason: (!hypervisor_supported).then(|| {
            "Hypervisor.framework is unavailable according to kern.hv_support".to_string()
        }),
    }
}

fn capability_from_observation(observation: HvfObservation) -> DriverCapability {
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "apple_silicon".to_string(),
        observation.apple_silicon.to_string(),
    );
    evidence.insert(
        "kern_hv_support".to_string(),
        observation.hypervisor_supported.map_or_else(
            || "unavailable".to_string(),
            |supported| supported.to_string(),
        ),
    );

    let status = if !observation.apple_silicon {
        CapabilityStatus::Unsupported
    } else if observation.hypervisor_supported == Some(true) {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unavailable
    };

    DriverCapability {
        driver: DriverKind::LibkrunHvf,
        status,
        readiness: DriverReadiness::ProbeOnly,
        isolation_classes: vec![
            IsolationClass::DedicatedVm,
            IsolationClass::SharedGuestKernel,
        ],
        reason: observation.reason,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::{CapabilityStatus, DriverKind, DriverReadiness};

    use super::{capability_from_observation, features, HvfObservation};

    #[test]
    fn available_hvf_remains_probe_only() {
        let capability = capability_from_observation(HvfObservation {
            apple_silicon: true,
            hypervisor_supported: Some(true),
            reason: None,
        });

        assert_eq!(capability.driver, DriverKind::LibkrunHvf);
        assert_eq!(capability.status, CapabilityStatus::Available);
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert!(!capability.can_launch());
    }

    #[test]
    fn unsupported_macos_architecture_is_explicit() {
        let capability = capability_from_observation(HvfObservation {
            apple_silicon: false,
            hypervisor_supported: None,
            reason: Some("Apple Silicon is required".to_string()),
        });

        assert_eq!(capability.status, CapabilityStatus::Unsupported);
        assert_eq!(capability.evidence["apple_silicon"], "false");
        assert_eq!(capability.evidence["kern_hv_support"], "unavailable");
    }

    #[test]
    fn real_probe_reports_one_hvf_driver() {
        let inventory = features();
        let capability = inventory
            .driver(DriverKind::LibkrunHvf)
            .expect("macOS features must include the HVF driver");

        assert_eq!(inventory.drivers.len(), 1);
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert!(!capability.can_launch());
    }
}
