use std::collections::BTreeMap;
#[cfg(target_arch = "aarch64")]
use std::ffi::c_void;
use std::mem;
use std::ptr;

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, HostPlatform, IsolationClass,
    RuntimeFeatures,
};
#[cfg(target_arch = "aarch64")]
use thiserror::Error;

use crate::HvfSmokeReport;

#[derive(Debug)]
struct HvfObservation {
    apple_silicon: bool,
    hypervisor_supported: Option<bool>,
    reason: Option<String>,
}

pub(crate) fn features() -> RuntimeFeatures {
    RuntimeFeatures::current(vec![capability_from_observation(observe_hvf())])
}

pub(crate) fn hvf_smoke() -> HvfSmokeReport {
    let observation = observe_hvf();
    if !observation.apple_silicon {
        return HvfSmokeReport::unsupported(
            HostPlatform::Macos,
            observation.reason.unwrap_or_else(|| {
                "Hypervisor.framework VM creation requires Apple Silicon".to_string()
            }),
        );
    }

    let mut report = HvfSmokeReport::initial(
        HostPlatform::Macos,
        observation.apple_silicon,
        observation.hypervisor_supported,
    );
    if observation.hypervisor_supported != Some(true) {
        report.reason = observation.reason.or_else(|| {
            Some("Hypervisor.framework is unavailable according to kern.hv_support".into())
        });
        return report;
    }

    #[cfg(target_arch = "aarch64")]
    {
        match HvfVm::create() {
            Ok(vm) => {
                report.vm_created = true;
                match vm.close() {
                    Ok(()) => {
                        report.vm_destroyed = true;
                        report.status = CapabilityStatus::Available;
                    }
                    Err(error) => report.reason = Some(error.to_string()),
                }
            }
            Err(error) => report.reason = Some(error.to_string()),
        }
    }

    report
}

#[cfg(target_arch = "aarch64")]
#[derive(Debug, Error)]
#[error("{operation} returned {name} (0x{code:08X})")]
struct HvfApiError {
    operation: &'static str,
    name: &'static str,
    code: u32,
}

#[cfg(target_arch = "aarch64")]
struct HvfVm {
    active: bool,
}

#[cfg(target_arch = "aarch64")]
impl HvfVm {
    fn create() -> Result<Self, HvfApiError> {
        // SAFETY: A null configuration requests Apple's documented default
        // VM configuration and transfers no pointer ownership.
        let status = unsafe { hv_vm_create(ptr::null()) };
        check_hvf_status("hv_vm_create", status)?;
        Ok(Self { active: true })
    }

    fn close(mut self) -> Result<(), HvfApiError> {
        // SAFETY: this guard owns the one process-local VM object created by
        // `hv_vm_create`, and it has created no vCPUs or memory mappings.
        let status = unsafe { hv_vm_destroy() };
        check_hvf_status("hv_vm_destroy", status)?;
        self.active = false;
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
impl Drop for HvfVm {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: this is the final cleanup attempt for the VM object
            // owned by this guard. Drop cannot report a second failure.
            unsafe {
                let _ = hv_vm_destroy();
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn check_hvf_status(operation: &'static str, status: i32) -> Result<(), HvfApiError> {
    if status == 0 {
        Ok(())
    } else {
        let code = status as u32;
        Err(HvfApiError {
            operation,
            name: hvf_status_name(code),
            code,
        })
    }
}

#[cfg(target_arch = "aarch64")]
const fn hvf_status_name(code: u32) -> &'static str {
    match code {
        0xFAE9_4001 => "HV_ERROR",
        0xFAE9_4002 => "HV_BUSY",
        0xFAE9_4003 => "HV_BAD_ARGUMENT",
        0xFAE9_4004 => "HV_ILLEGAL_GUEST_STATE",
        0xFAE9_4005 => "HV_NO_RESOURCES",
        0xFAE9_4006 => "HV_NO_DEVICE",
        0xFAE9_4007 => "HV_DENIED",
        0xFAE9_4008 => "HV_EXISTS",
        0xFAE9_400F => "HV_UNSUPPORTED",
        _ => "unknown Hypervisor.framework status",
    }
}

#[cfg(target_arch = "aarch64")]
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    fn hv_vm_create(config: *const c_void) -> i32;
    fn hv_vm_destroy() -> i32;
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
    #[cfg(target_arch = "aarch64")]
    use super::{check_hvf_status, hvf_status_name};

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

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn hypervisor_status_codes_remain_diagnostic() {
        assert_eq!(hvf_status_name(0xFAE9_4007), "HV_DENIED");
        assert_eq!(
            hvf_status_name(0xDEAD_BEEF),
            "unknown Hypervisor.framework status"
        );
        let error = check_hvf_status("hv_vm_create", 0xFAE9_4007_u32 as i32)
            .expect_err("HV_DENIED must fail");
        assert_eq!(
            error.to_string(),
            "hv_vm_create returned HV_DENIED (0xFAE94007)"
        );
    }
}
