use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    RuntimeFeatures,
};

const KVM_DEVICE: &str = "/dev/kvm";
const KVM_API_VERSION: i32 = 12;
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
const REQUIRED_NAMESPACE_FILES: [&str; 7] = ["cgroup", "ipc", "mnt", "net", "pid", "user", "uts"];

#[derive(Debug)]
struct NativeLinuxObservation {
    namespace_api: bool,
    cgroup_v2: bool,
    unprivileged_user_namespaces: &'static str,
    reason: Option<String>,
}

#[derive(Debug)]
struct KvmObservation {
    device_present: bool,
    device_opened: bool,
    api_version: Option<i32>,
    reason: Option<String>,
}

pub(crate) fn features() -> RuntimeFeatures {
    RuntimeFeatures::current(vec![
        native_driver_capability(),
        kvm_capability(observe_kvm()),
    ])
}

pub(crate) fn native_driver_capability() -> DriverCapability {
    native_capability(observe_native_linux())
}

fn observe_native_linux() -> NativeLinuxObservation {
    let missing_namespaces = REQUIRED_NAMESPACE_FILES
        .into_iter()
        .filter(|name| !Path::new("/proc/self/ns").join(name).exists())
        .collect::<Vec<_>>();
    let namespace_api = missing_namespaces.is_empty();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").is_file();
    let reason = if !namespace_api {
        Some(format!(
            "Linux namespace API is incomplete; missing /proc/self/ns/{}",
            missing_namespaces.join(", /proc/self/ns/")
        ))
    } else if !cgroup_v2 {
        Some("cgroup v2 is unavailable at /sys/fs/cgroup/cgroup.controllers".to_string())
    } else {
        None
    };

    NativeLinuxObservation {
        namespace_api,
        cgroup_v2,
        unprivileged_user_namespaces: observe_unprivileged_user_namespaces(),
        reason,
    }
}

fn observe_unprivileged_user_namespaces() -> &'static str {
    match fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(value) if value.trim() == "1" => "enabled",
        Ok(value) if value.trim() == "0" => "disabled",
        Ok(_) => "unknown",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "kernel-policy-implicit",
        Err(_) => "unavailable",
    }
}

fn native_capability(observation: NativeLinuxObservation) -> DriverCapability {
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "namespace_api".to_string(),
        observation.namespace_api.to_string(),
    );
    evidence.insert("cgroup_v2".to_string(), observation.cgroup_v2.to_string());
    evidence.insert(
        "unprivileged_user_namespaces".to_string(),
        observation.unprivileged_user_namespaces.to_string(),
    );

    DriverCapability {
        driver: DriverKind::NativeLinux,
        status: if observation.namespace_api && observation.cgroup_v2 {
            CapabilityStatus::Available
        } else {
            CapabilityStatus::Unavailable
        },
        readiness: DriverReadiness::ProbeOnly,
        isolation_classes: vec![IsolationClass::SharedHostKernel],
        reason: observation.reason,
        evidence,
    }
}

fn observe_kvm() -> KvmObservation {
    let device = Path::new(KVM_DEVICE);
    match device.try_exists() {
        Ok(false) => {
            return KvmObservation {
                device_present: false,
                device_opened: false,
                api_version: None,
                reason: Some(format!("{KVM_DEVICE} is absent")),
            };
        }
        Err(error) => {
            return KvmObservation {
                device_present: false,
                device_opened: false,
                api_version: None,
                reason: Some(format!("failed to inspect {KVM_DEVICE}: {error}")),
            };
        }
        Ok(true) => {}
    }

    let device = match OpenOptions::new().read(true).write(true).open(device) {
        Ok(device) => device,
        Err(error) => {
            return KvmObservation {
                device_present: true,
                device_opened: false,
                api_version: None,
                reason: Some(format!(
                    "failed to open {KVM_DEVICE} for read/write: {error}"
                )),
            };
        }
    };

    // SAFETY: `device` is a live descriptor for `/dev/kvm`. KVM_GET_API_VERSION
    // takes no pointer argument and returns either the integer API version or
    // `-1` with errno set.
    let api_version = unsafe { libc::ioctl(device.as_raw_fd(), KVM_GET_API_VERSION) };
    if api_version < 0 {
        return KvmObservation {
            device_present: true,
            device_opened: true,
            api_version: None,
            reason: Some(format!(
                "KVM_GET_API_VERSION failed: {}",
                std::io::Error::last_os_error()
            )),
        };
    }
    if api_version != KVM_API_VERSION {
        return KvmObservation {
            device_present: true,
            device_opened: true,
            api_version: Some(api_version),
            reason: Some(format!(
                "KVM API version {api_version} is unsupported; expected {KVM_API_VERSION}"
            )),
        };
    }

    KvmObservation {
        device_present: true,
        device_opened: true,
        api_version: Some(api_version),
        reason: None,
    }
}

fn kvm_capability(observation: KvmObservation) -> DriverCapability {
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "device_present".to_string(),
        observation.device_present.to_string(),
    );
    evidence.insert(
        "device_opened".to_string(),
        observation.device_opened.to_string(),
    );
    evidence.insert(
        "api_version".to_string(),
        observation
            .api_version
            .map_or_else(|| "unavailable".to_string(), |version| version.to_string()),
    );

    DriverCapability {
        driver: DriverKind::LibkrunKvm,
        status: if observation.device_opened && observation.api_version == Some(KVM_API_VERSION) {
            CapabilityStatus::Available
        } else {
            CapabilityStatus::Unavailable
        },
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
    use a3s_oci_core::{CapabilityStatus, DriverKind, DriverReadiness, IsolationClass};

    use super::{
        features, kvm_capability, native_capability, KvmObservation, NativeLinuxObservation,
        KVM_API_VERSION,
    };

    #[test]
    fn available_native_linux_remains_probe_only() {
        let capability = native_capability(NativeLinuxObservation {
            namespace_api: true,
            cgroup_v2: true,
            unprivileged_user_namespaces: "enabled",
            reason: None,
        });

        assert_eq!(capability.driver, DriverKind::NativeLinux);
        assert_eq!(capability.status, CapabilityStatus::Available);
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert_eq!(
            capability.isolation_classes,
            [IsolationClass::SharedHostKernel]
        );
        assert!(!capability.can_launch());
    }

    #[test]
    fn incomplete_native_prerequisites_are_unavailable() {
        let capability = native_capability(NativeLinuxObservation {
            namespace_api: true,
            cgroup_v2: false,
            unprivileged_user_namespaces: "disabled",
            reason: Some("cgroup v2 is unavailable".to_string()),
        });

        assert_eq!(capability.status, CapabilityStatus::Unavailable);
        assert_eq!(
            capability.evidence["unprivileged_user_namespaces"],
            "disabled"
        );
        assert!(!capability.can_launch());
    }

    #[test]
    fn usable_kvm_api_remains_probe_only() {
        let capability = kvm_capability(KvmObservation {
            device_present: true,
            device_opened: true,
            api_version: Some(KVM_API_VERSION),
            reason: None,
        });

        assert_eq!(capability.driver, DriverKind::LibkrunKvm);
        assert_eq!(capability.status, CapabilityStatus::Available);
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert!(!capability.can_launch());
    }

    #[test]
    fn inaccessible_kvm_is_distinct_from_an_absent_device() {
        let capability = kvm_capability(KvmObservation {
            device_present: true,
            device_opened: false,
            api_version: None,
            reason: Some("permission denied".to_string()),
        });

        assert_eq!(capability.status, CapabilityStatus::Unavailable);
        assert_eq!(capability.evidence["device_present"], "true");
        assert_eq!(capability.evidence["device_opened"], "false");
        assert_eq!(capability.evidence["api_version"], "unavailable");
    }

    #[test]
    fn real_probe_reports_native_and_optional_kvm_drivers() {
        let inventory = features();

        assert_eq!(inventory.drivers.len(), 2);
        assert!(inventory.driver(DriverKind::NativeLinux).is_some());
        assert!(inventory.driver(DriverKind::LibkrunKvm).is_some());
        assert!(inventory
            .drivers
            .iter()
            .all(|driver| driver.readiness == DriverReadiness::ProbeOnly));
    }
}
