use std::collections::BTreeSet;

use a3s_oci_sdk::oci_spec::runtime::Linux;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::namespace::NamespacePlan;

mod netlink;

pub(super) use netlink::NetworkDeviceLease;

const MAX_NETWORK_DEVICES: usize = 64;
const LINUX_INTERFACE_NAME_BYTES: usize = libc::IFNAMSIZ - 1;

/// One normalized OCI network-device move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetworkDeviceEntry {
    host_name: String,
    container_name: String,
    template: bool,
}

impl NetworkDeviceEntry {
    pub(super) fn host_name(&self) -> &str {
        &self.host_name
    }

    pub(super) fn container_name(&self) -> &str {
        &self.container_name
    }

    pub(super) const fn uses_template(&self) -> bool {
        self.template
    }
}

/// Bounded, deterministic network-device work retained by the init plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct NetworkDevicePlan {
    entries: Vec<NetworkDeviceEntry>,
}

impl NetworkDevicePlan {
    pub(super) fn from_linux(linux: Option<&Linux>, namespaces: &NamespacePlan) -> Result<Self> {
        let Some(devices) = linux.and_then(|linux| linux.net_devices().as_ref()) else {
            return Ok(Self::default());
        };
        if devices.len() > MAX_NETWORK_DEVICES {
            return Err(network_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "linux.netDevices contains {} entries; maximum is {MAX_NETWORK_DEVICES}",
                    devices.len()
                ),
            ));
        }
        if !devices.is_empty() && !namespaces.has_network() {
            return Err(network_error(
                ErrorCode::InvalidArgument,
                "linux.netDevices requires an explicit Linux network namespace",
            ));
        }

        let mut exact_targets = BTreeSet::new();
        let mut entries = devices
            .iter()
            .map(|(host_name, device)| {
                validate_interface_name(host_name, "linux.netDevices source name")?;
                let configured = device.name().as_deref().filter(|name| !name.is_empty());
                let container_name = configured.unwrap_or(host_name);
                let template = validate_container_name(container_name)?;
                if !template && !exact_targets.insert(container_name.to_string()) {
                    return Err(network_error(
                        ErrorCode::InvalidArgument,
                        format!(
                            "linux.netDevices assigns more than one source to target `{container_name}`"
                        ),
                    ));
                }
                Ok(NetworkDeviceEntry {
                    host_name: host_name.clone(),
                    container_name: container_name.to_string(),
                    template,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        entries.sort_unstable_by(|left, right| left.host_name.cmp(&right.host_name));
        Ok(Self { entries })
    }

    pub(super) fn entries(&self) -> &[NetworkDeviceEntry] {
        &self.entries
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn validate_container_name(name: &str) -> Result<bool> {
    validate_interface_name(name, "linux.netDevices target name")?;
    let template = name.ends_with("%d");
    let percent_count = name.bytes().filter(|byte| *byte == b'%').count();
    if percent_count != 0 && (!template || percent_count != 1) {
        return Err(network_error(
            ErrorCode::InvalidArgument,
            format!(
                "linux.netDevices target `{name}` must use `%d` only as one appended name template"
            ),
        ));
    }
    Ok(template)
}

fn validate_interface_name(name: &str, field: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > LINUX_INTERFACE_NAME_BYTES
        || matches!(name, "." | "..")
        || name
            .bytes()
            .any(|byte| byte == 0 || byte == b'/' || byte == b':' || byte.is_ascii_whitespace())
    {
        return Err(network_error(
            ErrorCode::InvalidArgument,
            format!(
                "{field} `{name}` must be 1-{LINUX_INTERFACE_NAME_BYTES} bytes and contain no NUL, slash, colon, or whitespace"
            ),
        ));
    }
    Ok(())
}

fn network_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("plan-guest-init")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::oci_spec::runtime::Linux;
    use a3s_oci_sdk::ErrorCode;

    use super::NetworkDevicePlan;
    use crate::executor::namespace::NamespacePlan;

    fn plan(value: serde_json::Value) -> a3s_oci_sdk::Result<NetworkDevicePlan> {
        let linux: Linux = serde_json::from_value(value).expect("schema-shaped Linux config");
        let namespaces = NamespacePlan::from_linux(Some(&linux), 0, 0, &[])?;
        NetworkDevicePlan::from_linux(Some(&linux), &namespaces)
    }

    #[test]
    fn normalizes_empty_names_and_accepts_only_appended_templates() {
        let planned = plan(serde_json::json!({
            "namespaces": [{"type": "network"}],
            "netDevices": {
                "veth2": {"name": ""},
                "veth0": {"name": "eth%d"},
                "veth1": {"name": "eth1"}
            }
        }))
        .expect("valid network-device plan");
        assert_eq!(planned.entries()[0].host_name(), "veth0");
        assert_eq!(planned.entries()[0].container_name(), "eth%d");
        assert!(planned.entries()[0].uses_template());
        assert_eq!(planned.entries()[2].container_name(), "veth2");
        assert!(!planned.entries()[2].uses_template());

        for invalid in ["eth%d-rest", "eth%d%d", "eth%%d", "eth%0"] {
            let error = plan(serde_json::json!({
                "namespaces": [{"type": "network"}],
                "netDevices": {"veth0": {"name": invalid}}
            }))
            .expect_err("invalid target template must fail");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert!(error.message.contains("appended name template"));
        }
    }

    #[test]
    fn rejects_duplicate_exact_targets_and_unbounded_names() {
        let duplicate = plan(serde_json::json!({
            "namespaces": [{"type": "network"}],
            "netDevices": {
                "veth0": {"name": "eth0"},
                "veth1": {"name": "eth0"}
            }
        }))
        .expect_err("duplicate target names must fail");
        assert_eq!(duplicate.code, ErrorCode::InvalidArgument);
        assert!(duplicate.message.contains("more than one source"));

        let long = plan(serde_json::json!({
            "namespaces": [{"type": "network"}],
            "netDevices": {"interface-name-too-long": {}}
        }))
        .expect_err("overlong source name must fail");
        assert_eq!(long.code, ErrorCode::InvalidArgument);
        assert!(long.message.contains("1-15 bytes"));
    }

    #[test]
    fn requires_network_isolation_and_bounds_the_complete_plan() {
        let missing_namespace = plan(serde_json::json!({
            "netDevices": {"veth0": {}}
        }))
        .expect_err("network devices without a network namespace must fail");
        assert_eq!(missing_namespace.code, ErrorCode::InvalidArgument);
        assert!(missing_namespace
            .message
            .contains("requires an explicit Linux network namespace"));

        let devices = (0..=super::MAX_NETWORK_DEVICES)
            .map(|index| (format!("v{index}"), serde_json::json!({})))
            .collect::<serde_json::Map<_, _>>();
        let unbounded = plan(serde_json::json!({
            "namespaces": [{"type": "network"}],
            "netDevices": devices
        }))
        .expect_err("unbounded network-device plans must fail");
        assert_eq!(unbounded.code, ErrorCode::ResourceExhausted);
        assert!(unbounded.message.contains("maximum is 64"));
    }
}
