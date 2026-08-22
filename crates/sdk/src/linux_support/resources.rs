use oci_spec::runtime::LinuxResources;
use serde_json::Value;

use crate::{Error, ErrorCode, Result};

use super::{profile_error, OciLinuxSupport};

impl OciLinuxSupport {
    /// Reject one live resource update outside this profile.
    pub fn validate_resources(
        &self,
        resources: &LinuxResources,
        operation: &'static str,
    ) -> Result<()> {
        let cgroup = self.linux.cgroup().as_ref();
        let supports_v1 = cgroup.is_some_and(|cgroup| *cgroup.v1() == Some(true));
        let supports_v2 = cgroup.is_some_and(|cgroup| *cgroup.v2() == Some(true));
        if !supports_v1 && !supports_v2 {
            return Err(unsupported(
                "linux.resources",
                "no cgroup manager is advertised",
                operation,
            ));
        }

        let value = serde_json::to_value(resources).map_err(|error| {
            profile_error(
                ErrorCode::Internal,
                format!("failed to inspect OCI Linux resources: {error}"),
                operation,
            )
        })?;
        if !supports_v1 {
            if let Some(field) = first_cgroup_v1_only_field(&value) {
                let reason = if field == "linux.resources.network" {
                    "cgroup v1 net_cls and net_prio controls are not advertised because the selected driver does not advertise cgroup v1"
                } else {
                    "the selected driver does not advertise cgroup v1"
                };
                return Err(unsupported(&field, reason, operation));
            }
        }
        if resources.unified().is_some() && !supports_v2 {
            return Err(unsupported(
                "linux.resources.unified",
                "unified resources require advertised cgroup v2 support",
                operation,
            ));
        }
        if resources.rdma().is_some() && !cgroup.is_some_and(|cgroup| *cgroup.rdma() == Some(true))
        {
            return Err(unsupported(
                "linux.resources.rdma",
                "the RDMA cgroup controller is not advertised",
                operation,
            ));
        }
        Ok(())
    }
}

fn first_cgroup_v1_only_field(resources: &Value) -> Option<String> {
    let object = resources.as_object()?;
    if object.contains_key("network") {
        return Some("linux.resources.network".to_string());
    }
    for (section, fields) in [
        (
            "memory",
            &[
                "kernel",
                "kernelTCP",
                "swappiness",
                "disableOOMKiller",
                "useHierarchy",
                "checkBeforeUpdate",
            ][..],
        ),
        ("cpu", &["realtimeRuntime", "realtimePeriod"][..]),
        ("blockIO", &["leafWeight"][..]),
    ] {
        let Some(section_value) = object.get(section).and_then(Value::as_object) else {
            continue;
        };
        if let Some(field) = fields
            .iter()
            .find(|field| section_value.contains_key(**field))
        {
            return Some(format!("linux.resources.{section}.{field}"));
        }
    }
    if object
        .get("blockIO")
        .and_then(Value::as_object)
        .and_then(|block_io| block_io.get("weightDevice"))
        .and_then(Value::as_array)
        .is_some_and(|devices| {
            devices.iter().any(|device| {
                device
                    .as_object()
                    .is_some_and(|device| device.contains_key("leafWeight"))
            })
        })
    {
        return Some("linux.resources.blockIO.weightDevice[].leafWeight".to_string());
    }
    None
}

fn unsupported(field: &str, reason: &str, operation: &'static str) -> Error {
    profile_error(
        ErrorCode::Unsupported,
        format!("{field}: {reason}"),
        operation,
    )
}
