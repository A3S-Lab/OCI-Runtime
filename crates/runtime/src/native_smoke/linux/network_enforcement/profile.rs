use std::path::PathBuf;

use a3s_oci_sdk::{NetworkEnforcementAttachment, OciBundle, NETWORK_ENFORCEMENT_EXTENSION};
use serde_json::Value;

use crate::NativeLinuxNetworkEnforcementSmokeConfig;

pub(super) struct NetworkProfile {
    pub(super) namespace_index: usize,
    pub(super) namespace_path: PathBuf,
    pub(super) target_interface: String,
    pub(super) attachment: NetworkEnforcementAttachment,
}

pub(super) fn network_profile(
    bundle: &OciBundle,
    configuration: &NativeLinuxNetworkEnforcementSmokeConfig,
) -> Result<NetworkProfile, String> {
    let value: Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode network-enforcement configuration: {error}"))?;
    let namespaces = value
        .pointer("/linux/namespaces")
        .and_then(Value::as_array)
        .ok_or_else(|| "network-enforcement bundle has no Linux namespace array".to_string())?;
    let mut network_namespaces = namespaces
        .iter()
        .enumerate()
        .filter(|(_, namespace)| namespace.get("type").and_then(Value::as_str) == Some("network"));
    let (namespace_index, namespace) = network_namespaces
        .next()
        .ok_or_else(|| "network-enforcement bundle has no network namespace".to_string())?;
    if network_namespaces.next().is_some() {
        return Err("network-enforcement bundle must contain exactly one network namespace".into());
    }
    let namespace_path = namespace
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            "network-enforcement bundle must join one caller-owned namespace path".to_string()
        })?;
    let devices = value
        .pointer("/linux/netDevices")
        .and_then(Value::as_object)
        .ok_or_else(|| "network-enforcement bundle has no linux.netDevices object".to_string())?;
    if devices.len() != 1 {
        return Err(
            "network-enforcement qualification requires exactly one network interface".into(),
        );
    }
    let descriptor = devices
        .get(configuration.source_interface())
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!(
                "network-enforcement bundle does not contain source interface {}",
                configuration.source_interface()
            )
        })?;
    let target_interface = descriptor
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(configuration.source_interface());
    if target_interface.contains('%') {
        return Err("network-enforcement target interface must be exact, not a template".into());
    }
    let encoded = value
        .pointer("/annotations")
        .and_then(Value::as_object)
        .and_then(|annotations| annotations.get(NETWORK_ENFORCEMENT_EXTENSION))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            format!(
                "network-enforcement bundle is missing string annotation {NETWORK_ENFORCEMENT_EXTENSION}"
            )
        })?;
    let attachment = NetworkEnforcementAttachment::from_annotation_value(encoded)
        .map_err(|error| format!("failed to decode network-enforcement annotation: {error}"))?;
    Ok(NetworkProfile {
        namespace_index,
        namespace_path,
        target_interface: target_interface.to_string(),
        attachment,
    })
}
