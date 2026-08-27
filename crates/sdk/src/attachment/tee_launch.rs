use std::collections::BTreeMap;

use serde_json::Value;

use super::{invalid_attachment, AttachmentSource, RuntimeExtensionAttachment};
use crate::{
    Result, TeeLaunchRequest, TeeTechnology, AMD_SEV_SNP_LAUNCH_EXTENSION,
    INTEL_TDX_LAUNCH_EXTENSION, TEE_LAUNCH_EXTENSION_VERSION,
};

const KNOWN_EXTENSIONS: [&str; 2] = [AMD_SEV_SNP_LAUNCH_EXTENSION, INTEL_TDX_LAUNCH_EXTENSION];

pub(super) fn decode_extension(
    extensions: &BTreeMap<String, RuntimeExtensionAttachment>,
    network_sources: &[AttachmentSource],
    secret_sources: &[AttachmentSource],
    configuration: &Value,
) -> Result<Option<TeeLaunchRequest>> {
    let declared = KNOWN_EXTENSIONS
        .iter()
        .filter_map(|name| extensions.get(*name).map(|extension| (*name, extension)))
        .collect::<Vec<_>>();
    if declared.is_empty() {
        return Ok(None);
    }
    if declared.len() != 1 {
        return Err(invalid_attachment(
            "one create or restore may declare only one TEE launch extension",
        ));
    }

    let configured = KNOWN_EXTENSIONS
        .iter()
        .filter_map(|name| {
            configuration
                .pointer(&format!("/annotations/{name}"))
                .map(|value| (*name, value))
        })
        .collect::<Vec<_>>();
    if configured.len() != 1 {
        return Err(invalid_attachment(
            "a TEE launch requires exactly one known technology annotation",
        ));
    }

    let (name, extension) = declared[0];
    if extension.version != TEE_LAUNCH_EXTENSION_VERSION || !extension.required {
        return Err(invalid_attachment(format!(
            "TEE launch {name} must be required extension version {TEE_LAUNCH_EXTENSION_VERSION}"
        )));
    }
    if network_sources
        .iter()
        .chain(secret_sources)
        .any(|source| {
            matches!(source, AttachmentSource::RuntimeExtension { name: source_name } if source_name == name)
        })
    {
        return Err(invalid_attachment(
            "a TEE launch extension cannot be classified as network or secret material",
        ));
    }
    let (configured_name, value) = configured[0];
    if configured_name != name {
        return Err(invalid_attachment(format!(
            "TEE launch extension {name} does not match annotation {configured_name}"
        )));
    }
    let encoded = value.as_str().ok_or_else(|| {
        invalid_attachment("TEE launch extension annotation must contain a JSON string")
    })?;
    let launch = TeeLaunchRequest::from_annotation_value(encoded)?;
    let expected = TeeTechnology::from_extension_name(name)
        .ok_or_else(|| invalid_attachment(format!("unknown TEE launch extension {name}")))?;
    if launch.technology() != expected {
        return Err(invalid_attachment(format!(
            "TEE launch technology {:?} does not match extension {name}",
            launch.technology()
        )));
    }
    Ok(Some(launch))
}
