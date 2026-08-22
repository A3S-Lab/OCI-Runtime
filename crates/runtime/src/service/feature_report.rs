use std::collections::HashMap;
use std::fmt;

use a3s_oci_sdk::oci_spec::runtime::{Features, FeaturesBuilder};
use a3s_oci_sdk::{
    AttachmentCapabilities, Error, ErrorCode, OciLinuxSupport, OciSchemaValidator, Result,
    BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS, OCI_RUNTIME_SPEC_VERSION_MAX,
    OCI_RUNTIME_SPEC_VERSION_MIN,
};

use crate::driver::OciHookPhase;

pub(super) fn build(
    has_lifecycle: bool,
    hooks: &[OciHookPhase],
    attachments: &AttachmentCapabilities,
    linux_support: &OciLinuxSupport,
) -> Result<Features> {
    let annotations = HashMap::from([
        (
            "dev.a3s.oci.runtime.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        (
            "dev.a3s.oci.runtime.lifecycle".to_string(),
            if has_lifecycle {
                "durable-core"
            } else {
                "probe-only"
            }
            .to_string(),
        ),
    ]);
    let features = FeaturesBuilder::default()
        .oci_version_min(OCI_RUNTIME_SPEC_VERSION_MIN)
        .oci_version_max(OCI_RUNTIME_SPEC_VERSION_MAX)
        .hooks(
            hooks
                .iter()
                .map(|phase| phase.as_str().to_string())
                .collect::<Vec<_>>(),
        )
        .mount_options(linux_support.mount_options().to_vec())
        .linux(linux_support.linux().clone())
        .annotations(annotations)
        .potentially_unsafe_config_annotations(potentially_unsafe_config_annotations(
            has_lifecycle,
            attachments,
        ))
        .build()
        .map_err(feature_build_error)?;
    OciSchemaValidator::new()?.validate_features(&features)?;
    Ok(features)
}

fn potentially_unsafe_config_annotations(
    has_lifecycle: bool,
    attachments: &AttachmentCapabilities,
) -> Vec<String> {
    if !has_lifecycle {
        return Vec::new();
    }

    let mut annotations = BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS
        .iter()
        .copied()
        .chain(attachments.extension_names())
        .map(str::to_string)
        .collect::<Vec<_>>();
    annotations.sort_unstable();
    annotations.dedup();
    annotations
}

fn feature_build_error(error: impl fmt::Display) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("failed to construct OCI feature report: {error}"),
    )
    .for_operation("features")
}
