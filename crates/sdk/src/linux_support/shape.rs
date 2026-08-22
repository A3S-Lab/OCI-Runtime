use std::collections::BTreeSet;

use oci_spec::runtime::LinuxFeature;
use serde::Serialize;

use crate::{ErrorCode, Result};

use super::{profile_error, CONSTRUCT_OPERATION};

pub(super) fn validate_feature_shape(linux: &LinuxFeature) -> Result<()> {
    ensure_unique(linux.namespaces().as_deref(), "linux.namespaces")?;
    ensure_unique(linux.capabilities().as_deref(), "linux.capabilities")?;
    if let Some(seccomp) = linux.seccomp().as_ref() {
        ensure_unique(seccomp.actions().as_deref(), "linux.seccomp.actions")?;
        ensure_unique(seccomp.operators().as_deref(), "linux.seccomp.operators")?;
        ensure_unique(seccomp.archs().as_deref(), "linux.seccomp.archs")?;
        ensure_unique(seccomp.known_flags().as_deref(), "linux.seccomp.knownFlags")?;
        ensure_unique(
            seccomp.supported_flags().as_deref(),
            "linux.seccomp.supportedFlags",
        )?;
        let known = seccomp.known_flags().as_deref().unwrap_or_default();
        if let Some(flag) = seccomp
            .supported_flags()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|flag| !known.contains(flag))
        {
            return Err(profile_error(
                ErrorCode::InvalidArgument,
                format!("supported seccomp flag {flag} is absent from knownFlags"),
                CONSTRUCT_OPERATION,
            ));
        }
    }
    if let Some(memory_policy) = linux.memory_policy().as_ref() {
        ensure_unique(memory_policy.modes().as_deref(), "linux.memoryPolicy.modes")?;
        ensure_unique(memory_policy.flags().as_deref(), "linux.memoryPolicy.flags")?;
    }
    if let Some(intel_rdt) = linux.intel_rdt().as_ref() {
        if (*intel_rdt.schemata() == Some(true) || *intel_rdt.monitoring() == Some(true))
            && *intel_rdt.enabled() != Some(true)
        {
            return Err(profile_error(
                ErrorCode::InvalidArgument,
                "Intel RDT subfeatures require linux.intelRdt.enabled=true",
                CONSTRUCT_OPERATION,
            ));
        }
    }
    Ok(())
}

fn ensure_unique<T: Serialize>(values: Option<&[T]>, field: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values.unwrap_or_default() {
        let encoded = serde_json::to_string(value).map_err(|error| {
            profile_error(
                ErrorCode::Internal,
                format!("failed to inspect {field}: {error}"),
                CONSTRUCT_OPERATION,
            )
        })?;
        if !seen.insert(encoded.clone()) {
            return Err(profile_error(
                ErrorCode::InvalidArgument,
                format!("{field} contains duplicate value {encoded}"),
                CONSTRUCT_OPERATION,
            ));
        }
    }
    Ok(())
}
