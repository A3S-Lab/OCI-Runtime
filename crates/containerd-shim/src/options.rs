use std::path::Path;

use a3s_oci_sdk::{
    Error, ErrorCode, IsolationClass, IsolationRequest, RuntimeExtensions, RuntimeOperation,
    RUNTIME_OPERATION_CONTRACT_V1,
};
use containerd_shim_protos::protobuf::well_known_types::any::Any;
use serde::{Deserialize, Serialize};

use crate::contract::{CREATE_OPTIONS_SCHEMA_VERSION, CREATE_OPTIONS_TYPE_URL};

/// OCI annotation carrying the same CreateOptions JSON schema when a client cannot
/// marshal `Runtime.Options` (for example `ctr --annotation`).
pub(crate) const CREATE_OPTIONS_ANNOTATION: &str = CREATE_OPTIONS_TYPE_URL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ContainerdIsolation {
    SharedHostKernel,
    DedicatedVm,
    SharedGuestKernel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateOptions {
    schema_version: u32,
    isolation: ContainerdIsolation,
}

/// Explicit CreateOptions selection versus "client omitted isolation".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CreateIsolationSelection {
    Requested(IsolationRequest),
    Unspecified,
}

/// Resolve isolation from Runtime.Options, falling back to the OCI annotation
/// that carries the same CreateOptions JSON. Conflicting sources fail closed.
///
/// When both sources are absent, returns [`CreateIsolationSelection::Unspecified`]
/// so the shim can pick a Host-advertised default instead of assuming
/// SharedHostKernel against a DedicatedVm-only Host.
pub(crate) fn resolve(
    options: Option<&Any>,
    bundle: &Path,
) -> Result<CreateIsolationSelection, Error> {
    let from_options = match options {
        None => None,
        Some(any) if any.type_url.is_empty() && any.value.is_empty() => None,
        Some(any) => Some(decode(Some(any))?),
    };
    let from_annotation = read_annotation_create_options(bundle)?;
    match (from_options, from_annotation) {
        (Some(left), Some(right)) if left != right => Err(options_error(
            ErrorCode::InvalidArgument,
            format!(
                "containerd Runtime.Options isolation {left:?} conflicts with OCI annotation isolation {right:?}"
            ),
        )),
        (Some(isolation), _) | (None, Some(isolation)) => {
            Ok(CreateIsolationSelection::Requested(isolation))
        }
        (None, None) => Ok(CreateIsolationSelection::Unspecified),
    }
}

/// Choose create isolation when the client omitted CreateOptions.
///
/// Prefer SharedHostKernel when the Host can create with it. Otherwise, if the
/// Host advertises exactly one create-capable isolation class, use that class.
/// Ambiguous multi-class Hosts without SharedHostKernel require explicit options.
pub(crate) fn default_from_extensions(
    extensions: &RuntimeExtensions,
) -> Result<IsolationRequest, Error> {
    let mut create_classes = Vec::new();
    for driver in extensions.drivers() {
        if !driver.supports_operation(RuntimeOperation::Create, RUNTIME_OPERATION_CONTRACT_V1) {
            continue;
        }
        for class in driver.isolation_classes() {
            if !create_classes.contains(class) {
                create_classes.push(*class);
            }
        }
    }
    if create_classes.contains(&IsolationClass::SharedHostKernel) {
        return Ok(IsolationRequest::SharedHostKernel);
    }
    match create_classes.as_slice() {
        [] => Err(options_error(
            ErrorCode::Unsupported,
            "Host Service advertises no create-capable isolation class",
        )),
        [IsolationClass::DedicatedVm] => Ok(IsolationRequest::DedicatedVm),
        [IsolationClass::SharedGuestKernel] => Err(options_error(
            ErrorCode::Unsupported,
            "Host Service only advertises shared-guest-kernel; containerd create requires explicit typed trust-domain CreateOptions",
        )),
        [IsolationClass::SharedHostKernel] => Ok(IsolationRequest::SharedHostKernel),
        _ => Err(options_error(
            ErrorCode::InvalidArgument,
            "Host Service advertises multiple create isolations without SharedHostKernel; set CreateOptions via Runtime.Options or the OCI annotation",
        )),
    }
}

pub(crate) fn decode(options: Option<&Any>) -> Result<IsolationRequest, Error> {
    let Some(options) = options else {
        return Ok(IsolationRequest::SharedHostKernel);
    };
    decode_bytes(&options.type_url, &options.value)
}

fn decode_bytes(type_url: &str, value: &[u8]) -> Result<IsolationRequest, Error> {
    if type_url != CREATE_OPTIONS_TYPE_URL {
        return Err(options_error(
            ErrorCode::InvalidArgument,
            format!(
                "unsupported containerd create options type {type_url}; expected {CREATE_OPTIONS_TYPE_URL}"
            ),
        ));
    }
    let options: CreateOptions = serde_json::from_slice(value).map_err(|error| {
        options_error(
            ErrorCode::InvalidArgument,
            format!("invalid A3S containerd create options: {error}"),
        )
    })?;
    create_options_to_isolation(options)
}

fn create_options_to_isolation(options: CreateOptions) -> Result<IsolationRequest, Error> {
    if options.schema_version != CREATE_OPTIONS_SCHEMA_VERSION {
        return Err(options_error(
            ErrorCode::Unsupported,
            format!(
                "unsupported A3S containerd create options schema {}; expected {CREATE_OPTIONS_SCHEMA_VERSION}",
                options.schema_version,
            ),
        ));
    }
    match options.isolation {
        ContainerdIsolation::SharedHostKernel => Ok(IsolationRequest::SharedHostKernel),
        ContainerdIsolation::DedicatedVm => Ok(IsolationRequest::DedicatedVm),
        ContainerdIsolation::SharedGuestKernel => Err(options_error(
            ErrorCode::Unsupported,
            "containerd shared-guest-kernel isolation requires a typed trust-domain contract that schema v1 does not provide",
        )),
    }
}

fn read_annotation_create_options(bundle: &Path) -> Result<Option<IsolationRequest>, Error> {
    let config_path = bundle.join("config.json");
    let bytes = match std::fs::read(&config_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(options_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to read OCI config {}: {error}",
                    config_path.display()
                ),
            ));
        }
    };
    let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        options_error(
            ErrorCode::InvalidArgument,
            format!("invalid OCI config {}: {error}", config_path.display()),
        )
    })?;
    let Some(annotations) = config.get("annotations") else {
        return Ok(None);
    };
    let Some(raw) = annotations.get(CREATE_OPTIONS_ANNOTATION) else {
        return Ok(None);
    };
    // ctr stores the payload as a JSON string; some writers may embed the object
    // directly. Accept both without changing the CreateOptions schema.
    let options: CreateOptions = match raw {
        serde_json::Value::String(text) => serde_json::from_str(text).map_err(|error| {
            options_error(
                ErrorCode::InvalidArgument,
                format!("invalid A3S containerd create options annotation: {error}"),
            )
        })?,
        object => serde_json::from_value(object.clone()).map_err(|error| {
            options_error(
                ErrorCode::InvalidArgument,
                format!("invalid A3S containerd create options annotation object: {error}"),
            )
        })?,
    };
    create_options_to_isolation(options).map(Some)
}

fn options_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("containerd-shim-options")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn any(value: serde_json::Value) -> Any {
        let mut any = Any::new();
        any.type_url = CREATE_OPTIONS_TYPE_URL.to_string();
        any.value = serde_json::to_vec(&value).expect("encode options");
        any
    }

    fn write_annotated_bundle(isolation: &str) -> tempfile::TempDir {
        let directory = tempdir().expect("tempdir");
        let config = serde_json::json!({
            "ociVersion": "1.0.2",
            "annotations": {
                CREATE_OPTIONS_ANNOTATION: serde_json::json!({
                    "schema_version": 1,
                    "isolation": isolation
                }).to_string()
            }
        });
        fs::write(
            directory.path().join("config.json"),
            serde_json::to_vec_pretty(&config).expect("encode config"),
        )
        .expect("write config");
        directory
    }

    #[test]
    fn absence_selects_unspecified_for_host_defaulting() {
        let directory = tempdir().expect("tempdir");
        assert_eq!(
            resolve(None, directory.path()).expect("unspecified"),
            CreateIsolationSelection::Unspecified
        );
    }

    #[test]
    fn decode_absence_keeps_shared_host_kernel_for_legacy_callers() {
        assert_eq!(
            decode(None).expect("default options"),
            IsolationRequest::SharedHostKernel
        );
    }

    #[test]
    fn schema_v1_selects_shared_host_or_dedicated_vm_without_fallback() {
        assert_eq!(
            decode(Some(&any(serde_json::json!({
                "schema_version": 1,
                "isolation": "shared-host-kernel"
            }))))
            .expect("shared host options"),
            IsolationRequest::SharedHostKernel
        );
        assert_eq!(
            decode(Some(&any(serde_json::json!({
                "schema_version": 1,
                "isolation": "dedicated-vm"
            }))))
            .expect("dedicated VM options"),
            IsolationRequest::DedicatedVm
        );
    }

    #[test]
    fn rejects_unknown_types_versions_fields_and_unscoped_guest_sharing() {
        let mut wrong_type = any(serde_json::json!({
            "schema_version": 1,
            "isolation": "shared-host-kernel"
        }));
        wrong_type.type_url = "io.containerd.runc.v2.Options".to_string();
        for options in [
            wrong_type,
            any(serde_json::json!({
                "schema_version": 1,
                "isolation": "shared-host-kernel",
                "unknown": true
            })),
            any(serde_json::json!({
                "schema_version": 2,
                "isolation": "shared-host-kernel"
            })),
            any(serde_json::json!({
                "schema_version": 1,
                "isolation": "shared-guest-kernel"
            })),
        ] {
            assert!(
                decode(Some(&options)).is_err(),
                "{options:?} must fail closed"
            );
        }
    }

    #[test]
    fn annotation_selects_dedicated_vm_when_runtime_options_are_absent() {
        let bundle = write_annotated_bundle("dedicated-vm");
        assert_eq!(
            resolve(None, bundle.path()).expect("annotation options"),
            CreateIsolationSelection::Requested(IsolationRequest::DedicatedVm)
        );
    }

    #[test]
    fn runtime_options_win_when_annotation_matches() {
        let bundle = write_annotated_bundle("dedicated-vm");
        assert_eq!(
            resolve(
                Some(&any(serde_json::json!({
                    "schema_version": 1,
                    "isolation": "dedicated-vm"
                }))),
                bundle.path()
            )
            .expect("matching sources"),
            CreateIsolationSelection::Requested(IsolationRequest::DedicatedVm)
        );
    }

    #[test]
    fn conflicting_runtime_options_and_annotation_fail_closed() {
        let bundle = write_annotated_bundle("dedicated-vm");
        assert!(resolve(
            Some(&any(serde_json::json!({
                "schema_version": 1,
                "isolation": "shared-host-kernel"
            }))),
            bundle.path()
        )
        .is_err());
    }
}
