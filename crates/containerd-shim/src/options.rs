use a3s_oci_sdk::{Error, ErrorCode, IsolationRequest};
use containerd_shim_protos::protobuf::well_known_types::any::Any;
use serde::{Deserialize, Serialize};

pub(crate) const CREATE_OPTIONS_TYPE_URL: &str = "dev.a3s.oci.runtime.v1.CreateOptions";

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

pub(crate) fn decode(options: Option<&Any>) -> Result<IsolationRequest, Error> {
    let Some(options) = options else {
        return Ok(IsolationRequest::SharedHostKernel);
    };
    if options.type_url != CREATE_OPTIONS_TYPE_URL {
        return Err(options_error(
            ErrorCode::InvalidArgument,
            format!(
                "unsupported containerd create options type {}; expected {CREATE_OPTIONS_TYPE_URL}",
                options.type_url
            ),
        ));
    }
    let options: CreateOptions = serde_json::from_slice(&options.value).map_err(|error| {
        options_error(
            ErrorCode::InvalidArgument,
            format!("invalid A3S containerd create options: {error}"),
        )
    })?;
    if options.schema_version != 1 {
        return Err(options_error(
            ErrorCode::Unsupported,
            format!(
                "unsupported A3S containerd create options schema {}; expected 1",
                options.schema_version
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

fn options_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("containerd-shim-options")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn any(value: serde_json::Value) -> Any {
        let mut any = Any::new();
        any.type_url = CREATE_OPTIONS_TYPE_URL.to_string();
        any.value = serde_json::to_vec(&value).expect("encode options");
        any
    }

    #[test]
    fn absence_selects_shared_host_kernel_explicitly() {
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
}
