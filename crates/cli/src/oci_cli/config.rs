use std::env;
use std::path::PathBuf;

use a3s_oci_sdk::{Error, ErrorCode, IsolationRequest, LocalIpcEndpoint, Result, TrustDomainId};

const RUNTIME_ENDPOINT_ENV: &str = "A3S_OCI_RUNTIME_ENDPOINT";
const LEGACY_RUNTIME_ENDPOINT_ENV: &str = "A3S_OCI_RUNTIME_SOCKET";
const STATE_ROOT_ENV: &str = "A3S_OCI_CLI_STATE_ROOT";
const ISOLATION_ENV: &str = "A3S_OCI_CLI_ISOLATION";
const TRUST_DOMAIN_ENV: &str = "A3S_OCI_CLI_TRUST_DOMAIN";

pub(super) struct AdapterConfig {
    pub(super) endpoint: LocalIpcEndpoint,
    pub(super) state_root: PathBuf,
    pub(super) isolation: Option<IsolationRequest>,
}

impl AdapterConfig {
    pub(super) fn from_environment(require_isolation: bool) -> Result<Self> {
        let endpoint = env::var_os(RUNTIME_ENDPOINT_ENV)
            .or_else(|| env::var_os(LEGACY_RUNTIME_ENDPOINT_ENV))
            .ok_or_else(|| {
                invalid_configuration(format!(
                    "{RUNTIME_ENDPOINT_ENV} must name the selected Host Service endpoint"
                ))
            })?;
        let state_root = env::var_os(STATE_ROOT_ENV)
            .map(PathBuf::from)
            .ok_or_else(|| {
                invalid_configuration(format!(
                    "{STATE_ROOT_ENV} must name an existing private absolute directory"
                ))
            })?;
        let isolation = if require_isolation {
            Some(parse_isolation()?)
        } else {
            None
        };

        Ok(Self {
            endpoint: local_endpoint(endpoint)?,
            state_root,
            isolation,
        })
    }
}

#[cfg(unix)]
fn local_endpoint(value: std::ffi::OsString) -> Result<LocalIpcEndpoint> {
    LocalIpcEndpoint::unix_socket(PathBuf::from(value))
}

#[cfg(windows)]
fn local_endpoint(value: std::ffi::OsString) -> Result<LocalIpcEndpoint> {
    let value = value.into_string().map_err(|_| {
        invalid_configuration(format!(
            "{RUNTIME_ENDPOINT_ENV} must be valid Unicode on Windows"
        ))
    })?;
    LocalIpcEndpoint::windows_named_pipe(value)
}

#[cfg(not(any(unix, windows)))]
fn local_endpoint(_value: std::ffi::OsString) -> Result<LocalIpcEndpoint> {
    Err(Error::new(
        ErrorCode::Unsupported,
        "the OCI command-line adapter requires Unix local sockets or Windows named pipes",
    )
    .for_operation("oci-cli-config"))
}

fn parse_isolation() -> Result<IsolationRequest> {
    let value = env::var(ISOLATION_ENV).map_err(|_| {
        invalid_configuration(format!(
            "{ISOLATION_ENV} must explicitly select shared-host-kernel, dedicated-vm, or shared-guest-kernel"
        ))
    })?;
    match value.as_str() {
        "shared-host-kernel" => Ok(IsolationRequest::SharedHostKernel),
        "dedicated-vm" => Ok(IsolationRequest::DedicatedVm),
        "shared-guest-kernel" => {
            let trust_domain = env::var(TRUST_DOMAIN_ENV).map_err(|_| {
                invalid_configuration(format!(
                    "{TRUST_DOMAIN_ENV} is required for shared-guest-kernel isolation"
                ))
            })?;
            Ok(IsolationRequest::SharedGuestKernel {
                trust_domain: TrustDomainId::new(trust_domain)?,
            })
        }
        _ => Err(invalid_configuration(format!(
            "unsupported {ISOLATION_ENV} value {value:?}; expected shared-host-kernel, dedicated-vm, or shared-guest-kernel"
        ))),
    }
}

fn invalid_configuration(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("oci-cli-config")
}
