use std::future::Future;
use std::path::PathBuf;

use a3s_oci_sdk::{Error, ErrorCode, Result};

/// Readiness evidence emitted only after the protected Box qualification
/// endpoint has been bound around a durable runtime service.
pub const BOX_WHPX_SERVICE_READY_SCHEMA_VERSION: &str = "a3s.oci.box-whpx-service-ready.v1";

/// Explicit inputs for the qualification-only A3S Box/WHPX SDK owner.
#[derive(Debug, Clone)]
pub struct BoxWhpxServiceConfig {
    pub shim: PathBuf,
    pub runtime_root: PathBuf,
    pub vm_rootfs: PathBuf,
    pub state_root: PathBuf,
    pub pipe_name: String,
    pub ready_file: Option<PathBuf>,
}

impl BoxWhpxServiceConfig {
    #[must_use]
    pub fn new(
        shim: impl Into<PathBuf>,
        runtime_root: impl Into<PathBuf>,
        vm_rootfs: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        pipe_name: impl Into<String>,
    ) -> Self {
        Self {
            shim: shim.into(),
            runtime_root: runtime_root.into(),
            vm_rootfs: vm_rootfs.into(),
            state_root: state_root.into(),
            pipe_name: pipe_name.into(),
            ready_file: None,
        }
    }

    #[must_use]
    pub fn with_ready_file(mut self, ready_file: impl Into<PathBuf>) -> Self {
        self.ready_file = Some(ready_file.into());
        self
    }
}

/// Serve a protected local SDK endpoint for the explicit Box/WHPX product
/// qualification gate.
///
/// The public WHPX driver remains probe-only. This function can launch it only
/// through the crate-private, narrowly labelled qualification constructor.
pub async fn serve_box_whpx_qualification<F>(
    config: BoxWhpxServiceConfig,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    serve_platform(config, shutdown).await
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
async fn serve_platform<F>(config: BoxWhpxServiceConfig, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    use std::sync::Arc;

    use a3s_oci_core::DriverReadiness;
    use a3s_oci_sdk::LocalIpcEndpoint;

    use crate::{
        HostRuntimeService, RuntimeDriver as _, WhpxRuntimeDriver, WhpxRuntimeDriverConfig,
        WindowsHostService,
    };

    let driver = Arc::new(
        WhpxRuntimeDriver::open_box_qualification(WhpxRuntimeDriverConfig::new(
            &config.shim,
            &config.runtime_root,
            &config.vm_rootfs,
        ))
        .await?,
    );
    let capability = driver.capability();
    let scoped = capability.readiness == DriverReadiness::Experimental
        && capability
            .evidence
            .get("qualification_override")
            .is_some_and(|value| value == "box-product-lifecycle-only");
    if !scoped {
        return Err(service_error(
            ErrorCode::FailedPrecondition,
            "WHPX Box service did not retain its qualification-only scope",
        ));
    }

    let endpoint = LocalIpcEndpoint::windows_named_pipe(config.pipe_name.clone())?;
    let service = HostRuntimeService::open(&config.state_root, driver).await?;
    let owner = WindowsHostService::bind(endpoint, service)?;
    if let Some(ready_file) = config.ready_file.as_ref() {
        write_ready_file(ready_file, &config)?;
    }

    let served = owner.serve_until(shutdown).await;
    if let Some(ready_file) = config.ready_file.as_ref() {
        match std::fs::remove_file(ready_file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if served.is_ok() => {
                return Err(service_error(
                    ErrorCode::Internal,
                    format!(
                        "failed to remove Box WHPX service readiness file {}: {error}",
                        ready_file.display()
                    ),
                ));
            }
            Err(_) => {}
        }
    }
    served
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
async fn serve_platform<F>(_config: BoxWhpxServiceConfig, _shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send,
{
    Err(service_error(
        ErrorCode::Unsupported,
        "the Box/WHPX qualification service requires Windows x86_64",
    ))
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn write_ready_file(path: &std::path::Path, config: &BoxWhpxServiceConfig) -> Result<()> {
    use std::io::Write;

    use serde::Serialize;

    #[derive(Serialize)]
    struct Ready<'a> {
        schema_version: &'static str,
        owner_pid: u32,
        endpoint: &'a str,
        runtime_root: &'a std::path::Path,
        state_root: &'a std::path::Path,
    }

    let parent = path.parent().ok_or_else(|| {
        service_error(
            ErrorCode::InvalidArgument,
            format!("Box WHPX readiness file has no parent: {}", path.display()),
        )
    })?;
    if !parent.is_dir() {
        return Err(service_error(
            ErrorCode::FailedPrecondition,
            format!(
                "Box WHPX readiness parent is not an existing directory: {}",
                parent.display()
            ),
        ));
    }
    if path.exists() {
        return Err(service_error(
            ErrorCode::Conflict,
            format!(
                "refusing to overwrite Box WHPX readiness file {}",
                path.display()
            ),
        ));
    }

    let temporary = path.with_extension(format!("pending-{}", std::process::id()));
    let payload = serde_json::to_vec_pretty(&Ready {
        schema_version: BOX_WHPX_SERVICE_READY_SCHEMA_VERSION,
        owner_pid: std::process::id(),
        endpoint: &config.pipe_name,
        runtime_root: &config.runtime_root,
        state_root: &config.state_root,
    })
    .map_err(|error| {
        service_error(
            ErrorCode::Internal,
            format!("failed to encode Box WHPX readiness evidence: {error}"),
        )
    })?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| {
            service_error(
                ErrorCode::Internal,
                format!(
                    "failed to create Box WHPX readiness file {}: {error}",
                    temporary.display()
                ),
            )
        })?;
    file.write_all(&payload).map_err(|error| {
        service_error(
            ErrorCode::Internal,
            format!("failed to write Box WHPX readiness evidence: {error}"),
        )
    })?;
    file.write_all(b"\n").map_err(|error| {
        service_error(
            ErrorCode::Internal,
            format!("failed to finish Box WHPX readiness evidence: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        service_error(
            ErrorCode::Internal,
            format!("failed to flush Box WHPX readiness evidence: {error}"),
        )
    })?;
    drop(file);
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        service_error(
            ErrorCode::Internal,
            format!(
                "failed to commit Box WHPX readiness file {}: {error}",
                path.display()
            ),
        )
    })
}

fn service_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("serve-box-whpx-qualification")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_keeps_the_explicit_endpoint_and_readiness_path() {
        let config = BoxWhpxServiceConfig::new(
            "shim",
            "runtime",
            "system",
            "state",
            r"\\.\pipe\a3s-oci-box-test",
        )
        .with_ready_file("ready.json");

        assert_eq!(config.pipe_name, r"\\.\pipe\a3s-oci-box-test");
        assert_eq!(config.ready_file, Some(PathBuf::from("ready.json")));
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    #[tokio::test]
    async fn unsupported_hosts_fail_before_waiting_for_shutdown() {
        let error = serve_box_whpx_qualification(
            BoxWhpxServiceConfig::new("shim", "runtime", "system", "state", "pipe"),
            std::future::pending(),
        )
        .await
        .expect_err("unsupported host must fail");

        assert_eq!(error.code, ErrorCode::Unsupported);
    }
}
