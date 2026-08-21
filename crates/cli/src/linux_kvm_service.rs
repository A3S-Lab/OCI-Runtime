use std::path::PathBuf;

use a3s_oci_runtime::{LinuxKvmRecoveryHostService, LinuxKvmRecoveryHostServiceConfig};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::signal::unix::{signal, SignalKind};

pub(crate) async fn run(
    root: PathBuf,
    shim: PathBuf,
    system_image_manifest: PathBuf,
) -> Result<()> {
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| signal_error("SIGINT", error))?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| signal_error("SIGTERM", error))?;
    let config = LinuxKvmRecoveryHostServiceConfig::new(root, shim, system_image_manifest)?;
    let service = LinuxKvmRecoveryHostService::bind(config).await?;
    service
        .serve_until(async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        })
        .await
}

fn signal_error(signal_name: &'static str, error: std::io::Error) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!(
            "failed to register Linux KVM recovery Host Service {signal_name} handler: {error}"
        ),
    )
    .for_operation("start-linux-kvm-recovery-host-service")
}
