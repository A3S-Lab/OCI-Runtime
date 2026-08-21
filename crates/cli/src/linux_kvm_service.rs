use std::path::PathBuf;

use a3s_oci_runtime::{
    LinuxKvmRecoveryHostService, LinuxKvmRecoveryHostServiceConfig, LinuxKvmSoakHostService,
    LinuxKvmSoakHostServiceConfig,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::signal::unix::{signal, SignalKind};

pub(crate) async fn run(
    root: PathBuf,
    shim: PathBuf,
    system_image_manifest: PathBuf,
) -> Result<()> {
    let (mut interrupt, mut terminate) = shutdown_signals(
        "Linux KVM recovery Host Service",
        "start-linux-kvm-recovery-host-service",
    )?;
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

pub(crate) async fn run_soak(
    root: PathBuf,
    shim: PathBuf,
    system_image_manifest: PathBuf,
) -> Result<()> {
    let (mut interrupt, mut terminate) = shutdown_signals(
        "Linux KVM soak Host Service",
        "start-linux-kvm-soak-host-service",
    )?;
    let config = LinuxKvmSoakHostServiceConfig::new(root, shim, system_image_manifest)?;
    let service = LinuxKvmSoakHostService::bind(config).await?;
    service
        .serve_until(async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        })
        .await
}

fn shutdown_signals(
    service_label: &'static str,
    operation: &'static str,
) -> Result<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)> {
    let interrupt = signal(SignalKind::interrupt())
        .map_err(|error| signal_error(service_label, operation, "SIGINT", error))?;
    let terminate = signal(SignalKind::terminate())
        .map_err(|error| signal_error(service_label, operation, "SIGTERM", error))?;
    Ok((interrupt, terminate))
}

fn signal_error(
    service_label: &'static str,
    operation: &'static str,
    signal_name: &'static str,
    error: std::io::Error,
) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!("failed to register {service_label} {signal_name} handler: {error}"),
    )
    .for_operation(operation)
}
