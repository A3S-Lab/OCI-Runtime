use std::path::PathBuf;

use a3s_oci_runtime::{
    NativeControlDescriptors, NativeLinuxService, NativeLinuxServiceConfig, EXEC_LISTENER_FD,
    INIT_LOG_FD, PTY_LISTENER_FD,
};
use a3s_oci_sdk::{ContainerId, Error, ErrorCode, Result};
use tokio::signal::unix::{signal, SignalKind};

pub(crate) async fn run(root: PathBuf, agent: PathBuf, container_id: ContainerId) -> Result<()> {
    let descriptors = inherited_control_descriptors()?;
    let mut interrupt =
        signal(SignalKind::interrupt()).map_err(|error| signal_error("SIGINT", error))?;
    let mut terminate =
        signal(SignalKind::terminate()).map_err(|error| signal_error("SIGTERM", error))?;
    let config = NativeLinuxServiceConfig::new(root, agent, container_id)?;
    let service = NativeLinuxService::bind(config, descriptors).await?;
    service
        .serve_until(async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        })
        .await
}

fn inherited_control_descriptors() -> Result<NativeControlDescriptors> {
    NativeControlDescriptors::try_clone_from_raw_fds(EXEC_LISTENER_FD, PTY_LISTENER_FD, INIT_LOG_FD)
}

fn signal_error(signal_name: &'static str, error: std::io::Error) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!("failed to register native service {signal_name} handler: {error}"),
    )
    .for_operation("start-native-linux-service")
}
