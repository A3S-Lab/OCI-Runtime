use std::future::Future;
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, DriverKind, DriverReadiness};
use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, FileOp, FileRequest, OperationContext, OperationId,
    RuntimeClient,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio::time::{sleep, timeout, Instant};

use super::host;
use super::report::LinuxProcessIdentity;

const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MARKER_PATH: &str = "/.a3s-oci-create-start-smoke";
const MARKER_CONTENTS: &[u8] = b"a3s-oci-create-start-user-time-v1\n";

pub(super) async fn verify_qualification_scope(
    client: &RuntimeClient,
    expected_scope: &str,
) -> Result<(), String> {
    let features = call("KVM qualification features", client.features()).await?;
    let launchable = features
        .drivers
        .drivers
        .iter()
        .filter(|capability| capability.can_launch())
        .collect::<Vec<_>>();
    if launchable.len() != 1 {
        return Err(format!(
            "KVM qualification Host Service advertised {} launchable drivers, expected one",
            launchable.len()
        ));
    }
    let capability = launchable[0];
    if capability.driver != DriverKind::LibkrunKvm
        || capability.status != CapabilityStatus::Available
        || capability.readiness != DriverReadiness::Experimental
        || capability
            .evidence
            .get("qualification_scope")
            .map(String::as_str)
            != Some(expected_scope)
    {
        return Err("KVM qualification Host Service did not retain its narrow scope".to_string());
    }
    Ok(())
}

pub(super) async fn wait_for_marker(
    client: &RuntimeClient,
    target: &ContainerTarget,
) -> Result<(), String> {
    let deadline = Instant::now() + QUALIFICATION_TIMEOUT;
    loop {
        match client
            .file(FileRequest {
                target: target.clone(),
                op: FileOp::Download,
                path: MARKER_PATH.to_string(),
                data: None,
                user: None,
                context: None,
            })
            .await
        {
            Ok(response) => {
                let decoded = response
                    .data
                    .as_deref()
                    .map(|value| STANDARD.decode(value))
                    .transpose()
                    .map_err(|error| format!("KVM marker was not base64: {error}"))?;
                return if decoded.as_deref() == Some(MARKER_CONTENTS) {
                    Ok(())
                } else {
                    Err("KVM marker contents were unexpected".to_string())
                };
            }
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(call_error("read KVM marker", &error)),
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for KVM init marker".to_string());
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub(super) async fn wait_for_vm_descendants(
    host_pid: u32,
) -> Result<Vec<LinuxProcessIdentity>, String> {
    let deadline = Instant::now() + QUALIFICATION_TIMEOUT;
    loop {
        let processes = host::process_descendants(host_pid)?;
        if processes.len() >= 2 {
            return Ok(processes);
        }
        if Instant::now() >= deadline {
            return Err("Host Service did not expose KVM shim and worker descendants".to_string());
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub(super) fn operation(
    prefix: &str,
    nonce: &str,
    suffix: &str,
) -> Result<OperationContext, String> {
    OperationId::new(format!("{prefix}-{nonce}-{suffix}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct KVM qualification operation ID: {error}"))
}

pub(super) async fn call<T>(
    label: &str,
    future: impl Future<Output = a3s_oci_sdk::Result<T>>,
) -> Result<T, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(call_error(label, &error)),
        Err(_) => Err(format!("{label} timed out")),
    }
}

pub(super) fn call_error(label: &str, error: &Error) -> String {
    format!("{label} failed with {:?}: {}", error.code, error.message)
}
