use std::path::Path;

use a3s_oci_sdk::{LocalIpcEndpoint, OperationId, ProcessId, RuntimeClient};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::support::{qualification_error, QualificationConfig, TestResult};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShimBootstrap {
    version: u32,
    address: String,
    protocol: String,
}

pub(crate) async fn load_shim_address(bundle: &Path) -> TestResult<String> {
    let bytes = tokio::fs::read(bundle.join("bootstrap.json"))
        .await
        .map_err(|error| qualification_error(format!("read shim bootstrap metadata: {error}")))?;
    let bootstrap: ShimBootstrap = serde_json::from_slice(&bytes)
        .map_err(|error| qualification_error(format!("decode shim bootstrap metadata: {error}")))?;
    if bootstrap.version != 2 || bootstrap.protocol != "ttrpc" {
        return Err(qualification_error(format!(
            "shim bootstrap contract was version={} protocol={:?}; expected version 2 ttrpc",
            bootstrap.version, bootstrap.protocol
        ))
        .into());
    }
    let socket = bootstrap
        .address
        .strip_prefix("unix://")
        .ok_or_else(|| qualification_error("shim bootstrap address is not a unix:// URI"))?;
    if !Path::new(socket).is_absolute() {
        return Err(qualification_error("shim bootstrap socket path is not absolute").into());
    }
    Ok(bootstrap.address)
}

pub(crate) async fn runtime_client(config: &QualificationConfig) -> TestResult<RuntimeClient> {
    let endpoint =
        LocalIpcEndpoint::unix_socket(config.runtime_endpoint.clone()).map_err(|error| {
            qualification_error(format!(
                "validate A3S OCI runtime endpoint {}: {error}",
                config.runtime_endpoint.display()
            ))
        })?;
    RuntimeClient::connect(&endpoint).await.map_err(|error| {
        qualification_error(format!(
            "connect A3S OCI runtime endpoint {}: {error}",
            config.runtime_endpoint.display()
        ))
        .into()
    })
}

pub(crate) fn containerd_operation_id(
    namespace: &str,
    task_id: &str,
    incarnation: &str,
    action: &str,
) -> TestResult<OperationId> {
    operation_id(namespace, task_id, incarnation, None, action)
}

pub(crate) fn containerd_exec_operation_id(
    namespace: &str,
    task_id: &str,
    incarnation: &str,
    exec_id: &str,
    exec_incarnation: u64,
    action: &str,
) -> TestResult<OperationId> {
    operation_id(
        namespace,
        task_id,
        incarnation,
        Some((exec_id, exec_incarnation)),
        action,
    )
}

pub(crate) fn containerd_process_id(
    namespace: &str,
    task_id: &str,
    exec_id: &str,
    exec_incarnation: u64,
) -> TestResult<ProcessId> {
    let incarnation = exec_incarnation.to_be_bytes();
    let mut components = vec![namespace.as_bytes(), task_id.as_bytes(), exec_id.as_bytes()];
    if exec_incarnation != 0 {
        components.push(&incarnation);
    }
    ProcessId::new(format!("exec-{}", digest_components(&components))).map_err(|error| {
        qualification_error(format!(
            "derive stable containerd process identity for {exec_id}: {error}"
        ))
        .into()
    })
}

fn operation_id(
    namespace: &str,
    task_id: &str,
    incarnation: &str,
    exec: Option<(&str, u64)>,
    action: &str,
) -> TestResult<OperationId> {
    let exec_incarnation = exec.map_or(0, |(_, incarnation)| incarnation).to_be_bytes();
    let mut components = vec![
        namespace.as_bytes(),
        task_id.as_bytes(),
        incarnation.as_bytes(),
    ];
    if let Some((exec_id, incarnation)) = exec {
        components.push(exec_id.as_bytes());
        if incarnation != 0 {
            components.push(&exec_incarnation);
        }
    }
    components.push(action.as_bytes());
    OperationId::new(format!("ctrd-op-{}", digest_components(&components))).map_err(|error| {
        qualification_error(format!(
            "derive stable containerd {action} operation identity: {error}"
        ))
        .into()
    })
}

fn digest_components(components: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    for component in components {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component);
    }
    format!("{:x}", digest.finalize())
}
