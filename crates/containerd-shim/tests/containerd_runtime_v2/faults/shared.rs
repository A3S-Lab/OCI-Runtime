use a3s_oci_sdk::{LocalIpcEndpoint, OperationId, ProcessId, RuntimeClient};
use sha2::{Digest, Sha256};

use crate::support::{qualification_error, QualificationConfig, TestResult};

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

pub(super) fn containerd_operation_id(
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
    action: &str,
) -> TestResult<OperationId> {
    operation_id(namespace, task_id, incarnation, Some(exec_id), action)
}

pub(crate) fn containerd_process_id(
    namespace: &str,
    task_id: &str,
    exec_id: &str,
) -> TestResult<ProcessId> {
    ProcessId::new(format!(
        "exec-{}",
        digest_components(&[namespace, task_id, exec_id])
    ))
    .map_err(|error| {
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
    exec_id: Option<&str>,
    action: &str,
) -> TestResult<OperationId> {
    let mut components = vec![namespace, task_id, incarnation];
    if let Some(exec_id) = exec_id {
        components.push(exec_id);
    }
    components.push(action);
    OperationId::new(format!("ctrd-op-{}", digest_components(&components))).map_err(|error| {
        qualification_error(format!(
            "derive stable containerd {action} operation identity: {error}"
        ))
        .into()
    })
}

fn digest_components(components: &[&str]) -> String {
    let mut digest = Sha256::new();
    for component in components {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component.as_bytes());
    }
    format!("{:x}", digest.finalize())
}
