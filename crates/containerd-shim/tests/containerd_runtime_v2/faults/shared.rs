use a3s_oci_sdk::{LocalIpcEndpoint, OperationId, RuntimeClient};
use sha2::{Digest, Sha256};

use crate::support::{qualification_error, QualificationConfig, TestResult};

pub(super) async fn runtime_client(config: &QualificationConfig) -> TestResult<RuntimeClient> {
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
    let mut digest = Sha256::new();
    for component in [namespace, task_id, incarnation, action] {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component.as_bytes());
    }
    OperationId::new(format!("ctrd-op-{:x}", digest.finalize())).map_err(|error| {
        qualification_error(format!(
            "derive stable containerd {action} operation identity: {error}"
        ))
        .into()
    })
}
