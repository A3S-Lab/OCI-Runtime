use a3s_oci_sdk::{ContainerId, OperationContext, OperationId, ProcessId, Result};
use sha2::{Digest, Sha256};

const CONTAINER_PREFIX: &str = "ctrd-";
const PROCESS_PREFIX: &str = "exec-";
const OPERATION_PREFIX: &str = "ctrd-op-";
const INCARNATION_BYTES: usize = 32;
const INCARNATION_HEX_BYTES: usize = INCARNATION_BYTES * 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IncarnationId(String);

impl IncarnationId {
    pub(crate) fn generate() -> Result<Self> {
        let mut bytes = [0_u8; INCARNATION_BYTES];
        getrandom::fill(&mut bytes).map_err(|error| {
            a3s_oci_sdk::Error::new(
                a3s_oci_sdk::ErrorCode::Unavailable,
                format!("failed to generate a containerd task incarnation: {error}"),
            )
            .for_operation("containerd-shim-incarnation")
        })?;
        let mut value = String::with_capacity(INCARNATION_HEX_BYTES);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Ok(Self(value))
    }

    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() != INCARNATION_HEX_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(a3s_oci_sdk::Error::new(
                a3s_oci_sdk::ErrorCode::InvalidArgument,
                "containerd task incarnation must be exactly 64 lowercase hexadecimal bytes",
            )
            .for_operation("containerd-shim-incarnation"));
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn container_id(namespace: &str, task_id: &str) -> Result<ContainerId> {
    ContainerId::new(format!(
        "{CONTAINER_PREFIX}{}",
        digest_components(&[namespace, task_id])
    ))
}

pub(crate) fn process_id(namespace: &str, task_id: &str, exec_id: &str) -> Result<ProcessId> {
    ProcessId::new(format!(
        "{PROCESS_PREFIX}{}",
        digest_components(&[namespace, task_id, exec_id])
    ))
}

pub(crate) fn operation(
    namespace: &str,
    task_id: &str,
    incarnation: Option<&IncarnationId>,
    exec_id: Option<&str>,
    action: &str,
) -> Result<OperationContext> {
    let mut components = vec![namespace, task_id];
    if let Some(incarnation) = incarnation {
        components.push(incarnation.as_str());
    }
    if let Some(exec_id) = exec_id {
        components.push(exec_id);
    }
    components.push(action);
    Ok(OperationContext::new(OperationId::new(format!(
        "{OPERATION_PREFIX}{}",
        digest_components(&components)
    ))?))
}

fn digest_components(components: &[&str]) -> String {
    let mut digest = Sha256::new();
    for component in components {
        digest.update((component.len() as u64).to_be_bytes());
        digest.update(component.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_stable_bounded_and_namespace_scoped() {
        let first = container_id("k8s.io", "task/a").expect("container identity");
        let replay = container_id("k8s.io", "task/a").expect("replayed identity");
        let other_namespace = container_id("moby", "task/a").expect("other namespace");

        assert_eq!(first, replay);
        assert_ne!(first, other_namespace);
        assert!(first.as_str().starts_with(CONTAINER_PREFIX));
        assert!(first.as_str().len() <= 128);
    }

    #[test]
    fn operation_identity_includes_action_and_exec_scope() {
        let incarnation = IncarnationId::new("01".repeat(INCARNATION_BYTES)).expect("incarnation");
        let start = operation("k8s.io", "task", Some(&incarnation), None, "start")
            .expect("start operation");
        let kill = operation("k8s.io", "task", Some(&incarnation), None, "kill-15")
            .expect("kill operation");
        let exec = operation("k8s.io", "task", Some(&incarnation), Some("shell"), "start")
            .expect("exec operation");

        assert_ne!(start.operation_id, kill.operation_id);
        assert_ne!(start.operation_id, exec.operation_id);
        assert_eq!(
            exec.operation_id,
            operation("k8s.io", "task", Some(&incarnation), Some("shell"), "start",)
                .expect("replay")
                .operation_id
        );
    }

    #[test]
    fn separate_task_incarnations_have_separate_operation_identities() {
        let first = IncarnationId::new("01".repeat(INCARNATION_BYTES)).expect("first");
        let second = IncarnationId::new("02".repeat(INCARNATION_BYTES)).expect("second");

        assert_ne!(
            operation("default", "task", Some(&first), None, "create")
                .expect("first operation")
                .operation_id,
            operation("default", "task", Some(&second), None, "create")
                .expect("second operation")
                .operation_id
        );
    }

    #[test]
    fn generated_incarnations_are_valid_and_distinct() {
        let first = IncarnationId::generate().expect("first incarnation");
        let second = IncarnationId::generate().expect("second incarnation");
        assert_eq!(first.as_str().len(), INCARNATION_HEX_BYTES);
        assert_ne!(first, second);
        IncarnationId::new(first.as_str()).expect("generated incarnation validates");
    }

    #[test]
    fn process_identity_does_not_embed_untrusted_path_text() {
        let process = process_id("k8s.io", "../task", "exec/../../x").expect("process ID");
        assert!(process.as_str().starts_with(PROCESS_PREFIX));
        assert!(!process.as_str().contains('/'));
        assert!(!process.as_str().contains(".."));
    }
}
