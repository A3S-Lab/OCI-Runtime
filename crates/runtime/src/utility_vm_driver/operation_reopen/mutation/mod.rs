use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{AgentOperation, AgentTransportOperationStage};
use a3s_oci_sdk::{
    ContainerTarget, CreateRequest, FileRequest, FilesystemRequest, OperationId, StartRequest,
};

use crate::utility_vm_driver::layout::PreparedUtilityVmLayout;
use crate::OciVmOperationReopenReplacementReport;

mod first_owner;
mod replacement;
mod support;

#[derive(Debug, Clone)]
pub(super) enum Mutation {
    File {
        request: FileRequest,
        download: FileRequest,
        cleanup: FilesystemRequest,
        expected_payload: Vec<u8>,
    },
    Filesystem {
        request: FilesystemRequest,
        stat: FilesystemRequest,
        cleanup: FilesystemRequest,
    },
}

impl Mutation {
    fn agent_operation(&self) -> AgentOperation {
        match self {
            Self::File { .. } => AgentOperation::File,
            Self::Filesystem { .. } => AgentOperation::Filesystem,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::File { .. } => "File",
            Self::Filesystem { .. } => "Filesystem",
        }
    }

    fn operation_id(&self) -> Result<&OperationId, String> {
        let context = match self {
            Self::File { request, .. } => request.context.as_ref(),
            Self::Filesystem { request, .. } => request.context.as_ref(),
        };
        context.map(|context| &context.operation_id).ok_or_else(|| {
            format!(
                "KVM {} qualification has no operation context",
                self.label()
            )
        })
    }

    fn exact_identity(&self, target: &ContainerTarget) -> MutationIdentity {
        match self {
            Self::File { request, .. } => MutationIdentity::File(FileRequest {
                target: target.clone(),
                ..request.clone()
            }),
            Self::Filesystem { request, .. } => MutationIdentity::Filesystem(FilesystemRequest {
                target: target.clone(),
                ..request.clone()
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MutationIdentity {
    File(FileRequest),
    Filesystem(FilesystemRequest),
}

#[derive(Debug, Clone)]
pub(super) struct Qualification {
    pub(super) create: CreateRequest,
    pub(super) start_operation_id: OperationId,
    pub(super) delete_operation_id: OperationId,
    pub(super) stale_guest_operation_id: OperationId,
    pub(super) stale_host_operation_id: OperationId,
    pub(super) mutation: Mutation,
    pub(super) init_marker_contents: Vec<u8>,
    pub(super) stage: AgentTransportOperationStage,
}

struct FirstOwnerOutcome {
    target: ContainerTarget,
    mount_root: PathBuf,
    init_marker: PathBuf,
    create_identity: (OperationId, ContainerTarget),
    start_identity: (OperationId, ContainerTarget),
    mutation_identity: MutationIdentity,
    start: StartRequest,
    response_delivered: bool,
}

pub(super) async fn exercise(
    prepared: &PreparedUtilityVmLayout,
    state_root: &Path,
    first_console: &Path,
    replacement_console: &Path,
    qualification: &Qualification,
    report: &mut OciVmOperationReopenReplacementReport,
) -> Result<(), String> {
    let first =
        first_owner::run(prepared, state_root, first_console, qualification, report).await?;
    replacement::run(
        prepared,
        state_root,
        replacement_console,
        qualification,
        first,
        report,
    )
    .await
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, FileOp, FileRequest, FilesystemOp, FilesystemRequest,
        Generation, OperationContext, OperationId,
    };

    use super::support::{mutation_identity_operation_id, mutation_identity_target};
    use super::{Mutation, MutationIdentity};

    #[test]
    fn exact_mutation_identity_rebinds_only_the_target() {
        let current = ContainerTarget::current(ContainerId::new("test").expect("container ID"));
        let exact = ContainerTarget::exact(
            ContainerId::new("test").expect("container ID"),
            Generation(7),
        );
        let operation_id = OperationId::new("upload").expect("operation ID");
        let mutation = Mutation::File {
            request: FileRequest {
                target: current,
                op: FileOp::Upload,
                path: "/tmp/test".to_string(),
                data: Some("dGVzdA==".to_string()),
                user: None,
                context: Some(OperationContext::new(operation_id.clone())),
            },
            download: FileRequest {
                target: exact.clone(),
                op: FileOp::Download,
                path: "/tmp/test".to_string(),
                data: None,
                user: None,
                context: None,
            },
            cleanup: FilesystemRequest {
                target: exact.clone(),
                op: FilesystemOp::Remove,
                path: "/tmp/test".to_string(),
                destination: None,
                depth: 0,
                user: None,
                context: Some(OperationContext::new(
                    OperationId::new("cleanup").expect("operation ID"),
                )),
            },
            expected_payload: b"test".to_vec(),
        };
        let identity = mutation.exact_identity(&exact);
        assert_eq!(mutation_identity_target(&identity), &exact);
        assert_eq!(
            mutation_identity_operation_id(&identity),
            Some(&operation_id)
        );
        assert!(matches!(identity, MutationIdentity::File(_)));
    }
}
