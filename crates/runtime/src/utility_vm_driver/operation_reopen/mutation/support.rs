use std::path::Path;

use a3s_oci_sdk::{
    ContainerTarget, FileRequest, FileResponse, FilesystemRequest, FilesystemResponse, Generation,
    OciRuntimeService, OperationContext, OperationId,
};

use super::super::driver::QualificationKvmOperationDriver;
use super::super::mutation_support::{
    changed_upload_data, directory_response_matches, download_response_matches,
    file_mutation_journal_status, filesystem_mutation_journal_status, upload_response_matches,
    FileMutationJournalStatus, FilesystemMutationJournalStatus,
};
use super::{FirstOwnerOutcome, Mutation, MutationIdentity};
use crate::{HostRuntimeService, OciVmOperationReopenReplacementReport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MutationResponse {
    File(FileResponse),
    Filesystem(Box<FilesystemResponse>),
}

impl MutationResponse {
    fn target(&self) -> &ContainerTarget {
        match self {
            Self::File(response) => &response.target,
            Self::Filesystem(response) => &response.target,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MutationJournalStatus {
    Prepared,
    Succeeded(MutationResponse),
}

pub(super) async fn dispatch_host_mutation(
    service: &HostRuntimeService,
    mutation: &Mutation,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => service
            .file(request.clone())
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => service
            .filesystem(request.clone())
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

pub(super) async fn mutation_journal_status(
    state_root: &Path,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> Result<MutationJournalStatus, String> {
    match mutation {
        Mutation::File { request, .. } => {
            match file_mutation_journal_status(state_root, request, target).await? {
                FileMutationJournalStatus::Prepared => Ok(MutationJournalStatus::Prepared),
                FileMutationJournalStatus::Succeeded(response) => Ok(
                    MutationJournalStatus::Succeeded(MutationResponse::File(response)),
                ),
            }
        }
        Mutation::Filesystem { request, .. } => {
            match filesystem_mutation_journal_status(state_root, request, target).await? {
                FilesystemMutationJournalStatus::Prepared => Ok(MutationJournalStatus::Prepared),
                FilesystemMutationJournalStatus::Succeeded(response) => Ok(
                    MutationJournalStatus::Succeeded(MutationResponse::Filesystem(response)),
                ),
            }
        }
    }
}

pub(super) fn response_matches(
    response: &MutationResponse,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> bool {
    match (response, mutation) {
        (
            MutationResponse::File(response),
            Mutation::File {
                expected_payload, ..
            },
        ) => upload_response_matches(response, target, expected_payload.len()),
        (MutationResponse::Filesystem(response), Mutation::Filesystem { request, .. }) => {
            directory_response_matches(response, target, &request.path)
        }
        _ => false,
    }
}

pub(super) fn effect_matches(
    response: &MutationResponse,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> bool {
    match (response, mutation) {
        (
            MutationResponse::File(response),
            Mutation::File {
                request,
                expected_payload,
                ..
            },
        ) => request.data.as_deref().is_some_and(|encoded| {
            download_response_matches(response, target, encoded, expected_payload.len())
        }),
        (MutationResponse::Filesystem(response), Mutation::Filesystem { request, .. }) => {
            directory_response_matches(response, target, &request.path)
        }
        _ => false,
    }
}

pub(super) fn response_generation(response: &MutationResponse) -> Option<Generation> {
    response.target().generation
}

pub(super) fn mutation_calls(driver: &QualificationKvmOperationDriver, mutation: &Mutation) -> u32 {
    match mutation {
        Mutation::File { .. } => driver.file_calls(),
        Mutation::Filesystem { .. } => driver.filesystem_calls(),
    }
}

pub(super) fn driver_mutation_identity(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
) -> Result<MutationIdentity, String> {
    match mutation {
        Mutation::File { .. } => driver.file_identity().map(MutationIdentity::File),
        Mutation::Filesystem { .. } => driver
            .filesystem_identity()
            .map(MutationIdentity::Filesystem),
    }
}

pub(super) fn mutation_identity_operation_id(identity: &MutationIdentity) -> Option<&OperationId> {
    match identity {
        MutationIdentity::File(request) => request.context.as_ref(),
        MutationIdentity::Filesystem(request) => request.context.as_ref(),
    }
    .map(|context| &context.operation_id)
}

pub(super) fn mutation_identity_target(identity: &MutationIdentity) -> &ContainerTarget {
    match identity {
        MutationIdentity::File(request) => &request.target,
        MutationIdentity::Filesystem(request) => &request.target,
    }
}

pub(super) fn capture_recovery(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    report: &mut OciVmOperationReopenReplacementReport,
) {
    report.replacement_recovery_calls = driver.recovery_calls();
    report.replacement_rehydrated_created_record = driver.rehydrated_created_record();
    report.replacement_rehydrated_running_record = driver.rehydrated_running_record();
    report.replacement_rehydrated_stopped_record = driver.rehydrated_stopped_record();
    report.replacement_rehydrated_exec_record = driver.rehydrated_exec_record();
    match mutation {
        Mutation::File { .. } => report.replacement_rehydrated_file = driver.rehydrated_file(),
        Mutation::Filesystem { .. } => {
            report.replacement_rehydrated_filesystem = driver.rehydrated_filesystem();
        }
    }
    report.replacement_created_pid = driver.rehydrated_running_pid();
    report.replacement_exec_pid = driver
        .rehydrated_exec_pid()
        .and_then(|pid| u32::try_from(pid).ok());
}

pub(super) async fn direct_effect_query(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { download, .. } => driver
            .guest_file(FileRequest {
                target: target.clone(),
                ..download.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { stat, .. } => driver
            .guest_filesystem(FilesystemRequest {
                target: target.clone(),
                ..stat.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

pub(super) async fn direct_effect_cleanup(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    target: &ContainerTarget,
) -> a3s_oci_sdk::Result<FilesystemResponse> {
    let cleanup = match mutation {
        Mutation::File { cleanup, .. } | Mutation::Filesystem { cleanup, .. } => {
            FilesystemRequest {
                target: target.clone(),
                ..cleanup.clone()
            }
        }
    };
    driver.guest_filesystem(cleanup).await
}

pub(super) async fn dispatch_changed_host_mutation(
    service: &HostRuntimeService,
    mutation: &Mutation,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => service
            .file(FileRequest {
                data: Some(changed_upload_data()),
                ..request.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => service
            .filesystem(FilesystemRequest {
                path: format!("{}-changed", request.path),
                ..request.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

pub(super) async fn dispatch_stale_guest_mutation(
    driver: &QualificationKvmOperationDriver,
    mutation: &Mutation,
    target: ContainerTarget,
    operation_id: OperationId,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => driver
            .guest_file(FileRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => driver
            .guest_filesystem(FilesystemRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

pub(super) async fn dispatch_stale_host_mutation(
    service: &HostRuntimeService,
    mutation: &Mutation,
    target: ContainerTarget,
    operation_id: OperationId,
) -> a3s_oci_sdk::Result<MutationResponse> {
    match mutation {
        Mutation::File { request, .. } => service
            .file(FileRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(MutationResponse::File),
        Mutation::Filesystem { request, .. } => service
            .filesystem(FilesystemRequest {
                target,
                context: Some(OperationContext::new(operation_id)),
                ..request.clone()
            })
            .await
            .map(|response| MutationResponse::Filesystem(Box::new(response))),
    }
}

pub(super) fn set_replacement_response_verified(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    verified: bool,
) {
    match mutation {
        Mutation::File { .. } => report.replacement_file_response_verified = verified,
        Mutation::Filesystem { .. } => report.replacement_filesystem_response_verified = verified,
    }
}

pub(super) fn set_response_replayed(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    replayed: bool,
) {
    match mutation {
        Mutation::File { .. } => report.file_response_replayed = replayed,
        Mutation::Filesystem { .. } => report.filesystem_response_replayed = replayed,
    }
}

pub(super) fn set_request_identity_reused(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    reused: bool,
) {
    match mutation {
        Mutation::File { .. } => report.file_request_identity_reused = reused,
        Mutation::Filesystem { .. } => report.filesystem_request_identity_reused = reused,
    }
}

pub(super) fn set_effect_verified(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    verified: bool,
) {
    match mutation {
        Mutation::File { .. } => report.replacement_file_effect_verified = verified,
        Mutation::Filesystem { .. } => report.replacement_filesystem_effect_verified = verified,
    }
}

pub(super) fn set_effect_absent(
    report: &mut OciVmOperationReopenReplacementReport,
    mutation: &Mutation,
    absent: bool,
) {
    match mutation {
        Mutation::File { .. } => report.file_effect_absent_after_cleanup = absent,
        Mutation::Filesystem { .. } => report.filesystem_effect_absent_after_cleanup = absent,
    }
}

pub(super) async fn setup_failure(
    driver: &QualificationKvmOperationDriver,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    let cleanup = match driver.create_identity() {
        Ok((_, target)) => driver.cleanup(&target).await,
        Err(_) => Ok(()),
    };
    match cleanup {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}

pub(super) async fn active_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    report: &mut OciVmOperationReopenReplacementReport,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    report.first_vm = driver.shutdown().await;
    cleanup_failure(driver, target, reason).await
}

pub(super) async fn cleanup_failure(
    driver: &QualificationKvmOperationDriver,
    target: &ContainerTarget,
    reason: String,
) -> Result<FirstOwnerOutcome, String> {
    match driver.cleanup(target).await {
        Ok(()) => Err(reason),
        Err(cleanup) => Err(format!("{reason}; {cleanup}")),
    }
}
