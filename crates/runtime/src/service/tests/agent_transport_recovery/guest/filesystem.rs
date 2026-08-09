use std::collections::BTreeMap;

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    Error, ErrorCode, FileOp, FileRequest, FileResponse, FilesystemEntry, FilesystemEntryKind,
    FilesystemOp, FilesystemRequest, FilesystemResponse, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::super::guest_journal::changed_request;
use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(super) fn transfer_file(&self, request: FileRequest) -> Result<FileResponse> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.file.requests += 1;
        if request.op != FileOp::Upload {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "reopen test guest supports only journaled file uploads",
            )
            .for_operation("agent-file"));
        }
        let operation_id = request
            .context
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest file upload requires an operation context",
                )
                .for_operation("agent-file")
            })?
            .operation_id
            .clone();
        if let Some((recorded, response)) = journal.file.entry.as_ref() {
            let recorded_operation_id = &recorded
                .context
                .as_ref()
                .expect("recorded file upload context")
                .operation_id;
            if recorded_operation_id == &operation_id {
                if recorded != &request {
                    return Err(changed_request("file"));
                }
                return Ok(response.clone());
            }
        }

        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-file")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-file"));
        }
        if !matches!(
            current.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest file upload requires a live container filesystem",
            )
            .for_operation("agent-file"));
        }
        if journal.file.entry.is_some() {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "the test guest already has a file upload journal",
            )
            .for_operation("agent-file"));
        }
        let size = request
            .data
            .as_deref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest file upload requires data",
                )
                .for_operation("agent-file")
            })
            .and_then(|data| {
                STANDARD.decode(data).map_err(|error| {
                    Error::new(
                        ErrorCode::InvalidArgument,
                        format!("guest file upload data is not valid base64: {error}"),
                    )
                    .for_operation("agent-file")
                })
            })?
            .len() as u64;
        let response = FileResponse {
            target: request.target.clone(),
            data: None,
            size,
        };
        journal.file.effects += 1;
        journal.file.entry = Some((request, response.clone()));
        Ok(response)
    }

    pub(in super::super) fn recorded_file_request(&self) -> Option<FileRequest> {
        self.journal
            .lock()
            .expect("guest journal lock")
            .file
            .entry
            .as_ref()
            .map(|(request, _)| request.clone())
    }

    pub(super) fn mutate_filesystem(
        &self,
        request: FilesystemRequest,
    ) -> Result<FilesystemResponse> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.filesystem.requests += 1;
        if request.op != FilesystemOp::MakeDir {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "reopen test guest supports only journaled mkdir operations",
            )
            .for_operation("agent-filesystem"));
        }
        let operation_id = request
            .context
            .as_ref()
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    "guest mkdir requires an operation context",
                )
                .for_operation("agent-filesystem")
            })?
            .operation_id
            .clone();
        if let Some((recorded, response)) = journal.filesystem.entry.as_ref() {
            let recorded_operation_id = &recorded
                .context
                .as_ref()
                .expect("recorded filesystem context")
                .operation_id;
            if recorded_operation_id == &operation_id {
                if recorded != &request {
                    return Err(changed_request("filesystem"));
                }
                return Ok(response.clone());
            }
        }

        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-filesystem")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-filesystem"));
        }
        if !matches!(
            current.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest mkdir requires a live container filesystem",
            )
            .for_operation("agent-filesystem"));
        }
        if journal.filesystem.entry.is_some() {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                "the test guest already has a filesystem mutation journal",
            )
            .for_operation("agent-filesystem"));
        }

        let entry = FilesystemEntry {
            name: "reopen-dir".to_string(),
            kind: FilesystemEntryKind::Directory,
            path: request.path.clone(),
            size: 0,
            mode: 0o755,
            permissions: "drwxr-xr-x".to_string(),
            owner: "1000".to_string(),
            group: "1000".to_string(),
            modified_seconds: 0,
            modified_nanos: 0,
            symlink_target: None,
            metadata: BTreeMap::new(),
        };
        let response = FilesystemResponse {
            target: request.target.clone(),
            entry: Some(entry),
            entries: Vec::new(),
        };
        journal.filesystem.effects += 1;
        journal.filesystem.entry = Some((request, response.clone()));
        Ok(response)
    }

    pub(in super::super) fn recorded_filesystem_request(&self) -> Option<FilesystemRequest> {
        self.journal
            .lock()
            .expect("guest journal lock")
            .filesystem
            .entry
            .as_ref()
            .map(|(request, _)| request.clone())
    }
}
