use std::time::Duration;

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use a3s_oci_agent_protocol::AgentClient;
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
use a3s_oci_sdk::RuntimeClient;
use a3s_oci_sdk::{
    async_trait, ContainerTarget, ErrorCode, FileOp, FileRequest, FileResponse, FilesystemEntry,
    FilesystemEntryKind, FilesystemOp, FilesystemRequest, FilesystemResponse, OperationContext,
    OperationId, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const PAYLOAD: &[u8] = b"a3s-oci-filesystem-smoke\0\xff\x80\n";

#[async_trait]
trait FilesystemSmokeClient: Sync {
    async fn file(&self, request: FileRequest) -> Result<FileResponse>;

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse>;
}

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
#[async_trait]
impl FilesystemSmokeClient for RuntimeClient {
    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        RuntimeClient::file(self, request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        RuntimeClient::filesystem(self, request).await
    }
}

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
#[async_trait]
impl<T> FilesystemSmokeClient for AgentClient<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn file(&self, request: FileRequest) -> Result<FileResponse> {
        AgentClient::file(self, request).await
    }

    async fn filesystem(&self, request: FilesystemRequest) -> Result<FilesystemResponse> {
        AgentClient::filesystem(self, request).await
    }
}

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) async fn exercise_runtime(
    client: &RuntimeClient,
    target: &ContainerTarget,
    nonce: &str,
) -> std::result::Result<(), String> {
    exercise(client, target, nonce).await
}

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
pub(crate) async fn exercise_agent<T>(
    client: &AgentClient<T>,
    target: &ContainerTarget,
    nonce: &str,
) -> std::result::Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    exercise(client, target, nonce).await
}

async fn exercise(
    client: &impl FilesystemSmokeClient,
    target: &ContainerTarget,
    nonce: &str,
) -> std::result::Result<(), String> {
    let directory = format!("/tmp/.a3s-oci-filesystem-{nonce}");
    let source = format!("{directory}/source.bin");
    let moved = format!("{directory}/moved.bin");
    let conflict = format!("{directory}/conflict.bin");

    require_filesystem_error(
        client,
        "preflight filesystem smoke directory",
        FilesystemRequest {
            target: target.clone(),
            op: FilesystemOp::Stat,
            path: directory.clone(),
            destination: None,
            depth: 0,
            user: None,
            context: None,
        },
        ErrorCode::NotFound,
    )
    .await?;

    let result = exercise_created_directory(
        client, target, nonce, &directory, &source, &moved, &conflict,
    )
    .await;
    if let Err(reason) = result {
        let cleanup = filesystem(
            client,
            "emergency filesystem smoke cleanup",
            FilesystemRequest {
                target: target.clone(),
                op: FilesystemOp::Remove,
                path: directory,
                destination: None,
                depth: 0,
                user: None,
                context: Some(operation(nonce, "emergency-remove")?),
            },
        )
        .await;
        return Err(match cleanup {
            Ok(_) => reason,
            Err(cleanup) => format!("{reason}; {cleanup}"),
        });
    }
    Ok(())
}

async fn exercise_created_directory(
    client: &impl FilesystemSmokeClient,
    target: &ContainerTarget,
    nonce: &str,
    directory: &str,
    source: &str,
    moved: &str,
    conflict: &str,
) -> std::result::Result<(), String> {
    let make_directory = FilesystemRequest {
        target: target.clone(),
        op: FilesystemOp::MakeDir,
        path: directory.to_string(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(operation(nonce, "make-directory")?),
    };
    let made = filesystem(
        client,
        "make filesystem smoke directory",
        make_directory.clone(),
    )
    .await?;
    require_entry(
        &made,
        target,
        directory,
        FilesystemEntryKind::Directory,
        None,
    )?;
    let replayed = filesystem(
        client,
        "replay filesystem smoke directory creation",
        make_directory,
    )
    .await?;
    if replayed != made {
        return Err("filesystem directory creation did not replay exactly".into());
    }

    let encoded = STANDARD.encode(PAYLOAD);
    let upload_context = operation(nonce, "upload")?;
    let upload = FileRequest {
        target: target.clone(),
        op: FileOp::Upload,
        path: source.to_string(),
        data: Some(encoded.clone()),
        user: None,
        context: Some(upload_context.clone()),
    };
    let uploaded = file(client, "upload filesystem smoke payload", upload.clone()).await?;
    require_upload(&uploaded, target)?;
    let replayed = file(client, "replay filesystem smoke upload", upload).await?;
    if replayed != uploaded {
        return Err("file upload did not replay exactly".into());
    }

    require_file_error(
        client,
        "reuse upload operation for a changed request",
        FileRequest {
            target: target.clone(),
            op: FileOp::Upload,
            path: conflict.to_string(),
            data: Some(STANDARD.encode(b"conflicting-payload")),
            user: None,
            context: Some(upload_context),
        },
        ErrorCode::Conflict,
    )
    .await?;
    require_filesystem_error(
        client,
        "inspect rejected upload destination",
        stat(target, conflict),
        ErrorCode::NotFound,
    )
    .await?;

    let downloaded = file(
        client,
        "download filesystem smoke payload",
        FileRequest {
            target: target.clone(),
            op: FileOp::Download,
            path: source.to_string(),
            data: None,
            user: None,
            context: None,
        },
    )
    .await?;
    require_download(&downloaded, target, &encoded)?;

    let stated = filesystem(
        client,
        "stat filesystem smoke payload",
        stat(target, source),
    )
    .await?;
    let source_entry = require_entry(
        &stated,
        target,
        source,
        FilesystemEntryKind::File,
        Some(PAYLOAD.len()),
    )?;
    let listed = filesystem(
        client,
        "list filesystem smoke directory",
        FilesystemRequest {
            target: target.clone(),
            op: FilesystemOp::ListDir,
            path: directory.to_string(),
            destination: None,
            depth: 1,
            user: None,
            context: None,
        },
    )
    .await?;
    if listed.target != *target
        || listed.entry.is_some()
        || listed.entries.len() != 1
        || !same_entry(&listed.entries[0], source_entry)
    {
        return Err("filesystem directory listing did not contain only the exact upload".into());
    }

    let move_request = FilesystemRequest {
        target: target.clone(),
        op: FilesystemOp::Move,
        path: source.to_string(),
        destination: Some(moved.to_string()),
        depth: 0,
        user: None,
        context: Some(operation(nonce, "move")?),
    };
    let moved_response = filesystem(
        client,
        "move filesystem smoke payload",
        move_request.clone(),
    )
    .await?;
    require_entry(
        &moved_response,
        target,
        moved,
        FilesystemEntryKind::File,
        Some(PAYLOAD.len()),
    )?;
    let replayed = filesystem(client, "replay filesystem smoke move", move_request).await?;
    if replayed != moved_response {
        return Err("filesystem move did not replay exactly".into());
    }
    require_filesystem_error(
        client,
        "stat moved filesystem smoke source",
        stat(target, source),
        ErrorCode::NotFound,
    )
    .await?;
    let stated = filesystem(
        client,
        "stat moved filesystem smoke payload",
        stat(target, moved),
    )
    .await?;
    require_entry(
        &stated,
        target,
        moved,
        FilesystemEntryKind::File,
        Some(PAYLOAD.len()),
    )?;

    let remove_request = FilesystemRequest {
        target: target.clone(),
        op: FilesystemOp::Remove,
        path: directory.to_string(),
        destination: None,
        depth: 0,
        user: None,
        context: Some(operation(nonce, "remove")?),
    };
    let removed = filesystem(
        client,
        "remove filesystem smoke directory recursively",
        remove_request.clone(),
    )
    .await?;
    require_empty_response(&removed, target)?;
    let replayed = filesystem(client, "replay filesystem smoke removal", remove_request).await?;
    if replayed != removed {
        return Err("filesystem removal did not replay exactly".into());
    }
    require_filesystem_error(
        client,
        "stat removed filesystem smoke directory",
        stat(target, directory),
        ErrorCode::NotFound,
    )
    .await
}

fn stat(target: &ContainerTarget, path: &str) -> FilesystemRequest {
    FilesystemRequest {
        target: target.clone(),
        op: FilesystemOp::Stat,
        path: path.to_string(),
        destination: None,
        depth: 0,
        user: None,
        context: None,
    }
}

fn require_upload(
    response: &FileResponse,
    target: &ContainerTarget,
) -> std::result::Result<(), String> {
    if response.target != *target
        || response.data.is_some()
        || response.size != PAYLOAD.len() as u64
    {
        return Err("filesystem smoke upload returned an invalid acknowledgement".into());
    }
    Ok(())
}

fn require_download(
    response: &FileResponse,
    target: &ContainerTarget,
    encoded: &str,
) -> std::result::Result<(), String> {
    if response.target != *target
        || response.size != PAYLOAD.len() as u64
        || response.data.as_deref() != Some(encoded)
    {
        return Err("filesystem smoke download did not preserve the exact binary payload".into());
    }
    Ok(())
}

fn require_entry<'a>(
    response: &'a FilesystemResponse,
    target: &ContainerTarget,
    path: &str,
    kind: FilesystemEntryKind,
    size: Option<usize>,
) -> std::result::Result<&'a FilesystemEntry, String> {
    let entry = response
        .entry
        .as_ref()
        .ok_or_else(|| format!("filesystem response omitted the entry for {path}"))?;
    let expected_name = path.rsplit('/').next().unwrap_or(path);
    if response.target != *target
        || !response.entries.is_empty()
        || entry.path != path
        || entry.name != expected_name
        || entry.kind != kind
        || size.is_some_and(|size| entry.size != size as i64)
    {
        return Err(format!(
            "filesystem response returned invalid metadata for {path}"
        ));
    }
    Ok(entry)
}

fn same_entry(left: &FilesystemEntry, right: &FilesystemEntry) -> bool {
    left.name == right.name
        && left.kind == right.kind
        && left.path == right.path
        && left.size == right.size
        && left.mode == right.mode
        && left.permissions == right.permissions
        && left.owner == right.owner
        && left.group == right.group
        && left.symlink_target == right.symlink_target
}

fn require_empty_response(
    response: &FilesystemResponse,
    target: &ContainerTarget,
) -> std::result::Result<(), String> {
    if response.target != *target || response.entry.is_some() || !response.entries.is_empty() {
        return Err("filesystem removal returned an invalid acknowledgement".into());
    }
    Ok(())
}

async fn file(
    client: &impl FilesystemSmokeClient,
    label: &str,
    request: FileRequest,
) -> std::result::Result<FileResponse, String> {
    match file_result(client, label, request).await? {
        Ok(response) => Ok(response),
        Err(error) => Err(format!("{label} failed: {error}")),
    }
}

async fn filesystem(
    client: &impl FilesystemSmokeClient,
    label: &str,
    request: FilesystemRequest,
) -> std::result::Result<FilesystemResponse, String> {
    match filesystem_result(client, label, request).await? {
        Ok(response) => Ok(response),
        Err(error) => Err(format!("{label} failed: {error}")),
    }
}

async fn require_file_error(
    client: &impl FilesystemSmokeClient,
    label: &str,
    request: FileRequest,
    expected: ErrorCode,
) -> std::result::Result<(), String> {
    match file_result(client, label, request).await? {
        Err(error) if error.code == expected => Ok(()),
        Err(error) => Err(format!(
            "{label} returned {:?}, expected {expected:?}: {error}",
            error.code
        )),
        Ok(_) => Err(format!("{label} unexpectedly succeeded")),
    }
}

async fn require_filesystem_error(
    client: &impl FilesystemSmokeClient,
    label: &str,
    request: FilesystemRequest,
    expected: ErrorCode,
) -> std::result::Result<(), String> {
    match filesystem_result(client, label, request).await? {
        Err(error) if error.code == expected => Ok(()),
        Err(error) => Err(format!(
            "{label} returned {:?}, expected {expected:?}: {error}",
            error.code
        )),
        Ok(_) => Err(format!("{label} unexpectedly succeeded")),
    }
}

async fn file_result(
    client: &impl FilesystemSmokeClient,
    label: &str,
    request: FileRequest,
) -> std::result::Result<Result<FileResponse>, String> {
    timeout(CALL_TIMEOUT, client.file(request))
        .await
        .map_err(|_| format!("{label} exceeded {CALL_TIMEOUT:?}"))
}

async fn filesystem_result(
    client: &impl FilesystemSmokeClient,
    label: &str,
    request: FilesystemRequest,
) -> std::result::Result<Result<FilesystemResponse>, String> {
    timeout(CALL_TIMEOUT, client.filesystem(request))
        .await
        .map_err(|_| format!("{label} exceeded {CALL_TIMEOUT:?}"))
}

fn operation(nonce: &str, name: &str) -> std::result::Result<OperationContext, String> {
    OperationId::new(format!("filesystem-{nonce}-{name}"))
        .map(OperationContext::new)
        .map_err(|error| format!("failed to construct filesystem smoke operation ID: {error}"))
}
