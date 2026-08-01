use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{
    Error, ErrorCode, FileOp, FileRequest, FileResponse, FilesystemEntry, FilesystemEntryKind,
    FilesystemOp, FilesystemRequest, FilesystemResponse, Result, ValidateRequest,
    MAX_FILESYSTEM_DEPTH, MAX_FILE_TRANSFER_BYTES,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nix::dir::Dir;

use super::namespace::RetainedExecutionContext;
use super::state::{ContainerKey, ContainerRecord, MutationKind, RecordedOutcome, RecordedRequest};
use super::{executor_error, validate_deadline, LinuxExecutor};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;
const MAX_ACCOUNT_FILE_BYTES: u64 = 1024 * 1024;
const MAX_FILESYSTEM_ENTRIES: usize = 4_096;
const MAX_FILESYSTEM_RESPONSE_BYTES: usize = 12 * 1024 * 1024;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

impl LinuxExecutor {
    pub(super) async fn file_recorded(&self, request: FileRequest) -> Result<FileResponse> {
        request.validate()?;
        let mut state = self.state.lock().await;
        if request.op == FileOp::Upload {
            let context = request.context.as_ref().ok_or_else(|| {
                filesystem_error(
                    ErrorCode::InvalidArgument,
                    "file upload requires an operation context",
                )
            })?;
            let operation = RecordedRequest::new(MutationKind::File, &request)?;
            let operation_id = context.operation_id.clone();
            if let Some(result) = state.replay_file(&operation_id, &operation) {
                return result;
            }
            state.reserve_operation(&operation_id)?;
            let result = validate_deadline(context)
                .and_then(|()| container_record(&mut state, &request.target))
                .and_then(|record| file_new(record, &request));
            state.record(
                operation_id,
                operation,
                RecordedOutcome::File(result.clone()),
            );
            result
        } else {
            let record = container_record(&mut state, &request.target)?;
            file_new(record, &request)
        }
    }

    pub(super) async fn filesystem_recorded(
        &self,
        request: FilesystemRequest,
    ) -> Result<FilesystemResponse> {
        request.validate()?;
        let mut state = self.state.lock().await;
        if request.op.is_mutating() {
            let context = request.context.as_ref().ok_or_else(|| {
                filesystem_error(
                    ErrorCode::InvalidArgument,
                    "filesystem mutation requires an operation context",
                )
            })?;
            let operation = RecordedRequest::new(MutationKind::Filesystem, &request)?;
            let operation_id = context.operation_id.clone();
            if let Some(result) = state.replay_filesystem(&operation_id, &operation) {
                return result;
            }
            state.reserve_operation(&operation_id)?;
            let result = validate_deadline(context)
                .and_then(|()| container_record(&mut state, &request.target))
                .and_then(|record| filesystem_new(record, &request));
            state.record(
                operation_id,
                operation,
                RecordedOutcome::Filesystem(result.clone()),
            );
            result
        } else {
            let record = container_record(&mut state, &request.target)?;
            filesystem_new(record, &request)
        }
    }
}

fn container_record<'a>(
    state: &'a mut super::state::ExecutorState,
    target: &a3s_oci_sdk::ContainerTarget,
) -> Result<&'a mut ContainerRecord> {
    let key = ContainerKey::from_target(target)?;
    let record = state.containers.get_mut(&key).ok_or_else(|| {
        filesystem_error(
            ErrorCode::NotFound,
            format!(
                "container {} generation {} does not exist",
                key.id, key.generation
            ),
        )
    })?;
    record.refresh()?;
    if !matches!(
        record.status,
        ContainerState::Created | ContainerState::Running
    ) {
        return Err(filesystem_error(
            ErrorCode::FailedPrecondition,
            format!(
                "container filesystem is unavailable while {}",
                record.status
            ),
        ));
    }
    Ok(record)
}

fn file_new(record: &mut ContainerRecord, request: &FileRequest) -> Result<FileResponse> {
    let view = RootView::new(record.process.execution_context())?;
    let owner = view.resolve_owner(request.user.as_deref())?;
    let path = resolve_path(&request.path, &owner.home)?;
    match request.op {
        FileOp::Upload => upload(&view, &path, &owner, request),
        FileOp::Download => download(&view, &path, request),
    }
}

fn filesystem_new(
    record: &mut ContainerRecord,
    request: &FilesystemRequest,
) -> Result<FilesystemResponse> {
    let view = RootView::new(record.process.execution_context())?;
    let owner = view.resolve_owner(request.user.as_deref())?;
    let path = resolve_path(&request.path, &owner.home)?;
    let (entry, entries) = match request.op {
        FilesystemOp::Stat => (Some(view.entry(&path)?), Vec::new()),
        FilesystemOp::MakeDir => {
            if view.path_exists(&path)? {
                return Err(filesystem_error(
                    ErrorCode::Conflict,
                    format!("path already exists: {}", path.display),
                ));
            }
            view.ensure_directories(&path.relative, owner.ids)?;
            (Some(view.entry(&path)?), Vec::new())
        }
        FilesystemOp::Move => {
            if path.is_root() {
                return Err(filesystem_error(
                    ErrorCode::PermissionDenied,
                    "refusing to move the container root directory",
                ));
            }
            let destination = request.destination.as_deref().ok_or_else(|| {
                filesystem_error(
                    ErrorCode::InvalidArgument,
                    "filesystem move requires a destination",
                )
            })?;
            let destination = resolve_path(destination, &owner.home)?;
            if destination.is_root() {
                return Err(filesystem_error(
                    ErrorCode::PermissionDenied,
                    "refusing to replace the container root directory",
                ));
            }
            view.rename(&path, &destination, owner.ids)?;
            (Some(view.entry(&destination)?), Vec::new())
        }
        FilesystemOp::ListDir => {
            let depth = if request.depth == 0 { 1 } else { request.depth };
            if depth > MAX_FILESYSTEM_DEPTH {
                return Err(filesystem_error(
                    ErrorCode::InvalidArgument,
                    format!("directory depth exceeds {MAX_FILESYSTEM_DEPTH}"),
                ));
            }
            (None, view.list(&path, depth)?)
        }
        FilesystemOp::Remove => {
            if path.is_root() {
                return Err(filesystem_error(
                    ErrorCode::PermissionDenied,
                    "refusing to remove the container root directory",
                ));
            }
            view.remove(&path)?;
            (None, Vec::new())
        }
    };
    Ok(FilesystemResponse {
        target: request.target.clone(),
        entry,
        entries,
    })
}

fn upload(
    view: &RootView<'_>,
    path: &ResolvedPath,
    owner: &ResolvedOwner,
    request: &FileRequest,
) -> Result<FileResponse> {
    let encoded = request.data.as_deref().ok_or_else(|| {
        filesystem_error(
            ErrorCode::InvalidArgument,
            "file upload requires base64 data",
        )
    })?;
    let data = STANDARD.decode(encoded).map_err(|error| {
        filesystem_error(
            ErrorCode::InvalidArgument,
            format!("file upload data is not valid base64: {error}"),
        )
    })?;
    if data.len() > MAX_FILE_TRANSFER_BYTES {
        return Err(filesystem_error(
            ErrorCode::ResourceExhausted,
            format!(
                "file upload is {} bytes; maximum is {MAX_FILE_TRANSFER_BYTES}",
                data.len()
            ),
        ));
    }
    let parent = path.relative.parent().ok_or_else(|| {
        filesystem_error(ErrorCode::InvalidArgument, "file upload path has no parent")
    })?;
    view.ensure_directories(parent, owner.ids)?;
    let mut file = view.open(
        &path.relative,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
        0o644,
    )?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect upload target", &path.display, error))?;
    if metadata.is_dir() {
        return Err(filesystem_error(
            ErrorCode::FailedPrecondition,
            format!("upload target is a directory: {}", path.display),
        ));
    }
    file.write_all(&data)
        .map_err(|error| io_error("write upload target", &path.display, error))?;
    file.sync_data()
        .map_err(|error| io_error("sync upload target", &path.display, error))?;
    if let Some((uid, gid)) = owner.ids {
        let result = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
        if result != 0 {
            return Err(io_error(
                "set upload ownership",
                &path.display,
                io::Error::last_os_error(),
            ));
        }
    }
    Ok(FileResponse {
        target: request.target.clone(),
        data: None,
        size: data.len() as u64,
    })
}

fn download(
    view: &RootView<'_>,
    path: &ResolvedPath,
    request: &FileRequest,
) -> Result<FileResponse> {
    let file = view.open(&path.relative, libc::O_RDONLY | libc::O_CLOEXEC, 0)?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect download target", &path.display, error))?;
    if !metadata.is_file() {
        return Err(filesystem_error(
            ErrorCode::FailedPrecondition,
            format!("download target is not a regular file: {}", path.display),
        ));
    }
    if metadata.len() > MAX_FILE_TRANSFER_BYTES as u64 {
        return Err(filesystem_error(
            ErrorCode::ResourceExhausted,
            format!(
                "download target is {} bytes; maximum is {MAX_FILE_TRANSFER_BYTES}",
                metadata.len()
            ),
        ));
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE_TRANSFER_BYTES as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|error| io_error("read download target", &path.display, error))?;
    if data.len() > MAX_FILE_TRANSFER_BYTES {
        return Err(filesystem_error(
            ErrorCode::ResourceExhausted,
            format!("download target grew beyond {MAX_FILE_TRANSFER_BYTES} bytes"),
        ));
    }
    Ok(FileResponse {
        target: request.target.clone(),
        data: Some(STANDARD.encode(&data)),
        size: data.len() as u64,
    })
}

struct RootView<'a> {
    execution: &'a RetainedExecutionContext,
    accounts: Accounts,
}

impl<'a> RootView<'a> {
    fn new(execution: &'a RetainedExecutionContext) -> Result<Self> {
        Ok(Self {
            execution,
            accounts: Accounts::load(execution.root_descriptor())?,
        })
    }

    fn resolve_owner(&self, selector: Option<&str>) -> Result<ResolvedOwner> {
        let Some(selector) = selector else {
            return Ok(ResolvedOwner {
                home: PathBuf::from("/root"),
                ids: Some((self.execution.host_uid(0)?, self.execution.host_gid(0)?)),
            });
        };
        let (user, group_override) = selector
            .split_once(':')
            .map_or((selector, None), |(user, group)| (user, Some(group)));
        if user.is_empty() || group_override == Some("") {
            return Err(filesystem_error(
                ErrorCode::InvalidArgument,
                format!("invalid file user selector {selector:?}"),
            ));
        }
        let account = user
            .parse::<u32>()
            .ok()
            .and_then(|uid| self.accounts.users.iter().find(|entry| entry.id == uid))
            .or_else(|| self.accounts.users.iter().find(|entry| entry.name == user))
            .cloned()
            .or_else(|| {
                (user == "0" || user == "root").then(|| Account {
                    name: "root".to_string(),
                    id: 0,
                    primary_group: 0,
                    home: Some(PathBuf::from("/root")),
                })
            })
            .ok_or_else(|| {
                filesystem_error(
                    ErrorCode::InvalidArgument,
                    format!("container account {user:?} does not exist"),
                )
            })?;
        let gid = match group_override {
            Some(group) => group
                .parse::<u32>()
                .ok()
                .or_else(|| {
                    self.accounts
                        .groups
                        .iter()
                        .find(|entry| entry.name == group)
                        .map(|entry| entry.id)
                })
                .ok_or_else(|| {
                    filesystem_error(
                        ErrorCode::InvalidArgument,
                        format!("container group {group:?} does not exist"),
                    )
                })?,
            None => account.primary_group,
        };
        let home = account.home.ok_or_else(|| {
            filesystem_error(
                ErrorCode::InvalidArgument,
                format!("container account {user:?} has no valid home directory"),
            )
        })?;
        Ok(ResolvedOwner {
            home,
            ids: Some((
                self.execution.host_uid(account.id)?,
                self.execution.host_gid(gid)?,
            )),
        })
    }

    fn open(&self, path: &Path, flags: i32, mode: u32) -> Result<File> {
        openat2_file(self.execution.root_descriptor(), path, flags, mode)
            .map_err(|error| io_error("open container path", &absolute_display(path), error))
    }

    fn path_exists(&self, path: &ResolvedPath) -> Result<bool> {
        match self.open(
            &path.relative,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(_) => Ok(true),
            Err(error) if error.code == ErrorCode::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn ensure_directories(&self, path: &Path, owner: Option<(u32, u32)>) -> Result<()> {
        let mut prefix = PathBuf::new();
        for component in path.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            prefix.push(component);
            match openat2_file(
                self.execution.root_descriptor(),
                &prefix,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
            ) {
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(io_error(
                        "inspect container directory",
                        &absolute_display(&prefix),
                        error,
                    ))
                }
            }
            let (parent, name) = parent_and_name(&prefix)?;
            let parent = openat2_file(
                self.execution.root_descriptor(),
                parent,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
            )
            .map_err(|error| {
                io_error(
                    "open container directory parent",
                    &absolute_display(parent),
                    error,
                )
            })?;
            let name = cstring(name)?;
            let created = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) };
            if created != 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(io_error(
                        "create container directory",
                        &absolute_display(&prefix),
                        error,
                    ));
                }
            }
            let directory = openat2_file(
                self.execution.root_descriptor(),
                &prefix,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                0,
            )
            .map_err(|error| {
                io_error(
                    "verify container directory",
                    &absolute_display(&prefix),
                    error,
                )
            })?;
            if created == 0 {
                if let Some((uid, gid)) = owner {
                    let result = unsafe { libc::fchown(directory.as_raw_fd(), uid, gid) };
                    if result != 0 {
                        return Err(io_error(
                            "set container directory ownership",
                            &absolute_display(&prefix),
                            io::Error::last_os_error(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn rename(
        &self,
        source: &ResolvedPath,
        destination: &ResolvedPath,
        owner: Option<(u32, u32)>,
    ) -> Result<()> {
        let destination_parent = destination.relative.parent().ok_or_else(|| {
            filesystem_error(ErrorCode::InvalidArgument, "move destination has no parent")
        })?;
        self.ensure_directories(destination_parent, owner)?;
        let (source_parent, source_name) = parent_and_name(&source.relative)?;
        let (destination_parent, destination_name) = parent_and_name(&destination.relative)?;
        let source_parent_file = self.open(
            source_parent,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let destination_parent_file = self.open(
            destination_parent,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let source_name = cstring(source_name)?;
        let destination_name = cstring(destination_name)?;
        let result = unsafe {
            libc::renameat(
                source_parent_file.as_raw_fd(),
                source_name.as_ptr(),
                destination_parent_file.as_raw_fd(),
                destination_name.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io_error(
                "move container path",
                &format!("{} -> {}", source.display, destination.display),
                io::Error::last_os_error(),
            ))
        }
    }

    fn entry(&self, path: &ResolvedPath) -> Result<FilesystemEntry> {
        let file = self.open(
            &path.relative,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("stat container path", &path.display, error))?;
        let is_symlink = metadata.file_type().is_symlink();
        let represented = if is_symlink {
            self.open(&path.relative, libc::O_PATH | libc::O_CLOEXEC, 0)
                .ok()
                .and_then(|target| target.metadata().ok())
        } else {
            None
        };
        let represented = represented.as_ref().unwrap_or(&metadata);
        let kind = if represented.is_file() {
            FilesystemEntryKind::File
        } else if represented.is_dir() {
            FilesystemEntryKind::Directory
        } else {
            FilesystemEntryKind::Unspecified
        };
        let container_uid = self.execution.container_uid(metadata.uid());
        let container_gid = self.execution.container_gid(metadata.gid());
        Ok(FilesystemEntry {
            name: path
                .relative
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/".to_string()),
            kind,
            path: path.display.clone(),
            size: i64::try_from(metadata.len()).unwrap_or(i64::MAX),
            mode: represented.mode() & 0o7777,
            permissions: permissions(&metadata, is_symlink),
            owner: self.accounts.user_name(container_uid),
            group: self.accounts.group_name(container_gid),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec() as i32,
            symlink_target: is_symlink
                .then(|| self.read_link(&path.relative))
                .transpose()?,
            metadata: Default::default(),
        })
    }

    fn read_link(&self, path: &Path) -> Result<String> {
        let (parent, name) = parent_and_name(path)?;
        let parent = self.open(
            parent,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let name = cstring(name)?;
        let mut buffer = vec![0_u8; 4_096];
        let length = unsafe {
            libc::readlinkat(
                parent.as_raw_fd(),
                name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if length < 0 {
            return Err(io_error(
                "read container symlink",
                &absolute_display(path),
                io::Error::last_os_error(),
            ));
        }
        buffer.truncate(length as usize);
        Ok(OsString::from_vec(buffer).to_string_lossy().into_owned())
    }

    fn list(&self, path: &ResolvedPath, depth: u32) -> Result<Vec<FilesystemEntry>> {
        let directory = self.open(
            &path.relative,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        drop(directory);
        let mut entries = Vec::new();
        let mut response_bytes = 0_usize;
        self.list_recursive(path, 1, depth, &mut entries, &mut response_bytes)?;
        Ok(entries)
    }

    fn list_recursive(
        &self,
        directory: &ResolvedPath,
        current_depth: u32,
        maximum_depth: u32,
        entries: &mut Vec<FilesystemEntry>,
        response_bytes: &mut usize,
    ) -> Result<()> {
        for name in self.directory_names(&directory.relative)? {
            if entries.len() >= MAX_FILESYSTEM_ENTRIES {
                return Err(filesystem_error(
                    ErrorCode::ResourceExhausted,
                    format!("directory listing exceeds {MAX_FILESYSTEM_ENTRIES} entries"),
                ));
            }
            let child = directory.child(name);
            let file = self.open(
                &child.relative,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?;
            let recurse = file
                .metadata()
                .map_err(|error| io_error("inspect directory entry", &child.display, error))?
                .is_dir();
            let entry = self.entry(&child)?;
            *response_bytes = response_bytes.saturating_add(
                serde_json::to_vec(&entry)
                    .map_err(|error| {
                        filesystem_error(
                            ErrorCode::Internal,
                            format!("failed to size filesystem entry: {error}"),
                        )
                    })?
                    .len(),
            );
            if *response_bytes > MAX_FILESYSTEM_RESPONSE_BYTES {
                return Err(filesystem_error(
                    ErrorCode::ResourceExhausted,
                    format!("directory listing exceeds {MAX_FILESYSTEM_RESPONSE_BYTES} bytes"),
                ));
            }
            entries.push(entry);
            if recurse && current_depth < maximum_depth {
                self.list_recursive(
                    &child,
                    current_depth + 1,
                    maximum_depth,
                    entries,
                    response_bytes,
                )?;
            }
        }
        Ok(())
    }

    fn directory_names(&self, path: &Path) -> Result<Vec<OsString>> {
        let file = self.open(
            path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )?;
        let mut directory = Dir::from_fd(file.into_raw_fd()).map_err(|error| {
            io_error(
                "open container directory stream",
                &absolute_display(path),
                io::Error::from_raw_os_error(error as i32),
            )
        })?;
        let mut names = Vec::new();
        for entry in directory.iter() {
            let entry = entry.map_err(|error| {
                io_error(
                    "read container directory",
                    &absolute_display(path),
                    io::Error::from_raw_os_error(error as i32),
                )
            })?;
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        Ok(names)
    }

    fn remove(&self, path: &ResolvedPath) -> Result<()> {
        match self.open(
            &path.relative,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        ) {
            Ok(file) => {
                let directory = file
                    .metadata()
                    .map_err(|error| io_error("inspect removal target", &path.display, error))?
                    .is_dir();
                if directory {
                    for name in self.directory_names(&path.relative)? {
                        self.remove(&path.child(name))?;
                    }
                }
                let (parent, name) = parent_and_name(&path.relative)?;
                let parent = self.open(
                    parent,
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    0,
                )?;
                let name = cstring(name)?;
                let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
                let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) };
                if result == 0 {
                    Ok(())
                } else {
                    Err(io_error(
                        "remove container path",
                        &path.display,
                        io::Error::last_os_error(),
                    ))
                }
            }
            Err(error) if error.code == ErrorCode::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone)]
struct Account {
    name: String,
    id: u32,
    primary_group: u32,
    home: Option<PathBuf>,
}

#[derive(Default)]
struct Accounts {
    users: Vec<Account>,
    groups: Vec<Account>,
}

impl Accounts {
    fn load(root: RawFd) -> Result<Self> {
        Ok(Self {
            users: read_optional_account_file(root, Path::new("etc/passwd"), true)?,
            groups: read_optional_account_file(root, Path::new("etc/group"), false)?,
        })
    }

    fn user_name(&self, id: u32) -> String {
        self.users
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    fn group_name(&self, id: u32) -> String {
        self.groups
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.name.clone())
            .unwrap_or_else(|| id.to_string())
    }
}

fn read_optional_account_file(root: RawFd, path: &Path, passwd: bool) -> Result<Vec<Account>> {
    let file = match openat2_file(root, path, libc::O_RDONLY | libc::O_CLOEXEC, 0) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(io_error(
                "open container account database",
                &absolute_display(path),
                error,
            ))
        }
    };
    let metadata = file.metadata().map_err(|error| {
        io_error(
            "inspect container account database",
            &absolute_display(path),
            error,
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_ACCOUNT_FILE_BYTES {
        return Err(filesystem_error(
            ErrorCode::FailedPrecondition,
            format!(
                "container account database {} is not a bounded regular file",
                absolute_display(path)
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ACCOUNT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            io_error(
                "read container account database",
                &absolute_display(path),
                error,
            )
        })?;
    if bytes.len() > MAX_ACCOUNT_FILE_BYTES as usize {
        return Err(filesystem_error(
            ErrorCode::ResourceExhausted,
            "container account database exceeded its read limit",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|error| {
        filesystem_error(
            ErrorCode::InvalidArgument,
            format!("container account database is not UTF-8: {error}"),
        )
    })?;
    Ok(text
        .lines()
        .filter_map(|line| parse_account(line, passwd))
        .collect())
}

fn parse_account(line: &str, passwd: bool) -> Option<Account> {
    let fields = line.split(':').collect::<Vec<_>>();
    if passwd {
        Some(Account {
            name: fields.first()?.to_string(),
            id: fields.get(2)?.parse().ok()?,
            primary_group: fields.get(3)?.parse().ok()?,
            home: fields
                .get(5)
                .filter(|home| home.starts_with('/'))
                .map(PathBuf::from),
        })
    } else {
        let id = fields.get(2)?.parse().ok()?;
        Some(Account {
            name: fields.first()?.to_string(),
            id,
            primary_group: id,
            home: None,
        })
    }
}

struct ResolvedOwner {
    home: PathBuf,
    ids: Option<(u32, u32)>,
}

#[derive(Clone)]
struct ResolvedPath {
    relative: PathBuf,
    display: String,
}

impl ResolvedPath {
    fn is_root(&self) -> bool {
        self.relative.as_os_str().is_empty()
    }

    fn child(&self, name: OsString) -> Self {
        let relative = self.relative.join(name);
        Self {
            display: absolute_display(&relative),
            relative,
        }
    }
}

fn resolve_path(value: &str, home: &Path) -> Result<ResolvedPath> {
    let candidate = if value.is_empty() || value == "~" {
        home.to_path_buf()
    } else if let Some(relative) = value.strip_prefix("~/") {
        home.join(relative)
    } else if value.starts_with('~') {
        return Err(filesystem_error(
            ErrorCode::InvalidArgument,
            "user-specific home expansion is not supported",
        ));
    } else {
        let path = Path::new(value);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            home.join(path)
        }
    };
    let mut relative = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                relative.pop();
            }
            Component::Normal(component) => relative.push(component),
            Component::Prefix(_) => {
                return Err(filesystem_error(
                    ErrorCode::InvalidArgument,
                    "container paths must use Linux path syntax",
                ))
            }
        }
    }
    if relative.as_os_str().as_bytes().contains(&0) {
        return Err(filesystem_error(
            ErrorCode::InvalidArgument,
            "container path contains a NUL byte",
        ));
    }
    Ok(ResolvedPath {
        display: absolute_display(&relative),
        relative,
    })
}

fn openat2_file(root: RawFd, path: &Path, flags: i32, mode: u32) -> io::Result<File> {
    let path = if path.as_os_str().is_empty() {
        CString::new(".").expect("literal path")
    } else {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?
    };
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor as RawFd) })
    }
}

fn parent_and_name(path: &Path) -> Result<(&Path, &OsStr)> {
    let parent = path.parent().ok_or_else(|| {
        filesystem_error(ErrorCode::InvalidArgument, "container path has no parent")
    })?;
    let name = path.file_name().ok_or_else(|| {
        filesystem_error(
            ErrorCode::InvalidArgument,
            "container path has no final component",
        )
    })?;
    Ok((parent, name))
}

fn cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| {
        filesystem_error(
            ErrorCode::InvalidArgument,
            "container path component contains a NUL byte",
        )
    })
}

fn absolute_display(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        "/".to_string()
    } else {
        format!("/{}", path.to_string_lossy())
    }
}

fn permissions(metadata: &std::fs::Metadata, symlink: bool) -> String {
    let kind = if symlink {
        'L'
    } else if metadata.is_dir() {
        'd'
    } else if metadata.is_file() {
        '-'
    } else if metadata.file_type().is_socket() {
        's'
    } else {
        '?'
    };
    let mode = metadata.mode();
    let mut value = String::with_capacity(10);
    value.push(kind);
    for (read, write, execute) in [
        (0o400, 0o200, 0o100),
        (0o040, 0o020, 0o010),
        (0o004, 0o002, 0o001),
    ] {
        value.push(if mode & read != 0 { 'r' } else { '-' });
        value.push(if mode & write != 0 { 'w' } else { '-' });
        value.push(if mode & execute != 0 { 'x' } else { '-' });
    }
    value
}

fn io_error(operation: &'static str, path: &str, error: io::Error) -> Error {
    let code = match error.kind() {
        io::ErrorKind::NotFound => ErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        io::ErrorKind::AlreadyExists => ErrorCode::Conflict,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => ErrorCode::InvalidArgument,
        _ => match error.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::EXDEV) => ErrorCode::PermissionDenied,
            Some(libc::ENOTDIR) | Some(libc::EISDIR) | Some(libc::ENOTEMPTY) => {
                ErrorCode::FailedPrecondition
            }
            Some(libc::ENOSYS) => ErrorCode::Unsupported,
            _ => ErrorCode::Internal,
        },
    };
    filesystem_error(code, format!("failed to {operation} {path}: {error}"))
}

fn filesystem_error(code: ErrorCode, message: impl Into<String>) -> Error {
    executor_error(code, message).for_operation("linux-container-filesystem")
}

#[cfg(test)]
mod tests {
    use super::{absolute_display, resolve_path};
    use std::path::Path;

    #[test]
    fn container_paths_normalize_at_the_retained_root() {
        let path = resolve_path("../../etc/./passwd", Path::new("/root")).expect("path");
        assert_eq!(path.relative, Path::new("etc/passwd"));
        assert_eq!(path.display, "/etc/passwd");

        let home = resolve_path("~/data", Path::new("/home/alice")).expect("home path");
        assert_eq!(home.relative, Path::new("home/alice/data"));
        assert_eq!(absolute_display(&home.relative), "/home/alice/data");
    }

    #[test]
    fn named_other_user_expansion_is_rejected() {
        assert!(resolve_path("~root/file", Path::new("/root")).is_err());
    }
}
