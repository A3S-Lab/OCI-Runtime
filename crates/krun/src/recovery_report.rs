use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::ffi::OsStrExt;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use a3s_oci_agent_protocol::{
    AgentRecoveryReport, AgentVsockEndpoint, AuthenticatedAgentRecoveryReport, SessionToken,
    AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX, AGENT_RECOVERY_REPORT_FILE_NAME,
    AGENT_RECOVERY_REPORT_MAX_BYTES, AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
    AGENT_RUNTIME_SHARE_GUEST_ROOT,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_WRITE_THROUGH,
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind {
    Directory,
    File,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl EntryIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl EntryIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        use std::mem::MaybeUninit;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `file` owns a live handle and `information` points to an
        // allocation for one complete Windows file-information structure.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
        if succeeded == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the API returned success and initialized the structure.
        let information = unsafe { information.assume_init() };
        Ok(Self {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }
}

pub(crate) struct RecoveryReportHandoff {
    paths: RecoveryCleanupPaths,
    guest_path: String,
    destination: PathBuf,
    cleaned: bool,
}

impl RecoveryReportHandoff {
    pub(crate) fn create(
        host_root: &Path,
        guest_root: &str,
        endpoint: &AgentVsockEndpoint,
        destination: &Path,
    ) -> io::Result<Self> {
        validate_guest_root(guest_root)?;
        let host_root = canonical_plain_directory(host_root, "guest handoff root")?;
        let destination = prepare_destination(destination)?;
        if destination.starts_with(&host_root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "trusted recovery destination must be outside guest handoff root {}: {}",
                    host_root.display(),
                    destination.display()
                ),
            ));
        }

        let pending = pending_path(&destination);
        let pending_file = private_new_file(&pending).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to create trusted recovery pending marker {}",
                    pending.display()
                ),
            )
        })?;
        let pending_identity = EntryIdentity::from_file(&pending_file).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to identify trusted recovery pending marker {}",
                    pending.display()
                ),
            )
        })?;
        if let Err(error) = pending_file.sync_all() {
            drop(pending_file);
            let _ = remove_owned_entry(
                &pending,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                pending_identity,
                "trusted recovery pending marker",
            );
            return Err(contextual(
                error,
                format!(
                    "failed to flush trusted recovery pending marker {}",
                    pending.display()
                ),
            ));
        }
        drop(pending_file);

        let directory_name = format!(
            "{AGENT_RECOVERY_REPORT_DIRECTORY_PREFIX}{}",
            endpoint.pipe_name()
        );
        let directory = host_root.join(&directory_name);
        if let Err(error) = fs::create_dir(&directory) {
            let _ = remove_owned_entry(
                &pending,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                pending_identity,
                "trusted recovery pending marker",
            );
            return Err(contextual(
                error,
                format!(
                    "failed to create one-time guest recovery directory {}",
                    directory.display()
                ),
            ));
        }
        #[cfg(unix)]
        if let Err(error) = fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        ) {
            let _ = remove_owned_entry(
                &pending,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                pending_identity,
                "trusted recovery pending marker",
            );
            return Err(contextual(
                error,
                format!(
                    "failed to protect one-time guest recovery directory {}",
                    directory.display()
                ),
            ));
        }
        let directory_handle =
            open_entry_nofollow(&directory, EntryKind::Directory).map_err(|error| {
                let _ = remove_owned_entry(
                    &pending,
                    EntryKind::File,
                    PRIVATE_FILE_MODE,
                    pending_identity,
                    "trusted recovery pending marker",
                );
                contextual(
                    error,
                    format!(
                        "failed to pin one-time guest recovery directory {}",
                        directory.display()
                    ),
                )
            })?;
        let directory_identity = verify_handle_entry(
            &directory,
            &directory_handle,
            EntryKind::Directory,
            PRIVATE_DIRECTORY_MODE,
        )
        .map_err(|error| {
            let _ = remove_owned_entry(
                &pending,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                pending_identity,
                "trusted recovery pending marker",
            );
            contextual(
                error,
                format!(
                    "failed to verify one-time guest recovery directory {}",
                    directory.display()
                ),
            )
        })?;
        let paths = RecoveryCleanupPaths::new(
            directory.join(AGENT_RECOVERY_REPORT_FILE_NAME),
            directory,
            pending,
            directory_identity,
            pending_identity,
        );

        Ok(Self {
            paths,
            guest_path: guest_path(guest_root, &directory_name, AGENT_RECOVERY_REPORT_FILE_NAME),
            destination,
            cleaned: false,
        })
    }

    pub(crate) fn guest_path(&self) -> &str {
        &self.guest_path
    }

    pub(crate) fn cleanup_paths(&self) -> RecoveryCleanupPaths {
        self.paths.clone()
    }

    /// Recheck the runtime-owned recovery handoff immediately before VM
    /// entry. The report file may not exist yet because the guest creates it
    /// only during shutdown, so its identity is checked when available.
    pub(crate) fn reverify(&self) -> io::Result<()> {
        verify_bound_entry(
            &self.paths.directory,
            EntryKind::Directory,
            PRIVATE_DIRECTORY_MODE,
            self.paths.directory_identity,
        )?;
        verify_bound_entry(
            &self.paths.pending,
            EntryKind::File,
            PRIVATE_FILE_MODE,
            self.paths.pending_identity,
        )?;
        if let Some(identity) = self.paths.file_identity()? {
            verify_bound_entry(
                &self.paths.file,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                identity,
            )?;
        }
        Ok(())
    }

    pub(crate) fn persist(mut self, token: &SessionToken) -> io::Result<AgentRecoveryReport> {
        let persist_result = self.persist_inner(token);
        let cleanup_result = self.paths.cleanup();
        self.cleaned = cleanup_result.is_ok();
        match (persist_result, cleanup_result) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(io::Error::new(
                error.kind(),
                format!("{error}; guest recovery cleanup also failed: {cleanup}"),
            )),
        }
    }

    fn persist_inner(&self, token: &SessionToken) -> io::Result<AgentRecoveryReport> {
        let mut file = open_entry_nofollow(&self.paths.file, EntryKind::File).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to open guest recovery report {}",
                    self.paths.file.display()
                ),
            )
        })?;
        let file_identity =
            verify_handle_entry(&self.paths.file, &file, EntryKind::File, PRIVATE_FILE_MODE)?;
        self.paths.set_file_identity(file_identity)?;
        let metadata = file.metadata()?;
        if metadata.len() > AGENT_RECOVERY_REPORT_MAX_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "guest recovery report must be a plain file of at most {} bytes: {}",
                    AGENT_RECOVERY_REPORT_MAX_BYTES,
                    self.paths.file.display()
                ),
            ));
        }

        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take((AGENT_RECOVERY_REPORT_MAX_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to read guest recovery report {}",
                        self.paths.file.display()
                    ),
                )
            })?;
        let bytes_read = u64::try_from(encoded.len()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guest recovery report length is not representable: {error}"),
            )
        })?;
        let final_metadata = file.metadata()?;
        if encoded.len() > AGENT_RECOVERY_REPORT_MAX_BYTES
            || final_metadata.len() != bytes_read
            || EntryIdentity::from_file(&file)? != file_identity
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest recovery report changed while it was being read",
            ));
        }
        verify_bound_entry(
            &self.paths.file,
            EntryKind::File,
            PRIVATE_FILE_MODE,
            file_identity,
        )?;
        let report = AuthenticatedAgentRecoveryReport::verify_json(&encoded, token)
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let normalized = report
            .to_json()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        atomic_write(&self.destination, &normalized)?;
        Ok(report)
    }
}

fn validate_guest_root(guest_root: &str) -> io::Result<()> {
    if matches!(guest_root, "/") || guest_root == AGENT_RUNTIME_SHARE_GUEST_ROOT {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported guest handoff root: {guest_root}"),
        ))
    }
}

fn guest_path(guest_root: &str, directory: &str, file: &str) -> String {
    if guest_root == "/" {
        format!("/{directory}/{file}")
    } else {
        format!("{guest_root}/{directory}/{file}")
    }
}

impl Drop for RecoveryReportHandoff {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.paths.cleanup();
        }
    }
}

#[derive(Clone)]
pub(crate) struct RecoveryCleanupPaths {
    file: PathBuf,
    directory: PathBuf,
    pending: PathBuf,
    directory_identity: EntryIdentity,
    pending_identity: EntryIdentity,
    file_identity: Arc<Mutex<Option<EntryIdentity>>>,
}

impl RecoveryCleanupPaths {
    fn new(
        file: PathBuf,
        directory: PathBuf,
        pending: PathBuf,
        directory_identity: EntryIdentity,
        pending_identity: EntryIdentity,
    ) -> Self {
        Self {
            file,
            directory,
            pending,
            directory_identity,
            pending_identity,
            file_identity: Arc::new(Mutex::new(None)),
        }
    }

    fn set_file_identity(&self, identity: EntryIdentity) -> io::Result<()> {
        let mut current = self
            .file_identity
            .lock()
            .map_err(|_| io::Error::other("guest recovery cleanup identity lock was poisoned"))?;
        if let Some(existing) = *current {
            if existing != identity {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "guest recovery report identity changed while it was being bound: {}",
                        self.file.display()
                    ),
                ));
            }
        } else {
            *current = Some(identity);
        }
        Ok(())
    }

    fn file_identity(&self) -> io::Result<Option<EntryIdentity>> {
        self.file_identity
            .lock()
            .map(|identity| *identity)
            .map_err(|_| io::Error::other("guest recovery cleanup identity lock was poisoned"))
    }

    pub(crate) fn cleanup(&self) -> io::Result<()> {
        let mut errors = Vec::new();
        if let Some(identity) = self.file_identity()? {
            if let Err(error) = remove_owned_entry(
                &self.file,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                identity,
                "one-time guest recovery report",
            ) {
                errors.push((error.kind(), error.to_string()));
            }
        }
        if let Err(error) = remove_owned_entry(
            &self.directory,
            EntryKind::Directory,
            PRIVATE_DIRECTORY_MODE,
            self.directory_identity,
            "one-time guest recovery directory",
        ) {
            errors.push((error.kind(), error.to_string()));
        }
        if let Err(error) = remove_owned_entry(
            &self.pending,
            EntryKind::File,
            PRIVATE_FILE_MODE,
            self.pending_identity,
            "trusted recovery pending marker",
        ) {
            errors.push((error.kind(), error.to_string()));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            let kind = if errors
                .iter()
                .any(|(kind, _)| *kind == io::ErrorKind::PermissionDenied)
            {
                io::ErrorKind::PermissionDenied
            } else {
                io::ErrorKind::Other
            };
            let message = errors
                .into_iter()
                .map(|(_, message)| message)
                .collect::<Vec<_>>()
                .join("; ");
            Err(io::Error::new(kind, message))
        }
    }
}

fn prepare_destination(destination: &Path) -> io::Result<PathBuf> {
    if !destination.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted recovery destination must be absolute: {}",
                destination.display()
            ),
        ));
    }
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted recovery destination must name a file: {}",
                destination.display()
            ),
        )
    })?;
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "trusted recovery destination has no parent: {}",
                destination.display()
            ),
        )
    })?;
    let parent = canonical_plain_directory(parent, "trusted recovery directory")?;
    let destination = parent.join(file_name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to overwrite trusted recovery destination {}",
                destination.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let pending = pending_path(&destination);
            match fs::symlink_metadata(&pending) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing to replace trusted recovery pending marker {}",
                        pending.display()
                    ),
                )),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(destination),
                Err(error) => Err(contextual(
                    error,
                    format!(
                        "failed to inspect trusted recovery pending marker {}",
                        pending.display()
                    ),
                )),
            }
        }
        Err(error) => Err(contextual(
            error,
            format!(
                "failed to inspect trusted recovery destination {}",
                destination.display()
            ),
        )),
    }
}

fn pending_path(destination: &Path) -> PathBuf {
    let mut path = destination.as_os_str().to_os_string();
    path.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
    PathBuf::from(path)
}

fn canonical_plain_directory(path: &Path, label: &str) -> io::Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        contextual(
            error,
            format!("failed to inspect {label} {}", path.display()),
        )
    })?;
    if !plain_private_directory(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} must be a plain directory: {}", path.display()),
        ));
    }
    path.canonicalize().map_err(|error| {
        contextual(
            error,
            format!("failed to resolve {label} {}", path.display()),
        )
    })
}

fn plain_private_directory(metadata: &fs::Metadata) -> bool {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions or failure return.
        metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == PRIVATE_DIRECTORY_MODE
    }
}

fn atomic_write(destination: &Path, encoded: &[u8]) -> io::Result<()> {
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted recovery destination has no file name",
        )
    })?;
    let temporary = destination.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut file = private_new_file(&temporary).map_err(|error| {
        contextual(
            error,
            format!(
                "failed to create temporary trusted recovery report {}",
                temporary.display()
            ),
        )
    })?;
    let temporary_identity = EntryIdentity::from_file(&file).map_err(|error| {
        contextual(
            error,
            format!(
                "failed to identify temporary trusted recovery report {}",
                temporary.display()
            ),
        )
    })?;
    let write_result = file
        .write_all(encoded)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            verify_handle_entry(&temporary, &file, EntryKind::File, PRIVATE_FILE_MODE).map(|_| ())
        });
    drop(file);
    if let Err(error) = write_result {
        let _ = remove_owned_entry(
            &temporary,
            EntryKind::File,
            PRIVATE_FILE_MODE,
            temporary_identity,
            "temporary trusted recovery report",
        );
        return Err(contextual(
            error,
            format!(
                "failed to write temporary trusted recovery report {}",
                temporary.display()
            ),
        ));
    }
    if let Err(error) = commit_atomic_file(&temporary, destination) {
        let _ = remove_owned_entry(
            &temporary,
            EntryKind::File,
            PRIVATE_FILE_MODE,
            temporary_identity,
            "temporary trusted recovery report",
        );
        return Err(contextual(
            error,
            format!(
                "failed to commit trusted recovery report {}",
                destination.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn commit_atomic_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    let temporary = nul_terminated_path(temporary)?;
    let destination = nul_terminated_path(destination)?;
    // SAFETY: both UTF-16 paths are NUL-terminated and remain live for the
    // call. Omitting MOVEFILE_REPLACE_EXISTING preserves the create-new fence;
    // WRITE_THROUGH waits for the durable move before reporting success.
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn nul_terminated_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("trusted recovery path contains NUL: {}", path.display()),
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn commit_atomic_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    // A plain rename would replace a caller-created destination if it appeared
    // after `prepare_destination` inspected the path.  A hard link gives us a
    // same-filesystem, no-replace publication fence; the temporary name is
    // removed only after the destination link is committed.
    fs::hard_link(temporary, destination)?;
    fs::remove_file(temporary)?;
    if let Some(parent) = destination.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn remove_owned_entry(
    path: &Path,
    kind: EntryKind,
    mode: u32,
    expected: EntryIdentity,
    label: &str,
) -> io::Result<()> {
    let result = (|| {
        verify_bound_entry(path, kind, mode, expected)?;
        match kind {
            EntryKind::Directory => fs::remove_dir(path),
            EntryKind::File => fs::remove_file(path),
        }
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("failed to remove {label} {}: {error}", path.display()),
        )),
    }
}

fn verify_bound_entry(
    path: &Path,
    kind: EntryKind,
    mode: u32,
    expected: EntryIdentity,
) -> io::Result<()> {
    let observed = inspect_entry(path, kind, mode)?;
    if observed != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("guest recovery entry identity changed: {}", path.display()),
        ));
    }
    Ok(())
}

fn inspect_entry(path: &Path, kind: EntryKind, mode: u32) -> io::Result<EntryIdentity> {
    let file = open_entry_nofollow(path, kind)?;
    let metadata = file.metadata()?;
    verify_metadata(&metadata, path, kind, mode)?;
    EntryIdentity::from_file(&file)
}

fn verify_handle_entry(
    path: &Path,
    file: &File,
    kind: EntryKind,
    mode: u32,
) -> io::Result<EntryIdentity> {
    let metadata = file.metadata()?;
    verify_metadata(&metadata, path, kind, mode)?;
    let handle_identity = EntryIdentity::from_file(file)?;
    let path_identity = inspect_entry(path, kind, mode)?;
    if handle_identity != path_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "guest recovery entry changed while it was being pinned: {}",
                path.display()
            ),
        ));
    }
    Ok(handle_identity)
}

fn verify_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    kind: EntryKind,
    mode: u32,
) -> io::Result<()> {
    let type_matches = match kind {
        EntryKind::Directory => metadata.is_dir(),
        EntryKind::File => metadata.is_file(),
    };
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    let reparsed = metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    let reparsed = false;
    if !type_matches || metadata.file_type().is_symlink() || reparsed {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "guest recovery {} has an unexpected entry type: {}",
                entry_label(kind),
                path.display()
            ),
        ));
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no pointer arguments or failure return.
        let effective_user_id = unsafe { libc::geteuid() };
        if metadata.uid() != effective_user_id || metadata.mode() & 0o777 != mode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "guest recovery {} is not owned by the runtime with mode {mode:03o}: {}",
                    entry_label(kind),
                    path.display()
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

fn entry_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Directory => "directory",
        EntryKind::File => "file",
    }
}

#[cfg(unix)]
fn open_entry_nofollow(path: &Path, kind: EntryKind) -> io::Result<File> {
    let mut options = OpenOptions::new();
    let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if kind == EntryKind::Directory {
        flags |= libc::O_DIRECTORY;
    }
    options.read(true).custom_flags(flags).open(path)
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn open_entry_nofollow(path: &Path, kind: EntryKind) -> io::Result<File> {
    let mut options = OpenOptions::new();
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if kind == EntryKind::Directory {
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(flags)
        .open(path)
}

fn private_new_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    options
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

fn contextual(error: io::Error, context: String) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_agent_protocol::{
        AgentRecoveryRecord, AgentRecoveryReport, AgentVsockEndpoint,
        AuthenticatedAgentRecoveryReport, SessionToken,
    };
    use a3s_oci_sdk::{ContainerId, ContainerTarget, ExitStatus, Generation};

    use super::{pending_path, RecoveryReportHandoff};

    fn create_private_directory(path: &Path) {
        std::fs::create_dir(path).expect("create private test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("protect private test directory");
        }
    }

    fn write_private_file(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).expect("write private test file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("protect private test file");
        }
    }

    fn token(byte: u8) -> SessionToken {
        SessionToken::from_bytes([byte; 32]).expect("nonzero token")
    }

    fn report() -> AgentRecoveryReport {
        AgentRecoveryReport::new(vec![AgentRecoveryRecord::new(
            ContainerTarget::exact(ContainerId::new("box").expect("valid ID"), Generation(7)),
            format!("sha256:{}", "b".repeat(64)),
            ExitStatus::exited(23).expect("valid exit"),
        )
        .expect("valid record")])
        .expect("valid report")
    }

    #[test]
    fn verifies_normalizes_and_cleans_one_time_guest_report() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        create_private_directory(&rootfs);
        create_private_directory(&trusted);
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-recovery-test").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        handoff.reverify().expect("reverify recovery handoff");
        assert!(pending_path(&destination).is_file());
        let guest_path = rootfs.join(handoff.guest_path().trim_start_matches('/'));
        let encoded = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        write_private_file(&guest_path, &encoded);

        let verified = handoff.persist(&token(4)).expect("persist report");
        assert_eq!(verified, report());
        assert_eq!(
            AgentRecoveryReport::from_json(&std::fs::read(&destination).unwrap()).unwrap(),
            report()
        );
        assert!(!guest_path.exists());
        assert!(!guest_path.parent().unwrap().exists());
        assert!(!pending_path(&destination).exists());
    }

    #[test]
    fn rejects_tampering_without_creating_a_trusted_report() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        create_private_directory(&rootfs);
        create_private_directory(&trusted);
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-tamper-test").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        let guest_path = rootfs.join(handoff.guest_path().trim_start_matches('/'));
        let encoded = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["report"]["records"][0]["initExitStatus"]["exit_code"] = 24.into();
        write_private_file(&guest_path, &serde_json::to_vec(&value).unwrap());

        assert!(handoff.persist(&token(4)).is_err());
        assert!(!destination.exists());
        assert!(!guest_path.exists());
        assert!(!pending_path(&destination).exists());
    }

    #[cfg(any(unix, all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn cleanup_refuses_a_replaced_guest_report() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        create_private_directory(&rootfs);
        create_private_directory(&trusted);
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-recovery-replacement").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        let guest_path = rootfs.join(handoff.guest_path().trim_start_matches('/'));
        let guest_directory = guest_path.parent().expect("guest directory").to_path_buf();
        let encoded = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        write_private_file(&guest_path, &encoded);

        // Bind the report identity exactly as the normal persist path does,
        // then replace the pathname with a distinct inode before cleanup.
        handoff.persist_inner(&token(4)).expect("verify report");
        let cleanup = handoff.cleanup_paths();
        let decoy = guest_directory.join("replacement");
        write_private_file(&decoy, b"replacement");
        std::fs::remove_file(&guest_path).expect("remove original report");
        std::fs::hard_link(&decoy, &guest_path).expect("install replacement report");

        let error = cleanup
            .cleanup()
            .expect_err("cleanup must refuse a replaced report");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(guest_path.exists(), "replacement report must remain");

        std::fs::remove_file(&guest_path).expect("remove replacement link");
        std::fs::remove_file(&decoy).expect("remove replacement target");
        let _ = std::fs::remove_dir(&guest_directory);
        let _ = std::fs::remove_file(pending_path(&destination));
    }

    #[cfg(any(unix, all(target_os = "windows", target_arch = "x86_64")))]
    #[test]
    fn cleanup_refuses_a_replaced_pending_marker() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        create_private_directory(&rootfs);
        create_private_directory(&trusted);
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-pending-replacement").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        let cleanup = handoff.cleanup_paths();
        let pending = pending_path(&destination);
        let decoy = trusted.join("pending-replacement");
        write_private_file(&decoy, b"replacement");
        std::fs::remove_file(&pending).expect("remove original pending marker");
        std::fs::hard_link(&decoy, &pending).expect("install replacement pending marker");

        let error = cleanup
            .cleanup()
            .expect_err("cleanup must refuse a replaced pending marker");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(pending.exists(), "replacement pending marker must remain");

        let _ = std::fs::remove_file(&pending);
        let _ = std::fs::remove_file(&decoy);
        let _ = std::fs::remove_dir(
            rootfs
                .join(handoff.guest_path().trim_start_matches('/'))
                .parent()
                .unwrap(),
        );
    }

    #[test]
    fn atomic_report_publish_never_replaces_an_incumbent() {
        let base = tempfile::tempdir().expect("temporary base");
        let destination = base.path().join("box-7.json");
        write_private_file(&destination, b"incumbent");

        let error = super::atomic_write(&destination, b"replacement")
            .expect_err("an incumbent destination must reject publication");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&destination).expect("read incumbent"),
            b"incumbent"
        );
        let temporary = destination.with_file_name(format!(
            ".{}.{}.tmp",
            destination.file_name().unwrap().to_string_lossy(),
            std::process::id()
        ));
        assert!(
            !temporary.exists(),
            "failed publication must remove its staging file"
        );
    }

    #[test]
    fn refuses_to_copy_trusted_evidence_into_the_guest_root() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        create_private_directory(&rootfs);
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-path-test").unwrap();
        assert!(
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &rootfs.join("box-7.json"),)
                .is_err()
        );
    }

    #[test]
    fn drop_cleans_the_guest_path_and_pending_marker() {
        let base = tempfile::tempdir().expect("temporary base");
        let rootfs = base.path().join("rootfs");
        let trusted = base.path().join("trusted");
        create_private_directory(&rootfs);
        create_private_directory(&trusted);
        let destination = trusted.join("box-7.json");
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-drop-test").unwrap();
        let handoff =
            RecoveryReportHandoff::create(&rootfs, "/", &endpoint, &destination).expect("handoff");
        let guest_directory = rootfs
            .join(handoff.guest_path().trim_start_matches('/'))
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(pending_path(&destination).is_file());
        drop(handoff);
        assert!(!pending_path(&destination).exists());
        assert!(!guest_directory.exists());
    }

    #[test]
    fn normalized_reports_do_not_retain_the_authentication_tag() {
        let authenticated = report().authenticate(&token(4)).unwrap().to_json().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&authenticated).unwrap();
        assert!(value.get("authenticationTag").is_some());
        let normalized = AuthenticatedAgentRecoveryReport::verify_json(&authenticated, &token(4))
            .unwrap()
            .to_json()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&normalized).unwrap();
        assert!(value.get("authenticationTag").is_none());
    }
}
