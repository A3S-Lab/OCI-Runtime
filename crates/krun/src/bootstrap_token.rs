use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::os::unix::fs::MetadataExt;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::io::AsRawHandle;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use a3s_oci_agent_protocol::{
    AgentVsockEndpoint, SessionToken, AGENT_RUNTIME_SHARE_GUEST_ROOT,
    AGENT_SESSION_TOKEN_DIRECTORY_PREFIX, AGENT_SESSION_TOKEN_FILE_NAME,
};

pub(crate) struct BootstrapTokenFile {
    paths: CleanupPaths,
    guest_path: String,
    cleaned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind {
    Directory,
    File,
}

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
impl EntryIdentity {
    fn from_file(file: &fs::File) -> io::Result<Self> {
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
    fn from_file(file: &fs::File) -> io::Result<Self> {
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

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "windows", target_arch = "x86_64")
)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity;

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "windows", target_arch = "x86_64")
)))]
impl EntryIdentity {
    fn from_file(_file: &fs::File) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "one-time guest bootstrap entry identity is unsupported on this platform",
        ))
    }
}

impl BootstrapTokenFile {
    pub(crate) fn create(
        host_root: &Path,
        guest_root: &str,
        endpoint: &AgentVsockEndpoint,
        token: &SessionToken,
    ) -> io::Result<Self> {
        validate_guest_root(guest_root)?;
        let host_metadata = fs::symlink_metadata(host_root).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to inspect guest handoff root {}",
                    host_root.display()
                ),
            )
        })?;
        if host_metadata.file_type().is_symlink() || !host_metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "guest handoff root must be a real directory: {}",
                    host_root.display()
                ),
            ));
        }
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            // SAFETY: geteuid has no arguments and cannot fail.
            let effective_user_id = unsafe { libc::geteuid() };
            if host_metadata.uid() != effective_user_id
                || host_metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "guest handoff root must be owned by UID {effective_user_id} with mode {PRIVATE_DIRECTORY_MODE:03o}: {}",
                        host_root.display()
                    ),
                ));
            }
        }
        let host_root = host_root.canonicalize().map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to resolve guest handoff root {}",
                    host_root.display()
                ),
            )
        })?;
        if !host_root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "guest handoff root is not a directory: {}",
                    host_root.display()
                ),
            ));
        }

        let directory_name = format!(
            "{AGENT_SESSION_TOKEN_DIRECTORY_PREFIX}{}",
            endpoint.pipe_name()
        );
        let directory = host_root.join(&directory_name);
        fs::create_dir(&directory).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to create one-time guest bootstrap directory {}",
                    directory.display()
                ),
            )
        })?;
        let mut paths = CleanupPaths::new(
            directory.join(AGENT_SESSION_TOKEN_FILE_NAME),
            directory.clone(),
        );
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        if let Err(error) = fs::set_permissions(
            &directory,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        ) {
            return Err(contextual(
                error,
                format!(
                    "failed to protect one-time guest bootstrap directory {}",
                    directory.display()
                ),
            ));
        }

        let directory_handle = open_directory_nofollow(&directory).map_err(|error| {
            contextual(
                error,
                format!(
                    "failed to pin one-time guest bootstrap directory {}",
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
            contextual(
                error,
                format!(
                    "failed to verify one-time guest bootstrap directory {}",
                    directory.display()
                ),
            )
        })?;
        paths.set_directory_identity(directory_identity);

        let result = (|| {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(any(
                all(target_os = "macos", target_arch = "aarch64"),
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            ))]
            options
                .mode(PRIVATE_FILE_MODE)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            options
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            let mut file = options.open(&paths.file).map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to create one-time guest bootstrap file {}",
                        paths.file.display()
                    ),
                )
            })?;
            let file_identity =
                verify_handle_entry(&paths.file, &file, EntryKind::File, PRIVATE_FILE_MODE)
                    .map_err(|error| {
                        contextual(
                            error,
                            format!(
                                "failed to verify one-time guest bootstrap file {}",
                                paths.file.display()
                            ),
                        )
                    })?;
            paths.set_file_identity(file_identity);
            let encoded = token.expose_hex();
            file.write_all(encoded.as_bytes()).map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to write one-time guest bootstrap file {}",
                        paths.file.display()
                    ),
                )
            })?;
            file.sync_all().map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to flush one-time guest bootstrap file {}",
                        paths.file.display()
                    ),
                )
            })?;
            verify_handle_entry(&paths.file, &file, EntryKind::File, PRIVATE_FILE_MODE)?;
            verify_bound_entry(
                &paths.directory,
                EntryKind::Directory,
                PRIVATE_DIRECTORY_MODE,
                directory_identity,
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = paths.cleanup();
            return Err(error);
        }

        Ok(Self {
            paths,
            guest_path: guest_path(guest_root, &directory_name, AGENT_SESSION_TOKEN_FILE_NAME),
            cleaned: false,
        })
    }

    pub(crate) fn guest_path(&self) -> &str {
        &self.guest_path
    }

    /// Recheck that the token handoff still names the exact entries created by
    /// this shim before the guest is allowed to consume it.
    pub(crate) fn reverify(&self) -> io::Result<()> {
        self.paths.reverify()
    }

    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) fn cleanup_paths(&self) -> CleanupPaths {
        self.paths.clone()
    }

    pub(crate) fn cleanup(mut self) -> io::Result<()> {
        let result = self.paths.cleanup();
        self.cleaned = result.is_ok();
        result
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

impl Drop for BootstrapTokenFile {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.paths.cleanup();
        }
    }
}

#[derive(Clone)]
pub(crate) struct CleanupPaths {
    file: PathBuf,
    directory: PathBuf,
    file_identity: Option<EntryIdentity>,
    directory_identity: Option<EntryIdentity>,
}

impl CleanupPaths {
    fn new(file: PathBuf, directory: PathBuf) -> Self {
        Self {
            file,
            directory,
            file_identity: None,
            directory_identity: None,
        }
    }

    fn set_file_identity(&mut self, identity: EntryIdentity) {
        self.file_identity = Some(identity);
    }

    fn set_directory_identity(&mut self, identity: EntryIdentity) {
        self.directory_identity = Some(identity);
    }

    fn reverify(&self) -> io::Result<()> {
        let directory_identity = self.directory_identity.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "one-time guest bootstrap directory identity is unavailable: {}",
                    self.directory.display()
                ),
            )
        })?;
        verify_bound_entry(
            &self.directory,
            EntryKind::Directory,
            PRIVATE_DIRECTORY_MODE,
            directory_identity,
        )?;

        let file_identity = self.file_identity.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "one-time guest bootstrap file identity is unavailable: {}",
                    self.file.display()
                ),
            )
        })?;
        verify_bound_entry(
            &self.file,
            EntryKind::File,
            PRIVATE_FILE_MODE,
            file_identity,
        )
    }

    pub(crate) fn cleanup(&self) -> io::Result<()> {
        let mut errors = Vec::new();
        if let Some(identity) = self.file_identity {
            remove_owned_entry(
                &self.file,
                EntryKind::File,
                PRIVATE_FILE_MODE,
                identity,
                &mut errors,
            );
        }
        if let Some(identity) = self.directory_identity {
            remove_owned_entry(
                &self.directory,
                EntryKind::Directory,
                PRIVATE_DIRECTORY_MODE,
                identity,
                &mut errors,
            );
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
            format!(
                "one-time guest bootstrap entry identity changed: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn remove_owned_entry(
    path: &Path,
    kind: EntryKind,
    mode: u32,
    expected: EntryIdentity,
    errors: &mut Vec<(io::ErrorKind, String)>,
) {
    let result = (|| {
        verify_bound_entry(path, kind, mode, expected)?;
        match kind {
            EntryKind::Directory => fs::remove_dir(path),
            EntryKind::File => fs::remove_file(path),
        }
    })();
    match result {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push((
            error.kind(),
            format!(
                "failed to remove one-time guest bootstrap {} {}: {error}",
                entry_label(kind),
                path.display()
            ),
        )),
    }
}

fn inspect_entry(path: &Path, kind: EntryKind, mode: u32) -> io::Result<EntryIdentity> {
    let file = open_entry_nofollow(path, kind)?;
    let metadata = file.metadata()?;
    verify_metadata(&metadata, path, kind, mode)?;
    EntryIdentity::from_file(&file)
}

fn verify_handle_entry(
    path: &Path,
    file: &fs::File,
    kind: EntryKind,
    mode: u32,
) -> io::Result<EntryIdentity> {
    let handle_metadata = file.metadata()?;
    verify_metadata(&handle_metadata, path, kind, mode)?;
    let handle_identity = EntryIdentity::from_file(file)?;
    let path_identity = inspect_entry(path, kind, mode)?;
    if path_identity != handle_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "one-time guest bootstrap entry changed while it was being pinned: {}",
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
                "one-time guest bootstrap {} has an unexpected entry type: {}",
                entry_label(kind),
                path.display()
            ),
        ));
    }
    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        // SAFETY: geteuid has no pointer arguments or failure return.
        let effective_user_id = unsafe { libc::geteuid() };
        if metadata.uid() != effective_user_id || metadata.mode() & 0o777 != mode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "one-time guest bootstrap {} is not owned by the runtime with mode {mode:03o}: {}",
                    entry_label(kind),
                    path.display()
                ),
            ));
        }
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    let _ = mode;
    Ok(())
}

fn entry_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Directory => "directory",
        EntryKind::File => "file",
    }
}

fn open_directory_nofollow(path: &Path) -> io::Result<fs::File> {
    open_entry_nofollow(path, EntryKind::Directory)
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn open_entry_nofollow(path: &Path, kind: EntryKind) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if kind == EntryKind::Directory {
        flags |= libc::O_DIRECTORY;
    }
    options.read(true).custom_flags(flags).open(path)
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn open_entry_nofollow(path: &Path, kind: EntryKind) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if kind == EntryKind::Directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(flags)
        .open(path)
}

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "windows", target_arch = "x86_64")
)))]
fn open_entry_nofollow(path: &Path, _kind: EntryKind) -> io::Result<fs::File> {
    fs::File::open(path)
}

fn contextual(error: io::Error, context: String) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_agent_protocol::{AgentVsockEndpoint, SessionToken};

    use super::BootstrapTokenFile;

    fn protect_linux_handoff_root(path: &Path) {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("protect Linux handoff root");
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        let _ = path;
    }

    #[test]
    fn creates_exact_one_time_file_and_removes_it() {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
        protect_linux_handoff_root(rootfs.path());
        let endpoint =
            AgentVsockEndpoint::new("a3s-oci-agent-bootstrap-test").expect("valid endpoint");
        let token = SessionToken::from_bytes([0x5a; 32]).expect("nonzero token");
        let bootstrap = BootstrapTokenFile::create(rootfs.path(), "/", &endpoint, &token)
            .expect("bootstrap file");
        let host_path = rootfs
            .path()
            .join(bootstrap.guest_path().trim_start_matches('/'));
        assert_eq!(
            std::fs::read_to_string(&host_path).expect("read bootstrap file"),
            "5a".repeat(32)
        );
        bootstrap.reverify().expect("reverify bootstrap handoff");
        let directory = host_path
            .parent()
            .expect("bootstrap directory")
            .to_path_buf();

        bootstrap.cleanup().expect("remove bootstrap file");
        assert!(!host_path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn reports_the_fixed_runtime_share_guest_path() {
        let runtime_share = tempfile::tempdir().expect("temporary runtime share");
        protect_linux_handoff_root(runtime_share.path());
        let endpoint =
            AgentVsockEndpoint::new("a3s-oci-agent-runtime-share").expect("valid endpoint");
        let token = SessionToken::from_bytes([0x3c; 32]).expect("nonzero token");
        let bootstrap = BootstrapTokenFile::create(
            runtime_share.path(),
            a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT,
            &endpoint,
            &token,
        )
        .expect("bootstrap file");

        assert!(bootstrap
            .guest_path()
            .starts_with(a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT));
        bootstrap.cleanup().expect("remove bootstrap file");
    }

    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ),
        all(target_os = "windows", target_arch = "x86_64")
    ))]
    #[test]
    fn cleanup_refuses_a_replaced_bootstrap_file() {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
        protect_linux_handoff_root(rootfs.path());
        let endpoint =
            AgentVsockEndpoint::new("a3s-oci-agent-bootstrap-replacement").expect("valid endpoint");
        let token = SessionToken::from_bytes([0x42; 32]).expect("nonzero token");
        let bootstrap = BootstrapTokenFile::create(rootfs.path(), "/", &endpoint, &token)
            .expect("bootstrap file");
        let host_path = rootfs
            .path()
            .join(bootstrap.guest_path().trim_start_matches('/'));
        let directory = host_path
            .parent()
            .expect("bootstrap directory")
            .to_path_buf();
        let decoy = directory.join("replacement");
        std::fs::write(&decoy, b"replacement").expect("write replacement");
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o600))
                .expect("protect replacement");
        }
        std::fs::remove_file(&host_path).expect("remove original bootstrap file");
        std::fs::hard_link(&decoy, &host_path).expect("install replacement hard link");

        let error = bootstrap
            .cleanup()
            .expect_err("cleanup must refuse a replaced file");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(host_path.exists(), "replacement file must remain");

        // The consumed BootstrapTokenFile cannot clean a replacement by
        // design; remove test-only entries explicitly so the temp directory
        // does not retain a non-empty child.
        std::fs::remove_file(&host_path).expect("remove replacement link");
        std::fs::remove_file(&decoy).expect("remove replacement target");
        std::fs::remove_dir(&directory).expect("remove bootstrap directory");
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn rejects_a_public_linux_handoff_root() {
        use std::os::unix::fs::PermissionsExt;

        let runtime_share = tempfile::tempdir().expect("temporary runtime share");
        std::fs::set_permissions(runtime_share.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make Linux handoff root public");
        let endpoint =
            AgentVsockEndpoint::new("a3s-oci-agent-public-runtime-share").expect("valid endpoint");
        let token = SessionToken::from_bytes([0x7d; 32]).expect("nonzero token");

        assert!(BootstrapTokenFile::create(
            runtime_share.path(),
            a3s_oci_agent_protocol::AGENT_RUNTIME_SHARE_GUEST_ROOT,
            &endpoint,
            &token,
        )
        .is_err());
    }
}
