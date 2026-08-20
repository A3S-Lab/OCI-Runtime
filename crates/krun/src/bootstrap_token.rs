use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
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
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{
    AgentVsockEndpoint, SessionToken, AGENT_RUNTIME_SHARE_GUEST_ROOT,
    AGENT_SESSION_TOKEN_DIRECTORY_PREFIX, AGENT_SESSION_TOKEN_FILE_NAME,
};

pub(crate) struct BootstrapTokenFile {
    paths: CleanupPaths,
    guest_path: String,
    cleaned: bool,
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const PRIVATE_FILE_MODE: u32 = 0o600;

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
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
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
            let _ = fs::remove_dir(&directory);
            return Err(contextual(
                error,
                format!(
                    "failed to protect one-time guest bootstrap directory {}",
                    directory.display()
                ),
            ));
        }
        let paths = CleanupPaths {
            file: directory.join(AGENT_SESSION_TOKEN_FILE_NAME),
            directory,
        };

        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
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
            let mut file = options.open(&paths.file).map_err(|error| {
                contextual(
                    error,
                    format!(
                        "failed to create one-time guest bootstrap file {}",
                        paths.file.display()
                    ),
                )
            })?;
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
            })
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
}

impl CleanupPaths {
    pub(crate) fn cleanup(&self) -> io::Result<()> {
        let mut errors = Vec::new();
        remove_file_if_present(&self.file, &mut errors);
        remove_dir_if_present(&self.directory, &mut errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(errors.join("; ")))
        }
    }
}

fn remove_file_if_present(path: &Path, errors: &mut Vec<String>) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove one-time guest bootstrap file {}: {error}",
            path.display()
        )),
    }
}

fn remove_dir_if_present(path: &Path, errors: &mut Vec<String>) {
    match fs::remove_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!(
            "failed to remove one-time guest bootstrap directory {}: {error}",
            path.display()
        )),
    }
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
