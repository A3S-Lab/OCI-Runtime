use std::fs::{self, OpenOptions};
use std::io::{self, Write};
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

impl BootstrapTokenFile {
    pub(crate) fn create(
        host_root: &Path,
        guest_root: &str,
        endpoint: &AgentVsockEndpoint,
        token: &SessionToken,
    ) -> io::Result<Self> {
        validate_guest_root(guest_root)?;
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
        let paths = CleanupPaths {
            file: directory.join(AGENT_SESSION_TOKEN_FILE_NAME),
            directory,
        };

        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&paths.file)
                .map_err(|error| {
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
        all(target_os = "macos", target_arch = "aarch64")
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
    use a3s_oci_agent_protocol::{AgentVsockEndpoint, SessionToken};

    use super::BootstrapTokenFile;

    #[test]
    fn creates_exact_one_time_file_and_removes_it() {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
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
}
