use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{ContainerId, IsolationRequest, Result};
use serde::{Deserialize, Serialize};

use super::{
    atomic_write, metadata_error, metadata_io, validate_metadata_file, MAX_METADATA_BYTES,
};
use crate::adapter::TaskIdentity;
use crate::identity::IncarnationId;

const CREATE_INTENT_FILE_NAME: &str = "a3s-oci-shim-create-v1.json";
const CREATE_INTENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShimCreateIntent {
    schema_version: u32,
    namespace: String,
    task_id: String,
    incarnation: String,
    container_id: ContainerId,
    isolation: IsolationRequest,
    bundle: PathBuf,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    rootfs_mounted: bool,
}

pub(crate) struct NewShimCreateIntent {
    pub(crate) identity: TaskIdentity,
    pub(crate) isolation: IsolationRequest,
    pub(crate) bundle: PathBuf,
    pub(crate) stdin: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) terminal: bool,
    pub(crate) rootfs_mounted: bool,
}

impl ShimCreateIntent {
    pub(crate) fn new(value: NewShimCreateIntent) -> Result<Self> {
        let TaskIdentity {
            namespace,
            task_id,
            incarnation,
            container_id,
        } = value.identity;
        let incarnation = incarnation.ok_or_else(|| {
            metadata_error("containerd shim create intent requires a task incarnation")
        })?;
        let intent = Self {
            schema_version: CREATE_INTENT_SCHEMA_VERSION,
            namespace,
            task_id,
            incarnation: incarnation.as_str().to_string(),
            container_id,
            isolation: value.isolation,
            bundle: value.bundle,
            stdin: value.stdin,
            stdout: value.stdout,
            stderr: value.stderr,
            terminal: value.terminal,
            rootfs_mounted: value.rootfs_mounted,
        };
        intent.validate(&Self::path(&intent.bundle))?;
        Ok(intent)
    }

    pub(crate) fn path(bundle: &Path) -> PathBuf {
        bundle.join(CREATE_INTENT_FILE_NAME)
    }

    pub(crate) fn load(path: &Path) -> Result<Option<Self>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(metadata_io("open create intent", path, error)),
        };
        validate_metadata_file(&file, path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| metadata_io("read create intent", path, error))?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(metadata_error(format!(
                "shim create intent {} exceeds the {MAX_METADATA_BYTES}-byte limit",
                path.display()
            )));
        }
        let intent: Self = serde_json::from_slice(&bytes).map_err(|error| {
            metadata_error(format!(
                "failed to decode shim create intent {}: {error}",
                path.display()
            ))
        })?;
        intent.validate(path)?;
        Ok(Some(intent))
    }

    pub(crate) fn store(&self) -> Result<()> {
        self.validate(&Self::path(&self.bundle))?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            metadata_error(format!(
                "failed to encode containerd shim create intent: {error}"
            ))
        })?;
        atomic_write(&Self::path(&self.bundle), &encoded)
    }

    pub(crate) fn remove(bundle: &Path) -> Result<()> {
        let path = Self::path(bundle);
        match fs::remove_file(&path) {
            Ok(()) => super::sync_parent(&path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(metadata_io("remove create intent", &path, error)),
        }
    }

    pub(crate) fn identity(&self) -> Result<TaskIdentity> {
        let incarnation = IncarnationId::new(self.incarnation.clone())?;
        let identity = TaskIdentity::with_incarnation(
            self.namespace.clone(),
            self.task_id.clone(),
            incarnation,
        )?;
        if identity.container_id != self.container_id {
            return Err(metadata_error(format!(
                "shim create intent identity resolves to {}, but records {}",
                identity.container_id.as_str(),
                self.container_id.as_str()
            )));
        }
        Ok(identity)
    }

    pub(crate) fn isolation(&self) -> &IsolationRequest {
        &self.isolation
    }

    pub(crate) fn bundle(&self) -> &Path {
        &self.bundle
    }

    pub(crate) fn stdin(&self) -> &str {
        &self.stdin
    }

    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }

    pub(crate) fn terminal(&self) -> bool {
        self.terminal
    }

    pub(crate) fn rootfs_mounted(&self) -> bool {
        self.rootfs_mounted
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.schema_version != CREATE_INTENT_SCHEMA_VERSION {
            return Err(metadata_error(format!(
                "unsupported shim create-intent schema {} in {}; expected {CREATE_INTENT_SCHEMA_VERSION}",
                self.schema_version,
                path.display()
            )));
        }
        if !self.bundle.is_absolute() {
            return Err(metadata_error(format!(
                "shim create intent {} records a non-absolute bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        if self.bundle != path.parent().unwrap_or_else(|| Path::new("")) {
            return Err(metadata_error(format!(
                "shim create intent {} records a different bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        self.identity()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent(bundle: &Path) -> ShimCreateIntent {
        let incarnation = IncarnationId::new("01".repeat(32)).expect("incarnation");
        ShimCreateIntent::new(NewShimCreateIntent {
            identity: TaskIdentity::with_incarnation("k8s.io", "task-a", incarnation)
                .expect("identity"),
            isolation: IsolationRequest::SharedHostKernel,
            bundle: bundle.to_path_buf(),
            stdin: "stdin".to_string(),
            stdout: "stdout".to_string(),
            stderr: "stderr".to_string(),
            terminal: false,
            rootfs_mounted: true,
        })
        .expect("create intent")
    }

    #[test]
    fn create_intent_round_trip_preserves_replay_identity_and_inputs() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected = intent(directory.path());
        expected.store().expect("store create intent");

        let loaded = ShimCreateIntent::load(&ShimCreateIntent::path(directory.path()))
            .expect("load create intent")
            .expect("create intent exists");
        assert_eq!(loaded, expected);
        assert_eq!(
            loaded.identity().expect("identity"),
            expected.identity().expect("identity")
        );
        assert_eq!(loaded.isolation(), &IsolationRequest::SharedHostKernel);

        ShimCreateIntent::remove(directory.path()).expect("remove create intent");
        assert_eq!(
            ShimCreateIntent::load(&ShimCreateIntent::path(directory.path()))
                .expect("reload removed create intent"),
            None
        );
    }

    #[test]
    fn create_intent_rejects_an_identity_without_an_incarnation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let error = ShimCreateIntent::new(NewShimCreateIntent {
            identity: TaskIdentity::new("k8s.io", "task-a").expect("identity"),
            isolation: IsolationRequest::SharedHostKernel,
            bundle: directory.path().to_path_buf(),
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: false,
            rootfs_mounted: false,
        })
        .expect_err("missing incarnation must fail closed");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);
    }
}
