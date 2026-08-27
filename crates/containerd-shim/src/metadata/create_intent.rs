use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{
    CheckpointArtifactPath, CheckpointReference, ContainerId, IsolationRequest, Result,
};
use serde::{Deserialize, Serialize};

use super::{
    atomic_write, metadata_error, metadata_io, validate_metadata_file, MAX_METADATA_BYTES,
};
use crate::adapter::TaskIdentity;
use crate::identity::IncarnationId;

const CREATE_INTENT_FILE_NAME: &str = "a3s-oci-shim-create-v1.json";
const CREATE_INTENT_SCHEMA_VERSION: u32 = 2;
const MIN_CREATE_INTENT_SCHEMA_VERSION: u32 = 1;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restore: Option<RestoreIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreIntent {
    artifact_path: CheckpointArtifactPath,
    reference: CheckpointReference,
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
    pub(crate) restore: Option<(CheckpointArtifactPath, CheckpointReference)>,
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
            restore: value
                .restore
                .map(|(artifact_path, reference)| RestoreIntent {
                    artifact_path,
                    reference,
                }),
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

    pub(crate) fn restore(&self) -> Option<(&CheckpointArtifactPath, &CheckpointReference)> {
        self.restore
            .as_ref()
            .map(|restore| (&restore.artifact_path, &restore.reference))
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if !(MIN_CREATE_INTENT_SCHEMA_VERSION..=CREATE_INTENT_SCHEMA_VERSION)
            .contains(&self.schema_version)
        {
            return Err(metadata_error(format!(
                "unsupported shim create-intent schema {} in {}; expected {MIN_CREATE_INTENT_SCHEMA_VERSION} through {CREATE_INTENT_SCHEMA_VERSION}",
                self.schema_version,
                path.display()
            )));
        }
        if self.schema_version < 2 && self.restore.is_some() {
            return Err(metadata_error(
                "shim create-intent schema v1 cannot contain checkpoint restore state",
            ));
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
        if let Some(restore) = &self.restore {
            if restore.reference.compatibility().isolation() != self.isolation.class() {
                return Err(metadata_error(
                    "shim restore intent isolation differs from its immutable checkpoint reference",
                ));
            }
        }
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
            restore: None,
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
    fn schema_v1_create_intent_remains_readable_without_restore_state() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected = intent(directory.path());
        expected.store().expect("store create intent");
        let path = ShimCreateIntent::path(directory.path());
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read create intent"))
                .expect("decode create intent");
        document["schema_version"] = serde_json::json!(1);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("encode schema-v1 create intent"),
        )
        .expect("write schema-v1 create intent");

        let loaded = ShimCreateIntent::load(&path)
            .expect("load schema-v1 create intent")
            .expect("schema-v1 create intent exists");
        assert_eq!(loaded.restore(), None);
        assert_eq!(
            loaded.identity().expect("legacy identity"),
            expected.identity().expect("expected identity")
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
            restore: None,
        })
        .expect_err("missing incarnation must fail closed");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::FailedPrecondition);
    }
}
