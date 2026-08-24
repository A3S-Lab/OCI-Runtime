use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use a3s_oci_sdk::{ContainerId, Generation, Result};
use serde::{Deserialize, Serialize};

use crate::adapter::TaskIdentity;
use crate::identity::IncarnationId;

use super::{
    atomic_write, metadata_error, metadata_io, open_private_read, sync_parent,
    validate_private_file,
};

const TASK_DELETE_RECEIPT_FILE_NAME: &str = "a3s-oci-shim-task-delete-v1.json";
const TASK_DELETE_RECEIPT_SCHEMA_VERSION: u32 = 1;
const MAX_TASK_DELETE_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskDeleteReceipt {
    schema_version: u32,
    namespace: String,
    task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incarnation: Option<String>,
    container_id: ContainerId,
    generation: Generation,
    bundle: PathBuf,
    pid: u32,
    exit_status: u32,
    exited_at_unix_nanos: u128,
}

impl TaskDeleteReceipt {
    pub(crate) fn new(
        bundle: &Path,
        identity: &TaskIdentity,
        generation: Generation,
        pid: u32,
        exit_status: u32,
        exited_at_unix_nanos: u128,
    ) -> Result<Self> {
        let receipt = Self {
            schema_version: TASK_DELETE_RECEIPT_SCHEMA_VERSION,
            namespace: identity.namespace.clone(),
            task_id: identity.task_id.clone(),
            incarnation: identity
                .incarnation
                .as_ref()
                .map(|incarnation| incarnation.as_str().to_string()),
            container_id: identity.container_id.clone(),
            generation,
            bundle: bundle.to_path_buf(),
            pid,
            exit_status,
            exited_at_unix_nanos,
        };
        receipt.validate(&Self::path(bundle))?;
        Ok(receipt)
    }

    pub(crate) fn load(bundle: &Path) -> Result<Option<Self>> {
        let path = Self::path(bundle);
        let mut file = match open_private_read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(metadata_io("open task delete receipt", &path, error)),
        };
        validate_private_file(&file, &path, MAX_TASK_DELETE_RECEIPT_BYTES)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_TASK_DELETE_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| metadata_io("read task delete receipt", &path, error))?;
        if bytes.len() as u64 > MAX_TASK_DELETE_RECEIPT_BYTES {
            return Err(metadata_error(format!(
                "containerd task delete receipt {} exceeds the {MAX_TASK_DELETE_RECEIPT_BYTES}-byte limit",
                path.display()
            )));
        }
        let receipt: Self = serde_json::from_slice(&bytes).map_err(|error| {
            metadata_error(format!(
                "failed to decode containerd task delete receipt {}: {error}",
                path.display()
            ))
        })?;
        receipt.validate(&path)?;
        Ok(Some(receipt))
    }

    pub(crate) fn store(&self) -> Result<()> {
        let path = Self::path(&self.bundle);
        self.validate(&path)?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            metadata_error(format!(
                "failed to encode containerd task delete receipt: {error}"
            ))
        })?;
        if encoded.len() as u64 > MAX_TASK_DELETE_RECEIPT_BYTES {
            return Err(metadata_error(format!(
                "containerd task delete receipt {} exceeds the {MAX_TASK_DELETE_RECEIPT_BYTES}-byte limit",
                path.display()
            )));
        }
        atomic_write(&path, &encoded)
    }

    pub(crate) fn remove(bundle: &Path) -> Result<()> {
        let path = Self::path(bundle);
        match fs::remove_file(&path) {
            Ok(()) => sync_parent(&path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(metadata_io("remove task delete receipt", &path, error)),
        }
    }

    pub(crate) fn path(bundle: &Path) -> PathBuf {
        bundle.join(TASK_DELETE_RECEIPT_FILE_NAME)
    }

    pub(crate) fn validate_for(
        &self,
        identity: &TaskIdentity,
        generation: Generation,
        bundle: &Path,
    ) -> Result<()> {
        if !self.matches_for(identity, generation, bundle)? {
            return Err(metadata_error(
                "containerd task delete receipt no longer matches the task identity, generation, or bundle",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches_for(
        &self,
        identity: &TaskIdentity,
        generation: Generation,
        bundle: &Path,
    ) -> Result<bool> {
        Ok(&self.identity()? == identity && self.generation == generation && self.bundle == bundle)
    }

    pub(crate) fn validate_for_service(
        &self,
        namespace: &str,
        task_id: &str,
        bundle: &Path,
    ) -> Result<()> {
        let identity = self.identity()?;
        if identity.namespace != namespace || identity.task_id != task_id || self.bundle != bundle {
            return Err(metadata_error(
                "containerd task delete receipt no longer matches the serving namespace, task ID, or bundle",
            ));
        }
        Ok(())
    }

    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) const fn exit_status(&self) -> u32 {
        self.exit_status
    }

    pub(crate) const fn exited_at_unix_nanos(&self) -> u128 {
        self.exited_at_unix_nanos
    }

    pub(crate) fn exited_at(&self) -> Option<SystemTime> {
        system_time_from_unix_nanos(self.exited_at_unix_nanos)
    }

    fn identity(&self) -> Result<TaskIdentity> {
        let incarnation = self
            .incarnation
            .as_deref()
            .map(IncarnationId::new)
            .transpose()?;
        let identity = TaskIdentity::with_optional_incarnation(
            self.namespace.clone(),
            self.task_id.clone(),
            incarnation,
        )?;
        if identity.container_id != self.container_id {
            return Err(metadata_error(format!(
                "containerd task delete receipt identity resolves to {}, but records {}",
                identity.container_id.as_str(),
                self.container_id.as_str()
            )));
        }
        Ok(identity)
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.schema_version != TASK_DELETE_RECEIPT_SCHEMA_VERSION {
            return Err(metadata_error(format!(
                "unsupported containerd task delete receipt schema {} in {}; expected {TASK_DELETE_RECEIPT_SCHEMA_VERSION}",
                self.schema_version,
                path.display()
            )));
        }
        if self.generation.0 == 0 {
            return Err(metadata_error(format!(
                "containerd task delete receipt {} records generation zero",
                path.display()
            )));
        }
        if !self.bundle.is_absolute()
            || self.bundle != path.parent().unwrap_or_else(|| Path::new(""))
        {
            return Err(metadata_error(format!(
                "containerd task delete receipt {} records an invalid bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        self.identity()?;
        if system_time_from_unix_nanos(self.exited_at_unix_nanos).is_none() {
            return Err(metadata_error(format!(
                "containerd task delete receipt {} records an unrepresentable exit time",
                path.display()
            )));
        }
        Ok(())
    }
}

fn system_time_from_unix_nanos(nanos: u128) -> Option<SystemTime> {
    let seconds = u64::try_from(nanos / 1_000_000_000).ok()?;
    let subsecond_nanos = u32::try_from(nanos % 1_000_000_000).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(seconds, subsecond_nanos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use a3s_oci_sdk::ErrorCode;

    #[test]
    fn receipt_round_trip_is_identity_generation_and_bundle_bound() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let identity = TaskIdentity::new("k8s.io", "task-a").expect("task identity");
        let receipt = TaskDeleteReceipt::new(
            directory.path(),
            &identity,
            Generation(7),
            51,
            23,
            23_000_000_123,
        )
        .expect("task delete receipt");
        receipt.store().expect("store task delete receipt");

        let loaded = TaskDeleteReceipt::load(directory.path())
            .expect("load task delete receipt")
            .expect("task delete receipt exists");
        assert_eq!(loaded, receipt);
        loaded
            .validate_for(&identity, Generation(7), directory.path())
            .expect("matching task receipt");
        assert_eq!(loaded.pid(), 51);
        assert_eq!(loaded.exit_status(), 23);
        assert_eq!(loaded.exited_at_unix_nanos(), 23_000_000_123);

        let replacement = TaskIdentity::new("k8s.io", "task-b").expect("replacement identity");
        let error = loaded
            .validate_for(&replacement, Generation(7), directory.path())
            .expect_err("identity replacement must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }
}
