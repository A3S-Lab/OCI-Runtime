use std::collections::BTreeSet;
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

const EXEC_DELETE_JOURNAL_FILE_NAME: &str = "a3s-oci-shim-exec-delete-v1.json";
const EXEC_DELETE_JOURNAL_SCHEMA_VERSION: u32 = 1;
const MAX_EXEC_DELETE_JOURNAL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecDeleteReceipt {
    exec_id: String,
    incarnation: u64,
    pid: u32,
    exit_status: u32,
    exited_at_unix_nanos: u128,
}

impl ExecDeleteReceipt {
    pub(crate) fn new(
        exec_id: String,
        incarnation: u64,
        pid: u32,
        exit_status: u32,
        exited_at_unix_nanos: u128,
    ) -> Result<Self> {
        let receipt = Self {
            exec_id,
            incarnation,
            pid,
            exit_status,
            exited_at_unix_nanos,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub(crate) fn exec_id(&self) -> &str {
        &self.exec_id
    }

    #[cfg(test)]
    pub(crate) const fn incarnation(&self) -> u64 {
        self.incarnation
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

    fn validate(&self) -> Result<()> {
        if self.exec_id.is_empty() {
            return Err(metadata_error(
                "containerd exec delete receipt contains an empty exec ID",
            ));
        }
        if system_time_from_unix_nanos(self.exited_at_unix_nanos).is_none() {
            return Err(metadata_error(format!(
                "containerd exec {} delete receipt records an unrepresentable exit time",
                self.exec_id
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecDeleteJournal {
    schema_version: u32,
    namespace: String,
    task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incarnation: Option<String>,
    container_id: ContainerId,
    generation: Generation,
    bundle: PathBuf,
    receipts: Vec<ExecDeleteReceipt>,
}

impl ExecDeleteJournal {
    pub(crate) fn load_or_new(
        bundle: &Path,
        identity: &TaskIdentity,
        generation: Generation,
    ) -> Result<Self> {
        let journal =
            Self::load(bundle)?.unwrap_or_else(|| Self::new(bundle, identity, generation));
        journal.validate_for(identity, generation, bundle)?;
        Ok(journal)
    }

    pub(crate) fn load(bundle: &Path) -> Result<Option<Self>> {
        let path = Self::path(bundle);
        let mut file = match open_private_read(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(metadata_io("open exec delete journal", &path, error)),
        };
        validate_private_file(&file, &path, MAX_EXEC_DELETE_JOURNAL_BYTES)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_EXEC_DELETE_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| metadata_io("read exec delete journal", &path, error))?;
        if bytes.len() as u64 > MAX_EXEC_DELETE_JOURNAL_BYTES {
            return Err(metadata_error(format!(
                "containerd exec delete journal {} exceeds the {MAX_EXEC_DELETE_JOURNAL_BYTES}-byte limit",
                path.display()
            )));
        }
        let journal: Self = serde_json::from_slice(&bytes).map_err(|error| {
            metadata_error(format!(
                "failed to decode containerd exec delete journal {}: {error}",
                path.display()
            ))
        })?;
        journal.validate(&path)?;
        Ok(Some(journal))
    }

    pub(crate) fn receipt(&self, exec_id: &str) -> Option<&ExecDeleteReceipt> {
        self.receipts
            .binary_search_by(|receipt| receipt.exec_id.as_str().cmp(exec_id))
            .ok()
            .map(|index| &self.receipts[index])
    }

    pub(crate) fn insert(&mut self, receipt: ExecDeleteReceipt) -> Result<()> {
        match self
            .receipts
            .binary_search_by(|candidate| candidate.exec_id.cmp(&receipt.exec_id))
        {
            Ok(index) if self.receipts[index] == receipt => Ok(()),
            Ok(index) if self.receipts[index].incarnation < receipt.incarnation => {
                self.receipts[index] = receipt;
                Ok(())
            }
            Ok(index) => Err(metadata_error(format!(
                "containerd exec {} delete receipt incarnation {} conflicts with retained incarnation {}",
                receipt.exec_id, receipt.incarnation, self.receipts[index].incarnation
            ))),
            Err(index) => {
                self.receipts.insert(index, receipt);
                Ok(())
            }
        }
    }

    pub(crate) fn remove_receipt(&mut self, exec_id: &str) -> bool {
        let Ok(index) = self
            .receipts
            .binary_search_by(|receipt| receipt.exec_id.as_str().cmp(exec_id))
        else {
            return false;
        };
        self.receipts.remove(index);
        true
    }

    pub(crate) fn store(&self) -> Result<()> {
        if self.receipts.is_empty() {
            return Self::remove(&self.bundle);
        }
        let path = Self::path(&self.bundle);
        self.validate(&path)?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            metadata_error(format!(
                "failed to encode containerd exec delete journal: {error}"
            ))
        })?;
        if encoded.len() as u64 > MAX_EXEC_DELETE_JOURNAL_BYTES {
            return Err(metadata_error(format!(
                "containerd exec delete journal {} exceeds the {MAX_EXEC_DELETE_JOURNAL_BYTES}-byte limit",
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
            Err(error) => Err(metadata_io("remove exec delete journal", &path, error)),
        }
    }

    fn new(bundle: &Path, identity: &TaskIdentity, generation: Generation) -> Self {
        Self {
            schema_version: EXEC_DELETE_JOURNAL_SCHEMA_VERSION,
            namespace: identity.namespace.clone(),
            task_id: identity.task_id.clone(),
            incarnation: identity
                .incarnation
                .as_ref()
                .map(|incarnation| incarnation.as_str().to_string()),
            container_id: identity.container_id.clone(),
            generation,
            bundle: bundle.to_path_buf(),
            receipts: Vec::new(),
        }
    }

    fn path(bundle: &Path) -> PathBuf {
        bundle.join(EXEC_DELETE_JOURNAL_FILE_NAME)
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
                "containerd exec delete journal identity resolves to {}, but records {}",
                identity.container_id.as_str(),
                self.container_id.as_str()
            )));
        }
        Ok(identity)
    }

    fn validate_for(
        &self,
        identity: &TaskIdentity,
        generation: Generation,
        bundle: &Path,
    ) -> Result<()> {
        if &self.identity()? != identity || self.generation != generation || self.bundle != bundle {
            return Err(metadata_error(
                "containerd exec delete journal no longer matches the task identity, generation, or bundle",
            ));
        }
        Ok(())
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.schema_version != EXEC_DELETE_JOURNAL_SCHEMA_VERSION {
            return Err(metadata_error(format!(
                "unsupported containerd exec delete journal schema {} in {}; expected {EXEC_DELETE_JOURNAL_SCHEMA_VERSION}",
                self.schema_version,
                path.display()
            )));
        }
        if self.generation.0 == 0 {
            return Err(metadata_error(format!(
                "containerd exec delete journal {} records generation zero",
                path.display()
            )));
        }
        if !self.bundle.is_absolute()
            || self.bundle != path.parent().unwrap_or_else(|| Path::new(""))
        {
            return Err(metadata_error(format!(
                "containerd exec delete journal {} records an invalid bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        self.identity()?;
        let mut previous = None;
        let mut incarnations = BTreeSet::new();
        for receipt in &self.receipts {
            receipt.validate()?;
            if previous
                .as_deref()
                .is_some_and(|exec_id| exec_id >= receipt.exec_id.as_str())
            {
                return Err(metadata_error(
                    "containerd exec delete receipts must be unique and sorted by exec ID",
                ));
            }
            if receipt.incarnation != 0 && !incarnations.insert(receipt.incarnation) {
                return Err(metadata_error(format!(
                    "containerd exec delete incarnation {} is retained more than once",
                    receipt.incarnation
                )));
            }
            previous = Some(receipt.exec_id.clone());
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
    fn journal_round_trip_is_identity_bound_and_sorted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let identity = TaskIdentity::new("k8s.io", "task-a").expect("task identity");
        let mut journal =
            ExecDeleteJournal::load_or_new(directory.path(), &identity, Generation(7))
                .expect("new journal");
        journal
            .insert(
                ExecDeleteReceipt::new("exec-b".to_string(), 2, 52, 23, 23)
                    .expect("exec-b receipt"),
            )
            .expect("insert exec-b receipt");
        journal
            .insert(
                ExecDeleteReceipt::new("exec-a".to_string(), 1, 51, 7, 7).expect("exec-a receipt"),
            )
            .expect("insert exec-a receipt");
        journal.store().expect("store journal");

        let loaded = ExecDeleteJournal::load_or_new(directory.path(), &identity, Generation(7))
            .expect("load journal");
        assert_eq!(loaded.receipt("exec-a").expect("exec-a").pid(), 51);
        assert_eq!(loaded.receipt("exec-b").expect("exec-b").pid(), 52);

        let replacement = TaskIdentity::new("k8s.io", "task-b").expect("replacement identity");
        let error = ExecDeleteJournal::load_or_new(directory.path(), &replacement, Generation(7))
            .expect_err("identity replacement must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
    }
}
