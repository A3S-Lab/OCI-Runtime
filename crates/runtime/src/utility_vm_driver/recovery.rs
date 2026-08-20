use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentRecoveryReport, AGENT_RECOVERY_REPORT_MAX_BYTES, AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
};
use a3s_oci_sdk::{ContainerRecord, ContainerTarget, Error, ErrorCode, ExitStatus, Result};
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, Instant};

use super::layout::{is_private_file, path_metadata, require_exact_generation};
use crate::{DriverRecovery, DriverState};

const RECOVERY_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(16);

#[derive(Debug, Clone)]
pub(crate) struct RecoveryStore {
    directory: PathBuf,
}

impl RecoveryStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub(crate) fn path(&self, target: &ContainerTarget) -> Result<PathBuf> {
        let generation = require_exact_generation(target, "utility-vm-recovery-report-path")?;
        Ok(self
            .directory
            .join(format!("{}-{}.json", target.id, generation.0)))
    }

    pub(super) async fn recover(
        &self,
        target: &ContainerTarget,
        record: &ContainerRecord,
    ) -> Result<DriverRecovery> {
        let can_commit_stopped =
            *record.state.status() != a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating;
        if !can_commit_stopped {
            // The durable create operation must resume. A stopped observation
            // is not legal while its host-side create intent is still active.
            self.wait_until_settled(&self.path(target)?).await?;
            return Ok(DriverRecovery::none());
        }
        match self.load_exit(target, &record.config_digest).await? {
            Some(status) => DriverRecovery::stopped_with_exit(status),
            None => Ok(DriverRecovery::observed(DriverState::stopped())),
        }
    }

    pub(super) async fn load_exit(
        &self,
        target: &ContainerTarget,
        expected_config_digest: &str,
    ) -> Result<Option<ExitStatus>> {
        let path = self.path(target)?;
        let Some(metadata) = self.wait_until_settled(&path).await? else {
            return Ok(None);
        };
        if !is_private_file(&metadata) || metadata.len() > AGENT_RECOVERY_REPORT_MAX_BYTES as u64 {
            return Err(recovery_error(format!(
                "utility-VM recovery report must be a same-UID mode-0600 file of at most {} bytes: {}",
                AGENT_RECOVERY_REPORT_MAX_BYTES,
                path.display()
            )));
        }
        let file = tokio::fs::File::open(&path).await.map_err(|error| {
            recovery_error(format!(
                "failed to open utility-VM recovery report {}: {error}",
                path.display()
            ))
        })?;
        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        file.take((AGENT_RECOVERY_REPORT_MAX_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .await
            .map_err(|error| {
                recovery_error(format!(
                    "failed to read utility-VM recovery report {}: {error}",
                    path.display()
                ))
            })?;
        if encoded.len() > AGENT_RECOVERY_REPORT_MAX_BYTES {
            return Err(recovery_error(format!(
                "utility-VM recovery report grew beyond {} bytes: {}",
                AGENT_RECOVERY_REPORT_MAX_BYTES,
                path.display()
            )));
        }
        let report = AgentRecoveryReport::from_json(&encoded).map_err(|error| {
            recovery_error(format!(
                "utility-VM recovery report {} is invalid: {error}",
                path.display()
            ))
        })?;
        if report.records().is_empty() {
            return Ok(None);
        }
        let retained = report
            .records()
            .iter()
            .find(|retained| &retained.target == target)
            .ok_or_else(|| {
                recovery_error(format!(
                    "utility-VM recovery report {} does not contain container {} generation {:?}",
                    path.display(),
                    target.id,
                    target.generation
                ))
            })?;
        if retained.config_digest != expected_config_digest {
            return Err(recovery_error(format!(
                "utility-VM recovery report config digest mismatch for container {} generation {:?}: durable {}, report {}",
                target.id,
                target.generation,
                expected_config_digest,
                retained.config_digest
            )));
        }
        Ok(Some(retained.init_exit_status.clone()))
    }

    pub(super) async fn remove(&self, target: &ContainerTarget) -> Result<()> {
        let path = self.path(target)?;
        remove_private_file(&path, "utility-VM recovery report").await?;
        remove_private_file(&pending_path(&path), "utility-VM recovery pending marker").await
    }

    async fn wait_until_settled(&self, path: &Path) -> Result<Option<std::fs::Metadata>> {
        self.wait_until(path, Instant::now() + RECOVERY_TIMEOUT)
            .await
    }

    async fn wait_until(
        &self,
        path: &Path,
        deadline: Instant,
    ) -> Result<Option<std::fs::Metadata>> {
        let pending = pending_path(path);
        loop {
            if let Some(metadata) = path_metadata(path).await? {
                return Ok(Some(metadata));
            }
            match path_metadata(&pending).await? {
                Some(metadata) => {
                    if !is_private_file(&metadata) || metadata.len() != 0 {
                        return Err(recovery_error(format!(
                            "utility-VM recovery pending marker must be a same-UID empty mode-0600 file: {}",
                            pending.display()
                        )));
                    }
                }
                None => {
                    // Recheck the committed path after observing no pending
                    // marker so rename/remove races cannot hide a report.
                    return path_metadata(path).await;
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!(
                        "timed out waiting for utility-VM recovery handoff marker {}",
                        pending.display()
                    ),
                )
                .for_operation("utility-vm-recover")
                .retryable(true));
            }
            sleep(RECOVERY_POLL_INTERVAL).await;
        }
    }
}

async fn remove_private_file(path: &Path, label: &str) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    if !is_private_file(&metadata) {
        // Include the observed owner to make permission failures actionable
        // without weakening the same-UID invariant.
        return Err(recovery_error(format!(
            "refusing to delete non-private {label} {} owned by UID {}",
            path.display(),
            metadata.uid()
        )));
    }
    tokio::fs::remove_file(path).await.map_err(|error| {
        recovery_error(format!(
            "failed to delete {label} {}: {error}",
            path.display()
        ))
    })
}

pub(super) fn pending_path(report: &Path) -> PathBuf {
    let mut path = report.as_os_str().to_os_string();
    path.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
    PathBuf::from(path)
}

fn recovery_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("utility-vm-recover")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::{pending_path, RecoveryStore};

    #[tokio::test]
    async fn pending_timeout_is_retryable_and_non_destructive() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private recovery directory");
        let report = temporary.path().join("container-1.json");
        let pending = pending_path(&report);
        std::fs::write(&pending, b"").expect("pending marker");
        std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600))
            .expect("private pending marker");
        let store = RecoveryStore::new(temporary.path().to_path_buf());
        let error = store
            .wait_until(&report, tokio::time::Instant::now())
            .await
            .expect_err("stuck recovery must fail");
        assert!(error.retryable);
        assert!(pending.is_file());
    }
}
