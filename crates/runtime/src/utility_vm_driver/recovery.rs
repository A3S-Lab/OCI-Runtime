use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentRecoveryReport, AGENT_RECOVERY_REPORT_MAX_BYTES, AGENT_RECOVERY_REPORT_PENDING_SUFFIX,
};
use a3s_oci_sdk::{
    ContainerRecord, ContainerTarget, Error, ErrorCode, ExitStatus, GuestSessionAttachment, Result,
};
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, Instant};

use super::atomic_publication;
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

    pub(crate) fn path(
        &self,
        target: &ContainerTarget,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<PathBuf> {
        let generation = require_exact_generation(target, "utility-vm-recovery-report-path")?;
        if let Some(session) = guest_session {
            return Ok(self.session_path(session));
        }
        Ok(self
            .directory
            .join(format!("{}-{}.json", target.id, generation.0)))
    }

    pub(super) async fn recover(
        &self,
        target: &ContainerTarget,
        record: &ContainerRecord,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<DriverRecovery> {
        let can_commit_stopped =
            *record.state.status() != a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating;
        if !can_commit_stopped {
            // The durable create operation must resume. A stopped observation
            // is not legal while its host-side create intent is still active.
            self.wait_until_settled(&self.path(target, guest_session)?)
                .await?;
            return Ok(DriverRecovery::none());
        }
        match self
            .load_exit(target, &record.config_digest, guest_session)
            .await?
        {
            Some(status) => DriverRecovery::stopped_with_exit(status),
            None => Ok(DriverRecovery::observed(DriverState::stopped())),
        }
    }

    pub(super) async fn load_exit(
        &self,
        target: &ContainerTarget,
        expected_config_digest: &str,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<Option<ExitStatus>> {
        let path = self.path(target, guest_session)?;
        let Some(metadata) = self.wait_until_settled(&path).await? else {
            return Ok(None);
        };
        let encoded = read_recovery_report(&path, &metadata).await?;
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

    pub(super) async fn remove(
        &self,
        target: &ContainerTarget,
        guest_session: Option<&GuestSessionAttachment>,
    ) -> Result<()> {
        let path = self.path(target, guest_session)?;
        remove_private_file(&path, "utility-VM recovery report").await?;
        remove_private_file(&pending_path(&path), "utility-VM recovery pending marker").await
    }

    pub(super) async fn remove_session(
        &self,
        guest_session: &GuestSessionAttachment,
    ) -> Result<()> {
        let path = self.session_path(guest_session);
        remove_private_file(&path, "utility-VM guest-session recovery report").await?;
        remove_private_file(
            &pending_path(&path),
            "utility-VM guest-session recovery pending marker",
        )
        .await
    }

    fn session_path(&self, guest_session: &GuestSessionAttachment) -> PathBuf {
        self.directory.join(format!(
            ".guest-session-{}-{}.json",
            guest_session.id(),
            guest_session.generation()
        ))
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

async fn read_recovery_report(path: &Path, metadata: &std::fs::Metadata) -> Result<Vec<u8>> {
    if !is_private_file(metadata) || metadata.len() > AGENT_RECOVERY_REPORT_MAX_BYTES as u64 {
        return Err(recovery_error(format!(
            "utility-VM recovery report must be a same-UID mode-0600 file of at most {} bytes: {}",
            AGENT_RECOVERY_REPORT_MAX_BYTES,
            path.display()
        )));
    }

    // Keep the path metadata only as an admission snapshot. The report itself
    // must be read through a no-follow handle whose identity and size still
    // match that snapshot; otherwise a replacement between `symlink_metadata`
    // and `File::open` could redirect recovery to an unrelated file.
    let mut file = atomic_publication::open_readonly_nofollow(path)
        .await
        .map_err(|error| {
            recovery_error(format!(
                "failed to open utility-VM recovery report {}: {error}",
                path.display()
            ))
        })?;
    let opened_metadata = file.metadata().await.map_err(|error| {
        recovery_error(format!(
            "failed to inspect opened utility-VM recovery report {}: {error}",
            path.display()
        ))
    })?;
    if !is_private_file(&opened_metadata)
        || opened_metadata.len() != metadata.len()
        || !atomic_publication::same_file_identity(metadata, &opened_metadata)
    {
        return Err(recovery_race_error(format!(
            "utility-VM recovery report changed while it was being opened: {}",
            path.display()
        )));
    }
    let mut encoded = Vec::with_capacity(opened_metadata.len() as usize);
    (&mut file)
        .take((AGENT_RECOVERY_REPORT_MAX_BYTES + 1) as u64)
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
    let final_metadata = file.metadata().await.map_err(|error| {
        recovery_error(format!(
            "failed to inspect utility-VM recovery report after reading {}: {error}",
            path.display()
        ))
    })?;
    if !is_private_file(&final_metadata)
        || final_metadata.len() != opened_metadata.len()
        || encoded.len() != opened_metadata.len() as usize
        || !atomic_publication::same_file_identity(&opened_metadata, &final_metadata)
    {
        return Err(recovery_race_error(format!(
            "utility-VM recovery report changed while it was being read: {}",
            path.display()
        )));
    }
    let Some(final_path_metadata) = path_metadata(path).await? else {
        return Err(recovery_race_error(format!(
            "utility-VM recovery report disappeared while it was being read: {}",
            path.display()
        )));
    };
    if !is_private_file(&final_path_metadata)
        || !atomic_publication::same_file_identity(&opened_metadata, &final_path_metadata)
    {
        return Err(recovery_race_error(format!(
            "utility-VM recovery report path changed while it was being read: {}",
            path.display()
        )));
    }
    Ok(encoded)
}

async fn remove_private_file(path: &Path, label: &str) -> Result<()> {
    let Some(metadata) = path_metadata(path).await? else {
        return Ok(());
    };
    remove_private_file_bound(path, label, &metadata).await
}

async fn remove_private_file_bound(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    if !is_private_file(metadata) {
        // Include the observed owner to make permission failures actionable
        // without weakening the same-UID invariant.
        return Err(recovery_error(format!(
            "refusing to delete non-private {label} {} owned by UID {}",
            path.display(),
            metadata.uid()
        )));
    }
    let file = match atomic_publication::open_readonly_nofollow(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(recovery_error(format!(
                "failed to open {label} {} for identity binding: {error}",
                path.display()
            )))
        }
    };
    let opened_metadata = file.metadata().await.map_err(|error| {
        recovery_error(format!(
            "failed to inspect {label} {} for identity binding: {error}",
            path.display()
        ))
    })?;
    if !is_private_file(&opened_metadata)
        || !atomic_publication::same_file_identity(metadata, &opened_metadata)
    {
        return Err(recovery_race_error(format!(
            "refusing to delete replaced {label} {}",
            path.display()
        )));
    }
    drop(file);
    let current_metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(recovery_error(format!(
                "failed to recheck {label} {} before deletion: {error}",
                path.display()
            )))
        }
    };
    if !is_private_file(&current_metadata)
        || !atomic_publication::same_file_identity(metadata, &current_metadata)
    {
        return Err(recovery_race_error(format!(
            "refusing to delete replaced {label} {}",
            path.display()
        )));
    }
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(recovery_error(format!(
            "failed to delete {label} {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn pending_path(report: &Path) -> PathBuf {
    let mut path = report.as_os_str().to_os_string();
    path.push(AGENT_RECOVERY_REPORT_PENDING_SUFFIX);
    PathBuf::from(path)
}

fn recovery_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("utility-vm-recover")
}

fn recovery_race_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unavailable, message)
        .for_operation("utility-vm-recover")
        .retryable(true)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use a3s_oci_agent_protocol::{AgentRecoveryRecord, AgentRecoveryReport};
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, ExitStatus, Generation, GuestSessionAttachment,
    };

    use super::{pending_path, read_recovery_report, remove_private_file_bound, RecoveryStore};

    fn report_bytes(target: &ContainerTarget) -> Vec<u8> {
        AgentRecoveryReport::new(vec![AgentRecoveryRecord::new(
            target.clone(),
            format!("sha256:{}", "a".repeat(64)),
            ExitStatus::exited(17).expect("valid exit status"),
        )
        .expect("valid recovery record")])
        .expect("valid recovery report")
        .to_json()
        .expect("encode recovery report")
    }

    fn private_file(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write private recovery file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("protect private recovery file");
    }

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

    #[tokio::test]
    async fn load_exit_reads_a_private_report_through_its_bound_inode() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private recovery directory");
        let target = ContainerTarget::exact(
            ContainerId::new("recovery-container").expect("container ID"),
            Generation(1),
        );
        let path = temporary.path().join("recovery-container-1.json");
        private_file(&path, &report_bytes(&target));
        let store = RecoveryStore::new(temporary.path().to_path_buf());

        let exit = store
            .load_exit(&target, &format!("sha256:{}", "a".repeat(64)), None)
            .await
            .expect("load recovery report")
            .expect("report has an exit status");
        assert_eq!(exit, ExitStatus::exited(17).expect("valid exit status"));
    }

    #[tokio::test]
    async fn report_reader_rejects_a_replaced_path_before_open() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private recovery directory");
        let path = temporary.path().join("report.json");
        private_file(&path, b"original");
        let original_metadata = std::fs::symlink_metadata(&path).expect("inspect original");
        // Keep a link to the original inode so filesystems that immediately
        // reuse inode numbers still produce a distinguishable replacement.
        let retained = temporary.path().join("retained-original");
        std::fs::hard_link(&path, &retained).expect("retain original inode");
        std::fs::remove_file(&path).expect("remove original");
        private_file(&path, b"replacement");

        let error = read_recovery_report(&path, &original_metadata)
            .await
            .expect_err("replacement must be rejected");
        assert!(error.retryable);
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            b"replacement"
        );
        std::fs::remove_file(retained).expect("remove retained original");
    }

    #[tokio::test]
    async fn report_reader_rejects_a_final_component_symlink() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private recovery directory");
        let victim = temporary.path().join("victim");
        private_file(&victim, b"victim");
        let path = temporary.path().join("report.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &path).expect("create report symlink");
        let metadata = std::fs::symlink_metadata(&path).expect("inspect report symlink");

        let error = read_recovery_report(&path, &metadata)
            .await
            .expect_err("symlink report must be rejected");
        assert!(!error.retryable);
        assert_eq!(std::fs::read(&victim).expect("read victim"), b"victim");
    }

    #[tokio::test]
    async fn cleanup_rejects_a_replaced_path_and_preserves_the_replacement() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private recovery directory");
        let path = temporary.path().join("report.json");
        private_file(&path, b"original");
        let original_metadata = std::fs::symlink_metadata(&path).expect("inspect original");
        let retained = temporary.path().join("retained-original");
        std::fs::hard_link(&path, &retained).expect("retain original inode");
        std::fs::remove_file(&path).expect("remove original");
        private_file(&path, b"replacement");

        let error = remove_private_file_bound(&path, "recovery report", &original_metadata)
            .await
            .expect_err("replacement must not be deleted");
        assert!(error.retryable);
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            b"replacement"
        );
        std::fs::remove_file(retained).expect("remove retained original");
    }

    #[test]
    fn reusable_members_resolve_one_session_scoped_recovery_report() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = RecoveryStore::new(temporary.path().to_path_buf());
        let session: GuestSessionAttachment = serde_json::from_value(serde_json::json!({
            "id": "recovery-session",
            "generation": 9,
            "trustDomain": "recovery-domain",
            "isolation": "shared-guest-kernel",
            "capacity": 2,
            "reset": "destroy-on-empty",
            "ownership": "runtime"
        }))
        .expect("valid reusable guest session");
        let alpha = ContainerTarget::exact(
            ContainerId::new("recovery-alpha").expect("container ID"),
            Generation(1),
        );
        let beta = ContainerTarget::exact(
            ContainerId::new("recovery-beta").expect("container ID"),
            Generation(4),
        );

        let alpha_path = store
            .path(&alpha, Some(&session))
            .expect("alpha report path");
        let beta_path = store.path(&beta, Some(&session)).expect("beta report path");
        assert_eq!(alpha_path, beta_path);
        assert_ne!(
            alpha_path,
            store.path(&alpha, None).expect("dedicated report path")
        );
        assert_eq!(
            alpha_path.file_name().and_then(|name| name.to_str()),
            Some(".guest-session-recovery-session-9.json")
        );
    }
}
