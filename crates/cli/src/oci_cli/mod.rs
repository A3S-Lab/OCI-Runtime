mod config;
mod journal;
mod signal;

use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, State};
use a3s_oci_sdk::{
    ContainerId, ContainerRecord, ContainerTarget, CreateAttachments, CreateRequest, DeleteMode,
    DeleteRequest, Error, ErrorCode, IsolationRequest, KillRequest, OciBundle, OperationContext,
    OperationId, ProcessIo, Result, RuntimeClient, Signal, StartRequest, StateRequest,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use self::config::AdapterConfig;
use self::journal::{
    LifecycleJournal, LockedJournal, PendingDelete, PendingKill, PendingOperation,
};

pub(super) async fn create(
    id: String,
    bundle: PathBuf,
    pid_file: Option<PathBuf>,
    console_socket: Option<PathBuf>,
) -> Result<()> {
    reject_untransported_descriptors(console_socket.as_deref())?;
    let config = AdapterConfig::from_environment(true)?;
    let isolation = config
        .isolation
        .clone()
        .ok_or_else(|| internal("create configuration lost its explicit isolation request"))?;
    let bundle = OciBundle::load(bundle).await?;
    reject_terminal_bundle(&bundle)?;
    let pid_file = absolute_optional_path(pid_file)?;
    let client = RuntimeClient::connect(&config.endpoint).await?;
    Adapter::new(config.state_root, client)
        .create(ContainerId::new(id)?, bundle, isolation, pid_file)
        .await
}

pub(super) async fn state(id: String) -> Result<State> {
    let config = AdapterConfig::from_environment(false)?;
    let client = RuntimeClient::connect(&config.endpoint).await?;
    Adapter::new(config.state_root, client)
        .state(ContainerId::new(id)?)
        .await
}

pub(super) async fn start(id: String) -> Result<()> {
    let config = AdapterConfig::from_environment(false)?;
    let client = RuntimeClient::connect(&config.endpoint).await?;
    Adapter::new(config.state_root, client)
        .start(ContainerId::new(id)?)
        .await
}

pub(super) async fn kill(id: String, signal: String, all: bool) -> Result<()> {
    let signal = signal::parse(&signal)?;
    let config = AdapterConfig::from_environment(false)?;
    let client = RuntimeClient::connect(&config.endpoint).await?;
    Adapter::new(config.state_root, client)
        .kill(ContainerId::new(id)?, signal, all)
        .await
}

pub(super) async fn delete(id: String, force: bool) -> Result<()> {
    let config = AdapterConfig::from_environment(false)?;
    let client = RuntimeClient::connect(&config.endpoint).await?;
    Adapter::new(config.state_root, client)
        .delete(
            ContainerId::new(id)?,
            if force {
                DeleteMode::Force
            } else {
                DeleteMode::StoppedOnly
            },
        )
        .await
}

struct Adapter {
    state_root: PathBuf,
    client: RuntimeClient,
}

impl Adapter {
    const fn new(state_root: PathBuf, client: RuntimeClient) -> Self {
        Self { state_root, client }
    }

    async fn create(
        &self,
        id: ContainerId,
        bundle: OciBundle,
        isolation: IsolationRequest,
        pid_file: Option<PathBuf>,
    ) -> Result<()> {
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())?;
        let attachments_digest = attachments.digest()?;
        let mut journal = LockedJournal::open(self.state_root.clone(), id.clone(), true).await?;
        if let Some(lifecycle) = &journal.state().lifecycle {
            if lifecycle.create_acknowledged {
                return Err(already_exists(&id));
            }
            validate_create_retry(
                lifecycle,
                &bundle,
                &attachments_digest,
                &isolation,
                pid_file.as_deref(),
            )?;
        } else {
            let incarnation = journal.state().next_incarnation;
            let next_incarnation = incarnation
                .checked_add(1)
                .ok_or_else(|| internal("OCI CLI lifecycle incarnation overflowed"))?;
            let isolation_json = serde_json::to_string(&isolation).map_err(|error| {
                internal(format!("failed to encode isolation request: {error}"))
            })?;
            let create_operation_id = operation_id(
                &id,
                incarnation,
                "create",
                0,
                &[bundle.config_digest(), &attachments_digest, &isolation_json],
            )?;
            journal.state_mut().next_incarnation = next_incarnation;
            journal.state_mut().lifecycle = Some(LifecycleJournal {
                incarnation,
                bundle_directory: bundle.directory().to_path_buf(),
                config_digest: bundle.config_digest().to_string(),
                attachments_digest: attachments_digest.clone(),
                isolation: isolation.clone(),
                pid_file: pid_file.clone(),
                create_operation_id,
                create_acknowledged: false,
                target: None,
                next_operation_sequence: 1,
                start_acknowledged: false,
                pending_start: None,
                pending_kill: None,
                pending_delete: None,
            });
            journal = journal.persist().await?;
        }

        let operation_id = journal
            .state()
            .lifecycle
            .as_ref()
            .ok_or_else(|| internal("create journal lost its active lifecycle"))?
            .create_operation_id
            .clone();
        let request = CreateRequest {
            context: OperationContext::new(operation_id),
            id: id.clone(),
            bundle,
            isolation,
            attachments,
        };
        let record = match self.client.create(request).await {
            Ok(record) => record,
            Err(error) => {
                return self.reconcile_create_error(journal, error).await;
            }
        };
        let target = validate_created_record(&record, active_lifecycle(journal.state())?, &id)?;
        if let Some(path) = pid_file.as_deref() {
            write_pid_file(path, &record).await?;
        }
        let lifecycle = active_lifecycle_mut(journal.state_mut())?;
        lifecycle.target = Some(target);
        lifecycle.create_acknowledged = true;
        journal.persist().await?;
        Ok(())
    }

    async fn state(&self, id: ContainerId) -> Result<State> {
        let journal = LockedJournal::open(self.state_root.clone(), id, false).await?;
        let (journal, target) = self.resolve_target(journal).await?;
        let record = self
            .client
            .state(StateRequest {
                target: target.clone(),
            })
            .await?;
        validate_record(
            &record,
            active_lifecycle(journal.state())?,
            &target.id,
            Some(&target),
        )?;
        Ok(record.state)
    }

    async fn start(&self, id: ContainerId) -> Result<()> {
        let journal = LockedJournal::open(self.state_root.clone(), id, false).await?;
        let (mut journal, target) = self.resolve_target(journal).await?;
        if active_lifecycle(journal.state())?.start_acknowledged {
            return Err(failed_precondition(
                "container init process has already been started",
                "start",
            ));
        }

        let operation =
            if let Some(pending) = active_lifecycle(journal.state())?.pending_start.clone() {
                pending
            } else {
                let state = self
                    .client
                    .state(StateRequest {
                        target: target.clone(),
                    })
                    .await?;
                validate_record(
                    &state,
                    active_lifecycle(journal.state())?,
                    &target.id,
                    Some(&target),
                )?;
                if *state.state.status() != ContainerState::Created {
                    return Err(failed_precondition(
                        format!(
                            "container {} is {}; start requires created",
                            target.id,
                            state.state.status()
                        ),
                        "start",
                    ));
                }
                let pending = allocate_operation(
                    active_lifecycle_mut(journal.state_mut())?,
                    &target.id,
                    "start",
                    &[],
                )?;
                active_lifecycle_mut(journal.state_mut())?.pending_start = Some(pending.clone());
                journal = journal.persist().await?;
                pending
            };

        let record = match self
            .client
            .start(StartRequest {
                context: OperationContext::new(operation.operation_id),
                target: target.clone(),
            })
            .await
        {
            Ok(record) => record,
            Err(error) => {
                if !error.retryable {
                    active_lifecycle_mut(journal.state_mut())?.pending_start = None;
                    journal.persist().await?;
                }
                return Err(error);
            }
        };
        validate_record(
            &record,
            active_lifecycle(journal.state())?,
            &target.id,
            Some(&target),
        )?;
        if *record.state.status() != ContainerState::Running {
            return Err(conflict(format!(
                "start returned state {}; expected running",
                record.state.status()
            )));
        }
        let lifecycle = active_lifecycle_mut(journal.state_mut())?;
        lifecycle.pending_start = None;
        lifecycle.start_acknowledged = true;
        journal.persist().await?;
        Ok(())
    }

    async fn kill(&self, id: ContainerId, signal: Signal, all: bool) -> Result<()> {
        let journal = LockedJournal::open(self.state_root.clone(), id, false).await?;
        let (mut journal, target) = self.resolve_target(journal).await?;
        let operation = if let Some(pending) =
            active_lifecycle(journal.state())?.pending_kill.clone()
        {
            if pending.signal != signal.get() || pending.all != all {
                return Err(failed_precondition(
                    "a different kill request remains ambiguous; retry its exact signal and --all value",
                    "kill",
                ));
            }
            pending.operation
        } else {
            let state = self
                .client
                .state(StateRequest {
                    target: target.clone(),
                })
                .await?;
            validate_record(
                &state,
                active_lifecycle(journal.state())?,
                &target.id,
                Some(&target),
            )?;
            if !matches!(
                *state.state.status(),
                ContainerState::Created | ContainerState::Running
            ) {
                return Err(failed_precondition(
                    format!(
                        "container {} is {}; kill requires created or running",
                        target.id,
                        state.state.status()
                    ),
                    "kill",
                ));
            }
            let signal_value = signal.get().to_string();
            let all_value = all.to_string();
            let pending = allocate_operation(
                active_lifecycle_mut(journal.state_mut())?,
                &target.id,
                "kill",
                &[&signal_value, &all_value],
            )?;
            active_lifecycle_mut(journal.state_mut())?.pending_kill = Some(PendingKill {
                operation: pending.clone(),
                signal: signal.get(),
                all,
            });
            journal = journal.persist().await?;
            pending
        };

        let record = match self
            .client
            .kill(KillRequest {
                context: OperationContext::new(operation.operation_id),
                target: target.clone(),
                signal,
                all,
            })
            .await
        {
            Ok(record) => record,
            Err(error) => {
                if !error.retryable {
                    active_lifecycle_mut(journal.state_mut())?.pending_kill = None;
                    journal.persist().await?;
                }
                return Err(error);
            }
        };
        validate_record(
            &record,
            active_lifecycle(journal.state())?,
            &target.id,
            Some(&target),
        )?;
        active_lifecycle_mut(journal.state_mut())?.pending_kill = None;
        journal.persist().await?;
        Ok(())
    }

    async fn delete(&self, id: ContainerId, mode: DeleteMode) -> Result<()> {
        let journal = LockedJournal::open(self.state_root.clone(), id, false).await?;
        let (mut journal, target) = self.resolve_target(journal).await?;
        let (operation, replaying) =
            if let Some(pending) = active_lifecycle(journal.state())?.pending_delete.clone() {
                if pending.mode != mode {
                    return Err(failed_precondition(
                        "a delete request with a different force mode remains ambiguous",
                        "delete",
                    ));
                }
                (pending.operation, true)
            } else {
                let state = self
                    .client
                    .state(StateRequest {
                        target: target.clone(),
                    })
                    .await?;
                validate_record(
                    &state,
                    active_lifecycle(journal.state())?,
                    &target.id,
                    Some(&target),
                )?;
                let mode_value = match mode {
                    DeleteMode::StoppedOnly => "stopped-only",
                    DeleteMode::Force => "force",
                };
                let pending = allocate_operation(
                    active_lifecycle_mut(journal.state_mut())?,
                    &target.id,
                    "delete",
                    &[mode_value],
                )?;
                active_lifecycle_mut(journal.state_mut())?.pending_delete = Some(PendingDelete {
                    operation: pending.clone(),
                    mode,
                });
                journal = journal.persist().await?;
                (pending, false)
            };

        match self
            .client
            .delete(DeleteRequest {
                context: OperationContext::new(operation.operation_id),
                target,
                mode,
            })
            .await
        {
            Ok(()) => retire_lifecycle(journal).await,
            Err(error) if replaying && error.code == ErrorCode::NotFound => {
                retire_lifecycle(journal).await
            }
            Err(error) => {
                if !error.retryable {
                    active_lifecycle_mut(journal.state_mut())?.pending_delete = None;
                    journal.persist().await?;
                }
                Err(error)
            }
        }
    }

    async fn resolve_target(
        &self,
        mut journal: LockedJournal,
    ) -> Result<(LockedJournal, ContainerTarget)> {
        if let Some(target) = active_lifecycle(journal.state())?.target.clone() {
            return Ok((journal, target));
        }
        let id = journal.state().container_id.clone();
        let record = self
            .client
            .state(StateRequest {
                target: ContainerTarget::current(id.clone()),
            })
            .await?;
        let target = validate_record(&record, active_lifecycle(journal.state())?, &id, None)?;
        let lifecycle = active_lifecycle_mut(journal.state_mut())?;
        lifecycle.target = Some(target.clone());
        if *record.state.status() != ContainerState::Creating {
            lifecycle.create_acknowledged = true;
        }
        journal = journal.persist().await?;
        Ok((journal, target))
    }

    async fn reconcile_create_error(&self, mut journal: LockedJournal, error: Error) -> Result<()> {
        if error.retryable {
            return Err(error);
        }
        if error.code == ErrorCode::AlreadyExists {
            journal.state_mut().lifecycle = None;
            journal.persist().await?;
            return Err(error);
        }

        let id = journal.state().container_id.clone();
        match self
            .client
            .state(StateRequest {
                target: ContainerTarget::current(id.clone()),
            })
            .await
        {
            Ok(record) => {
                if let Ok(target) =
                    validate_record(&record, active_lifecycle(journal.state())?, &id, None)
                {
                    active_lifecycle_mut(journal.state_mut())?.target = Some(target);
                    journal.persist().await?;
                }
            }
            Err(state_error) if state_error.code == ErrorCode::NotFound => {
                journal.state_mut().lifecycle = None;
                journal.persist().await?;
            }
            Err(_) => {}
        }
        Err(error)
    }
}

async fn retire_lifecycle(mut journal: LockedJournal) -> Result<()> {
    journal.state_mut().lifecycle = None;
    journal.persist().await?;
    Ok(())
}

fn validate_create_retry(
    lifecycle: &LifecycleJournal,
    bundle: &OciBundle,
    attachments_digest: &str,
    isolation: &IsolationRequest,
    pid_file: Option<&Path>,
) -> Result<()> {
    if lifecycle.bundle_directory != bundle.directory()
        || lifecycle.config_digest != bundle.config_digest()
        || lifecycle.attachments_digest != attachments_digest
        || &lifecycle.isolation != isolation
        || lifecycle.pid_file.as_deref() != pid_file
    {
        return Err(failed_precondition(
            "an unresolved create must be retried with the exact bundle, isolation, and PID-file request",
            "create",
        ));
    }
    Ok(())
}

fn validate_created_record(
    record: &ContainerRecord,
    lifecycle: &LifecycleJournal,
    expected_id: &ContainerId,
) -> Result<ContainerTarget> {
    let target = validate_record(record, lifecycle, expected_id, None)?;
    if *record.state.status() != ContainerState::Created {
        return Err(conflict(format!(
            "create returned state {}; expected created",
            record.state.status()
        )));
    }
    if record.state.pid().is_none_or(|pid| pid <= 0) {
        return Err(conflict(
            "create returned no positive container init PID".to_string(),
        ));
    }
    Ok(target)
}

fn validate_record(
    record: &ContainerRecord,
    lifecycle: &LifecycleJournal,
    expected_id: &ContainerId,
    expected_target: Option<&ContainerTarget>,
) -> Result<ContainerTarget> {
    if record.state.id() != expected_id.as_str()
        || expected_target.is_some_and(|target| target.id != *expected_id)
        || record.state.bundle() != &lifecycle.bundle_directory
        || record.config_digest != lifecycle.config_digest
        || record.attachments_digest.as_deref() != Some(lifecycle.attachments_digest.as_str())
        || record.isolation != lifecycle.isolation.class()
        || record.generation.0 == 0
        || expected_target.is_some_and(|target| target.generation != Some(record.generation))
    {
        return Err(conflict(
            "Host Service response does not match the journaled exact container lifecycle"
                .to_string(),
        ));
    }
    Ok(ContainerTarget::exact(
        ContainerId::new(record.state.id().to_string())?,
        record.generation,
    ))
}

fn allocate_operation(
    lifecycle: &mut LifecycleJournal,
    id: &ContainerId,
    action: &str,
    details: &[&str],
) -> Result<PendingOperation> {
    let sequence = lifecycle.next_operation_sequence;
    lifecycle.next_operation_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| internal("OCI CLI operation sequence overflowed"))?;
    Ok(PendingOperation {
        sequence,
        operation_id: operation_id(id, lifecycle.incarnation, action, sequence, details)?,
    })
}

fn operation_id(
    id: &ContainerId,
    incarnation: u64,
    action: &str,
    sequence: u64,
    details: &[&str],
) -> Result<OperationId> {
    let mut digest = Sha256::new();
    for value in [
        "a3s.oci.cli-operation.v1",
        id.as_str(),
        action,
        &incarnation.to_string(),
        &sequence.to_string(),
    ]
    .into_iter()
    .chain(details.iter().copied())
    {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    OperationId::new(format!("oci-cli-{action}-{:x}", digest.finalize()))
}

fn active_lifecycle(snapshot: &journal::JournalSnapshot) -> Result<&LifecycleJournal> {
    snapshot
        .lifecycle
        .as_ref()
        .ok_or_else(|| not_found(&snapshot.container_id))
}

fn active_lifecycle_mut(snapshot: &mut journal::JournalSnapshot) -> Result<&mut LifecycleJournal> {
    let id = snapshot.container_id.clone();
    snapshot.lifecycle.as_mut().ok_or_else(|| not_found(&id))
}

async fn write_pid_file(path: &Path, record: &ContainerRecord) -> Result<()> {
    let pid = record
        .state
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| conflict("created container has no positive init PID".to_string()))?;
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .await
        .map_err(|error| pid_file_error(path, "open", error))?;
    file.write_all(pid.to_string().as_bytes())
        .await
        .map_err(|error| pid_file_error(path, "write", error))?;
    file.sync_all()
        .await
        .map_err(|error| pid_file_error(path, "synchronize", error))
}

fn reject_untransported_descriptors(console_socket: Option<&Path>) -> Result<()> {
    if let Some(path) = console_socket {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "OCI terminal console handoff is not implemented for Host Service endpoint adapters: {}",
                path.display()
            ),
        )
        .for_operation("create"));
    }
    if let Some(value) = std::env::var_os("LISTEN_FDS") {
        let value = value.into_string().map_err(|_| {
            Error::new(
                ErrorCode::InvalidArgument,
                "LISTEN_FDS must be valid Unicode",
            )
            .for_operation("create")
        })?;
        let count = value.parse::<u32>().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("LISTEN_FDS is not an unsigned integer: {error}"),
            )
            .for_operation("create")
        })?;
        if count != 0 {
            return Err(Error::new(
                ErrorCode::Unsupported,
                "OCI LISTEN_FDS descriptor transport is not implemented by the CLI adapter",
            )
            .for_operation("create"));
        }
    }
    Ok(())
}

fn reject_terminal_bundle(bundle: &OciBundle) -> Result<()> {
    if bundle
        .spec()
        .process()
        .as_ref()
        .is_some_and(|process| process.terminal().unwrap_or(false))
    {
        return Err(Error::new(
            ErrorCode::Unsupported,
            "terminal OCI bundles require console-socket descriptor transport, which is not implemented by the CLI adapter",
        )
        .for_operation("create"));
    }
    Ok(())
}

fn absolute_optional_path(path: Option<PathBuf>) -> Result<Option<PathBuf>> {
    path.map(|path| {
        if path.is_absolute() {
            Ok(path)
        } else {
            std::env::current_dir()
                .map(|current| current.join(&path))
                .map_err(|error| {
                    Error::new(
                        ErrorCode::Internal,
                        format!(
                            "failed to resolve relative PID-file path {}: {error}",
                            path.display()
                        ),
                    )
                    .for_operation("create")
                })
        }
    })
    .transpose()
}

fn pid_file_error(path: &Path, action: &str, error: std::io::Error) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!(
            "failed to {action} OCI container PID file {}: {error}",
            path.display()
        ),
    )
    .for_operation("create")
}

fn already_exists(id: &ContainerId) -> Error {
    Error::new(
        ErrorCode::AlreadyExists,
        format!("container {id} already exists"),
    )
    .for_operation("create")
}

fn not_found(id: &ContainerId) -> Error {
    Error::new(
        ErrorCode::NotFound,
        format!("container {id} does not exist"),
    )
    .for_operation("oci-cli")
}

fn failed_precondition(message: impl Into<String>, operation: &'static str) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation(operation)
}

fn conflict(message: String) -> Error {
    Error::new(ErrorCode::Conflict, message).for_operation("oci-cli")
}

fn internal(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, message).for_operation("oci-cli")
}

#[cfg(all(test, any(unix, windows)))]
mod tests;
