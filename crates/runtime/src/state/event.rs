use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{
    ContainerTarget, Error, ErrorCode, EventBatch, EventsRequest, OperationId, ProcessId, Result,
    RuntimeEvent, RuntimeEventKind, ValidateRequest,
};
use sha2::{Digest, Sha256};

use crate::fault::DurableMutation;

use super::filesystem::state_error;
use super::model::{
    StoredEventClaim, StoredEventCursor, StoredEventRecord, EVENT_CLAIM_SCHEMA_VERSION,
    EVENT_CURSOR_SCHEMA_VERSION, EVENT_RECORD_SCHEMA_VERSION,
};
use super::DurableStateStore;

mod audit;

const EVENT_CURSOR_FILE: &str = "sequence.json";

impl DurableStateStore {
    /// Poll the durable event journal, optionally waiting for a matching event.
    pub(crate) async fn events(&self, request: &EventsRequest) -> Result<EventBatch> {
        request.validate()?;
        let deadline = request
            .wait_timeout_ms
            .map(|timeout| tokio::time::Instant::now() + Duration::from_millis(timeout));
        let mut after_sequence = request.after_sequence;

        loop {
            let notified = self.event_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let batch = self
                .poll_events(&request.container, after_sequence, request.limit)
                .await?;
            if !batch.events.is_empty() || deadline.is_none() {
                return Ok(batch);
            }
            after_sequence = batch.next_sequence;

            let Some(deadline) = deadline else {
                return Ok(batch);
            };
            if deadline <= tokio::time::Instant::now() {
                return Ok(batch);
            }
            if tokio::time::timeout_at(deadline, &mut notified)
                .await
                .is_err()
            {
                return Ok(batch);
            }
        }
    }

    pub(super) async fn append_container_event(
        &self,
        identity_suffix: &str,
        target: &ContainerTarget,
        kind: RuntimeEventKind,
        attributes: BTreeMap<String, String>,
    ) -> Result<RuntimeEvent> {
        let identity = format!("container:{}:{identity_suffix}", exact_target_key(target)?);
        self.append_event(identity, target, None, None, kind, attributes)
            .await
    }

    pub(super) async fn append_process_event(
        &self,
        identity_suffix: &str,
        target: &ContainerTarget,
        process_id: &ProcessId,
        kind: RuntimeEventKind,
        attributes: BTreeMap<String, String>,
    ) -> Result<RuntimeEvent> {
        let identity = format!(
            "process:{}:{}:{identity_suffix}",
            exact_target_key(target)?,
            process_id.as_str()
        );
        self.append_event(
            identity,
            target,
            None,
            Some(process_id.clone()),
            kind,
            attributes,
        )
        .await
    }

    pub(super) async fn append_operation_event(
        &self,
        operation_id: &OperationId,
        identity_suffix: &str,
        target: &ContainerTarget,
        process_id: Option<ProcessId>,
        kind: RuntimeEventKind,
        attributes: BTreeMap<String, String>,
    ) -> Result<RuntimeEvent> {
        let identity = format!("operation:{}:{identity_suffix}", operation_id.as_str());
        self.append_event(
            identity,
            target,
            Some(operation_id.clone()),
            process_id,
            kind,
            attributes,
        )
        .await
    }

    async fn append_event(
        &self,
        identity: String,
        target: &ContainerTarget,
        operation_id: Option<OperationId>,
        process_id: Option<ProcessId>,
        kind: RuntimeEventKind,
        attributes: BTreeMap<String, String>,
    ) -> Result<RuntimeEvent> {
        exact_target_key(target)?;
        let claim_path = self.event_claim_path(&identity);
        if self.filesystem.path_exists(&claim_path).await? {
            let claim = self.load_event_claim(&claim_path, &identity).await?;
            validate_claimed_event(
                &claim.event,
                target,
                operation_id.as_ref(),
                process_id.as_ref(),
                kind,
                &attributes,
            )?;
            self.ensure_event_record(&claim.event).await?;
            self.event_notify.notify_waiters();
            return Ok(claim.event);
        }

        let mut cursor = self.load_event_cursor().await?;
        let sequence = cursor.last_sequence.checked_add(1).ok_or_else(|| {
            state_error(
                ErrorCode::ResourceExhausted,
                "append-runtime-event",
                "runtime event sequence is exhausted",
            )
        })?;
        cursor.last_sequence = sequence;
        self.write_json(
            DurableMutation::AdvanceEventSequence,
            &self.event_cursor_path(),
            &cursor,
        )
        .await?;

        let timestamp_unix_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| {
                    state_error(
                        ErrorCode::Internal,
                        "append-runtime-event",
                        format!("system clock precedes the Unix epoch: {error}"),
                    )
                })?
                .as_nanos(),
        )
        .map_err(|error| {
            state_error(
                ErrorCode::ResourceExhausted,
                "append-runtime-event",
                format!("runtime event timestamp does not fit u64: {error}"),
            )
        })?;
        let event = RuntimeEvent {
            sequence,
            timestamp_unix_ns,
            container: target.clone(),
            operation_id,
            process_id,
            kind,
            attributes,
        };
        validate_exact_event_target(&event)?;
        let claim = StoredEventClaim {
            schema_version: EVENT_CLAIM_SCHEMA_VERSION.to_string(),
            identity,
            event: event.clone(),
        };
        self.write_json(DurableMutation::ClaimRuntimeEvent, &claim_path, &claim)
            .await?;
        self.ensure_event_record(&event).await?;
        self.event_notify.notify_waiters();
        Ok(event)
    }

    async fn poll_events(
        &self,
        filter: &Option<ContainerTarget>,
        after_sequence: u64,
        limit: u32,
    ) -> Result<EventBatch> {
        let _guard = self.gate.lock().await;
        let claimed_sequences = self.repair_pending_event_records().await?;
        let cursor = self.load_event_cursor().await?;
        let directory = self.event_records_directory();
        self.filesystem
            .ensure_plain_directory(&directory, "runtime event records")
            .await?;
        let mut records = Vec::new();
        for entry in self
            .filesystem
            .read_directory(&directory, "runtime event records")
            .await?
        {
            let name = entry.into_string().map_err(|name| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "poll-runtime-events",
                    format!("runtime event directory contains a non-UTF-8 entry: {name:?}"),
                )
            })?;
            if is_transaction_file(&name) {
                continue;
            }
            let sequence = parse_event_record_name(&name)?;
            let stored: StoredEventRecord =
                self.filesystem.read_json(&directory.join(&name)).await?;
            validate_event_record(&stored, sequence, cursor.last_sequence)?;
            if !claimed_sequences.contains(&sequence) {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "poll-runtime-events",
                    format!("runtime event sequence {sequence} has no durable identity claim"),
                ));
            }
            if sequence > after_sequence {
                records.push(stored.event);
            }
        }
        records.sort_by_key(|event| event.sequence);
        if records
            .windows(2)
            .any(|window| window[0].sequence == window[1].sequence)
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "poll-runtime-events",
                "runtime event journal contains duplicate sequences",
            ));
        }

        let mut events = Vec::new();
        let mut next_sequence = after_sequence;
        for event in records {
            next_sequence = event.sequence;
            if event_matches_filter(&event, filter) {
                events.push(event);
                if events.len() == limit as usize {
                    return Ok(EventBatch {
                        events,
                        next_sequence,
                    });
                }
            }
        }
        next_sequence = next_sequence.max(cursor.last_sequence);
        Ok(EventBatch {
            events,
            next_sequence,
        })
    }

    async fn repair_pending_event_records(&self) -> Result<BTreeSet<u64>> {
        let cursor = self.load_event_cursor().await?;
        let directory = self.event_claims_directory();
        self.filesystem
            .ensure_plain_directory(&directory, "runtime event claims")
            .await?;
        let mut claimed_sequences = BTreeSet::new();
        for entry in self
            .filesystem
            .read_directory(&directory, "runtime event claims")
            .await?
        {
            let name = entry.into_string().map_err(|name| {
                state_error(
                    ErrorCode::FailedPrecondition,
                    "repair-runtime-events",
                    format!("runtime event claim directory contains a non-UTF-8 entry: {name:?}"),
                )
            })?;
            if is_transaction_file(&name) {
                continue;
            }
            let expected_hash = parse_event_claim_name(&name)?;
            let claim: StoredEventClaim = self.filesystem.read_json(&directory.join(&name)).await?;
            if claim.schema_version != EVENT_CLAIM_SCHEMA_VERSION
                || event_identity_hash(&claim.identity) != expected_hash
                || claim.event.sequence == 0
                || claim.event.sequence > cursor.last_sequence
            {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "repair-runtime-events",
                    format!("invalid durable runtime event claim {name:?}"),
                ));
            }
            validate_exact_event_target(&claim.event)?;
            validate_event_identity(&claim.identity, &claim.event)?;
            if !claimed_sequences.insert(claim.event.sequence) {
                return Err(state_error(
                    ErrorCode::FailedPrecondition,
                    "repair-runtime-events",
                    format!(
                        "runtime event sequence {} has more than one durable identity claim",
                        claim.event.sequence
                    ),
                ));
            }
            self.ensure_event_record(&claim.event).await?;
        }
        Ok(claimed_sequences)
    }

    async fn ensure_event_record(&self, event: &RuntimeEvent) -> Result<()> {
        let path = self.event_record_path(event.sequence);
        let expected = StoredEventRecord {
            schema_version: EVENT_RECORD_SCHEMA_VERSION.to_string(),
            event: event.clone(),
        };
        if self.filesystem.path_exists(&path).await? {
            let actual: StoredEventRecord = self.filesystem.read_json(&path).await?;
            if actual != expected {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "store-runtime-event",
                    format!(
                        "runtime event sequence {} is already bound to different contents",
                        event.sequence
                    ),
                ));
            }
            return Ok(());
        }
        self.write_json(DurableMutation::StoreRuntimeEvent, &path, &expected)
            .await
    }

    async fn load_event_claim(&self, path: &Path, identity: &str) -> Result<StoredEventClaim> {
        let claim: StoredEventClaim = self.filesystem.read_json(path).await?;
        if claim.schema_version != EVENT_CLAIM_SCHEMA_VERSION || claim.identity != identity {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-runtime-event-claim",
                format!("invalid durable runtime event claim {}", path.display()),
            ));
        }
        validate_exact_event_target(&claim.event)?;
        validate_event_identity(&claim.identity, &claim.event)?;
        let cursor = self.load_event_cursor().await?;
        if claim.event.sequence == 0 || claim.event.sequence > cursor.last_sequence {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-runtime-event-claim",
                format!(
                    "runtime event claim sequence {} exceeds durable cursor {}",
                    claim.event.sequence, cursor.last_sequence
                ),
            ));
        }
        Ok(claim)
    }

    async fn load_event_cursor(&self) -> Result<StoredEventCursor> {
        let path = self.event_cursor_path();
        if !self.filesystem.path_exists(&path).await? {
            return Ok(StoredEventCursor {
                schema_version: EVENT_CURSOR_SCHEMA_VERSION.to_string(),
                last_sequence: 0,
            });
        }
        let cursor: StoredEventCursor = self.filesystem.read_json(&path).await?;
        if cursor.schema_version != EVENT_CURSOR_SCHEMA_VERSION {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "load-runtime-event-cursor",
                format!("invalid durable runtime event cursor {}", path.display()),
            ));
        }
        Ok(cursor)
    }

    fn event_cursor_path(&self) -> PathBuf {
        self.root.join("events").join(EVENT_CURSOR_FILE)
    }

    fn event_records_directory(&self) -> PathBuf {
        self.root.join("events").join("records")
    }

    fn event_claims_directory(&self) -> PathBuf {
        self.root.join("events").join("keys")
    }

    fn event_record_path(&self, sequence: u64) -> PathBuf {
        self.event_records_directory()
            .join(format!("{sequence:020}.json"))
    }

    fn event_claim_path(&self, identity: &str) -> PathBuf {
        self.event_claims_directory()
            .join(format!("{}.json", event_identity_hash(identity)))
    }
}

fn exact_target_key(target: &ContainerTarget) -> Result<String> {
    let generation = target.generation.ok_or_else(|| {
        state_error(
            ErrorCode::InvalidArgument,
            "append-runtime-event",
            "runtime events require an exact container generation",
        )
    })?;
    if generation.0 == 0 {
        return Err(state_error(
            ErrorCode::InvalidArgument,
            "append-runtime-event",
            "runtime events require a nonzero container generation",
        ));
    }
    Ok(format!("{}:{}", target.id.as_str(), generation.0))
}

fn validate_claimed_event(
    event: &RuntimeEvent,
    target: &ContainerTarget,
    operation_id: Option<&OperationId>,
    process_id: Option<&ProcessId>,
    kind: RuntimeEventKind,
    attributes: &BTreeMap<String, String>,
) -> Result<()> {
    let operation_matches = event.operation_id.as_ref() == operation_id
        || (event.operation_id.is_none()
            && operation_id.is_some_and(|operation_id| {
                event.attributes.get("operation-id").map(String::as_str)
                    == Some(operation_id.as_str())
            }));
    if &event.container == target
        && operation_matches
        && event.process_id.as_ref() == process_id
        && event.kind == kind
        && &event.attributes == attributes
    {
        Ok(())
    } else {
        Err(state_error(
            ErrorCode::Conflict,
            "append-runtime-event",
            "runtime event identity was reused with different contents",
        ))
    }
}

fn validate_event_record(
    stored: &StoredEventRecord,
    sequence: u64,
    last_sequence: u64,
) -> Result<()> {
    if stored.schema_version != EVENT_RECORD_SCHEMA_VERSION
        || sequence == 0
        || stored.event.sequence != sequence
        || sequence > last_sequence
    {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "poll-runtime-events",
            format!("invalid durable runtime event record at sequence {sequence}"),
        ));
    }
    validate_exact_event_target(&stored.event)
}

fn validate_exact_event_target(event: &RuntimeEvent) -> Result<()> {
    exact_target_key(&event.container)?;
    if event.sequence == 0 || event.timestamp_unix_ns == 0 {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "validate-runtime-event",
            "runtime event sequence and timestamp must be nonzero",
        ));
    }
    if let Some(operation_id) = &event.operation_id {
        if event.attributes.get("operation-id").map(String::as_str) != Some(operation_id.as_str()) {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "validate-runtime-event",
                "typed runtime event operation identity does not match its compatibility attribute",
            ));
        }
    }
    match event.kind {
        RuntimeEventKind::ProcessCreated
        | RuntimeEventKind::ProcessStarted
        | RuntimeEventKind::ProcessExited
            if event.process_id.is_none() =>
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "validate-runtime-event",
                "process runtime event has no process identity",
            ));
        }
        RuntimeEventKind::ContainerCreating
        | RuntimeEventKind::ContainerCreated
        | RuntimeEventKind::ContainerStarted
        | RuntimeEventKind::ContainerStopped
        | RuntimeEventKind::ContainerDeleted
        | RuntimeEventKind::ContainerPaused
        | RuntimeEventKind::ContainerResumed
        | RuntimeEventKind::ResourcesUpdated
            if event.process_id.is_some() =>
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "validate-runtime-event",
                "container runtime event unexpectedly has a process identity",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn validate_event_identity(identity: &str, event: &RuntimeEvent) -> Result<()> {
    let Some(operation_identity) = identity.strip_prefix("operation:") else {
        if event.operation_id.is_some() || event.attributes.contains_key("operation-id") {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "validate-runtime-event",
                "non-operation runtime event carries an operation identity projection",
            ));
        }
        return Ok(());
    };
    let Some((operation_id, suffix)) = operation_identity.rsplit_once(':') else {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "validate-runtime-event",
            "operation runtime event has an invalid durable identity",
        ));
    };
    if suffix.is_empty() {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "validate-runtime-event",
            "operation runtime event has an empty identity suffix",
        ));
    }
    OperationId::new(operation_id.to_string()).map_err(|error| {
        state_error(
            ErrorCode::FailedPrecondition,
            "validate-runtime-event",
            format!("operation runtime event has an invalid operation identity: {error}"),
        )
    })?;
    let observed = event
        .operation_id
        .as_ref()
        .map(OperationId::as_str)
        .or_else(|| event.attributes.get("operation-id").map(String::as_str));
    if observed != Some(operation_id) {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "validate-runtime-event",
            "operation runtime event does not match its durable identity",
        ));
    }
    Ok(())
}

fn event_matches_filter(event: &RuntimeEvent, filter: &Option<ContainerTarget>) -> bool {
    filter.as_ref().is_none_or(|filter| {
        filter.id == event.container.id
            && filter
                .generation
                .is_none_or(|generation| event.container.generation == Some(generation))
    })
}

fn event_identity_hash(identity: &str) -> String {
    Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_event_record_name(name: &str) -> Result<u64> {
    let value = name
        .strip_suffix(".json")
        .ok_or_else(|| invalid_event_entry("runtime event record", name))?;
    if value.len() != 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_event_entry("runtime event record", name));
    }
    value
        .parse::<u64>()
        .map_err(|_| invalid_event_entry("runtime event record", name))
}

fn parse_event_claim_name(name: &str) -> Result<String> {
    let value = name
        .strip_suffix(".json")
        .ok_or_else(|| invalid_event_entry("runtime event claim", name))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_event_entry("runtime event claim", name));
    }
    Ok(value.to_string())
}

fn is_transaction_file(name: &str) -> bool {
    name.starts_with('.') && name.ends_with(".next")
}

fn invalid_event_entry(label: &str, name: &str) -> Error {
    state_error(
        ErrorCode::FailedPrecondition,
        "poll-runtime-events",
        format!("{label} directory contains invalid entry {name:?}"),
    )
}
