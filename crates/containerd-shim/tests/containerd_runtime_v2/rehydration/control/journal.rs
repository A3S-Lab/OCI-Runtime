use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::canonical_json_bytes;
use a3s_oci_sdk::oci_spec::runtime::LinuxResources;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::ControlKind;
use crate::support::{qualification_error, TestResult};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingControlEvidence {
    sequence: u64,
    kind: String,
    #[serde(default)]
    request_digest: Option<String>,
    #[serde(default)]
    resources: Option<LinuxResources>,
}

#[derive(Debug)]
pub(super) struct ControlJournalEvidence {
    pub(super) schema_version: u64,
    pub(super) completed_sequence: u64,
    pub(super) pending: Option<PendingControlEvidence>,
    pub(super) last_update_digest: Option<String>,
}

pub(super) async fn wait_for_pending_control(
    bundle: &Path,
    sequence: u64,
    kind: ControlKind,
    resources: Option<&LinuxResources>,
    control_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let digest = resources.map(update_digest).transpose()?;
    let expected = PendingControlEvidence {
        sequence,
        kind: kind.journal_kind().to_string(),
        request_digest: digest,
        resources: resources.cloned(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read_control_journal(bundle).await?;
        if evidence.schema_version == 10
            && evidence.completed_sequence.checked_add(1) == Some(sequence)
            && evidence.pending.as_ref() == Some(&expected)
        {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "task control journal did not retain pending {} sequence {sequence}: {evidence:?}",
                kind.name()
            ))
            .into());
        }
        tokio::select! {
            result = &mut *control_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(format!(
                        "{} returned before its durable request reached the suspended Runtime",
                        kind.name()
                    )).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "{} failed before its durable request reached the suspended Runtime: {error}",
                        kind.name()
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "{} task failed before its durable request reached the suspended Runtime: {error}",
                        kind.name()
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

pub(super) async fn assert_completed(
    bundle: &Path,
    sequence: u64,
    update_digest: Option<&str>,
) -> TestResult<()> {
    let evidence = read_control_journal(bundle).await?;
    if evidence.schema_version != 10
        || evidence.completed_sequence != sequence
        || evidence.pending.is_some()
        || evidence.last_update_digest.as_deref() != update_digest
    {
        return Err(qualification_error(format!(
            "task control journal did not complete sequence {sequence}: {evidence:?}"
        ))
        .into());
    }
    Ok(())
}

pub(super) async fn read_control_journal(bundle: &Path) -> TestResult<ControlJournalEvidence> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let document: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
    )
    .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    Ok(ControlJournalEvidence {
        schema_version: document["schema_version"]
            .as_u64()
            .ok_or_else(|| qualification_error("shim metadata omitted schema_version"))?,
        completed_sequence: document["control_sequence"].as_u64().unwrap_or(0),
        pending: serde_json::from_value(
            document
                .get("pending_control")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|error| {
            qualification_error(format!("decode shim metadata pending control: {error}"))
        })?,
        last_update_digest: document["last_update_digest"].as_str().map(str::to_string),
    })
}

pub(super) fn update_digest(resources: &LinuxResources) -> TestResult<String> {
    let bytes = canonical_json_bytes(resources).map_err(|error| {
        qualification_error(format!("canonicalize rehydrated Update resources: {error}"))
    })?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}
