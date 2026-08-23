use std::path::Path;
use std::time::Duration;

use a3s_oci_sdk::ProcessRecord;
use serde::Deserialize;

use crate::support::{qualification_error, TestResult};

#[derive(Debug, Deserialize)]
struct MetadataDocument {
    schema_version: u64,
    #[serde(default)]
    exec_sequence: u64,
    execs: Vec<ExecEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ExecEvidence {
    exec_id: String,
    #[serde(default)]
    incarnation: u64,
    stage: String,
    #[serde(default)]
    record: Option<ProcessRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataEvidence {
    schema_version: u64,
    exec_sequence: u64,
    exec: ExecEvidence,
}

pub(super) async fn wait_for_starting(
    bundle: &Path,
    exec_id: &str,
    start_call: &mut tokio::task::JoinHandle<TestResult<()>>,
) -> TestResult<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let evidence = read(bundle, exec_id).await?;
        if matches(&evidence, "starting", None) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(qualification_error(format!(
                "Exec Start did not persist schema-9 incarnation-1 starting metadata before reaching the suspended Runtime executor: {evidence:?}"
            ))
            .into());
        }
        tokio::select! {
            result = &mut *start_call => {
                return match result {
                    Ok(Ok(())) => Err(qualification_error(
                        "Exec Start returned before its durable request reached the suspended Runtime executor",
                    ).into()),
                    Ok(Err(error)) => Err(qualification_error(format!(
                        "Exec Start failed before its durable request reached the suspended Runtime executor: {error}"
                    )).into()),
                    Err(error) => Err(qualification_error(format!(
                        "Exec Start task failed before its durable request reached the suspended Runtime executor: {error}"
                    )).into()),
                };
            }
            () = tokio::time::sleep(Duration::from_millis(10).min(remaining)) => {}
        }
    }
}

pub(super) async fn require(
    bundle: &Path,
    exec_id: &str,
    stage: &str,
    record: Option<&ProcessRecord>,
    context: &str,
) -> TestResult<()> {
    let evidence = read(bundle, exec_id).await?;
    if !matches(&evidence, stage, record) {
        return Err(qualification_error(format!(
            "committed Exec metadata {context} was {evidence:?}; expected schema 9, exec sequence/incarnation 1, stage {stage:?}, and record {record:?}"
        ))
        .into());
    }
    Ok(())
}

fn matches(evidence: &MetadataEvidence, stage: &str, record: Option<&ProcessRecord>) -> bool {
    evidence.schema_version == 9
        && evidence.exec_sequence == 1
        && evidence.exec.incarnation == 1
        && evidence.exec.stage == stage
        && evidence.exec.record.as_ref() == record
}

async fn read(bundle: &Path, exec_id: &str) -> TestResult<MetadataEvidence> {
    let path = bundle.join("a3s-oci-shim-v1.json");
    let document: MetadataDocument = serde_json::from_slice(
        &tokio::fs::read(&path)
            .await
            .map_err(|error| qualification_error(format!("read shim metadata: {error}")))?,
    )
    .map_err(|error| qualification_error(format!("decode shim metadata: {error}")))?;
    let exec = document
        .execs
        .into_iter()
        .find(|exec| exec.exec_id == exec_id)
        .ok_or_else(|| qualification_error(format!("shim metadata omitted exec {exec_id}")))?;
    Ok(MetadataEvidence {
        schema_version: document.schema_version,
        exec_sequence: document.exec_sequence,
        exec,
    })
}
