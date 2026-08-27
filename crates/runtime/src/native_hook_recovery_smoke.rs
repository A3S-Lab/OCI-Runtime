use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::ContainerTarget;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Instant};

use crate::{native_linux_recovery_resume, NativeLinuxRecoverySmokeReport};

/// Versioned input captured while the interrupted Hook is still alive.
pub const NATIVE_LINUX_HOOK_OWNER_DEATH_EVIDENCE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-hook-owner-death-evidence.v1";
/// Versioned real-host evidence for Hook cleanup across Native owner death.
pub const NATIVE_LINUX_HOOK_OWNER_DEATH_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-hook-owner-death-smoke.v1";

const PROCESS_TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// PID-reuse-safe identity for one process in the interrupted Hook tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLinuxProcessIdentity {
    pub pid: u32,
    pub process_group_id: u32,
    pub start_time_ticks: u64,
}

/// Exact owner and Hook process identities captured before owner termination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLinuxHookOwnerDeathEvidence {
    pub schema_version: String,
    pub target: ContainerTarget,
    pub owner: NativeLinuxProcessIdentity,
    pub hook_leader: NativeLinuxProcessIdentity,
    pub hook_descendant: NativeLinuxProcessIdentity,
}

impl NativeLinuxHookOwnerDeathEvidence {
    fn validate(&self, target: &ContainerTarget) -> Result<(), String> {
        if self.schema_version != NATIVE_LINUX_HOOK_OWNER_DEATH_EVIDENCE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported Hook owner-death evidence schema {:?}",
                self.schema_version
            ));
        }
        if &self.target != target || target.generation.is_none() {
            return Err(
                "Hook owner-death evidence is not bound to the exact recovery target".into(),
            );
        }
        for (role, identity) in [
            ("owner", self.owner),
            ("Hook leader", self.hook_leader),
            ("Hook descendant", self.hook_descendant),
        ] {
            if identity.pid == 0 || identity.process_group_id == 0 || identity.start_time_ticks == 0
            {
                return Err(format!("{role} process identity is incomplete"));
            }
        }
        if self.owner.pid == self.hook_leader.pid
            || self.owner.pid == self.hook_descendant.pid
            || self.hook_leader.pid == self.hook_descendant.pid
        {
            return Err("Hook owner-death evidence contains duplicate process IDs".into());
        }
        if self.hook_leader.process_group_id != self.hook_leader.pid
            || self.hook_descendant.process_group_id != self.hook_leader.pid
        {
            return Err(
                "Hook leader and descendant were not captured in one private process group".into(),
            );
        }
        Ok(())
    }
}

/// Real-host evidence that owner death terminated the complete Hook process
/// group and that a replacement owner completed stopped-only reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxHookOwnerDeathSmokeReport {
    pub schema_version: String,
    pub status: CapabilityStatus,
    pub platform: HostPlatform,
    pub target: ContainerTarget,
    pub evidence: NativeLinuxHookOwnerDeathEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement_owner: Option<NativeLinuxProcessIdentity>,
    pub evidence_validated: bool,
    pub owner_replaced: bool,
    pub owner_terminated: bool,
    pub hook_leader_terminated: bool,
    pub hook_descendant_terminated: bool,
    pub recovery: NativeLinuxRecoverySmokeReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxHookOwnerDeathSmokeReport {
    fn initial(
        target: ContainerTarget,
        evidence: NativeLinuxHookOwnerDeathEvidence,
        recovery: NativeLinuxRecoverySmokeReport,
    ) -> Self {
        Self {
            schema_version: NATIVE_LINUX_HOOK_OWNER_DEATH_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            platform: HostPlatform::Linux,
            target,
            evidence,
            replacement_owner: None,
            evidence_validated: false,
            owner_replaced: false,
            owner_terminated: false,
            hook_leader_terminated: false,
            hook_descendant_terminated: false,
            recovery,
            reason: None,
        }
    }

    fn contract_complete(&self) -> bool {
        self.evidence_validated
            && self.owner_replaced
            && self.owner_terminated
            && self.hook_leader_terminated
            && self.hook_descendant_terminated
            && self.recovery.is_success()
            && self.reason.is_none()
    }

    /// Whether exact Hook cleanup and replacement-owner reconciliation passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status == CapabilityStatus::Available && self.contract_complete()
    }
}

/// Reopen one Native generation interrupted inside `startContainer`, then
/// qualify exact owner and Hook process termination around the normal recovery
/// contract.
#[must_use]
pub async fn native_linux_hook_owner_death_resume(
    agent: &Path,
    root: &Path,
    bundle_directory: &Path,
    target: ContainerTarget,
    evidence: NativeLinuxHookOwnerDeathEvidence,
) -> NativeLinuxHookOwnerDeathSmokeReport {
    let replacement_owner = capture_native_process_identity(std::process::id());
    let recovery =
        native_linux_recovery_resume(agent, root, bundle_directory, target.clone()).await;
    let mut report = NativeLinuxHookOwnerDeathSmokeReport::initial(target, evidence, recovery);

    match report.evidence.validate(&report.target) {
        Ok(()) => report.evidence_validated = true,
        Err(reason) => append_reason(&mut report, reason),
    }
    match replacement_owner {
        Ok(identity) => {
            report.owner_replaced = identity.pid != report.evidence.owner.pid
                || identity.start_time_ticks != report.evidence.owner.start_time_ticks;
            report.replacement_owner = Some(identity);
            if !report.owner_replaced {
                append_reason(
                    &mut report,
                    "replacement process has the interrupted owner's exact identity",
                );
            }
        }
        Err(reason) => append_reason(&mut report, reason),
    }

    let owner = report.evidence.owner;
    let hook_leader = report.evidence.hook_leader;
    let hook_descendant = report.evidence.hook_descendant;
    report.owner_terminated = retain_termination(&mut report, "interrupted owner", owner).await;
    report.hook_leader_terminated =
        retain_termination(&mut report, "Hook process-group leader", hook_leader).await;
    report.hook_descendant_terminated =
        retain_termination(&mut report, "Hook descendant", hook_descendant).await;
    if !report.recovery.is_success() {
        let recovery_reason = report.recovery.reason.clone().map_or_else(
            || "Native recovery contract did not complete".to_string(),
            |reason| format!("Native recovery contract did not complete: {reason}"),
        );
        append_reason(&mut report, recovery_reason);
    }
    if report.contract_complete() {
        report.status = CapabilityStatus::Available;
    }
    report
}

pub(crate) fn capture_native_process_identity(
    pid: u32,
) -> Result<NativeLinuxProcessIdentity, String> {
    observe_process(pid)?
        .filter(|observation| !observation.is_terminated())
        .map(|observation| observation.identity)
        .ok_or_else(|| format!("process PID {pid} exited before its identity could be captured"))
}

async fn retain_termination(
    report: &mut NativeLinuxHookOwnerDeathSmokeReport,
    role: &str,
    identity: NativeLinuxProcessIdentity,
) -> bool {
    match wait_for_process_termination(identity).await {
        Ok(true) => true,
        Ok(false) => {
            append_reason(
                report,
                format!(
                    "{role} PID {} start-time {} remained live",
                    identity.pid, identity.start_time_ticks
                ),
            );
            false
        }
        Err(reason) => {
            append_reason(report, format!("failed to inspect {role}: {reason}"));
            false
        }
    }
}

async fn wait_for_process_termination(
    identity: NativeLinuxProcessIdentity,
) -> Result<bool, String> {
    let deadline = Instant::now() + PROCESS_TERMINATION_TIMEOUT;
    loop {
        let terminated = observe_process(identity.pid)?.is_none_or(|observation| {
            observation.identity.start_time_ticks != identity.start_time_ticks
                || observation.is_terminated()
        });
        if terminated {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(PROCESS_POLL_INTERVAL).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessObservation {
    identity: NativeLinuxProcessIdentity,
    state: u8,
}

impl ProcessObservation {
    const fn is_terminated(self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x')
    }
}

fn observe_process(pid: u32) -> Result<Option<ProcessObservation>, String> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let encoded = match std::fs::read_to_string(&path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    };
    parse_process_stat(pid, &path, &encoded).map(Some)
}

fn parse_process_stat(pid: u32, path: &Path, encoded: &str) -> Result<ProcessObservation, String> {
    let opening = encoded
        .find(" (")
        .ok_or_else(|| format!("process stat has no command start: {}", path.display()))?;
    let closing = encoded
        .rfind(") ")
        .ok_or_else(|| format!("process stat has no command end: {}", path.display()))?;
    if closing <= opening + 1 {
        return Err(format!(
            "process stat command is malformed: {}",
            path.display()
        ));
    }
    let reported_pid = encoded[..opening]
        .parse::<u32>()
        .map_err(|error| format!("invalid process stat PID at {}: {error}", path.display()))?;
    if reported_pid != pid {
        return Err(format!(
            "process stat PID changed from {pid} to {reported_pid} at {}",
            path.display()
        ));
    }
    let fields = encoded[closing + 2..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .filter(|field| field.len() == 1)
        .and_then(|field| field.as_bytes().first())
        .copied()
        .ok_or_else(|| format!("process stat has no valid state: {}", path.display()))?;
    let process_group_id = fields
        .get(2)
        .and_then(|field| field.parse::<u32>().ok())
        .ok_or_else(|| {
            format!(
                "process stat has no valid process group: {}",
                path.display()
            )
        })?;
    let start_time_ticks = fields
        .get(19)
        .and_then(|field| field.parse::<u64>().ok())
        .ok_or_else(|| format!("process stat has no valid start time: {}", path.display()))?;
    Ok(ProcessObservation {
        identity: NativeLinuxProcessIdentity {
            pid,
            process_group_id,
            start_time_ticks,
        },
        state,
    })
}

fn append_reason(report: &mut NativeLinuxHookOwnerDeathSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{ContainerId, Generation};

    use super::*;

    fn target() -> ContainerTarget {
        ContainerTarget::exact(
            ContainerId::new("native-hook-owner-death").expect("container ID"),
            Generation(1),
        )
    }

    fn identity(pid: u32, process_group_id: u32) -> NativeLinuxProcessIdentity {
        NativeLinuxProcessIdentity {
            pid,
            process_group_id,
            start_time_ticks: u64::from(pid) * 100,
        }
    }

    fn evidence() -> NativeLinuxHookOwnerDeathEvidence {
        NativeLinuxHookOwnerDeathEvidence {
            schema_version: NATIVE_LINUX_HOOK_OWNER_DEATH_EVIDENCE_SCHEMA_VERSION.to_string(),
            target: target(),
            owner: identity(10, 10),
            hook_leader: identity(20, 20),
            hook_descendant: identity(21, 20),
        }
    }

    fn complete_recovery() -> NativeLinuxRecoverySmokeReport {
        let mut report = NativeLinuxRecoverySmokeReport::initial(target(), false);
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.host_service_reopened = true;
        report.recorded_workload_terminated = true;
        report.stopped_observed = true;
        report.process_inventory_empty = true;
        report.kill_idempotent = true;
        report.exact_wait_evidence_refused = true;
        report.stopped_delete_succeeded = true;
        report.durable_record_removed = true;
        report.current_driver_shutdown = true;
        report.executor_transients_clean = true;
        report.cgroup_delegation_clean = true;
        report
    }

    #[test]
    fn evidence_requires_one_private_hook_process_group() {
        let expected = target();
        let mut evidence = evidence();
        evidence.validate(&expected).expect("valid evidence");
        evidence.hook_descendant.process_group_id = 21;
        assert!(evidence.validate(&expected).is_err());
    }

    #[test]
    fn report_requires_hook_cleanup_and_native_recovery() {
        let expected = target();
        let mut report = NativeLinuxHookOwnerDeathSmokeReport::initial(
            expected,
            evidence(),
            complete_recovery(),
        );
        report.status = CapabilityStatus::Available;
        report.evidence_validated = true;
        report.owner_replaced = true;
        report.owner_terminated = true;
        report.hook_leader_terminated = true;
        report.hook_descendant_terminated = true;
        assert!(report.is_success());
        report.hook_descendant_terminated = false;
        assert!(!report.is_success());
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_in_command() {
        let fields = [
            "S", "1", "42", "42", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
            "0", "0", "98765",
        ];
        let encoded = format!("42 (Hook worker (test)) {}", fields.join(" "));
        let observed = parse_process_stat(42, Path::new("/proc/42/stat"), &encoded)
            .expect("parse process stat");
        assert_eq!(observed.identity.pid, 42);
        assert_eq!(observed.identity.process_group_id, 42);
        assert_eq!(observed.identity.start_time_ticks, 98_765);
        assert_eq!(observed.state, b'S');
    }
}
