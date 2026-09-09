use std::io;
use std::sync::{Arc, Mutex};

/// Successful daemon restarts exercised by the real Runtime V2 qualification.
///
/// Keep this inventory ordered by the qualification flow.  The ledger below
/// makes the evidence claim executable: a run is not complete when it merely
/// happens to restart containerd, but only when every advertised lifecycle
/// boundary was observed exactly once and in the intended order.
pub(crate) const EXPECTED_RESTART_BOUNDARIES: &[&str] = &[
    "init-created",
    "init-running",
    "exec-added",
    "exec-running",
    "exec-stopped",
    "exec-id-reused-added",
    "terminal-exec-running",
    "init-stopped",
    "committed-Start-shim-rehydration",
    "committed-Exec-shim-rehydration",
    "committed-terminal-SignalProcess-shim-rehydration",
    "DeleteProcess-receipt-replay",
    "committed-terminal-Kill-shim-rehydration",
    "task-Delete-receipt-replay",
    "manual-shim-rehydration",
    "committed-pause-shim-rehydration",
    "committed-resume-shim-rehydration",
    "committed-update-shim-rehydration",
    "committed-Kill-shim-rehydration",
    "committed-signal-shim-rehydration",
    "committed-resize-shim-rehydration",
    "committed-close-shim-rehydration",
    "parallel-running",
];

/// DedicatedVm containerd slice: daemon restart at Created/Running/Stopped only.
///
/// This is intentionally narrower than [`EXPECTED_RESTART_BOUNDARIES`]. It
/// proves the shim survives `KillMode=process` daemon replacement without
/// inventing PID, driver, or isolation — not the full Native Linux exec/PTY
/// rehydration matrix.
pub(crate) const EXPECTED_DEDICATED_VM_RESTART_BOUNDARIES: &[&str] = &[
    "dedicated-vm-init-created",
    "dedicated-vm-init-running",
    "dedicated-vm-init-stopped",
];

#[derive(Debug, Clone, Default)]
pub(crate) struct RestartBoundaryLedger {
    entries: Arc<Mutex<Vec<String>>>,
}

impl RestartBoundaryLedger {
    pub(crate) fn reset(&self) -> io::Result<()> {
        self.entries.lock().map_err(lock_error)?.clear();
        Ok(())
    }

    pub(crate) fn record(&self, boundary: &str) -> io::Result<()> {
        let mut entries = self.entries.lock().map_err(lock_error)?;
        if entries.iter().any(|entry| entry == boundary) {
            return Err(io::Error::other(format!(
                "restart boundary {boundary:?} was recorded more than once"
            )));
        }
        entries.push(boundary.to_owned());
        Ok(())
    }

    pub(crate) fn verify_complete(&self) -> io::Result<()> {
        self.verify_exact(EXPECTED_RESTART_BOUNDARIES)
    }

    pub(crate) fn verify_dedicated_vm_complete(&self) -> io::Result<()> {
        self.verify_exact(EXPECTED_DEDICATED_VM_RESTART_BOUNDARIES)
    }

    pub(crate) fn verify_exact(&self, expected: &[&str]) -> io::Result<()> {
        let entries = self.entries.lock().map_err(lock_error)?;
        let observed = entries.iter().map(String::as_str).collect::<Vec<_>>();
        if observed == expected {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "restart boundary ledger did not match the qualification contract: observed {} entries {observed:?}, expected {} entries {expected:?}",
            observed.len(),
            expected.len(),
        )))
    }

    pub(crate) fn snapshot(&self) -> io::Result<Vec<String>> {
        Ok(self.entries.lock().map_err(lock_error)?.clone())
    }
}

fn lock_error(_: std::sync::PoisonError<std::sync::MutexGuard<'_, Vec<String>>>) -> io::Error {
    io::Error::other("restart boundary ledger lock was poisoned")
}

#[cfg(test)]
mod tests {
    use super::{
        RestartBoundaryLedger, EXPECTED_DEDICATED_VM_RESTART_BOUNDARIES,
        EXPECTED_RESTART_BOUNDARIES,
    };

    #[test]
    fn accepts_the_complete_ordered_inventory() {
        let ledger = RestartBoundaryLedger::default();
        for boundary in EXPECTED_RESTART_BOUNDARIES {
            ledger
                .record(boundary)
                .expect("the contract inventory contains unique boundaries");
        }
        ledger
            .verify_complete()
            .expect("the complete contract inventory must verify");
    }

    #[test]
    fn accepts_the_dedicated_vm_restart_inventory() {
        let ledger = RestartBoundaryLedger::default();
        for boundary in EXPECTED_DEDICATED_VM_RESTART_BOUNDARIES {
            ledger
                .record(boundary)
                .expect("dedicated-vm inventory contains unique boundaries");
        }
        ledger
            .verify_dedicated_vm_complete()
            .expect("dedicated-vm restart inventory must verify");
        assert!(ledger.verify_complete().is_err());
    }

    #[test]
    fn rejects_duplicate_boundaries() {
        let ledger = RestartBoundaryLedger::default();
        ledger
            .record(EXPECTED_RESTART_BOUNDARIES[0])
            .expect("first boundary should be accepted");
        assert!(ledger.record(EXPECTED_RESTART_BOUNDARIES[0]).is_err());
    }

    #[test]
    fn rejects_missing_or_reordered_boundaries() {
        let ledger = RestartBoundaryLedger::default();
        ledger
            .record(EXPECTED_RESTART_BOUNDARIES[1])
            .expect("the ledger records observations before final validation");
        assert!(ledger.verify_complete().is_err());

        ledger
            .reset()
            .expect("reset should clear the observation ledger");
        ledger
            .record("unexpected-boundary")
            .expect("unknown observations are diagnosed by final validation");
        assert_eq!(
            ledger.snapshot().expect("snapshot should read the ledger"),
            vec!["unexpected-boundary".to_string()]
        );
        assert!(ledger.verify_complete().is_err());
    }
}
