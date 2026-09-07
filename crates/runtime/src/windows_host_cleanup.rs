//! Windows cleanup evidence for qualification-only utility-VM sessions.
//!
//! Windows does not expose a Unix socket or a process descriptor table. The
//! equivalent boundary is the authenticated named-pipe owner process. The
//! shim report already carries an exact pre-entry/post-entry native handle
//! inventory for each VM. Process-wide handle counts are intentionally not
//! checked here: Tokio, logging, and test harness activity can legitimately
//! open or close unrelated handles between two observations. The independent
//! same-process reclamation gate is responsible for proving native handle
//! stability across repeated VM entries.

use std::io;
use std::time::Duration;

use a3s_oci_core::CapabilityStatus;
use tokio::time::{sleep, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::AgentVmSmokeReport;

const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const STILL_ACTIVE: u32 = 259;

/// Compatibility name retained for the operation-reopen modules, which share
/// the macOS and Windows qualification flow. The implementation is Windows
/// specific and does not emit macOS descriptor evidence.
pub(crate) type MacosHostCleanupTracker = WindowsHostCleanupTracker;

#[derive(Debug)]
pub(crate) struct WindowsHostCleanupTracker {}

impl WindowsHostCleanupTracker {
    /// Capture the host cleanup boundary before a VM session.
    pub(crate) fn capture() -> Self {
        Self {}
    }

    /// Fail closed when the named-pipe owner process was not reaped after the
    /// session's destructive shutdown.
    pub(crate) async fn apply(self, report: &mut AgentVmSmokeReport) {
        let mut reasons = Vec::new();

        let shim_reaped = process_reaped(report.shim_process_id, !report.shim_spawned).await;
        if !shim_reaped {
            reasons.push(match report.shim_process_id {
                Some(process_id) => {
                    format!("WHPX shim PID {process_id} remained after session cleanup")
                }
                None => "spawned WHPX shim had no process ID to verify".to_string(),
            });
        }

        // WHPX uses the shim itself as the verified bridge peer. Keep this
        // check separate so malformed reports cannot hide a missing bridge.
        let bridge_reaped =
            process_reaped(report.bridge_process_id, !report.shim_client_verified).await;
        if !bridge_reaped {
            reasons.push(match report.bridge_process_id {
                Some(process_id) => format!(
                    "WHPX authenticated bridge PID {process_id} remained after session cleanup"
                ),
                None => "verified WHPX bridge had no process ID to verify".to_string(),
            });
        }

        if !reasons.is_empty() {
            report.status = CapabilityStatus::Unavailable;
            append_reason(report, reasons.join("; "));
        }
    }
}

async fn process_reaped(process_id: Option<u32>, absent_is_valid: bool) -> bool {
    let Some(process_id) = process_id else {
        return absent_is_valid;
    };
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        match process_exists(process_id) {
            Ok(false) => return true,
            Ok(true) if Instant::now() < deadline => sleep(PROCESS_POLL_INTERVAL).await,
            Ok(true) | Err(_) => return false,
        }
    }
}

fn process_exists(process_id: u32) -> Result<bool, String> {
    // SAFETY: the requested access is limited to querying process state, and
    // the PID comes directly from the trusted session report.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        // SAFETY: GetLastError reads the thread-local error from OpenProcess.
        let error = unsafe { GetLastError() };
        return match error {
            ERROR_INVALID_PARAMETER => Ok(false),
            ERROR_ACCESS_DENIED => Ok(true),
            _ => Err(format!(
                "failed to inspect WHPX process ID {process_id}: {}",
                io::Error::from_raw_os_error(error as i32)
            )),
        };
    }

    let mut exit_code = 0_u32;
    // SAFETY: handle is a live process handle and exit_code points to writable
    // storage for the call.
    let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
    // SAFETY: handle was returned by OpenProcess and is owned by this scope.
    unsafe { CloseHandle(handle) };
    if !queried {
        return Err(format!(
            "failed to query WHPX process ID {process_id}: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(exit_code == STILL_ACTIVE)
}

fn append_reason(report: &mut AgentVmSmokeReport, reason: impl Into<String>) {
    let reason = reason.into();
    report.reason = Some(match report.reason.take() {
        Some(existing) if existing != reason => format!("{existing}; {reason}"),
        Some(existing) => existing,
        None => reason,
    });
}
