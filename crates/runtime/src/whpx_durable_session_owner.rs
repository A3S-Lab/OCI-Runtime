//! Opt-in durable WHPX session-owner mode (Live Host reopen substrate).
//!
//! Default Host-bound ownership keeps the libkrun shim's owner watchdog pointed
//! at the Host Service PID, so Host taskkill tears down the Guest
//! (stopped-only recovery — see `whpx_recovery_smoke`). Opt-in durable mode
//! will insert a long-lived session-owner process as the shim owner so Host
//! death does not terminate the VM; replacement Host Live reattach uses
//! [`crate::whpx_live_session_binding`].
//!
//! This slice owns the env flag and fail-closed gate only. Durable spawn via
//! Windows Job Object / intermediate process lands next. Does **not** claim
//! Box Enterprise GA or flip `b2_process_session_recovery_closed`.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::env;
use std::io;

/// Environment flag that requests durable WHPX session ownership.
///
/// When unset/false, Host remains the shim owner (stopped-only on Host death).
/// When true, callers must use the durable session-owner spawn path (not yet
/// productized); until then, Host services fail closed rather than silently
/// staying Host-bound.
pub const WHPX_SESSION_OWNER_ENV: &str = "A3S_OCI_WHPX_SESSION_OWNER";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhpxOwnerMode {
    /// Shim owner watchdog watches the Host Service process (default).
    HostBound,
    /// Shim owner watchdog will watch a durable session-owner process.
    DurableSession,
}

/// Resolve ownership mode from the process environment.
pub fn owner_mode_from_env() -> WhpxOwnerMode {
    owner_mode_from_value(env::var(WHPX_SESSION_OWNER_ENV).ok().as_deref())
}

/// Resolve ownership mode from an optional raw flag value.
pub fn owner_mode_from_value(value: Option<&str>) -> WhpxOwnerMode {
    match value {
        Some(value) if is_truthy(value) => WhpxOwnerMode::DurableSession,
        _ => WhpxOwnerMode::HostBound,
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Refuse DurableSession until the Job Object / intermediate-owner spawn lands.
///
/// Call from WHPX Host Service construction so `A3S_OCI_WHPX_SESSION_OWNER=1`
/// cannot silently degrade to Host-bound mid-run Live.
pub fn require_durable_spawn_ready(mode: WhpxOwnerMode) -> io::Result<()> {
    match mode {
        WhpxOwnerMode::HostBound => Ok(()),
        WhpxOwnerMode::DurableSession => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{WHPX_SESSION_OWNER_ENV}=1 requested durable WHPX Live session ownership, \
                 but the Windows session-owner spawn path is not productized yet \
                 (Job Object / intermediate owner + host-control pipe). \
                 Unset the env for stopped-only Host-bound WHPX, or wait for the \
                 Live spawn slice. Does not claim Box mid-run Live tip-prove."
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_mode_defaults_host_bound() {
        assert_eq!(owner_mode_from_value(None), WhpxOwnerMode::HostBound);
        assert_eq!(owner_mode_from_value(Some("")), WhpxOwnerMode::HostBound);
        assert_eq!(owner_mode_from_value(Some("0")), WhpxOwnerMode::HostBound);
        assert_eq!(
            owner_mode_from_value(Some("false")),
            WhpxOwnerMode::HostBound
        );
    }

    #[test]
    fn owner_mode_truthy_is_durable() {
        for value in ["1", "true", "TRUE", "yes", "on"] {
            assert_eq!(
                owner_mode_from_value(Some(value)),
                WhpxOwnerMode::DurableSession
            );
        }
    }

    #[test]
    fn durable_mode_fails_closed_until_spawn_lands() {
        let error = require_durable_spawn_ready(WhpxOwnerMode::DurableSession)
            .expect_err("durable must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        require_durable_spawn_ready(WhpxOwnerMode::HostBound).expect("host-bound ok");
    }
}
