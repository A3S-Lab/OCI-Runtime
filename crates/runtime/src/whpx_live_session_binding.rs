//! Opt-in durable WHPX Live session binding for Host reopen reattach.
//!
//! When `A3S_OCI_WHPX_SESSION_OWNER=1`, the first Host publishes authenticated
//! process identities into the runtime share after the session-owner owns the
//! host-control named pipe. A replacement Host loads that binding,
//! re-authenticates PID + `GetProcessTimes` creation ticks, and reconnects to
//! the surviving session-owner bridge without launching a second Guest.
//!
//! Default Host-bound ownership never writes this artifact. Full utility-VM
//! Live reattach (`whpx_live_reattach`) is a thin follow-up on top of this
//! binding + host-control connect path. Does **not** claim Box Enterprise GA
//! or flip B2.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, FILETIME};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Binding schema published under the container runtime share.
pub const WHPX_LIVE_SESSION_BINDING_SCHEMA: &str = "a3s.oci.whpx-live-session-binding.v1";

/// Filename under the runtime share for the Live reattach binding.
pub const WHPX_LIVE_SESSION_BINDING_FILE: &str = ".a3s-oci-whpx-live-session-binding.json";

/// Guest agent env: after a clean Host EOF, reconnect vsock (same as KVM Live).
///
/// Forwarded into the Linux guest by the Windows WHPX agent-vm smoke path when
/// durable session-owner mode is enabled.
pub const GUEST_HOST_RECONNECT_ENV: &str = "A3S_OCI_GUEST_HOST_RECONNECT";

const MAX_BINDING_BYTES: u64 = 16 * 1024;

/// Authenticated Windows process identity (PID + `GetProcessTimes` creation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WhpxProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
}

impl WhpxProcessIdentity {
    /// Capture identity for a live PID from `GetProcessTimes` creation FILETIME.
    pub fn capture(pid: u32, role: &str) -> io::Result<Self> {
        let start_time_ticks = process_start_time_ticks(pid)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{role} PID {pid} exited before identity capture"),
            )
        })?;
        Ok(Self {
            pid,
            start_time_ticks,
        })
    }

    /// True when the same PID still reports the recorded creation ticks.
    pub fn is_live(self) -> io::Result<bool> {
        Ok(process_start_time_ticks(self.pid)? == Some(self.start_time_ticks))
    }
}

/// Durable binding a replacement Host uses to reattach Live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WhpxLiveSessionBinding {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub session_owner: WhpxProcessIdentity,
    pub shim: WhpxProcessIdentity,
    /// Host-facing named pipe owned by the durable session-owner bridge.
    pub host_control_pipe: String,
    /// Product Host pipe the Box/SDK client reconnects to after Host reopen.
    pub service_pipe: String,
    pub session_token_hex: String,
}

impl WhpxLiveSessionBinding {
    pub fn binding_path(runtime_share: &Path) -> PathBuf {
        runtime_share.join(WHPX_LIVE_SESSION_BINDING_FILE)
    }

    /// Reserved host-control pipe name for a product service pipe (Live reopen).
    ///
    /// The durable session-owner binds this pipe and proxies Host↔shim so Host
    /// death does not destroy the guest agent pipe.
    pub fn host_control_pipe_for_service(service_pipe: &str) -> String {
        let leaf = service_pipe
            .rsplit('\\')
            .next()
            .filter(|part| !part.is_empty())
            .unwrap_or(service_pipe);
        format!(r"\\.\pipe\a3s-oci-whpx-live-control-{leaf}")
    }

    /// Persist the binding under the runtime share (create-new, fail closed).
    pub fn publish(&self, runtime_share: &Path) -> io::Result<PathBuf> {
        if self.schema_version != WHPX_LIVE_SESSION_BINDING_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "WHPX Live binding schema must be {WHPX_LIVE_SESSION_BINDING_SCHEMA}, got {}",
                    self.schema_version
                ),
            ));
        }
        let path = Self::binding_path(runtime_share);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to serialize WHPX Live binding: {error}"),
            )
        })?;
        if bytes.len() as u64 > MAX_BINDING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WHPX Live binding exceeds size limit",
            ));
        }
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        Ok(path)
    }

    /// Fail closed unless session-owner and shim identities are still live.
    pub fn authenticate_live(&self) -> io::Result<()> {
        if self.schema_version != WHPX_LIVE_SESSION_BINDING_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unexpected WHPX Live binding schema {}",
                    self.schema_version
                ),
            ));
        }
        if !self.session_owner.is_live()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "WHPX session-owner PID {} start-time {} is not live",
                    self.session_owner.pid, self.session_owner.start_time_ticks
                ),
            ));
        }
        if !self.shim.is_live()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "WHPX shim PID {} start-time {} is not live",
                    self.shim.pid, self.shim.start_time_ticks
                ),
            ));
        }
        Ok(())
    }
}

/// Load a published WHPX Live binding from the runtime share.
pub fn load_binding(runtime_share: &Path) -> io::Result<WhpxLiveSessionBinding> {
    let path = WhpxLiveSessionBinding::binding_path(runtime_share);
    let metadata = fs::metadata(&path)?;
    if metadata.len() > MAX_BINDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WHPX Live binding exceeds size limit",
        ));
    }
    let bytes = fs::read(&path)?;
    let binding: WhpxLiveSessionBinding = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid WHPX Live binding JSON: {error}"),
        )
    })?;
    if binding.schema_version != WHPX_LIVE_SESSION_BINDING_SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unexpected WHPX Live binding schema {}",
                binding.schema_version
            ),
        ));
    }
    Ok(binding)
}

/// Remove a published binding when Live teardown is intentional.
pub fn remove_binding(runtime_share: &Path) -> io::Result<()> {
    let path = WhpxLiveSessionBinding::binding_path(runtime_share);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn process_start_time_ticks(pid: u32) -> io::Result<Option<u64>> {
    if pid == 0 {
        return Ok(None);
    }
    // SAFETY: OpenProcess with QUERY_LIMITED is a documented PID lookup.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if handle.is_null() {
        return Ok(None);
    }
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: handle is an owned OpenProcess result; FILETIME outs are local.
    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: close the owned process handle exactly once.
    unsafe {
        let _ = CloseHandle(handle);
    }
    if ok == 0 {
        return Ok(None);
    }
    let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if ticks == 0 {
        return Ok(None);
    }
    Ok(Some(ticks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_current_process_identity() {
        let identity =
            WhpxProcessIdentity::capture(std::process::id(), "self").expect("capture self");
        assert!(identity.pid > 0);
        assert!(identity.start_time_ticks > 0);
        assert!(identity.is_live().expect("self must stay live"));
    }

    #[test]
    fn host_control_pipe_derives_stable_leaf_from_service_pipe() {
        assert_eq!(
            WhpxLiveSessionBinding::host_control_pipe_for_service(r"\\.\pipe\a3s-oci-agent-abc"),
            r"\\.\pipe\a3s-oci-whpx-live-control-a3s-oci-agent-abc"
        );
        assert_eq!(
            WhpxLiveSessionBinding::host_control_pipe_for_service("a3s-oci-agent-abc"),
            r"\\.\pipe\a3s-oci-whpx-live-control-a3s-oci-agent-abc"
        );
    }

    #[test]
    fn publish_load_authenticate_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let self_id =
            WhpxProcessIdentity::capture(std::process::id(), "self").expect("capture self");
        let binding = WhpxLiveSessionBinding {
            schema_version: WHPX_LIVE_SESSION_BINDING_SCHEMA.to_string(),
            container_id: Some("c1".into()),
            generation: Some(1),
            config_digest: Some("deadbeef".into()),
            session_owner: self_id,
            shim: self_id,
            host_control_pipe: r"\\.\pipe\a3s-oci-whpx-live-control-test".into(),
            service_pipe: r"\\.\pipe\a3s-box-whpx-owner-test".into(),
            session_token_hex: "00".repeat(16),
        };
        binding.publish(dir.path()).expect("publish");
        let loaded = load_binding(dir.path()).expect("load");
        assert_eq!(loaded, binding);
        loaded.authenticate_live().expect("authenticate");
        remove_binding(dir.path()).expect("remove");
        assert!(load_binding(dir.path()).is_err());
    }

    #[test]
    fn authenticate_live_rejects_start_time_mismatch() {
        let self_id =
            WhpxProcessIdentity::capture(std::process::id(), "self").expect("capture self");
        let mut forged = self_id;
        forged.start_time_ticks = self_id.start_time_ticks.saturating_add(1);
        let binding = WhpxLiveSessionBinding {
            schema_version: WHPX_LIVE_SESSION_BINDING_SCHEMA.to_string(),
            container_id: None,
            generation: None,
            config_digest: None,
            session_owner: forged,
            shim: self_id,
            host_control_pipe: r"\\.\pipe\a3s-oci-whpx-live-control-test".into(),
            service_pipe: r"\\.\pipe\a3s-box-whpx-owner-test".into(),
            session_token_hex: "11".repeat(16),
        };
        let error = binding.authenticate_live().expect_err("forged owner");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
