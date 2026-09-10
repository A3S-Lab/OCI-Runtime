//! Opt-in durable KVM Live session binding for Host reopen reattach.
//!
//! When `A3S_OCI_KVM_SESSION_OWNER=1`, the first Host publishes authenticated
//! process identities and the Host-control socket path into the runtime share.
//! A replacement Host loads that binding, re-authenticates PID + start-time,
//! and reconnects to the surviving session-owner bridge without launching a
//! second Guest.
//!
//! Default Host-bound ownership never writes this artifact.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Binding schema published under the container runtime share.
pub const KVM_LIVE_SESSION_BINDING_SCHEMA: &str = "a3s.oci.kvm-live-session-binding.v1";

/// Filename under the runtime share for the Live reattach binding.
pub const KVM_LIVE_SESSION_BINDING_FILE: &str = ".a3s-oci-kvm-live-session-binding.json";

/// Host-facing control socket owned by the durable session-owner bridge.
pub const KVM_HOST_CONTROL_SOCKET_FILE: &str = ".a3s-oci-kvm-host-control.sock";

/// Guest reconnect loop flag forwarded into the utility-VM agent.
pub const GUEST_HOST_RECONNECT_ENV: &str = "A3S_OCI_GUEST_HOST_RECONNECT";

const PRIVATE_FILE_MODE: u32 = 0o600;
const MAX_BINDING_BYTES: u64 = 16 * 1024;

/// Authenticated Linux process identity (PID + start-time ticks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KvmProcessIdentity {
    pub pid: i32,
    pub start_time_ticks: u64,
}

impl KvmProcessIdentity {
    /// Capture identity for a live PID from `/proc/<pid>/stat`.
    pub fn capture(pid: i32, role: &str) -> io::Result<Self> {
        let observation = process_observation(pid)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{role} PID {pid} exited before identity capture"),
            )
        })?;
        if matches!(observation.state, b'X' | b'x') {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{role} PID {pid} exited before identity capture"),
            ));
        }
        Ok(Self {
            pid,
            start_time_ticks: observation.start_time_ticks,
        })
    }

    /// True when `/proc` still reports the same start-time and a non-terminal state.
    pub fn is_live(self) -> io::Result<bool> {
        Ok(process_observation(self.pid)?.is_some_and(|observation| {
            observation.start_time_ticks == self.start_time_ticks && !observation.is_terminated()
        }))
    }
}

/// Durable binding a replacement Host uses to reattach Live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KvmLiveSessionBinding {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
    pub session_owner: KvmProcessIdentity,
    pub shim: KvmProcessIdentity,
    pub host_control_socket: String,
    pub pipe_name: String,
    pub session_token_hex: String,
}

impl KvmLiveSessionBinding {
    pub fn binding_path(runtime_share: &Path) -> PathBuf {
        runtime_share.join(KVM_LIVE_SESSION_BINDING_FILE)
    }

    pub fn host_control_path(runtime_share: &Path) -> PathBuf {
        runtime_share.join(KVM_HOST_CONTROL_SOCKET_FILE)
    }

    /// Atomically publish a private binding file under `runtime_share`.
    pub fn publish(&self, runtime_share: &Path) -> io::Result<PathBuf> {
        if self.schema_version != KVM_LIVE_SESSION_BINDING_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "refusing to publish unsupported KVM Live binding schema {}",
                    self.schema_version
                ),
            ));
        }
        if self.session_token_hex.len() != 64
            || !self
                .session_token_hex
                .chars()
                .all(|ch| ch.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KVM Live binding session token must be 64 hex characters",
            ));
        }
        let path = Self::binding_path(runtime_share);
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if encoded.len() as u64 > MAX_BINDING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "KVM Live binding exceeds its fixed size bound",
            ));
        }
        let tmp = path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(PRIVATE_FILE_MODE)
                .open(&tmp)?;
            file.write_all(&encoded)?;
            file.sync_all()?;
        }
        fs::set_permissions(&tmp, fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// Load and validate a binding from disk.
    pub fn load(path: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_BINDING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "KVM Live binding exceeds its fixed size bound: {}",
                    path.display()
                ),
            ));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != PRIVATE_FILE_MODE {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "KVM Live binding must be mode {:o}, observed {:o}: {}",
                    PRIVATE_FILE_MODE,
                    mode,
                    path.display()
                ),
            ));
        }
        let encoded = fs::read(path)?;
        let binding: Self = serde_json::from_slice(&encoded)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if binding.schema_version != KVM_LIVE_SESSION_BINDING_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported KVM Live binding schema {}",
                    binding.schema_version
                ),
            ));
        }
        Ok(binding)
    }

    /// Fail closed unless both session-owner and shim identities are still live.
    pub fn authenticate_live(&self) -> io::Result<()> {
        if !self.session_owner.is_live()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "KVM session-owner PID {} start-time {} is not live",
                    self.session_owner.pid, self.session_owner.start_time_ticks
                ),
            ));
        }
        if !self.shim.is_live()? {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "KVM shim PID {} start-time {} is not live",
                    self.shim.pid, self.shim.start_time_ticks
                ),
            ));
        }
        Ok(())
    }

    pub fn remove(runtime_share: &Path) -> io::Result<()> {
        let path = Self::binding_path(runtime_share);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Load a binding from an exact path.
pub fn load_binding(path: &Path) -> io::Result<KvmLiveSessionBinding> {
    KvmLiveSessionBinding::load(path)
}

/// Fail closed unless session-owner and shim identities are still live.
pub fn authenticate_live(binding: &KvmLiveSessionBinding) -> io::Result<()> {
    binding.authenticate_live()
}

/// Remove the binding file when present.
pub fn remove_binding(runtime_share: &Path) -> io::Result<()> {
    KvmLiveSessionBinding::remove(runtime_share)
}

#[derive(Debug, Clone, Copy)]
struct ProcessObservation {
    state: u8,
    start_time_ticks: u64,
}

impl ProcessObservation {
    fn is_terminated(self) -> bool {
        matches!(self.state, b'Z' | b'X' | b'x')
    }
}

fn process_observation(pid: i32) -> io::Result<Option<ProcessObservation>> {
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("process identity PID {pid} must be positive"),
        ));
    }
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let encoded = match fs::read_to_string(&path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(close) = encoded.rfind(')') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("/proc/{pid}/stat is missing the command close"),
        ));
    };
    let fields: Vec<&str> = encoded[close + 1..].split_whitespace().collect();
    // After `)`: state is field 0, starttime is field 19 (1-indexed field 22).
    let state = fields
        .first()
        .and_then(|value| value.as_bytes().first().copied())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("/proc/{pid}/stat is missing process state"),
            )
        })?;
    let start_time_ticks = fields.get(19).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("/proc/{pid}/stat is missing start-time ticks"),
        )
    })?;
    let start_time_ticks = start_time_ticks.parse::<u64>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("/proc/{pid}/stat start-time is not an integer: {error}"),
        )
    })?;
    Ok(Some(ProcessObservation {
        state,
        start_time_ticks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_share() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("a3s-oci-kvm-live-binding-{nanos}"));
        fs::create_dir_all(&path).expect("temp share");
        path
    }

    fn sample_binding(owner: KvmProcessIdentity, shim: KvmProcessIdentity) -> KvmLiveSessionBinding {
        KvmLiveSessionBinding {
            schema_version: KVM_LIVE_SESSION_BINDING_SCHEMA.to_string(),
            container_id: Some("ctr".into()),
            generation: Some(7),
            config_digest: Some("abc".into()),
            session_owner: owner,
            shim,
            host_control_socket: "/tmp/control.sock".into(),
            pipe_name: "a3s-oci-pipe".into(),
            session_token_hex: "ab".repeat(32),
        }
    }

    #[test]
    fn publish_load_round_trips_private_binding() {
        let share = temp_share();
        let owner = KvmProcessIdentity::capture(std::process::id() as i32, "test-owner")
            .expect("capture self");
        let binding = sample_binding(owner, owner);
        let path = binding.publish(&share).expect("publish");
        let loaded = KvmLiveSessionBinding::load(&path).expect("load");
        assert_eq!(loaded, binding);
        binding.authenticate_live().expect("self must be live");
        KvmLiveSessionBinding::remove(&share).expect("remove");
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&share);
    }

    #[test]
    fn authenticate_live_rejects_start_time_mismatch() {
        let owner = KvmProcessIdentity::capture(std::process::id() as i32, "test-owner")
            .expect("capture self");
        let mut forged = owner;
        forged.start_time_ticks = owner.start_time_ticks.saturating_add(1);
        let binding = sample_binding(forged, owner);
        let error = binding
            .authenticate_live()
            .expect_err("forged start-time must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn authenticate_live_rejects_dead_pid() {
        let owner = KvmProcessIdentity {
            pid: i32::MAX - 7,
            start_time_ticks: 1,
        };
        let binding = sample_binding(owner, owner);
        let error = binding
            .authenticate_live()
            .expect_err("missing pid must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
