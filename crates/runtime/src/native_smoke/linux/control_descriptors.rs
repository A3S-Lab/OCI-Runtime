use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::OciBundle;
use tokio::net::UnixStream;
use tokio::time::{sleep, Instant};

use super::filesystem::create_private_directory;
use crate::NativeControlDescriptors;

const CONTROL_ENVIRONMENT: &str = "A3S_OCI_NATIVE_CONTROL_SMOKE=1";
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
const CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(25);
pub(super) const INIT_LOG_CONTENTS: &[u8] = b"a3s-box-native-control-v1\n";

pub(super) struct ControlDescriptorFixture {
    descriptors: Option<NativeControlDescriptors>,
    exec_path: PathBuf,
    pty_path: PathBuf,
    init_log_path: PathBuf,
}

impl ControlDescriptorFixture {
    pub(super) async fn create(session_root: &Path) -> Result<Self, String> {
        let control_root = session_root.join("control");
        create_private_directory(&control_root).await?;
        let exec_path = control_root.join("exec.sock");
        let pty_path = control_root.join("pty.sock");
        let init_log_path = control_root.join("init.log");
        let exec_listener = UnixListener::bind(&exec_path).map_err(|error| {
            format!(
                "failed to bind native exec listener {}: {error}",
                exec_path.display()
            )
        })?;
        let pty_listener = UnixListener::bind(&pty_path).map_err(|error| {
            format!(
                "failed to bind native PTY listener {}: {error}",
                pty_path.display()
            )
        })?;
        let init_log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&init_log_path)
            .map_err(|error| {
                format!(
                    "failed to open native init log {}: {error}",
                    init_log_path.display()
                )
            })?;
        let descriptors = NativeControlDescriptors::new(exec_listener, pty_listener, init_log)
            .map_err(|error| format!("failed to validate native control descriptors: {error}"))?;
        Ok(Self {
            descriptors: Some(descriptors),
            exec_path,
            pty_path,
            init_log_path,
        })
    }

    pub(super) fn take_descriptors(&mut self) -> Result<NativeControlDescriptors, String> {
        self.descriptors
            .take()
            .ok_or_else(|| "native control descriptors were already consumed".to_string())
    }

    pub(super) async fn verify_listeners(&self) -> Result<(), String> {
        if self.descriptors.is_some() {
            return Err(
                "host listener copies must be dropped before connectivity verification".into(),
            );
        }
        for (role, path) in [("exec", &self.exec_path), ("PTY", &self.pty_path)] {
            tokio::time::timeout(CONTROL_TIMEOUT, UnixStream::connect(path))
                .await
                .map_err(|_| format!("timed out connecting to inherited {role} listener"))?
                .map_err(|error| {
                    format!(
                        "failed to connect to inherited {role} listener {}: {error}",
                        path.display()
                    )
                })?;
        }
        Ok(())
    }

    pub(super) async fn verify_init_log(&self) -> Result<(), String> {
        let deadline = Instant::now() + CONTROL_TIMEOUT;
        loop {
            let bytes = tokio::fs::read(&self.init_log_path)
                .await
                .map_err(|error| {
                    format!(
                        "failed to read inherited init log {}: {error}",
                        self.init_log_path.display()
                    )
                })?;
            if bytes == INIT_LOG_CONTENTS {
                return Ok(());
            }
            if bytes.len() >= INIT_LOG_CONTENTS.len() || Instant::now() >= deadline {
                return Err(format!(
                    "inherited init log contained {bytes:?}, expected {INIT_LOG_CONTENTS:?}"
                ));
            }
            sleep(CONTROL_POLL_INTERVAL).await;
        }
    }

    pub(super) async fn verify_closed(&self) -> Result<(), String> {
        for (role, path) in [("exec", &self.exec_path), ("PTY", &self.pty_path)] {
            if UnixStream::connect(path).await.is_ok() {
                return Err(format!(
                    "inherited {role} listener {} remained open after delete",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn enable_workload_verification(bundle: &OciBundle) -> Result<OciBundle, String> {
    let mut config: serde_json::Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode native smoke configuration: {error}"))?;
    let environment = config
        .pointer_mut("/process/env")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| "native smoke process.env must be an array".to_string())?;
    if environment.iter().any(|entry| {
        entry
            .as_str()
            .is_some_and(|entry| entry.starts_with("A3S_OCI_NATIVE_CONTROL_SMOKE="))
    }) {
        return Err("native smoke control environment is already configured".into());
    }
    environment.push(serde_json::Value::String(CONTROL_ENVIRONMENT.to_string()));
    let encoded = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("failed to encode native control smoke bundle: {error}"))?;
    OciBundle::from_json(bundle.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate native control smoke bundle: {error}"))
}
