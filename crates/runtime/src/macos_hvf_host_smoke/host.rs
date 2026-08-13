use std::collections::BTreeSet;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::macos::fs::MetadataExt as MacosMetadataExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Instant};

use super::report::{MacosProcessIdentity, MacosSocketIdentity};

const START_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const PROCESS_REAP_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

pub(super) struct HostServiceProcess {
    child: Child,
    socket: PathBuf,
}

impl HostServiceProcess {
    pub(super) async fn spawn(
        executable: &Path,
        root: &Path,
        shim: &Path,
        manifest: &Path,
        stdout: &Path,
        stderr: &Path,
    ) -> Result<Self, String> {
        let stdout = create_private_log(stdout, "Host Service stdout")?;
        let stderr = create_private_log(stderr, "Host Service stderr")?;
        let child = Command::new(executable)
            .arg("macos-hvf-host-service")
            .arg("--root")
            .arg(root)
            .arg("--shim")
            .arg(shim)
            .arg("--system-image-manifest")
            .arg(manifest)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("failed to start public macOS HVF Host Service: {error}"))?;
        let mut process = Self {
            child,
            socket: root.join("runtime.sock"),
        };
        match process.wait_for_private_socket().await {
            Ok(()) => Ok(process),
            Err(primary) => {
                process.emergency_stop().await;
                Err(primary)
            }
        }
    }

    pub(super) fn pid(&self) -> Result<u32, String> {
        self.child
            .id()
            .ok_or_else(|| "public macOS HVF Host Service has no live PID".to_string())
    }

    pub(super) fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub(super) async fn connect(&self) -> Result<RuntimeClient, String> {
        let endpoint = LocalIpcEndpoint::unix_socket(&self.socket)
            .map_err(|error| format!("failed to configure Host Service endpoint: {error}"))?;
        timeout(START_TIMEOUT, RuntimeClient::connect(&endpoint))
            .await
            .map_err(|_| "timed out connecting to public macOS HVF Host Service".to_string())?
            .map_err(|error| format!("failed to connect public Host Service: {error}"))
    }

    pub(super) async fn terminate(&mut self) -> Result<bool, String> {
        let pid = self.pid()?;
        let pid = libc::pid_t::try_from(pid)
            .map_err(|error| format!("Host Service PID is invalid: {error}"))?;
        // SAFETY: pid identifies the exact retained Child and SIGTERM is a
        // normal request handled by the public service command.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("failed to terminate public Host Service: {error}"));
            }
        }
        match timeout(STOP_TIMEOUT, self.child.wait()).await {
            Ok(Ok(status)) => Ok(status.success()),
            Ok(Err(error)) => Err(format!("failed to reap public Host Service: {error}")),
            Err(_) => {
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
                Err("public Host Service did not stop after SIGTERM".to_string())
            }
        }
    }

    pub(super) async fn sigkill(&mut self) -> Result<(), String> {
        let pid = self.pid()?;
        let pid = libc::pid_t::try_from(pid)
            .map_err(|error| format!("Host Service PID is invalid: {error}"))?;
        // SAFETY: pid identifies the exact retained Child. This is the
        // qualification's deliberate uncatchable owner-death boundary.
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            return Err(format!(
                "failed to SIGKILL public Host Service: {}",
                io::Error::last_os_error()
            ));
        }
        let status = timeout(STOP_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| "timed out reaping SIGKILLed Host Service".to_string())?
            .map_err(|error| format!("failed to reap SIGKILLed Host Service: {error}"))?;
        if status.signal() != Some(libc::SIGKILL) {
            return Err(format!(
                "Host Service exited with {status}, expected termination by SIGKILL"
            ));
        }
        Ok(())
    }

    pub(super) async fn emergency_stop(&mut self) {
        if self.child.id().is_none() {
            return;
        }
        let _ = self.child.kill().await;
        let _ = timeout(STOP_TIMEOUT, self.child.wait()).await;
    }

    async fn wait_for_private_socket(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("failed to inspect Host Service: {error}"))?
            {
                return Err(format!(
                    "public Host Service exited before publishing its socket: {status}"
                ));
            }
            match std::fs::symlink_metadata(&self.socket) {
                Ok(metadata) => {
                    // SAFETY: geteuid has no preconditions or failure result.
                    let uid = unsafe { libc::geteuid() };
                    if metadata.file_type().is_socket()
                        && metadata.uid() == uid
                        && metadata.mode() & 0o777 == 0o600
                    {
                        return Ok(());
                    }
                    return Err(format!(
                        "public Host Service endpoint is not a same-UID mode-0600 socket: {}",
                        self.socket.display()
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect public Host Service socket {}: {error}",
                        self.socket.display()
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for public Host Service socket".to_string());
            }
            sleep(POLL_INTERVAL).await;
        }
    }
}

fn create_private_log(path: &Path, label: &str) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("failed to create {label} {}: {error}", path.display()))
}

pub(super) fn socket_identity(path: &Path) -> Result<MacosSocketIdentity, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "failed to inspect socket identity {}: {error}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "Host Service path is no longer a socket: {}",
            path.display()
        ));
    }
    Ok(MacosSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        generation: MacosMetadataExt::st_gen(&metadata),
        birth_time_unix_seconds: MacosMetadataExt::st_birthtime(&metadata),
        birth_time_nanoseconds: MacosMetadataExt::st_birthtime_nsec(&metadata),
    })
}

pub(super) fn process_descendants(root_pid: u32) -> Result<Vec<MacosProcessIdentity>, String> {
    let all = process_inventory()?;
    let mut retained = BTreeSet::from([root_pid]);
    loop {
        let before = retained.len();
        for process in &all {
            if retained.contains(&process.parent_pid) {
                retained.insert(process.pid);
            }
        }
        if retained.len() == before {
            break;
        }
    }
    Ok(all
        .into_iter()
        .filter(|process| process.pid != root_pid && retained.contains(&process.pid))
        .collect())
}

pub(super) async fn wait_for_processes_reaped(
    processes: &[MacosProcessIdentity],
) -> Result<bool, String> {
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        let current = process_inventory()?;
        let live = processes.iter().any(|expected| {
            current.iter().any(|process| {
                process.pid == expected.pid
                    && process.start_time_unix_us == expected.start_time_unix_us
            })
        });
        if !live {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub(super) fn endpoint_inventory() -> Result<BTreeSet<PathBuf>, String> {
    let mut endpoints = BTreeSet::new();
    let root = Path::new("/private/tmp");
    for entry in std::fs::read_dir(root)
        .map_err(|error| format!("failed to enumerate /private/tmp: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("failed to inspect /private/tmp entry: {error}"))?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("a3s-oci-agent-") {
            endpoints.insert(entry.path());
        }
    }
    Ok(endpoints)
}

pub(super) fn descriptor_inventory(pid: u32) -> Result<BTreeSet<(i32, u32)>, String> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|error| format!("Host Service PID is invalid: {error}"))?;
    crate::host_cleanup::open_descriptor_inventory_for_pid(pid)
}

pub(super) async fn wait_for_descriptor_inventory(
    pid: u32,
    expected: &BTreeSet<(i32, u32)>,
) -> Result<bool, String> {
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        if descriptor_inventory(pid)? == *expected {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

pub(super) async fn wait_for_endpoint_inventory(
    expected: &BTreeSet<PathBuf>,
) -> Result<bool, String> {
    let deadline = Instant::now() + PROCESS_REAP_TIMEOUT;
    loop {
        if endpoint_inventory()? == *expected {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(POLL_INTERVAL).await;
    }
}

fn process_inventory() -> Result<Vec<MacosProcessIdentity>, String> {
    // SAFETY: a null buffer and zero length request the current PID count.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count < 1 {
        return Err(format!(
            "failed to count macOS processes: {}",
            io::Error::last_os_error()
        ));
    }
    let capacity = usize::try_from(count)
        .ok()
        .and_then(|count| count.checked_add(64))
        .ok_or_else(|| "macOS process inventory capacity overflowed".to_string())?;
    let bytes = capacity
        .checked_mul(size_of::<libc::pid_t>())
        .and_then(|bytes| libc::c_int::try_from(bytes).ok())
        .ok_or_else(|| "macOS process inventory byte size overflowed".to_string())?;
    let mut pids = Vec::<libc::pid_t>::with_capacity(capacity);
    // SAFETY: pids owns capacity for bytes and proc_listallpids initializes
    // at most that many complete pid_t values.
    let retained = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    if retained < 1 {
        return Err(format!(
            "failed to read macOS process inventory: {}",
            io::Error::last_os_error()
        ));
    }
    let retained = usize::try_from(retained)
        .map_err(|error| format!("invalid process inventory length: {error}"))?
        .min(capacity);
    // SAFETY: the kernel reported retained initialized PID entries.
    unsafe { pids.set_len(retained) };
    Ok(pids.into_iter().filter_map(process_identity).collect())
}

fn process_identity(pid: libc::pid_t) -> Option<MacosProcessIdentity> {
    if pid <= 0 {
        return None;
    }
    let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: info is exactly size bytes and a complete return initializes it.
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        return None;
    }
    // SAFETY: proc_pidinfo returned the complete structure size.
    let info = unsafe { info.assume_init() };
    let name_bytes = info
        .pbi_name
        .iter()
        .map(|byte| *byte as u8)
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    let name = String::from_utf8_lossy(&name_bytes).into_owned();
    Some(MacosProcessIdentity {
        pid: info.pbi_pid,
        parent_pid: info.pbi_ppid,
        process_group_id: info.pbi_pgid,
        start_time_unix_us: info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
        command: name,
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::socket_identity;

    #[test]
    fn socket_identity_changes_for_every_rebound_path() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket_path = temporary.path().join("runtime.sock");

        for _ in 0..256 {
            let first =
                std::os::unix::net::UnixListener::bind(&socket_path).expect("bind first socket");
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
                .expect("protect first socket");
            let first_identity = socket_identity(&socket_path).expect("first socket identity");
            drop(first);
            std::fs::remove_file(&socket_path).expect("remove first socket");

            let replacement = std::os::unix::net::UnixListener::bind(&socket_path)
                .expect("bind replacement socket");
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
                .expect("protect replacement socket");
            let replacement_identity =
                socket_identity(&socket_path).expect("replacement socket identity");
            assert_ne!(first_identity, replacement_identity);
            if first_identity.device == replacement_identity.device
                && first_identity.inode == replacement_identity.inode
            {
                assert!(
                    first_identity.generation != replacement_identity.generation
                        || first_identity.birth_time_unix_seconds
                            != replacement_identity.birth_time_unix_seconds
                        || first_identity.birth_time_nanoseconds
                            != replacement_identity.birth_time_nanoseconds
                );
            }
            drop(replacement);
            std::fs::remove_file(&socket_path).expect("remove replacement socket");
        }
    }
}
