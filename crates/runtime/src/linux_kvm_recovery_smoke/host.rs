use std::collections::BTreeSet;
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Instant};

use super::report::LinuxProcessIdentity;

const START_TIMEOUT: Duration = Duration::from_secs(20);
const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const REAP_TIMEOUT: Duration = Duration::from_secs(25);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostServiceKind {
    Recovery,
    Soak,
}

impl HostServiceKind {
    const fn command(self) -> &'static str {
        match self {
            Self::Recovery => "linux-kvm-recovery-host-service",
            Self::Soak => "linux-kvm-soak-host-service",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Recovery => "Linux KVM recovery Host Service",
            Self::Soak => "Linux KVM soak Host Service",
        }
    }
}

pub(super) struct HostServiceProcess {
    child: Child,
    socket: PathBuf,
    socket_peer: Option<LinuxProcessIdentity>,
    kind: HostServiceKind,
}

impl HostServiceProcess {
    pub(super) async fn spawn(
        kind: HostServiceKind,
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
            .arg(kind.command())
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
            .map_err(|error| format!("failed to start {}: {error}", kind.label()))?;
        let mut process = Self {
            child,
            socket: root.join("runtime.sock"),
            socket_peer: None,
            kind,
        };
        match process.wait_for_private_socket().await {
            Ok(()) => Ok(process),
            Err(primary) => {
                process.emergency_stop().await;
                Err(primary)
            }
        }
    }

    pub(super) fn identity(&self) -> Result<LinuxProcessIdentity, String> {
        let pid = self.pid()?;
        process_identity(pid)?.ok_or_else(|| {
            format!("failed to retain exact Host Service process identity for PID {pid}")
        })
    }

    pub(super) fn pid(&self) -> Result<u32, String> {
        self.child
            .id()
            .ok_or_else(|| format!("{} has no live PID", self.kind.label()))
    }

    pub(super) fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub(super) fn socket_peer(&self) -> Result<&LinuxProcessIdentity, String> {
        self.socket_peer
            .as_ref()
            .ok_or_else(|| "Host Service socket peer was not retained".to_string())
    }

    pub(super) async fn connect(&self) -> Result<RuntimeClient, String> {
        let endpoint = LocalIpcEndpoint::unix_socket(&self.socket)
            .map_err(|error| format!("failed to configure Host Service endpoint: {error}"))?;
        timeout(START_TIMEOUT, RuntimeClient::connect(&endpoint))
            .await
            .map_err(|_| format!("timed out connecting to {}", self.kind.label()))?
            .map_err(|error| format!("failed to connect {}: {error}", self.kind.label()))
    }

    pub(super) async fn terminate(&mut self) -> Result<bool, String> {
        let pid = libc::pid_t::try_from(self.pid()?)
            .map_err(|error| format!("Host Service PID is invalid: {error}"))?;
        // SAFETY: pid identifies the exact retained child and SIGTERM is handled
        // as a normal graceful service shutdown request.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("failed to terminate Host Service: {error}"));
            }
        }
        match timeout(STOP_TIMEOUT, self.child.wait()).await {
            Ok(Ok(status)) => Ok(status.success()),
            Ok(Err(error)) => Err(format!("failed to reap Host Service: {error}")),
            Err(_) => {
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
                Err("Host Service did not stop after SIGTERM".to_string())
            }
        }
    }

    pub(super) async fn sigkill(&mut self) -> Result<(), String> {
        let pid = libc::pid_t::try_from(self.pid()?)
            .map_err(|error| format!("Host Service PID is invalid: {error}"))?;
        // SAFETY: pid identifies the exact retained child. This is the
        // qualification's deliberate uncatchable owner-death boundary.
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            return Err(format!(
                "failed to SIGKILL Host Service: {}",
                io::Error::last_os_error()
            ));
        }
        let status = timeout(STOP_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| "timed out reaping SIGKILLed Host Service".to_string())?
            .map_err(|error| format!("failed to reap SIGKILLed Host Service: {error}"))?;
        if status.signal() != Some(libc::SIGKILL) {
            return Err(format!(
                "Host Service exited with {status}, expected SIGKILL"
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
        let expected_pid = self.pid()?;
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("failed to inspect Host Service: {error}"))?
            {
                return Err(format!(
                    "Host Service exited before publishing its socket: {status}"
                ));
            }
            match std::fs::symlink_metadata(&self.socket) {
                Ok(metadata) => {
                    // SAFETY: geteuid has no preconditions or failure result.
                    let uid = unsafe { libc::geteuid() };
                    if !metadata.file_type().is_socket()
                        || metadata.uid() != uid
                        || metadata.mode() & 0o777 != 0o600
                    {
                        return Err(format!(
                            "Host Service endpoint is not a same-UID mode-0600 socket: {}",
                            self.socket.display()
                        ));
                    }
                    if let Some(peer) =
                        connect_expected_socket_peer(&self.socket, expected_pid).await?
                    {
                        self.socket_peer = Some(peer);
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "failed to inspect Host Service socket {}: {error}",
                        self.socket.display()
                    ));
                }
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for Host Service socket".to_string());
            }
            sleep(POLL_INTERVAL).await;
        }
    }
}

async fn connect_expected_socket_peer(
    path: &Path,
    expected_pid: u32,
) -> Result<Option<LinuxProcessIdentity>, String> {
    let stream = match tokio::net::UnixStream::connect(path).await {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => {
            return Err(format!(
                "failed to probe Host Service socket {}: {error}",
                path.display()
            ));
        }
    };
    let mut credentials = MaybeUninit::<libc::ucred>::zeroed();
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>())
        .map_err(|error| format!("failed to represent SO_PEERCRED size: {error}"))?;
    // SAFETY: the connected stream owns a valid descriptor and the output
    // storage is exactly one ucred structure for the complete call.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if status != 0 || usize::try_from(length).ok() != Some(size_of::<libc::ucred>()) {
        return Err(format!(
            "failed to identify Host Service socket peer: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: getsockopt returned the complete ucred structure.
    let credentials = unsafe { credentials.assume_init() };
    let peer_pid = u32::try_from(credentials.pid)
        .map_err(|_| format!("SO_PEERCRED returned invalid PID {}", credentials.pid))?;
    if peer_pid != expected_pid {
        return Err(format!(
            "Host Service socket peer PID {peer_pid} does not match spawned PID {expected_pid}"
        ));
    }
    process_identity(peer_pid)?.map_or_else(
        || Err("failed to retain exact Host Service socket peer identity".to_string()),
        |identity| Ok(Some(identity)),
    )
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

pub(super) fn socket_identity(path: &Path) -> Result<(u64, u64), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("failed to inspect socket {}: {error}", path.display()))?;
    if !metadata.file_type().is_socket() {
        return Err(format!(
            "Host Service path is not a socket: {}",
            path.display()
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

pub(super) fn process_descendants(root_pid: u32) -> Result<Vec<LinuxProcessIdentity>, String> {
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
    processes: &[LinuxProcessIdentity],
) -> Result<bool, String> {
    let deadline = Instant::now() + REAP_TIMEOUT;
    loop {
        let current = process_inventory()?;
        let live = processes.iter().any(|expected| {
            current.iter().any(|process| {
                process.pid == expected.pid && process.start_time_ticks == expected.start_time_ticks
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
    for entry in
        std::fs::read_dir("/tmp").map_err(|error| format!("failed to enumerate /tmp: {error}"))?
    {
        let entry = entry.map_err(|error| format!("failed to inspect /tmp entry: {error}"))?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("a3s-oci-agent-")
        {
            endpoints.insert(entry.path());
        }
    }
    Ok(endpoints)
}

pub(super) async fn wait_for_endpoint_inventory(
    expected: &BTreeSet<PathBuf>,
) -> Result<bool, String> {
    let deadline = Instant::now() + REAP_TIMEOUT;
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

pub(super) fn descriptor_inventory(pid: u32) -> Result<BTreeSet<(u32, String)>, String> {
    let root = PathBuf::from(format!("/proc/{pid}/fd"));
    let mut descriptors = BTreeSet::new();
    for entry in std::fs::read_dir(&root)
        .map_err(|error| format!("failed to enumerate {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| format!("failed to inspect descriptor: {error}"))?;
        let descriptor = entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|error| format!("invalid descriptor name: {error}"))?;
        match std::fs::read_link(entry.path()) {
            Ok(target) => {
                descriptors.insert((descriptor, target.to_string_lossy().into_owned()));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect descriptor {descriptor}: {error}"
                ))
            }
        }
    }
    Ok(descriptors)
}

pub(super) async fn wait_for_descriptor_inventory(
    pid: u32,
    expected: &BTreeSet<(u32, String)>,
) -> Result<bool, String> {
    let deadline = Instant::now() + REAP_TIMEOUT;
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

fn process_inventory() -> Result<Vec<LinuxProcessIdentity>, String> {
    let mut processes = Vec::new();
    for entry in
        std::fs::read_dir("/proc").map_err(|error| format!("failed to enumerate /proc: {error}"))?
    {
        let entry = entry.map_err(|error| format!("failed to inspect /proc entry: {error}"))?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Some(identity) = process_identity(pid)? {
            processes.push(identity);
        }
    }
    Ok(processes)
}

fn process_identity(pid: u32) -> Result<Option<LinuxProcessIdentity>, String> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let encoded = match std::fs::read_to_string(&path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return Ok(None),
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    };
    let open = encoded
        .find('(')
        .ok_or_else(|| format!("process stat has no command start: {}", path.display()))?;
    let close = encoded
        .rfind(')')
        .ok_or_else(|| format!("process stat has no command end: {}", path.display()))?;
    if close <= open {
        return Err(format!(
            "process stat command is malformed: {}",
            path.display()
        ));
    }
    let retained_pid = encoded[..open]
        .trim()
        .parse::<u32>()
        .map_err(|error| format!("invalid process stat PID: {error}"))?;
    if retained_pid != pid {
        return Err(format!(
            "process stat PID changed from {pid} to {retained_pid}"
        ));
    }
    let command = encoded[open + 1..close].to_string();
    let fields = encoded[close + 1..].split_whitespace().collect::<Vec<_>>();
    if fields.len() <= 19 {
        return Err(format!("process stat is truncated: {}", path.display()));
    }
    let parent_pid = fields[1]
        .parse::<u32>()
        .map_err(|error| format!("invalid parent PID: {error}"))?;
    let process_group_id = fields[2]
        .parse::<u32>()
        .map_err(|error| format!("invalid process group ID: {error}"))?;
    let start_time_ticks = fields[19]
        .parse::<u64>()
        .map_err(|error| format!("invalid process start time: {error}"))?;
    Ok(Some(LinuxProcessIdentity {
        pid,
        parent_pid,
        process_group_id,
        start_time_ticks,
        command,
    }))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn current_process_identity_is_exact_and_live() {
        let identity = process_identity(std::process::id())
            .expect("inspect current process")
            .expect("current process identity");
        assert_eq!(identity.pid, std::process::id());
        assert!(identity.start_time_ticks > 0);
        assert!(!identity.command.is_empty());
    }

    #[tokio::test]
    async fn readiness_requires_the_expected_kernel_socket_peer() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let socket = temporary.path().join("runtime.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind socket");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("protect socket");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept readiness probe");
            drop(stream);
        });
        let peer = connect_expected_socket_peer(&socket, std::process::id())
            .await
            .expect("probe peer")
            .expect("live peer");
        assert_eq!(peer.pid, std::process::id());
        server.await.expect("server task");
    }
}
