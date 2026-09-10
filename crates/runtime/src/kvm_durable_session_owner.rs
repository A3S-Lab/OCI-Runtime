//! Opt-in durable KVM session-owner binding (observation / Live reopen path).
//!
//! Default Host-bound ownership keeps the shim's direct parent as the Host
//! Service PID so owner-death recovery stays stopped-only. Opt-in durable mode
//! inserts a long-lived session-owner process as the shim's direct parent so
//! Host SIGKILL does not tear down the Guest. Replacement Host Live reattach
//! is a later slice; this module only owns the parentage invariant the Linux
//! krun watchdog already enforces (`owner_pid == getppid()`).

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::env;
use std::io;
use std::num::NonZeroU32;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Environment flag that requests durable KVM session ownership.
///
/// When unset/false, Host remains the shim parent (stopped-only on Host death).
/// When true, callers must spawn through [`spawn_holding_child`] so the
/// session owner — not Host — is the shim's direct parent.
#[allow(dead_code)] // public opt-in surface; shim spawn wire-up is the next slice
pub const KVM_SESSION_OWNER_ENV: &str = "A3S_OCI_KVM_SESSION_OWNER";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvmOwnerMode {
    /// Shim parent is the Host Service process (default).
    HostBound,
    /// Shim parent is a durable session-owner process that outlives Host.
    DurableSession,
}

/// Resolve ownership mode from the process environment.
#[allow(dead_code)] // public opt-in surface; shim spawn wire-up is the next slice
pub fn owner_mode_from_env() -> KvmOwnerMode {
    owner_mode_from_value(env::var(KVM_SESSION_OWNER_ENV).ok().as_deref())
}

/// Resolve ownership mode from an optional raw flag value.
pub fn owner_mode_from_value(value: Option<&str>) -> KvmOwnerMode {
    match value {
        Some(value) if is_truthy(value) => KvmOwnerMode::DurableSession,
        _ => KvmOwnerMode::HostBound,
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Handle for a durable session owner that holds one child process group.
#[derive(Debug)]
pub struct DurableSessionOwner {
    owner_pid: NonZeroU32,
    child_pid: NonZeroU32,
}

impl DurableSessionOwner {
    pub fn owner_pid(&self) -> NonZeroU32 {
        self.owner_pid
    }

    pub fn child_pid(&self) -> NonZeroU32 {
        self.child_pid
    }

    /// Terminate the session owner and its process-group child.
    pub fn shutdown(self) -> io::Result<()> {
        // SAFETY: child_pid is the process-group leader we spawned.
        let _ = unsafe { libc::kill(-(self.child_pid.get() as libc::pid_t), libc::SIGKILL) };
        // SAFETY: owner_pid is the durable owner we spawned.
        let rc = unsafe { libc::kill(self.owner_pid.get() as libc::pid_t, libc::SIGKILL) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err);
            }
        }
        let mut status = 0;
        loop {
            let waited = unsafe {
                libc::waitpid(
                    self.owner_pid.get() as libc::pid_t,
                    &mut status,
                    libc::WNOHANG,
                )
            };
            if waited == 0 {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            if waited < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD) {
                    break;
                }
                return Err(err);
            }
            break;
        }
        Ok(())
    }
}

/// Spawn a durable session owner that becomes the direct parent of `child`.
///
/// The owner process:
/// - is forked from the current Host process;
/// - forks/execs `child` with `process_group(0)` so the Linux krun parentage
///   and process-group invariants can hold;
/// - stays alive until [`DurableSessionOwner::shutdown`] or the owner is
///   SIGKILL'd (Host exit alone does not terminate it).
///
/// The caller must not `kill_on_drop` this owner if Host death should leave
/// the Guest running for Live reopen.
pub fn spawn_holding_child(child: Command) -> io::Result<DurableSessionOwner> {
    let mut child = child;
    let (owner_ready_reader, owner_ready_writer) = anonymous_pipe()?;
    let (child_ready_reader, child_ready_writer) = anonymous_pipe()?;

    // SAFETY: callers must invoke from a single-threaded Host context (or a
    // freshly exec'd helper). The Linux krun Host path matches that boundary.
    let owner_pid = unsafe { libc::fork() };
    if owner_pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if owner_pid == 0 {
        drop(owner_ready_reader);
        drop(child_ready_reader);
        // SAFETY: setsid has no preconditions beyond being a non-leader.
        let _ = unsafe { libc::setsid() };
        run_owner_child(child, owner_ready_writer, child_ready_writer);
    }

    drop(owner_ready_writer);
    drop(child_ready_writer);
    wait_pipe_byte(owner_ready_reader)?;
    let child_pid = read_pid_from_pipe(child_ready_reader)?;
    let owner_pid = NonZeroU32::new(owner_pid as u32).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "durable KVM session owner returned a zero PID",
        )
    })?;
    Ok(DurableSessionOwner {
        owner_pid,
        child_pid,
    })
}

fn run_owner_child(
    mut child: Command,
    owner_ready_writer: OwnedWritePipe,
    child_ready_writer: OwnedWritePipe,
) -> ! {
    child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    child.process_group(0);
    let mut spawned = match child.spawn() {
        Ok(spawned) => spawned,
        Err(_) => unsafe { libc::_exit(111) },
    };
    let Some(child_pid) = NonZeroU32::new(spawned.id()) else {
        let _ = spawned.kill();
        unsafe { libc::_exit(112) };
    };
    if write_pipe_byte(&owner_ready_writer).is_err() {
        let _ = spawned.kill();
        unsafe { libc::_exit(113) };
    }
    if write_pid_to_pipe(&child_ready_writer, child_pid).is_err() {
        let _ = spawned.kill();
        unsafe { libc::_exit(114) };
    }
    drop(owner_ready_writer);
    drop(child_ready_writer);
    loop {
        match spawned.try_wait() {
            Ok(Some(_)) => unsafe { libc::_exit(0) },
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => unsafe { libc::_exit(115) },
        }
    }
}

struct OwnedWritePipe(i32);
struct OwnedReadPipe(i32);

impl Drop for OwnedWritePipe {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.0);
        }
    }
}

impl Drop for OwnedReadPipe {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.0);
        }
    }
}

fn anonymous_pipe() -> io::Result<(OwnedReadPipe, OwnedWritePipe)> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((OwnedReadPipe(fds[0]), OwnedWritePipe(fds[1])))
}

fn write_pipe_byte(pipe: &OwnedWritePipe) -> io::Result<()> {
    loop {
        let n = unsafe { libc::write(pipe.0, b"R".as_ptr().cast(), 1) };
        if n == 1 {
            return Ok(());
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
    }
}

fn wait_pipe_byte(pipe: OwnedReadPipe) -> io::Result<()> {
    let mut buf = [0u8; 1];
    loop {
        let n = unsafe { libc::read(pipe.0, buf.as_mut_ptr().cast(), 1) };
        if n == 1 {
            return Ok(());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "durable KVM session owner exited before readiness",
            ));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(err);
    }
}

fn write_pid_to_pipe(pipe: &OwnedWritePipe, pid: NonZeroU32) -> io::Result<()> {
    let bytes = pid.get().to_ne_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let n = unsafe {
            libc::write(
                pipe.0,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        offset += n as usize;
    }
    Ok(())
}

fn read_pid_from_pipe(pipe: OwnedReadPipe) -> io::Result<NonZeroU32> {
    let mut bytes = [0u8; 4];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = unsafe {
            libc::read(
                pipe.0,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "durable KVM session owner closed child-pid pipe early",
            ));
        }
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        offset += n as usize;
    }
    NonZeroU32::new(u32::from_ne_bytes(bytes)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "durable KVM session owner reported a zero child PID",
        )
    })
}

fn process_alive(pid: NonZeroU32) -> bool {
    let rc = unsafe { libc::kill(pid.get() as libc::pid_t, 0) };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    const HOST_REPORT_ENV: &str = "A3S_OCI_TEST_KVM_OWNER_REPORT";
    const HOST_GATE_ENV: &str = "A3S_OCI_TEST_KVM_OWNER_GATE";
    const HOST_WORKER: &str = "kvm_durable_session_owner::tests::host_analogue_worker";

    #[test]
    fn owner_mode_defaults_to_host_bound() {
        assert_eq!(owner_mode_from_value(None), KvmOwnerMode::HostBound);
        assert_eq!(owner_mode_from_value(Some("")), KvmOwnerMode::HostBound);
        assert_eq!(owner_mode_from_value(Some("0")), KvmOwnerMode::HostBound);
        assert_eq!(owner_mode_from_value(Some("false")), KvmOwnerMode::HostBound);
    }

    #[test]
    fn owner_mode_opt_in_is_durable() {
        assert_eq!(owner_mode_from_value(Some("1")), KvmOwnerMode::DurableSession);
        assert_eq!(owner_mode_from_value(Some("true")), KvmOwnerMode::DurableSession);
        assert_eq!(owner_mode_from_value(Some("YES")), KvmOwnerMode::DurableSession);
    }

    #[test]
    fn durable_session_owner_outlives_host_and_stops_with_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let report = temp.path().join("report");
        let gate = temp.path().join("gate");

        let mut host = Command::new(env::current_exe().expect("test exe"))
            .args(["--exact", HOST_WORKER, "--nocapture"])
            .env(HOST_REPORT_ENV, &report)
            .env(HOST_GATE_ENV, &gate)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn host analogue worker");

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if report.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let payload = fs::read(&report).expect("read owner/child report");
        assert_eq!(payload.len(), 8, "report must be two u32 PIDs");
        let owner_pid =
            NonZeroU32::new(u32::from_ne_bytes(payload[..4].try_into().unwrap())).unwrap();
        let child_pid =
            NonZeroU32::new(u32::from_ne_bytes(payload[4..].try_into().unwrap())).unwrap();

        // SIGKILL the Host analogue without giving it a chance to shut down.
        // SAFETY: host.id is the worker we spawned.
        let host_pid = host.id() as i32;
        assert_eq!(unsafe { libc::kill(host_pid, libc::SIGKILL) }, 0);
        let _ = host.wait();

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if process_alive(owner_pid) && process_alive(child_pid) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            process_alive(owner_pid),
            "durable session owner must survive Host SIGKILL"
        );
        assert!(
            process_alive(child_pid),
            "session child must survive Host SIGKILL while owner lives"
        );

        DurableSessionOwner {
            owner_pid,
            child_pid,
        }
        .shutdown()
        .expect("shutdown durable owner");

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if !process_alive(owner_pid) && !process_alive(child_pid) {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!process_alive(owner_pid), "owner must exit after shutdown");
        assert!(
            !process_alive(child_pid),
            "child must exit after owner shutdown"
        );

        let _ = gate;
        let _ = PathBuf::from("keep tempdir until assertions finish");
        drop(temp);
    }

    #[test]
    fn host_analogue_worker() {
        let Ok(report_path) = env::var(HOST_REPORT_ENV) else {
            return;
        };
        let Ok(gate_path) = env::var(HOST_GATE_ENV) else {
            return;
        };
        env::remove_var(HOST_REPORT_ENV);
        env::remove_var(HOST_GATE_ENV);

        let mut sleep = Command::new("/bin/sleep");
        sleep.arg("3600");
        let owner =
            spawn_holding_child(sleep).expect("spawn durable owner under isolated host analogue");
        let mut payload = [0u8; 8];
        payload[..4].copy_from_slice(&owner.owner_pid().get().to_ne_bytes());
        payload[4..].copy_from_slice(&owner.child_pid().get().to_ne_bytes());
        let tmp = PathBuf::from(&report_path).with_extension("tmp");
        fs::write(&tmp, payload).expect("write report tmp");
        fs::rename(&tmp, &report_path).expect("publish report");

        // Stay alive until SIGKILL from the parent test (gate unused except as
        // a rendezvous path identity). Do not shut down the durable owner.
        let _ = gate_path;
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
}
