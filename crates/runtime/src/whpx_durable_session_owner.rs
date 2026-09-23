//! Opt-in durable WHPX session-owner mode (Live Host reopen substrate).
//!
//! Default Host-bound ownership keeps the libkrun shim's owner watchdog pointed
//! at the Host Service PID, so Host taskkill tears down the Guest
//! (stopped-only recovery — see `whpx_recovery_smoke`). Opt-in durable mode
//! inserts a long-lived session-owner process as the shim owner so Host death
//! does not terminate the VM; replacement Host Live reattach uses
//! [`crate::whpx_live_session_binding`].
//!
//! Durable AgentVmSession Live path requires session-owner host-control named
//! pipe ownership (`--host-control`) so Host connects as a client and Host death
//! does not destroy the guest agent pipe. Does **not** claim Box Enterprise GA
//! or flip `b2_process_session_recovery_closed`.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::env;
use std::fs;
use std::io;
use std::num::NonZeroU32;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, CREATE_BREAKAWAY_FROM_JOB,
    CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

/// Environment flag that requests durable WHPX session ownership.
///
/// When unset/false, Host remains the shim owner (stopped-only on Host death).
/// When true, callers must use [`spawn_via_session_owner_helper`] with a
/// host-control pipe for the AgentVmSession Live path.
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

/// Handle for a durable session owner that holds one Job-Object child.
#[derive(Debug)]
pub struct DurableSessionOwner {
    owner_pid: NonZeroU32,
    child_pid: NonZeroU32,
}

impl DurableSessionOwner {
    /// Reconstruct a durable owner handle from authenticated PIDs (Live reattach).
    pub fn from_authenticated(owner_pid: NonZeroU32, child_pid: NonZeroU32) -> Self {
        Self {
            owner_pid,
            child_pid,
        }
    }

    pub fn owner_pid(&self) -> NonZeroU32 {
        self.owner_pid
    }

    pub fn child_pid(&self) -> NonZeroU32 {
        self.child_pid
    }

    pub fn child_alive(&self) -> bool {
        process_alive(self.child_pid)
    }

    pub fn owner_alive(&self) -> bool {
        process_alive(self.owner_pid)
    }

    /// Terminate the session owner (Job `KILL_ON_JOB_CLOSE` reaps the shim).
    pub fn shutdown(self) -> io::Result<()> {
        terminate_pid(self.owner_pid)
    }
}

/// DurableSession spawn helper is productized (Job Object + optional host-control).
///
/// AgentVmSession must still pass `--host-control` for the Live bridge path;
/// missing host-control fails closed in the session launch, not here.
pub fn require_durable_spawn_ready(mode: WhpxOwnerMode) -> io::Result<()> {
    let _ = mode;
    Ok(())
}

/// Spawn `a3s-oci-krun-shim session-owner` as a Host child (Tokio-safe).
///
/// Uses `CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS`
/// so Host taskkill does not tear down the session-owner. `shim_argv` must not
/// include `--owner-pid`; the helper injects its own PID.
pub fn spawn_via_session_owner_helper(
    krun_shim: &Path,
    shim_argv: &[std::ffi::OsString],
    ready_file: &Path,
) -> io::Result<DurableSessionOwner> {
    spawn_via_session_owner_helper_with_env(krun_shim, shim_argv, ready_file, None, &[])
}

/// Like [`spawn_via_session_owner_helper`], forwarding extra environment.
///
/// When `host_control` is set, the session-owner binds the shim `--pipe-name`
/// guest pipe and proxies Host↔shim on that control named pipe for Live reattach.
pub fn spawn_via_session_owner_helper_with_env(
    krun_shim: &Path,
    shim_argv: &[std::ffi::OsString],
    ready_file: &Path,
    host_control: Option<&str>,
    envs: &[(&str, &str)],
) -> io::Result<DurableSessionOwner> {
    if shim_argv.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable session-owner shim argv must be non-empty",
        ));
    }
    if shim_argv.iter().any(|arg| arg == "--owner-pid") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "durable session-owner shim argv must not include --owner-pid",
        ));
    }
    if let Some(path) = host_control {
        if !path.starts_with(r"\\.\pipe\") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "durable session-owner host-control must be a local named-pipe path, got {path}"
                ),
            ));
        }
    }
    if ready_file.exists() {
        let _ = fs::remove_file(ready_file);
    }

    let stderr_log = ready_file.with_extension("stderr.log");
    let stderr_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&stderr_log)?;

    // Prefer breakaway so Host job KILL_ON_JOB_CLOSE does not reap the owner.
    // When the parent job forbids breakaway (ERROR_ACCESS_DENIED / 5), fall back
    // to new-process-group + detached only.
    let breakaway_flags = CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;
    let fallback_flags = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;

    let mut owner = Command::new(krun_shim);
    owner
        .arg("session-owner")
        .arg("--ready-file")
        .arg(ready_file);
    if let Some(path) = host_control {
        owner.arg("--host-control").arg(path);
    }
    owner
        .args(shim_argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .creation_flags(breakaway_flags);
    for (key, value) in envs {
        owner.env(key, value);
    }
    let mut spawned = match owner.spawn() {
        Ok(child) => child,
        Err(error) if error.raw_os_error() == Some(5) => {
            let stderr_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&stderr_log)?;
            let mut retry = Command::new(krun_shim);
            retry
                .arg("session-owner")
                .arg("--ready-file")
                .arg(ready_file);
            if let Some(path) = host_control {
                retry.arg("--host-control").arg(path);
            }
            retry
                .args(shim_argv)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(stderr_file))
                .creation_flags(fallback_flags);
            for (key, value) in envs {
                retry.env(key, value);
            }
            retry.spawn()?
        }
        Err(error) => return Err(error),
    };
    let owner_pid = NonZeroU32::new(spawned.id()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "durable session-owner helper returned a zero PID",
        )
    })?;

    let child_pid = wait_for_ready_file(ready_file, owner_pid, &mut spawned, &stderr_log)?;
    // Detach from the Child handle so Host drop does not kill the owner.
    // Session-owner outlives Host; shutdown() terminates it explicitly.
    std::mem::forget(spawned);

    Ok(DurableSessionOwner {
        owner_pid,
        child_pid,
    })
}

/// Build the session-owner argv prefix used by the spawn helper (test aid).
#[cfg(test)]
pub(crate) fn session_owner_argv_prefix(
    ready_file: &Path,
    host_control: Option<&str>,
) -> Vec<std::ffi::OsString> {
    let mut args = vec![
        std::ffi::OsString::from("session-owner"),
        std::ffi::OsString::from("--ready-file"),
        ready_file.as_os_str().to_owned(),
    ];
    if let Some(path) = host_control {
        args.push(std::ffi::OsString::from("--host-control"));
        args.push(std::ffi::OsString::from(path));
    }
    args
}

fn wait_for_ready_file(
    ready_file: &Path,
    owner_pid: NonZeroU32,
    spawned: &mut std::process::Child,
    stderr_log: &Path,
) -> io::Result<NonZeroU32> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Some(status)) = spawned.try_wait() {
            let detail = fs::read_to_string(stderr_log).unwrap_or_default();
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                if detail.trim().is_empty() {
                    format!("durable session-owner helper exited before readiness: {status}")
                } else {
                    format!(
                        "durable session-owner helper exited before readiness: {status}: {detail}"
                    )
                },
            ));
        }
        if !process_alive(owner_pid) {
            let detail = fs::read_to_string(stderr_log).unwrap_or_default();
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!(
                    "durable session-owner helper died before readiness: {}",
                    detail.trim()
                ),
            ));
        }
        if ready_file.is_file() {
            let contents = fs::read_to_string(ready_file)?;
            let line = contents
                .lines()
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "session-owner ready file is empty",
                    )
                })?
                .trim();
            let pid: u32 = line.parse().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("session-owner ready file pid parse failed: {error}"),
                )
            })?;
            return NonZeroU32::new(pid).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session-owner ready file reported a zero shim PID",
                )
            });
        }
        if Instant::now() >= deadline {
            let _ = terminate_pid(owner_pid);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for durable session-owner readiness",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn process_alive(pid: NonZeroU32) -> bool {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid.get()) };
    if handle.is_null() {
        return false;
    }
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    wait != WAIT_OBJECT_0
}

fn terminate_pid(pid: NonZeroU32) -> io::Result<()> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.get(),
        )
    };
    if handle.is_null() {
        let err = io::Error::last_os_error();
        // Already gone.
        if err.raw_os_error() == Some(87) || err.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(err);
    }
    let ok = unsafe { TerminateProcess(handle, 1) };
    if ok == 0 {
        let err = io::Error::last_os_error();
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(err);
    }
    let _ = unsafe { WaitForSingleObject(handle, INFINITE) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use std::path::PathBuf;
    use std::ptr;
    use std::thread;

    use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

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
    fn durable_mode_is_ready_when_spawn_helper_exists() {
        require_durable_spawn_ready(WhpxOwnerMode::DurableSession)
            .expect("durable spawn helper is productized");
        require_durable_spawn_ready(WhpxOwnerMode::HostBound).expect("host-bound ok");
    }

    #[test]
    fn session_owner_argv_includes_host_control_before_shim() {
        let ready = PathBuf::from(r"C:\temp\ready");
        let host_control = r"\\.\pipe\a3s-oci-whpx-live-control-test";
        let prefix = session_owner_argv_prefix(&ready, Some(host_control));
        assert_eq!(prefix[0], "session-owner");
        assert_eq!(prefix[1], "--ready-file");
        assert_eq!(prefix[2], ready.as_os_str());
        assert_eq!(prefix[3], "--host-control");
        assert_eq!(prefix[4], host_control);
    }

    #[test]
    fn host_control_must_be_local_named_pipe_path() {
        let temporary = tempfile::tempdir().expect("tempdir");
        let ready = temporary.path().join("ready");
        let shim = PathBuf::from("C:\\Windows\\System32\\cmd.exe");
        let argv = [OsString::from("/c"), OsString::from("exit")];
        let error = spawn_via_session_owner_helper_with_env(
            &shim,
            &argv,
            &ready,
            Some(r"C:\not-a-pipe"),
            &[],
        )
        .expect_err("non-pipe host-control must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    fn resolve_krun_shim() -> Option<PathBuf> {
        if let Ok(path) = env::var("A3S_OCI_KRUN_SHIM") {
            let path = PathBuf::from(path);
            if path.is_file() {
                return Some(path);
            }
        }
        let mut dir = env::current_exe().ok()?.parent()?.to_path_buf();
        for _ in 0..6 {
            for candidate in [
                dir.join("a3s-oci-krun-shim.exe"),
                dir.join("deps").join("a3s-oci-krun-shim.exe"),
            ] {
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
            if !dir.pop() {
                break;
            }
        }
        None
    }

    #[test]
    fn session_owner_helper_parents_probe_and_survives_host_detach() {
        let Some(shim) = resolve_krun_shim() else {
            eprintln!("skipping: build a3s-oci-krun-shim or set A3S_OCI_KRUN_SHIM");
            return;
        };
        assert!(shim.is_file(), "krun shim must be a file: {shim:?}");

        let temporary = tempfile::tempdir().expect("tempdir");
        let ready = temporary.path().join("ready");
        let argv = vec![
            OsString::from("session-owner-probe"),
            OsString::from("--sleep-ms"),
            OsString::from("60000"),
        ];
        let owner = spawn_via_session_owner_helper(&shim, &argv, &ready)
            .expect("spawn via session-owner helper");
        let owner_pid = owner.owner_pid();
        let child_pid = owner.child_pid();
        assert!(
            owner.owner_alive(),
            "session-owner must be alive after ready"
        );
        assert!(owner.child_alive(), "probe child must be alive after ready");
        assert_ne!(
            owner_pid.get(),
            child_pid.get(),
            "owner and probe must be distinct PIDs"
        );

        // Host released the Child handle via mem::forget inside spawn; owner
        // must still be alive briefly without Host holding it.
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            process_alive(owner_pid) && process_alive(child_pid),
            "durable session owner must survive after Host releases Child handle"
        );

        owner.shutdown().expect("shutdown session-owner");
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !process_alive(owner_pid) && !process_alive(child_pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!process_alive(owner_pid), "owner must exit after shutdown");
        assert!(
            !process_alive(child_pid),
            "Job KILL_ON_JOB_CLOSE must reap probe after owner shutdown"
        );
    }

    #[test]
    fn session_owner_host_control_bridge_echoes_across_host_reconnect() {
        let Some(shim) = resolve_krun_shim() else {
            eprintln!("skipping: build a3s-oci-krun-shim or set A3S_OCI_KRUN_SHIM");
            return;
        };

        let leaf = format!("a3s-oci-whpx-bridge-{}", std::process::id());
        let guest_pipe_name = format!("a3s-oci-agent-{leaf}");
        let host_control = format!(r"\\.\pipe\a3s-oci-whpx-live-control-{leaf}");
        let temporary = tempfile::tempdir().expect("tempdir");
        let ready = temporary.path().join("ready");
        let argv = [
            OsString::from("session-owner-bridge-echo"),
            OsString::from("--pipe-name"),
            OsString::from(&guest_pipe_name),
        ];
        let owner = spawn_via_session_owner_helper_with_env(
            &shim,
            &argv,
            &ready,
            Some(host_control.as_str()),
            &[],
        )
        .expect("spawn session-owner bridge");

        let mut first = connect_host_control_client(&host_control).expect("first host connect");
        first.write_all(b"ping-1").expect("write first");
        let mut buf = [0u8; 16];
        let n = first.read(&mut buf).expect("read first");
        assert_eq!(&buf[..n], b"ping-1");
        drop(first);

        let mut second = connect_host_control_client(&host_control).expect("second host connect");
        second.write_all(b"ping-2").expect("write second");
        let n = second.read(&mut buf).expect("read second");
        assert_eq!(&buf[..n], b"ping-2");
        drop(second);

        assert!(owner.owner_alive());
        assert!(owner.child_alive());
        owner.shutdown().expect("shutdown bridge owner");
    }

    fn connect_host_control_client(path: &str) -> io::Result<std::fs::File> {
        let wide: Vec<u16> =
            std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(path))
                .chain(std::iter::once(0))
                .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let _ = unsafe { WaitNamedPipeW(wide.as_ptr(), 100) };
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0 as FILE_SHARE_MODE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE && !raw.is_null() {
                return Ok(unsafe { std::fs::File::from_raw_handle(raw as _) });
            }
            let err = io::Error::last_os_error();
            if Instant::now() >= deadline {
                return Err(err);
            }
            if err.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
