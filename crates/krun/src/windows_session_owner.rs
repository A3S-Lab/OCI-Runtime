//! Windows WHPX durable session-owner helper (shim CLI).
//!
//! Becomes the shim `--owner-pid` so Host taskkill does not tear down the Guest.
//! Holds a Job Object with `KILL_ON_JOB_CLOSE` so session-owner exit reaps the
//! shim. Host-control named-pipe proxy for Live reattach is a later slice.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::fs;
use std::io;
use std::num::NonZeroU32;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::ptr;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, WaitForSingleObject, CREATE_NEW_PROCESS_GROUP,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

const OWNER_EXIT_CODE: u32 = 3;

/// Qualification probe: sleep while the injected owner PID remains openable.
pub(crate) fn run_session_owner_probe(
    owner_pid: NonZeroU32,
    sleep_ms: u64,
) -> Result<ExitCode, String> {
    // Windows owner watchdog uses process handles, not parentage. Prove the
    // owner PID is a live process object the probe can synchronize on.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, owner_pid.get()) };
    if handle.is_null() {
        return Err(format!(
            "session-owner-probe cannot open owner PID {}: {}",
            owner_pid,
            io::Error::last_os_error()
        ));
    }
    unsafe {
        let _ = CloseHandle(handle);
    }
    thread::sleep(Duration::from_millis(sleep_ms));
    Ok(ExitCode::SUCCESS)
}

/// Spawn trailing shim argv with `--owner-pid` = this process; publish ready file.
pub(crate) fn run_session_owner(
    ready_file: PathBuf,
    shim_argv: Vec<std::ffi::OsString>,
) -> Result<ExitCode, String> {
    if shim_argv.is_empty() {
        return Err("session-owner requires a non-empty shim argv after the subcommand".into());
    }
    if shim_argv.iter().any(|arg| arg == "--owner-pid") {
        return Err("session-owner shim argv must not include --owner-pid".into());
    }

    let job = create_kill_on_close_job()?;
    let owner_pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| "session-owner observed a zero process ID".to_string())?;
    let exe = std::env::current_exe()
        .map_err(|error| format!("resolve session-owner executable: {error}"))?;

    let mut child = Command::new(&exe);
    child.args(&shim_argv);
    child.arg("--owner-pid").arg(owner_pid.to_string());
    child
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NEW_PROCESS_GROUP);
    let mut spawned = child
        .spawn()
        .map_err(|error| format!("spawn shim under session-owner: {error}"))?;
    let shim_pid = NonZeroU32::new(spawned.id())
        .ok_or_else(|| "shim under session-owner has no process ID".to_string())?;

    assign_child_to_job(&job, &spawned)?;

    let tmp = ready_file.with_extension("tmp");
    fs::write(&tmp, format!("{}\n", shim_pid.get()))
        .map_err(|error| format!("write session-owner ready tmp: {error}"))?;
    fs::rename(&tmp, &ready_file)
        .map_err(|error| format!("publish session-owner ready file: {error}"))?;

    let status = spawned
        .wait()
        .map_err(|error| format!("wait for session-owner shim: {error}"))?;
    // Dropping `job` with KILL_ON_JOB_CLOSE terminates any leftover children.
    drop(job);
    if status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(OWNER_EXIT_CODE as u8))
    }
}

fn create_kill_on_close_job() -> Result<OwnedHandle, String> {
    // SAFETY: CreateJobObjectW with null name/attrs returns an owned handle or null.
    let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if raw.is_null() {
        return Err(format!(
            "CreateJobObjectW failed: {}",
            io::Error::last_os_error()
        ));
    }
    let job = unsafe { OwnedHandle::from_raw_handle(raw as _) };

    let mut info = unsafe { std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = unsafe {
        SetInformationJobObject(
            job.as_raw_handle() as HANDLE,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of_val(&info) as u32,
        )
    };
    if ok == 0 {
        return Err(format!(
            "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(job)
}

fn assign_child_to_job(job: &OwnedHandle, child: &std::process::Child) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: Child's raw handle is valid for the process lifetime.
    let process = child.as_raw_handle() as HANDLE;
    let ok = unsafe { AssignProcessToJobObject(job.as_raw_handle() as HANDLE, process) };
    if ok == 0 {
        // Best-effort terminate so we do not leave an unbound shim.
        let _ = unsafe { TerminateJobObject(job.as_raw_handle() as HANDLE, OWNER_EXIT_CODE) };
        return Err(format!(
            "AssignProcessToJobObject failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn process_exit_code(pid: NonZeroU32) -> Option<u32> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.get(),
        )
    };
    if handle.is_null() {
        return None;
    }
    let mut code = 0u32;
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
    let wait = unsafe { WaitForSingleObject(handle, 0) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    if ok == 0 {
        return None;
    }
    // STILL_ACTIVE == 259
    if wait == WAIT_OBJECT_0 || code != 259 {
        Some(code)
    } else {
        None
    }
}
