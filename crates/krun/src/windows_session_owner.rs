//! Windows WHPX durable session-owner helper (shim CLI).
//!
//! Becomes the shim `--owner-pid` so Host taskkill does not tear down the Guest.
//! Holds a Job Object with `KILL_ON_JOB_CLOSE` so session-owner exit reaps the
//! shim.
//!
//! When `--host-control` is set, this process also owns the guest agent named
//! pipe (from shim `--pipe-name`) and a Host-facing control pipe, byte-bridging
//! Host↔shim so Host death does not destroy the agent pipe (Live reattach
//! substrate).
//!
//! Pipe security honesty: servers use `PIPE_REJECT_REMOTE_CLIENTS` with the
//! default same-user DACL (`lpSecurityAttributes = null`). A private DACL like
//! `WindowsAgentPipeListener` is not applied here to avoid pulling the runtime
//! security module into the shim; remote clients are still rejected.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::ptr;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PeekNamedPipe, SetNamedPipeHandleState, WaitNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, WaitForSingleObject, CREATE_NEW_PROCESS_GROUP,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

const OWNER_EXIT_CODE: u32 = 3;
const PIPE_BUFFER_SIZE: u32 = 64 * 1024;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

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

/// Qualification-only child: connect to the guest agent pipe and echo until EOF,
/// then reconnect (simulates Guest Host-reconnect without WHPX).
pub(crate) fn run_session_owner_bridge_echo(
    owner_pid: NonZeroU32,
    pipe_name: String,
) -> Result<ExitCode, String> {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, owner_pid.get()) };
    if handle.is_null() {
        return Err(format!(
            "session-owner-bridge-echo cannot open owner PID {}: {}",
            owner_pid,
            io::Error::last_os_error()
        ));
    }
    unsafe {
        let _ = CloseHandle(handle);
    }

    let guest_pipe = windows_pipe_path_from_name(&pipe_name);
    loop {
        let mut stream = connect_named_pipe_client(&guest_pipe)?;
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    stream
                        .write_all(&buffer[..n])
                        .map_err(|error| format!("bridge-echo write failed: {error}"))?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Clean Host disconnect: reconnect like Guest Host-reconnect mode.
    }
}

/// Spawn trailing shim argv with `--owner-pid` = this process; publish ready file.
///
/// When `host_control` is set, bind the guest agent pipe and host-control pipe,
/// then byte-proxy Host↔shim until either side EOF; loop for the next Host.
pub(crate) fn run_session_owner(
    ready_file: PathBuf,
    host_control: Option<String>,
    shim_argv: Vec<std::ffi::OsString>,
) -> Result<ExitCode, String> {
    if shim_argv.is_empty() {
        return Err("session-owner requires a non-empty shim argv after the subcommand".into());
    }
    if shim_argv.iter().any(|arg| arg == "--owner-pid") {
        return Err("session-owner shim argv must not include --owner-pid".into());
    }

    let guest_path = host_control
        .as_ref()
        .map(|_| extract_shim_pipe_path(&shim_argv))
        .transpose()?;

    // Bind the guest agent pipe before spawn so the shim/bridge-echo can connect.
    // Host-control is created after the guest connects (per cycle) so Host clients
    // cannot attach before the session-owner is ready to proxy.
    let mut next_guest = match guest_path.as_ref() {
        Some(path) => Some(create_named_pipe_server(path, true)?),
        None => None,
    };
    let host_path = host_control.clone();
    if host_path.is_some() && next_guest.is_none() {
        return Err("session-owner bridge mode requires both guest pipe and host-control".into());
    }
    if let Some(path) = host_path.as_ref() {
        if !path.starts_with(r"\\.\pipe\") {
            return Err(format!(
                "session-owner --host-control must be a local named-pipe path, got {path}"
            ));
        }
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

    let (Some(guest_path), Some(host_path)) = (guest_path, host_path) else {
        let status = spawned
            .wait()
            .map_err(|error| format!("wait for session-owner shim: {error}"))?;
        drop(next_guest);
        drop(job);
        return if status.success() {
            Ok(ExitCode::SUCCESS)
        } else {
            Ok(ExitCode::from(OWNER_EXIT_CODE as u8))
        };
    };
    let mut first_host = true;

    loop {
        if let Some(status) = spawned
            .try_wait()
            .map_err(|error| format!("poll session-owner shim: {error}"))?
        {
            let _ = fs::remove_file(&ready_file);
            drop(next_guest);
            drop(job);
            return if status.success() {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::from(OWNER_EXIT_CODE as u8))
            };
        }

        let guest = match next_guest.take() {
            Some(handle) => handle,
            None => create_named_pipe_server(&guest_path, false)?,
        };
        match wait_for_pipe_client(&guest, Some(shim_pid), &mut spawned)? {
            PipeAccept::ShimExited(status) => {
                let _ = fs::remove_file(&ready_file);
                drop(guest);
                drop(job);
                return if status.success() {
                    Ok(ExitCode::SUCCESS)
                } else {
                    Ok(ExitCode::from(OWNER_EXIT_CODE as u8))
                };
            }
            PipeAccept::Connected => {}
        }

        let host = create_named_pipe_server(&host_path, first_host)?;
        first_host = false;
        match wait_for_pipe_client(&host, None, &mut spawned)? {
            PipeAccept::ShimExited(status) => {
                let _ = fs::remove_file(&ready_file);
                drop(guest);
                drop(host);
                drop(job);
                return if status.success() {
                    Ok(ExitCode::SUCCESS)
                } else {
                    Ok(ExitCode::from(OWNER_EXIT_CODE as u8))
                };
            }
            PipeAccept::Connected => {}
        }

        // Move connected handles into Files for the byte proxy; closing them
        // ends the cycle so the next CreateNamedPipe can bind the same names.
        proxy_pipe_files(owned_handle_into_file(guest), owned_handle_into_file(host));
        next_guest = Some(create_named_pipe_server(&guest_path, false)?);
    }
}

enum PipeAccept {
    Connected,
    ShimExited(std::process::ExitStatus),
}

fn wait_for_pipe_client(
    server: &OwnedHandle,
    expected_client_pid: Option<NonZeroU32>,
    spawned: &mut std::process::Child,
) -> Result<PipeAccept, String> {
    loop {
        if let Some(status) = spawned
            .try_wait()
            .map_err(|error| format!("poll session-owner shim while accepting: {error}"))?
        {
            return Ok(PipeAccept::ShimExited(status));
        }
        match try_connect_named_pipe(server)? {
            true => {
                if let Some(expected) = expected_client_pid {
                    let client_pid = named_pipe_client_pid(server)?;
                    if client_pid != expected.get() {
                        eprintln!(
                            "a3s-oci-krun-shim: session-owner rejected guest pipe client PID \
                             {client_pid} (expected shim PID {})",
                            expected.get()
                        );
                        let _ = unsafe { DisconnectNamedPipe(server.as_raw_handle() as HANDLE) };
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                }
                // Switch connected instance to blocking I/O for the byte proxy.
                set_pipe_wait_mode(server)?;
                return Ok(PipeAccept::Connected);
            }
            false => thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn extract_shim_pipe_path(shim_argv: &[std::ffi::OsString]) -> Result<String, String> {
    let mut iter = shim_argv.iter();
    while let Some(arg) = iter.next() {
        if arg == "--pipe-name" {
            let name = iter
                .next()
                .ok_or_else(|| "session-owner --pipe-name is missing a value".to_string())?;
            let name = name
                .to_str()
                .ok_or_else(|| "session-owner --pipe-name must be valid UTF-8".to_string())?;
            return Ok(windows_pipe_path_from_name(name));
        }
    }
    Err("session-owner bridge mode requires shim argv --pipe-name".into())
}

fn windows_pipe_path_from_name(pipe_name: &str) -> String {
    if pipe_name.starts_with(r"\\.\pipe\") {
        pipe_name.to_string()
    } else {
        format!(r"\\.\pipe\{pipe_name}")
    }
}

fn create_named_pipe_server(path: &str, first_instance: bool) -> Result<OwnedHandle, String> {
    let wide = to_wide(path);
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first_instance {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: CreateNamedPipeW with a null-terminated path and null security
    // attributes returns an owned handle or INVALID_HANDLE_VALUE.
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            ptr::null(),
        )
    };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(format!(
            "CreateNamedPipeW({}) failed: {}",
            path,
            io::Error::last_os_error()
        ));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}

fn try_connect_named_pipe(server: &OwnedHandle) -> Result<bool, String> {
    // SAFETY: server owns a live named-pipe handle; null overlapped is sync.
    let ok = unsafe { ConnectNamedPipe(server.as_raw_handle() as HANDLE, ptr::null_mut()) };
    if ok != 0 {
        return Ok(true);
    }
    // SAFETY: GetLastError after a failed ConnectNamedPipe.
    let code = unsafe { GetLastError() };
    if code == ERROR_PIPE_CONNECTED {
        Ok(true)
    } else if code == ERROR_PIPE_LISTENING || code == ERROR_NO_DATA {
        Ok(false)
    } else {
        Err(format!(
            "ConnectNamedPipe failed: {}",
            io::Error::from_raw_os_error(code as i32)
        ))
    }
}

fn named_pipe_client_pid(server: &OwnedHandle) -> Result<u32, String> {
    let mut client_pid = 0u32;
    // SAFETY: connected pipe handle; output pointer is valid for one u32.
    let ok =
        unsafe { GetNamedPipeClientProcessId(server.as_raw_handle() as HANDLE, &mut client_pid) };
    if ok == 0 {
        return Err(format!(
            "GetNamedPipeClientProcessId failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(client_pid)
}

fn set_pipe_wait_mode(server: &OwnedHandle) -> Result<(), String> {
    let mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    // SAFETY: connected pipe; mode pointer is valid for the call.
    let ok = unsafe {
        SetNamedPipeHandleState(
            server.as_raw_handle() as HANDLE,
            &mode,
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == 0 {
        return Err(format!(
            "SetNamedPipeHandleState(PIPE_WAIT) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn proxy_pipe_files(left: File, right: File) {
    // Synchronous duplex named-pipe handles cannot safely Read+Write concurrently
    // from two threads (one blocking Read owns the pipe object). Poll both sides
    // with PeekNamedPipe on one thread instead.
    let left_handle = left.as_raw_handle() as HANDLE;
    let right_handle = right.as_raw_handle() as HANDLE;
    let mut left_buf = [0u8; 8192];
    let mut right_buf = [0u8; 8192];
    loop {
        let left_closed =
            pump_pipe_if_readable(left_handle, right_handle, &mut left_buf).unwrap_or(true);
        let right_closed =
            pump_pipe_if_readable(right_handle, left_handle, &mut right_buf).unwrap_or(true);
        if left_closed || right_closed {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    drop(left);
    drop(right);
}

fn pump_pipe_if_readable(from: HANDLE, to: HANDLE, buffer: &mut [u8]) -> io::Result<bool> {
    let mut avail = 0u32;
    let mut bytes_left = 0u32;
    // SAFETY: live pipe handles; output pointers are valid locals.
    let ok = unsafe {
        PeekNamedPipe(
            from,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut avail,
            &mut bytes_left,
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32)
            || err.raw_os_error() == Some(ERROR_NO_DATA as i32)
            || err.kind() == io::ErrorKind::BrokenPipe
        {
            return Ok(true);
        }
        return Err(err);
    }
    if avail == 0 {
        return Ok(false);
    }
    let to_read = (avail as usize).min(buffer.len()) as u32;
    let mut read = 0u32;
    let ok = unsafe {
        ReadFile(
            from,
            buffer.as_mut_ptr(),
            to_read,
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::BrokenPipe
            || err.raw_os_error() == Some(ERROR_NO_DATA as i32)
        {
            return Ok(true);
        }
        return Err(err);
    }
    if read == 0 {
        return Ok(true);
    }
    let mut offset = 0usize;
    while offset < read as usize {
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                to,
                buffer.as_ptr().add(offset),
                (read as usize - offset) as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if written == 0 {
            return Ok(true);
        }
        offset += written as usize;
    }
    let _ = unsafe { FlushFileBuffers(to) };
    Ok(false)
}

fn owned_handle_into_file(handle: OwnedHandle) -> File {
    // SAFETY: OwnedHandle is a live pipe handle; File takes exclusive ownership.
    unsafe { File::from_raw_handle(handle.into_raw_handle()) }
}

fn connect_named_pipe_client(path: &str) -> Result<File, String> {
    let wide = to_wide(path);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        // SAFETY: WaitNamedPipeW with a null-terminated path.
        let _ = unsafe { WaitNamedPipeW(wide.as_ptr(), 100) };
        // SAFETY: CreateFileW opens an existing local named pipe.
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
            return Ok(unsafe { File::from_raw_handle(raw as _) });
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out connecting bridge-echo to {path}: {}",
                io::Error::last_os_error()
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::windows_pipe_path_from_name;

    #[test]
    fn pipe_name_qualifies_to_local_path() {
        assert_eq!(
            windows_pipe_path_from_name("a3s-oci-agent-test"),
            r"\\.\pipe\a3s-oci-agent-test"
        );
        assert_eq!(
            windows_pipe_path_from_name(r"\\.\pipe\already-qualified"),
            r"\\.\pipe\already-qualified"
        );
    }
}
