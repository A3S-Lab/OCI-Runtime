use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PRIVATE_TMP_ROOT: &str = "/private/tmp";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_SOCKET_MODE: u32 = 0o600;

pub(crate) struct WorkerExit {
    pub(crate) status: ExitStatus,
    pub(crate) timed_out: bool,
}

pub(crate) fn resolve_console(console: &Path) -> Result<PathBuf, String> {
    let file_name = console
        .file_name()
        .ok_or_else(|| format!("console path has no file name: {}", console.display()))?;
    let parent = console
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create console directory {}: {error}",
            parent.display()
        )
    })?;
    let parent = parent.canonicalize().map_err(|error| {
        format!(
            "failed to resolve console directory {}: {error}",
            parent.display()
        )
    })?;
    let console = parent.join(file_name);
    require_absent(&console, "console output")?;
    Ok(console)
}

pub(crate) fn resolve_agent_socket(socket: &Path) -> Result<PathBuf, String> {
    if !socket.is_absolute() {
        return Err(format!(
            "agent socket path must be absolute: {}",
            socket.display()
        ));
    }
    let file_name = socket
        .file_name()
        .ok_or_else(|| format!("agent socket path has no file name: {}", socket.display()))?;
    let parent = socket
        .parent()
        .ok_or_else(|| format!("agent socket path has no parent: {}", socket.display()))?
        .canonicalize()
        .map_err(|error| {
            format!(
                "failed to resolve agent socket directory {}: {error}",
                socket.display()
            )
        })?;
    let private_tmp_root = Path::new(PRIVATE_TMP_ROOT)
        .canonicalize()
        .map_err(|error| {
            format!("failed to resolve private temporary root {PRIVATE_TMP_ROOT}: {error}")
        })?;
    if parent.parent() != Some(private_tmp_root.as_path()) {
        return Err(format!(
            "agent socket directory must be a direct child of {PRIVATE_TMP_ROOT}: {}",
            parent.display()
        ));
    }
    let parent_metadata = fs::symlink_metadata(&parent).map_err(|error| {
        format!(
            "failed to inspect agent socket directory {}: {error}",
            parent.display()
        )
    })?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(format!(
            "agent socket directory must be a non-symlink directory with mode \
             {PRIVATE_DIRECTORY_MODE:03o}: {}",
            parent.display()
        ));
    }

    let socket = parent.join(file_name);
    let socket_metadata = fs::symlink_metadata(&socket).map_err(|error| {
        format!(
            "failed to inspect agent socket {}: {error}",
            socket.display()
        )
    })?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.file_type().is_symlink()
        || socket_metadata.mode() & 0o777 != PRIVATE_SOCKET_MODE
    {
        return Err(format!(
            "agent socket must be a non-symlink Unix socket with mode \
             {PRIVATE_SOCKET_MODE:03o}: {}",
            socket.display()
        ));
    }

    // SAFETY: `geteuid` has no pointer arguments or failure return.
    let effective_user_id = unsafe { libc::geteuid() };
    if parent_metadata.uid() != effective_user_id || socket_metadata.uid() != effective_user_id {
        return Err(format!(
            "agent socket and its private directory must be owned by effective UID \
             {effective_user_id}: {}",
            socket.display()
        ));
    }
    Ok(socket)
}

pub(crate) fn require_absent(path: &Path, description: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "refusing to overwrite existing {description}: {}",
            path.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )),
    }
}

pub(crate) fn wait_for_worker(child: &mut Child, timeout: Duration) -> io::Result<WorkerExit> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(WorkerExit {
                status,
                timed_out: false,
            });
        }
        if Instant::now() >= deadline {
            return match child.kill() {
                Ok(()) => child.wait().map(|status| WorkerExit {
                    status,
                    timed_out: true,
                }),
                Err(kill_error) => match child.try_wait()? {
                    Some(status) => Ok(WorkerExit {
                        status,
                        timed_out: false,
                    }),
                    None => Err(kill_error),
                },
            };
        }
        thread::sleep(WORKER_POLL_INTERVAL);
    }
}

pub(crate) fn terminate_and_wait(child: &mut Child) -> io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    match child.kill() {
        Ok(()) => child.wait(),
        Err(kill_error) => child.try_wait()?.ok_or(kill_error),
    }
}

pub(crate) fn read_bounded_worker_output(mut input: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    input.by_ref().take(limit + 1).read_to_end(&mut output)?;
    if output.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("macOS VM worker output exceeds {limit} bytes"),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::wait_for_worker;

    #[test]
    fn timed_out_worker_is_killed_and_reaped() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 10"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test worker must start");

        let result =
            wait_for_worker(&mut child, Duration::from_millis(10)).expect("worker must be reaped");
        assert!(result.timed_out);
        assert!(child
            .try_wait()
            .expect("reaped child must be queryable")
            .is_some());
    }
}
