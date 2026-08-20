use std::io;
use std::process::ExitStatus;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SHIM_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const MAX_CAPTURE_BYTES: usize = 64 * 1024;

pub(crate) struct RunningShim {
    child: Child,
    stdout: JoinHandle<io::Result<BoundedOutput>>,
    stderr: JoinHandle<io::Result<BoundedOutput>>,
}

impl RunningShim {
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        command.process_group(0);
        let mut child = command.spawn()?;
        #[cfg(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        verify_process_group(&mut child)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("libkrun shim stdout is not piped"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("libkrun shim stderr is not piped"))?;
        Ok(Self {
            child,
            stdout: tokio::spawn(read_bounded(stdout)),
            stderr: tokio::spawn(read_bounded(stderr)),
        })
    }

    pub(crate) fn process_id(&self) -> Option<u32> {
        self.child.id()
    }

    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub(crate) async fn wait_and_collect(self) -> CompletedShim {
        self.wait_and_collect_with_timeout(SHIM_EXIT_TIMEOUT).await
    }

    async fn wait_and_collect_with_timeout(mut self, exit_timeout: Duration) -> CompletedShim {
        match timeout(exit_timeout, self.child.wait()).await {
            Ok(status) => self.collect_after_wait(status).await,
            Err(_) => {
                let _ = terminate_process_tree(&mut self.child).await;
                let status = self.child.wait().await;
                let mut completed = self.collect_after_wait(status).await;
                completed.timed_out = true;
                completed
            }
        }
    }

    pub(crate) async fn terminate_and_collect(mut self) -> CompletedShim {
        let status = match self.child.try_wait() {
            Ok(Some(status)) => Ok(status),
            Ok(None) => {
                let _ = terminate_process_tree(&mut self.child).await;
                self.child.wait().await
            }
            Err(error) => {
                let inspection_error =
                    format!("failed to inspect libkrun shim before termination: {error}");
                let _ = terminate_process_tree(&mut self.child).await;
                let status = self.child.wait().await;
                let mut completed = self.collect_after_wait(status).await;
                completed.collection_errors.insert(0, inspection_error);
                return completed;
            }
        };
        self.collect_after_wait(status).await
    }

    pub(crate) async fn collect_after_wait(self, status: io::Result<ExitStatus>) -> CompletedShim {
        let (stdout, stdout_error) = collect_output(self.stdout, "stdout").await;
        let (stderr, stderr_error) = collect_output(self.stderr, "stderr").await;
        let mut collection_errors = Vec::new();
        let status = match status {
            Ok(status) => Some(status),
            Err(error) => {
                collection_errors.push(format!("failed to wait for libkrun shim: {error}"));
                None
            }
        };
        collection_errors.extend(stdout_error);
        collection_errors.extend(stderr_error);
        CompletedShim {
            status,
            stdout,
            stderr,
            timed_out: false,
            collection_errors,
        }
    }
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn verify_process_group(child: &mut Child) -> io::Result<()> {
    let process_id = child
        .id()
        .ok_or_else(|| io::Error::other("spawned libkrun shim has no process ID"))?;
    let process_id = libc::pid_t::try_from(process_id)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `process_id` identifies the newly spawned live child.
    let process_group = unsafe { libc::getpgid(process_id) };
    if process_group == process_id {
        return Ok(());
    }
    let error = if process_group < 0 {
        io::Error::last_os_error()
    } else {
        io::Error::other(format!(
            "spawned libkrun shim PID {process_id} joined unexpected process group \
             {process_group}"
        ))
    };
    let _ = child.start_kill();
    Err(error)
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
async fn terminate_process_tree(child: &mut Child) -> io::Result<()> {
    let Some(process_id) = child.id() else {
        return Ok(());
    };
    let process_id = libc::pid_t::try_from(process_id)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `RunningShim::spawn` verified that the shim PID is also its
    // process-group ID. A negative target terminates the shim and its direct
    // libkrun VM worker without affecting the host runtime group.
    if unsafe { libc::kill(-process_id, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        child.kill().await
    } else {
        Err(error)
    }
}

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
async fn terminate_process_tree(child: &mut Child) -> io::Result<()> {
    child.kill().await
}

pub(crate) struct CompletedShim {
    pub(crate) status: Option<ExitStatus>,
    pub(crate) stdout: BoundedOutput,
    pub(crate) stderr: BoundedOutput,
    pub(crate) timed_out: bool,
    pub(crate) collection_errors: Vec<String>,
}

#[derive(Default)]
pub(crate) struct BoundedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

async fn read_bounded(mut input: impl AsyncRead + Unpin) -> io::Result<BoundedOutput> {
    let mut output = BoundedOutput::default();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = input.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(output.bytes.len());
        let retained = remaining.min(read);
        output.bytes.extend_from_slice(&buffer[..retained]);
        output.truncated |= retained != read;
    }
    Ok(output)
}

async fn collect_output(
    task: JoinHandle<io::Result<BoundedOutput>>,
    stream_name: &str,
) -> (BoundedOutput, Option<String>) {
    match task.await {
        Ok(Ok(output)) => (output, None),
        Ok(Err(error)) => (
            BoundedOutput::default(),
            Some(format!(
                "failed to read libkrun shim {stream_name}: {error}"
            )),
        ),
        Err(error) => (
            BoundedOutput::default(),
            Some(format!(
                "libkrun shim {stream_name} collector failed: {error}"
            )),
        ),
    }
}

#[cfg(all(
    test,
    any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod tests {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use tokio::process::Command;

    use super::RunningShim;

    const CHILD_PID_FILE_ENV: &str = "A3S_OCI_TEST_PROCESS_GROUP_PID_FILE";
    const CHILD_TEST_NAME: &str = "agent_smoke_process::tests::process_group_child";

    #[tokio::test]
    async fn timeout_terminates_and_reaps_the_shim_process_group() {
        let temporary = tempfile::tempdir().expect("create process-group test directory");
        let child_pid_file = temporary.path().join("child.pid");
        let mut command = Command::new(std::env::current_exe().expect("resolve test executable"));
        command
            .args(["--exact", CHILD_TEST_NAME, "--nocapture"])
            .env(CHILD_PID_FILE_ENV, &child_pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let running = RunningShim::spawn(&mut command).expect("spawn process-group test shim");

        let deadline = Instant::now() + Duration::from_secs(5);
        let grandchild_process_id = loop {
            match tokio::fs::read_to_string(&child_pid_file).await {
                Ok(value) if !value.trim().is_empty() => {
                    break value
                        .trim()
                        .parse::<u32>()
                        .expect("child PID file contains a process ID");
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("failed to read child PID file: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "process-group test child did not publish its PID"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        let completed = running
            .wait_and_collect_with_timeout(Duration::from_millis(20))
            .await;
        assert!(completed.timed_out);
        assert!(completed.status.is_some());

        let deadline = Instant::now() + Duration::from_secs(5);
        while process_exists(grandchild_process_id) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !process_exists(grandchild_process_id),
            "timed-out shim left grandchild PID {grandchild_process_id} alive"
        );
    }

    #[test]
    fn process_group_child() {
        let Ok(pid_file) = std::env::var(CHILD_PID_FILE_ENV) else {
            return;
        };
        std::env::remove_var(CHILD_PID_FILE_ENV);
        let mut grandchild = std::process::Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn process-group test grandchild");
        std::fs::write(pid_file, grandchild.id().to_string())
            .expect("publish process-group test grandchild PID");
        let _ = grandchild.wait();
    }

    fn process_exists(process_id: u32) -> bool {
        let Ok(process_id) = libc::pid_t::try_from(process_id) else {
            return false;
        };
        // SAFETY: signal zero performs existence and permission checking only.
        if unsafe { libc::kill(process_id, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
}
