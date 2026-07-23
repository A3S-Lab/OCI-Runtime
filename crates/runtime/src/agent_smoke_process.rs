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
        let mut child = command.spawn()?;
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

    pub(crate) async fn wait_and_collect(mut self) -> CompletedShim {
        match timeout(SHIM_EXIT_TIMEOUT, self.child.wait()).await {
            Ok(status) => self.collect_after_wait(status).await,
            Err(_) => {
                let _ = self.child.kill().await;
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
                let _ = self.child.kill().await;
                self.child.wait().await
            }
            Err(error) => {
                let inspection_error =
                    format!("failed to inspect libkrun shim before termination: {error}");
                let _ = self.child.kill().await;
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
