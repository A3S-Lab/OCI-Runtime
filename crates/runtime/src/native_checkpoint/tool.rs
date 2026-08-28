use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use a3s_oci_agent::{LinuxExecutorCheckpointSource, LinuxRestoreSpawnRequest, LinuxRestoreSpawner};
use a3s_oci_sdk::{async_trait, CheckpointDigest, ErrorCode, OperationContext, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use super::artifact::ExternalMountManifestEntry;
use super::{checkpoint_error, io_error};

const TOOL_OUTPUT_LIMIT: usize = 64 * 1024;
const TOOL_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_DUMP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CRIU_DUMP_OPTIONS: [&str; 6] = [
    "--leave-running",
    "--shell-job",
    "--file-locks",
    "--manage-cgroups=soft",
    "--external",
    "mnt[]",
];
const CRIU_RESTORE_OPTIONS: [&str; 7] = [
    "--leave-stopped",
    "--shell-job",
    "--file-locks",
    "--manage-cgroups=ignore",
    "--external",
    "mnt[]",
    "--exec-cmd",
];

#[derive(Debug)]
pub(super) struct CriuTool {
    executable: File,
    canonical_path: PathBuf,
    digest: CheckpointDigest,
    version: String,
    git_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CriuIdentity {
    pub(super) executable_digest: CheckpointDigest,
    pub(super) version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) git_id: Option<String>,
}

#[derive(Debug)]
struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_overflowed: bool,
}

pub(super) struct CriuRestoreSpawner<'a> {
    tool: &'a CriuTool,
    images_directory: &'a Path,
    work_directory: &'a Path,
    external_mounts: &'a [ExternalMountManifestEntry],
}

impl CriuTool {
    pub(super) async fn open(path: impl AsRef<Path>) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(checkpoint_error(
                ErrorCode::PermissionDenied,
                "native CRIU checkpointing requires effective UID 0",
            ));
        }
        let requested = path.as_ref().to_path_buf();
        let (executable, canonical_path, digest) =
            tokio::task::spawn_blocking(move || open_verified_executable(&requested))
                .await
                .map_err(|error| {
                    checkpoint_error(
                        ErrorCode::Internal,
                        format!("CRIU executable verification task failed: {error}"),
                    )
                })??;

        let provisional = Self {
            executable,
            canonical_path,
            digest,
            version: String::new(),
            git_id: None,
        };
        let version_output = provisional
            .run([OsStr::new("--version")], TOOL_PROBE_TIMEOUT)
            .await?;
        require_success("query CRIU version", &version_output, None).await?;
        let (version, git_id) = parse_version_output(&version_output.stdout)?;
        let tool = Self {
            version,
            git_id,
            ..provisional
        };
        let check = tool.run([OsStr::new("check")], TOOL_PROBE_TIMEOUT).await?;
        require_success("run CRIU feature check", &check, None).await?;
        Ok(tool)
    }

    pub(super) fn identity(&self) -> CriuIdentity {
        CriuIdentity {
            executable_digest: self.digest.clone(),
            version: self.version.clone(),
            git_id: self.git_id.clone(),
        }
    }

    pub(super) fn version(&self) -> &str {
        &self.version
    }

    pub(super) fn digest(&self) -> &CheckpointDigest {
        &self.digest
    }

    pub(super) fn dump_option_identity() -> Vec<String> {
        let mut options = CRIU_DUMP_OPTIONS
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        options.extend([
            "--external".to_string(),
            "mnt[<oci-device-mountpoint>]:<a3s-device-cookie>".to_string(),
            "--freeze-cgroup".to_string(),
            "<source-cgroup>".to_string(),
            "--cgroup-root".to_string(),
            "<source-cgroup-root>".to_string(),
        ]);
        options
    }

    pub(super) fn restore_option_identity() -> Vec<String> {
        let mut options = CRIU_RESTORE_OPTIONS
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        options.extend([
            "--external".to_string(),
            "mnt[<a3s-device-cookie>]:<target-device-source>".to_string(),
            "--root".to_string(),
            "<target-rootfs>".to_string(),
            "--pidfile".to_string(),
            "<restore-pidfile>".to_string(),
        ]);
        options
    }

    pub(super) fn dump_options<'a>(
        cgroup_path: &str,
        external_mounts: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> Result<Vec<String>> {
        let mut options = CRIU_DUMP_OPTIONS
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        for (name, mountpoint) in external_mounts {
            options.push("--external".to_string());
            options.push(dump_external_mount_option(name, mountpoint)?);
        }
        options.push("--freeze-cgroup".to_string());
        options.push(cgroup_path.to_string());
        options.push("--cgroup-root".to_string());
        options.push(cgroup_root(Path::new(cgroup_path))?.display().to_string());
        Ok(options)
    }

    pub(super) async fn verify_identity(&self) -> Result<()> {
        let descriptor_path = self.descriptor_path();
        let expected = self.digest.clone();
        tokio::task::spawn_blocking(move || {
            let actual = digest_path(&descriptor_path)?;
            if actual == expected {
                Ok(())
            } else {
                Err(checkpoint_error(
                    ErrorCode::FailedPrecondition,
                    "the retained CRIU executable changed after capability probing",
                ))
            }
        })
        .await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("CRIU identity verification task failed: {error}"),
            )
        })?
    }

    pub(super) async fn dump(
        &self,
        source: &LinuxExecutorCheckpointSource,
        images_directory: &Path,
        work_directory: &Path,
        context: &OperationContext,
    ) -> Result<()> {
        self.verify_identity().await?;
        let log_path = work_directory.join("dump.log");
        let mut arguments = vec![
            OsString::from("dump"),
            OsString::from("--tree"),
            OsString::from(source.checkpoint_root_pid().to_string()),
            OsString::from("--images-dir"),
            images_directory.as_os_str().to_os_string(),
            OsString::from("--work-dir"),
            work_directory.as_os_str().to_os_string(),
            OsString::from("--log-file"),
            OsString::from("dump.log"),
        ];
        arguments.extend(CRIU_DUMP_OPTIONS.iter().map(OsString::from));
        for (name, mountpoint) in source.external_mounts() {
            arguments.push(OsString::from("--external"));
            arguments.push(OsString::from(dump_external_mount_option(
                name, mountpoint,
            )?));
        }
        arguments.push(OsString::from("--freeze-cgroup"));
        arguments.push(source.cgroup_path().as_os_str().to_os_string());
        arguments.push(OsString::from("--cgroup-root"));
        arguments.push(
            cgroup_root(source.cgroup_path())?
                .as_os_str()
                .to_os_string(),
        );
        let timeout = dump_timeout(context)?;
        let output = self
            .run(arguments.iter().map(OsString::as_os_str), timeout)
            .await?;
        require_success(
            "dump the paused native process tree",
            &output,
            Some(&log_path),
        )
        .await
    }

    fn descriptor_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.executable.as_raw_fd()))
    }

    async fn run<'a>(
        &self,
        arguments: impl IntoIterator<Item = &'a OsStr>,
        timeout: Duration,
    ) -> Result<CommandOutput> {
        let mut command = Command::new(self.descriptor_path());
        command
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| {
            io_error(
                "spawn retained CRIU executable",
                &self.canonical_path,
                error,
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            checkpoint_error(ErrorCode::Internal, "CRIU stdout pipe was not created")
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            checkpoint_error(ErrorCode::Internal, "CRIU stderr pipe was not created")
        })?;
        let stdout_task = tokio::spawn(read_bounded(stdout));
        let stderr_task = tokio::spawn(read_bounded(stderr));
        let status = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(result) => result.map_err(|error| {
                io_error(
                    "wait for retained CRIU executable",
                    &self.canonical_path,
                    error,
                )
            })?,
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(checkpoint_error(
                    ErrorCode::DeadlineExceeded,
                    format!(
                        "CRIU command exceeded its {} second deadline",
                        timeout.as_secs()
                    ),
                )
                .retryable(true));
            }
        };
        let (stdout, stdout_overflowed) = join_output(stdout_task, "stdout").await?;
        let (stderr, stderr_overflowed) = join_output(stderr_task, "stderr").await?;
        Ok(CommandOutput {
            status,
            stdout,
            stderr,
            output_overflowed: stdout_overflowed || stderr_overflowed,
        })
    }
}

impl<'a> CriuRestoreSpawner<'a> {
    pub(super) const fn new(
        tool: &'a CriuTool,
        images_directory: &'a Path,
        work_directory: &'a Path,
        external_mounts: &'a [ExternalMountManifestEntry],
    ) -> Self {
        Self {
            tool,
            images_directory,
            work_directory,
            external_mounts,
        }
    }
}

#[async_trait]
impl LinuxRestoreSpawner for CriuRestoreSpawner<'_> {
    async fn spawn(&self, request: LinuxRestoreSpawnRequest) -> Result<tokio::process::Child> {
        self.tool.verify_identity().await?;
        let pidfile = self.work_directory.join("restore.pid");
        let log_path = self.work_directory.join("restore.log");
        let external_mounts = request.external_mounts().collect::<Vec<_>>();
        if external_mounts.len() != self.external_mounts.len()
            || external_mounts.iter().zip(self.external_mounts).any(
                |((name, mountpoint, _), expected)| {
                    *name != expected.name() || *mountpoint != expected.mountpoint()
                },
            )
        {
            return Err(checkpoint_error(
                ErrorCode::FailedPrecondition,
                "restore device mount contract differs from the checkpoint artifact",
            ));
        }
        let mut command = Command::new(self.tool.descriptor_path());
        command
            .arg("restore")
            .arg("--images-dir")
            .arg(self.images_directory)
            .arg("--work-dir")
            .arg(self.work_directory)
            .arg("--log-file")
            .arg("restore.log")
            .args(CRIU_RESTORE_OPTIONS);
        for (name, _, source) in external_mounts {
            command
                .arg("--external")
                .arg(restore_external_mount_option(name, source));
        }
        command
            .arg("--root")
            .arg(request.rootfs())
            .arg("--pidfile")
            .arg(&pidfile)
            .arg("--")
            .arg(request.supervisor_executable())
            .arg("container-restore-supervisor")
            .arg(request.config_snapshot())
            .arg(request.control_name())
            .arg(&pidfile)
            .arg(request.expected_owner_pid().to_string())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        request.prepare_command(&mut command)?;
        command
            .spawn()
            .map_err(|error| {
                io_error(
                    "spawn retained CRIU restore executable",
                    &self.tool.canonical_path,
                    error,
                )
            })
            .map_err(|mut error| {
                error.message = format!("{}; restore log: {}", error.message, log_path.display());
                error
            })
    }
}

fn dump_external_mount_option(name: &str, mountpoint: &Path) -> Result<String> {
    let mountpoint = mountpoint.to_str().ok_or_else(|| {
        checkpoint_error(
            ErrorCode::FailedPrecondition,
            "checkpoint external device mountpoint is not valid UTF-8",
        )
    })?;
    Ok(format!("mnt[{mountpoint}]:{name}"))
}

fn restore_external_mount_option(name: &str, source: &Path) -> OsString {
    let mut option = OsString::from(format!("mnt[{name}]:"));
    option.push(source);
    option
}

fn cgroup_root(workload: &Path) -> Result<PathBuf> {
    let root = workload
        .parent()
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native checkpoint workload has no absolute management cgroup parent: {}",
                    workload.display()
                ),
            )
        })?;
    cgroup_argument(root)
}

fn cgroup_argument(root: &Path) -> Result<PathBuf> {
    const CGROUP2_MOUNT: &str = "/sys/fs/cgroup";
    let relative = root
        .strip_prefix(CGROUP2_MOUNT)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .ok_or_else(|| {
            checkpoint_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "native CRIU cgroup root is outside {CGROUP2_MOUNT}: {}",
                    root.display()
                ),
            )
        })?;
    Ok(Path::new("/").join(relative))
}

fn open_verified_executable(path: &Path) -> Result<(File, PathBuf, CheckpointDigest)> {
    if !path.is_absolute() {
        return Err(checkpoint_error(
            ErrorCode::InvalidArgument,
            format!("CRIU executable path must be absolute: {}", path.display()),
        ));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| io_error("resolve CRIU executable", path, error))?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&canonical)
        .map_err(|error| io_error("open CRIU executable", &canonical, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect CRIU executable", &canonical, error))?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.uid() != 0 || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(checkpoint_error(
            ErrorCode::PermissionDenied,
            format!(
                "CRIU executable must be a root-owned regular executable without group/world write access: {}",
                canonical.display()
            ),
        ));
    }
    let digest = digest_reader(&mut file, &canonical)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind CRIU executable", &canonical, error))?;
    Ok((file, canonical, digest))
}

fn digest_path(path: &Path) -> Result<CheckpointDigest> {
    let mut file =
        File::open(path).map_err(|error| io_error("open retained CRIU executable", path, error))?;
    digest_reader(&mut file, path)
}

fn digest_reader(reader: &mut File, display: &Path) -> Result<CheckpointDigest> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("hash CRIU executable", display, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    CheckpointDigest::new(format!("sha256:{:x}", digest.finalize()))
}

async fn read_bounded(
    mut reader: impl tokio::io::AsyncRead + Unpin,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut overflowed = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = TOOL_OUTPUT_LIMIT.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..read.min(remaining)]);
        overflowed |= read > remaining;
    }
    Ok((retained, overflowed))
}

async fn join_output(
    task: tokio::task::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
    stream: &str,
) -> Result<(Vec<u8>, bool)> {
    task.await
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("CRIU {stream} reader task failed: {error}"),
            )
        })?
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Unavailable,
                format!("failed to read CRIU {stream}: {error}"),
            )
            .retryable(true)
        })
}

fn parse_version_output(bytes: &[u8]) -> Result<(String, Option<String>)> {
    let output = std::str::from_utf8(bytes).map_err(|error| {
        checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!("CRIU version output is not UTF-8: {error}"),
        )
    })?;
    let mut version = None;
    let mut git_id = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Version:") {
            version = Some(validate_version_field(value.trim(), "version")?);
        } else if let Some(value) = line.strip_prefix("GitID:") {
            git_id = Some(validate_version_field(value.trim(), "GitID")?);
        }
    }
    let version = version.ok_or_else(|| {
        checkpoint_error(
            ErrorCode::FailedPrecondition,
            "CRIU --version output omits the Version field",
        )
    })?;
    Ok((version, git_id))
}

fn validate_version_field(value: &str, label: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
    {
        return Err(checkpoint_error(
            ErrorCode::FailedPrecondition,
            format!("CRIU {label} is empty, oversized, or contains unsafe characters"),
        ));
    }
    Ok(value.to_string())
}

async fn require_success(
    action: &str,
    output: &CommandOutput,
    log_path: Option<&Path>,
) -> Result<()> {
    if output.status.success() && !output.output_overflowed {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let (log, log_overflowed) = match log_path {
        Some(path) => read_log_bounded(path).await,
        None => (String::new(), false),
    };
    let code = if output.output_overflowed {
        ErrorCode::ResourceExhausted
    } else {
        ErrorCode::FailedPrecondition
    };
    Err(checkpoint_error(
        code,
        format!(
            "failed to {action}; status={}; stdout={:?}; stderr={:?}; log={:?}; log_truncated={log_overflowed}",
            output.status,
            stdout.trim(),
            stderr.trim(),
            log.trim()
        ),
    ))
}

pub(super) async fn read_log_bounded(path: &Path) -> (String, bool) {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) => return (format!("<unavailable: {error}>"), false),
    };
    let mut bytes = Vec::with_capacity(TOOL_OUTPUT_LIMIT + 1);
    let mut bounded = file.take((TOOL_OUTPUT_LIMIT + 1) as u64);
    if let Err(error) = bounded.read_to_end(&mut bytes).await {
        return (format!("<unavailable: {error}>"), false);
    }
    let overflowed = bytes.len() > TOOL_OUTPUT_LIMIT;
    bytes.truncate(TOOL_OUTPUT_LIMIT);
    (String::from_utf8_lossy(&bytes).into_owned(), overflowed)
}

fn dump_timeout(context: &OperationContext) -> Result<Duration> {
    let Some(deadline) = context.deadline_unix_ms else {
        return Ok(DEFAULT_DUMP_TIMEOUT);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            checkpoint_error(
                ErrorCode::Internal,
                format!("system clock is before the Unix epoch: {error}"),
            )
        })?;
    let now_ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
    let remaining_ms = deadline.checked_sub(now_ms).ok_or_else(|| {
        checkpoint_error(
            ErrorCode::DeadlineExceeded,
            format!("checkpoint operation deadline {deadline} has expired"),
        )
    })?;
    if remaining_ms == 0 {
        return Err(checkpoint_error(
            ErrorCode::DeadlineExceeded,
            format!("checkpoint operation deadline {deadline} has expired"),
        ));
    }
    Ok(DEFAULT_DUMP_TIMEOUT.min(Duration::from_millis(remaining_ms)))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{dump_timeout, parse_version_output, CriuTool, OperationContext};
    use a3s_oci_sdk::OperationId;

    #[test]
    fn parses_bounded_criu_identity() {
        let (version, git_id) =
            parse_version_output(b"Version: 4.2.1\nGitID: v4.2.1\n").expect("valid CRIU identity");
        assert_eq!(version, "4.2.1");
        assert_eq!(git_id.as_deref(), Some("v4.2.1"));
        assert!(parse_version_output(b"GitID: missing-version\n").is_err());
        assert!(parse_version_output(b"Version: unsafe value\n").is_err());
    }

    #[test]
    fn expired_dump_deadline_fails_before_spawning_criu() {
        let mut context = OperationContext::new(OperationId::new("expired-dump").unwrap());
        context.deadline_unix_ms = Some(1);
        assert!(dump_timeout(&context).is_err());
    }

    #[test]
    fn dump_identity_binds_the_dynamic_freezer_boundary() {
        let identity = CriuTool::dump_option_identity();
        let options = CriuTool::dump_options(
            "/sys/fs/cgroup/a3s/workload",
            [("a3s-oci-device-0000", Path::new("/dev/null"))],
        )
        .expect("valid source cgroup path");
        let mut expected = identity.clone();
        let external = expected
            .iter()
            .position(|value| value == "mnt[<oci-device-mountpoint>]:<a3s-device-cookie>")
            .expect("external mount placeholder");
        expected[external] = "mnt[/dev/null]:a3s-oci-device-0000".to_string();
        let source = expected
            .iter()
            .position(|value| value == "<source-cgroup>")
            .expect("source cgroup placeholder");
        expected[source] = "/sys/fs/cgroup/a3s/workload".to_string();
        let root = expected
            .iter()
            .position(|value| value == "<source-cgroup-root>")
            .expect("source cgroup root placeholder");
        expected[root] = "/a3s".to_string();
        assert_eq!(expected, options);
        assert!(options
            .windows(2)
            .any(|pair| { pair == ["--external".to_string(), "mnt[]".to_string(),] }));
    }
}
