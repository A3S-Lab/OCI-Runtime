use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, Hook, Hooks};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::Serialize;

const MAX_HOOKS_PER_PHASE: usize = 256;
const MAX_HOOK_ARGUMENTS: usize = 4_096;
const MAX_HOOK_ENVIRONMENT: usize = 4_096;
const MAX_HOOK_BYTES: usize = 1024 * 1024;
const MAX_HOOK_STATE_BYTES: usize = 2 * 1024 * 1024;
const HOOK_WAIT_INTERVAL: Duration = Duration::from_millis(10);
const FIRST_PRIVATE_DESCRIPTOR: u32 = 3;

/// OCI hook phases in their normative lifecycle order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HookPhase {
    Prestart,
    CreateRuntime,
    CreateContainer,
    StartContainer,
    Poststart,
    Poststop,
}

impl HookPhase {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Prestart => "prestart",
            Self::CreateRuntime => "createRuntime",
            Self::CreateContainer => "createContainer",
            Self::StartContainer => "startContainer",
            Self::Poststart => "poststart",
            Self::Poststop => "poststop",
        }
    }
}

/// Validated, bounded hook command detached from the untrusted OCI model.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HookPlan {
    path: PathBuf,
    args: Option<Vec<String>>,
    environment: Option<Vec<(String, String)>>,
    timeout: Option<Duration>,
}

/// Complete immutable hook plan for one container generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct HookSet {
    prestart: Vec<HookPlan>,
    create_runtime: Vec<HookPlan>,
    create_container: Vec<HookPlan>,
    start_container: Vec<HookPlan>,
    poststart: Vec<HookPlan>,
    poststop: Vec<HookPlan>,
}

impl HookSet {
    #[allow(deprecated)]
    pub(super) fn from_oci(hooks: Option<&Hooks>) -> Result<Self> {
        let Some(hooks) = hooks else {
            return Ok(Self::default());
        };
        Ok(Self {
            prestart: plan_phase(HookPhase::Prestart, hooks.prestart().as_deref())?,
            create_runtime: plan_phase(
                HookPhase::CreateRuntime,
                hooks.create_runtime().as_deref(),
            )?,
            create_container: plan_phase(
                HookPhase::CreateContainer,
                hooks.create_container().as_deref(),
            )?,
            start_container: plan_phase(
                HookPhase::StartContainer,
                hooks.start_container().as_deref(),
            )?,
            poststart: plan_phase(HookPhase::Poststart, hooks.poststart().as_deref())?,
            poststop: plan_phase(HookPhase::Poststop, hooks.poststop().as_deref())?,
        })
    }

    pub(super) fn run_sync(&self, phase: HookPhase, state: &[u8]) -> Result<()> {
        validate_state(state)?;
        for (index, hook) in self.phase(phase).iter().enumerate() {
            run_hook(phase, index, hook, state)?;
        }
        Ok(())
    }

    pub(super) async fn run(&self, phase: HookPhase, state: &[u8]) -> Result<()> {
        let hooks = self.phase(phase).to_vec();
        let state = state.to_vec();
        tokio::task::spawn_blocking(move || {
            validate_state(&state)?;
            for (index, hook) in hooks.iter().enumerate() {
                run_hook(phase, index, hook, &state)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            hook_error(
                ErrorCode::Internal,
                phase,
                format!("hook worker failed to join: {error}"),
            )
        })?
    }

    /// Run every poststop hook and report warnings without changing cleanup.
    pub(super) async fn run_poststop(&self, state: &[u8]) {
        let hooks = self.poststop.clone();
        let state = state.to_vec();
        let joined = tokio::task::spawn_blocking(move || {
            let mut warnings = Vec::new();
            if let Err(error) = validate_state(&state) {
                warnings.push(error);
                return warnings;
            }
            for (index, hook) in hooks.iter().enumerate() {
                if let Err(error) = run_hook(HookPhase::Poststop, index, hook, &state) {
                    warnings.push(error);
                }
            }
            warnings
        })
        .await;
        match joined {
            Ok(warnings) => {
                for warning in warnings {
                    eprintln!("a3s-oci-agent: poststop hook warning: {warning}");
                }
            }
            Err(error) => {
                eprintln!("a3s-oci-agent: poststop hook worker warning: {error}");
            }
        }
    }

    fn phase(&self, phase: HookPhase) -> &[HookPlan] {
        match phase {
            HookPhase::Prestart => &self.prestart,
            HookPhase::CreateRuntime => &self.create_runtime,
            HookPhase::CreateContainer => &self.create_container,
            HookPhase::StartContainer => &self.start_container,
            HookPhase::Poststart => &self.poststart,
            HookPhase::Poststop => &self.poststop,
        }
    }
}

/// Stable fields shared by every OCI state document sent to hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HookStateTemplate {
    version: String,
    id: String,
    bundle: PathBuf,
    annotations: BTreeMap<String, String>,
}

impl HookStateTemplate {
    pub(super) fn new(
        version: impl Into<String>,
        id: impl Into<String>,
        bundle: PathBuf,
        annotations: BTreeMap<String, String>,
    ) -> Result<Self> {
        let version = version.into();
        let id = id.into();
        if version.is_empty() || id.is_empty() || !bundle.is_absolute() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "hook state requires a version, container ID, and absolute bundle path",
            )
            .for_operation("plan-oci-hooks"));
        }
        Ok(Self {
            version,
            id,
            bundle,
            annotations,
        })
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn encode(&self, status: ContainerState, pid: Option<i32>) -> Result<Vec<u8>> {
        if matches!(
            status,
            ContainerState::Creating | ContainerState::Created | ContainerState::Running
        ) && pid.is_none_or(|pid| pid <= 0)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("{status} hook state requires a positive init PID"),
            )
            .for_operation("encode-oci-hook-state"));
        }
        if status == ContainerState::Stopped && pid.is_some() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "stopped hook state must not contain an init PID",
            )
            .for_operation("encode-oci-hook-state"));
        }
        let encoded = serde_json::to_vec(&HookState {
            version: &self.version,
            id: &self.id,
            status,
            pid,
            bundle: &self.bundle,
            annotations: (!self.annotations.is_empty()).then_some(&self.annotations),
        })
        .map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to encode OCI hook state: {error}"),
            )
            .for_operation("encode-oci-hook-state")
        })?;
        validate_state(&encoded)?;
        Ok(encoded)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HookState<'a> {
    #[serde(rename = "ociVersion")]
    version: &'a str,
    id: &'a str,
    status: ContainerState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<i32>,
    bundle: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<&'a BTreeMap<String, String>>,
}

fn plan_phase(phase: HookPhase, hooks: Option<&[Hook]>) -> Result<Vec<HookPlan>> {
    let hooks = hooks.unwrap_or_default();
    if hooks.len() > MAX_HOOKS_PER_PHASE {
        return Err(hook_error(
            ErrorCode::ResourceExhausted,
            phase,
            format!(
                "contains {} hooks; maximum is {MAX_HOOKS_PER_PHASE}",
                hooks.len()
            ),
        ));
    }
    hooks
        .iter()
        .enumerate()
        .map(|(index, hook)| plan_hook(phase, index, hook))
        .collect()
}

fn plan_hook(phase: HookPhase, index: usize, hook: &Hook) -> Result<HookPlan> {
    let path = normalized_absolute_path(hook.path(), phase, index)?;
    let args = hook.args().clone();
    if let Some(args) = &args {
        validate_vector(phase, index, "args", args, MAX_HOOK_ARGUMENTS)?;
    }
    let environment = hook
        .env()
        .as_ref()
        .map(|environment| plan_environment(phase, index, environment))
        .transpose()?;
    let timeout = hook
        .timeout()
        .map(|seconds| {
            u64::try_from(seconds)
                .ok()
                .filter(|seconds| *seconds > 0)
                .map(Duration::from_secs)
                .ok_or_else(|| {
                    hook_error(
                        ErrorCode::InvalidArgument,
                        phase,
                        format!("hook {index} timeout must be a positive number of seconds"),
                    )
                })
        })
        .transpose()?;
    Ok(HookPlan {
        path,
        args,
        environment,
        timeout,
    })
}

fn normalized_absolute_path(path: &Path, phase: HookPhase, index: usize) -> Result<PathBuf> {
    let value = path.to_str().ok_or_else(|| {
        hook_error(
            ErrorCode::InvalidArgument,
            phase,
            format!("hook {index} path is not valid UTF-8"),
        )
    })?;
    let normalized = value.starts_with('/')
        && value != "/"
        && !value.ends_with('/')
        && !value.as_bytes().contains(&0)
        && !value.contains('\\')
        && value.strip_prefix('/').is_some_and(|path| {
            !path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        });
    if !normalized {
        return Err(hook_error(
            ErrorCode::InvalidArgument,
            phase,
            format!("hook {index} path must be a normalized absolute POSIX path"),
        ));
    }
    Ok(path.to_path_buf())
}

fn plan_environment(
    phase: HookPhase,
    index: usize,
    environment: &[String],
) -> Result<Vec<(String, String)>> {
    validate_vector(phase, index, "env", environment, MAX_HOOK_ENVIRONMENT)?;
    let mut names = BTreeSet::new();
    let mut planned = Vec::with_capacity(environment.len());
    for entry in environment {
        let Some((name, value)) = entry.split_once('=') else {
            return Err(hook_error(
                ErrorCode::InvalidArgument,
                phase,
                format!("hook {index} env entry must contain a name and `=` separator"),
            ));
        };
        if name.is_empty() || name.contains('=') || !names.insert(name.to_string()) {
            return Err(hook_error(
                ErrorCode::InvalidArgument,
                phase,
                format!("hook {index} env contains an empty or duplicate variable name"),
            ));
        }
        planned.push((name.to_string(), value.to_string()));
    }
    Ok(planned)
}

fn validate_vector(
    phase: HookPhase,
    index: usize,
    field: &str,
    values: &[String],
    maximum: usize,
) -> Result<()> {
    if values.len() > maximum {
        return Err(hook_error(
            ErrorCode::ResourceExhausted,
            phase,
            format!(
                "hook {index} {field} contains {} entries; maximum is {maximum}",
                values.len()
            ),
        ));
    }
    let mut bytes = 0_usize;
    for value in values {
        if value.as_bytes().contains(&0) {
            return Err(hook_error(
                ErrorCode::InvalidArgument,
                phase,
                format!("hook {index} {field} contains a NUL byte"),
            ));
        }
        bytes = bytes
            .checked_add(value.len().saturating_add(1))
            .ok_or_else(|| {
                hook_error(
                    ErrorCode::ResourceExhausted,
                    phase,
                    format!("hook {index} {field} size overflow"),
                )
            })?;
        if bytes > MAX_HOOK_BYTES {
            return Err(hook_error(
                ErrorCode::ResourceExhausted,
                phase,
                format!("hook {index} {field} exceeds {MAX_HOOK_BYTES} bytes"),
            ));
        }
    }
    Ok(())
}

fn validate_state(state: &[u8]) -> Result<()> {
    if state.is_empty() || state.len() > MAX_HOOK_STATE_BYTES {
        Err(Error::new(
            ErrorCode::ResourceExhausted,
            format!(
                "OCI hook state contains {} bytes; expected 1..={MAX_HOOK_STATE_BYTES}",
                state.len()
            ),
        )
        .for_operation("run-oci-hook"))
    } else {
        Ok(())
    }
}

fn run_hook(phase: HookPhase, index: usize, hook: &HookPlan, state: &[u8]) -> Result<()> {
    let deadline = hook
        .timeout
        .map(|limit| {
            Instant::now().checked_add(limit).ok_or_else(|| {
                hook_error(
                    ErrorCode::ResourceExhausted,
                    phase,
                    format!("hook {index} timeout exceeds the monotonic clock range"),
                )
            })
        })
        .transpose()?;
    let mut command = Command::new(&hook.path);
    if let Some(args) = &hook.args {
        if let Some((arg0, remaining)) = args.split_first() {
            command.arg0(arg0).args(remaining);
        }
    }
    if let Some(environment) = &hook.environment {
        command.env_clear();
        command.envs(environment.iter().map(|(name, value)| (name, value)));
    }
    command.stdin(Stdio::piped()).process_group(0);
    isolate_hook_descriptors(&mut command);
    let mut child = command.spawn().map_err(|error| {
        hook_error(
            ErrorCode::FailedPrecondition,
            phase,
            format!(
                "hook {index} {} failed to spawn with private descriptor isolation: {error}",
                hook.path.display()
            ),
        )
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        terminate_hook(&mut child);
        hook_error(
            ErrorCode::Internal,
            phase,
            format!("hook {index} did not expose its configured stdin"),
        )
    })?;
    let payload = state.to_vec();
    let writer = thread::Builder::new()
        .name(format!("a3s-oci-hook-{index}"))
        .spawn(move || write_hook_state(stdin, &payload, deadline))
        .map_err(|error| {
            terminate_hook(&mut child);
            hook_error(
                ErrorCode::ResourceExhausted,
                phase,
                format!("hook {index} state writer failed to start: {error}"),
            )
        })?;

    let write_result = writer.join();
    let write_result = match write_result {
        Ok(result) => result,
        Err(_) => {
            terminate_hook(&mut child);
            return Err(hook_error(
                ErrorCode::Internal,
                phase,
                format!("hook {index} state writer panicked"),
            ));
        }
    };
    if let Err(error) = write_result {
        terminate_hook(&mut child);
        let code = if error.kind() == io::ErrorKind::TimedOut {
            ErrorCode::DeadlineExceeded
        } else {
            ErrorCode::FailedPrecondition
        };
        return Err(hook_error(
            code,
            phase,
            format!("hook {index} did not receive complete OCI state: {error}"),
        ));
    }
    let status = wait_hook(&mut child, deadline).map_err(|error| {
        hook_error(
            error.code,
            phase,
            format!("hook {index} {}: {}", hook.path.display(), error.message),
        )
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(hook_error(
            ErrorCode::FailedPrecondition,
            phase,
            format!("hook {index} {} exited with {status}", hook.path.display()),
        ))
    }
}

fn isolate_hook_descriptors(command: &mut Command) {
    // SAFETY: this closure runs in the forked child before exec. It invokes one
    // allocation-free Linux syscall and touches only the child's descriptor
    // table. CLOEXEC preserves the process-spawn error channel until exec while
    // ensuring that no runtime-private descriptor reaches untrusted hook code.
    unsafe {
        command.pre_exec(|| {
            let result = libc::syscall(
                libc::SYS_close_range,
                FIRST_PRIVATE_DESCRIPTOR,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    }
}

fn write_hook_state(
    mut stdin: std::process::ChildStdin,
    state: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    let Some(deadline) = deadline else {
        stdin.write_all(state)?;
        return stdin.flush();
    };
    set_nonblocking(&stdin)?;
    let mut written = 0_usize;
    while written < state.len() {
        match stdin.write(&state[written..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => written += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out writing OCI state to the hook",
                    ));
                }
                thread::sleep(HOOK_WAIT_INTERVAL.min(remaining));
            }
            Err(error) => return Err(error),
        }
    }
    stdin.flush()
}

fn set_nonblocking(stdin: &std::process::ChildStdin) -> io::Result<()> {
    let descriptor = stdin.as_raw_fd();
    // SAFETY: `descriptor` is owned by the live ChildStdin. These operations
    // only read and update the descriptor's file-status flags.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_hook(child: &mut Child, deadline: Option<Instant>) -> Result<ExitStatus> {
    let Some(deadline) = deadline else {
        return child.wait().map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to wait for hook process: {error}"),
            )
            .for_operation("run-oci-hook")
        });
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(
                    HOOK_WAIT_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Ok(None) => {
                terminate_hook(child);
                return Err(Error::new(
                    ErrorCode::DeadlineExceeded,
                    "hook exceeded its configured timeout",
                )
                .for_operation("run-oci-hook"));
            }
            Err(error) => {
                terminate_hook(child);
                return Err(Error::new(
                    ErrorCode::Internal,
                    format!("failed to inspect hook process: {error}"),
                )
                .for_operation("run-oci-hook"));
            }
        }
    }
}

fn terminate_hook(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: a negative PID addresses the process group created for this
        // exact hook. Failure falls back to killing the direct child.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn hook_error(code: ErrorCode, phase: HookPhase, message: impl Into<String>) -> Error {
    Error::new(code, format!("{} hook: {}", phase.as_str(), message.into()))
        .for_operation("run-oci-hook")
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use a3s_oci_sdk::oci_spec::runtime::ContainerState;
    use a3s_oci_sdk::ErrorCode;

    use super::{HookPhase, HookPlan, HookSet, HookStateTemplate};

    const DESCRIPTOR_CHILD_ENV: &str = "A3S_OCI_TEST_HOOK_DESCRIPTOR_CHILD";
    const DESCRIPTOR_CHILD_TEST: &str = "executor::hook::tests::hook_descriptor_isolation_child";

    #[test]
    fn hook_descriptor_isolation_child() {
        if std::env::var_os(DESCRIPTOR_CHILD_ENV).is_none() {
            return;
        }

        let descriptor = File::open("/dev/null").expect("open descriptor inheritance probe");
        let raw_descriptor = descriptor.as_raw_fd();
        // SAFETY: the descriptor is owned by `descriptor`; this deliberately
        // removes CLOEXEC so the hook boundary must restore isolation.
        let flags = unsafe { libc::fcntl(raw_descriptor, libc::F_GETFD) };
        assert!(flags >= 0, "read descriptor flags");
        // SAFETY: the descriptor remains live and F_SETFD changes only its
        // close-on-exec flag.
        assert_eq!(
            unsafe { libc::fcntl(raw_descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0,
            "clear descriptor CLOEXEC"
        );

        let hooks = HookSet {
            prestart: vec![HookPlan {
                path: PathBuf::from("/bin/sh"),
                args: Some(vec![
                    "a3s-hook".to_string(),
                    "-c".to_string(),
                    format!("/bin/cat >/dev/null; test ! -e /proc/self/fd/{raw_descriptor}"),
                ]),
                environment: Some(Vec::new()),
                timeout: Some(Duration::from_secs(2)),
            }],
            ..HookSet::default()
        };
        hooks
            .run_sync(HookPhase::Prestart, b"{}")
            .expect("hook must not inherit runtime descriptors");
    }

    #[test]
    fn hook_process_cannot_inherit_runtime_descriptors() {
        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", DESCRIPTOR_CHILD_TEST, "--nocapture"])
            .env(DESCRIPTOR_CHILD_ENV, "1")
            .output()
            .expect("launch descriptor isolation child");
        assert!(
            output.status.success(),
            "descriptor isolation child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn hook_planning_accepts_every_phase_and_rejects_unsafe_inputs() {
        let hooks: a3s_oci_sdk::oci_spec::runtime::Hooks =
            serde_json::from_value(serde_json::json!({
                "prestart": [{"path": "/bin/true"}],
                "createRuntime": [{"path": "/bin/true", "timeout": 1}],
                "createContainer": [{"path": "/bin/true"}],
                "startContainer": [{"path": "/bin/true"}],
                "poststart": [{"path": "/bin/true"}],
                "poststop": [{"path": "/bin/true"}]
            }))
            .expect("decode complete hooks");
        let planned = HookSet::from_oci(Some(&hooks)).expect("plan complete hooks");
        for phase in [
            HookPhase::Prestart,
            HookPhase::CreateRuntime,
            HookPhase::CreateContainer,
            HookPhase::StartContainer,
            HookPhase::Poststart,
            HookPhase::Poststop,
        ] {
            assert_eq!(planned.phase(phase).len(), 1, "missing {phase:?}");
        }

        let relative: a3s_oci_sdk::oci_spec::runtime::Hooks =
            serde_json::from_value(serde_json::json!({"poststop": [{"path": "relative"}]}))
                .expect("decode relative hook");
        assert_eq!(
            HookSet::from_oci(Some(&relative))
                .expect_err("relative hook path must fail")
                .code,
            ErrorCode::InvalidArgument
        );
        let duplicate_environment: a3s_oci_sdk::oci_spec::runtime::Hooks =
            serde_json::from_value(serde_json::json!({
                "poststop": [{"path": "/bin/true", "env": ["A=1", "A=2"]}]
            }))
            .expect("decode duplicate environment");
        assert_eq!(
            HookSet::from_oci(Some(&duplicate_environment))
                .expect_err("duplicate environment names must fail")
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn hook_state_is_exact_for_live_and_stopped_phases() {
        let template = HookStateTemplate::new(
            "1.3.0",
            "hook-container",
            PathBuf::from("/bundle"),
            [("example.test/key".to_string(), "value".to_string())]
                .into_iter()
                .collect(),
        )
        .expect("hook state template");
        let creating = template
            .encode(ContainerState::Creating, Some(42))
            .expect("creating state");
        let state: a3s_oci_sdk::oci_spec::runtime::State =
            serde_json::from_slice(&creating).expect("decode creating state");
        assert_eq!(state.id(), "hook-container");
        assert_eq!(*state.status(), ContainerState::Creating);
        assert_eq!(*state.pid(), Some(42));
        assert_eq!(state.bundle(), &PathBuf::from("/bundle"));

        let stopped = template
            .encode(ContainerState::Stopped, None)
            .expect("stopped state");
        let state: a3s_oci_sdk::oci_spec::runtime::State =
            serde_json::from_slice(&stopped).expect("decode stopped state");
        assert_eq!(*state.status(), ContainerState::Stopped);
        assert_eq!(*state.pid(), None);
    }

    #[test]
    fn hooks_receive_state_environment_and_exact_order() {
        let directory = tempfile::tempdir().expect("temporary hook directory");
        let trace = directory.path().join("trace");
        let hook = |phase: &str| {
            HookPlan {
                path: PathBuf::from("/bin/sh"),
                args: Some(vec![
                    "a3s-hook".to_string(),
                    "-c".to_string(),
                    "printf '%s ' \"$PHASE\" >> \"$TRACE\"; cat >> \"$TRACE\"; printf '\\n' >> \"$TRACE\""
                        .to_string(),
                ]),
                environment: Some(vec![
                    ("PHASE".to_string(), phase.to_string()),
                    (
                        "TRACE".to_string(),
                        trace.to_str().expect("UTF-8 trace path").to_string(),
                    ),
                ]),
                timeout: Some(Duration::from_secs(2)),
            }
        };
        let hooks = HookSet {
            prestart: vec![hook("first"), hook("second")],
            ..HookSet::default()
        };
        hooks
            .run_sync(HookPhase::Prestart, br#"{"status":"creating"}"#)
            .expect("run ordered hooks");
        assert_eq!(
            std::fs::read_to_string(trace).expect("read hook trace"),
            "first {\"status\":\"creating\"}\nsecond {\"status\":\"creating\"}\n"
        );
    }

    #[test]
    fn hook_timeout_kills_the_entire_supervised_process_group() {
        let directory = tempfile::tempdir().expect("temporary hook process-group directory");
        let descendant_started = directory.path().join("descendant-started");
        let descendant_escaped = directory.path().join("descendant-escaped");
        let hooks = HookSet {
            prestart: vec![HookPlan {
                path: PathBuf::from("/bin/sh"),
                args: Some(vec![
                    "a3s-hook".to_string(),
                    "-c".to_string(),
                    "set -eu; (trap '' HUP TERM; /bin/sleep 1; : > \"$ESCAPED\") & \
                     printf '%s\\n' \"$!\" > \"$STARTED\"; exec /bin/sleep 30"
                        .to_string(),
                ]),
                environment: Some(vec![
                    (
                        "STARTED".to_string(),
                        descendant_started
                            .to_str()
                            .expect("UTF-8 started path")
                            .to_string(),
                    ),
                    (
                        "ESCAPED".to_string(),
                        descendant_escaped
                            .to_str()
                            .expect("UTF-8 escaped path")
                            .to_string(),
                    ),
                ]),
                timeout: Some(Duration::from_millis(500)),
            }],
            ..HookSet::default()
        };
        let started_at = Instant::now();
        let error = hooks
            .run_sync(HookPhase::Prestart, b"{}")
            .expect_err("hook must time out");
        assert_eq!(error.code, ErrorCode::DeadlineExceeded);
        assert!(started_at.elapsed() < Duration::from_secs(2));
        assert!(
            descendant_started.is_file(),
            "hook descendant did not publish startup evidence"
        );
        std::thread::sleep(Duration::from_millis(750));
        assert!(
            !descendant_escaped.exists(),
            "hook descendant survived process-group termination"
        );
    }

    #[test]
    fn hook_state_writer_obeys_the_same_deadline() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("spawn non-reading hook process");
        let stdin = child.stdin.take().expect("piped hook stdin");
        let state = vec![b'x'; super::MAX_HOOK_STATE_BYTES];
        let started = Instant::now();
        let error = super::write_hook_state(
            stdin,
            &state,
            Some(Instant::now() + Duration::from_millis(100)),
        )
        .expect_err("unread state must time out");
        super::terminate_hook(&mut child);
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn poststop_failure_does_not_skip_remaining_hooks() {
        let directory = tempfile::tempdir().expect("temporary hook directory");
        let trace = directory.path().join("trace");
        let hooks = HookSet {
            poststop: vec![
                HookPlan {
                    path: PathBuf::from("/bin/false"),
                    args: None,
                    environment: Some(Vec::new()),
                    timeout: Some(Duration::from_secs(1)),
                },
                HookPlan {
                    path: PathBuf::from("/bin/sh"),
                    args: Some(vec![
                        "a3s-hook".to_string(),
                        "-c".to_string(),
                        "cat > \"$TRACE\"".to_string(),
                    ]),
                    environment: Some(vec![(
                        "TRACE".to_string(),
                        trace.to_str().expect("UTF-8 trace path").to_string(),
                    )]),
                    timeout: Some(Duration::from_secs(1)),
                },
            ],
            ..HookSet::default()
        };
        hooks.run_poststop(br#"{"status":"stopped"}"#).await;
        assert_eq!(
            std::fs::read_to_string(trace).expect("read poststop trace"),
            "{\"status\":\"stopped\"}"
        );
    }
}
