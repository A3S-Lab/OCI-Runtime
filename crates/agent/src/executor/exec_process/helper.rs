use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result, MAX_CONFIG_BYTES};

use super::{exec_error, EXEC_MODE};
use crate::executor::control::{write_ready, write_rejection, START_BYTE};
use crate::executor::namespace::{apply_supplementary_groups, become_user_namespace_root};
use crate::executor::pid;
use crate::executor::pid_supervisor;
use crate::executor::plan::ProcessPlan;
use crate::executor::process_group::ProcessGroupLease;
use crate::executor::rootfs;

pub(super) fn run_container_exec_if_requested() -> Option<Result<()>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new(EXEC_MODE)) {
        return None;
    }
    Some(parse_helper_arguments(arguments).and_then(run_container_exec))
}

#[derive(Debug)]
struct HelperArguments {
    snapshot: PathBuf,
    control_name: OsString,
    rootfs: File,
    init_pidfd: File,
    expected_parent: libc::pid_t,
    namespaces: Vec<HelperNamespace>,
}

#[derive(Debug)]
struct HelperNamespace {
    name: &'static str,
    clone_flag: libc::c_int,
    descriptor: File,
}

#[derive(Debug)]
struct RawHelperNamespace {
    name: &'static str,
    clone_flag: libc::c_int,
    descriptor: RawFd,
}

fn parse_helper_arguments(arguments: impl Iterator<Item = OsString>) -> Result<HelperArguments> {
    let arguments = arguments.collect::<Vec<_>>();
    if arguments.len() < 5 {
        return Err(exec_error(
            ErrorCode::InvalidArgument,
            "container-exec requires SNAPSHOT CONTROL ROOTFD INITPIDFD PARENTPID [NAMESPACE...]",
        ));
    }
    let snapshot = PathBuf::from(&arguments[0]);
    let control_name = arguments[1].clone();
    let rootfs = parse_descriptor(&arguments[2], "rootfs descriptor")?;
    let init_pidfd = parse_descriptor(&arguments[3], "init pidfd")?;
    let expected_parent = parse_positive_pid(&arguments[4], "expected parent PID")?;

    let mut descriptors = BTreeSet::new();
    if !descriptors.insert(rootfs) || !descriptors.insert(init_pidfd) {
        return Err(exec_error(
            ErrorCode::InvalidArgument,
            "container-exec rootfs and init pidfd descriptors must be distinct",
        ));
    }
    let mut last_order = None;
    let mut namespaces = Vec::new();
    for encoded in &arguments[5..] {
        let encoded = encoded.to_str().ok_or_else(|| {
            exec_error(
                ErrorCode::InvalidArgument,
                "namespace descriptor argument is not UTF-8",
            )
        })?;
        let mut parts = encoded.split(':');
        let name = parts.next().unwrap_or_default();
        let flag = parts
            .next()
            .ok_or_else(|| invalid_namespace_argument(encoded))?
            .parse::<libc::c_int>()
            .map_err(|_| invalid_namespace_argument(encoded))?;
        let descriptor = parts
            .next()
            .ok_or_else(|| invalid_namespace_argument(encoded))?
            .parse::<RawFd>()
            .map_err(|_| invalid_namespace_argument(encoded))?;
        if parts.next().is_some() || descriptor <= libc::STDERR_FILENO {
            return Err(invalid_namespace_argument(encoded));
        }
        let (name, expected_flag, order) = allowed_namespace(name).ok_or_else(|| {
            exec_error(
                ErrorCode::InvalidArgument,
                format!("unsupported retained namespace argument `{encoded}`"),
            )
        })?;
        if flag != expected_flag
            || last_order.is_some_and(|previous| order <= previous)
            || !descriptors.insert(descriptor)
        {
            return Err(invalid_namespace_argument(encoded));
        }
        last_order = Some(order);
        namespaces.push(RawHelperNamespace {
            name,
            clone_flag: flag,
            descriptor,
        });
    }
    let namespaces = namespaces
        .into_iter()
        .map(|namespace| {
            // SAFETY: every descriptor was inherited exclusively into this
            // helper and all descriptors were validated as distinct before
            // ownership is transferred.
            let descriptor = unsafe { File::from_raw_fd(namespace.descriptor) };
            HelperNamespace {
                name: namespace.name,
                clone_flag: namespace.clone_flag,
                descriptor,
            }
        })
        .collect();
    // SAFETY: these distinct descriptors were inherited exclusively into the
    // helper and are each transferred to exactly one owner.
    let rootfs = unsafe { File::from_raw_fd(rootfs) };
    let init_pidfd = unsafe { File::from_raw_fd(init_pidfd) };
    Ok(HelperArguments {
        snapshot,
        control_name,
        rootfs,
        init_pidfd,
        expected_parent,
        namespaces,
    })
}

fn run_container_exec(arguments: HelperArguments) -> Result<()> {
    let HelperArguments {
        snapshot,
        control_name,
        rootfs,
        init_pidfd,
        expected_parent,
        namespaces,
    } = arguments;
    verify_and_arm_parent(expected_parent)?;
    let control_address =
        StdSocketAddr::from_abstract_name(control_name.as_bytes()).map_err(|error| {
            exec_error(
                ErrorCode::InvalidArgument,
                format!("invalid abstract exec control address: {error}"),
            )
        })?;
    let mut control = StdUnixStream::connect_addr(&control_address).map_err(|error| {
        exec_error(
            ErrorCode::Unavailable,
            format!("failed to connect container exec control socket: {error}"),
        )
    })?;
    ensure_control_close_on_exec(&control)?;
    let process_group = match ProcessGroupLease::open_for_snapshot_sync(&snapshot) {
        Ok(process_group) => process_group,
        Err(error) => return reject_exec(&mut control, error),
    };
    let prepared = prepare_helper(&snapshot);
    let (plan, host_proc) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return reject_exec(&mut control, error),
    };
    if let Err(error) = enter_namespaces(&namespaces) {
        return reject_exec(&mut control, error);
    }

    // SAFETY: this internal helper is a fresh, single-threaded executable.
    // The child follows a bounded setup path and the parent only supervises it.
    let payload_pid = unsafe { libc::fork() };
    if payload_pid < 0 {
        return reject_exec(
            &mut control,
            last_exec_os_error("fork container exec payload"),
        );
    }
    if payload_pid == 0 {
        // SAFETY: `getppid` has no preconditions.
        let helper_pid = unsafe { libc::getppid() };
        if let Err(error) = pid_supervisor::arm_parent_death_signal("exec payload") {
            return reject_exec(&mut control, error);
        }
        // SAFETY: `getppid` has no preconditions.
        if unsafe { libc::getppid() } != helper_pid {
            return reject_exec(
                &mut control,
                exec_error(
                    ErrorCode::Unavailable,
                    "exec helper exited while preparing its payload",
                ),
            );
        }
        return run_exec_payload(
            &plan,
            &host_proc,
            &rootfs,
            &init_pidfd,
            &namespaces,
            &mut control,
        );
    }

    drop(control);
    drop(host_proc);
    drop(rootfs);
    drop(namespaces);
    let outcome = pid_supervisor::supervise_exec_payload(
        payload_pid,
        init_pidfd.as_raw_fd(),
        &process_group,
    )?;
    pid_supervisor::mirror_child_outcome(outcome)
}

fn prepare_helper(snapshot: &Path) -> Result<(ProcessPlan, File)> {
    let plan = read_process_plan(snapshot)?;
    let host_proc = File::open("/proc").map_err(|error| {
        exec_error(
            ErrorCode::FailedPrecondition,
            format!("failed to retain host procfs for exec PID authentication: {error}"),
        )
    })?;
    Ok((plan, host_proc))
}

fn enter_namespaces(namespaces: &[HelperNamespace]) -> Result<()> {
    for namespace in namespaces {
        // SAFETY: the descriptor pins the exact namespace captured from the
        // configured process and the clone flag is matched to its path type.
        if unsafe { libc::setns(namespace.descriptor.as_raw_fd(), namespace.clone_flag) } != 0 {
            return Err(last_exec_os_error(&format!(
                "enter retained {} namespace",
                namespace.name
            )));
        }
        if namespace.clone_flag == libc::CLONE_NEWUSER {
            become_user_namespace_root("retained exec")?;
        }
    }
    Ok(())
}

fn run_exec_payload(
    plan: &ProcessPlan,
    host_proc: &File,
    rootfs: &File,
    init_pidfd: &File,
    namespaces: &[HelperNamespace],
    control: &mut StdUnixStream,
) -> Result<()> {
    // The child no longer monitors init itself; its direct helper owns that
    // pidfd and will kill this process group if init exits.
    restore_close_on_exec(rootfs, init_pidfd, namespaces)?;
    let runtime_pid = match pid::host_visible_pid(host_proc) {
        Ok(pid) => pid,
        Err(error) => return reject_exec(control, error),
    };
    if let Err(error) = pid_supervisor::establish_process_group() {
        return reject_exec(control, error);
    }
    if let Err(error) = crate::executor::terminal::make_foreground_process_group(plan.terminal) {
        return reject_exec(
            control,
            exec_error(
                ErrorCode::Internal,
                format!("make exec process group terminal foreground failed: {error}"),
            ),
        );
    }
    if let Err(error) = prepare_exec_root(plan, rootfs) {
        return reject_exec(control, error);
    }
    write_ready(control, runtime_pid, None)?;
    let mut start = [0_u8; 1];
    if let Err(error) = control.read_exact(&mut start) {
        return reject_exec(
            control,
            exec_error(
                ErrorCode::Unavailable,
                format!("prepared exec start barrier closed: {error}"),
            ),
        );
    }
    if start[0] != START_BYTE {
        return reject_exec(
            control,
            exec_error(
                ErrorCode::FailedPrecondition,
                "prepared exec received an invalid start byte",
            ),
        );
    }
    match crate::executor::scheduler::apply(plan.scheduler.as_ref())
        .and_then(|()| crate::executor::io_priority::apply(plan.io_priority.as_ref()))
        .and_then(|()| crate::executor::oom::apply(host_proc, plan.oom_score_adj))
        .and_then(|()| apply_exec_credentials(plan))
        .and_then(|()| execute_process(plan))
    {
        Ok(()) => Ok(()),
        Err(error) => reject_exec(control, error),
    }
}

fn prepare_exec_root(plan: &ProcessPlan, rootfs: &File) -> Result<()> {
    rootfs::chroot(rootfs)?;
    let cwd = CString::new(plan.cwd.as_bytes()).map_err(|error| {
        exec_error(
            ErrorCode::InvalidArgument,
            format!("process.cwd contains a NUL byte: {error}"),
        )
    })?;
    // SAFETY: the plan was validated and this is a dedicated single-threaded
    // payload before untrusted code runs.
    unsafe {
        if libc::chdir(cwd.as_ptr()) != 0 {
            return Err(last_exec_os_error("change to exec process.cwd"));
        }
    }
    Ok(())
}

fn apply_exec_credentials(plan: &ProcessPlan) -> Result<()> {
    plan.rlimits.apply()?;
    plan.capabilities.prepare_for_credentials(plan.uid)?;
    apply_supplementary_groups(&plan.additional_gids, "apply exec supplementary groups")?;
    // SAFETY: the plan was validated and this is a dedicated single-threaded
    // payload before untrusted code runs.
    unsafe {
        if libc::setgid(plan.gid) != 0 {
            return Err(last_exec_os_error("apply exec process GID"));
        }
        if libc::setuid(plan.uid) != 0 {
            return Err(last_exec_os_error("apply exec process UID"));
        }
        if let Some(umask) = plan.umask {
            libc::umask(umask);
        }
    }
    plan.capabilities.apply_after_credentials(plan.uid)?;
    // SAFETY: `PR_SET_NO_NEW_PRIVS` consumes a boolean integer and zero
    // padding arguments.
    if plan.no_new_privileges && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(last_exec_os_error("enable exec no_new_privileges"));
    }
    plan.seccomp.install()?;
    Ok(())
}

fn execute_process(plan: &ProcessPlan) -> Result<()> {
    let args = cstring_vector(&plan.args, "process.args")?;
    let environment = cstring_vector(&plan.environment, "process.env")?;
    let executable = args.first().ok_or_else(|| {
        exec_error(
            ErrorCode::InvalidArgument,
            "process.args must contain an executable",
        )
    })?;
    let mut arg_pointers = args.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    arg_pointers.push(std::ptr::null());
    let mut environment_pointers = environment
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null());
    // SAFETY: every pointer references a live NUL-terminated buffer and this
    // dedicated child immediately replaces itself.
    unsafe {
        libc::execve(
            executable.as_ptr(),
            arg_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        );
    }
    Err(last_exec_os_error("execute configured exec process"))
}

fn restore_close_on_exec(
    rootfs: &File,
    init_pidfd: &File,
    namespaces: &[HelperNamespace],
) -> Result<()> {
    let descriptors = std::iter::once(rootfs.as_raw_fd())
        .chain(std::iter::once(init_pidfd.as_raw_fd()))
        .chain(
            namespaces
                .iter()
                .map(|namespace| namespace.descriptor.as_raw_fd()),
        );
    for descriptor in descriptors {
        // SAFETY: every descriptor is live in this payload descriptor table.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            // SAFETY: `F_SETFD` updates only this payload descriptor table.
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(last_exec_os_error(
                "restore close-on-exec on retained descriptor",
            ));
        }
    }
    Ok(())
}

fn ensure_control_close_on_exec(control: &StdUnixStream) -> Result<()> {
    let descriptor = control.as_raw_fd();
    // SAFETY: `descriptor` is owned by the live control stream. These calls
    // only inspect and update its close-on-exec flag in this helper process.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        Err(last_exec_os_error(
            "mark exec control descriptor close-on-exec",
        ))
    } else {
        Ok(())
    }
}

fn read_process_plan(path: &Path) -> Result<ProcessPlan> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        exec_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to inspect exec process snapshot {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(exec_error(
            ErrorCode::InvalidArgument,
            format!(
                "exec process snapshot must be a regular file no larger than \
                 {MAX_CONFIG_BYTES} bytes"
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| {
            exec_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to read exec process snapshot {}: {error}",
                    path.display()
                ),
            )
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(exec_error(
            ErrorCode::ResourceExhausted,
            "exec process snapshot exceeded its bounded size while reading",
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        exec_error(
            ErrorCode::FailedPrecondition,
            format!("exec process snapshot is invalid: {error}"),
        )
    })
}

fn verify_and_arm_parent(expected_parent: libc::pid_t) -> Result<()> {
    // SAFETY: `getppid` has no preconditions.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(exec_error(
            ErrorCode::PermissionDenied,
            "container exec helper parent does not match its authenticated launcher",
        ));
    }
    pid_supervisor::arm_parent_death_signal("exec helper")?;
    // SAFETY: rechecking closes the race between parent inspection and prctl.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(exec_error(
            ErrorCode::Unavailable,
            "container exec launcher exited during helper bootstrap",
        ));
    }
    Ok(())
}

fn parse_descriptor(value: &OsStr, description: &str) -> Result<RawFd> {
    value
        .to_str()
        .and_then(|value| value.parse::<RawFd>().ok())
        .filter(|descriptor| *descriptor > libc::STDERR_FILENO)
        .ok_or_else(|| {
            exec_error(
                ErrorCode::InvalidArgument,
                format!("container exec received invalid {description}"),
            )
        })
}

fn parse_positive_pid(value: &OsStr, description: &str) -> Result<libc::pid_t> {
    value
        .to_str()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            exec_error(
                ErrorCode::InvalidArgument,
                format!("container exec received invalid {description}"),
            )
        })
}

fn allowed_namespace(name: &str) -> Option<(&'static str, libc::c_int, usize)> {
    match name {
        "user" => Some(("user", libc::CLONE_NEWUSER, 0)),
        "cgroup" => Some(("cgroup", libc::CLONE_NEWCGROUP, 1)),
        "ipc" => Some(("ipc", libc::CLONE_NEWIPC, 2)),
        "uts" => Some(("uts", libc::CLONE_NEWUTS, 3)),
        "net" => Some(("net", libc::CLONE_NEWNET, 4)),
        "mnt" => Some(("mnt", libc::CLONE_NEWNS, 5)),
        "pid" => Some(("pid", libc::CLONE_NEWPID, 6)),
        "time" => Some(("time", libc::CLONE_NEWTIME, 7)),
        _ => None,
    }
}

fn invalid_namespace_argument(encoded: &str) -> Error {
    exec_error(
        ErrorCode::InvalidArgument,
        format!("invalid retained namespace argument `{encoded}`"),
    )
}

fn reject_exec(control: &mut StdUnixStream, error: Error) -> Result<()> {
    if let Err(report) = write_rejection(control, &error) {
        Err(exec_error(
            ErrorCode::Internal,
            format!("{error}; failed to report the exact rejection: {report}"),
        ))
    } else {
        Err(error)
    }
}

fn cstring_vector(values: &[String], field: &str) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_bytes()).map_err(|error| {
                exec_error(
                    ErrorCode::InvalidArgument,
                    format!("{field} contains a NUL byte: {error}"),
                )
            })
        })
        .collect()
}

fn last_exec_os_error(operation: &str) -> Error {
    exec_error(
        ErrorCode::Internal,
        format!("{operation} failed: {}", io::Error::last_os_error()),
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use a3s_oci_sdk::ErrorCode;

    use super::parse_helper_arguments;

    fn parse(values: &[&str]) -> a3s_oci_sdk::Result<super::HelperArguments> {
        parse_helper_arguments(values.iter().map(OsString::from))
    }

    #[test]
    fn helper_requires_its_complete_authenticated_argument_prefix() {
        let error = parse(&["snapshot", "control", "3", "4"])
            .expect_err("missing parent PID must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("requires SNAPSHOT"));
    }

    #[test]
    fn helper_rejects_duplicate_root_and_init_descriptors() {
        let error = parse(&["snapshot", "control", "3", "3", "42"])
            .expect_err("duplicate retained descriptors must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("must be distinct"));
    }

    #[test]
    fn helper_rejects_unordered_duplicate_and_unknown_namespaces_before_owning_fds() {
        for arguments in [
            vec![
                "snapshot",
                "control",
                "3",
                "4",
                "42",
                "mnt:131072:5",
                "user:268435456:6",
            ],
            vec![
                "snapshot",
                "control",
                "3",
                "4",
                "42",
                "user:268435456:5",
                "user:268435456:6",
            ],
            vec!["snapshot", "control", "3", "4", "42", "unknown:1:5"],
        ] {
            let error = parse(&arguments).expect_err("invalid namespace layout must fail closed");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }
    }
}
