use std::ffi::{CString, OsStr};
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixStream};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, IoMode, OciBundle, ProcessIo, Result, MAX_CONFIG_BYTES};

use super::plan::InitPlan;
use super::process::{READY_BYTE, START_BYTE};

pub(crate) fn run_container_init_if_requested() -> Option<Result<()>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new("container-init")) {
        return None;
    }
    let config_snapshot = arguments.next().map(PathBuf::from);
    let bundle_directory = arguments.next().map(PathBuf::from);
    let control_name = arguments.next();
    let extra = arguments.next();
    let (Some(config_snapshot), Some(bundle_directory), Some(control_name), None) =
        (config_snapshot, bundle_directory, control_name, extra)
    else {
        return Some(Err(init_error(
            ErrorCode::InvalidArgument,
            "container-init requires CONFIG BUNDLE CONTROL and no extra arguments",
        )));
    };
    Some(run_container_init(
        config_snapshot,
        bundle_directory,
        control_name,
    ))
}

fn run_container_init(
    config_snapshot: PathBuf,
    bundle_directory: PathBuf,
    control_name: std::ffi::OsString,
) -> Result<()> {
    let config_json = read_bounded_config(&config_snapshot)?;
    let bundle = OciBundle::from_json(bundle_directory, config_json)?;
    let plan = InitPlan::from_bundle(&bundle, &null_io())?;
    let canonical_bundle = plan.bundle_directory.canonicalize().map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to resolve guest bundle {}: {error}",
                plan.bundle_directory.display()
            ),
        )
    })?;
    let rootfs = plan.rootfs.canonicalize().map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to resolve container rootfs {}: {error}",
                plan.rootfs.display()
            ),
        )
    })?;
    if rootfs == canonical_bundle || !rootfs.starts_with(&canonical_bundle) || !rootfs.is_dir() {
        return Err(init_error(
            ErrorCode::PermissionDenied,
            format!(
                "container rootfs escapes its guest bundle: {}",
                rootfs.display()
            ),
        ));
    }
    prepare_create_environment(&plan)?;

    let control_address =
        StdSocketAddr::from_abstract_name(control_name.as_bytes()).map_err(|error| {
            init_error(
                ErrorCode::InvalidArgument,
                format!("invalid abstract init control address: {error}"),
            )
        })?;
    let mut control = UnixStream::connect_addr(&control_address).map_err(|error| {
        init_error(
            ErrorCode::Unavailable,
            format!("failed to connect abstract prepared init control socket: {error}"),
        )
    })?;
    control.write_all(&[READY_BYTE]).map_err(|error| {
        init_error(
            ErrorCode::Unavailable,
            format!("failed to report prepared init readiness: {error}"),
        )
    })?;
    let mut start = [0_u8; 1];
    control.read_exact(&mut start).map_err(|error| {
        init_error(
            ErrorCode::Unavailable,
            format!("prepared init start barrier closed: {error}"),
        )
    })?;
    if start[0] != START_BYTE {
        return Err(init_error(
            ErrorCode::FailedPrecondition,
            "prepared init received an invalid start byte",
        ));
    }
    drop(control);
    enter_rootfs_and_exec(&plan, &rootfs)
}

fn prepare_create_environment(plan: &InitPlan) -> Result<()> {
    if plan.new_uts_namespace {
        // SAFETY: `unshare` has no pointer preconditions. This dedicated
        // wrapper is single-threaded before it reports the created barrier.
        if unsafe { libc::unshare(libc::CLONE_NEWUTS) } != 0 {
            return Err(last_os_error("create Linux UTS namespace"));
        }
    }
    if let Some(hostname) = &plan.hostname {
        if !plan.new_uts_namespace {
            return Err(init_error(
                ErrorCode::FailedPrecondition,
                "refusing to change hostname outside a new UTS namespace",
            ));
        }
        // SAFETY: the byte slice remains live for the call and its exact
        // length was bounded by the validated init plan.
        if unsafe { libc::sethostname(hostname.as_bytes().as_ptr().cast(), hostname.len()) } != 0 {
            return Err(last_os_error("set container hostname"));
        }
    }
    if let Some(domainname) = &plan.domainname {
        if !plan.new_uts_namespace {
            return Err(init_error(
                ErrorCode::FailedPrecondition,
                "refusing to change domainname outside a new UTS namespace",
            ));
        }
        // SAFETY: the byte slice remains live for the call and its exact
        // length was bounded by the validated init plan.
        if unsafe { libc::setdomainname(domainname.as_bytes().as_ptr().cast(), domainname.len()) }
            != 0
        {
            return Err(last_os_error("set container domainname"));
        }
    }
    verify_uts_names(plan)
}

fn verify_uts_names(plan: &InitPlan) -> Result<()> {
    if plan.hostname.is_none() && plan.domainname.is_none() {
        return Ok(());
    }
    let mut names = MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `names` points to writable storage for one complete `utsname`.
    // A successful `uname` initializes the entire structure.
    if unsafe { libc::uname(names.as_mut_ptr()) } != 0 {
        return Err(last_os_error("read configured UTS names"));
    }
    // SAFETY: the successful `uname` call above initialized `names`.
    let names = unsafe { names.assume_init() };
    if let Some(expected) = &plan.hostname {
        verify_uts_name("hostname", expected, &names.nodename)?;
    }
    if let Some(expected) = &plan.domainname {
        verify_uts_name("domainname", expected, &names.domainname)?;
    }
    Ok(())
}

fn verify_uts_name(field: &str, expected: &str, actual: &[libc::c_char]) -> Result<()> {
    let actual = actual
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    if actual == expected.as_bytes() {
        Ok(())
    } else {
        Err(init_error(
            ErrorCode::Internal,
            format!("{field} did not match after applying the OCI UTS configuration"),
        ))
    }
}

fn read_bounded_config(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to inspect init configuration {}: {error}",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(init_error(
            ErrorCode::InvalidArgument,
            format!(
                "init configuration must be a regular file no larger than {MAX_CONFIG_BYTES} bytes"
            ),
        ));
    }
    let file = std::fs::File::open(path).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to open init configuration {}: {error}",
                path.display()
            ),
        )
    })?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            init_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to read init configuration {}: {error}",
                    path.display()
                ),
            )
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(init_error(
            ErrorCode::InvalidArgument,
            "init configuration exceeded its bounded size while reading",
        ));
    }
    String::from_utf8(bytes).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!("init configuration is not UTF-8: {error}"),
        )
    })
}

fn enter_rootfs_and_exec(plan: &InitPlan, rootfs: &Path) -> Result<()> {
    let rootfs = path_cstring(rootfs, "rootfs")?;
    let cwd = CString::new(plan.cwd.as_bytes()).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!("process.cwd contains a NUL byte: {error}"),
        )
    })?;
    let args = cstring_vector(&plan.args, "process.args")?;
    let environment = cstring_vector(&plan.environment, "process.env")?;
    let executable = args.first().ok_or_else(|| {
        init_error(
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

    // SAFETY: every pointer below references a live, NUL-terminated buffer.
    // This internal init process is single-threaded and immediately replaces
    // its image after applying the validated bootstrap profile.
    unsafe {
        if libc::chroot(rootfs.as_ptr()) != 0 {
            return Err(last_os_error("chroot container rootfs"));
        }
        if libc::chdir(cwd.as_ptr()) != 0 {
            return Err(last_os_error("change to configured process.cwd"));
        }
        let groups = plan.additional_gids.clone();
        if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
            return Err(last_os_error("apply supplementary groups"));
        }
        if libc::setgid(plan.gid) != 0 {
            return Err(last_os_error("apply process GID"));
        }
        if libc::setuid(plan.uid) != 0 {
            return Err(last_os_error("apply process UID"));
        }
        if let Some(umask) = plan.umask {
            libc::umask(umask);
        }
        if plan.no_new_privileges && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(last_os_error("enable no_new_privileges"));
        }
        libc::execve(
            executable.as_ptr(),
            arg_pointers.as_ptr(),
            environment_pointers.as_ptr(),
        );
    }
    Err(last_os_error("execute configured init process"))
}

fn cstring_vector(values: &[String], field: &str) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_bytes()).map_err(|error| {
                init_error(
                    ErrorCode::InvalidArgument,
                    format!("{field} contains a NUL byte: {error}"),
                )
            })
        })
        .collect()
}

fn path_cstring(path: &Path, field: &str) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!("{field} contains a NUL byte: {error}"),
        )
    })
}

fn null_io() -> ProcessIo {
    ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Null,
        stderr: IoMode::Null,
        terminal_size: None,
    }
}

fn last_os_error(operation: &str) -> Error {
    init_error(
        ErrorCode::Internal,
        format!("{operation} failed: {}", io::Error::last_os_error()),
    )
}

fn init_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}
