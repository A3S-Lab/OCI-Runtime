use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixStream};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, IoMode, OciBundle, ProcessIo, Result, MAX_CONFIG_BYTES};

use super::control::{write_ready, write_rejection, START_BYTE};
use super::mount::{self, IdmappedMountSources};
use super::namespace::{self, IdmapNamespaceHandles};
use super::plan::InitPlan;
use super::rootfs;

mod supervision;

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
    let (plan, canonical_bundle, rootfs, rootfs_file, host_proc) =
        match prepare_container_init(config_snapshot, bundle_directory) {
            Ok(prepared) => prepared,
            Err(error) => return reject_before_ready(&mut control, error),
        };
    let idmap_namespaces = match IdmapNamespaceHandles::prepare(
        plan.mounts.iter().filter_map(|mount| mount.idmap.as_ref()),
    ) {
        Ok(namespaces) => namespaces,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    let mut idmapped_sources =
        match IdmappedMountSources::prepare(&plan.mounts, &canonical_bundle, &idmap_namespaces) {
            Ok(sources) => sources,
            Err(error) => return reject_before_ready(&mut control, error),
        };
    drop(idmap_namespaces);
    if let Err(error) = namespace::enter_new_namespaces(&plan.namespaces, &mut control) {
        return reject_before_ready(&mut control, error);
    }
    if plan.namespaces.requires_child_process() {
        return supervision::run_namespaced_init(
            &plan,
            &canonical_bundle,
            &rootfs,
            &rootfs_file,
            &host_proc,
            idmapped_sources,
            control,
        );
    }
    if let Err(error) =
        prepare_create_environment(&plan, &canonical_bundle, &rootfs, &mut idmapped_sources)
    {
        return reject_before_ready(&mut control, error);
    }
    // SAFETY: `getpid` has no preconditions and this wrapper has not entered a
    // PID namespace that changes the runtime-visible process.
    let pid = unsafe { libc::getpid() };
    write_ready(&mut control, pid, None)?;
    wait_for_start_and_exec(&plan, &rootfs_file, control)
}

fn wait_for_start_and_exec(plan: &InitPlan, rootfs: &File, mut control: UnixStream) -> Result<()> {
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
    enter_rootfs_and_exec(plan, rootfs)
}

fn reject_before_ready(control: &mut UnixStream, error: Error) -> Result<()> {
    if let Err(report) = write_rejection(control, &error) {
        Err(init_error(
            ErrorCode::Internal,
            format!("{error}; failed to report the exact rejection: {report}"),
        ))
    } else {
        Err(error)
    }
}

fn prepare_container_init(
    config_snapshot: PathBuf,
    bundle_directory: PathBuf,
) -> Result<(InitPlan, PathBuf, PathBuf, File, File)> {
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
    let rootfs_file = File::open(&rootfs).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!(
                "failed to retain the container rootfs {} before namespace entry: {error}",
                rootfs.display()
            ),
        )
    })?;
    if !rootfs_file
        .metadata()
        .map_err(|error| {
            init_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to inspect retained container rootfs {}: {error}",
                    rootfs.display()
                ),
            )
        })?
        .is_dir()
    {
        return Err(init_error(
            ErrorCode::InvalidArgument,
            format!("container rootfs is not a directory: {}", rootfs.display()),
        ));
    }
    let host_proc = File::open("/proc").map_err(|error| {
        init_error(
            ErrorCode::FailedPrecondition,
            format!("failed to retain host procfs before PID namespace entry: {error}"),
        )
    })?;
    if !host_proc
        .metadata()
        .map_err(|error| {
            init_error(
                ErrorCode::FailedPrecondition,
                format!("failed to inspect retained host procfs: {error}"),
            )
        })?
        .is_dir()
    {
        return Err(init_error(
            ErrorCode::FailedPrecondition,
            "retained host procfs path is not a directory",
        ));
    }
    Ok((plan, canonical_bundle, rootfs, rootfs_file, host_proc))
}

fn prepare_create_environment(
    plan: &InitPlan,
    bundle_directory: &Path,
    rootfs: &Path,
    idmapped_sources: &mut IdmappedMountSources,
) -> Result<()> {
    if let Some(hostname) = &plan.hostname {
        if !plan.namespaces.has_uts() {
            return Err(init_error(
                ErrorCode::FailedPrecondition,
                "refusing to change hostname outside a configured UTS namespace",
            ));
        }
        // SAFETY: the byte slice remains live for the call and its exact
        // length was bounded by the validated init plan.
        if unsafe { libc::sethostname(hostname.as_bytes().as_ptr().cast(), hostname.len()) } != 0 {
            return Err(last_os_error("set container hostname"));
        }
    }
    if let Some(domainname) = &plan.domainname {
        if !plan.namespaces.has_uts() {
            return Err(init_error(
                ErrorCode::FailedPrecondition,
                "refusing to change domainname outside a configured UTS namespace",
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
    verify_uts_names(plan)?;
    if plan.namespaces.new_mount() {
        plan.devices.validate_rootfs(rootfs)?;
        rootfs::prepare_pivot(rootfs, plan.rootfs_propagation)?;
        mount::apply_all(&plan.mounts, bundle_directory, rootfs, idmapped_sources)?;
        rootfs::pivot_root(rootfs)?;
        plan.devices.create_all()?;
        rootfs::finalize(
            plan.rootfs_propagation,
            &plan.readonly_paths,
            &plan.masked_paths,
            plan.root_readonly,
        )?;
    }
    Ok(())
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
        .map(|byte| byte.to_ne_bytes()[0])
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

fn enter_rootfs_and_exec(plan: &InitPlan, rootfs: &File) -> Result<()> {
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

    if !plan.namespaces.new_mount() {
        rootfs::chroot(rootfs)?;
    }

    plan.capabilities.prepare_for_credentials(plan.uid)?;
    // SAFETY: every pointer below references a live, NUL-terminated buffer.
    // This internal init process is single-threaded and immediately replaces
    // its image after applying the validated bootstrap profile.
    unsafe {
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
    }
    plan.capabilities.apply_after_credentials(plan.uid)?;
    // SAFETY: `PR_SET_NO_NEW_PRIVS` consumes a boolean integer and zero
    // padding arguments.
    if plan.no_new_privileges && unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err(last_os_error("enable no_new_privileges"));
    }
    plan.seccomp.install()?;
    // SAFETY: every pointer below references a live, NUL-terminated buffer.
    unsafe {
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
