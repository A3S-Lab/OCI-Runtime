use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixStream};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, OciBundle, ProcessIo, Result, MAX_CONFIG_BYTES};

use super::control::{
    receive_device_mounts, write_create_hooks_ready, write_ready, write_rejection,
    CREATE_CONTINUE_BYTE, START_BYTE,
};
use super::device::{DevicePlan, PreparedDeviceSources};
use super::hook::{HookPhase, HookStateTemplate};
use super::mount::{self, DetachedMountSources};
use super::namespace::{self, IdmapNamespaceHandles};
use super::pid_supervisor;
use super::plan::InitPlan;
use super::process_group::ProcessGroupLease;
use super::rootfs;
use super::RootfsScope;

mod supervision;

struct ContainerInitInvocation {
    config_snapshot: PathBuf,
    bundle_directory: PathBuf,
    control_name: std::ffi::OsString,
    container_id: String,
    rootfs_scope: RootfsScope,
    expected_owner_pid: libc::pid_t,
    rootless: bool,
    device_source_directory: PathBuf,
    process_io: ProcessIo,
}

pub(crate) fn run_container_init_if_requested() -> Option<Result<()>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new("container-init")) {
        return None;
    }
    let config_snapshot = arguments.next().map(PathBuf::from);
    let bundle_directory = arguments.next().map(PathBuf::from);
    let control_name = arguments.next();
    let container_id = arguments.next();
    let rootfs_scope = arguments.next();
    let expected_owner_pid = arguments.next();
    let mapping_mode = arguments.next();
    let device_source_directory = arguments.next().map(PathBuf::from);
    let process_io = arguments.next();
    let extra = arguments.next();
    let (
        Some(config_snapshot),
        Some(bundle_directory),
        Some(control_name),
        Some(container_id),
        Some(rootfs_scope),
        Some(expected_owner_pid),
        Some(mapping_mode),
        Some(device_source_directory),
        Some(process_io),
        None,
    ) = (
        config_snapshot,
        bundle_directory,
        control_name,
        container_id,
        rootfs_scope,
        expected_owner_pid,
        mapping_mode,
        device_source_directory,
        process_io,
        extra,
    )
    else {
        return Some(Err(init_error(
            ErrorCode::InvalidArgument,
            "container-init requires CONFIG BUNDLE CONTROL ID ROOTFS_SCOPE OWNER_PID MAPPING_MODE DEVICE_SOURCE_DIRECTORY PROCESS_IO and no extra arguments",
        )));
    };
    let container_id = match container_id.into_string() {
        Ok(container_id) if !container_id.is_empty() => container_id,
        _ => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                "container-init requires a non-empty UTF-8 container ID",
            )));
        }
    };
    let Some(rootfs_scope) = RootfsScope::from_internal_argument(&rootfs_scope) else {
        return Some(Err(init_error(
            ErrorCode::InvalidArgument,
            "container-init received an invalid rootfs scope",
        )));
    };
    let expected_owner_pid = match expected_owner_pid
        .to_str()
        .and_then(|value| value.parse::<libc::pid_t>().ok())
        .filter(|pid| *pid > 0)
    {
        Some(pid) => pid,
        None => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                "container-init received an invalid authenticated owner PID",
            )));
        }
    };
    let rootless = match mapping_mode.to_str() {
        Some("rootless") => true,
        Some("privileged") => false,
        _ => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                "container-init received an invalid user-mapping mode",
            )));
        }
    };
    if !device_source_directory.is_absolute() {
        return Some(Err(init_error(
            ErrorCode::InvalidArgument,
            format!(
                "container-init device-source directory must be absolute: {}",
                device_source_directory.display()
            ),
        )));
    }
    let process_io = match process_io.to_str() {
        Some(encoded) if encoded.len() <= super::MAX_INTERNAL_PROCESS_IO_BYTES => {
            match serde_json::from_str::<ProcessIo>(encoded) {
                Ok(process_io) => process_io,
                Err(error) => {
                    return Some(Err(init_error(
                        ErrorCode::InvalidArgument,
                        format!("container-init received invalid process I/O: {error}"),
                    )));
                }
            }
        }
        Some(encoded) => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                format!(
                    "container-init process I/O is {} bytes; maximum is {}",
                    encoded.len(),
                    super::MAX_INTERNAL_PROCESS_IO_BYTES
                ),
            )));
        }
        None => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                "container-init process I/O must be valid UTF-8",
            )));
        }
    };
    Some(run_container_init(ContainerInitInvocation {
        config_snapshot,
        bundle_directory,
        control_name,
        container_id,
        rootfs_scope,
        expected_owner_pid,
        rootless,
        device_source_directory,
        process_io,
    }))
}

fn run_container_init(invocation: ContainerInitInvocation) -> Result<()> {
    let ContainerInitInvocation {
        config_snapshot,
        bundle_directory,
        control_name,
        container_id,
        rootfs_scope,
        expected_owner_pid,
        rootless,
        device_source_directory,
        process_io,
    } = invocation;
    pid_supervisor::verify_and_arm_parent_death_signal(expected_owner_pid, "container launcher")?;
    let runtime_directory = config_snapshot
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            init_error(
                ErrorCode::InvalidArgument,
                "container init configuration has no runtime directory",
            )
        })?;
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
    ensure_close_on_exec(&control)?;
    let process_group = match ProcessGroupLease::open_for_snapshot_sync(&config_snapshot) {
        Ok(process_group) => process_group,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    let (plan, canonical_bundle, rootfs, rootfs_file, host_proc) = match prepare_container_init(
        config_snapshot,
        bundle_directory,
        rootfs_scope,
        &process_io,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    let expected_device_mount_count = usize::from(rootless && plan.devices.has_node_setup())
        * super::device::ROOTLESS_DEVICE_MOUNT_COUNT;
    let rootless_device_mount_descriptors =
        match receive_device_mounts(&control, expected_device_mount_count) {
            Ok(descriptors) => descriptors,
            Err(error) => return reject_before_ready(&mut control, error),
        };
    let prepared_devices = match plan.devices.prepare_sources(
        &plan.namespaces,
        &runtime_directory,
        &device_source_directory,
        rootless,
        &rootless_device_mount_descriptors,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    if let Err(error) = prepared_devices.bind_rootfs(&rootfs) {
        return reject_before_ready(&mut control, error);
    }
    let idmap_namespaces = match IdmapNamespaceHandles::prepare(
        plan.mounts.iter().filter_map(|mount| mount.idmap.as_ref()),
    ) {
        Ok(namespaces) => namespaces,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    let detached_sources =
        match DetachedMountSources::prepare(&plan.mounts, &canonical_bundle, &idmap_namespaces) {
            Ok(sources) => sources,
            Err(error) => return reject_before_ready(&mut control, error),
        };
    drop(idmap_namespaces);
    let hook_state = HookStateTemplate::new(
        plan.oci_version.clone(),
        container_id,
        plan.bundle_directory.clone(),
        plan.annotations.clone(),
    )?;
    if let Err(error) = namespace::enter_new_namespaces(&plan.namespaces, &mut control) {
        return reject_before_ready(&mut control, error);
    }
    // Entering a mapped user namespace changes the launcher's effective
    // kernel credentials. Linux clears PR_SET_PDEATHSIG on that transition,
    // so authenticate the original runtime owner and re-arm the fatal signal
    // before this process can fork either namespace init or workload code.
    if let Err(error) = pid_supervisor::verify_and_arm_parent_death_signal(
        expected_owner_pid,
        "container launcher after namespace credential transition",
    ) {
        return reject_before_ready(&mut control, error);
    }
    if plan.cgroup.uses_control_workload_layout() {
        // Creating the cgroup namespace while init is still in management
        // anchors /sys/fs/cgroup at the complete container topology. Move the
        // trusted init into control immediately afterwards; the parent will
        // enable domain controllers only after the create-hook barrier proves
        // that management is empty again.
        if let Err(error) =
            super::cgroup::join_current_process(a3s_oci_sdk::CONTROL_CGROUP_PROCS_FD)
        {
            return reject_before_ready(
                &mut control,
                init_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "move trusted init into the delegated control cgroup after namespace creation failed: {error}"
                    ),
                ),
            );
        }
    }
    let create = CreateContext {
        plan: &plan,
        bundle_directory: &canonical_bundle,
        rootfs: &rootfs,
        rootfs_file: &rootfs_file,
        prepared_devices: &prepared_devices,
        hook_state: &hook_state,
    };
    supervision::run_supervised_init(
        &create,
        &host_proc,
        detached_sources,
        control,
        process_group,
    )
}

pub(super) struct CreateContext<'a> {
    plan: &'a InitPlan,
    bundle_directory: &'a Path,
    rootfs: &'a Path,
    rootfs_file: &'a File,
    prepared_devices: &'a PreparedDeviceSources,
    hook_state: &'a HookStateTemplate,
}

pub(super) fn complete_create_and_wait_for_start(
    create: &CreateContext<'_>,
    host_proc: &File,
    mut detached_sources: DetachedMountSources,
    runtime_pid: i32,
    namespace_init_pid: Option<i32>,
    mut control: UnixStream,
) -> Result<()> {
    if let Err(error) = prepare_configured_process_group(create.plan.terminal) {
        return reject_before_ready(&mut control, error);
    }
    if let Err(error) = prepare_create_environment_before_pivot(
        create.plan,
        create.bundle_directory,
        create.rootfs,
        create.prepared_devices,
        &mut detached_sources,
    ) {
        return reject_before_ready(&mut control, error);
    }
    drop(detached_sources);
    let creating = match create.hook_state.encode(
        a3s_oci_sdk::oci_spec::runtime::ContainerState::Creating,
        Some(runtime_pid),
    ) {
        Ok(state) => state,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    write_create_hooks_ready(&mut control, runtime_pid, namespace_init_pid)?;
    if let Err(error) = wait_for_create_continue(&mut control) {
        return reject_before_ready(&mut control, error);
    }
    if let Err(error) = create
        .plan
        .hooks
        .run_sync(HookPhase::CreateContainer, &creating)
    {
        return reject_before_ready(&mut control, error);
    }
    if let Err(error) = finish_create_environment(
        create.plan,
        create.rootfs,
        create.rootfs_file,
        create.prepared_devices,
    ) {
        return reject_before_ready(&mut control, error);
    }
    write_ready(&mut control, runtime_pid, namespace_init_pid)?;
    wait_for_start_and_exec(
        create.plan,
        host_proc,
        create.rootfs_file,
        runtime_pid,
        control,
        create.hook_state,
    )
}

fn prepare_configured_process_group(terminal: bool) -> Result<()> {
    pid_supervisor::establish_process_group()?;
    super::terminal::make_foreground_process_group(terminal).map_err(|error| {
        init_error(
            ErrorCode::Internal,
            format!("make configured workload process group terminal foreground failed: {error}"),
        )
    })
}

fn wait_for_create_continue(control: &mut UnixStream) -> Result<()> {
    let mut release = [0_u8; 1];
    control.read_exact(&mut release).map_err(|error| {
        init_error(
            ErrorCode::Unavailable,
            format!("prepared create-hook barrier closed: {error}"),
        )
    })?;
    if release[0] == CREATE_CONTINUE_BYTE {
        Ok(())
    } else {
        Err(init_error(
            ErrorCode::FailedPrecondition,
            "prepared init received an invalid create-hook release byte",
        ))
    }
}

fn wait_for_start_and_exec(
    plan: &InitPlan,
    host_proc: &File,
    rootfs: &File,
    runtime_pid: i32,
    mut control: UnixStream,
    hook_state: &HookStateTemplate,
) -> Result<()> {
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
    let result =
        enter_rootfs_run_start_hooks_and_exec(plan, host_proc, rootfs, runtime_pid, hook_state);
    match result {
        Ok(()) => Ok(()),
        Err(error) => reject_before_ready(&mut control, error),
    }
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
    rootfs_scope: RootfsScope,
    process_io: &ProcessIo,
) -> Result<(InitPlan, PathBuf, PathBuf, File, File)> {
    let config_json = read_bounded_config(&config_snapshot)?;
    let bundle = OciBundle::from_json(bundle_directory, config_json)?;
    let root_path_is_absolute = bundle
        .spec()
        .root()
        .as_ref()
        .is_some_and(|root| root.path().is_absolute());
    let mut plan = InitPlan::from_bundle(&bundle, process_io)?;
    plan.namespaces
        .resolve_joined_user_mappings(plan.uid, plan.gid, &plan.additional_gids)?;
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
    if !rootfs.is_dir() {
        return Err(init_error(
            ErrorCode::InvalidArgument,
            format!("container rootfs is not a directory: {}", rootfs.display()),
        ));
    }
    let rootfs_is_in_bundle = rootfs != canonical_bundle && rootfs.starts_with(&canonical_bundle);
    if rootfs == canonical_bundle
        || (!rootfs_is_in_bundle
            && (rootfs_scope == RootfsScope::BundleOnly || !root_path_is_absolute))
    {
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

fn prepare_create_environment_before_pivot(
    plan: &InitPlan,
    bundle_directory: &Path,
    rootfs: &Path,
    prepared_devices: &PreparedDeviceSources,
    detached_sources: &mut DetachedMountSources,
) -> Result<()> {
    super::portable_rootfs_metadata::replay_if_requested(&plan.annotations, rootfs)?;
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
        mount::apply_all(&plan.mounts, bundle_directory, rootfs, detached_sources)?;
        plan.devices
            .bind_prepared_sources(rootfs, prepared_devices)?;
    }
    Ok(())
}

fn finish_create_environment(
    plan: &InitPlan,
    rootfs: &Path,
    rootfs_file: &File,
    prepared_devices: &PreparedDeviceSources,
) -> Result<()> {
    if plan.namespaces.new_mount() {
        rootfs::pivot_root(rootfs)?;
        if !DevicePlan::uses_prepared_sources(prepared_devices) {
            plan.devices.create_all()?;
        }
        rootfs::create_required_dev_symlinks(Path::new("/"))?;
        rootfs::finalize(
            plan.rootfs_propagation,
            &plan.readonly_paths,
            &plan.masked_paths,
            plan.root_readonly,
        )?;
    } else {
        // Joining another mount namespace can hide the original bundle path.
        // Keep all rootfs mutation anchored to the pre-setns descriptor that
        // will also be used by the eventual chroot.
        rootfs::create_required_dev_symlinks_from_root(rootfs_file)?;
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

fn enter_rootfs_run_start_hooks_and_exec(
    plan: &InitPlan,
    host_proc: &File,
    rootfs: &File,
    runtime_pid: i32,
    hook_state: &HookStateTemplate,
) -> Result<()> {
    if !plan.namespaces.new_mount() {
        rootfs::chroot(rootfs)?;
    }
    let created = hook_state.encode(
        a3s_oci_sdk::oci_spec::runtime::ContainerState::Created,
        Some(runtime_pid),
    )?;
    plan.hooks.run_sync(HookPhase::StartContainer, &created)?;
    exec_configured_process(plan, host_proc)
}

fn exec_configured_process(plan: &InitPlan, host_proc: &File) -> Result<()> {
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

    super::scheduler::apply(plan.scheduler.as_ref())?;
    super::io_priority::apply(plan.io_priority.as_ref())?;
    super::oom::apply(host_proc, plan.oom_score_adj)?;
    plan.rlimits.apply()?;
    plan.capabilities.prepare_for_credentials(plan.uid)?;
    namespace::apply_supplementary_groups(
        &plan.additional_gids,
        "apply init supplementary groups",
    )?;
    // SAFETY: every pointer below references a live, NUL-terminated buffer.
    // This internal init process is single-threaded and immediately replaces
    // its image after applying the validated bootstrap profile.
    unsafe {
        if libc::chdir(cwd.as_ptr()) != 0 {
            return Err(last_os_error("change to configured process.cwd"));
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

fn ensure_close_on_exec(control: &UnixStream) -> Result<()> {
    let descriptor = control.as_raw_fd();
    // SAFETY: `descriptor` is owned by the live control stream. `F_GETFD` and
    // `F_SETFD` only inspect and update its descriptor flags.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        Err(last_os_error("mark init control descriptor close-on-exec"))
    } else {
        Ok(())
    }
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

fn last_os_error(operation: &str) -> Error {
    init_error(
        ErrorCode::Internal,
        format!("{operation} failed: {}", io::Error::last_os_error()),
    )
}

fn init_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_sdk::{ErrorCode, IoMode, ProcessIo, TerminalSize};
    use tempfile::tempdir;

    use super::{prepare_container_init, RootfsScope};

    fn configuration(rootfs: &Path) -> String {
        serde_json::json!({
            "ociVersion": "1.3.0",
            "root": {
                "path": rootfs.to_str().expect("UTF-8 test rootfs"),
                "readonly": false
            },
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/true"],
                "cwd": "/",
                "noNewPrivileges": true
            }
        })
        .to_string()
    }

    fn write_configuration(directory: &Path, rootfs: &Path) -> std::path::PathBuf {
        let path = directory.join("config.json");
        std::fs::write(&path, configuration(rootfs)).expect("write test configuration");
        path
    }

    #[test]
    fn native_scope_accepts_an_explicit_absolute_rootfs_outside_the_bundle() {
        let temporary = tempdir().expect("temporary rootfs fixture");
        let bundle = temporary.path().join("sandbox/bundle");
        let rootfs = temporary.path().join("rootfs");
        std::fs::create_dir_all(&bundle).expect("bundle directory");
        std::fs::create_dir(&rootfs).expect("external rootfs directory");
        let config = write_configuration(temporary.path(), &rootfs);

        let (_, canonical_bundle, canonical_rootfs, _, _) = prepare_container_init(
            config,
            bundle.clone(),
            RootfsScope::NativeAbsolute,
            &ProcessIo::default(),
        )
        .expect("native absolute rootfs");

        assert_eq!(
            canonical_bundle,
            bundle.canonicalize().expect("canonical bundle")
        );
        assert_eq!(
            canonical_rootfs,
            rootfs.canonicalize().expect("canonical rootfs")
        );
    }

    #[test]
    fn bundle_scope_rejects_the_same_external_absolute_rootfs() {
        let temporary = tempdir().expect("temporary rootfs fixture");
        let bundle = temporary.path().join("sandbox/bundle");
        let rootfs = temporary.path().join("rootfs");
        std::fs::create_dir_all(&bundle).expect("bundle directory");
        std::fs::create_dir(&rootfs).expect("external rootfs directory");
        let config = write_configuration(temporary.path(), &rootfs);

        let error = prepare_container_init(
            config,
            bundle,
            RootfsScope::BundleOnly,
            &ProcessIo::default(),
        )
        .expect_err("guest rootfs must remain bundle-confined");

        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("escapes its guest bundle"));
    }

    #[test]
    fn native_scope_does_not_let_a_relative_symlink_escape_the_bundle() {
        let temporary = tempdir().expect("temporary rootfs fixture");
        let bundle = temporary.path().join("sandbox/bundle");
        let external = temporary.path().join("rootfs");
        std::fs::create_dir_all(&bundle).expect("bundle directory");
        std::fs::create_dir(&external).expect("external rootfs directory");
        std::os::unix::fs::symlink(&external, bundle.join("rootfs"))
            .expect("escaping rootfs symlink");
        let config = write_configuration(temporary.path(), Path::new("rootfs"));

        let error = prepare_container_init(
            config,
            bundle,
            RootfsScope::NativeAbsolute,
            &ProcessIo::default(),
        )
        .expect_err("relative rootfs must remain bundle-confined");

        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("escapes its guest bundle"));
    }

    #[test]
    fn prepared_init_reloads_terminal_bundle_with_forwarded_process_io() {
        let temporary = tempdir().expect("temporary rootfs fixture");
        let bundle = temporary.path().join("sandbox/bundle");
        let rootfs = temporary.path().join("rootfs");
        std::fs::create_dir_all(&bundle).expect("bundle directory");
        std::fs::create_dir(&rootfs).expect("external rootfs directory");
        let mut config: serde_json::Value =
            serde_json::from_str(&configuration(&rootfs)).expect("decode configuration");
        config["process"]["terminal"] = serde_json::Value::Bool(true);
        let config_path = temporary.path().join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("encode terminal configuration"),
        )
        .expect("write terminal configuration");
        let terminal_io = ProcessIo {
            stdin: IoMode::Terminal,
            stdout: IoMode::Terminal,
            stderr: IoMode::Terminal,
            terminal_size: Some(TerminalSize {
                width: 120,
                height: 40,
            }),
        };

        let (plan, _, _, _, _) = prepare_container_init(
            config_path,
            bundle,
            RootfsScope::NativeAbsolute,
            &terminal_io,
        )
        .expect("prepared terminal init");

        assert!(plan.terminal);
    }
}
