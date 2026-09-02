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

use super::bundle_scope::{PinnedBundleDirectory, PinnedRootfsDirectory};
use super::control::{
    receive_device_mounts, write_capability_warnings, write_create_hooks_ready, write_ready,
    write_rejection, CREATE_CONTINUE_BYTE, START_BYTE,
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
    pinned_bundle: Option<PinnedBundleDirectory>,
    pinned_rootfs: Option<File>,
    expected_owner_pid: libc::pid_t,
    rootless: bool,
    device_source_directory: PathBuf,
    vm_storage_sources: crate::vm_attachment::UtilityVmStorageSources,
    process_io: ProcessIo,
}

#[derive(Debug)]
struct PreparedContainerRootfs {
    access_path: PathBuf,
    descriptor_mountpoint: Option<PathBuf>,
    file: File,
}

impl PreparedContainerRootfs {
    fn access_path(&self) -> &Path {
        &self.access_path
    }

    fn descriptor_mountpoint(&self) -> Option<&Path> {
        self.descriptor_mountpoint.as_deref()
    }

    const fn file(&self) -> &File {
        &self.file
    }
}

fn uses_private_joined_rootfs(plan: &InitPlan) -> bool {
    plan.namespaces.joined_mount().is_some() && plan.devices.has_node_setup()
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
    let bundle_access = arguments.next();
    let expected_owner_pid = arguments.next();
    let mapping_mode = arguments.next();
    let device_source_directory = arguments.next().map(PathBuf::from);
    let vm_storage_sources = arguments.next();
    let process_io = arguments.next();
    let extra = arguments.next();
    let (
        Some(config_snapshot),
        Some(bundle_directory),
        Some(control_name),
        Some(container_id),
        Some(rootfs_scope),
        Some(bundle_access),
        Some(expected_owner_pid),
        Some(mapping_mode),
        Some(device_source_directory),
        Some(vm_storage_sources),
        Some(process_io),
        None,
    ) = (
        config_snapshot,
        bundle_directory,
        control_name,
        container_id,
        rootfs_scope,
        bundle_access,
        expected_owner_pid,
        mapping_mode,
        device_source_directory,
        vm_storage_sources,
        process_io,
        extra,
    )
    else {
        return Some(Err(init_error(
            ErrorCode::InvalidArgument,
            "container-init requires CONFIG BUNDLE CONTROL ID ROOTFS_SCOPE BUNDLE_ACCESS OWNER_PID MAPPING_MODE DEVICE_SOURCE_DIRECTORY VM_STORAGE_SOURCES PROCESS_IO and no extra arguments",
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
    let (pinned_bundle, pinned_rootfs) = match bundle_access.to_str() {
        Some("bundle-path") => (None, None),
        Some("pinned-bundle-fd") if rootfs_scope == RootfsScope::BundleOnly => {
            let bundle = match PinnedBundleDirectory::take_from_child() {
                Ok(bundle) => bundle,
                Err(error) => return Some(Err(error)),
            };
            let rootfs = match PinnedRootfsDirectory::take_from_child() {
                Ok(rootfs) => rootfs,
                Err(error) => return Some(Err(error)),
            };
            (Some(bundle), Some(rootfs))
        }
        _ => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                "container-init received an invalid bundle-access mode",
            )));
        }
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
    let vm_storage_sources = match vm_storage_sources.to_str() {
        Some(encoded) => match crate::vm_attachment::UtilityVmStorageSources::from_json(encoded) {
            Ok(sources) => sources,
            Err(error) => return Some(Err(error)),
        },
        None => {
            return Some(Err(init_error(
                ErrorCode::InvalidArgument,
                "container-init VM storage sources must be valid UTF-8",
            )));
        }
    };
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
        pinned_bundle,
        pinned_rootfs,
        expected_owner_pid,
        rootless,
        device_source_directory,
        vm_storage_sources,
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
        pinned_bundle,
        pinned_rootfs,
        expected_owner_pid,
        rootless,
        device_source_directory,
        vm_storage_sources,
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
    let (plan, canonical_bundle, mut rootfs, host_proc) = match prepare_container_init(
        config_snapshot,
        bundle_directory,
        rootfs_scope,
        pinned_bundle.as_ref(),
        pinned_rootfs,
        &vm_storage_sources,
        &process_io,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    let source_resolver = mount::BindSourceResolver::new(&canonical_bundle, pinned_bundle.as_ref());
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
    if let Err(error) = prepared_devices.bind_rootfs(rootfs.access_path()) {
        return reject_before_ready(&mut control, error);
    }
    if uses_private_joined_rootfs(&plan) {
        rootfs.file = match plan.devices.prepare_detached_joined_rootfs(
            rootfs.access_path(),
            rootfs.file(),
            &runtime_directory,
            &prepared_devices,
        ) {
            Ok(rootfs) => rootfs,
            Err(error) => return reject_before_ready(&mut control, error),
        };
    }
    let idmap_namespaces = match IdmapNamespaceHandles::prepare(
        plan.mounts.iter().filter_map(|mount| mount.idmap.as_ref()),
    ) {
        Ok(namespaces) => namespaces,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    let mut detached_sources =
        match DetachedMountSources::prepare(&plan.mounts, &source_resolver, idmap_namespaces) {
            Ok(sources) => sources,
            Err(error) => return reject_before_ready(&mut control, error),
        };
    if plan
        .mounts
        .iter()
        .any(|mount| mount.ordered_source.is_some() && mount.idmap.is_some())
    {
        let ordered_idmap_control = match control.try_clone() {
            Ok(control) => control,
            Err(error) => {
                return reject_before_ready(
                    &mut control,
                    init_error(
                        ErrorCode::Internal,
                        format!(
                            "failed to retain ordered ID-mapped mount control channel: {error}"
                        ),
                    ),
                );
            }
        };
        if let Err(error) = detached_sources.set_ordered_idmap_control(ordered_idmap_control) {
            return reject_before_ready(&mut control, error);
        }
    }
    let hook_state = HookStateTemplate::new(
        plan.oci_version.clone(),
        container_id,
        plan.bundle_directory.clone(),
        plan.annotations.clone(),
    )?;
    let mut namespace_isolation = plan.sysctls.namespace_isolation();
    if !plan.network_devices.is_empty() {
        namespace_isolation.require(a3s_oci_sdk::OciLinuxSysctlNamespace::Network);
    }
    if let Err(error) =
        namespace::enter_new_namespaces(&plan.namespaces, &namespace_isolation, &mut control)
    {
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
        source_resolver: &source_resolver,
        rootfs: &rootfs,
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
    source_resolver: &'a mount::BindSourceResolver<'a>,
    rootfs: &'a PreparedContainerRootfs,
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
    let prepared_rootfs_mount = match prepare_create_environment_before_pivot(
        create.plan,
        create.rootfs,
        create.prepared_devices,
        &mut detached_sources,
        create.source_resolver,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return reject_before_ready(&mut control, error),
    };
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
    let effective_rootfs = prepared_rootfs_mount.as_ref().map_or_else(
        || create.rootfs.access_path(),
        rootfs::PreparedRootfsMount::path,
    );
    let applied_sysctls = match finish_create_environment(
        create.plan,
        effective_rootfs,
        create.rootfs.file(),
        create.prepared_devices,
        host_proc,
    ) {
        Ok(applied) => applied,
        Err(error) => return reject_before_ready(&mut control, error),
    };
    if let Err(error) = write_ready(&mut control, runtime_pid, namespace_init_pid) {
        return reject_before_ready(&mut control, applied_sysctls.rollback_after(error));
    }
    applied_sysctls.commit();
    wait_for_start_and_exec(
        create.plan,
        host_proc,
        create.rootfs.file(),
        runtime_pid,
        control,
        create.hook_state,
    )
}

fn prepare_configured_process_group(terminal: bool) -> Result<()> {
    if terminal {
        pid_supervisor::establish_process_group()?;
    } else {
        pid_supervisor::establish_process_session()?;
    }
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
    let result = enter_rootfs_run_start_hooks_and_exec(
        plan,
        host_proc,
        rootfs,
        runtime_pid,
        hook_state,
        &mut control,
    );
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
    pinned_bundle: Option<&PinnedBundleDirectory>,
    pinned_rootfs: Option<File>,
    vm_storage_sources: &crate::vm_attachment::UtilityVmStorageSources,
    process_io: &ProcessIo,
) -> Result<(InitPlan, PathBuf, PreparedContainerRootfs, File)> {
    let config_json = read_bounded_config(&config_snapshot)?;
    let bundle = OciBundle::from_json(bundle_directory, config_json)?;
    let root_path_is_absolute = bundle
        .spec()
        .root()
        .as_ref()
        .is_some_and(|root| root.path().is_absolute());
    let mut plan = InitPlan::from_bundle(&bundle, process_io)?;
    mount::rewrite_vm_storage_sources(&mut plan.mounts, vm_storage_sources)?;
    plan.resolve_joined_user_namespace()?;
    let canonical_bundle = if pinned_bundle.is_some() {
        plan.bundle_directory.clone()
    } else {
        plan.bundle_directory.canonicalize().map_err(|error| {
            init_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to resolve guest bundle {}: {error}",
                    plan.bundle_directory.display()
                ),
            )
        })?
    };
    if pinned_bundle.is_none() {
        mount::validate_bundle_scoped_sources(&plan.mounts, &canonical_bundle, rootfs_scope)?;
    }
    let pinned_rootfs = if let Some(bundle) = pinned_bundle {
        let relative = plan
            .rootfs
            .strip_prefix(&plan.bundle_directory)
            .map_err(|_| {
                init_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "container rootfs must be relative to its descriptor-pinned utility-VM bundle: {}",
                        plan.rootfs.display()
                    ),
                )
            })?;
        let inherited = pinned_rootfs.ok_or_else(|| {
            init_error(
                ErrorCode::PermissionDenied,
                "container-init did not receive its descriptor-pinned utility-VM rootfs",
            )
        })?;
        let current = bundle
            .open_rootfs(relative, "run-container-init")?
            .ok_or_else(|| {
                init_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "descriptor-pinned container rootfs no longer occupies its bundle entry: {}",
                        plan.rootfs.display()
                    ),
                )
            })?;
        let inherited_metadata = inherited.metadata().map_err(|error| {
            init_error(
                ErrorCode::FailedPrecondition,
                format!("failed to inspect inherited container rootfs: {error}"),
            )
        })?;
        let current_metadata = current.metadata().map_err(|error| {
            init_error(
                ErrorCode::FailedPrecondition,
                format!("failed to inspect current container rootfs entry: {error}"),
            )
        })?;
        use std::os::unix::fs::MetadataExt;
        if inherited_metadata.dev() != current_metadata.dev()
            || inherited_metadata.ino() != current_metadata.ino()
        {
            return Err(init_error(
                ErrorCode::PermissionDenied,
                format!(
                    "container rootfs changed after descriptor-confined validation: {}",
                    plan.rootfs.display()
                ),
            ));
        }
        Some(inherited)
    } else {
        if pinned_rootfs.is_some() {
            return Err(init_error(
                ErrorCode::PermissionDenied,
                "container-init received a rootfs descriptor without bundle authority",
            ));
        }
        None
    };
    let descriptor_mountpoint = pinned_rootfs.as_ref().map(|_| plan.rootfs.clone());
    let rootfs = if let Some(rootfs) = pinned_rootfs.as_ref() {
        PathBuf::from(format!("/proc/self/fd/{}", rootfs.as_raw_fd()))
    } else {
        plan.rootfs.canonicalize().map_err(|error| {
            init_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to resolve container rootfs {}: {error}",
                    plan.rootfs.display()
                ),
            )
        })?
    };
    if !rootfs.is_dir() {
        return Err(init_error(
            ErrorCode::InvalidArgument,
            format!("container rootfs is not a directory: {}", rootfs.display()),
        ));
    }
    if pinned_bundle.is_none() {
        let rootfs_is_in_bundle = rootfs.starts_with(&canonical_bundle);
        if !rootfs_is_in_bundle
            && (rootfs_scope == RootfsScope::BundleOnly || !root_path_is_absolute)
        {
            return Err(init_error(
                ErrorCode::PermissionDenied,
                format!(
                    "container rootfs escapes its guest bundle: {}",
                    rootfs.display()
                ),
            ));
        }
    }
    let rootfs_file = match pinned_rootfs {
        Some(rootfs) => rootfs,
        None => File::open(&rootfs).map_err(|error| {
            init_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to retain the container rootfs {} before namespace entry: {error}",
                    rootfs.display()
                ),
            )
        })?,
    };
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
    Ok((
        plan,
        canonical_bundle,
        PreparedContainerRootfs {
            access_path: rootfs,
            descriptor_mountpoint,
            file: rootfs_file,
        },
        host_proc,
    ))
}

fn prepare_create_environment_before_pivot(
    plan: &InitPlan,
    rootfs: &PreparedContainerRootfs,
    prepared_devices: &PreparedDeviceSources,
    detached_sources: &mut DetachedMountSources,
    source_resolver: &mount::BindSourceResolver<'_>,
) -> Result<Option<rootfs::PreparedRootfsMount>> {
    super::portable_rootfs_metadata::replay_if_requested(&plan.annotations, rootfs.access_path())?;
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
        plan.devices.validate_rootfs(rootfs.access_path())?;
        let prepared_rootfs = match rootfs.descriptor_mountpoint() {
            Some(mountpoint) => rootfs::prepare_descriptor_pinned_pivot(
                mountpoint,
                rootfs.file(),
                plan.rootfs_propagation,
            )?,
            None => rootfs::prepare_pivot(rootfs.access_path(), plan.rootfs_propagation)?,
        };
        let effective_rootfs = prepared_rootfs.path();
        plan.default_filesystems.apply_early(
            effective_rootfs,
            detached_sources,
            source_resolver,
        )?;
        mount::apply_all(
            &plan.mounts,
            effective_rootfs,
            detached_sources,
            source_resolver,
        )?;
        plan.default_filesystems
            .apply_late(effective_rootfs, detached_sources, source_resolver)?;
        plan.devices
            .bind_prepared_sources(effective_rootfs, prepared_devices)?;
        Ok(Some(prepared_rootfs))
    } else {
        Ok(None)
    }
}

fn finish_create_environment<'a>(
    plan: &InitPlan,
    rootfs: &Path,
    rootfs_file: &File,
    prepared_devices: &PreparedDeviceSources,
    host_proc: &'a File,
) -> Result<super::sysctl::AppliedSysctls<'a>> {
    if plan.namespaces.new_mount() {
        rootfs::pivot_root(rootfs)?;
        if !DevicePlan::uses_prepared_sources(prepared_devices) {
            plan.devices.create_all()?;
        }
        plan.devices.finish_rootfs_devices()?;
        rootfs::create_required_dev_symlinks(Path::new("/"))?;
        rootfs::finalize(
            plan.rootfs_propagation,
            &plan.readonly_paths,
            &plan.masked_paths,
            plan.root_readonly,
        )?;
    } else if uses_private_joined_rootfs(plan) {
        plan.devices.verify_existing_from_root(rootfs_file)?;
        rootfs::create_required_dev_symlinks_from_root(rootfs_file)?;
        rootfs::chroot(rootfs_file)?;
    } else {
        plan.devices.verify_existing_from_root(rootfs_file)?;
        // Joining another mount namespace can hide the original bundle path.
        // Keep all rootfs mutation anchored to the pre-setns descriptor that
        // will also be used by the eventual chroot.
        rootfs::create_required_dev_symlinks_from_root(rootfs_file)?;
    }
    plan.sysctls.apply(host_proc)
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
    control: &mut UnixStream,
) -> Result<()> {
    if !plan.namespaces.new_mount() && !uses_private_joined_rootfs(plan) {
        rootfs::chroot(rootfs)?;
    }
    let created = hook_state.encode(
        a3s_oci_sdk::oci_spec::runtime::ContainerState::Created,
        Some(runtime_pid),
    )?;
    plan.hooks.run_sync(HookPhase::StartContainer, &created)?;
    exec_configured_process(plan, host_proc, control)
}

fn exec_configured_process(
    plan: &InitPlan,
    host_proc: &File,
    control: &mut UnixStream,
) -> Result<()> {
    let cwd = CString::new(plan.cwd.as_bytes()).map_err(|error| {
        init_error(
            ErrorCode::InvalidArgument,
            format!("process.cwd contains a NUL byte: {error}"),
        )
    })?;
    let args = cstring_vector(&plan.args, "process.args")?;
    let mut process_environment = plan.environment.clone();
    super::secret_env::materialize(&mut process_environment)?;
    let environment = cstring_vector(&process_environment, "process.env")?;
    if args.is_empty() {
        return Err(init_error(
            ErrorCode::InvalidArgument,
            "process.args must contain an executable",
        ));
    }

    super::scheduler::apply(plan.scheduler.as_ref())?;
    super::io_priority::apply(plan.io_priority.as_ref())?;
    super::oom::apply(host_proc, plan.oom_score_adj)?;
    super::personality::apply(plan.personality.as_ref())?;
    super::memory_policy::apply(plan.memory_policy.as_ref())?;
    plan.rlimits.apply()?;
    let capabilities = plan.capabilities.prepare_for_credentials(plan.uid)?;
    write_capability_warnings(control, capabilities.warnings())?;
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
    capabilities.apply_after_credentials(plan.uid)?;
    super::no_new_privileges::apply(plan.no_new_privileges)?;
    plan.seccomp.install()?;
    let error = super::process_executable::execute(&args, &environment);
    Err(init_error(
        ErrorCode::Internal,
        format!("execute configured init process failed: {error}"),
    ))
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
mod tests;
