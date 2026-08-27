use std::ffi::c_char;
use std::fs::{self, File};
use std::io::Read;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_LOCAL, RTLD_NOW};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ffi::{path_to_cstring, value_to_cstring, FfiStringArray};
use crate::linux_kvm_device::LinuxKvmDevice;
use crate::linux_runtime_share::LinuxRuntimeShare;
use crate::linux_system_image::LinuxSystemImage;
use crate::runtime_assets::{
    runtime_bundle, RuntimeBundle, RuntimeFile, RuntimeFileRole, RuntimeKernel,
};
use crate::VmConfig;

const KRUN_DISK_FORMAT_RAW: u32 = 0;
const SYSTEM_DISK_ID: &str = "a3s-oci-system";
const ROOT_DISK_DEVICE: &str = "/dev/vda";
const ROOT_DISK_FILESYSTEM: &str = "ext4";
const ROOT_DISK_OPTIONS: &str = "ro";

type KrunCreateCtx = unsafe extern "C" fn() -> i32;
type KrunFreeCtx = unsafe extern "C" fn(u32) -> i32;
type KrunSetVmConfig = unsafe extern "C" fn(u32, u8, u32) -> i32;
type KrunDisableImplicitVsock = unsafe extern "C" fn(u32) -> i32;
type KrunAddVsock = unsafe extern "C" fn(u32, u32) -> i32;
type KrunAddVsockPort = unsafe extern "C" fn(u32, u32, *const c_char, bool) -> i32;
type KrunAddDisk = unsafe extern "C" fn(u32, *const c_char, *const c_char, u32, bool) -> i32;
type KrunSetRootDiskRemount =
    unsafe extern "C" fn(u32, *const c_char, *const c_char, *const c_char) -> i32;
type KrunAddVirtiofs = unsafe extern "C" fn(u32, *const c_char, *const c_char) -> i32;
type KrunAddNetTap = unsafe extern "C" fn(u32, *const c_char, *const u8, u32, u32) -> i32;
type KrunSetWorkdir = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunSetExec =
    unsafe extern "C" fn(u32, *const c_char, *const *const c_char, *const *const c_char) -> i32;
type KrunSetConsoleOutput = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunStartEnter = unsafe extern "C" fn(u32) -> i32;
type KrunfwGetKernel = unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *const c_char;

/// Exact process-local Linux API loaded from the selected runtime bundle.
pub(crate) struct LinuxKrunApi {
    create_ctx: KrunCreateCtx,
    free_ctx: KrunFreeCtx,
    set_vm_config: KrunSetVmConfig,
    disable_implicit_vsock: KrunDisableImplicitVsock,
    add_vsock: KrunAddVsock,
    add_vsock_port: KrunAddVsockPort,
    add_disk: KrunAddDisk,
    set_root_disk_remount: KrunSetRootDiskRemount,
    add_virtiofs: KrunAddVirtiofs,
    add_net_tap: Option<KrunAddNetTap>,
    set_workdir: KrunSetWorkdir,
    set_exec: KrunSetExec,
    set_console_output: KrunSetConsoleOutput,
    start_enter: KrunStartEnter,
    get_kernel: KrunfwGetKernel,
    runtime_dir: PathBuf,
    bundle: &'static RuntimeBundle,
    kernel_sha256: String,
    // Drop libkrun before its global firmware provider.
    _krun: Library,
    _firmware: Library,
}

impl LinuxKrunApi {
    pub(crate) fn load() -> Result<Self> {
        let bundle = runtime_bundle("linux", std::env::consts::ARCH)
            .map_err(|error| {
                runtime_error(
                    "resolve-linux-libkrun-runtime",
                    format!("checked-in runtime asset manifest is invalid: {error}"),
                )
            })?
            .ok_or_else(|| {
                runtime_error(
                    "resolve-linux-libkrun-runtime",
                    format!(
                        "no pinned Linux libkrun runtime exists for architecture {}",
                        std::env::consts::ARCH
                    ),
                )
            })?;
        let runtime_dir = resolve_runtime_dir(bundle)?;
        let firmware_file = required_file(bundle, RuntimeFileRole::Firmware)?;
        let krun_file = required_file(bundle, RuntimeFileRole::Library)?;
        let firmware_path = runtime_dir.join(&firmware_file.name);
        let krun_path = runtime_dir.join(&krun_file.name);

        // SAFETY: both absolute paths name checksum-verified regular files.
        // RTLD_GLOBAL makes the firmware's fixed SONAME available while the
        // selected libkrun object resolves its dependency.
        let firmware =
            unsafe { Library::open(Some(firmware_path.as_os_str()), RTLD_NOW | RTLD_GLOBAL) }
                .map_err(|error| {
                    runtime_error(
                        "load-linux-libkrunfw",
                        format!(
                            "failed to load checksum-verified firmware {}: {error}",
                            firmware_path.display()
                        ),
                    )
                })?;

        // SAFETY: the exact runtime-owned libkrun object was verified above
        // and stays loaded for the lifetime of every copied function pointer.
        let krun = unsafe { Library::open(Some(krun_path.as_os_str()), RTLD_NOW | RTLD_LOCAL) }
            .map_err(|error| {
                runtime_error(
                    "load-linux-libkrun",
                    format!(
                        "failed to load checksum-verified libkrun {}: {error}",
                        krun_path.display()
                    ),
                )
            })?;

        let get_kernel = load_symbol(&firmware, b"krunfw_get_kernel\0", "krunfw_get_kernel")?;
        let kernel_sha256 = verify_exported_kernel(get_kernel, &bundle.kernel)?;
        let api = Self {
            create_ctx: load_symbol(&krun, b"krun_create_ctx\0", "krun_create_ctx")?,
            free_ctx: load_symbol(&krun, b"krun_free_ctx\0", "krun_free_ctx")?,
            set_vm_config: load_symbol(&krun, b"krun_set_vm_config\0", "krun_set_vm_config")?,
            disable_implicit_vsock: load_symbol(
                &krun,
                b"krun_disable_implicit_vsock\0",
                "krun_disable_implicit_vsock",
            )?,
            add_vsock: load_symbol(&krun, b"krun_add_vsock\0", "krun_add_vsock")?,
            add_vsock_port: load_symbol(&krun, b"krun_add_vsock_port2\0", "krun_add_vsock_port2")?,
            add_disk: load_symbol(&krun, b"krun_add_disk2\0", "krun_add_disk2")?,
            set_root_disk_remount: load_symbol(
                &krun,
                b"krun_set_root_disk_remount\0",
                "krun_set_root_disk_remount",
            )?,
            add_virtiofs: load_symbol(&krun, b"krun_add_virtiofs\0", "krun_add_virtiofs")?,
            add_net_tap: load_optional_symbol(&krun, b"krun_add_net_tap\0"),
            set_workdir: load_symbol(&krun, b"krun_set_workdir\0", "krun_set_workdir")?,
            set_exec: load_symbol(&krun, b"krun_set_exec\0", "krun_set_exec")?,
            set_console_output: load_symbol(
                &krun,
                b"krun_set_console_output\0",
                "krun_set_console_output",
            )?,
            start_enter: load_symbol(&krun, b"krun_start_enter\0", "krun_start_enter")?,
            get_kernel,
            runtime_dir,
            bundle,
            kernel_sha256,
            _krun: krun,
            _firmware: firmware,
        };
        api.reverify_runtime()?;
        Ok(api)
    }

    pub(crate) fn runtime_bundle(&self) -> &'static RuntimeBundle {
        self.bundle
    }

    fn reverify_runtime(&self) -> Result<()> {
        verify_runtime_dir(&self.runtime_dir, self.bundle)?;
        let kernel_sha256 = verify_exported_kernel(self.get_kernel, &self.bundle.kernel)?;
        if kernel_sha256 != self.kernel_sha256 {
            return Err(runtime_error(
                "reverify-linux-libkrun-runtime",
                "loaded Linux firmware kernel identity changed after loading".to_string(),
            ));
        }
        Ok(())
    }
}

/// Single-threaded owner of one Linux libkrun configuration context.
pub(crate) struct KrunContext {
    id: Option<u32>,
    api: LinuxKrunApi,
    system_image: Option<LinuxSystemImage>,
    runtime_share: Option<LinuxRuntimeShare>,
    network_taps: Vec<String>,
    not_thread_safe: PhantomData<Rc<()>>,
}

impl KrunContext {
    pub(crate) fn create(api: LinuxKrunApi) -> Result<Self> {
        api.reverify_runtime()?;
        // SAFETY: the function pointer was resolved from the pinned libkrun
        // object and accepts no arguments.
        let status = unsafe { (api.create_ctx)() };
        let id = u32::try_from(status).map_err(|_| {
            ffi_error(
                "krun_create_ctx",
                status,
                "failed to allocate a Linux libkrun configuration context",
            )
        })?;

        Ok(Self {
            id: Some(id),
            api,
            system_image: None,
            runtime_share: None,
            network_taps: Vec::new(),
            not_thread_safe: PhantomData,
        })
    }

    pub(crate) fn set_read_only_system_image(
        &mut self,
        system_image: LinuxSystemImage,
    ) -> Result<()> {
        let id = self.active_id("configure-linux-kvm-system-image")?;
        if self.system_image.is_some() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "Linux KVM system image has already been configured",
            )
            .for_operation("configure-linux-kvm-system-image"));
        }
        self.api.reverify_runtime()?;
        system_image.reverify(self.api.runtime_bundle())?;

        let disk_id = value_to_cstring("krun_add_disk2", "block identifier", SYSTEM_DISK_ID)?;
        let image_path = system_image.pinned_image_path();
        let image_path = path_to_cstring("krun_add_disk2", &image_path)?;
        // SAFETY: the retained descriptor keeps the verified raw image alive,
        // all strings remain valid for the call, and read-only is explicit.
        let status = unsafe {
            (self.api.add_disk)(
                id,
                disk_id.as_ptr(),
                image_path.as_ptr(),
                KRUN_DISK_FORMAT_RAW,
                true,
            )
        };
        check_status(
            "krun_add_disk2",
            status,
            "failed to attach the immutable Linux KVM system image read-only",
        )?;

        let device = value_to_cstring(
            "krun_set_root_disk_remount",
            "root disk device",
            ROOT_DISK_DEVICE,
        )?;
        let filesystem = value_to_cstring(
            "krun_set_root_disk_remount",
            "root disk filesystem",
            ROOT_DISK_FILESYSTEM,
        )?;
        let options = value_to_cstring(
            "krun_set_root_disk_remount",
            "root disk mount options",
            ROOT_DISK_OPTIONS,
        )?;
        // SAFETY: the exact block disk was configured above and all fixed
        // strings remain NUL-terminated for this call.
        let status = unsafe {
            (self.api.set_root_disk_remount)(
                id,
                device.as_ptr(),
                filesystem.as_ptr(),
                options.as_ptr(),
            )
        };
        check_status(
            "krun_set_root_disk_remount",
            status,
            "failed to select the immutable ext4 root disk read-only",
        )?;
        self.system_image = Some(system_image);
        Ok(())
    }

    pub(crate) fn set_vm_config(&mut self, config: VmConfig) -> Result<()> {
        let id = self.active_id("krun_set_vm_config")?;
        // SAFETY: this context exclusively owns the ID, and VmConfig has
        // validated both scalar resource values.
        let status = unsafe { (self.api.set_vm_config)(id, config.vcpus(), config.memory_mib()) };
        check_status(
            "krun_set_vm_config",
            status,
            "failed to configure Linux libkrun VM resources",
        )
    }

    pub(crate) fn add_runtime_share(
        &mut self,
        tag: &str,
        runtime_share: LinuxRuntimeShare,
    ) -> Result<()> {
        let id = self.active_id("krun_add_virtiofs")?;
        if self.runtime_share.is_some() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "Linux KVM runtime share has already been configured",
            )
            .for_operation("krun_add_virtiofs"));
        }
        self.api.reverify_runtime()?;
        runtime_share.reverify()?;
        let tag = value_to_cstring("krun_add_virtiofs", "virtio-fs tag", tag)?;
        let pinned_path = runtime_share.pinned_path();
        let pinned_path = path_to_cstring("krun_add_virtiofs", &pinned_path)?;
        // SAFETY: the context is exclusively owned and the descriptor-pinned
        // share plus both C strings remain live through the complete call.
        let status = unsafe { (self.api.add_virtiofs)(id, tag.as_ptr(), pinned_path.as_ptr()) };
        check_status(
            "krun_add_virtiofs",
            status,
            "failed to attach the protected Linux KVM runtime share",
        )?;
        self.runtime_share = Some(runtime_share);
        Ok(())
    }

    pub(crate) fn set_agent_vsock(&mut self, socket_path: &Path, port: u32) -> Result<()> {
        let id = self.active_id("configure-agent-vsock")?;
        let socket_path = path_to_cstring("krun_add_vsock_port2", socket_path)?;

        // SAFETY: the live context is exclusively owned. Removing the
        // implicit device prevents libkrun's TSI policy from changing the
        // explicitly requested plain-vsock boundary.
        let status = unsafe { (self.api.disable_implicit_vsock)(id) };
        check_status(
            "krun_disable_implicit_vsock",
            status,
            "failed to disable the implicit Linux libkrun vsock device",
        )?;

        // SAFETY: the same live context remains exclusively owned, and a zero
        // feature mask requests a plain AF_VSOCK device without TSI hijacking.
        let status = unsafe { (self.api.add_vsock)(id, 0) };
        check_status(
            "krun_add_vsock",
            status,
            "failed to configure a plain Linux agent vsock device",
        )?;

        // SAFETY: the path is a live NUL-terminated string for this call.
        // `listen = false` records a guest-to-existing-host-socket mapping;
        // context configuration does not connect to the path.
        let status = unsafe { (self.api.add_vsock_port)(id, port, socket_path.as_ptr(), false) };
        check_status(
            "krun_add_vsock_port2",
            status,
            "failed to map the guest agent port to a Linux Unix socket",
        )
    }

    pub(crate) fn add_network_tap(&mut self, tap_name: &str, mac_address: &[u8; 6]) -> Result<()> {
        let id = self.active_id("krun_add_net_tap")?;
        if self.network_taps.iter().any(|known| known == tap_name) {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!("Linux KVM TAP {tap_name} has already been configured"),
            )
            .for_operation("krun_add_net_tap"));
        }
        let add_net_tap = self.api.add_net_tap.ok_or_else(|| {
            Error::new(
                ErrorCode::Unsupported,
                "the pinned Linux libkrun runtime does not export krun_add_net_tap",
            )
            .for_operation("krun_add_net_tap")
        })?;
        self.api.reverify_runtime()?;
        let retained_tap_name = tap_name.to_string();
        let tap_name = value_to_cstring("krun_add_net_tap", "TAP name", tap_name)?;
        // SAFETY: the live context is exclusively owned, both pointers remain
        // valid for the complete call, the MAC is exactly six bytes, and the
        // pinned TAP backend supports neither optional features nor flags.
        let status = unsafe { add_net_tap(id, tap_name.as_ptr(), mac_address.as_ptr(), 0, 0) };
        check_status(
            "krun_add_net_tap",
            status,
            "failed to attach an authorized TAP to the Linux KVM guest",
        )?;
        self.network_taps.push(retained_tap_name);
        Ok(())
    }

    pub(crate) fn set_workdir(&mut self, workdir: &str) -> Result<()> {
        let id = self.active_id("krun_set_workdir")?;
        let workdir = value_to_cstring("krun_set_workdir", "working directory", workdir)?;
        // SAFETY: the context remains exclusively owned and the C string is
        // retained for the duration of the call.
        let status = unsafe { (self.api.set_workdir)(id, workdir.as_ptr()) };
        check_status(
            "krun_set_workdir",
            status,
            "failed to configure the Linux KVM guest working directory",
        )
    }

    pub(crate) fn set_exec(
        &mut self,
        executable: &str,
        arguments: &[String],
        environment: &[(String, String)],
    ) -> Result<()> {
        let id = self.active_id("krun_set_exec")?;
        let executable = value_to_cstring("krun_set_exec", "executable", executable)?;
        let arguments = FfiStringArray::new("krun_set_exec", "arguments", arguments)?;
        let environment_entries = Zeroizing::new(
            environment
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>(),
        );
        let environment =
            FfiStringArray::new("krun_set_exec", "environment", &environment_entries)?;

        // SAFETY: the context is exclusively owned. All pointers refer to
        // live allocations and both pointer tables have libkrun's fixed size.
        let status = unsafe {
            (self.api.set_exec)(
                id,
                executable.as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
            )
        };
        check_status(
            "krun_set_exec",
            status,
            "failed to configure the Linux KVM guest agent",
        )
    }

    pub(crate) fn set_console_output(&mut self, output: &Path) -> Result<()> {
        let id = self.active_id("krun_set_console_output")?;
        let output = path_to_cstring("krun_set_console_output", output)?;
        // SAFETY: the context remains exclusively owned and the C string is
        // retained for the duration of the call.
        let status = unsafe { (self.api.set_console_output)(id, output.as_ptr()) };
        check_status(
            "krun_set_console_output",
            status,
            "failed to configure Linux KVM console output",
        )
    }

    /// Revalidate every retained non-KVM entry asset without entering a VM.
    ///
    /// The worker calls this before opening `/dev/kvm`; `start_enter` repeats
    /// the same checks after the device has been pinned and verified.
    pub(crate) fn reverify_entry_assets(&self) -> Result<()> {
        self.api.reverify_runtime()?;
        let system_image = self.system_image.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "Linux KVM VM entry requires a manifest-bound immutable system image",
            )
            .for_operation("reverify-linux-kvm-entry-assets")
        })?;
        system_image.reverify(self.api.runtime_bundle())?;
        let runtime_share = self.runtime_share.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "Linux KVM VM entry requires one protected per-generation runtime share",
            )
            .for_operation("reverify-linux-kvm-entry-assets")
        })?;
        runtime_share.reverify()
    }

    pub(crate) fn start_enter(mut self, kvm_device: &LinuxKvmDevice) -> Result<i32> {
        kvm_device.reverify()?;
        self.reverify_entry_assets()?;
        let id = self.id.take().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "libkrun context has already been released",
            )
            .for_operation("krun_start_enter")
        })?;

        // SAFETY: the live context is exclusively owned. libkrun consumes it
        // before VM construction and returns either a guest status or a
        // negative errno-style entry failure.
        let status = unsafe { (self.api.start_enter)(id) };
        if status < 0 {
            Err(ffi_error(
                "krun_start_enter",
                status,
                "failed to enter the Linux KVM utility VM",
            ))
        } else {
            Ok(status)
        }
    }

    pub(crate) fn close(mut self) -> Result<()> {
        let Some(id) = self.id.take() else {
            return Ok(());
        };
        // SAFETY: the live context ID remains exclusively owned. Restore
        // cleanup ownership on failure so Drop makes one final release attempt.
        let status = unsafe { (self.api.free_ctx)(id) };
        if let Err(error) = check_status(
            "krun_free_ctx",
            status,
            "failed to release the Linux libkrun configuration context",
        ) {
            self.id = Some(id);
            return Err(error);
        }
        Ok(())
    }

    fn active_id(&self, operation: &'static str) -> Result<u32> {
        self.id.ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "libkrun context has already been released",
            )
            .for_operation(operation)
        })
    }
}

impl Drop for KrunContext {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        // SAFETY: this is the final owner of the context ID, and the loaded
        // API remains alive until after this Drop implementation returns.
        unsafe {
            let _ = (self.api.free_ctx)(id);
        }
    }
}

fn resolve_runtime_dir(bundle: &'static RuntimeBundle) -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|error| {
        runtime_error(
            "resolve-linux-libkrun-runtime",
            format!("failed to resolve the current shim executable: {error}"),
        )
    })?;
    let executable_dir = executable.parent().ok_or_else(|| {
        runtime_error(
            "resolve-linux-libkrun-runtime",
            format!(
                "shim executable has no parent directory: {}",
                executable.display()
            ),
        )
    })?;
    let adjacent = executable_dir.join("a3s-oci-krun-runtime");
    match fs::symlink_metadata(&adjacent) {
        Ok(_) => return verify_runtime_dir(&adjacent, bundle),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(runtime_error(
                "resolve-linux-libkrun-runtime",
                format!(
                    "failed to inspect adjacent runtime directory {}: {error}",
                    adjacent.display()
                ),
            ));
        }
    }

    verify_runtime_dir(Path::new(env!("A3S_OCI_KRUN_RUNTIME_DIR")), bundle)
}

fn verify_runtime_dir(runtime_dir: &Path, bundle: &RuntimeBundle) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(runtime_dir).map_err(|error| {
        runtime_error(
            "verify-linux-libkrun-runtime",
            format!(
                "failed to inspect runtime directory {}: {error}",
                runtime_dir.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(runtime_error(
            "verify-linux-libkrun-runtime",
            format!(
                "runtime path must be a real directory, not a symlink: {}",
                runtime_dir.display()
            ),
        ));
    }

    for file in &bundle.files {
        verify_runtime_file(&runtime_dir.join(&file.name), file)?;
    }

    runtime_dir.canonicalize().map_err(|error| {
        runtime_error(
            "verify-linux-libkrun-runtime",
            format!(
                "failed to canonicalize runtime directory {}: {error}",
                runtime_dir.display()
            ),
        )
    })
}

fn verify_runtime_file(path: &Path, expected: &RuntimeFile) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        runtime_error(
            "verify-linux-libkrun-runtime",
            format!("failed to inspect runtime file {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(runtime_error(
            "verify-linux-libkrun-runtime",
            format!(
                "runtime asset must be a real regular file, not a symlink: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() != expected.size {
        return Err(runtime_error(
            "verify-linux-libkrun-runtime",
            format!(
                "size mismatch for {}: expected {}, found {}",
                path.display(),
                expected.size,
                metadata.len()
            ),
        ));
    }

    let actual = sha256_file(path)?;
    if actual != expected.sha256 {
        return Err(runtime_error(
            "verify-linux-libkrun-runtime",
            format!(
                "SHA-256 mismatch for {}: expected {}, found {actual}",
                path.display(),
                expected.sha256
            ),
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| {
        runtime_error(
            "verify-linux-libkrun-runtime",
            format!("failed to open runtime file {}: {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            runtime_error(
                "verify-linux-libkrun-runtime",
                format!("failed to read runtime file {}: {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_exported_kernel(get_kernel: KrunfwGetKernel, expected: &RuntimeKernel) -> Result<String> {
    let mut guest_load_address = 0_u64;
    let mut entry_address = 0_u64;
    let mut size = 0_usize;
    // SAFETY: all output pointers are valid, aligned stack values. The symbol
    // is loaded from the checksum-verified firmware object and owns the
    // returned immutable buffer for the process lifetime.
    let bytes = unsafe { get_kernel(&mut guest_load_address, &mut entry_address, &mut size) };
    let expected_size = usize::try_from(expected.size).map_err(|_| {
        runtime_error(
            "verify-linux-libkrun-kernel",
            format!(
                "pinned firmware kernel size does not fit this host: {}",
                expected.size
            ),
        )
    })?;
    if bytes.is_null() || size != expected_size {
        return Err(runtime_error(
            "verify-linux-libkrun-kernel",
            format!(
                "firmware exported an unexpected kernel bundle size: expected {}, found {size}",
                expected.size
            ),
        ));
    }
    if guest_load_address != expected.guest_load_address || entry_address != expected.entry_address
    {
        return Err(runtime_error(
            "verify-linux-libkrun-kernel",
            format!(
                "firmware exported unexpected kernel addresses: expected load=0x{:016x}, entry=0x{:016x}; found load=0x{guest_load_address:016x}, entry=0x{entry_address:016x}",
                expected.guest_load_address, expected.entry_address
            ),
        ));
    }
    // SAFETY: the firmware returned a non-null buffer with the exact bounded
    // size above and retains ownership for the process lifetime.
    let bytes = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), size) };
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != expected.sha256 {
        return Err(runtime_error(
            "verify-linux-libkrun-kernel",
            format!(
                "firmware kernel SHA-256 mismatch: expected {}, found {digest}",
                expected.sha256
            ),
        ));
    }
    Ok(digest)
}

fn required_file(
    bundle: &'static RuntimeBundle,
    role: RuntimeFileRole,
) -> Result<&'static RuntimeFile> {
    bundle.file(role).ok_or_else(|| {
        runtime_error(
            "resolve-linux-libkrun-runtime",
            format!(
                "{} runtime manifest does not declare the {} role",
                bundle.platform,
                role.as_str()
            ),
        )
    })
}

fn load_symbol<T: Copy>(
    library: &Library,
    name: &'static [u8],
    display_name: &'static str,
) -> Result<T> {
    // SAFETY: callers supply the exact C ABI function-pointer type documented
    // by the pinned libkrun header, and the library outlives the copied value.
    let symbol = unsafe { library.get::<T>(name) }.map_err(|error| {
        runtime_error(
            "load-linux-libkrun-symbol",
            format!("runtime libkrun does not export {display_name}: {error}"),
        )
    })?;
    Ok(*symbol)
}

fn load_optional_symbol<T: Copy>(library: &Library, name: &'static [u8]) -> Option<T> {
    // SAFETY: callers supply the exact C ABI type from the pinned header. The
    // copied pointer cannot outlive `library`, which remains owned by the API.
    unsafe { library.get::<T>(name) }.ok().map(|symbol| *symbol)
}

fn check_status(operation: &'static str, status: i32, message: &'static str) -> Result<()> {
    if status < 0 {
        Err(ffi_error(operation, status, message))
    } else {
        Ok(())
    }
}

fn ffi_error(operation: &'static str, status: i32, message: &'static str) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!("{message}: {operation} returned status {status}"),
    )
    .for_operation(operation)
}

fn runtime_error(operation: &'static str, message: String) -> Error {
    Error::new(ErrorCode::Unavailable, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::{verify_runtime_file, LinuxKrunApi};
    use crate::runtime_assets::{RuntimeFile, RuntimeFileRole};

    #[test]
    fn checksum_verified_runtime_exports_the_required_context_api() {
        LinuxKrunApi::load().expect("pinned Linux runtime bundle must load");
    }

    #[test]
    fn runtime_asset_symlink_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary runtime directory");
        let target = directory.path().join("target");
        let link = directory.path().join("runtime");
        fs::write(&target, b"runtime").expect("write runtime fixture");
        symlink(&target, &link).expect("create runtime symlink");

        let expected = RuntimeFile {
            role: RuntimeFileRole::Library,
            name: "runtime".to_string(),
            size: 7,
            sha256: "d92c6a81b2ff30f006066879b4f5b8aa648cbd0c42f282403ba2d9cd904b3e41".to_string(),
        };
        let error = verify_runtime_file(&link, &expected)
            .expect_err("a symbolic-link runtime asset must be rejected");
        assert!(error.to_string().contains("not a symlink"));
    }
}
