use std::ffi::c_char;
use std::fs;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use a3s_oci_sdk::{Error, ErrorCode, Result};
use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_LOCAL, RTLD_NOW};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ffi::{path_to_cstring, value_to_cstring, FfiStringArray};
use crate::macos_assets::{
    MacosRuntimeProvenance, PinnedFile, KERNEL_BUNDLE_SHA256, KERNEL_BUNDLE_SIZE,
    KERNEL_ENTRY_ADDRESS, KERNEL_GUEST_LOAD_ADDRESS, LIBKRUNFW_NAME, LIBKRUNFW_SHA256,
    LIBKRUNFW_SIZE, LIBKRUN_NAME, LIBKRUN_SHA256, LIBKRUN_SIZE,
};
use crate::macos_system_image::MacosSystemImage;
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
type KrunSetWorkdir = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunSetExec =
    unsafe extern "C" fn(u32, *const c_char, *const *const c_char, *const *const c_char) -> i32;
type KrunSetConsoleOutput = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunStartEnter = unsafe extern "C" fn(u32) -> i32;
type KrunfwGetKernel = unsafe extern "C" fn(*mut u64, *mut u64, *mut usize) -> *const c_char;

/// Exact, process-local API loaded from the checksum-verified runtime bundle.
pub(crate) struct MacosKrunApi {
    create_ctx: KrunCreateCtx,
    free_ctx: KrunFreeCtx,
    set_vm_config: KrunSetVmConfig,
    disable_implicit_vsock: KrunDisableImplicitVsock,
    add_vsock: KrunAddVsock,
    add_vsock_port: KrunAddVsockPort,
    add_disk: KrunAddDisk,
    set_root_disk_remount: KrunSetRootDiskRemount,
    add_virtiofs: KrunAddVirtiofs,
    set_workdir: KrunSetWorkdir,
    set_exec: KrunSetExec,
    set_console_output: KrunSetConsoleOutput,
    start_enter: KrunStartEnter,
    get_kernel: KrunfwGetKernel,
    runtime_provenance: MacosRuntimeProvenance,
    runtime_krun: PinnedFile,
    runtime_firmware: PinnedFile,
    // Drop libkrun before its firmware provider.
    _krun: Library,
    _firmware: Library,
}

impl MacosKrunApi {
    pub(crate) fn load() -> Result<Self> {
        let runtime_dir = resolve_runtime_dir()?;
        let firmware_path = runtime_dir.join(LIBKRUNFW_NAME);
        let krun_path = runtime_dir.join(LIBKRUN_NAME);
        let firmware_file = PinnedFile::open(&firmware_path, "macOS libkrun firmware")
            .map_err(|error| error.for_operation("load-macos-libkrunfw"))?;
        let krun_file = PinnedFile::open(&krun_path, "macOS libkrun")
            .map_err(|error| error.for_operation("load-macos-libkrun"))?;
        verify_pinned_runtime_file(&firmware_file, LIBKRUNFW_SIZE, LIBKRUNFW_SHA256)?;
        verify_pinned_runtime_file(&krun_file, LIBKRUN_SIZE, LIBKRUN_SHA256)?;

        // SAFETY: both paths are absolute, checksum-verified regular files.
        // RTLD_GLOBAL makes the already-loaded firmware visible when libkrun
        // later resolves its fixed `libkrunfw.5.dylib` provider.
        let firmware =
            unsafe { Library::open(Some(firmware_path.as_os_str()), RTLD_NOW | RTLD_GLOBAL) }
                .map_err(|error| {
                    runtime_error(
                        "load-macos-libkrunfw",
                        format!(
                            "failed to load checksum-verified firmware {}: {error}",
                            firmware_path.display()
                        ),
                    )
                })?;
        firmware_file
            .reverify("dynamic library load")
            .map_err(|error| error.for_operation("load-macos-libkrunfw"))?;

        // SAFETY: the exact runtime-owned libkrun file was verified above and
        // stays loaded for the lifetime of every copied function pointer.
        let krun = unsafe { Library::open(Some(krun_path.as_os_str()), RTLD_NOW | RTLD_LOCAL) }
            .map_err(|error| {
                runtime_error(
                    "load-macos-libkrun",
                    format!(
                        "failed to load checksum-verified libkrun {}: {error}",
                        krun_path.display()
                    ),
                )
            })?;
        krun_file
            .reverify("dynamic library load")
            .map_err(|error| error.for_operation("load-macos-libkrun"))?;

        let get_kernel = load_symbol(&firmware, b"krunfw_get_kernel\0", "krunfw_get_kernel")?;
        let runtime_provenance = verify_exported_kernel(get_kernel)?;
        let create_ctx = load_symbol(&krun, b"krun_create_ctx\0", "krun_create_ctx")?;
        let free_ctx = load_symbol(&krun, b"krun_free_ctx\0", "krun_free_ctx")?;
        let set_vm_config = load_symbol(&krun, b"krun_set_vm_config\0", "krun_set_vm_config")?;
        let disable_implicit_vsock = load_symbol(
            &krun,
            b"krun_disable_implicit_vsock\0",
            "krun_disable_implicit_vsock",
        )?;
        let add_vsock = load_symbol(&krun, b"krun_add_vsock\0", "krun_add_vsock")?;
        let add_vsock_port = load_symbol(&krun, b"krun_add_vsock_port2\0", "krun_add_vsock_port2")?;
        let add_disk = load_symbol(&krun, b"krun_add_disk2\0", "krun_add_disk2")?;
        let set_root_disk_remount = load_symbol(
            &krun,
            b"krun_set_root_disk_remount\0",
            "krun_set_root_disk_remount",
        )?;
        let add_virtiofs = load_symbol(&krun, b"krun_add_virtiofs\0", "krun_add_virtiofs")?;
        let set_workdir = load_symbol(&krun, b"krun_set_workdir\0", "krun_set_workdir")?;
        let set_exec = load_symbol(&krun, b"krun_set_exec\0", "krun_set_exec")?;
        let set_console_output = load_symbol(
            &krun,
            b"krun_set_console_output\0",
            "krun_set_console_output",
        )?;
        let start_enter = load_symbol(&krun, b"krun_start_enter\0", "krun_start_enter")?;

        Ok(Self {
            create_ctx,
            free_ctx,
            set_vm_config,
            disable_implicit_vsock,
            add_vsock,
            add_vsock_port,
            add_disk,
            set_root_disk_remount,
            add_virtiofs,
            set_workdir,
            set_exec,
            set_console_output,
            start_enter,
            get_kernel,
            runtime_provenance,
            runtime_krun: krun_file,
            runtime_firmware: firmware_file,
            _krun: krun,
            _firmware: firmware,
        })
    }

    pub(crate) fn runtime_provenance(&self) -> &MacosRuntimeProvenance {
        &self.runtime_provenance
    }

    fn reverify_runtime(&self) -> Result<MacosRuntimeProvenance> {
        self.runtime_krun
            .reverify("VM entry")
            .map_err(|error| error.for_operation("reverify-macos-libkrun-runtime"))?;
        self.runtime_firmware
            .reverify("VM entry")
            .map_err(|error| error.for_operation("reverify-macos-libkrun-runtime"))?;
        let provenance = verify_exported_kernel(self.get_kernel)?;
        if provenance != self.runtime_provenance {
            return Err(runtime_error(
                "reverify-macos-libkrun-runtime",
                "loaded macOS runtime provenance changed before VM entry".to_string(),
            ));
        }
        Ok(provenance)
    }
}

/// Single-threaded owner of one macOS libkrun configuration context.
pub(crate) struct KrunContext {
    id: Option<u32>,
    api: MacosKrunApi,
    system_image: Option<MacosSystemImage>,
    not_thread_safe: PhantomData<Rc<()>>,
}

impl KrunContext {
    pub(crate) fn create(api: MacosKrunApi) -> Result<Self> {
        // SAFETY: the function pointer was resolved from the pinned libkrun
        // image and accepts no arguments.
        let status = unsafe { (api.create_ctx)() };
        let id = u32::try_from(status).map_err(|_| {
            ffi_error(
                "krun_create_ctx",
                status,
                "failed to allocate a macOS libkrun configuration context",
            )
        })?;

        Ok(Self {
            id: Some(id),
            api,
            system_image: None,
            not_thread_safe: PhantomData,
        })
    }

    pub(crate) fn set_read_only_system_image(
        &mut self,
        system_image: MacosSystemImage,
    ) -> Result<()> {
        let id = self.active_id("configure-macos-system-image")?;
        if self.system_image.is_some() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "macOS system image has already been configured",
            )
            .for_operation("configure-macos-system-image"));
        }
        let disk_id = value_to_cstring("krun_add_disk2", "block identifier", SYSTEM_DISK_ID)?;
        let image_path = path_to_cstring("krun_add_disk2", system_image.image_path())?;
        // SAFETY: all strings remain live for the call. The manifest-bound raw
        // image was verified as a regular file and is explicitly read-only.
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
            "failed to attach the immutable macOS system image read-only",
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
        // SAFETY: the exact block disk was added above, and all fixed strings
        // are NUL-terminated for the duration of this call.
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
            "failed to select the immutable ext4 block root read-only",
        )?;
        self.system_image = Some(system_image);
        Ok(())
    }

    pub(crate) fn add_virtiofs(&mut self, tag: &str, host_path: &Path) -> Result<()> {
        let id = self.active_id("krun_add_virtiofs")?;
        let tag = value_to_cstring("krun_add_virtiofs", "virtio-fs tag", tag)?;
        let host_path = path_to_cstring("krun_add_virtiofs", host_path)?;
        // SAFETY: both strings remain live for the call, and this context is
        // exclusively owned by `self`.
        let status = unsafe { (self.api.add_virtiofs)(id, tag.as_ptr(), host_path.as_ptr()) };
        check_status(
            "krun_add_virtiofs",
            status,
            "failed to attach the writable macOS runtime share",
        )
    }

    pub(crate) fn set_vm_config(&mut self, config: VmConfig) -> Result<()> {
        let id = self.active_id("krun_set_vm_config")?;
        // SAFETY: this context exclusively owns `id`, and `VmConfig` has
        // validated both scalar resource values.
        let status = unsafe { (self.api.set_vm_config)(id, config.vcpus(), config.memory_mib()) };
        check_status(
            "krun_set_vm_config",
            status,
            "failed to configure macOS libkrun VM resources",
        )
    }

    pub(crate) fn set_agent_vsock(&mut self, socket_path: &Path, port: u32) -> Result<()> {
        let id = self.active_id("configure-agent-vsock")?;
        let socket_path = path_to_cstring("krun_add_vsock_port2", socket_path)?;

        // SAFETY: `id` is live and exclusively owned. Removing the implicit
        // device prevents TSI from being enabled by libkrun policy.
        let status = unsafe { (self.api.disable_implicit_vsock)(id) };
        check_status(
            "krun_disable_implicit_vsock",
            status,
            "failed to disable the implicit macOS libkrun vsock device",
        )?;

        // SAFETY: `id` remains live and a zero feature mask requests plain
        // AF_VSOCK without transparent socket impersonation.
        let status = unsafe { (self.api.add_vsock)(id, 0) };
        check_status(
            "krun_add_vsock",
            status,
            "failed to configure a plain macOS agent vsock device",
        )?;

        // SAFETY: the path is a live NUL-terminated string for this call.
        // `listen = false` records a guest-to-existing-host-socket mapping and
        // does not create or connect the socket during context configuration.
        let status = unsafe { (self.api.add_vsock_port)(id, port, socket_path.as_ptr(), false) };
        check_status(
            "krun_add_vsock_port2",
            status,
            "failed to map the guest agent port to a macOS Unix socket",
        )
    }

    pub(crate) fn set_workdir(&mut self, workdir: &str) -> Result<()> {
        let id = self.active_id("krun_set_workdir")?;
        let workdir = value_to_cstring("krun_set_workdir", "working directory", workdir)?;
        // SAFETY: the context remains exclusively owned by `self`, and the
        // value is NUL-terminated for the duration of this call.
        let status = unsafe { (self.api.set_workdir)(id, workdir.as_ptr()) };
        check_status(
            "krun_set_workdir",
            status,
            "failed to configure the macOS libkrun working directory",
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

        // SAFETY: all pointers refer to live allocations, and both tables
        // contain the exact number of slots read by the pinned libkrun.
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
            "failed to configure the macOS libkrun guest workload",
        )
    }

    pub(crate) fn set_console_output(&mut self, output: &Path) -> Result<()> {
        let id = self.active_id("krun_set_console_output")?;
        let output = path_to_cstring("krun_set_console_output", output)?;
        // SAFETY: the context remains exclusively owned by `self`, and the
        // path is NUL-terminated for the duration of this call.
        let status = unsafe { (self.api.set_console_output)(id, output.as_ptr()) };
        check_status(
            "krun_set_console_output",
            status,
            "failed to configure macOS libkrun console output",
        )
    }

    pub(crate) fn start_enter(mut self) -> Result<i32> {
        let runtime = self.api.reverify_runtime()?;
        let system_image = self.system_image.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "macOS VM entry requires a manifest-bound immutable system image",
            )
            .for_operation("krun_start_enter")
        })?;
        system_image.reverify(&runtime)?;
        let id = self.id.take().ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "libkrun context has already been released",
            )
            .for_operation("krun_start_enter")
        })?;

        // SAFETY: `id` is valid and exclusively owned. libkrun consumes the
        // context before VM construction and terminates this worker process
        // with the guest exit code after a successful entry.
        let status = unsafe { (self.api.start_enter)(id) };
        if status < 0 {
            Err(ffi_error(
                "krun_start_enter",
                status,
                "failed to enter the macOS libkrun virtual machine",
            ))
        } else {
            Ok(status)
        }
    }

    pub(crate) fn close(mut self) -> Result<()> {
        let Some(id) = self.id.take() else {
            return Ok(());
        };
        // SAFETY: `id` is still owned by this context. Restore cleanup
        // ownership on failure so Drop makes one final release attempt.
        let status = unsafe { (self.api.free_ctx)(id) };
        if let Err(error) = check_status(
            "krun_free_ctx",
            status,
            "failed to release the macOS libkrun configuration context",
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
        // SAFETY: this is the final owner of the context ID and the loaded API
        // remains alive until after this field's Drop implementation returns.
        unsafe {
            let _ = (self.api.free_ctx)(id);
        }
    }
}

fn resolve_runtime_dir() -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|error| {
        runtime_error(
            "resolve-macos-libkrun-runtime",
            format!("failed to resolve the current shim executable: {error}"),
        )
    })?;
    let executable_dir = executable.parent().ok_or_else(|| {
        runtime_error(
            "resolve-macos-libkrun-runtime",
            format!(
                "shim executable has no parent directory: {}",
                executable.display()
            ),
        )
    })?;
    let adjacent = executable_dir.join("a3s-oci-krun-runtime");
    match fs::symlink_metadata(&adjacent) {
        Ok(_) => return verify_runtime_dir(&adjacent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(runtime_error(
                "resolve-macos-libkrun-runtime",
                format!(
                    "failed to inspect adjacent runtime directory {}: {error}",
                    adjacent.display()
                ),
            ))
        }
    }

    verify_runtime_dir(Path::new(env!("A3S_OCI_KRUN_RUNTIME_DIR")))
}

fn verify_runtime_dir(runtime_dir: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(runtime_dir).map_err(|error| {
        runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "failed to inspect runtime directory {}: {error}",
                runtime_dir.display()
            ),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "runtime path must be a real directory, not a symlink: {}",
                runtime_dir.display()
            ),
        ));
    }

    runtime_dir.canonicalize().map_err(|error| {
        runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "failed to canonicalize runtime directory {}: {error}",
                runtime_dir.display()
            ),
        )
    })
}

fn verify_pinned_runtime_file(file: &PinnedFile, expected_size: u64, expected: &str) -> Result<()> {
    if file.size() != expected_size {
        return Err(runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "size mismatch for {}: expected {expected_size}, found {}",
                file.path().display(),
                file.size()
            ),
        ));
    }
    if file.sha256() != expected {
        return Err(runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "SHA-256 mismatch for {}: expected {expected}, found {}",
                file.path().display(),
                file.sha256()
            ),
        ));
    }
    Ok(())
}

fn verify_exported_kernel(get_kernel: KrunfwGetKernel) -> Result<MacosRuntimeProvenance> {
    let mut guest_load_address = 0_u64;
    let mut entry_address = 0_u64;
    let mut size = 0_usize;
    // SAFETY: all output pointers are valid, aligned stack values. The symbol
    // is loaded from the checksum-verified firmware library and owns the
    // returned immutable buffer for the process lifetime.
    let bytes = unsafe { get_kernel(&mut guest_load_address, &mut entry_address, &mut size) };
    if bytes.is_null() || size != KERNEL_BUNDLE_SIZE {
        return Err(runtime_error(
            "verify-macos-libkrun-kernel",
            format!(
                "firmware exported an unexpected kernel bundle size: expected {KERNEL_BUNDLE_SIZE}, found {size}"
            ),
        ));
    }
    if guest_load_address != KERNEL_GUEST_LOAD_ADDRESS || entry_address != KERNEL_ENTRY_ADDRESS {
        return Err(runtime_error(
            "verify-macos-libkrun-kernel",
            format!(
                "firmware exported unexpected kernel addresses: load=0x{guest_load_address:016x}, entry=0x{entry_address:016x}"
            ),
        ));
    }
    // SAFETY: the firmware returned a non-null buffer with the exact bounded
    // size above and retains ownership for the process lifetime.
    let bytes = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), size) };
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != KERNEL_BUNDLE_SHA256 {
        return Err(runtime_error(
            "verify-macos-libkrun-kernel",
            format!(
                "firmware kernel SHA-256 mismatch: expected {KERNEL_BUNDLE_SHA256}, found {digest}"
            ),
        ));
    }
    Ok(MacosRuntimeProvenance::pinned(digest))
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
            "load-macos-libkrun-symbol",
            format!("runtime libkrun does not export {display_name}: {error}"),
        )
    })?;
    Ok(*symbol)
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
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{verify_pinned_runtime_file, MacosKrunApi};

    #[test]
    fn checksum_verified_runtime_exports_the_required_context_api() {
        MacosKrunApi::load().expect("pinned macOS runtime bundle must load");
    }

    #[test]
    fn modified_runtime_asset_fails_closed_before_loading() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "a3s-oci-tampered-runtime-{}-{nonce}",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("unique test file must be created");
        file.write_all(b"tampered runtime")
            .expect("test file must be written");
        drop(file);

        let pinned = super::PinnedFile::open(&path, "test runtime asset")
            .expect("test runtime asset must be pinnable");
        let error = verify_pinned_runtime_file(&pinned, 16, &"0".repeat(64))
            .expect_err("a modified runtime file must be rejected");
        fs::remove_file(&path).expect("test file must be removed");
        assert!(error.to_string().contains("SHA-256 mismatch"));
    }
}
