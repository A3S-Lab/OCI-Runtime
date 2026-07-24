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
use crate::VmConfig;

const LIBKRUN_NAME: &str = "libkrun.1.17.0.dylib";
const LIBKRUN_SHA256: &str = "c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d";
const LIBKRUNFW_NAME: &str = "libkrunfw.5.dylib";
const LIBKRUNFW_SHA256: &str = "841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4";

type KrunCreateCtx = unsafe extern "C" fn() -> i32;
type KrunFreeCtx = unsafe extern "C" fn(u32) -> i32;
type KrunSetVmConfig = unsafe extern "C" fn(u32, u8, u32) -> i32;
type KrunDisableImplicitVsock = unsafe extern "C" fn(u32) -> i32;
type KrunAddVsock = unsafe extern "C" fn(u32, u32) -> i32;
type KrunAddVsockPort = unsafe extern "C" fn(u32, u32, *const c_char, bool) -> i32;
type KrunSetRoot = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunSetWorkdir = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunSetExec =
    unsafe extern "C" fn(u32, *const c_char, *const *const c_char, *const *const c_char) -> i32;
type KrunSetConsoleOutput = unsafe extern "C" fn(u32, *const c_char) -> i32;
type KrunStartEnter = unsafe extern "C" fn(u32) -> i32;

/// Exact, process-local API loaded from the checksum-verified runtime bundle.
pub(crate) struct MacosKrunApi {
    create_ctx: KrunCreateCtx,
    free_ctx: KrunFreeCtx,
    set_vm_config: KrunSetVmConfig,
    disable_implicit_vsock: KrunDisableImplicitVsock,
    add_vsock: KrunAddVsock,
    add_vsock_port: KrunAddVsockPort,
    set_root: KrunSetRoot,
    set_workdir: KrunSetWorkdir,
    set_exec: KrunSetExec,
    set_console_output: KrunSetConsoleOutput,
    start_enter: KrunStartEnter,
    // Drop libkrun before its firmware provider.
    _krun: Library,
    _firmware: Library,
}

impl MacosKrunApi {
    pub(crate) fn load() -> Result<Self> {
        let runtime_dir = resolve_runtime_dir()?;
        let firmware_path = runtime_dir.join(LIBKRUNFW_NAME);
        let krun_path = runtime_dir.join(LIBKRUN_NAME);

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
        let set_root = load_symbol(&krun, b"krun_set_root\0", "krun_set_root")?;
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
            set_root,
            set_workdir,
            set_exec,
            set_console_output,
            start_enter,
            _krun: krun,
            _firmware: firmware,
        })
    }
}

/// Single-threaded owner of one macOS libkrun configuration context.
pub(crate) struct KrunContext {
    id: Option<u32>,
    api: MacosKrunApi,
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
            not_thread_safe: PhantomData,
        })
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

    pub(crate) fn set_root(&mut self, root: &Path) -> Result<()> {
        let id = self.active_id("krun_set_root")?;
        let root = path_to_cstring("krun_set_root", root)?;
        // SAFETY: the context remains exclusively owned by `self`, and the
        // verified path is NUL-terminated for the duration of this call.
        let status = unsafe { (self.api.set_root)(id, root.as_ptr()) };
        check_status(
            "krun_set_root",
            status,
            "failed to configure the macOS libkrun root filesystem",
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

    for (name, expected) in [
        (LIBKRUN_NAME, LIBKRUN_SHA256),
        (LIBKRUNFW_NAME, LIBKRUNFW_SHA256),
    ] {
        verify_runtime_file(&runtime_dir.join(name), expected)?;
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

fn verify_runtime_file(path: &Path, expected: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        runtime_error(
            "verify-macos-libkrun-runtime",
            format!("failed to inspect runtime file {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "runtime asset must be a real regular file, not a symlink: {}",
                path.display()
            ),
        ));
    }

    let mut file = File::open(path).map_err(|error| {
        runtime_error(
            "verify-macos-libkrun-runtime",
            format!("failed to open runtime file {}: {error}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            runtime_error(
                "verify-macos-libkrun-runtime",
                format!("failed to read runtime file {}: {error}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if actual != expected {
        return Err(runtime_error(
            "verify-macos-libkrun-runtime",
            format!(
                "SHA-256 mismatch for {}: expected {expected}, found {actual}",
                path.display()
            ),
        ));
    }
    Ok(())
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

    use super::{verify_runtime_file, MacosKrunApi};

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

        let error = verify_runtime_file(&path, &"0".repeat(64))
            .expect_err("a modified runtime file must be rejected");
        fs::remove_file(&path).expect("test file must be removed");
        assert!(error.to_string().contains("SHA-256 mismatch"));
    }
}
