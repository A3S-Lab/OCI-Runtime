use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

use a3s_libkrun_sys::{
    krun_add_disk, krun_add_virtiofs, krun_add_vsock, krun_add_vsock_port_windows, krun_create_ctx,
    krun_disable_implicit_vsock, krun_free_ctx, krun_set_console_output, krun_set_exec,
    krun_set_root, krun_set_vm_config, krun_set_workdir, krun_start_enter,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use zeroize::Zeroizing;

use crate::ffi::{path_to_cstring, value_to_cstring, FfiStringArray};
use crate::{AgentVsockEndpoint, VmConfig};

/// Single-threaded owner of one valid libkrun configuration context.
pub(crate) struct KrunContext {
    id: Option<u32>,
    root_disk_configured: bool,
    not_thread_safe: PhantomData<Rc<()>>,
}

const BLOCK_ROOT_ENVIRONMENT: &[(&str, &str)] = &[
    ("KRUN_BLOCK_ROOT_DEVICE", "/dev/vda"),
    ("KRUN_BLOCK_ROOT_FSTYPE", "ext4"),
    ("KRUN_BLOCK_ROOT_OPTIONS", "ro"),
];

impl KrunContext {
    pub(crate) fn create() -> Result<Self> {
        // SAFETY: `krun_create_ctx` accepts no pointers and returns either a
        // non-negative owned context ID or a negative errno-style status.
        let status = unsafe { krun_create_ctx() };
        let id = u32::try_from(status).map_err(|_| {
            ffi_error(
                "krun_create_ctx",
                status,
                "failed to allocate a libkrun configuration context",
            )
        })?;

        Ok(Self {
            id: Some(id),
            root_disk_configured: false,
            not_thread_safe: PhantomData,
        })
    }

    pub(crate) fn set_vm_config(&mut self, config: VmConfig) -> Result<()> {
        let id = self.id.ok_or_else(|| {
            Error::new(
                ErrorCode::FailedPrecondition,
                "libkrun context has already been released",
            )
            .for_operation("krun_set_vm_config")
        })?;
        // SAFETY: `id` was returned by `krun_create_ctx`, remains owned by
        // `self`, and both scalar arguments were validated by `VmConfig`.
        let status = unsafe { krun_set_vm_config(id, config.vcpus(), config.memory_mib()) };
        check_status(
            "krun_set_vm_config",
            status,
            "failed to configure libkrun VM resources",
        )
    }

    pub(crate) fn set_root(&mut self, root: &Path) -> Result<()> {
        let id = self.active_id("krun_set_root")?;
        let root = path_to_cstring("krun_set_root", root)?;
        // SAFETY: the context remains owned by `self` and `root` is a
        // NUL-terminated string that lives for the duration of the call.
        let status = unsafe { krun_set_root(id, root.as_ptr()) };
        check_status(
            "krun_set_root",
            status,
            "failed to configure the libkrun root filesystem",
        )
    }

    pub(crate) fn add_virtiofs(&mut self, tag: &str, host_path: &Path) -> Result<()> {
        let id = self.active_id("krun_add_virtiofs")?;
        let tag = value_to_cstring("krun_add_virtiofs", "virtio-fs tag", tag)?;
        let host_path = path_to_cstring("krun_add_virtiofs", host_path)?;
        // SAFETY: the context remains exclusively owned and both strings are
        // NUL-terminated allocations retained for the complete call.
        let status = unsafe { krun_add_virtiofs(id, tag.as_ptr(), host_path.as_ptr()) };
        check_status(
            "krun_add_virtiofs",
            status,
            "failed to configure the protected runtime share",
        )
    }

    /// Attach the manifest-verified system image as the first, read-only disk.
    pub(crate) fn set_root_disk(&mut self, image: &Path) -> Result<()> {
        let id = self.active_id("krun_add_disk")?;
        if self.root_disk_configured {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "the immutable libkrun root disk is already configured",
            )
            .for_operation("krun_add_disk"));
        }
        let block_id = value_to_cstring("krun_add_disk", "block device ID", "root")?;
        let image = path_to_cstring("krun_add_disk", image)?;
        // SAFETY: the context is exclusively owned, both C strings remain
        // live for the call, and true selects the Windows read-only backend.
        let status = unsafe { krun_add_disk(id, block_id.as_ptr(), image.as_ptr(), true) };
        check_status(
            "krun_add_disk",
            status,
            "failed to configure the immutable libkrun root disk",
        )?;
        self.root_disk_configured = true;
        Ok(())
    }

    pub(crate) fn set_agent_vsock(&mut self, endpoint: &AgentVsockEndpoint) -> Result<()> {
        let id = self.active_id("configure-agent-vsock")?;
        // The implicit device enables TSI according to libkrun policy. Replace
        // it with an explicit device whose zero flags expose only vsock.
        // SAFETY: `id` is a live, exclusively owned libkrun context.
        let status = unsafe { krun_disable_implicit_vsock(id) };
        check_status(
            "krun_disable_implicit_vsock",
            status,
            "failed to disable the implicit libkrun vsock device",
        )?;
        // SAFETY: `id` remains live and zero is the documented plain-vsock
        // feature mask.
        let status = unsafe { krun_add_vsock(id, 0) };
        check_status(
            "krun_add_vsock",
            status,
            "failed to configure a plain agent vsock device",
        )?;

        let pipe_name = value_to_cstring(
            "krun_add_vsock_port_windows",
            "agent pipe name",
            endpoint.pipe_name(),
        )?;
        // SAFETY: the context remains live and `pipe_name` is a validated,
        // NUL-terminated bare name retained for the duration of the call.
        let status =
            unsafe { krun_add_vsock_port_windows(id, endpoint.port(), pipe_name.as_ptr()) };
        check_status(
            "krun_add_vsock_port_windows",
            status,
            "failed to map the guest agent port to a Windows named pipe",
        )
    }

    pub(crate) fn set_workdir(&mut self, workdir: &str) -> Result<()> {
        let id = self.active_id("krun_set_workdir")?;
        let workdir = value_to_cstring("krun_set_workdir", "working directory", workdir)?;
        // SAFETY: the context remains owned by `self` and `workdir` is a
        // NUL-terminated string that lives for the duration of the call.
        let status = unsafe { krun_set_workdir(id, workdir.as_ptr()) };
        check_status(
            "krun_set_workdir",
            status,
            "failed to configure the libkrun working directory",
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
        let environment_entries = Zeroizing::new(self.guest_environment(environment)?);
        let environment =
            FfiStringArray::new("krun_set_exec", "environment", &environment_entries)?;

        // SAFETY: all pointers refer to live CString allocations and both
        // pointer tables contain exactly the number of slots libkrun reads.
        let status = unsafe {
            krun_set_exec(
                id,
                executable.as_ptr(),
                arguments.as_ptr(),
                environment.as_ptr(),
            )
        };
        check_status(
            "krun_set_exec",
            status,
            "failed to configure the libkrun guest workload",
        )
    }

    fn guest_environment(&self, environment: &[(String, String)]) -> Result<Vec<String>> {
        for (key, _) in environment {
            if BLOCK_ROOT_ENVIRONMENT
                .iter()
                .any(|(reserved, _)| key == reserved)
            {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    format!("guest environment cannot override internal libkrun key {key}"),
                )
                .for_operation("krun_set_exec"));
            }
        }
        let mut entries = environment
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>();
        if self.root_disk_configured {
            entries.extend(
                BLOCK_ROOT_ENVIRONMENT
                    .iter()
                    .map(|(key, value)| format!("{key}={value}")),
            );
        }
        Ok(entries)
    }

    pub(crate) fn set_console_output(&mut self, output: &Path) -> Result<()> {
        let id = self.active_id("krun_set_console_output")?;
        let output = path_to_cstring("krun_set_console_output", output)?;
        // SAFETY: the context remains owned by `self` and `output` is a
        // NUL-terminated string that lives for the duration of the call.
        let status = unsafe { krun_set_console_output(id, output.as_ptr()) };
        check_status(
            "krun_set_console_output",
            status,
            "failed to configure libkrun console output",
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

        // SAFETY: `id` is valid and exclusively owned. libkrun removes it from
        // its context map before attempting VM construction, so ownership is
        // consumed even when this call reports an error.
        let status = unsafe { krun_start_enter(id) };
        if status < 0 {
            Err(ffi_error(
                "krun_start_enter",
                status,
                "failed to enter the libkrun virtual machine",
            ))
        } else {
            Ok(status)
        }
    }

    pub(crate) fn close(mut self) -> Result<()> {
        let Some(id) = self.id.take() else {
            return Ok(());
        };
        // SAFETY: `id` is still owned by this context and is removed before
        // the call so `Drop` cannot release it twice.
        let status = unsafe { krun_free_ctx(id) };
        check_status(
            "krun_free_ctx",
            status,
            "failed to release the libkrun configuration context",
        )
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
        // SAFETY: this is the final owner of a context ID created by libkrun.
        // Drop cannot report cleanup failure, so explicit callers use `close`.
        unsafe {
            let _ = krun_free_ctx(id);
        }
    }
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

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::KrunContext;

    fn context_with_root_disk(configured: bool) -> KrunContext {
        KrunContext {
            id: None,
            root_disk_configured: configured,
            not_thread_safe: PhantomData,
        }
    }

    #[test]
    fn injects_the_fixed_read_only_block_root_environment() {
        let context = context_with_root_disk(true);
        let environment = context
            .guest_environment(&[("A3S_TOKEN".to_string(), "value".to_string())])
            .expect("ordinary guest environment must remain valid");

        assert_eq!(environment[0], "A3S_TOKEN=value");
        assert!(environment.contains(&"KRUN_BLOCK_ROOT_DEVICE=/dev/vda".to_string()));
        assert!(environment.contains(&"KRUN_BLOCK_ROOT_FSTYPE=ext4".to_string()));
        assert!(environment.contains(&"KRUN_BLOCK_ROOT_OPTIONS=ro".to_string()));
    }

    #[test]
    fn rejects_callers_that_override_internal_block_root_environment() {
        let context = context_with_root_disk(true);
        let error = context
            .guest_environment(&[("KRUN_BLOCK_ROOT_OPTIONS".to_string(), "rw".to_string())])
            .expect_err("callers must not make the immutable root writable");

        assert!(error.to_string().contains("cannot override"));
    }
}
