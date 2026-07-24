use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

use a3s_libkrun_sys::{
    krun_add_vsock, krun_add_vsock_port_windows, krun_create_ctx, krun_disable_implicit_vsock,
    krun_free_ctx, krun_set_console_output, krun_set_exec, krun_set_root, krun_set_vm_config,
    krun_set_workdir, krun_start_enter,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use zeroize::Zeroizing;

use crate::ffi::{path_to_cstring, value_to_cstring, FfiStringArray};
use crate::{AgentVsockEndpoint, VmConfig};

/// Single-threaded owner of one valid libkrun configuration context.
pub(crate) struct KrunContext {
    id: Option<u32>,
    not_thread_safe: PhantomData<Rc<()>>,
}

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
        let environment_entries = Zeroizing::new(
            environment
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>(),
        );
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
