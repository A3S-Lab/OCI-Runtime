use std::marker::PhantomData;
use std::rc::Rc;

use a3s_libkrun_sys::{krun_create_ctx, krun_free_ctx, krun_set_vm_config};
use a3s_oci_sdk::{Error, ErrorCode, Result};

use crate::VmConfig;

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
