use std::io;
use std::num::NonZeroU32;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE,
    PROCESS_SYNCHRONIZE,
};

use crate::bootstrap_token::CleanupPaths;

const OWNER_EXIT_CODE: u32 = 3;
const OWNER_EXIT_GRACE: Duration = Duration::from_secs(15);

pub(crate) struct OwnerMonitor {
    vm_completion: VmCompletion,
}

impl OwnerMonitor {
    pub(crate) fn mark_vm_finished(&self) {
        self.vm_completion.mark_finished();
    }
}

/// Terminate the shim if the runtime process that owns this VM exits.
///
/// The process handle identifies one kernel process object, so a later PID
/// reuse cannot keep the shim alive. The monitor is installed before libkrun
/// creates a VM context and fails closed if the owner cannot be opened or the
/// monitor thread cannot be created.
pub(crate) fn start(owner_pid: NonZeroU32, cleanup: CleanupPaths) -> io::Result<OwnerMonitor> {
    let owner = open(owner_pid)?;
    let vm_completion = VmCompletion::new();
    let watchdog_completion = vm_completion.clone();
    thread::Builder::new()
        .name("a3s-oci-owner-watchdog".into())
        .spawn(move || terminate_when_signaled(owner, cleanup, watchdog_completion))?;
    Ok(OwnerMonitor { vm_completion })
}

fn open(owner_pid: NonZeroU32) -> io::Result<OwnedHandle> {
    // SAFETY: `owner_pid` is nonzero. The returned process handle is converted
    // immediately into `OwnedHandle`, which closes it exactly once.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, owner_pid.get()) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "failed to open runtime owner process {} for synchronization: {error}",
                owner_pid
            ),
        ));
    }
    // SAFETY: `OpenProcess` returned one owned, non-null process handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn terminate_when_signaled(owner: OwnedHandle, cleanup: CleanupPaths, vm_completion: VmCompletion) {
    // SAFETY: `owner` is a live process handle opened with synchronization
    // rights. With an infinite timeout, any return means the owner exited or
    // the wait itself failed; both conditions must fail closed.
    unsafe {
        WaitForSingleObject(owner.as_raw_handle(), INFINITE);
    }
    let _ = cleanup.cleanup();
    if vm_completion.wait(OWNER_EXIT_GRACE) {
        return;
    }
    // SAFETY: the owner has exited or its wait failed. Terminating the current
    // shim after the bounded guest cleanup grace tears down a stuck in-process
    // libkrun VM instead of orphaning it.
    unsafe {
        TerminateProcess(GetCurrentProcess(), OWNER_EXIT_CODE);
    }
    std::process::exit(OWNER_EXIT_CODE as i32);
}

#[derive(Clone)]
struct VmCompletion {
    shared: Arc<(Mutex<bool>, Condvar)>,
}

impl VmCompletion {
    fn new() -> Self {
        Self {
            shared: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    fn mark_finished(&self) {
        let (finished, notification) = self.shared.as_ref();
        let mut finished = match finished.lock() {
            Ok(finished) => finished,
            Err(poisoned) => poisoned.into_inner(),
        };
        *finished = true;
        notification.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let (finished, notification) = self.shared.as_ref();
        let finished = match finished.lock() {
            Ok(finished) => finished,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *finished {
            return true;
        }
        match notification.wait_timeout_while(finished, timeout, |finished| !*finished) {
            Ok((finished, _)) => *finished,
            Err(poisoned) => *poisoned.into_inner().0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    use super::{open, VmCompletion};

    #[test]
    fn opens_the_exact_live_owner_process() {
        let process = open(NonZeroU32::new(std::process::id()).expect("nonzero process ID"))
            .expect("open current process");
        // SAFETY: `process` is a live synchronization handle and a zero
        // timeout only inspects its current signaled state.
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
    }

    #[test]
    fn rejects_a_missing_owner_process() {
        assert!(open(NonZeroU32::new(u32::MAX).expect("nonzero process ID")).is_err());
    }

    #[test]
    fn observes_a_finished_vm_without_waiting_for_the_grace_timeout() {
        let completion = VmCompletion::new();
        completion.mark_finished();
        assert!(completion.wait(Duration::ZERO));
    }
}
