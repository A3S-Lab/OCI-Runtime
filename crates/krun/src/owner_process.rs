use std::io;
use std::num::NonZeroU32;
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, TerminateProcess, WaitForSingleObject, INFINITE,
    PROCESS_SYNCHRONIZE,
};

use crate::bootstrap_token::CleanupPaths;
use crate::recovery_report::RecoveryCleanupPaths;

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
/// The process handle identifies one kernel process object, so later PID reuse
/// cannot keep the shim alive. The monitor is installed before libkrun creates
/// a VM context and fails closed if the owner cannot be opened.
pub(crate) fn start(
    owner_pid: NonZeroU32,
    bootstrap_cleanup: CleanupPaths,
    recovery_cleanup: Option<RecoveryCleanupPaths>,
) -> io::Result<OwnerMonitor> {
    let owner = open(owner_pid)?;
    let vm_completion = VmCompletion::new();
    let watchdog_completion = vm_completion.clone();
    thread::Builder::new()
        .name("a3s-oci-owner-watchdog".into())
        .spawn(move || {
            terminate_when_signaled(
                owner,
                bootstrap_cleanup,
                recovery_cleanup,
                watchdog_completion,
            );
        })?;
    Ok(OwnerMonitor { vm_completion })
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
type ExactOwner = OwnedHandle;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ExactOwner {
    queue: OwnedFd,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
struct ExactOwner {
    pidfd: OwnedFd,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn open(owner_pid: NonZeroU32) -> io::Result<ExactOwner> {
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn open(owner_pid: NonZeroU32) -> io::Result<ExactOwner> {
    let owner_pid = libc::pid_t::try_from(owner_pid.get())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // The runtime starts the shim directly. Requiring this exact relationship
    // prevents a caller from binding the watchdog to an unrelated same-UID
    // process and also fails closed if the owner exited before registration.
    // SAFETY: getppid and getpid have no preconditions or failure returns.
    let parent = unsafe { libc::getppid() };
    let process = unsafe { libc::getpid() };
    if parent != owner_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("runtime owner PID {owner_pid} is not the shim's direct parent PID {parent}"),
        ));
    }
    // RunningShim creates a fresh process group before exec. This invariant
    // makes a later group kill target only the shim and its VM worker.
    // SAFETY: getpgrp has no preconditions or failure return.
    let process_group = unsafe { libc::getpgrp() };
    if process_group != process {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "libkrun shim PID {process} must lead its process group; observed {process_group}"
            ),
        ));
    }

    // SAFETY: kqueue returns a new owned descriptor or -1 on failure.
    let queue = unsafe { libc::kqueue() };
    if queue < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: queue is a newly returned owned descriptor.
    let queue = unsafe { OwnedFd::from_raw_fd(queue) };
    // Prevent the owner watch descriptor from leaking into the libkrun worker.
    // SAFETY: queue is live and F_SETFD accepts FD_CLOEXEC as its integer arg.
    if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let change = libc::kevent {
        ident: owner_pid as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    // SAFETY: change points to one initialized event; no output buffer is
    // supplied during registration. The kernel pins this process incarnation.
    let registered = unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &change,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if registered != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ExactOwner { queue })
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn open(owner_pid: NonZeroU32) -> io::Result<ExactOwner> {
    let owner_pid = libc::pid_t::try_from(owner_pid.get())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: getppid, getpid, and getpgrp have no preconditions.
    let parent = unsafe { libc::getppid() };
    let process = unsafe { libc::getpid() };
    let process_group = unsafe { libc::getpgrp() };
    if parent != owner_pid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("runtime owner PID {owner_pid} is not the shim's direct parent PID {parent}"),
        ));
    }
    if process_group != process {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Linux KVM shim PID {process} must lead its process group; observed {process_group}"
            ),
        ));
    }

    // SAFETY: pidfd_open takes a positive live PID and zero flags. The
    // returned descriptor pins this process incarnation across PID reuse.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, owner_pid, 0_u32) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("failed to open runtime owner PID {owner_pid} with pidfd: {error}"),
        ));
    }
    let descriptor = i32::try_from(descriptor)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    // SAFETY: pidfd_open returned one newly owned nonnegative descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // Prevent the owner descriptor from crossing into the VM worker exec.
    // SAFETY: pidfd is live and F_SETFD accepts FD_CLOEXEC.
    if unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ExactOwner { pidfd })
}

fn terminate_when_signaled(
    owner: ExactOwner,
    bootstrap_cleanup: CleanupPaths,
    recovery_cleanup: Option<RecoveryCleanupPaths>,
    vm_completion: VmCompletion,
) {
    wait_for_owner_exit(&owner);
    let _ = bootstrap_cleanup.cleanup();
    if vm_completion.wait(OWNER_EXIT_GRACE) {
        return;
    }
    if let Some(cleanup) = recovery_cleanup {
        let _ = cleanup.cleanup();
    }
    terminate_current_shim();
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn wait_for_owner_exit(owner: &ExactOwner) {
    // SAFETY: owner is a live process handle opened with synchronization
    // rights. Any return means the owner exited or the wait failed, and both
    // conditions must fail closed.
    unsafe {
        WaitForSingleObject(owner.as_raw_handle(), INFINITE);
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn wait_for_owner_exit(owner: &ExactOwner) {
    let mut descriptor = libc::pollfd {
        fd: owner.pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: descriptor points to one initialized pollfd and -1 requests
        // an unbounded wait. Any terminal event or non-EINTR error fails closed.
        let status = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if status > 0 {
            return;
        }
        if status < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn wait_for_owner_exit(owner: &ExactOwner) {
    // Any event or wait error is terminal. The registration is one-shot and
    // bound to the exact process incarnation observed before VM launch.
    let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
    // SAFETY: event points to storage for one result and the call blocks until
    // that result or an error. No changelist is supplied.
    unsafe {
        let _ = libc::kevent(
            owner.queue.as_raw_fd(),
            std::ptr::null(),
            0,
            event.as_mut_ptr(),
            1,
            std::ptr::null(),
        );
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn terminate_current_shim() -> ! {
    // SAFETY: the owner has exited or its wait failed. Terminating the current
    // shim tears down a stuck in-process libkrun VM after a bounded grace.
    unsafe {
        TerminateProcess(GetCurrentProcess(), OWNER_EXIT_CODE);
    }
    std::process::exit(OWNER_EXIT_CODE as i32);
}

#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn terminate_current_shim() -> ! {
    // open() verified that this shim leads a private process group. Killing the
    // negative group ID tears down the shim and its libkrun worker together.
    // SAFETY: getpgrp has no preconditions; kill targets only this group.
    unsafe {
        let process_group = libc::getpgrp();
        let _ = libc::kill(-process_group, libc::SIGKILL);
        libc::_exit(OWNER_EXIT_CODE as i32);
    }
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
    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    use std::num::NonZeroU32;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    use super::open;
    use super::VmCompletion;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn opens_the_exact_live_owner_process() {
        let process = open(NonZeroU32::new(std::process::id()).expect("nonzero process ID"))
            .expect("open current process");
        // SAFETY: `process` is live and a zero timeout only inspects its state.
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn rejects_a_missing_owner_process() {
        assert!(open(NonZeroU32::new(u32::MAX).expect("nonzero process ID")).is_err());
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn opens_the_exact_direct_linux_parent() {
        use std::os::unix::process::CommandExt;

        const OWNER_PID_ENV: &str = "A3S_OCI_TEST_OWNER_PID";
        const CHILD_TEST: &str = "owner_process::tests::linux_owner_child";

        let output = std::process::Command::new(
            std::env::current_exe().expect("resolve owner-monitor test executable"),
        )
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(OWNER_PID_ENV, std::process::id().to_string())
        .process_group(0)
        .output()
        .expect("spawn isolated owner-monitor test child");
        assert!(
            output.status.success(),
            "owner-monitor test child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn linux_owner_child() {
        use std::os::fd::AsRawFd;

        let Ok(owner_pid) = std::env::var("A3S_OCI_TEST_OWNER_PID") else {
            return;
        };
        std::env::remove_var("A3S_OCI_TEST_OWNER_PID");
        let owner_pid = owner_pid
            .parse::<u32>()
            .ok()
            .and_then(NonZeroU32::new)
            .expect("valid direct parent process ID");
        let owner = open(owner_pid).expect("pin exact direct parent with pidfd");
        let mut descriptor = libc::pollfd {
            fd: owner.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd and zero performs
        // a nonblocking liveness check.
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 0) }, 0);
    }

    #[test]
    fn observes_a_finished_vm_without_waiting_for_the_grace_timeout() {
        let completion = VmCompletion::new();
        completion.mark_finished();
        assert!(completion.wait(Duration::ZERO));
    }
}
