use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::device::{DevicePlan, LoadedDeviceProgram, ROOTLESS_DEVICE_MOUNT_COUNT};
use super::pidfd::PidFd;
use mount::{open_rootless_device_sources, prepare_device_mounts, verify_prepared_device_mounts};
use protocol::{
    read_message, receive_device_mounts, send_device_mounts, write_message, DevicePolicyRequest,
    DevicePolicyResponse,
};

mod mount;
mod protocol;

const DEVICE_POLICY_SCHEMA_VERSION: &str = "a3s.oci.rootless-device-policy.v2";
const MAX_DEVICE_POLICY_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_DEVICE_POLICY_KEY_BYTES: usize = 512;
const MAX_DEVICE_POLICY_PATH_BYTES: usize = 4_096;
const DEVICE_POLICY_OPERATION: &str = "rootless-device-policy";
const HELPER_GRACEFUL_EXIT_TIMEOUT: Duration = Duration::from_millis(500);
const HELPER_TERMINATE_TIMEOUT: Duration = Duration::from_millis(250);
const HELPER_WAIT_INTERVAL: Duration = Duration::from_millis(10);

/// A privileged, parent-bound authority for rootless cgroup-device policy.
///
/// The authority owns one descriptor for the exact delegated cgroup root and
/// accepts only structured device plans plus normalized paths below that
/// descriptor. It never accepts a filesystem root, absolute cgroup path, BPF
/// bytecode, or caller-supplied program descriptor.
#[derive(Clone)]
pub(super) struct DevicePolicyAuthority {
    inner: Arc<AuthorityInner>,
}

struct AuthorityInner {
    transport: Mutex<Option<UnixStream>>,
    helper: Option<HelperProcess>,
    available: AtomicBool,
    shutdown_started: AtomicBool,
}

struct HelperProcess {
    pid: libc::pid_t,
    pidfd: PidFd,
    status: Mutex<Option<i32>>,
    reap_lock: Mutex<()>,
}

impl std::fmt::Debug for DevicePolicyAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DevicePolicyAuthority")
            .field(
                "helper_pid",
                &self.inner.helper.as_ref().map(|helper| helper.pid),
            )
            .field("available", &self.inner.available.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl DevicePolicyAuthority {
    pub(super) fn spawn(delegated_root: OwnedFd) -> Result<Self> {
        verify_single_threaded_bootstrap()?;
        // SAFETY: getpid has no preconditions and the value is captured before
        // fork so the child cannot authenticate a later subreaper as owner.
        let expected_parent = unsafe { libc::getpid() };
        let (parent, child) = UnixStream::pair().map_err(|error| {
            policy_error(
                ErrorCode::Internal,
                format!("failed to create rootless device-policy channel: {error}"),
            )
        })?;
        // SAFETY: this constructor runs while the native executor is opened,
        // before it exposes itself to concurrent callers. The child executes
        // only the single-threaded helper loop and exits without unwinding.
        let helper_pid = unsafe { libc::fork() };
        if helper_pid < 0 {
            return Err(last_policy_error(
                ErrorCode::Internal,
                "fork rootless device-policy helper",
            ));
        }
        if helper_pid == 0 {
            drop(parent);
            let result = run_helper(child, delegated_root, expected_parent);
            let exit_code = match result {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("a3s-oci-agent: rootless device-policy helper: {error}");
                    1
                }
            };
            // SAFETY: this is the isolated fork child. `_exit` avoids running
            // inherited Rust destructors from the parent executor.
            unsafe { libc::_exit(exit_code) }
        }
        drop(child);
        drop(delegated_root);
        let pidfd = PidFd::open(helper_pid).inspect_err(|_| terminate_and_reap(helper_pid))?;
        let authority = Self {
            inner: Arc::new(AuthorityInner {
                transport: Mutex::new(Some(parent)),
                helper: Some(HelperProcess {
                    pid: helper_pid,
                    pidfd,
                    status: Mutex::new(None),
                    reap_lock: Mutex::new(()),
                }),
                available: AtomicBool::new(true),
                shutdown_started: AtomicBool::new(false),
            }),
        };
        if let Err(error) = authority.exchange(DevicePolicyRequest::Hello {
            schema_version: DEVICE_POLICY_SCHEMA_VERSION.to_string(),
            expected_helper_pid: helper_pid,
        }) {
            drop(authority);
            return Err(error);
        }
        Ok(authority)
    }

    pub(super) fn bootstrap_identity() -> Result<(u32, u32)> {
        // SAFETY: credential queries have no pointer arguments or failure result.
        let (uid, euid, gid, egid) = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        if uid == 0 || gid == 0 || euid != 0 || egid != 0 {
            return Err(policy_error(
                ErrorCode::InvalidArgument,
                format!(
                    "rootless device-policy bootstrap requires non-root real UID/GID with effective root; observed UID {uid}/{euid}, GID {gid}/{egid}"
                ),
            ));
        }
        // SAFETY: a zero-sized query accepts a null pointer and returns the
        // number of supplementary groups attached to this single thread.
        let supplementary_groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if supplementary_groups < 0 {
            return Err(last_policy_error(
                ErrorCode::FailedPrecondition,
                "inspect rootless device-policy bootstrap supplementary groups",
            ));
        }
        if supplementary_groups != 0 {
            return Err(policy_error(
                ErrorCode::PermissionDenied,
                format!(
                    "rootless device-policy bootstrap requires supplementary groups to be cleared; observed {supplementary_groups} group(s)"
                ),
            ));
        }
        Ok((uid, gid))
    }

    pub(super) fn drop_to_identity(uid: u32, gid: u32) -> Result<()> {
        if Self::bootstrap_identity()? != (uid, gid) {
            return Err(policy_error(
                ErrorCode::Conflict,
                "rootless device-policy bootstrap identity changed before privilege drop",
            ));
        }
        // SAFETY: the bootstrap is single-threaded and still has effective-root
        // group authority. Clear the complete supplementary set before dropping
        // the real/effective/saved group and user identities.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(last_policy_error(
                ErrorCode::PermissionDenied,
                "clear rootless device-policy parent supplementary groups",
            ));
        }
        // SAFETY: setresgid/setresuid receive validated scalar IDs. Setting all
        // three identities removes both effective privilege and the saved-root
        // credential before any untrusted OCI request is processed.
        if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
            return Err(last_policy_error(
                ErrorCode::PermissionDenied,
                "drop rootless device-policy parent group privilege",
            ));
        }
        // SAFETY: see above; group privilege has already been dropped.
        if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
            return Err(last_policy_error(
                ErrorCode::PermissionDenied,
                "drop rootless device-policy parent user privilege",
            ));
        }
        // SAFETY: credential queries have no pointer arguments or failure result.
        let (observed_uid, observed_euid, observed_gid, observed_egid) = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        // SAFETY: see the zero-sized supplementary-group query above.
        let supplementary_groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if observed_uid == uid
            && observed_euid == uid
            && observed_gid == gid
            && observed_egid == gid
            && supplementary_groups == 0
        {
            Ok(())
        } else {
            Err(policy_error(
                ErrorCode::PermissionDenied,
                "rootless device-policy parent retained unexpected credentials after privilege drop",
            ))
        }
    }

    pub(super) fn install(
        &self,
        key: &str,
        relative_cgroup: &Path,
        plan: &DevicePlan,
    ) -> Result<()> {
        self.exchange(DevicePolicyRequest::Install {
            key: validate_key(key)?.to_string(),
            relative_cgroup: validate_relative_cgroup(relative_cgroup)?,
            plan: plan.clone(),
        })
    }

    pub(super) fn replace(&self, key: &str, plan: &DevicePlan) -> Result<()> {
        self.exchange(DevicePolicyRequest::Replace {
            key: validate_key(key)?.to_string(),
            plan: plan.clone(),
        })
    }

    pub(super) fn remove(&self, key: &str) -> Result<()> {
        self.exchange(DevicePolicyRequest::Remove {
            key: validate_key(key)?.to_string(),
        })
    }

    pub(super) fn prepare_device_mounts(&self) -> Result<Vec<OwnedFd>> {
        if !self.inner.available.load(Ordering::Acquire) {
            return Err(self.unavailable_error());
        }
        let mut transport = self.inner.transport.lock().map_err(|_| {
            self.inner.available.store(false, Ordering::Release);
            self.unavailable_error()
        })?;
        let Some(transport) = transport.as_mut() else {
            self.inner.available.store(false, Ordering::Release);
            return Err(self.unavailable_error());
        };
        if let Err(error) = write_message(transport, &DevicePolicyRequest::PrepareMounts) {
            self.inner.available.store(false, Ordering::Release);
            return Err(self.transport_failure(error));
        }
        let response: DevicePolicyResponse = match read_message(transport) {
            Ok(response) => response,
            Err(error) => {
                self.inner.available.store(false, Ordering::Release);
                return Err(self.transport_failure(error));
            }
        };
        match response {
            DevicePolicyResponse::MountsPrepared { count }
                if count == ROOTLESS_DEVICE_MOUNT_COUNT => {}
            DevicePolicyResponse::Rejected(error) => {
                self.inner.available.store(false, Ordering::Release);
                return Err(self.transport_failure(error));
            }
            response => {
                self.inner.available.store(false, Ordering::Release);
                return Err(self.transport_failure(policy_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "rootless device-policy helper returned an invalid mount response: {response:?}"
                    ),
                )));
            }
        }
        let mounts = match receive_device_mounts(transport) {
            Ok(mounts) => mounts,
            Err(error) => {
                self.inner.available.store(false, Ordering::Release);
                return Err(self.transport_failure(error));
            }
        };
        if let Err(error) = verify_prepared_device_mounts(&mounts) {
            self.inner.available.store(false, Ordering::Release);
            return Err(self.transport_failure(error));
        }
        Ok(mounts)
    }

    fn exchange(&self, request: DevicePolicyRequest) -> Result<()> {
        if !self.inner.available.load(Ordering::Acquire) {
            return Err(self.unavailable_error());
        }
        let mut transport = self.inner.transport.lock().map_err(|_| {
            self.inner.available.store(false, Ordering::Release);
            self.unavailable_error()
        })?;
        let Some(transport) = transport.as_mut() else {
            self.inner.available.store(false, Ordering::Release);
            return Err(self.unavailable_error());
        };
        if let Err(error) = write_message(transport, &request) {
            self.inner.available.store(false, Ordering::Release);
            return Err(self.transport_failure(error));
        }
        let response: DevicePolicyResponse = match read_message(transport) {
            Ok(response) => response,
            Err(error) => {
                self.inner.available.store(false, Ordering::Release);
                return Err(self.transport_failure(error));
            }
        };
        match response {
            DevicePolicyResponse::Applied => Ok(()),
            DevicePolicyResponse::MountsPrepared { .. } => {
                self.inner.available.store(false, Ordering::Release);
                Err(self.transport_failure(policy_error(
                    ErrorCode::PermissionDenied,
                    "rootless device-policy helper returned mount descriptors for a policy mutation",
                )))
            }
            DevicePolicyResponse::Rejected(error) => Err(error),
        }
    }

    fn unavailable_error(&self) -> Error {
        let detail = self
            .inner
            .helper
            .as_ref()
            .and_then(HelperProcess::observe_exit)
            .map_or_else(
                || "helper channel is unavailable".to_string(),
                |status| format!("helper exited with {}", describe_wait_status(status)),
            );
        policy_error(
            ErrorCode::Unavailable,
            format!("rootless device-policy {detail}"),
        )
        .retryable(true)
    }

    fn transport_failure(&self, error: Error) -> Error {
        let unavailable = self.unavailable_error();
        policy_error(
            ErrorCode::Unavailable,
            format!("{}: {}", unavailable.message, error.message),
        )
        .retryable(true)
    }

    pub(super) fn shutdown(&self) -> Result<()> {
        if self.inner.shutdown_started.swap(true, Ordering::AcqRel) {
            if let Some(helper) = &self.inner.helper {
                helper.reap_bounded();
            }
            return Ok(());
        }
        let result = if self.inner.available.load(Ordering::Acquire) {
            self.exchange(DevicePolicyRequest::Shutdown)
        } else {
            Err(self.unavailable_error())
        };
        let mut transport = match self.inner.transport.lock() {
            Ok(transport) => transport,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(stream) = transport.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        self.inner.available.store(false, Ordering::Release);
        if let Some(helper) = &self.inner.helper {
            helper.reap_bounded();
        }
        result
    }

    #[cfg(test)]
    fn from_transport(transport: UnixStream) -> Self {
        Self {
            inner: Arc::new(AuthorityInner {
                transport: Mutex::new(Some(transport)),
                helper: None,
                available: AtomicBool::new(true),
                shutdown_started: AtomicBool::new(false),
            }),
        }
    }

    #[cfg(test)]
    fn helper_request(&self, request: DevicePolicyRequest) -> Result<()> {
        self.exchange(request)
    }
}

impl Drop for AuthorityInner {
    fn drop(&mut self) {
        self.available.store(false, Ordering::Release);
        let transport = match self.transport.get_mut() {
            Ok(transport) => transport,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(stream) = transport.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl HelperProcess {
    fn observe_exit(&self) -> Option<i32> {
        let mut status = match self.status.lock() {
            Ok(status) => status,
            Err(poisoned) => poisoned.into_inner(),
        };
        if status.is_some() {
            return *status;
        }
        loop {
            let mut observed = 0;
            // SAFETY: pid identifies the exact unreaped direct child and
            // observed points to writable wait-status storage.
            let waited = unsafe { libc::waitpid(self.pid, &mut observed, libc::WNOHANG) };
            if waited == self.pid {
                *status = Some(observed);
                return Some(observed);
            }
            if waited == 0 {
                return None;
            }
            if io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                continue;
            }
            return None;
        }
    }

    fn wait_until(&self, deadline: Instant) -> bool {
        loop {
            if self.observe_exit().is_some() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(HELPER_WAIT_INTERVAL);
        }
    }

    fn reap_bounded(&self) {
        let _reap = match self.reap_lock.lock() {
            Ok(reap) => reap,
            Err(poisoned) => poisoned.into_inner(),
        };
        if self.wait_until(Instant::now() + HELPER_GRACEFUL_EXIT_TIMEOUT) {
            return;
        }
        let _ = self.pidfd.send_signal(libc::SIGTERM);
        if self.wait_until(Instant::now() + HELPER_TERMINATE_TIMEOUT) {
            return;
        }
        let _ = self.pidfd.send_signal(libc::SIGKILL);
        loop {
            let mut observed = 0;
            // SAFETY: pid identifies the exact direct child retained through
            // pidfd and this final blocking wait runs only after SIGKILL.
            let waited = unsafe { libc::waitpid(self.pid, &mut observed, 0) };
            if waited == self.pid {
                let mut status = match self.status.lock() {
                    Ok(status) => status,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *status = Some(observed);
                break;
            }
            if waited < 0 && io::Error::last_os_error().kind() != ErrorKind::Interrupted {
                break;
            }
        }
    }
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        self.reap_bounded();
    }
}

fn verify_single_threaded_bootstrap() -> Result<()> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(policy_error(
            ErrorCode::FailedPrecondition,
            "rootless device-policy bootstrap must run before the async runtime is created",
        ));
    }
    let threads = std::fs::read_dir("/proc/self/task")
        .map_err(|error| {
            policy_error(
                ErrorCode::FailedPrecondition,
                format!("failed to inspect bootstrap thread count: {error}"),
            )
        })?
        .filter_map(std::result::Result::ok)
        .take(2)
        .count();
    if threads == 1 {
        Ok(())
    } else {
        Err(policy_error(
            ErrorCode::FailedPrecondition,
            "rootless device-policy bootstrap must run before any worker thread or async runtime is created",
        ))
    }
}

fn describe_wait_status(status: i32) -> String {
    if libc::WIFEXITED(status) {
        format!("status {}", libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        format!("signal {}", libc::WTERMSIG(status))
    } else {
        format!("wait status {status}")
    }
}

fn terminate_and_reap(pid: libc::pid_t) {
    // SAFETY: the PID is the positive direct child returned by fork. It cannot
    // be reused before this parent reaps it.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0
            && io::Error::last_os_error().kind() == ErrorKind::Interrupted
        {}
    }
}

#[derive(Debug)]
struct InstalledPolicy {
    cgroup: OwnedFd,
    program: LoadedDeviceProgram,
}

fn run_helper(
    mut transport: UnixStream,
    delegated_root: OwnedFd,
    expected_parent: libc::pid_t,
) -> Result<()> {
    let parent = PidFd::open(expected_parent)?;
    verify_parent_identity(expected_parent)?;
    verify_privileged_helper_identity()?;
    verify_cgroup2_descriptor(&delegated_root)?;
    let device_sources = open_rootless_device_sources()?;

    let actual_pid = i32::try_from(std::process::id()).map_err(|error| {
        policy_error(
            ErrorCode::ResourceExhausted,
            format!("device-policy helper PID does not fit pid_t: {error}"),
        )
    })?;
    validate_hello(read_message(&mut transport)?, actual_pid)?;
    write_message(&mut transport, &DevicePolicyResponse::Applied)?;

    let mut policies = BTreeMap::new();
    (|| -> Result<()> {
        transport.set_nonblocking(true).map_err(|error| {
            policy_error(
                ErrorCode::Internal,
                format!("failed to make rootless device-policy channel nonblocking: {error}"),
            )
        })?;
        loop {
            match wait_for_helper_input(&transport, &parent)? {
                HelperInput::Request => {}
                HelperInput::ParentExited | HelperInput::ChannelClosed => {
                    // An unexpected owner or channel loss must fail closed. Do
                    // not detach active policies: closing the program FDs leaves
                    // their cgroup attachments enforced until recovery removes
                    // the protected cgroups.
                    return Ok(());
                }
            }
            transport.set_nonblocking(false).map_err(|error| {
                policy_error(
                    ErrorCode::Internal,
                    format!("failed to read rootless device-policy request: {error}"),
                )
            })?;
            let request = read_message::<DevicePolicyRequest>(&mut transport)?;
            if matches!(&request, DevicePolicyRequest::Shutdown) {
                let cleanup = cleanup_all(&mut policies);
                let response = match &cleanup {
                    Ok(()) => DevicePolicyResponse::Applied,
                    Err(error) => DevicePolicyResponse::Rejected(error.clone()),
                };
                write_message(&mut transport, &response)?;
                return cleanup;
            }
            if matches!(&request, DevicePolicyRequest::PrepareMounts) {
                let result = prepare_device_mounts(&device_sources);
                match result {
                    Ok(mounts) => {
                        write_message(
                            &mut transport,
                            &DevicePolicyResponse::MountsPrepared {
                                count: mounts.len(),
                            },
                        )?;
                        send_device_mounts(&transport, &mounts)?;
                    }
                    Err(error) => {
                        write_message(&mut transport, &DevicePolicyResponse::Rejected(error))?;
                    }
                }
                transport.set_nonblocking(true).map_err(|error| {
                    policy_error(
                        ErrorCode::Internal,
                        format!("failed to resume rootless device-policy monitoring: {error}"),
                    )
                })?;
                continue;
            }
            let result = apply_request(&delegated_root, &mut policies, request);
            let response = match result {
                Ok(()) => DevicePolicyResponse::Applied,
                Err(error) => DevicePolicyResponse::Rejected(error),
            };
            write_message(&mut transport, &response)?;
            transport.set_nonblocking(true).map_err(|error| {
                policy_error(
                    ErrorCode::Internal,
                    format!("failed to resume rootless device-policy monitoring: {error}"),
                )
            })?;
        }
    })()
}

fn validate_hello(request: DevicePolicyRequest, actual_pid: libc::pid_t) -> Result<()> {
    let DevicePolicyRequest::Hello {
        schema_version,
        expected_helper_pid,
    } = request
    else {
        return Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device-policy helper requires an authenticated hello before mutations",
        ));
    };
    if schema_version != DEVICE_POLICY_SCHEMA_VERSION {
        return Err(policy_error(
            ErrorCode::FailedPrecondition,
            format!("unsupported rootless device-policy schema {schema_version:?}"),
        ));
    }
    if actual_pid != expected_helper_pid {
        return Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device-policy hello did not identify the receiving helper",
        ));
    }
    Ok(())
}

enum HelperInput {
    Request,
    ParentExited,
    ChannelClosed,
}

fn verify_parent_identity(expected_parent: libc::pid_t) -> Result<()> {
    // SAFETY: getppid has no preconditions.
    let observed_parent = unsafe { libc::getppid() };
    if observed_parent == expected_parent {
        Ok(())
    } else {
        Err(policy_error(
            ErrorCode::PermissionDenied,
            format!(
                "rootless device-policy helper parent changed from {expected_parent} to {observed_parent} during bootstrap"
            ),
        ))
    }
}

fn wait_for_helper_input(transport: &UnixStream, parent: &PidFd) -> Result<HelperInput> {
    let mut descriptors = [
        libc::pollfd {
            fd: transport.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        },
        libc::pollfd {
            fd: parent.raw_descriptor(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        },
    ];
    loop {
        // SAFETY: descriptors points to two initialized pollfd values.
        let ready = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as u64, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(policy_error(
                ErrorCode::Internal,
                format!("failed to monitor rootless device-policy ownership: {error}"),
            ));
        }
        if descriptors[1].revents != 0 {
            return Ok(HelperInput::ParentExited);
        }
        if descriptors[0].revents & libc::POLLIN != 0 {
            return Ok(HelperInput::Request);
        }
        if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(HelperInput::ChannelClosed);
        }
    }
}

fn apply_request(
    delegated_root: &OwnedFd,
    policies: &mut BTreeMap<String, InstalledPolicy>,
    request: DevicePolicyRequest,
) -> Result<()> {
    match request {
        DevicePolicyRequest::Hello { .. } => Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device-policy hello cannot be replayed",
        )),
        DevicePolicyRequest::Install {
            key,
            relative_cgroup,
            plan,
        } => {
            validate_key(&key)?;
            let relative_cgroup = validate_relative_cgroup(&relative_cgroup)?;
            if policies.contains_key(&key) {
                return Err(policy_error(
                    ErrorCode::AlreadyExists,
                    format!("rootless device-policy key {key:?} is already installed"),
                ));
            }
            if !plan.requires_setup() {
                return Err(policy_error(
                    ErrorCode::InvalidArgument,
                    "rootless device-policy install requires an active allowlist",
                ));
            }
            let cgroup = open_cgroup_beneath(delegated_root, &relative_cgroup)?;
            let program = plan.load_device_program()?;
            program.attach_to_fd(cgroup.as_raw_fd())?;
            policies.insert(key, InstalledPolicy { cgroup, program });
            Ok(())
        }
        DevicePolicyRequest::Replace { key, plan } => {
            validate_key(&key)?;
            let installed = policies.get(&key).ok_or_else(|| {
                policy_error(
                    ErrorCode::NotFound,
                    format!("rootless device-policy key {key:?} is not installed"),
                )
            })?;
            if !plan.requires_setup() {
                installed
                    .program
                    .detach_from_fd(installed.cgroup.as_raw_fd())?;
                policies.remove(&key);
                return Ok(());
            }
            let replacement = plan.load_device_program()?;
            replacement.replace_on_fd(installed.cgroup.as_raw_fd(), &installed.program)?;
            let installed = policies.get_mut(&key).ok_or_else(|| {
                policy_error(
                    ErrorCode::Internal,
                    "rootless device-policy state changed during a serialized replacement",
                )
            })?;
            installed.program = replacement;
            Ok(())
        }
        DevicePolicyRequest::Remove { key } => {
            validate_key(&key)?;
            let installed = policies.get(&key).ok_or_else(|| {
                policy_error(
                    ErrorCode::NotFound,
                    format!("rootless device-policy key {key:?} is not installed"),
                )
            })?;
            installed
                .program
                .detach_from_fd(installed.cgroup.as_raw_fd())?;
            policies.remove(&key);
            Ok(())
        }
        DevicePolicyRequest::PrepareMounts => Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device mount preparation must be handled by the authenticated service loop",
        )),
        DevicePolicyRequest::Shutdown => Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device-policy shutdown must be handled by the authenticated service loop",
        )),
    }
}

fn cleanup_all(policies: &mut BTreeMap<String, InstalledPolicy>) -> Result<()> {
    let mut failures = Vec::new();
    for (key, installed) in std::mem::take(policies) {
        if let Err(error) = installed
            .program
            .detach_from_fd(installed.cgroup.as_raw_fd())
        {
            failures.push(format!("{key}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(policy_error(
            ErrorCode::Internal,
            format!(
                "failed to clean up rootless device policies: {}",
                failures.join("; ")
            ),
        ))
    }
}

fn validate_key(key: &str) -> Result<&str> {
    if key.is_empty()
        || key.len() > MAX_DEVICE_POLICY_KEY_BYTES
        || key.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
    {
        Err(policy_error(
            ErrorCode::InvalidArgument,
            format!(
                "rootless device-policy key must contain 1..={MAX_DEVICE_POLICY_KEY_BYTES} non-control bytes"
            ),
        ))
    } else {
        Ok(key)
    }
}

fn validate_relative_cgroup(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_DEVICE_POLICY_PATH_BYTES
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device-policy cgroup path must be a normalized relative path below the delegated root",
        ));
    }
    Ok(path.to_path_buf())
}

fn open_cgroup_beneath(root: &OwnedFd, relative: &Path) -> Result<OwnedFd> {
    let relative = validate_relative_cgroup(relative)?;
    let path =
        std::ffi::CString::new(relative.as_os_str().as_encoded_bytes()).map_err(|error| {
            policy_error(
                ErrorCode::InvalidArgument,
                format!("rootless device-policy cgroup path contains NUL: {error}"),
            )
        })?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero initializes every current open_how field.
    let how = unsafe { how.assume_init_mut() };
    // BPF_PROG_ATTACH requires a cgroup file descriptor backed by the cgroup
    // file operations; an O_PATH descriptor is sufficient as the trusted
    // openat2 dirfd above, but not as the attachment target itself.
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64;
    how.resolve = libc::RESOLVE_BENEATH
        | libc::RESOLVE_NO_MAGICLINKS
        | libc::RESOLVE_NO_SYMLINKS
        | libc::RESOLVE_NO_XDEV;
    // SAFETY: the root descriptor and NUL-terminated path are live for the
    // syscall and `how` has the exact userspace ABI size.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        let code = match error.raw_os_error() {
            Some(code) if code == libc::EXDEV || code == libc::ELOOP => ErrorCode::PermissionDenied,
            Some(libc::ENOENT) => ErrorCode::NotFound,
            _ => ErrorCode::FailedPrecondition,
        };
        return Err(policy_error(
            code,
            format!(
                "failed to open rootless device-policy cgroup {} below the delegated descriptor: {error}",
                relative.display()
            ),
        ));
    }
    let descriptor = i32::try_from(descriptor).map_err(|error| {
        policy_error(
            ErrorCode::Internal,
            format!("openat2 returned an invalid cgroup descriptor: {error}"),
        )
    })?;
    // SAFETY: openat2 returned a fresh owned descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    verify_cgroup2_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn verify_cgroup2_descriptor(descriptor: &OwnedFd) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: the descriptor is live and stat points to writable storage.
    if unsafe { libc::fstatfs(descriptor.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(last_policy_error(
            ErrorCode::FailedPrecondition,
            "inspect rootless device-policy cgroup filesystem",
        ));
    }
    // SAFETY: fstatfs succeeded and initialized stat.
    let stat = unsafe { stat.assume_init() };
    if i128::from(stat.f_type) != 0x6367_7270_i128 {
        return Err(policy_error(
            ErrorCode::PermissionDenied,
            "rootless device-policy descriptor is not on cgroup v2",
        ));
    }
    Ok(())
}

fn verify_privileged_helper_identity() -> Result<()> {
    // SAFETY: credential queries have no pointer arguments or failure result.
    let (uid, euid, gid, egid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if uid != 0 && gid != 0 && euid == 0 && egid == 0 {
        Ok(())
    } else {
        Err(policy_error(
            ErrorCode::PermissionDenied,
            format!(
                "rootless device-policy helper requires non-root real UID/GID with effective root; observed UID {uid}/{euid}, GID {gid}/{egid}"
            ),
        ))
    }
}

fn last_policy_error(code: ErrorCode, action: &str) -> Error {
    policy_error(
        code,
        format!("failed to {action}: {}", io::Error::last_os_error()),
    )
}

fn policy_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation(DEVICE_POLICY_OPERATION)
}

#[cfg(test)]
mod tests;
