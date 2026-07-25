use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::join::validate_namespace_type;
use super::user::install_idmap_user_mappings;
use super::IdMapping;

const HELPER_READY: u8 = 1;
const HELPER_ERROR: u8 = 2;
const HELPER_RELEASE: u8 = 3;
const HELPER_MESSAGE_BYTES: usize = 1 + size_of::<i32>();

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::executor) struct IdmapPlan {
    pub(in crate::executor) recursive: bool,
    pub(in crate::executor) uid_mappings: Vec<IdMapping>,
    pub(in crate::executor) gid_mappings: Vec<IdMapping>,
}

impl IdmapPlan {
    pub(in crate::executor) fn container(
        recursive: bool,
        uid_mappings: &[IdMapping],
        gid_mappings: &[IdMapping],
    ) -> Self {
        Self {
            recursive,
            uid_mappings: uid_mappings.to_vec(),
            gid_mappings: gid_mappings.to_vec(),
        }
    }

    pub(in crate::executor) fn dedicated(
        recursive: bool,
        uid_mappings: Vec<IdMapping>,
        gid_mappings: Vec<IdMapping>,
    ) -> Self {
        Self {
            recursive,
            uid_mappings,
            gid_mappings,
        }
    }

    fn mapping_key(&self) -> IdmapMappingKey {
        IdmapMappingKey {
            uid_mappings: self.uid_mappings.clone(),
            gid_mappings: self.gid_mappings.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IdmapMappingKey {
    uid_mappings: Vec<IdMapping>,
    gid_mappings: Vec<IdMapping>,
}

#[derive(Debug, Default)]
pub(in crate::executor) struct IdmapNamespaceHandles {
    namespaces: BTreeMap<IdmapMappingKey, File>,
}

impl IdmapNamespaceHandles {
    pub(in crate::executor) fn prepare<'a>(
        plans: impl IntoIterator<Item = &'a IdmapPlan>,
    ) -> Result<Self> {
        let plans = plans.into_iter().collect::<Vec<_>>();
        let mappings = deduplicated_mappings(plans.iter().copied());
        let mut namespaces = BTreeMap::new();
        for mapping in mappings {
            let namespace = create_mapping_namespace(&mapping)?;
            namespaces.insert(mapping, namespace);
        }
        Ok(Self { namespaces })
    }

    pub(in crate::executor) fn namespace_fd(&self, plan: &IdmapPlan) -> Result<libc::c_int> {
        let namespace = self.namespaces.get(&plan.mapping_key()).ok_or_else(|| {
            idmap_error(
                ErrorCode::FailedPrecondition,
                "the ID-mapping user namespace was not retained",
            )
        })?;
        Ok(namespace.as_raw_fd())
    }
}

fn deduplicated_mappings<'a>(
    plans: impl IntoIterator<Item = &'a IdmapPlan>,
) -> BTreeSet<IdmapMappingKey> {
    plans.into_iter().map(IdmapPlan::mapping_key).collect()
}

fn create_mapping_namespace(mapping: &IdmapMappingKey) -> Result<File> {
    let (mut parent, mut child) = UnixStream::pair().map_err(|error| {
        idmap_error(
            ErrorCode::Internal,
            format!("failed to create ID-mapping namespace helper channel: {error}"),
        )
    })?;
    // SAFETY: getpid has no preconditions.
    let expected_parent = unsafe { libc::getpid() };
    // SAFETY: this path runs in the dedicated, single-threaded container-init
    // wrapper before it enters any container namespaces.
    let helper_pid = unsafe { libc::fork() };
    if helper_pid < 0 {
        return Err(idmap_last_os_error("fork ID-mapping user namespace helper"));
    }
    if helper_pid == 0 {
        drop(parent);
        mapping_namespace_helper(&mut child, expected_parent);
    }

    drop(child);
    let mut message = [0_u8; HELPER_MESSAGE_BYTES];
    if let Err(error) = parent.read_exact(&mut message) {
        terminate_and_reap(helper_pid);
        return Err(idmap_error(
            ErrorCode::Internal,
            format!("ID-mapping namespace helper did not report readiness: {error}"),
        ));
    }
    if message[0] != HELPER_READY {
        let reported = i32::from_be_bytes(
            message[1..]
                .try_into()
                .expect("fixed helper error payload length"),
        );
        terminate_and_reap(helper_pid);
        if message[0] != HELPER_ERROR || reported <= 0 {
            return Err(idmap_error(
                ErrorCode::Internal,
                format!(
                    "ID-mapping namespace helper reported malformed status {} and errno \
                     {reported}",
                    message[0]
                ),
            ));
        }
        let error = io::Error::from_raw_os_error(reported);
        return Err(idmap_error(
            error_code(&error),
            format!("ID-mapping namespace helper failed before readiness: {error}"),
        ));
    }

    let prepared = (|| {
        install_idmap_user_mappings(helper_pid, &mapping.uid_mappings, &mapping.gid_mappings)?;
        let path = format!("/proc/{helper_pid}/ns/user");
        let namespace = File::open(&path).map_err(|error| {
            idmap_error(
                error_code(&error),
                format!("failed to retain ID-mapping user namespace {path}: {error}"),
            )
        })?;
        validate_namespace_type(
            "ID-mapping user",
            Path::new(&path),
            &namespace,
            libc::CLONE_NEWUSER,
        )?;
        ensure_distinct_user_namespace(&namespace)?;
        Ok(namespace)
    })();
    let namespace = match prepared {
        Ok(namespace) => namespace,
        Err(error) => {
            terminate_and_reap(helper_pid);
            return Err(error);
        }
    };

    if let Err(error) = parent.write_all(&[HELPER_RELEASE]) {
        terminate_and_reap(helper_pid);
        return Err(idmap_error(
            ErrorCode::Internal,
            format!("failed to release ID-mapping namespace helper: {error}"),
        ));
    }
    drop(parent);
    match wait_for_helper(helper_pid)? {
        HelperOutcome::Exited(0) => Ok(namespace),
        outcome => Err(idmap_error(
            ErrorCode::Internal,
            format!("ID-mapping namespace helper returned {outcome:?}"),
        )),
    }
}

fn mapping_namespace_helper(channel: &mut UnixStream, expected_parent: libc::pid_t) -> ! {
    // SAFETY: prctl and unshare receive only integer arguments and this helper
    // is a single-threaded fork child that exits without returning to Rust
    // caller code.
    let result = unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            Err(io::Error::last_os_error())
        } else if libc::getppid() != expected_parent {
            Err(io::Error::from_raw_os_error(libc::ESRCH))
        } else if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    if let Err(error) = result {
        let errno = error.raw_os_error().unwrap_or(libc::EIO);
        let mut message = [0_u8; HELPER_MESSAGE_BYTES];
        message[0] = HELPER_ERROR;
        message[1..].copy_from_slice(&errno.to_be_bytes());
        let _ = channel.write_all(&message);
        unsafe { libc::_exit(125) }
    }

    let mut message = [0_u8; HELPER_MESSAGE_BYTES];
    message[0] = HELPER_READY;
    if channel.write_all(&message).is_err() {
        unsafe { libc::_exit(126) }
    }
    let mut release = [0_u8; 1];
    if channel.read_exact(&mut release).is_err() || release[0] != HELPER_RELEASE {
        unsafe { libc::_exit(127) }
    }
    unsafe { libc::_exit(0) }
}

fn ensure_distinct_user_namespace(namespace: &File) -> Result<()> {
    let current = File::open("/proc/self/ns/user").map_err(|error| {
        idmap_error(
            ErrorCode::Internal,
            format!("failed to inspect the runtime user namespace: {error}"),
        )
    })?;
    let namespace = namespace.metadata().map_err(|error| {
        idmap_error(
            ErrorCode::Internal,
            format!("failed to inspect the retained ID-mapping namespace: {error}"),
        )
    })?;
    let current = current.metadata().map_err(|error| {
        idmap_error(
            ErrorCode::Internal,
            format!("failed to inspect the runtime user namespace: {error}"),
        )
    })?;
    use std::os::linux::fs::MetadataExt;
    if namespace.st_dev() == current.st_dev() && namespace.st_ino() == current.st_ino() {
        Err(idmap_error(
            ErrorCode::PermissionDenied,
            "ID-mapping helper did not enter a distinct user namespace",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperOutcome {
    Exited(i32),
    Signaled(i32),
}

fn wait_for_helper(pid: libc::pid_t) -> Result<HelperOutcome> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable and pid is the positive child returned by
        // fork.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            if libc::WIFEXITED(status) {
                return Ok(HelperOutcome::Exited(libc::WEXITSTATUS(status)));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(HelperOutcome::Signaled(libc::WTERMSIG(status)));
            }
            return Err(idmap_error(
                ErrorCode::Internal,
                format!("ID-mapping namespace helper returned wait status {status:#x}"),
            ));
        }
        let error = io::Error::last_os_error();
        if waited < 0 && error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(idmap_error(
            ErrorCode::Internal,
            format!("failed to reap ID-mapping namespace helper: {error}"),
        ));
    }
}

fn terminate_and_reap(pid: libc::pid_t) {
    if pid > 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = wait_for_helper(pid);
    }
}

fn idmap_last_os_error(operation: &str) -> Error {
    let error = io::Error::last_os_error();
    idmap_error(error_code(&error), format!("{operation} failed: {error}"))
}

fn error_code(error: &io::Error) -> ErrorCode {
    match error.raw_os_error() {
        Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => ErrorCode::Unsupported,
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        _ => ErrorCode::Internal,
    }
}

fn idmap_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-idmapped-mounts")
}

#[cfg(test)]
mod tests {
    use super::{deduplicated_mappings, error_code, IdmapPlan};
    use crate::executor::namespace::IdMapping;
    use a3s_oci_sdk::ErrorCode;

    fn mapping(container_id: u32, host_id: u32) -> IdMapping {
        IdMapping {
            container_id,
            host_id,
            size: 1,
        }
    }

    #[test]
    fn equivalent_dedicated_mapping_sets_share_one_namespace_key() {
        let first = IdmapPlan::dedicated(
            false,
            vec![mapping(0, 1000), mapping(1, 1001)],
            vec![mapping(0, 2000)],
        );
        let equivalent = IdmapPlan::dedicated(
            true,
            vec![mapping(0, 1000), mapping(1, 1001)],
            vec![mapping(0, 2000)],
        );
        let container = IdmapPlan::container(
            false,
            &[mapping(0, 1000), mapping(1, 1001)],
            &[mapping(0, 2000)],
        );

        let unique = deduplicated_mappings([&first, &equivalent, &container]);
        assert_eq!(unique.len(), 1);
    }

    #[test]
    fn namespace_setup_errors_have_stable_types() {
        assert_eq!(
            error_code(&std::io::Error::from_raw_os_error(libc::ENOSYS)),
            ErrorCode::Unsupported
        );
        assert_eq!(
            error_code(&std::io::Error::from_raw_os_error(libc::EPERM)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            error_code(&std::io::Error::from_raw_os_error(libc::EIO)),
            ErrorCode::Internal
        );
    }
}
