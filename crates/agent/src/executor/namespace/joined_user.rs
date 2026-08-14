use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use a3s_oci_sdk::{ErrorCode, Result};

use super::join::validate_namespace_type;
use super::user::parse_mapping_file;
use super::{namespace_error, IdMapping};

const HELPER_SUCCESS: u8 = 1;
const HELPER_ERROR: u8 = 2;
const HELPER_HEADER_BYTES: usize = 1 + size_of::<u32>() + size_of::<u32>();
const MAX_MAPPING_FILE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct JoinedUserNamespaceIdentity {
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone)]
pub(super) struct JoinedUserNamespaceAuthority {
    namespace: Arc<File>,
    identity: JoinedUserNamespaceIdentity,
}

pub(super) struct ObservedJoinedUserNamespace {
    pub(super) authority: JoinedUserNamespaceAuthority,
    pub(super) uid_mappings: Vec<IdMapping>,
    pub(super) gid_mappings: Vec<IdMapping>,
}

impl PartialEq for JoinedUserNamespaceAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for JoinedUserNamespaceAuthority {}

impl JoinedUserNamespaceAuthority {
    fn retain(namespace: File) -> Result<Self> {
        let identity = JoinedUserNamespaceIdentity::capture(&namespace)?;
        Ok(Self {
            namespace: Arc::new(namespace),
            identity,
        })
    }

    pub(super) fn verify(&self, path: &Path, namespace: &File) -> Result<()> {
        if self.identity.matches(namespace)? {
            Ok(())
        } else {
            Err(joined_error(
                ErrorCode::PermissionDenied,
                format!(
                    "joined user namespace identity changed after authority inspection: {}",
                    path.display()
                ),
            ))
        }
    }
}

impl JoinedUserNamespaceIdentity {
    fn capture(namespace: &File) -> Result<Self> {
        let metadata = namespace.metadata().map_err(|error| {
            joined_error(
                error_code(&error),
                format!("failed to inspect retained joined user namespace: {error}"),
            )
        })?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }

    fn matches(&self, namespace: &File) -> Result<bool> {
        let observed = Self::capture(namespace)?;
        Ok(*self == observed)
    }
}

pub(super) fn observe(path: &Path) -> Result<ObservedJoinedUserNamespace> {
    let namespace = File::open(path).map_err(|error| {
        joined_error(
            error_code(&error),
            format!(
                "failed to open joined user namespace {} for authority inspection: {error}",
                path.display()
            ),
        )
    })?;
    validate_namespace_type("user", path, &namespace, libc::CLONE_NEWUSER)?;
    let authority = JoinedUserNamespaceAuthority::retain(namespace)?;
    let current = File::open("/proc/self/ns/user").map_err(|error| {
        joined_error(
            ErrorCode::Internal,
            format!("failed to retain the executor user namespace: {error}"),
        )
    })?;
    let (uid_map, gid_map) = if authority.identity.matches(&current)? {
        (
            read_mapping_file(Path::new("/proc/self/uid_map"))?,
            read_mapping_file(Path::new("/proc/self/gid_map"))?,
        )
    } else {
        read_mappings_in_namespace(&authority)?
    };
    Ok(ObservedJoinedUserNamespace {
        authority,
        uid_mappings: parse_mapping_file(Path::new("joined-user/uid_map"), &uid_map)?,
        gid_mappings: parse_mapping_file(Path::new("joined-user/gid_map"), &gid_map)?,
    })
}

fn read_mappings_in_namespace(
    authority: &JoinedUserNamespaceAuthority,
) -> Result<(String, String)> {
    let (mut parent, child) = UnixStream::pair().map_err(|error| {
        joined_error(
            ErrorCode::Internal,
            format!("failed to create joined user namespace helper channel: {error}"),
        )
    })?;
    // SAFETY: this runs in the dedicated single-threaded container-init
    // wrapper before it enters container namespaces or starts workload code.
    let helper_pid = unsafe { libc::fork() };
    if helper_pid < 0 {
        return Err(last_joined_error(
            "fork joined user namespace mapping helper",
        ));
    }
    if helper_pid == 0 {
        drop(parent);
        mapping_helper(child, authority.namespace.as_raw_fd(), &authority.identity);
    }
    drop(child);

    let mut header = [0_u8; HELPER_HEADER_BYTES];
    if let Err(error) = parent.read_exact(&mut header) {
        terminate_and_reap(helper_pid);
        return Err(joined_error(
            ErrorCode::Internal,
            format!("joined user namespace mapping helper returned no header: {error}"),
        ));
    }
    if header[0] == HELPER_ERROR {
        let errno = i32::from_be_bytes(
            header[1..1 + size_of::<u32>()]
                .try_into()
                .expect("fixed joined-user helper errno length"),
        );
        let outcome = wait_for_helper(helper_pid)?;
        if errno <= 0 || !matches!(outcome, HelperOutcome::Exited(125)) {
            return Err(joined_error(
                ErrorCode::Internal,
                format!(
                    "joined user namespace mapping helper returned malformed error {errno} and {outcome:?}"
                ),
            ));
        }
        let error = io::Error::from_raw_os_error(errno);
        return Err(joined_error(
            error_code(&error),
            format!("joined user namespace mapping helper failed: {error}"),
        ));
    }
    if header[0] != HELPER_SUCCESS {
        terminate_and_reap(helper_pid);
        return Err(joined_error(
            ErrorCode::Internal,
            format!(
                "joined user namespace mapping helper returned unknown status {}",
                header[0]
            ),
        ));
    }
    let uid_length = u32::from_be_bytes(
        header[1..1 + size_of::<u32>()]
            .try_into()
            .expect("fixed UID mapping length"),
    ) as usize;
    let gid_length = u32::from_be_bytes(
        header[1 + size_of::<u32>()..]
            .try_into()
            .expect("fixed GID mapping length"),
    ) as usize;
    if uid_length == 0
        || gid_length == 0
        || uid_length > MAX_MAPPING_FILE_BYTES
        || gid_length > MAX_MAPPING_FILE_BYTES
    {
        terminate_and_reap(helper_pid);
        return Err(joined_error(
            ErrorCode::ResourceExhausted,
            format!(
                "joined user namespace mapping helper returned invalid lengths {uid_length}/{gid_length}"
            ),
        ));
    }
    let mut uid_map = vec![0_u8; uid_length];
    let mut gid_map = vec![0_u8; gid_length];
    if let Err(error) = parent
        .read_exact(&mut uid_map)
        .and_then(|()| parent.read_exact(&mut gid_map))
    {
        terminate_and_reap(helper_pid);
        return Err(joined_error(
            ErrorCode::Internal,
            format!("joined user namespace mapping helper payload was truncated: {error}"),
        ));
    }
    let outcome = wait_for_helper(helper_pid)?;
    if !matches!(outcome, HelperOutcome::Exited(0)) {
        return Err(joined_error(
            ErrorCode::Internal,
            format!("joined user namespace mapping helper returned {outcome:?}"),
        ));
    }
    let uid_map = String::from_utf8(uid_map).map_err(|error| {
        joined_error(
            ErrorCode::FailedPrecondition,
            format!("joined user namespace UID mappings are not UTF-8: {error}"),
        )
    })?;
    let gid_map = String::from_utf8(gid_map).map_err(|error| {
        joined_error(
            ErrorCode::FailedPrecondition,
            format!("joined user namespace GID mappings are not UTF-8: {error}"),
        )
    })?;
    Ok((uid_map, gid_map))
}

fn mapping_helper(
    mut channel: UnixStream,
    namespace: libc::c_int,
    identity: &JoinedUserNamespaceIdentity,
) -> ! {
    // SAFETY: all calls use integer arguments or live descriptors. This fork
    // child exits with `_exit` and never returns into the Rust caller.
    let expected_parent = unsafe { libc::getppid() };
    let result = (|| -> io::Result<(Vec<u8>, Vec<u8>)> {
        arm_parent_death(expected_parent)?;
        if unsafe { libc::setns(namespace, libc::CLONE_NEWUSER) } != 0 {
            return Err(io::Error::last_os_error());
        }
        arm_parent_death(expected_parent)?;
        let current = File::open("/proc/self/ns/user")?;
        let metadata = current.metadata()?;
        if metadata.dev() != identity.dev || metadata.ino() != identity.ino {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok((
            read_mapping_bytes(Path::new("/proc/self/uid_map"))?,
            read_mapping_bytes(Path::new("/proc/self/gid_map"))?,
        ))
    })();
    match result {
        Ok((uid_map, gid_map)) => {
            let mut header = [0_u8; HELPER_HEADER_BYTES];
            header[0] = HELPER_SUCCESS;
            header[1..1 + size_of::<u32>()].copy_from_slice(&(uid_map.len() as u32).to_be_bytes());
            header[1 + size_of::<u32>()..].copy_from_slice(&(gid_map.len() as u32).to_be_bytes());
            if channel
                .write_all(&header)
                .and_then(|()| channel.write_all(&uid_map))
                .and_then(|()| channel.write_all(&gid_map))
                .is_ok()
            {
                unsafe { libc::_exit(0) }
            }
            unsafe { libc::_exit(126) }
        }
        Err(error) => {
            let errno = error.raw_os_error().unwrap_or(libc::EIO);
            let mut header = [0_u8; HELPER_HEADER_BYTES];
            header[0] = HELPER_ERROR;
            header[1..1 + size_of::<u32>()].copy_from_slice(&errno.to_be_bytes());
            let _ = channel.write_all(&header);
            unsafe { libc::_exit(125) }
        }
    }
}

fn arm_parent_death(expected_parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: PR_SET_PDEATHSIG receives only integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getppid has no preconditions.
    if unsafe { libc::getppid() } != expected_parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

fn read_mapping_file(path: &Path) -> Result<String> {
    let bytes = read_mapping_bytes(path).map_err(|error| {
        joined_error(
            error_code(&error),
            format!(
                "failed to read joined user namespace mapping {}: {error}",
                path.display()
            ),
        )
    })?;
    String::from_utf8(bytes).map_err(|error| {
        joined_error(
            ErrorCode::FailedPrecondition,
            format!(
                "joined user namespace mapping {} is not UTF-8: {error}",
                path.display()
            ),
        )
    })
}

fn read_mapping_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_MAPPING_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MAPPING_FILE_BYTES {
        Err(io::Error::from_raw_os_error(libc::EFBIG))
    } else {
        Ok(bytes)
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
        // SAFETY: status is writable and pid is the positive fork result.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            if libc::WIFEXITED(status) {
                return Ok(HelperOutcome::Exited(libc::WEXITSTATUS(status)));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(HelperOutcome::Signaled(libc::WTERMSIG(status)));
            }
            return Err(joined_error(
                ErrorCode::Internal,
                format!("joined user namespace helper returned wait status {status:#x}"),
            ));
        }
        let error = io::Error::last_os_error();
        if waited < 0 && error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(joined_error(
            ErrorCode::Internal,
            format!("failed to reap joined user namespace helper: {error}"),
        ));
    }
}

fn terminate_and_reap(pid: libc::pid_t) {
    if pid > 0 {
        // SAFETY: pid is the positive child returned by fork.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = wait_for_helper(pid);
    }
}

fn last_joined_error(operation: &str) -> a3s_oci_sdk::Error {
    let error = io::Error::last_os_error();
    joined_error(error_code(&error), format!("{operation} failed: {error}"))
}

fn error_code(error: &io::Error) -> ErrorCode {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EFBIG | libc::EMSGSIZE) => ErrorCode::ResourceExhausted,
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP) => ErrorCode::Unsupported,
        Some(libc::ENOENT | libc::ESRCH | libc::ESTALE) => ErrorCode::FailedPrecondition,
        _ => ErrorCode::Internal,
    }
}

fn joined_error(code: ErrorCode, message: impl Into<String>) -> a3s_oci_sdk::Error {
    namespace_error(code, message)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use super::{observe, JoinedUserNamespaceAuthority};

    #[test]
    fn current_namespace_authority_is_observed_without_setns() {
        let observed = observe(Path::new("/proc/self/ns/user"))
            .expect("observe current user namespace authority");
        assert!(!observed.uid_mappings.is_empty());
        assert!(!observed.gid_mappings.is_empty());
        observed
            .authority
            .verify(
                Path::new("/proc/self/ns/user"),
                &File::open("/proc/self/ns/user").expect("current user namespace"),
            )
            .expect("stable current namespace identity");
    }

    #[test]
    fn namespace_identity_rejects_a_different_namespace_type_descriptor() {
        let user = File::open("/proc/self/ns/user").expect("current user namespace");
        let authority =
            JoinedUserNamespaceAuthority::retain(user).expect("user namespace authority");
        let mount = File::open("/proc/self/ns/mnt").expect("current mount namespace");
        assert!(authority
            .verify(Path::new("/proc/self/ns/user"), &mount)
            .is_err());
    }
}
