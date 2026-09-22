//! Operator setuid launcher identity for rootless device-policy bootstrap.
//!
//! A mode 4755 `a3s-oci` has effective uid 0 and the caller's real gid and
//! supplementary groups. Bootstrap requires effective root gid and no
//! supplementary groups, and cgroup v2 migration into a delegated child must
//! happen as effective root: the unprivileged parent cannot write the common
//! ancestor `cgroup.procs`. This does not close B2 or prove the operator path
//! on a host that has not run it.

use std::path::{Component, Path};

/// Environment set by Box when the parent cannot migrate the owner itself.
pub const OWNER_CGROUP_ENV: &str = "A3S_BOX_OWNER_CGROUP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorSetuidCredentialFix {
    pub set_egid_root: bool,
    pub clear_groups: bool,
}

/// Decide whether a setuid-root, non-root-real-uid process must adopt the
/// rootless bootstrap identity. Already-correct setpriv shapes and real-root
/// processes are left untouched.
#[must_use]
pub fn operator_setuid_credential_fix(
    uid: u32,
    euid: u32,
    _gid: u32,
    egid: u32,
    supplementary_groups: i32,
) -> Option<OperatorSetuidCredentialFix> {
    if euid != 0 || uid == 0 || supplementary_groups < 0 {
        return None;
    }
    let set_egid_root = egid != 0;
    let clear_groups = supplementary_groups != 0;
    if !set_egid_root && !clear_groups {
        return None;
    }
    Some(OperatorSetuidCredentialFix {
        set_egid_root,
        clear_groups,
    })
}

/// `owner_cgroup` must be a lexical child of `delegated_root`, with no `..`.
#[must_use]
pub fn owner_cgroup_within_delegated_root(delegated_root: &Path, owner_cgroup: &Path) -> bool {
    // Cgroup v2 destinations are Linux pathname-absolute (`/...`). Host
    // `Path::is_absolute` rejects that shape on Windows, which only matters
    // when unit-testing these helpers outside Linux.
    if !is_linux_pathname_absolute(delegated_root) || !is_linux_pathname_absolute(owner_cgroup) {
        return false;
    }
    if has_parent_dir(delegated_root) || has_parent_dir(owner_cgroup) {
        return false;
    }
    let Ok(relative) = owner_cgroup.strip_prefix(delegated_root) else {
        return false;
    };
    relative.components().next().is_some()
}

fn is_linux_pathname_absolute(path: &Path) -> bool {
    path.as_os_str().as_encoded_bytes().starts_with(b"/")
}

fn has_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

/// Adopt operator setuid credentials and migrate into the Box-created owner
/// cgroup while effective uid is still 0. No-op when this process is not that
/// shape or Box did not publish a destination.
#[cfg(target_os = "linux")]
pub fn prepare_operator_setuid_owner(delegated_root: &Path) -> Result<(), String> {
    adopt_operator_setuid_credentials()?;
    migrate_published_owner_cgroup(delegated_root)
}

#[cfg(target_os = "linux")]
fn adopt_operator_setuid_credentials() -> Result<(), String> {
    // SAFETY: credential queries have no pointer arguments or failure result.
    let (uid, euid, gid, egid) = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    // SAFETY: a zero-sized query accepts a null pointer and returns the count.
    let supplementary_groups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if supplementary_groups < 0 {
        return Err(
            "failed to inspect supplementary groups before operator setuid adoption".into(),
        );
    }
    let Some(fix) = operator_setuid_credential_fix(uid, euid, gid, egid, supplementary_groups)
    else {
        return Ok(());
    };
    if fix.set_egid_root {
        // Keep the non-root real gid. Bootstrap rejects a real root gid.
        // SAFETY: scalar ids; effective uid 0 holds CAP_SETGID.
        if unsafe { libc::setresgid(gid, 0, 0) } != 0 {
            return Err(format!(
                "failed to set operator effective gid to 0: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    if fix.clear_groups {
        // SAFETY: effective uid 0 may clear the caller's supplementary set.
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
            return Err(format!(
                "failed to clear operator supplementary groups: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn migrate_published_owner_cgroup(delegated_root: &Path) -> Result<(), String> {
    let Some(raw) = std::env::var_os(OWNER_CGROUP_ENV) else {
        return Ok(());
    };
    std::env::remove_var(OWNER_CGROUP_ENV);
    let owner_cgroup = std::path::PathBuf::from(raw);
    if !owner_cgroup_within_delegated_root(delegated_root, &owner_cgroup) {
        return Err(format!(
            "refusing to migrate the operator owner into {} outside delegated root {}",
            owner_cgroup.display(),
            delegated_root.display()
        ));
    }
    write_self_pid_to_cgroup_procs(delegated_root, &owner_cgroup)
}

#[cfg(target_os = "linux")]
fn write_self_pid_to_cgroup_procs(
    delegated_root: &Path,
    owner_cgroup: &Path,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    let relative = owner_cgroup
        .strip_prefix(delegated_root)
        .map_err(|_| "owner cgroup escaped the delegated root".to_string())?;
    let mut current = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(delegated_root)
        .map_err(|error| {
            format!(
                "failed to open delegated cgroup root {}: {error}",
                delegated_root.display()
            )
        })?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err("owner cgroup component is not a plain directory name".into());
        };
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| "owner cgroup component contains an interior NUL".to_string())?;
        // SAFETY: dirfd is owned, name is NUL-terminated, flags do not follow links.
        let next = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(format!(
                "failed to open owner cgroup component under {}: {}",
                delegated_root.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: openat returned an owned descriptor.
        current = unsafe { std::fs::File::from_raw_fd(next) };
    }
    let procs_name =
        std::ffi::CString::new("cgroup.procs").expect("cgroup.procs has no interior NUL");
    // SAFETY: dirfd is the owner cgroup directory opened without following links.
    let procs = unsafe {
        libc::openat(
            current.as_raw_fd(),
            procs_name.as_ptr(),
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if procs < 0 {
        return Err(format!(
            "failed to open owner cgroup.procs: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat returned an owned descriptor.
    let mut procs = unsafe { std::fs::File::from_raw_fd(procs) };
    procs
        .write_all(b"0")
        .map_err(|error| format!("failed to migrate operator owner into cgroup.procs: {error}"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        operator_setuid_credential_fix, owner_cgroup_within_delegated_root, OWNER_CGROUP_ENV,
    };

    #[test]
    fn owner_cgroup_env_name_matches_box() {
        assert_eq!(OWNER_CGROUP_ENV, "A3S_BOX_OWNER_CGROUP");
    }

    #[test]
    fn setuid_operator_fixes_egid_and_supplementary_groups() {
        let fix = operator_setuid_credential_fix(1001, 0, 1001, 1001, 3).expect("needs adoption");
        assert!(fix.set_egid_root);
        assert!(fix.clear_groups);
    }

    #[test]
    fn setpriv_shape_is_already_the_bootstrap_identity() {
        assert!(operator_setuid_credential_fix(1001, 0, 1001, 0, 0).is_none());
    }

    #[test]
    fn real_root_and_unprivileged_processes_are_not_rewritten() {
        assert!(operator_setuid_credential_fix(0, 0, 0, 0, 0).is_none());
        assert!(operator_setuid_credential_fix(1001, 1001, 1001, 1001, 2).is_none());
    }

    #[test]
    fn owner_cgroup_must_be_a_child_of_the_delegated_root() {
        let root = Path::new("/sys/fs/cgroup/a3s-box-sandbox/delegated");
        assert!(owner_cgroup_within_delegated_root(
            root,
            Path::new("/sys/fs/cgroup/a3s-box-sandbox/delegated/box-native-owner-7")
        ));
        assert!(!owner_cgroup_within_delegated_root(root, root));
        assert!(!owner_cgroup_within_delegated_root(
            root,
            Path::new("/sys/fs/cgroup/a3s-box-sandbox/delegated/../probe")
        ));
        assert!(!owner_cgroup_within_delegated_root(
            root,
            Path::new("/tmp/box-native-owner-7")
        ));
        assert!(!owner_cgroup_within_delegated_root(
            Path::new("delegated"),
            Path::new("delegated/child")
        ));
    }
}
