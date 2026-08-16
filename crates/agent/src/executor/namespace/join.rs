use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::{NamespaceIsolation, NamespacePlan};

struct OpenNamespace {
    name: &'static str,
    path: PathBuf,
    file: File,
    namespace_type: libc::c_int,
    current_name: &'static str,
    joined: bool,
}

pub(super) fn enter(plan: &NamespacePlan, isolation: &NamespaceIsolation) -> Result<()> {
    let mut namespaces = open_all(plan)?;
    if namespaces.is_empty() {
        return Ok(());
    }
    let current_namespaces = File::open("/proc/self/ns").map_err(|error| {
        join_error(
            ErrorCode::Internal,
            format!("failed to retain /proc/self/ns before namespace entry: {error}"),
        )
    })?;

    join_pass(&mut namespaces, &current_namespaces, isolation, false)?;
    join_pass(&mut namespaces, &current_namespaces, isolation, true)?;
    join_pass(&mut namespaces, &current_namespaces, isolation, false)?;

    let missing = namespaces
        .iter()
        .filter(|namespace| !namespace.joined)
        .map(|namespace| namespace.name)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(join_error(
            ErrorCode::PermissionDenied,
            format!(
                "failed to join existing Linux namespaces after the user namespace permission \
                 transition: {}",
                missing.join(", ")
            ),
        ))
    }
}

fn open_all(plan: &NamespacePlan) -> Result<Vec<OpenNamespace>> {
    let specifications = [
        (
            "cgroup",
            plan.joined_cgroup(),
            libc::CLONE_NEWCGROUP,
            "cgroup",
        ),
        ("ipc", plan.joined_ipc(), libc::CLONE_NEWIPC, "ipc"),
        ("mount", plan.joined_mount(), libc::CLONE_NEWNS, "mnt"),
        ("network", plan.joined_network(), libc::CLONE_NEWNET, "net"),
        (
            "pid",
            plan.joined_pid(),
            libc::CLONE_NEWPID,
            "pid_for_children",
        ),
        (
            "time",
            plan.joined_time(),
            libc::CLONE_NEWTIME,
            "time_for_children",
        ),
        ("user", plan.joined_user(), libc::CLONE_NEWUSER, "user"),
        ("uts", plan.joined_uts(), libc::CLONE_NEWUTS, "uts"),
    ];
    let mut opened = Vec::new();
    for (name, path, namespace_type, current_name) in specifications {
        let Some(path) = path else {
            continue;
        };
        let file = File::open(path).map_err(|error| open_error(name, path, error))?;
        validate_namespace_type(name, path, &file, namespace_type)?;
        if namespace_type == libc::CLONE_NEWUSER {
            plan.verify_joined_user_identity(path, &file)?;
        }
        opened.push(OpenNamespace {
            name,
            path: path.to_path_buf(),
            file,
            namespace_type,
            current_name,
            joined: false,
        });
    }
    Ok(opened)
}

fn join_pass(
    namespaces: &mut [OpenNamespace],
    current_namespaces: &File,
    isolation: &NamespaceIsolation,
    user_namespace: bool,
) -> Result<()> {
    for namespace in namespaces {
        if namespace.joined || (namespace.namespace_type == libc::CLONE_NEWUSER) != user_namespace {
            continue;
        }
        if same_namespace(&namespace.file, current_namespaces, namespace.current_name)? {
            if isolation.requires_joined_name(namespace.name) {
                return Err(join_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "refusing namespace-scoped mutation through current {} namespace {}",
                        namespace.name,
                        namespace.path.display()
                    ),
                ));
            }
            namespace.joined = true;
            continue;
        }

        // SAFETY: the descriptor was opened and type-checked before any
        // namespace transition. This dedicated init wrapper is single-threaded.
        if unsafe { libc::setns(namespace.file.as_raw_fd(), namespace.namespace_type) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPERM) {
                continue;
            }
            return Err(join_error(
                error_code(&error),
                format!(
                    "setns into existing {} namespace {} failed: {error}",
                    namespace.name,
                    namespace.path.display()
                ),
            ));
        }
        if !same_namespace(&namespace.file, current_namespaces, namespace.current_name)? {
            return Err(join_error(
                ErrorCode::PermissionDenied,
                format!(
                    "setns did not place the container init in the requested {} namespace {}",
                    namespace.name,
                    namespace.path.display()
                ),
            ));
        }
        namespace.joined = true;
    }
    Ok(())
}

pub(super) fn validate_namespace_type(
    name: &str,
    path: &Path,
    file: &File,
    expected: libc::c_int,
) -> Result<()> {
    // SAFETY: NS_GET_NSTYPE reads namespace metadata from a live descriptor
    // and does not require a third ioctl argument.
    let actual = unsafe { libc::ioctl(file.as_raw_fd(), libc::NS_GET_NSTYPE) };
    if actual < 0 {
        let error = io::Error::last_os_error();
        return Err(join_error(
            if matches!(error.raw_os_error(), Some(libc::ENOTTY | libc::EINVAL)) {
                ErrorCode::InvalidArgument
            } else {
                error_code(&error)
            },
            format!(
                "failed to verify existing {name} namespace path {}: {error}",
                path.display()
            ),
        ));
    }
    if actual != expected {
        return Err(join_error(
            ErrorCode::InvalidArgument,
            format!(
                "existing {name} namespace path {} has namespace type {actual:#x}, expected \
                 {expected:#x}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn same_namespace(target: &File, current_namespaces: &File, current_name: &str) -> Result<bool> {
    let current_name = CString::new(current_name).map_err(|error| {
        join_error(
            ErrorCode::Internal,
            format!("current namespace name contains a NUL byte: {error}"),
        )
    })?;
    // SAFETY: the retained descriptor references `/proc/self/ns`, the name is
    // NUL-terminated, and ownership of a successful descriptor is transferred
    // exactly once to `File`.
    let current = unsafe {
        libc::openat(
            current_namespaces.as_raw_fd(),
            current_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if current < 0 {
        let error = io::Error::last_os_error();
        return Err(join_error(
            ErrorCode::Internal,
            format!("failed to inspect current namespace through retained /proc/self/ns: {error}"),
        ));
    }
    // SAFETY: `current` is a new owned descriptor returned by successful
    // `openat` and has not been wrapped or closed elsewhere.
    let current = unsafe { File::from_raw_fd(current) };
    let target = target.metadata().map_err(|error| {
        join_error(
            ErrorCode::Internal,
            format!("failed to inspect an opened namespace descriptor: {error}"),
        )
    })?;
    let current = current.metadata().map_err(|error| {
        join_error(
            ErrorCode::Internal,
            format!("failed to inspect current namespace through retained /proc/self/ns: {error}"),
        )
    })?;

    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt;

        Ok(target.st_dev() == current.st_dev() && target.st_ino() == current.st_ino())
    }
}

fn open_error(name: &str, path: &Path, error: io::Error) -> Error {
    join_error(
        error_code(&error),
        format!(
            "failed to open existing {name} namespace {}: {error}",
            path.display()
        ),
    )
}

fn error_code(error: &io::Error) -> ErrorCode {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP) => ErrorCode::InvalidArgument,
        _ => ErrorCode::FailedPrecondition,
    }
}

fn join_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("run-container-init")
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use a3s_oci_sdk::oci_spec::runtime::Linux;
    use a3s_oci_sdk::{ErrorCode, OciLinuxSysctlNamespace};

    use super::{enter, same_namespace, validate_namespace_type};
    use crate::executor::namespace::{NamespaceIsolation, NamespacePlan};

    #[test]
    fn namespace_descriptors_are_type_checked_before_setns() {
        let uts = File::open("/proc/self/ns/uts").expect("open current UTS namespace");
        validate_namespace_type(
            "uts",
            Path::new("/proc/self/ns/uts"),
            &uts,
            libc::CLONE_NEWUTS,
        )
        .expect("correct namespace type");

        let error = validate_namespace_type(
            "network",
            Path::new("/proc/self/ns/uts"),
            &uts,
            libc::CLONE_NEWNET,
        )
        .expect_err("wrong namespace type");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("expected"));
    }

    #[test]
    fn regular_files_are_rejected_as_namespace_targets() {
        let file = File::open("/etc/passwd").expect("open regular file");
        let error =
            validate_namespace_type("uts", Path::new("/etc/passwd"), &file, libc::CLONE_NEWUTS)
                .expect_err("regular file is not an nsfs descriptor");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("verify"));
    }

    #[test]
    fn namespace_identity_uses_the_open_descriptor_not_a_re_resolved_target() {
        let current = File::open("/proc/self/ns").expect("retain current namespace directory");
        let uts = File::open("/proc/self/ns/uts").expect("open current UTS namespace");
        assert!(same_namespace(&uts, &current, "uts").expect("compare namespace identities"));
        assert!(!same_namespace(&uts, &current, "net").expect("compare different namespaces"));
    }

    #[test]
    fn current_namespace_join_is_rejected_for_namespace_scoped_mutation() {
        let linux: Linux = serde_json::from_value(serde_json::json!({
            "namespaces": [{"type": "network", "path": "/proc/self/ns/net"}]
        }))
        .expect("Linux namespace fixture");
        let plan = NamespacePlan::from_linux(Some(&linux), 0, 0, &[])
            .expect("joined network namespace plan");
        let mut isolation = NamespaceIsolation::default();
        isolation.require(OciLinuxSysctlNamespace::Network);

        let error =
            enter(&plan, &isolation).expect_err("host network namespace mutation must fail closed");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert!(error.message.contains("current network namespace"));

        enter(&plan, &NamespaceIsolation::default())
            .expect("read-only same-namespace join remains a no-op");
    }
}
