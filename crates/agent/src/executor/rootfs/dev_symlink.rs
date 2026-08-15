use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

#[derive(Debug, Clone, Copy)]
struct RequiredLink {
    source: &'static str,
    destination: &'static str,
    target: &'static str,
}

const REQUIRED_LINKS: [RequiredLink; 4] = [
    RequiredLink {
        source: "proc/self/fd",
        destination: "fd",
        target: "/proc/self/fd",
    },
    RequiredLink {
        source: "proc/self/fd/0",
        destination: "stdin",
        target: "/proc/self/fd/0",
    },
    RequiredLink {
        source: "proc/self/fd/1",
        destination: "stdout",
        target: "/proc/self/fd/1",
    },
    RequiredLink {
        source: "proc/self/fd/2",
        destination: "stderr",
        target: "/proc/self/fd/2",
    },
];
const MAX_LINK_TARGET_BYTES: usize = 256;

/// Create the four OCI Linux `/dev` links whose `/proc/self/fd` sources exist.
///
/// The caller has already applied every configured mount and entered the new
/// root. Root and `/dev` descriptors keep the mutations on the directories
/// that were inspected. Existing exact links are idempotent; any other entry
/// fails closed instead of replacing container or bind-mounted content.
pub(in crate::executor) fn create_required_dev_symlinks(rootfs: &Path) -> Result<()> {
    let root = open_root(rootfs)?;
    let mut required = [false; REQUIRED_LINKS.len()];
    for (index, link) in REQUIRED_LINKS.iter().enumerate() {
        required[index] = source_exists(root.as_raw_fd(), link.source)?;
    }
    if !required.iter().any(|required| *required) {
        return Ok(());
    }

    let dev = open_dev(root.as_raw_fd())?;
    for (link, required) in REQUIRED_LINKS.iter().zip(required) {
        if required {
            ensure_exact_link(dev.as_raw_fd(), link.destination, link.target)?;
        }
    }
    Ok(())
}

fn open_root(rootfs: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(rootfs)
        .map_err(|error| {
            dev_link_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to retain the container root for required /dev links at {}: {error}",
                    rootfs.display()
                ),
            )
        })
}

fn open_dev(root: RawFd) -> Result<File> {
    let name = cstring("dev", "required /dev directory")?;
    // SAFETY: `root` is a live directory descriptor and `name` is a live,
    // NUL-terminated single component. O_NOFOLLOW rejects a substituted link.
    let descriptor = unsafe {
        libc::openat(
            root,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(dev_link_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to retain the container /dev directory for required links: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn source_exists(root: RawFd, source: &str) -> Result<bool> {
    let source = cstring(source, "required /dev link source")?;
    let mut how = std::mem::MaybeUninit::<libc::open_how>::zeroed();
    // SAFETY: zero is a valid initialization for every field in `open_how`.
    let how = unsafe { how.assume_init_mut() };
    how.flags = (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT;
    // SAFETY: `root` is a live directory descriptor, `source` is live and
    // NUL-terminated, and `how` is initialized for the exact kernel ABI size.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            source.as_ptr(),
            how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor >= 0 {
        let descriptor = RawFd::try_from(descriptor).map_err(|error| {
            dev_link_error(
                ErrorCode::Internal,
                format!("openat2 returned an invalid descriptor: {error}"),
            )
        })?;
        // SAFETY: `openat2` returned a fresh owned descriptor.
        drop(unsafe { File::from_raw_fd(descriptor) });
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) {
        Ok(false)
    } else {
        Err(dev_link_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect required /dev link source {}: {error}",
                source.to_string_lossy()
            ),
        ))
    }
}

fn ensure_exact_link(dev: RawFd, destination: &str, expected: &str) -> Result<()> {
    match read_link(dev, destination) {
        Ok(Some(actual)) if actual == expected.as_bytes() => return Ok(()),
        Ok(Some(actual)) => {
            return Err(conflicting_link(destination, expected, &actual));
        }
        Ok(None) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => {
            return Err(dev_link_error(
                ErrorCode::FailedPrecondition,
                format!("container /dev/{destination} exists but is not a symbolic link"),
            ));
        }
        Err(error) => {
            return Err(dev_link_error(
                ErrorCode::FailedPrecondition,
                format!("failed to inspect container /dev/{destination}: {error}"),
            ));
        }
    }

    let destination_c = cstring(destination, "required /dev link destination")?;
    let expected_c = cstring(expected, "required /dev link target")?;
    // SAFETY: `dev` is a live directory descriptor and both path buffers are
    // live and NUL-terminated for the duration of the call.
    if unsafe { libc::symlinkat(expected_c.as_ptr(), dev, destination_c.as_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(dev_link_error(
                ErrorCode::FailedPrecondition,
                format!("failed to create required /dev/{destination} -> {expected}: {error}"),
            ));
        }
    }

    match read_link(dev, destination) {
        Ok(Some(actual)) if actual == expected.as_bytes() => Ok(()),
        Ok(Some(actual)) => Err(conflicting_link(destination, expected, &actual)),
        Ok(None) => Err(dev_link_error(
            ErrorCode::Conflict,
            format!("container /dev/{destination} disappeared after creation"),
        )),
        Err(error) => Err(dev_link_error(
            ErrorCode::Conflict,
            format!("failed to verify container /dev/{destination}: {error}"),
        )),
    }
}

fn read_link(dev: RawFd, destination: &str) -> io::Result<Option<Vec<u8>>> {
    let destination = CString::new(destination).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid /dev link destination: {error}"),
        )
    })?;
    let mut target = [0_u8; MAX_LINK_TARGET_BYTES];
    // SAFETY: `dev` is a live directory descriptor, `destination` is live and
    // NUL-terminated, and `target` is writable for its full reported length.
    let length = unsafe {
        libc::readlinkat(
            dev,
            destination.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let length = usize::try_from(length).map_err(io::Error::other)?;
    if length == target.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "container /dev link target exceeds the bounded length",
        ));
    }
    Ok(Some(target[..length].to_vec()))
}

fn cstring(value: &str, description: &str) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|error| {
        dev_link_error(
            ErrorCode::InvalidArgument,
            format!("{description} contains a NUL byte: {error}"),
        )
    })
}

fn conflicting_link(destination: &str, expected: &str, actual: &[u8]) -> Error {
    dev_link_error(
        ErrorCode::FailedPrecondition,
        format!(
            "container /dev/{destination} points to {}, expected {expected}",
            String::from_utf8_lossy(actual)
        ),
    )
}

fn dev_link_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("prepare-container-dev-links")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use a3s_oci_sdk::ErrorCode;

    use super::create_required_dev_symlinks;

    fn rootfs_with_fd_directory() -> tempfile::TempDir {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
        fs::create_dir_all(rootfs.path().join("proc/self/fd")).expect("proc fd directory");
        fs::create_dir(rootfs.path().join("dev")).expect("dev directory");
        rootfs
    }

    #[test]
    fn creates_only_links_whose_sources_exist_and_is_idempotent() {
        let rootfs = rootfs_with_fd_directory();
        fs::write(rootfs.path().join("proc/self/fd/0"), b"stdin").expect("stdin source");
        fs::write(rootfs.path().join("proc/self/fd/2"), b"stderr").expect("stderr source");

        create_required_dev_symlinks(rootfs.path()).expect("create required links");
        create_required_dev_symlinks(rootfs.path()).expect("replay required links");

        assert_eq!(
            fs::read_link(rootfs.path().join("dev/fd")).expect("fd link"),
            Path::new("/proc/self/fd")
        );
        assert_eq!(
            fs::read_link(rootfs.path().join("dev/stdin")).expect("stdin link"),
            Path::new("/proc/self/fd/0")
        );
        assert!(fs::symlink_metadata(rootfs.path().join("dev/stdout")).is_err());
        assert_eq!(
            fs::read_link(rootfs.path().join("dev/stderr")).expect("stderr link"),
            Path::new("/proc/self/fd/2")
        );
    }

    #[test]
    fn rejects_a_conflicting_destination_without_replacing_it() {
        let rootfs = rootfs_with_fd_directory();
        fs::write(rootfs.path().join("proc/self/fd/0"), b"stdin").expect("stdin source");
        fs::write(rootfs.path().join("dev/stdin"), b"preserve").expect("conflicting target");

        let error = create_required_dev_symlinks(rootfs.path())
            .expect_err("regular destination must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            fs::read(rootfs.path().join("dev/stdin")).expect("preserved target"),
            b"preserve"
        );
    }

    #[test]
    fn rejects_a_wrong_existing_link_without_replacing_it() {
        let rootfs = rootfs_with_fd_directory();
        symlink("/wrong/fd", rootfs.path().join("dev/fd")).expect("wrong fd link");

        let error =
            create_required_dev_symlinks(rootfs.path()).expect_err("wrong link must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            fs::read_link(rootfs.path().join("dev/fd")).expect("preserved wrong link"),
            Path::new("/wrong/fd")
        );
    }

    #[test]
    fn rejects_a_symlinked_dev_directory_without_touching_its_target() {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
        let external = tempfile::tempdir().expect("external dev directory");
        fs::create_dir_all(rootfs.path().join("proc/self/fd")).expect("proc fd directory");
        symlink(external.path(), rootfs.path().join("dev")).expect("symlinked dev directory");

        let error = create_required_dev_symlinks(rootfs.path())
            .expect_err("symlinked dev directory must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(fs::read_dir(external.path())
            .expect("external directory")
            .next()
            .is_none());
    }

    #[test]
    fn source_lookup_cannot_escape_through_a_rootfs_symlink() {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
        let external = tempfile::tempdir().expect("external proc directory");
        fs::create_dir_all(external.path().join("self/fd")).expect("external fd directory");
        fs::create_dir(rootfs.path().join("dev")).expect("dev directory");
        symlink(external.path(), rootfs.path().join("proc")).expect("external proc link");

        create_required_dev_symlinks(rootfs.path()).expect("escaped source must not be observed");

        assert!(fs::symlink_metadata(rootfs.path().join("dev/fd")).is_err());
    }

    #[test]
    fn missing_sources_do_not_require_a_dev_directory() {
        let rootfs = tempfile::tempdir().expect("temporary rootfs");
        create_required_dev_symlinks(rootfs.path()).expect("no conditional links required");
    }
}
