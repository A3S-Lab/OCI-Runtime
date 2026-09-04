//! Descriptor-relative filesystem operations for one-time guest handoffs.
//!
//! The utility VM guest receives these paths through environment variables, so
//! the path itself is not an authority.  This module pins the parent directory
//! and the opened entry, then performs cleanup relative to that directory.  A
//! replacement entry is rejected instead of being removed on behalf of the
//! original handoff.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use a3s_oci_agent_protocol::{AGENT_RECOVERY_REPORT_MAX_BYTES, AGENT_SESSION_TOKEN_BYTES};
use zeroize::Zeroizing;

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const TOKEN_TEXT_BYTES: u64 = (AGENT_SESSION_TOKEN_BYTES * 2) as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryIdentity {
    device: u64,
    inode: u64,
}

impl EntryIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let stat = fstat(file)?;
        Ok(Self::from_stat(&stat))
    }

    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }
}

/// Read and consume the one-time token without ever deleting a path that was
/// substituted after the token file was opened.
pub(crate) fn consume_token_file(path: &Path) -> io::Result<Zeroizing<String>> {
    consume_token_file_inner(path, || {})
}

fn consume_token_file_inner<F>(path: &Path, before_unlink: F) -> io::Result<Zeroizing<String>>
where
    F: FnOnce(),
{
    let (parent_path, name) = split_entry(path)?;
    let parent = open_directory_nofollow(parent_path)?;
    let parent_identity = EntryIdentity::from_file(&parent)?;
    verify_directory_stat(&fstat(&parent)?, parent_path)?;

    let mut file = open_relative_file(
        &parent,
        &name,
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        0,
    )?;
    let file_identity = verify_token_file(&file, path)?;

    let mut encoded = Zeroizing::new(String::with_capacity(TOKEN_TEXT_BYTES as usize));
    (&mut file)
        .take(TOKEN_TEXT_BYTES + 1)
        .read_to_string(&mut encoded)?;
    let after_read = fstat(&file)?;
    if EntryIdentity::from_stat(&after_read) != file_identity
        || after_read.st_size < 0
        || after_read.st_size as u64 != TOKEN_TEXT_BYTES
        || encoded.len() as u64 != TOKEN_TEXT_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "guest bootstrap token changed while it was being read: {}",
                path.display()
            ),
        ));
    }

    // Destroy the secret through the pinned descriptor before touching the
    // directory entry.  If an attacker swaps the pathname, the replacement is
    // never truncated or removed.
    file.set_len(0)?;
    file.sync_all()?;
    let after_consume = fstat(&file)?;
    if EntryIdentity::from_stat(&after_consume) != file_identity || after_consume.st_size != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "guest bootstrap token could not be consumed safely: {}",
                path.display()
            ),
        ));
    }

    verify_directory_stat(&fstat(&parent)?, parent_path)?;
    before_unlink();
    remove_bound_file_at(&parent, &name, file_identity, path)?;
    // Parent removal is only a best-effort hygiene operation.  It is bound to
    // the same directory identity and therefore cannot remove a replacement.
    let _ = remove_bound_directory(parent_path, parent_identity);
    Ok(encoded)
}

/// Create a bounded, exclusive recovery report relative to a pinned parent
/// directory.  On failure, cleanup is restricted to the inode created here.
pub(crate) fn write_recovery_report_file(path: &Path, encoded: &[u8]) -> io::Result<()> {
    if encoded.len() > AGENT_RECOVERY_REPORT_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "guest recovery report is {} bytes; maximum is {}",
                encoded.len(),
                AGENT_RECOVERY_REPORT_MAX_BYTES
            ),
        ));
    }

    let (parent_path, name) = split_entry(path)?;
    let parent = open_directory_nofollow(parent_path)?;
    verify_directory_stat(&fstat(&parent)?, parent_path)?;
    let mut file = open_relative_file(
        &parent,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        PRIVATE_FILE_MODE,
    )?;
    let opened_identity = EntryIdentity::from_file(&file);
    let file_identity = match verify_plain_file(&file, path, Some(0)) {
        Ok(identity) => identity,
        Err(error) => {
            if let Ok(identity) = opened_identity {
                let _ = remove_bound_file_at(&parent, &name, identity, path);
            }
            return Err(error);
        }
    };

    let write_result = (|| -> io::Result<()> {
        file.write_all(encoded)?;
        file.sync_all()?;
        let metadata = fstat(&file)?;
        let length = u64::try_from(metadata.st_size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "guest recovery report has a negative length: {}",
                    path.display()
                ),
            )
        })?;
        if EntryIdentity::from_stat(&metadata) != file_identity || length != encoded.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "guest recovery report changed while it was being written: {}",
                    path.display()
                ),
            ));
        }
        verify_bound_file_at(&parent, &name, file_identity, path)?;
        verify_directory_stat(&fstat(&parent)?, parent_path)?;
        parent.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let cleanup = remove_bound_file_at(&parent, &name, file_identity, path).err();
        return Err(combine_cleanup_error(error, cleanup, path));
    }
    Ok(())
}

fn combine_cleanup_error(primary: io::Error, cleanup: Option<io::Error>, path: &Path) -> io::Error {
    match cleanup {
        Some(cleanup) => io::Error::new(
            primary.kind(),
            format!(
                "{primary}; failed to remove the failed guest recovery report {}: {cleanup}",
                path.display()
            ),
        ),
        None => primary,
    }
}

fn split_entry(path: &Path) -> io::Result<(&Path, CString)> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("handoff path has no parent: {}", path.display()),
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("handoff path has no file name: {}", path.display()),
        )
    })?;
    let name = name.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("handoff path has a non-UTF-8 file name: {}", path.display()),
        )
    })?;
    CString::new(name)
        .map(|name| (parent, name))
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("handoff path contains an invalid file name: {error}"),
            )
        })
}

fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY);
    options.open(path)
}

fn open_relative_file(parent: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: `parent` is a live directory descriptor, `name` is a bounded
    // NUL-terminated component, and the flags request no-follow semantics.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by openat and is transferred to this File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `file` owns a live descriptor and `stat` points to writable
    // storage for the complete libc structure.
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

fn fstatat(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `parent` is a live directory descriptor, `name` is a bounded
    // component, and `stat` points to writable storage.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

fn verify_directory_stat(stat: &libc::stat, path: &Path) -> io::Result<()> {
    let mode = stat.st_mode;
    if stat_mode_type(mode) != libc::S_IFDIR || mode & 0o777 != PRIVATE_DIRECTORY_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "guest handoff parent is not a private directory: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn verify_token_file(file: &File, path: &Path) -> io::Result<EntryIdentity> {
    let stat = fstat(file)?;
    verify_plain_stat(&stat, path, Some(TOKEN_TEXT_BYTES))?;
    Ok(EntryIdentity::from_stat(&stat))
}

fn verify_plain_file(
    file: &File,
    path: &Path,
    expected_len: Option<u64>,
) -> io::Result<EntryIdentity> {
    let stat = fstat(file)?;
    verify_plain_stat(&stat, path, expected_len)?;
    Ok(EntryIdentity::from_stat(&stat))
}

fn verify_plain_stat(stat: &libc::stat, path: &Path, expected_len: Option<u64>) -> io::Result<()> {
    let mode = stat.st_mode;
    let length = u64::try_from(stat.st_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("handoff file has a negative length: {}", path.display()),
        )
    })?;
    if stat_mode_type(mode) != libc::S_IFREG
        || mode & 0o777 != PRIVATE_FILE_MODE
        || expected_len.is_some_and(|expected| length != expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "guest handoff file is not a private regular file: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn stat_mode_type(mode: u32) -> u32 {
    mode & libc::S_IFMT
}

fn verify_bound_file_at(
    parent: &File,
    name: &CStr,
    expected: EntryIdentity,
    path: &Path,
) -> io::Result<()> {
    let stat = fstatat(parent, name)?;
    let observed = EntryIdentity::from_stat(&stat);
    let mode = stat.st_mode;
    if observed != expected
        || stat_mode_type(mode) != libc::S_IFREG
        || mode & 0o777 != PRIVATE_FILE_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("guest handoff file identity changed: {}", path.display()),
        ));
    }
    Ok(())
}

fn remove_bound_file_at(
    parent: &File,
    name: &CStr,
    expected: EntryIdentity,
    path: &Path,
) -> io::Result<()> {
    verify_bound_file_at(parent, name, expected, path)?;
    // SAFETY: `parent` is a live directory descriptor and `name` is a single
    // NUL-terminated component.  The entry identity was checked immediately
    // before this descriptor-relative unlink.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn remove_bound_directory(path: &Path, expected: EntryIdentity) -> io::Result<()> {
    let (grandparent_path, name) = split_entry(path)?;
    let grandparent = open_directory_nofollow(grandparent_path)?;
    verify_directory_container_stat(&fstat(&grandparent)?, grandparent_path)?;
    let stat = fstatat(&grandparent, &name)?;
    if EntryIdentity::from_stat(&stat) != expected
        || stat_mode_type(stat.st_mode) != libc::S_IFDIR
        || stat.st_mode & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "guest handoff directory identity changed: {}",
                path.display()
            ),
        ));
    }
    // SAFETY: `grandparent` is a live directory descriptor and `name` is one
    // bounded component.  AT_REMOVEDIR cannot remove a non-directory entry.
    let result =
        unsafe { libc::unlinkat(grandparent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn verify_directory_container_stat(stat: &libc::stat, path: &Path) -> io::Result<()> {
    if stat_mode_type(stat.st_mode) != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "handoff directory container is not a directory: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn private_directory(path: &Path) {
        std::fs::create_dir(path).expect("create handoff directory");
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .expect("protect handoff directory");
    }

    fn private_file(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).expect("write handoff file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("protect handoff file");
    }

    #[test]
    fn token_consumption_zeroizes_the_opened_inode_before_unlink() {
        let temporary = tempfile::tempdir().expect("create token fixture");
        let directory = temporary.path().join(".a3s-oci-bootstrap-test");
        private_directory(&directory);
        let path = directory.join("session-token");
        private_file(&path, &[b'a'; TOKEN_TEXT_BYTES as usize]);

        let encoded = consume_token_file(&path).expect("consume token");

        assert_eq!(encoded.as_bytes(), &[b'a'; TOKEN_TEXT_BYTES as usize]);
        assert!(!path.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn cleanup_refuses_a_replaced_entry() {
        let temporary = tempfile::tempdir().expect("create replacement fixture");
        let directory = temporary.path().join(".a3s-oci-bootstrap-test");
        private_directory(&directory);
        let path = directory.join("session-token");
        private_file(&path, &[b'a'; TOKEN_TEXT_BYTES as usize]);

        let parent = open_directory_nofollow(&directory).expect("open parent");
        let name = CString::new("session-token").expect("token name");
        let file = open_relative_file(
            &parent,
            &name,
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
        .expect("open original");
        let identity = verify_token_file(&file, &path).expect("identify original");
        std::fs::remove_file(&path).expect("remove original path");
        private_file(&path, &[b'b'; TOKEN_TEXT_BYTES as usize]);

        let error = remove_bound_file_at(&parent, &name, identity, &path)
            .expect_err("replacement must not be removed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            vec![b'b'; 64]
        );
    }

    #[test]
    fn token_consumption_leaves_a_replacement_untouched() {
        let temporary = tempfile::tempdir().expect("create token replacement fixture");
        let directory = temporary.path().join(".a3s-oci-bootstrap-test");
        private_directory(&directory);
        let path = directory.join("session-token");
        private_file(&path, &[b'a'; TOKEN_TEXT_BYTES as usize]);

        let error = consume_token_file_inner(&path, || {
            std::fs::remove_file(&path).expect("remove original token path");
            private_file(&path, &[b'b'; TOKEN_TEXT_BYTES as usize]);
        })
        .expect_err("replacement must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::read(&path).expect("read replacement token"),
            vec![b'b'; TOKEN_TEXT_BYTES as usize]
        );
    }

    #[test]
    fn report_publish_is_exclusive() {
        let temporary = tempfile::tempdir().expect("create report fixture");
        let directory = temporary.path().join(".a3s-oci-recovery-test");
        private_directory(&directory);
        let path = directory.join("report.json");
        private_file(&path, b"incumbent");

        let error = write_recovery_report_file(&path, b"new").expect_err("incumbent is fenced");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read incumbent"), b"incumbent");
    }

    #[test]
    fn report_publish_is_private_and_durable() {
        let temporary = tempfile::tempdir().expect("create report fixture");
        let directory = temporary.path().join(".a3s-oci-recovery-test");
        private_directory(&directory);
        let path = directory.join("report.json");

        write_recovery_report_file(&path, b"report").expect("publish report");

        let metadata = std::fs::metadata(&path).expect("inspect report");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, PRIVATE_FILE_MODE);
        assert_eq!(std::fs::read(&path).expect("read report"), b"report");
    }

    #[test]
    fn report_publish_rejects_a_symlink_destination() {
        let temporary = tempfile::tempdir().expect("create symlink fixture");
        let directory = temporary.path().join(".a3s-oci-recovery-test");
        private_directory(&directory);
        let victim = temporary.path().join("victim");
        private_file(&victim, b"victim");
        let path = directory.join("report.json");
        std::os::unix::fs::symlink(&victim, &path).expect("create report symlink");

        let error = write_recovery_report_file(&path, b"replacement")
            .expect_err("symlink destination must fail closed");
        assert!(
            error.kind() == io::ErrorKind::AlreadyExists
                || error.raw_os_error() == Some(libc::ELOOP)
        );
        assert_eq!(std::fs::read(&victim).expect("read victim"), b"victim");
    }
}
