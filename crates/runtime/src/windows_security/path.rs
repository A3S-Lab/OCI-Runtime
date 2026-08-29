use std::fs::File;
use std::io;
use std::mem::zeroed;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use a3s_oci_sdk::{Error, ErrorCode, Result};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    SetNamedSecurityInfoW, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, MoveFileExW,
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
};

use super::{
    last_windows_error, status_error, verify_private_file_handle_dacl, verify_private_path_dacl,
    wide_path, windows_error, PrivateSecurityDescriptor,
};

const PRIVATE_DIRECTORY_ACE_FLAGS: u32 = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

/// Create one new directory with an owner-and-LocalSystem-only protected DACL.
pub fn create_private_directory(path: &Path) -> Result<()> {
    create_private_directory_inner(path, false)
}

/// Ensure that one directory has an owner-and-LocalSystem-only protected DACL.
///
/// An existing path is accepted only when it already has the exact private
/// directory descriptor. This keeps concurrent creators idempotent without
/// repairing caller-controlled state.
pub fn ensure_private_directory(path: &Path) -> Result<()> {
    create_private_directory_inner(path, true)
}

fn create_private_directory_inner(path: &Path, accept_existing: bool) -> Result<()> {
    let path_wide = wide_path(path)?;
    let mut security =
        PrivateSecurityDescriptor::new(PRIVATE_DIRECTORY_ACE_FLAGS, "build-state-dacl", path)?;
    let attributes = security.security_attributes("create-state-directory", path)?;

    // SAFETY: `path_wide` is NUL-terminated and the security descriptor,
    // DACL, and copied SIDs remain live and immutable for the call.
    let created = unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) };
    if created == 0 {
        let error = io::Error::last_os_error();
        let already_exists = matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
        );
        if accept_existing && already_exists {
            return verify_private_directory(path);
        }
        if already_exists {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                format!("{}: {error}", path.display()),
            )
            .for_operation("create-state-directory"));
        }
        return Err(windows_error(
            "create-state-directory",
            path,
            error.to_string(),
        ));
    }
    protect_path(path)
}

pub(crate) fn protect_path(path: &Path) -> Result<()> {
    let mut path_wide = wide_path(path)?;
    let metadata = plain_path_metadata(path).map_err(|error| {
        windows_error(
            "protect-state-path",
            path,
            format!("failed to inspect protected path: {error}"),
        )
    })?;
    let ace_flags = if metadata.is_dir() {
        PRIVATE_DIRECTORY_ACE_FLAGS
    } else {
        0
    };
    let security = PrivateSecurityDescriptor::new(ace_flags, "build-state-dacl", path)?;

    // SAFETY: `path_wide` is NUL-terminated and mutable for APIs that use the
    // historical `PWSTR` signature. The ACL remains live for the call.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            security.allowed_sids[0].as_ptr(),
            null_mut(),
            security.acl,
            null(),
        )
    };
    if status != 0 {
        return Err(status_error("protect-state-path", path, status));
    }
    verify_private_path_dacl(path, &security.allowed_sids, ace_flags)
}

/// Verify that one existing file or directory has the exact private DACL.
pub fn verify_private_path(path: &Path) -> Result<()> {
    let metadata = plain_path_metadata(path).map_err(|error| {
        windows_error(
            "verify-state-dacl",
            path,
            format!("failed to inspect protected path: {error}"),
        )
    })?;
    let ace_flags = if metadata.is_dir() {
        PRIVATE_DIRECTORY_ACE_FLAGS
    } else {
        0
    };
    let security = PrivateSecurityDescriptor::new(ace_flags, "build-state-dacl", path)?;
    verify_private_path_dacl(path, &security.allowed_sids, ace_flags)
}

fn verify_private_directory(path: &Path) -> Result<()> {
    let metadata = plain_path_metadata(path).map_err(|error| {
        windows_error(
            "verify-state-dacl",
            path,
            format!("failed to inspect protected directory: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(windows_error(
            "verify-state-dacl",
            path,
            "protected directory path is not a directory",
        ));
    }
    let security =
        PrivateSecurityDescriptor::new(PRIVATE_DIRECTORY_ACE_FLAGS, "build-state-dacl", path)?;
    verify_private_path_dacl(path, &security.allowed_sids, PRIVATE_DIRECTORY_ACE_FLAGS)
}

/// Atomically create one private, nonsymlink regular file for durable state.
pub fn create_private_file(path: &Path) -> Result<File> {
    let path_wide = wide_path(path)?;
    let mut security = PrivateSecurityDescriptor::new(0, "build-state-dacl", path)?;
    let attributes = security.security_attributes("create-state-file", path)?;
    // SAFETY: the path is NUL-terminated, the security descriptor remains
    // live for the call, and a successful handle is transferred to `File`.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
        ) {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                format!("{}: {error}", path.display()),
            )
            .for_operation("create-state-file"));
        }
        return Err(windows_error("create-state-file", path, error.to_string()));
    }
    // SAFETY: CreateFileW returned a unique owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    verify_plain_file_handle(handle, path)?;
    verify_private_file_handle_dacl(handle, path, &security.allowed_sids)?;
    Ok(file)
}

/// Open and verify one existing private, nonsymlink regular file.
pub fn open_private_file(path: &Path, writable: bool) -> Result<File> {
    let path_wide = wide_path(path)?;
    let access = if writable {
        FILE_GENERIC_READ | FILE_GENERIC_WRITE
    } else {
        FILE_GENERIC_READ
    };
    // SAFETY: the path is NUL-terminated and a successful handle is
    // transferred to `File` exactly once.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_windows_error("open-state-file", path));
    }
    // SAFETY: CreateFileW returned a unique owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    verify_private_file(&file, path)?;
    Ok(file)
}

/// Verify a retained file handle against the exact private file contract.
pub fn verify_private_file(file: &File, path: &Path) -> Result<()> {
    let handle = file.as_raw_handle();
    verify_plain_file_handle(handle, path)?;
    let security = PrivateSecurityDescriptor::new(0, "build-state-dacl", path)?;
    verify_private_file_handle_dacl(handle, path, &security.allowed_sids)
}

/// Atomically publish one private file without replacing an existing target.
///
/// The retained source handle permits only a same-filesystem rename and keeps
/// the verified object alive through the write-through namespace commit.
pub fn rename_private_file_noreplace(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        return Err(Error::new(
            ErrorCode::AlreadyExists,
            format!(
                "private state destination already exists: {}",
                destination.display()
            ),
        )
        .for_operation("publish-state-file"));
    }
    let _source = open_private_file_for_rename(source)?;
    let source_wide = wide_path(source)?;
    let destination_wide = wide_path(destination)?;
    // SAFETY: both paths are NUL-terminated, the source handle retains the
    // verified object with delete sharing, and REPLACE_EXISTING is omitted.
    if unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
        ) {
            return Err(Error::new(
                ErrorCode::AlreadyExists,
                format!("{}: {error}", destination.display()),
            )
            .for_operation("publish-state-file"));
        }
        return Err(windows_error(
            "publish-state-file",
            destination,
            error.to_string(),
        ));
    }
    verify_private_path(destination)
}

pub(crate) fn protect_file_handle(handle: HANDLE, path: &Path) -> Result<()> {
    let security = PrivateSecurityDescriptor::new(0, "build-state-dacl", path)?;

    // SAFETY: `handle` is a live file handle opened with WRITE_OWNER and
    // WRITE_DAC. The owner SID and ACL remain live and immutable for the call.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            security.allowed_sids[0].as_ptr(),
            null_mut(),
            security.acl,
            null(),
        )
    };
    if status != 0 {
        return Err(status_error("protect-state-file", path, status));
    }
    verify_private_file_handle_dacl(handle, path, &security.allowed_sids)
}

fn plain_path_metadata(path: &Path) -> io::Result<std::fs::Metadata> {
    use std::os::windows::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (!metadata.is_dir() && !metadata.is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected path must be a nonsymlink file or directory",
        ));
    }
    Ok(metadata)
}

fn verify_plain_file_handle(handle: HANDLE, path: &Path) -> Result<()> {
    // SAFETY: the caller retains a live file handle and supplies writable
    // storage for the fixed-size information structure.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(last_windows_error("verify-state-file", path));
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(windows_error(
            "verify-state-file",
            path,
            "protected state file must be a nonsymlink regular file with exactly one link",
        ));
    }
    Ok(())
}

fn open_private_file_for_rename(path: &Path) -> Result<File> {
    let path_wide = wide_path(path)?;
    // SAFETY: the path is NUL-terminated and a successful handle is
    // transferred to `File` exactly once.
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            FILE_GENERIC_READ | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_windows_error("open-state-file-for-publish", path));
    }
    // SAFETY: CreateFileW returned a unique owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    verify_private_file(&file, path)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::{
        create_private_directory, create_private_file, ensure_private_directory, open_private_file,
        rename_private_file_noreplace,
    };
    use a3s_oci_sdk::ErrorCode;

    #[test]
    fn directory_creation_keeps_strict_and_idempotent_contracts_separate() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("private-state");
        create_private_directory(&root).expect("private state directory");

        let error = create_private_directory(&root).expect_err("strict creation must fail");
        assert_eq!(error.code, ErrorCode::AlreadyExists);
        ensure_private_directory(&root).expect("verified existing private directory");
    }

    #[test]
    fn private_file_publication_is_write_through_and_never_replaces() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("private-state");
        create_private_directory(&root).expect("private state directory");

        let source = root.join("source.pending");
        let destination = root.join("destination.json");
        let mut source_file = create_private_file(&source).expect("private source");
        source_file.write_all(b"source").expect("write source");
        source_file.sync_all().expect("sync source");
        drop(source_file);
        let mut destination_file = create_private_file(&destination).expect("private destination");
        destination_file
            .write_all(b"destination")
            .expect("write destination");
        destination_file.sync_all().expect("sync destination");
        drop(destination_file);

        let error = rename_private_file_noreplace(&source, &destination)
            .expect_err("publication must not replace an existing destination");
        assert_eq!(error.code, ErrorCode::AlreadyExists);
        assert_eq!(std::fs::read(&source).expect("retained source"), b"source");
        assert_eq!(
            std::fs::read(&destination).expect("retained destination"),
            b"destination"
        );

        let published = root.join("published.json");
        rename_private_file_noreplace(&source, &published).expect("publish source");
        assert!(!source.exists());
        let mut published_file = open_private_file(&published, false).expect("open publication");
        let mut contents = Vec::new();
        published_file
            .read_to_end(&mut contents)
            .expect("read publication");
        assert_eq!(contents, b"source");
    }
}
