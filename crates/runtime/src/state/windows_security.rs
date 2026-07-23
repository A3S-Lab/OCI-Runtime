use std::ffi::c_void;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{addr_of, null, null_mut};

use a3s_oci_sdk::{ErrorCode, Result};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AddAccessAllowedAceEx, CopySid, CreateWellKnownSid, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TokenUser,
    WinLocalSystemSid, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ALL_ACCESS};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::filesystem::state_error;

const PRIVATE_ACE_FLAGS: u32 = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;

pub(super) fn create_private_directory(path: &Path) -> Result<()> {
    let path_wide = wide_path(path)?;
    let mut security = PrivateSecurityDescriptor::new()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|error| {
            windows_error(
                "create-state-directory",
                path,
                format!("invalid security-attributes size: {error}"),
            )
        })?,
        lpSecurityDescriptor: (&mut security.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };

    // SAFETY: `path_wide` is NUL-terminated and the security descriptor,
    // DACL, and copied SIDs remain live and immutable for the call.
    let created = unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) };
    if created == 0 {
        return Err(last_windows_error("create-state-directory", path));
    }
    protect_path(path)
}

pub(super) fn protect_path(path: &Path) -> Result<()> {
    let mut path_wide = wide_path(path)?;
    let security = PrivateSecurityDescriptor::new()?;

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
    verify_private_dacl(path, &security.allowed_sids)
}

struct PrivateSecurityDescriptor {
    _acl_storage: AlignedBuffer,
    acl: *mut ACL,
    descriptor: SECURITY_DESCRIPTOR,
    allowed_sids: Vec<Sid>,
}

impl PrivateSecurityDescriptor {
    fn new() -> Result<Self> {
        let user = current_user_sid()?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let same_principal = unsafe {
            // SAFETY: both SIDs are copied into aligned buffers and validated
            // by the Windows SID APIs that created them.
            EqualSid(user.as_ptr(), system.as_ptr()) != 0
        };
        let allowed_sids = if same_principal {
            vec![user]
        } else {
            vec![user, system]
        };
        let acl_bytes = allowed_sids
            .iter()
            .try_fold(
                size_of::<ACL>(),
                |total, sid| -> std::result::Result<usize, std::num::TryFromIntError> {
                    let sid_bytes = usize::try_from(sid.len)?;
                    Ok(
                        total + size_of::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>()
                            - size_of::<u32>()
                            + sid_bytes,
                    )
                },
            )
            .map_err(|error| {
                windows_error(
                    "build-state-dacl",
                    Path::new("<runtime-state>"),
                    format!("private DACL size overflow: {error}"),
                )
            })?;
        let acl_length = u32::try_from(acl_bytes).map_err(|error| {
            windows_error(
                "build-state-dacl",
                Path::new("<runtime-state>"),
                format!("private DACL is too large: {error}"),
            )
        })?;
        let mut acl_storage = AlignedBuffer::new(acl_bytes);
        let acl = acl_storage.as_mut_ptr().cast::<ACL>();

        // SAFETY: `acl_storage` is aligned, zero-initialized, writable, and at
        // least `acl_length` bytes long.
        if unsafe { InitializeAcl(acl, acl_length, ACL_REVISION) } == 0 {
            return Err(last_windows_error(
                "build-state-dacl",
                Path::new("<runtime-state>"),
            ));
        }
        for sid in &allowed_sids {
            // SAFETY: the ACL has exact capacity for every copied SID and each
            // SID buffer remains live for the duration of this call.
            if unsafe {
                AddAccessAllowedAceEx(
                    acl,
                    ACL_REVISION,
                    PRIVATE_ACE_FLAGS,
                    FILE_ALL_ACCESS,
                    sid.as_ptr(),
                )
            } == 0
            {
                return Err(last_windows_error(
                    "build-state-dacl",
                    Path::new("<runtime-state>"),
                ));
            }
        }

        // SAFETY: the descriptor is immediately initialized before any field
        // is read, and `acl_storage` outlives the descriptor.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { zeroed() };
        // SAFETY: `descriptor` is writable and correctly aligned.
        if unsafe {
            InitializeSecurityDescriptor(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(last_windows_error(
                "build-state-security-descriptor",
                Path::new("<runtime-state>"),
            ));
        }
        // SAFETY: `descriptor` is initialized and `acl` points to a valid ACL
        // whose backing allocation is retained in the returned value.
        if unsafe {
            SetSecurityDescriptorDacl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                1,
                acl,
                0,
            )
        } == 0
        {
            return Err(last_windows_error(
                "build-state-security-descriptor",
                Path::new("<runtime-state>"),
            ));
        }
        // SAFETY: `descriptor` is initialized and the current-principal SID
        // remains live in `allowed_sids` for the descriptor's lifetime.
        if unsafe {
            SetSecurityDescriptorOwner(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                allowed_sids[0].as_ptr(),
                0,
            )
        } == 0
        {
            return Err(last_windows_error(
                "build-state-security-descriptor",
                Path::new("<runtime-state>"),
            ));
        }
        // SAFETY: `descriptor` is initialized and the control mask changes
        // only the DACL inheritance bit.
        if unsafe {
            SetSecurityDescriptorControl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(last_windows_error(
                "build-state-security-descriptor",
                Path::new("<runtime-state>"),
            ));
        }

        Ok(Self {
            _acl_storage: acl_storage,
            acl,
            descriptor,
            allowed_sids,
        })
    }
}

fn current_user_sid() -> Result<Sid> {
    let mut token = null_mut();
    // SAFETY: the output pointer is valid; `GetCurrentProcess` returns the
    // documented pseudo-handle accepted by `OpenProcessToken`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_windows_error(
            "query-runtime-principal",
            Path::new("<process-token>"),
        ));
    }
    let token = OwnedHandle(token);
    let mut required = 0;
    // SAFETY: the null-buffer probe is the documented way to obtain the
    // required token-information length.
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required);
    }
    if required == 0 {
        return Err(last_windows_error(
            "query-runtime-principal",
            Path::new("<process-token>"),
        ));
    }
    let mut token_information = AlignedBuffer::new(required as usize);
    // SAFETY: the aligned output buffer is at least `required` bytes and all
    // pointers are valid for the call.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            token_information.as_mut_ptr(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_windows_error(
            "query-runtime-principal",
            Path::new("<process-token>"),
        ));
    }
    // SAFETY: a successful TokenUser query initializes a TOKEN_USER at the
    // start of the aligned buffer and keeps its embedded SID live.
    let source = unsafe { (*token_information.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    copy_sid(source, "copy-runtime-principal")
}

fn well_known_sid(kind: i32) -> Result<Sid> {
    let mut storage = AlignedBuffer::new(SECURITY_MAX_SID_SIZE as usize);
    let mut length = SECURITY_MAX_SID_SIZE;
    // SAFETY: the output buffer is aligned and has the advertised capacity.
    if unsafe { CreateWellKnownSid(kind, null_mut(), storage.as_mut_ptr().cast(), &mut length) }
        == 0
    {
        return Err(last_windows_error(
            "create-system-principal",
            Path::new("<local-system-sid>"),
        ));
    }
    Ok(Sid {
        storage,
        len: length,
    })
}

fn copy_sid(source: PSID, operation: &'static str) -> Result<Sid> {
    if source.is_null() {
        return Err(windows_error(
            operation,
            Path::new("<sid>"),
            "Windows returned a null SID",
        ));
    }
    // SAFETY: the source is returned by a successful Windows token query.
    let length = unsafe { GetLengthSid(source) };
    if length == 0 {
        return Err(last_windows_error(operation, Path::new("<sid>")));
    }
    let mut storage = AlignedBuffer::new(length as usize);
    // SAFETY: the destination has `length` bytes and the source SID remains
    // valid during the call.
    if unsafe { CopySid(length, storage.as_mut_ptr().cast(), source) } == 0 {
        return Err(last_windows_error(operation, Path::new("<sid>")));
    }
    Ok(Sid {
        storage,
        len: length,
    })
}

fn verify_private_dacl(path: &Path, allowed_sids: &[Sid]) -> Result<()> {
    let expected_ace_flags = if std::fs::metadata(path)
        .map_err(|error| {
            windows_error(
                "verify-state-dacl",
                path,
                format!("failed to inspect protected path: {error}"),
            )
        })?
        .is_dir()
    {
        PRIVATE_ACE_FLAGS
    } else {
        0
    };
    let mut path_wide = wide_path(path)?;
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: all output pointers are valid and `path_wide` is NUL-terminated.
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(status_error("verify-state-dacl", path, status));
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    if owner.is_null() || dacl.is_null() || descriptor.0.is_null() {
        return Err(insecure_dacl(path, "the owner or DACL is absent"));
    }
    // SAFETY: both SIDs belong to live security descriptors or owned buffers.
    if unsafe { EqualSid(owner, allowed_sids[0].as_ptr()) } == 0 {
        return Err(insecure_dacl(
            path,
            "the owner is not the runtime process principal",
        ));
    }

    let mut control = 0;
    let mut revision = 0;
    // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW and remains
    // live through the guard.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(last_windows_error("verify-state-dacl", path));
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(insecure_dacl(path, "the DACL inherits permissions"));
    }

    // SAFETY: `dacl` belongs to the live security descriptor.
    let ace_count = unsafe { (*dacl).AceCount };
    if usize::from(ace_count) != allowed_sids.len() {
        return Err(insecure_dacl(
            path,
            format!(
                "expected {} access entries, found {ace_count}",
                allowed_sids.len()
            ),
        ));
    }
    let mut seen = vec![false; allowed_sids.len()];
    for index in 0..u32::from(ace_count) {
        let mut raw_ace: *mut c_void = null_mut();
        // SAFETY: the index is less than AceCount and the output pointer is
        // valid.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(last_windows_error("verify-state-dacl", path));
        }
        // SAFETY: GetAce returned a valid ACE pointer for the live DACL.
        let ace = unsafe { &*raw_ace.cast::<windows_sys::Win32::Security::ACCESS_ALLOWED_ACE>() };
        if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || ace.Mask != FILE_ALL_ACCESS
            || u32::from(ace.Header.AceFlags) != expected_ace_flags
        {
            return Err(insecure_dacl(
                path,
                format!(
                    "unexpected access entry type={}, mask={:#x}, flags={:#x}; expected type={}, mask={:#x}, flags={:#x}",
                    ace.Header.AceType,
                    ace.Mask,
                    ace.Header.AceFlags,
                    ACCESS_ALLOWED_ACE_TYPE,
                    FILE_ALL_ACCESS,
                    expected_ace_flags,
                ),
            ));
        }
        let sid = addr_of!(ace.SidStart).cast_mut().cast();
        let Some((position, _)) = allowed_sids.iter().enumerate().find(|(_, allowed)| unsafe {
            // SAFETY: the ACE SID and copied allowed SID are both valid
            // for the duration of the comparison.
            EqualSid(sid, allowed.as_ptr()) != 0
        }) else {
            return Err(insecure_dacl(
                path,
                "an access entry grants an unexpected principal",
            ));
        };
        if seen[position] {
            return Err(insecure_dacl(path, "a principal has duplicate entries"));
        }
        seen[position] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(insecure_dacl(path, "an allowed principal is missing"))
    }
}

struct Sid {
    storage: AlignedBuffer,
    len: u32,
}

impl Sid {
    fn as_ptr(&self) -> PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

struct AlignedBuffer(Vec<usize>);

impl AlignedBuffer {
    fn new(byte_length: usize) -> Self {
        let words = byte_length.div_ceil(size_of::<usize>());
        Self(vec![0; words])
    }

    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr().cast()
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this guard owns a real token handle returned by
        // OpenProcessToken and drops it exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this allocation was returned by
            // GetNamedSecurityInfoW and is released exactly once.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(windows_error(
            "encode-state-path",
            path,
            "path contains a NUL code unit",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn insecure_dacl(path: &Path, detail: impl Into<String>) -> a3s_oci_sdk::Error {
    windows_error(
        "verify-state-dacl",
        path,
        format!("runtime state path has an insecure DACL: {}", detail.into()),
    )
}

fn last_windows_error(operation: &'static str, path: &Path) -> a3s_oci_sdk::Error {
    windows_error(operation, path, io::Error::last_os_error().to_string())
}

fn status_error(operation: &'static str, path: &Path, status: u32) -> a3s_oci_sdk::Error {
    let code = i32::try_from(status).unwrap_or(i32::MAX);
    windows_error(
        operation,
        path,
        io::Error::from_raw_os_error(code).to_string(),
    )
}

fn windows_error(
    operation: &'static str,
    path: &Path,
    detail: impl Into<String>,
) -> a3s_oci_sdk::Error {
    state_error(
        ErrorCode::FailedPrecondition,
        operation,
        format!("{}: {}", path.display(), detail.into()),
    )
}
