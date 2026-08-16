use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};

use a3s_oci_sdk::oci_spec::runtime::Linux;
use a3s_oci_sdk::{Error, ErrorCode, OciLinuxSysctlKey, OciLinuxSysctlNamespace, Result};

use super::namespace::{NamespaceIsolation, NamespacePlan};

const MAX_SYSCTLS: usize = 1_024;
const MAX_SYSCTL_VALUE_BYTES: usize = 4_096;
const MAX_SYSCTL_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_SYSCTL_READBACK_BYTES: u64 = 64 * 1024;
const LINUX_UTS_NAME_MAX: usize = 64;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SysctlEntry {
    key: OciLinuxSysctlKey,
    value: String,
}

/// Validated, deterministically ordered OCI Linux sysctl transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SysctlPlan {
    entries: Vec<SysctlEntry>,
}

impl SysctlPlan {
    pub(super) fn from_linux(
        linux: Option<&Linux>,
        namespaces: &NamespacePlan,
        configured_domainname: Option<&str>,
    ) -> Result<Self> {
        let Some(sysctls) = linux.and_then(|linux| linux.sysctl().as_ref()) else {
            return Ok(Self::default());
        };
        if sysctls.len() > MAX_SYSCTLS {
            return Err(plan_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "linux.sysctl contains {} entries; maximum is {MAX_SYSCTLS}",
                    sysctls.len()
                ),
            ));
        }

        let mut total_bytes = 0_usize;
        let mut entries = BTreeMap::new();
        for (raw_key, value) in sysctls {
            let key = OciLinuxSysctlKey::parse(raw_key).map_err(|source| {
                plan_error(
                    ErrorCode::InvalidArgument,
                    format!("linux.sysctl key `{raw_key}` is invalid: {source}"),
                )
            })?;
            validate_namespace(&key, namespaces)?;
            validate_value(&key, value, configured_domainname)?;
            total_bytes = total_bytes
                .checked_add(raw_key.len())
                .and_then(|bytes| bytes.checked_add(value.len()))
                .ok_or_else(|| {
                    plan_error(ErrorCode::ResourceExhausted, "linux.sysctl size overflow")
                })?;
            if total_bytes > MAX_SYSCTL_TOTAL_BYTES {
                return Err(plan_error(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "linux.sysctl exceeds the {MAX_SYSCTL_TOTAL_BYTES}-byte executor limit"
                    ),
                ));
            }
            let path = key.procfs_path().to_string();
            if entries
                .insert(
                    path.clone(),
                    SysctlEntry {
                        key,
                        value: value.clone(),
                    },
                )
                .is_some()
            {
                return Err(plan_error(
                    ErrorCode::InvalidArgument,
                    format!("linux.sysctl contains more than one spelling for procfs path {path}"),
                ));
            }
        }
        Ok(Self {
            entries: entries.into_values().collect(),
        })
    }

    pub(super) fn namespace_isolation(&self) -> NamespaceIsolation {
        let mut isolation = NamespaceIsolation::default();
        for entry in &self.entries {
            isolation.require(entry.key.namespace());
        }
        isolation
    }

    pub(super) fn apply<'a>(&self, host_proc: &'a File) -> Result<AppliedSysctls<'a>> {
        let mut rollback = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let original = match read_value(host_proc, &entry.key) {
                Ok(original) => original,
                Err(error) => return Err(fail_with_rollback(host_proc, &rollback, error)),
            };
            rollback.push(SysctlRollback {
                key: entry.key.clone(),
                original,
            });
            if let Err(error) = write_value(host_proc, &entry.key, &entry.value)
                .and_then(|()| verify_value(host_proc, &entry.key, &entry.value, "requested"))
            {
                return Err(fail_with_rollback(host_proc, &rollback, error));
            }
        }
        Ok(AppliedSysctls {
            host_proc,
            rollback,
            committed: false,
        })
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize {
        self.entries.len()
    }
}

fn validate_namespace(key: &OciLinuxSysctlKey, namespaces: &NamespacePlan) -> Result<()> {
    let (configured, name) = match key.namespace() {
        OciLinuxSysctlNamespace::Ipc => (namespaces.has_ipc(), "IPC"),
        OciLinuxSysctlNamespace::Network => (namespaces.has_network(), "network"),
        OciLinuxSysctlNamespace::Uts => (namespaces.has_uts(), "UTS"),
        OciLinuxSysctlNamespace::User => (namespaces.has_user(), "user"),
    };
    if configured {
        Ok(())
    } else {
        Err(plan_error(
            ErrorCode::InvalidArgument,
            format!(
                "linux.sysctl key {} requires an explicit Linux {name} namespace",
                key.canonical()
            ),
        ))
    }
}

fn validate_value(
    key: &OciLinuxSysctlKey,
    value: &str,
    configured_domainname: Option<&str>,
) -> Result<()> {
    if value.len() > MAX_SYSCTL_VALUE_BYTES {
        return Err(plan_error(
            ErrorCode::ResourceExhausted,
            format!(
                "linux.sysctl value for {} is {} bytes; maximum is {MAX_SYSCTL_VALUE_BYTES}",
                key.canonical(),
                value.len()
            ),
        ));
    }
    if value.as_bytes().contains(&0) || value.contains(['\r', '\n']) {
        return Err(plan_error(
            ErrorCode::InvalidArgument,
            format!(
                "linux.sysctl value for {} must be one line without NUL bytes",
                key.canonical()
            ),
        ));
    }
    if key.canonical() == "kernel.domainname" {
        if value.len() > LINUX_UTS_NAME_MAX {
            return Err(plan_error(
                ErrorCode::InvalidArgument,
                format!(
                    "linux.sysctl kernel.domainname must contain at most {LINUX_UTS_NAME_MAX} bytes"
                ),
            ));
        }
        if configured_domainname.is_some_and(|domainname| domainname != value) {
            return Err(plan_error(
                ErrorCode::InvalidArgument,
                "linux.sysctl kernel.domainname conflicts with the dedicated OCI domainname field",
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct SysctlRollback {
    key: OciLinuxSysctlKey,
    original: String,
}

/// Uncommitted sysctl mutation set. Dropping it before the OCI Create barrier
/// becomes durable restores every original value in reverse order.
#[derive(Debug)]
pub(super) struct AppliedSysctls<'a> {
    host_proc: &'a File,
    rollback: Vec<SysctlRollback>,
    committed: bool,
}

impl AppliedSysctls<'_> {
    pub(super) fn commit(mut self) {
        self.committed = true;
    }

    pub(super) fn rollback_after(mut self, cause: Error) -> Error {
        let rollback = rollback_all(self.host_proc, &self.rollback);
        self.committed = true;
        match rollback {
            Ok(()) => cause,
            Err(rollback) => sysctl_error(
                ErrorCode::FailedPrecondition,
                format!("{cause}; OCI sysctl rollback also failed: {rollback}"),
            ),
        }
    }
}

impl Drop for AppliedSysctls<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = rollback_all(self.host_proc, &self.rollback);
        }
    }
}

fn fail_with_rollback(host_proc: &File, rollback: &[SysctlRollback], cause: Error) -> Error {
    match rollback_all(host_proc, rollback) {
        Ok(()) => cause,
        Err(rollback) => sysctl_error(
            ErrorCode::FailedPrecondition,
            format!("{cause}; partial OCI sysctl rollback also failed: {rollback}"),
        ),
    }
}

fn rollback_all(host_proc: &File, rollback: &[SysctlRollback]) -> Result<()> {
    let mut first_failure = None;
    let mut failures = 0_usize;
    for record in rollback.iter().rev() {
        let original = record.original.trim_end_matches(['\r', '\n']);
        let result = write_value(host_proc, &record.key, original)
            .and_then(|()| verify_value(host_proc, &record.key, &record.original, "rollback"));
        if let Err(error) = result {
            failures += 1;
            if first_failure.is_none() {
                first_failure = Some(error);
            }
        }
    }
    match first_failure {
        Some(first) => Err(sysctl_error(
            ErrorCode::FailedPrecondition,
            format!("{failures} OCI sysctl rollback operations failed; first failure: {first}"),
        )),
        None => Ok(()),
    }
}

fn read_value(host_proc: &File, key: &OciLinuxSysctlKey) -> Result<String> {
    let source = open_sysctl(host_proc, key, libc::O_RDONLY)?;
    let mut bytes = Vec::new();
    source
        .take(MAX_SYSCTL_READBACK_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            sysctl_error(
                error_code_for_io(&source),
                format!(
                    "read back linux.sysctl {} failed: {source}",
                    key.canonical()
                ),
            )
        })?;
    if bytes.len() as u64 > MAX_SYSCTL_READBACK_BYTES {
        return Err(sysctl_error(
            ErrorCode::ResourceExhausted,
            format!(
                "linux.sysctl {} read-back exceeds {MAX_SYSCTL_READBACK_BYTES} bytes",
                key.canonical()
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|source| {
        sysctl_error(
            ErrorCode::FailedPrecondition,
            format!(
                "linux.sysctl {} read-back is not UTF-8: {source}",
                key.canonical()
            ),
        )
    })
}

fn write_value(host_proc: &File, key: &OciLinuxSysctlKey, value: &str) -> Result<()> {
    let destination = open_sysctl(host_proc, key, libc::O_WRONLY | libc::O_TRUNC)?;
    let bytes: &[u8] = if value.is_empty() {
        b"\n"
    } else {
        value.as_bytes()
    };
    // SAFETY: the descriptor and byte slice remain live for one bounded write.
    let written =
        unsafe { libc::write(destination.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 {
        let source = io::Error::last_os_error();
        return Err(sysctl_error(
            error_code_for_io(&source),
            format!("write linux.sysctl {} failed: {source}", key.canonical()),
        ));
    }
    if usize::try_from(written).ok() != Some(bytes.len()) {
        return Err(sysctl_error(
            ErrorCode::FailedPrecondition,
            format!(
                "write linux.sysctl {} accepted {written} of {} bytes",
                key.canonical(),
                bytes.len()
            ),
        ));
    }
    Ok(())
}

fn verify_value(
    host_proc: &File,
    key: &OciLinuxSysctlKey,
    expected: &str,
    purpose: &str,
) -> Result<()> {
    let actual = read_value(host_proc, key)?;
    if equivalent_values(expected, &actual) {
        Ok(())
    } else {
        Err(sysctl_error(
            ErrorCode::FailedPrecondition,
            format!(
                "linux.sysctl {} {purpose} read-back did not match the requested token sequence",
                key.canonical()
            ),
        ))
    }
}

fn equivalent_values(expected: &str, actual: &str) -> bool {
    expected
        .split_ascii_whitespace()
        .eq(actual.split_ascii_whitespace())
}

fn open_sysctl(host_proc: &File, key: &OciLinuxSysctlKey, flags: i32) -> Result<File> {
    let path = CString::new(format!("sys/{}", key.procfs_path())).map_err(|source| {
        sysctl_error(
            ErrorCode::Internal,
            format!("validated linux.sysctl procfs path became invalid: {source}"),
        )
    })?;
    let how = OpenHow {
        flags: u64::try_from(flags | libc::O_CLOEXEC | libc::O_NOFOLLOW).unwrap_or(u64::MAX),
        mode: 0,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS | libc::RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: `host_proc` is a live retained procfs descriptor, `path` is a
    // bounded NUL-terminated relative path, and `how` has the kernel ABI shape.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            host_proc.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return Err(sysctl_error(
            error_code_for_io(&source),
            format!(
                "open retained procfs linux.sysctl {} failed: {source}",
                key.canonical()
            ),
        ));
    }
    let descriptor = i32::try_from(descriptor).map_err(|source| {
        sysctl_error(
            ErrorCode::Internal,
            format!("openat2 returned an invalid sysctl descriptor: {source}"),
        )
    })?;
    // SAFETY: openat2 returned a fresh descriptor whose ownership transfers
    // exactly once to `File`.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata().map_err(|source| {
        sysctl_error(
            error_code_for_io(&source),
            format!(
                "inspect retained procfs linux.sysctl {} failed: {source}",
                key.canonical()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(sysctl_error(
            ErrorCode::FailedPrecondition,
            format!(
                "retained procfs linux.sysctl {} is not a regular kernel control",
                key.canonical()
            ),
        ));
    }
    Ok(file)
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::ENOENT | libc::ENOTDIR | libc::ELOOP | libc::EXDEV) => {
            ErrorCode::FailedPrecondition
        }
        Some(libc::EINVAL) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    }
}

fn plan_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("plan-guest-init")
}

fn sysctl_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("apply-linux-sysctl")
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::Path;

    use a3s_oci_sdk::OciLinuxSysctlKey;
    use tempfile::{tempdir, TempDir};

    use super::{SysctlEntry, SysctlPlan};

    fn fake_proc(entries: &[(&str, &str)]) -> (TempDir, File) {
        let temporary = tempdir().expect("temporary procfs");
        for (path, value) in entries {
            let path = temporary.path().join("sys").join(path);
            std::fs::create_dir_all(path.parent().expect("sysctl parent"))
                .expect("fake sysctl parent");
            std::fs::write(path, value).expect("fake sysctl value");
        }
        let retained = File::open(temporary.path()).expect("retain fake procfs");
        (temporary, retained)
    }

    fn plan(entries: &[(&str, &str)]) -> SysctlPlan {
        SysctlPlan {
            entries: entries
                .iter()
                .map(|(key, value)| SysctlEntry {
                    key: OciLinuxSysctlKey::parse(key).expect("test sysctl key"),
                    value: (*value).to_string(),
                })
                .collect(),
        }
    }

    fn read(root: &Path, path: &str) -> String {
        std::fs::read_to_string(root.join("sys").join(path)).expect("read fake sysctl")
    }

    #[test]
    fn applies_reads_back_and_commits_exact_values() {
        let (temporary, retained) =
            fake_proc(&[("kernel/msgmax", "8192\n"), ("net/ipv4/ip_forward", "0\n")]);
        let plan = plan(&[("kernel.msgmax", "16384"), ("net.ipv4.ip_forward", "1")]);

        let applied = plan.apply(&retained).expect("apply sysctls");
        assert_eq!(read(temporary.path(), "kernel/msgmax"), "16384");
        assert_eq!(read(temporary.path(), "net/ipv4/ip_forward"), "1");
        applied.commit();

        assert_eq!(read(temporary.path(), "kernel/msgmax"), "16384");
        assert_eq!(read(temporary.path(), "net/ipv4/ip_forward"), "1");
    }

    #[test]
    fn an_uncommitted_transaction_restores_original_values() {
        let (temporary, retained) = fake_proc(&[("net/ipv4/ip_forward", "0\n")]);
        let plan = plan(&[("net.ipv4.ip_forward", "1")]);

        let applied = plan.apply(&retained).expect("apply sysctl");
        assert_eq!(read(temporary.path(), "net/ipv4/ip_forward"), "1");
        drop(applied);

        assert_eq!(read(temporary.path(), "net/ipv4/ip_forward"), "0");
    }

    #[test]
    fn partial_application_rolls_back_instead_of_leaving_the_first_write() {
        let (temporary, retained) = fake_proc(&[("kernel/msgmax", "8192\n")]);
        let plan = plan(&[("kernel.msgmax", "16384"), ("net.ipv4.ip_forward", "1")]);

        let error = plan
            .apply(&retained)
            .expect_err("missing second sysctl must fail");
        assert!(error.message.contains("net.ipv4.ip_forward"));
        assert_eq!(read(temporary.path(), "kernel/msgmax"), "8192");
    }
}
