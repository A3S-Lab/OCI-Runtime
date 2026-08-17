use std::fmt;

/// Maximum encoded length accepted for an OCI Linux `cgroupsPath`.
pub const OCI_LINUX_CGROUP_PATH_MAX_BYTES: usize = 4_096;

/// Maximum encoded length accepted for one cgroupfs name.
pub const OCI_LINUX_CGROUP_NAME_MAX_BYTES: usize = 255;

/// Stable classification for an invalid OCI Linux `cgroupsPath`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciLinuxCgroupPathErrorKind {
    /// The path is an empty string.
    Empty,
    /// The path contains a NUL byte.
    Nul,
    /// The complete path exceeds the executor bound.
    TooLong,
    /// One cgroupfs name exceeds the kernel name bound.
    ComponentTooLong,
    /// The path is ambiguous, traverses, or uses unsupported systemd syntax.
    UnsafePath,
}

/// Error returned while parsing an OCI Linux `cgroupsPath`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLinuxCgroupPathError {
    kind: OciLinuxCgroupPathErrorKind,
}

impl OciLinuxCgroupPathError {
    const fn new(kind: OciLinuxCgroupPathErrorKind) -> Self {
        Self { kind }
    }

    /// Stable error classification suitable for semantic validation.
    #[must_use]
    pub const fn kind(&self) -> OciLinuxCgroupPathErrorKind {
        self.kind
    }
}

impl fmt::Display for OciLinuxCgroupPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            OciLinuxCgroupPathErrorKind::Empty => "linux.cgroupsPath is empty",
            OciLinuxCgroupPathErrorKind::Nul => "linux.cgroupsPath contains a NUL byte",
            OciLinuxCgroupPathErrorKind::TooLong => "linux.cgroupsPath is too long",
            OciLinuxCgroupPathErrorKind::ComponentTooLong => {
                "linux.cgroupsPath contains an overlong cgroup name"
            }
            OciLinuxCgroupPathErrorKind::UnsafePath => {
                "linux.cgroupsPath must be a normalized absolute or relative cgroupfs path without traversal, control characters, or systemd syntax"
            }
        })
    }
}

impl std::error::Error for OciLinuxCgroupPathError {}

/// Parsed OCI Linux cgroup identity shared by validation and execution.
///
/// `relative` never begins or ends with `/` and contains only bounded,
/// normalized cgroupfs names. The `absolute` bit preserves whether the source
/// path must be resolved from the visible cgroup mount point or from the
/// runtime's stable private location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLinuxCgroupPath {
    absolute: bool,
    relative: String,
}

impl OciLinuxCgroupPath {
    /// Parse Linux path syntax identically on Linux, macOS, and Windows hosts.
    pub fn parse(value: &str) -> Result<Self, OciLinuxCgroupPathError> {
        if value.is_empty() {
            return Err(OciLinuxCgroupPathError::new(
                OciLinuxCgroupPathErrorKind::Empty,
            ));
        }
        if value.as_bytes().contains(&0) {
            return Err(OciLinuxCgroupPathError::new(
                OciLinuxCgroupPathErrorKind::Nul,
            ));
        }
        if value.len() > OCI_LINUX_CGROUP_PATH_MAX_BYTES {
            return Err(OciLinuxCgroupPathError::new(
                OciLinuxCgroupPathErrorKind::TooLong,
            ));
        }

        let absolute = value.starts_with('/');
        let relative = if absolute { &value[1..] } else { value };
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.ends_with('/')
            || relative.split('/').any(|component| {
                component.is_empty()
                    || matches!(component, "." | "..")
                    || component.contains(':')
                    || component.chars().any(char::is_control)
            })
        {
            return Err(OciLinuxCgroupPathError::new(
                OciLinuxCgroupPathErrorKind::UnsafePath,
            ));
        }
        if relative
            .split('/')
            .any(|component| component.len() > OCI_LINUX_CGROUP_NAME_MAX_BYTES)
        {
            return Err(OciLinuxCgroupPathError::new(
                OciLinuxCgroupPathErrorKind::ComponentTooLong,
            ));
        }

        Ok(Self {
            absolute,
            relative: relative.to_string(),
        })
    }

    /// Whether this path is rooted at the visible cgroup mount point.
    #[must_use]
    pub const fn is_absolute(&self) -> bool {
        self.absolute
    }

    /// Normalized path below the selected cgroup base, without a leading `/`.
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.relative
    }
}
