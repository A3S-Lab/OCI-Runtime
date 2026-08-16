use std::fmt;

const MAX_SYSCTL_KEY_BYTES: usize = 4_096;
const MAX_SYSCTL_PATH_COMPONENT_BYTES: usize = 255;

const IPC_SYSCTLS: &[&str] = &[
    "kernel.msgmax",
    "kernel.msgmnb",
    "kernel.msgmni",
    "kernel.sem",
    "kernel.shmall",
    "kernel.shmmax",
    "kernel.shmmni",
    "kernel.shm_rmid_forced",
];

/// Kernel namespace that owns one OCI Linux sysctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OciLinuxSysctlNamespace {
    /// System V IPC and POSIX message-queue controls.
    Ipc,
    /// Network-stack controls.
    Network,
    /// UTS domain-name controls.
    Uts,
    /// Per-user-namespace ucount controls.
    User,
}

/// Stable classification for an invalid or unsupported OCI Linux sysctl key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciLinuxSysctlKeyErrorKind {
    /// The key is empty.
    Empty,
    /// The key contains a NUL byte.
    Nul,
    /// The key exceeds the bounded executor path representation.
    TooLong,
    /// The key would escape or ambiguously traverse procfs.
    UnsafePath,
    /// `kernel.hostname` conflicts with the dedicated OCI `hostname` field.
    HostnameConflict,
    /// The key is not known to be isolated by a Linux namespace.
    NotNamespaced,
}

/// Error returned while parsing an OCI Linux sysctl key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLinuxSysctlKeyError {
    kind: OciLinuxSysctlKeyErrorKind,
}

impl OciLinuxSysctlKeyError {
    const fn new(kind: OciLinuxSysctlKeyErrorKind) -> Self {
        Self { kind }
    }

    /// Stable error classification suitable for semantic validation.
    #[must_use]
    pub const fn kind(&self) -> OciLinuxSysctlKeyErrorKind {
        self.kind
    }
}

impl fmt::Display for OciLinuxSysctlKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            OciLinuxSysctlKeyErrorKind::Empty => "sysctl key is empty",
            OciLinuxSysctlKeyErrorKind::Nul => "sysctl key contains a NUL byte",
            OciLinuxSysctlKeyErrorKind::TooLong => "sysctl key is too long",
            OciLinuxSysctlKeyErrorKind::UnsafePath => {
                "sysctl key does not map to a safe relative procfs path"
            }
            OciLinuxSysctlKeyErrorKind::HostnameConflict => {
                "kernel.hostname conflicts with the dedicated OCI hostname field"
            }
            OciLinuxSysctlKeyErrorKind::NotNamespaced => {
                "sysctl key is not known to be isolated by a Linux namespace"
            }
        })
    }
}

impl std::error::Error for OciLinuxSysctlKeyError {}

/// Parsed OCI Linux sysctl identity shared by validation and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciLinuxSysctlKey {
    canonical: String,
    procfs_path: String,
    namespace: OciLinuxSysctlNamespace,
}

impl OciLinuxSysctlKey {
    /// Parse dot- or slash-separated sysctl notation without permitting a
    /// procfs escape or a host-global kernel control.
    pub fn parse(value: &str) -> Result<Self, OciLinuxSysctlKeyError> {
        if value.is_empty() {
            return Err(OciLinuxSysctlKeyError::new(
                OciLinuxSysctlKeyErrorKind::Empty,
            ));
        }
        if value.as_bytes().contains(&0) {
            return Err(OciLinuxSysctlKeyError::new(OciLinuxSysctlKeyErrorKind::Nul));
        }
        if value.len() > MAX_SYSCTL_KEY_BYTES {
            return Err(OciLinuxSysctlKeyError::new(
                OciLinuxSysctlKeyErrorKind::TooLong,
            ));
        }

        let first_separator = value.find(['.', '/']);
        let slash_notation = first_separator.is_some_and(|index| value.as_bytes()[index] == b'/');
        let canonical = if slash_notation {
            swap_sysctl_separators(value)
        } else {
            value.to_string()
        };
        let namespace = classify(&canonical)?;
        let procfs_path = if slash_notation {
            value.to_string()
        } else {
            swap_sysctl_separators(value)
        };
        validate_procfs_path(&procfs_path)?;

        Ok(Self {
            canonical,
            procfs_path,
            namespace,
        })
    }

    /// Canonical dot-separated identity used for namespace classification.
    #[must_use]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Safe path below `/proc/sys`, without the leading `sys/` component.
    #[must_use]
    pub fn procfs_path(&self) -> &str {
        &self.procfs_path
    }

    /// Namespace that must be isolated before this key may be changed.
    #[must_use]
    pub const fn namespace(&self) -> OciLinuxSysctlNamespace {
        self.namespace
    }
}

fn classify(canonical: &str) -> Result<OciLinuxSysctlNamespace, OciLinuxSysctlKeyError> {
    if IPC_SYSCTLS.contains(&canonical) || canonical.starts_with("fs.mqueue.") {
        return Ok(OciLinuxSysctlNamespace::Ipc);
    }
    if canonical.starts_with("net.") {
        return Ok(OciLinuxSysctlNamespace::Network);
    }
    if canonical == "kernel.domainname" {
        return Ok(OciLinuxSysctlNamespace::Uts);
    }
    if canonical == "kernel.hostname" {
        return Err(OciLinuxSysctlKeyError::new(
            OciLinuxSysctlKeyErrorKind::HostnameConflict,
        ));
    }
    if canonical.starts_with("user.") {
        return Ok(OciLinuxSysctlNamespace::User);
    }
    Err(OciLinuxSysctlKeyError::new(
        OciLinuxSysctlKeyErrorKind::NotNamespaced,
    ))
}

fn swap_sysctl_separators(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '.' => '/',
            '/' => '.',
            other => other,
        })
        .collect()
}

fn validate_procfs_path(path: &str) -> Result<(), OciLinuxSysctlKeyError> {
    if path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.len() > MAX_SYSCTL_PATH_COMPONENT_BYTES
        })
    {
        Err(OciLinuxSysctlKeyError::new(
            OciLinuxSysctlKeyErrorKind::UnsafePath,
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{OciLinuxSysctlKey, OciLinuxSysctlKeyErrorKind, OciLinuxSysctlNamespace};

    #[test]
    fn normalizes_dot_and_slash_notation_without_losing_literal_dots() {
        let dotted = OciLinuxSysctlKey::parse("net.ipv4.conf.eno2/100.rp_filter")
            .expect("dotted sysctl notation");
        let slashed = OciLinuxSysctlKey::parse("net/ipv4/conf/eno2.100/rp_filter")
            .expect("slash sysctl notation");

        assert_eq!(dotted, slashed);
        assert_eq!(dotted.canonical(), "net.ipv4.conf.eno2/100.rp_filter");
        assert_eq!(dotted.procfs_path(), "net/ipv4/conf/eno2.100/rp_filter");
        assert_eq!(dotted.namespace(), OciLinuxSysctlNamespace::Network);
    }

    #[test]
    fn classifies_only_known_namespaced_sysctl_families() {
        for (key, namespace) in [
            ("kernel.msgmax", OciLinuxSysctlNamespace::Ipc),
            ("fs.mqueue.msg_max", OciLinuxSysctlNamespace::Ipc),
            ("net.ipv4.ip_forward", OciLinuxSysctlNamespace::Network),
            ("kernel.domainname", OciLinuxSysctlNamespace::Uts),
            ("user.max_user_namespaces", OciLinuxSysctlNamespace::User),
        ] {
            assert_eq!(
                OciLinuxSysctlKey::parse(key)
                    .expect("known namespaced sysctl")
                    .namespace(),
                namespace
            );
        }
    }

    #[test]
    fn rejects_hostname_host_global_and_escaping_keys() {
        for (key, expected) in [
            (
                "kernel.hostname",
                OciLinuxSysctlKeyErrorKind::HostnameConflict,
            ),
            ("vm.swappiness", OciLinuxSysctlKeyErrorKind::NotNamespaced),
            ("net..ipv4", OciLinuxSysctlKeyErrorKind::UnsafePath),
            ("net/../ipv4", OciLinuxSysctlKeyErrorKind::UnsafePath),
            (
                "/net/ipv4/ip_forward",
                OciLinuxSysctlKeyErrorKind::NotNamespaced,
            ),
        ] {
            assert_eq!(
                OciLinuxSysctlKey::parse(key)
                    .expect_err("unsafe sysctl key")
                    .kind(),
                expected,
                "unexpected classification for {key}"
            );
        }
    }
}
