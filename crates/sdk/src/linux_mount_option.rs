/// RFC 2119 requirement attached to one Linux mount option in OCI 1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciLinuxMountOptionRequirement {
    /// The runtime specification marks the option as `MUST`.
    Required,
    /// The runtime specification marks the option as `SHOULD`.
    Recommended,
    /// The runtime specification marks the option as `MAY`.
    Optional,
}

/// One Linux mount option named by the pinned OCI Runtime Specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciLinuxMountOption {
    name: &'static str,
    requirement: OciLinuxMountOptionRequirement,
}

impl OciLinuxMountOption {
    const fn new(name: &'static str, requirement: OciLinuxMountOptionRequirement) -> Self {
        Self { name, requirement }
    }

    /// Exact option spelling from OCI Runtime Specification 1.3.0.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Normative implementation level assigned by OCI 1.3.0.
    #[must_use]
    pub const fn requirement(self) -> OciLinuxMountOptionRequirement {
        self.requirement
    }
}

use OciLinuxMountOptionRequirement::{Optional, Recommended, Required};

/// Complete Linux mount-option table from OCI Runtime Specification 1.3.0.
///
/// The upstream source contains trailing whitespace in the `rrelatime` table
/// cell. The option name itself is retained here without presentation
/// whitespace, as it is in upstream feature reports and `mount_setattr(2)`
/// implementations.
pub const OCI_LINUX_MOUNT_OPTIONS: &[OciLinuxMountOption] = &[
    OciLinuxMountOption::new("async", Required),
    OciLinuxMountOption::new("atime", Required),
    OciLinuxMountOption::new("bind", Required),
    OciLinuxMountOption::new("defaults", Required),
    OciLinuxMountOption::new("dev", Required),
    OciLinuxMountOption::new("diratime", Required),
    OciLinuxMountOption::new("dirsync", Required),
    OciLinuxMountOption::new("exec", Required),
    OciLinuxMountOption::new("iversion", Required),
    OciLinuxMountOption::new("lazytime", Required),
    OciLinuxMountOption::new("loud", Required),
    OciLinuxMountOption::new("mand", Optional),
    OciLinuxMountOption::new("noatime", Required),
    OciLinuxMountOption::new("nodev", Required),
    OciLinuxMountOption::new("nodiratime", Required),
    OciLinuxMountOption::new("noexec", Required),
    OciLinuxMountOption::new("noiversion", Required),
    OciLinuxMountOption::new("nolazytime", Required),
    OciLinuxMountOption::new("nomand", Optional),
    OciLinuxMountOption::new("norelatime", Required),
    OciLinuxMountOption::new("nostrictatime", Required),
    OciLinuxMountOption::new("nosuid", Required),
    OciLinuxMountOption::new("nosymfollow", Recommended),
    OciLinuxMountOption::new("private", Required),
    OciLinuxMountOption::new("ratime", Recommended),
    OciLinuxMountOption::new("rbind", Required),
    OciLinuxMountOption::new("rdev", Recommended),
    OciLinuxMountOption::new("rdiratime", Recommended),
    OciLinuxMountOption::new("relatime", Required),
    OciLinuxMountOption::new("remount", Required),
    OciLinuxMountOption::new("rexec", Recommended),
    OciLinuxMountOption::new("rnoatime", Recommended),
    OciLinuxMountOption::new("rnodiratime", Recommended),
    OciLinuxMountOption::new("rnoexec", Recommended),
    OciLinuxMountOption::new("rnorelatime", Recommended),
    OciLinuxMountOption::new("rnostrictatime", Recommended),
    OciLinuxMountOption::new("rnosuid", Recommended),
    OciLinuxMountOption::new("rnosymfollow", Recommended),
    OciLinuxMountOption::new("ro", Required),
    OciLinuxMountOption::new("rprivate", Required),
    OciLinuxMountOption::new("rrelatime", Recommended),
    OciLinuxMountOption::new("rro", Recommended),
    OciLinuxMountOption::new("rrw", Recommended),
    OciLinuxMountOption::new("rshared", Required),
    OciLinuxMountOption::new("rslave", Required),
    OciLinuxMountOption::new("rstrictatime", Recommended),
    OciLinuxMountOption::new("rsuid", Recommended),
    OciLinuxMountOption::new("rsymfollow", Recommended),
    OciLinuxMountOption::new("runbindable", Required),
    OciLinuxMountOption::new("rw", Required),
    OciLinuxMountOption::new("shared", Required),
    OciLinuxMountOption::new("silent", Required),
    OciLinuxMountOption::new("slave", Required),
    OciLinuxMountOption::new("strictatime", Required),
    OciLinuxMountOption::new("suid", Required),
    OciLinuxMountOption::new("symfollow", Recommended),
    OciLinuxMountOption::new("sync", Required),
    OciLinuxMountOption::new("tmpcopyup", Optional),
    OciLinuxMountOption::new("unbindable", Required),
    OciLinuxMountOption::new("idmap", Recommended),
    OciLinuxMountOption::new("ridmap", Recommended),
];

#[cfg(test)]
mod tests {
    use super::{OciLinuxMountOptionRequirement, OCI_LINUX_MOUNT_OPTIONS};
    use std::collections::BTreeSet;

    #[test]
    fn registry_covers_the_pinned_oci_linux_mount_option_table_once() {
        let names = OCI_LINUX_MOUNT_OPTIONS
            .iter()
            .map(|option| option.name())
            .collect::<BTreeSet<_>>();

        assert_eq!(OCI_LINUX_MOUNT_OPTIONS.len(), 61);
        assert_eq!(names.len(), OCI_LINUX_MOUNT_OPTIONS.len());
        for (requirement, expected) in [
            (OciLinuxMountOptionRequirement::Required, 37),
            (OciLinuxMountOptionRequirement::Recommended, 21),
            (OciLinuxMountOptionRequirement::Optional, 3),
        ] {
            assert_eq!(
                OCI_LINUX_MOUNT_OPTIONS
                    .iter()
                    .filter(|option| option.requirement() == requirement)
                    .count(),
                expected
            );
        }
        assert!(names.contains("idmap"));
        assert!(names.contains("ridmap"));
        assert!(OCI_LINUX_MOUNT_OPTIONS.iter().any(|option| {
            option.name() == "tmpcopyup"
                && option.requirement() == OciLinuxMountOptionRequirement::Optional
        }));
    }
}
