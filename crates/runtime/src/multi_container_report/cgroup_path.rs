use serde::{Deserialize, Serialize};

/// Exact host-hierarchy evidence for OCI Linux `cgroupsPath` resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupPathEvidence {
    /// Relative value submitted for the recreated first container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_relative: Option<String>,
    /// Absolute value submitted for the second container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_absolute: Option<String>,
    /// Initial host-visible membership for the relative value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_relative_initial: Option<String>,
    /// Recreated host-visible membership for the same relative value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_relative_recreated: Option<String>,
    /// Host-visible membership for the absolute value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_absolute: Option<String>,
    /// Whether the absolute value resolved exactly from the cgroup mount point.
    pub absolute_mountpoint_resolution_verified: bool,
    /// Whether recreating the relative value selected exactly the same location.
    pub relative_recreate_resolution_verified: bool,
    /// Whether the absolute and runtime-relative locations remained distinct.
    pub distinct_locations: bool,
    /// Whether deletion removed both exact workload cgroups.
    pub paths_removed_after_delete: bool,
}

impl CgroupPathEvidence {
    /// Return whether absolute, relative, repeat, and cleanup semantics passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.requested_relative.is_some()
            && self.requested_absolute.is_some()
            && self.observed_relative_initial.is_some()
            && self.observed_relative_recreated.is_some()
            && self.observed_absolute.is_some()
            && self.absolute_mountpoint_resolution_verified
            && self.relative_recreate_resolution_verified
            && self.distinct_locations
            && self.paths_removed_after_delete
    }
}
