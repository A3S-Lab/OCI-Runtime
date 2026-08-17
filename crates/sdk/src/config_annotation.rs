use crate::model::{
    CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION, CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION, CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION,
    PAUSED_STATE_ANNOTATION,
};
use crate::rootfs_metadata::PORTABLE_ROOTFS_METADATA_ANNOTATION;

/// Exact built-in configuration annotations that can affect runtime behavior.
///
/// Driver-specific attachment extensions are reported separately from the
/// active driver's capability inventory.
pub const BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS: &[&str] = &[
    CONTROL_CGROUP_CPU_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_MEMORY_HEADROOM_ANNOTATION,
    CONTROL_CGROUP_PIDS_HEADROOM_ANNOTATION,
    CONTROL_WORKLOAD_CGROUP_LAYOUT_ANNOTATION,
    PORTABLE_ROOTFS_METADATA_ANNOTATION,
    PAUSED_STATE_ANNOTATION,
];

#[cfg(test)]
mod tests {
    use super::BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS;

    #[test]
    fn builtin_unsafe_config_annotations_are_exact_sorted_reverse_dns_keys() {
        assert_eq!(
            BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS,
            [
                "dev.a3s.oci.cgroup.control-cpu-headroom-micros",
                "dev.a3s.oci.cgroup.control-memory-headroom-bytes",
                "dev.a3s.oci.cgroup.control-pids-headroom",
                "dev.a3s.oci.cgroup.layout",
                "dev.a3s.oci.rootfs-metadata",
                "dev.a3s.oci.runtime.paused",
            ]
        );
        assert!(BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        for annotation in BUILTIN_POTENTIALLY_UNSAFE_CONFIG_ANNOTATIONS {
            assert!(!annotation.ends_with('.'));
            assert!(annotation.split('.').count() >= 3);
            assert!(annotation.split('.').all(|label| {
                !label.is_empty()
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }));
        }
    }
}
