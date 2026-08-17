use oci_spec::runtime::{MemoryPolicyFlagType, MemoryPolicyModeType};

/// Maximum NUMA node-bit count accepted by the bounded memory-policy parser.
///
/// Linux rejects masks larger than one base page. The supported x86_64 and
/// AArch64 guests use at least 4 KiB pages, so 32,768 bits covers the largest
/// mask accepted by a minimum-page-size kernel without host probing.
pub const OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS: usize = 32_768;

/// OCI Linux NUMA memory-policy modes recognized by the shared executor.
pub const OCI_LINUX_MEMORY_POLICY_MODES: &[MemoryPolicyModeType] = &[
    MemoryPolicyModeType::MpolDefault,
    MemoryPolicyModeType::MpolBind,
    MemoryPolicyModeType::MpolInterleave,
    MemoryPolicyModeType::MpolWeightedInterleave,
    MemoryPolicyModeType::MpolPreferred,
    MemoryPolicyModeType::MpolPreferredMany,
    MemoryPolicyModeType::MpolLocal,
];

/// OCI Linux NUMA memory-policy flags recognized by the shared executor.
pub const OCI_LINUX_MEMORY_POLICY_FLAGS: &[MemoryPolicyFlagType] = &[
    MemoryPolicyFlagType::MpolFNumaBalancing,
    MemoryPolicyFlagType::MpolFRelativeNodes,
    MemoryPolicyFlagType::MpolFStaticNodes,
];

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{OCI_LINUX_MEMORY_POLICY_FLAGS, OCI_LINUX_MEMORY_POLICY_MODES};

    #[test]
    fn registries_cover_every_oci_memory_policy_value_once() {
        let modes = OCI_LINUX_MEMORY_POLICY_MODES
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let flags = OCI_LINUX_MEMORY_POLICY_FLAGS
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();

        assert_eq!(modes.len(), OCI_LINUX_MEMORY_POLICY_MODES.len());
        assert_eq!(flags.len(), OCI_LINUX_MEMORY_POLICY_FLAGS.len());
        assert_eq!(
            modes,
            [
                "MPOL_BIND",
                "MPOL_DEFAULT",
                "MPOL_INTERLEAVE",
                "MPOL_LOCAL",
                "MPOL_PREFERRED",
                "MPOL_PREFERRED_MANY",
                "MPOL_WEIGHTED_INTERLEAVE",
            ]
            .map(str::to_string)
            .into_iter()
            .collect()
        );
        assert_eq!(
            flags,
            [
                "MPOL_F_NUMA_BALANCING",
                "MPOL_F_RELATIVE_NODES",
                "MPOL_F_STATIC_NODES",
            ]
            .map(str::to_string)
            .into_iter()
            .collect()
        );
    }
}
