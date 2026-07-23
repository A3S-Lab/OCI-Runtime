use serde::Serialize;

/// Relationship between a semantic rule and OCI conformance evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSemanticRuleKind {
    /// The rule directly validates an applicable OCI specification statement.
    Normative,
    /// The rule rejects an invalid kernel, syscall, or transport input.
    RuntimeConstraint,
    /// The rule enforces the advertised A3S workload-platform boundary.
    PlatformPolicy,
}

/// Stable descriptor for one SDK semantic-validation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSemanticRule {
    pub id: &'static str,
    pub kind: OciSemanticRuleKind,
}

impl OciSemanticRule {
    const fn new(id: &'static str, kind: OciSemanticRuleKind) -> Self {
        Self { id, kind }
    }
}

macro_rules! define_rules {
    ($($name:ident => $kind:ident, $id:literal;)+) => {
        $(
            pub(super) const $name: OciSemanticRule =
                OciSemanticRule::new($id, OciSemanticRuleKind::$kind);
        )+

        pub(super) const ALL: &[OciSemanticRule] = &[
            $($name,)+
        ];
    };
}

define_rules! {
    ANNOTATION_KEY_NON_EMPTY => Normative, "oci.common.annotation.key.non-empty";
    ENVIRONMENT_ASSIGNMENT => RuntimeConstraint, "oci.common.environment.assignment";
    ENVIRONMENT_NAME_NON_EMPTY => RuntimeConstraint, "oci.common.environment.name.non-empty";
    ENVIRONMENT_NO_NUL => RuntimeConstraint, "oci.common.environment.no-nul";
    HOOK_PATH_ABSOLUTE => Normative, "oci.common.hook.path.absolute";
    MOUNT_DESTINATION_NON_EMPTY => Normative, "oci.common.mount.destination.non-empty";
    MOUNT_ID_MAPPINGS_PAIRED => Normative, "oci.common.mount.id-mappings.paired";
    PATH_NO_NUL => RuntimeConstraint, "oci.common.path.no-nul";
    PROCESS_ARGS_NON_EMPTY => Normative, "oci.common.process.args.non-empty";
    PROCESS_ARGS_REQUIRED_LINUX => Normative, "oci.common.process.args.required-linux";
    PROCESS_ARGUMENT_NO_NUL => RuntimeConstraint, "oci.common.process.argument.no-nul";
    PROCESS_CWD_ABSOLUTE => Normative, "oci.common.process.cwd.absolute";
    PROCESS_EXECUTABLE_NON_EMPTY => Normative, "oci.common.process.executable.non-empty";
    PROCESS_REQUIRED_FOR_START => Normative, "oci.common.process.required-for-start";
    RLIMIT_SOFT_AT_MOST_HARD => RuntimeConstraint, "oci.common.rlimit.soft-at-most-hard";
    RLIMIT_TYPE_UNIQUE => Normative, "oci.common.rlimit.type.unique";
    ROOT_PATH_NON_EMPTY => Normative, "oci.common.root.path.non-empty";
    ROOT_REQUIRED => Normative, "oci.common.root.required";
    BLOCK_IO_WEIGHT_DEVICE_WEIGHT_REQUIRED => Normative, "oci.linux.block-io.weight-device.weight-required";
    CONTAINER_PATH_ABSOLUTE => Normative, "oci.linux.container-path.absolute";
    CPU_BURST_AT_MOST_QUOTA => Normative, "oci.linux.cpu.burst-at-most-quota";
    CPU_REALTIME_RUNTIME_AT_MOST_PERIOD => RuntimeConstraint, "oci.linux.cpu.realtime-runtime-at-most-period";
    DEVICE_PATH_ABSOLUTE => RuntimeConstraint, "oci.linux.device.path.absolute";
    DOMAINNAME_REQUIRES_UTS_NAMESPACE => RuntimeConstraint, "oci.linux.domainname.requires-uts-namespace";
    HOSTNAME_REQUIRES_UTS_NAMESPACE => RuntimeConstraint, "oci.linux.hostname.requires-uts-namespace";
    ID_MAPPING_CONTAINER_RANGE => RuntimeConstraint, "oci.linux.id-mapping.container-range";
    ID_MAPPING_CONTAINER_RANGE_UNIQUE => RuntimeConstraint, "oci.linux.id-mapping.container-range.unique";
    ID_MAPPING_HOST_RANGE => RuntimeConstraint, "oci.linux.id-mapping.host-range";
    ID_MAPPING_HOST_RANGE_UNIQUE => RuntimeConstraint, "oci.linux.id-mapping.host-range.unique";
    ID_MAPPING_REQUIRES_NEW_USER_NAMESPACE => RuntimeConstraint, "oci.linux.id-mapping.requires-new-user-namespace";
    ID_MAPPING_SIZE_NONZERO => RuntimeConstraint, "oci.linux.id-mapping.size.nonzero";
    INTEL_RDT_CLOS_ID_SAFE_NAME => RuntimeConstraint, "oci.linux.intel-rdt.clos-id.safe-name";
    INTEL_RDT_L3_SCHEMA => RuntimeConstraint, "oci.linux.intel-rdt.l3-schema";
    INTEL_RDT_MEMORY_BANDWIDTH_SCHEMA => RuntimeConstraint, "oci.linux.intel-rdt.memory-bandwidth-schema";
    INTEL_RDT_SCHEMATA_SINGLE_LINE => RuntimeConstraint, "oci.linux.intel-rdt.schemata.single-line";
    IO_PRIORITY_RANGE => Normative, "oci.linux.io-priority.range";
    MEMORY_POLICY_NODES_FORBIDDEN => RuntimeConstraint, "oci.linux.memory-policy.nodes-forbidden";
    MEMORY_POLICY_NODES_REQUIRED => RuntimeConstraint, "oci.linux.memory-policy.nodes-required";
    MOUNT_IDMAP_MAPPING_REQUIRED => RuntimeConstraint, "oci.linux.mount.idmap.mapping-required";
    MOUNT_IDMAP_MODE_UNIQUE => RuntimeConstraint, "oci.linux.mount.idmap.mode.unique";
    NAMESPACE_PATH_ABSOLUTE => Normative, "oci.linux.namespace.path.absolute";
    NAMESPACE_TYPE_UNIQUE => Normative, "oci.linux.namespace.type.unique";
    NET_DEVICE_CONTAINER_NAME_VALID => RuntimeConstraint, "oci.linux.net-device.container-name.valid";
    NET_DEVICE_HOST_NAME_VALID => RuntimeConstraint, "oci.linux.net-device.host-name.valid";
    NET_DEVICE_NAME_NO_NUL => RuntimeConstraint, "oci.linux.net-device.name.no-nul";
    NET_DEVICE_REQUIRES_NETWORK_NAMESPACE => RuntimeConstraint, "oci.linux.net-device.requires-network-namespace";
    RDMA_LIMIT_REQUIRED => Normative, "oci.linux.rdma.limit-required";
    RESTRICTED_PATH_REQUIRES_MOUNT_NAMESPACE => RuntimeConstraint, "oci.linux.restricted-path.requires-mount-namespace";
    SCHEDULER_DEADLINE_FIELDS_POLICY => RuntimeConstraint, "oci.linux.scheduler.deadline-fields.policy";
    SCHEDULER_DEADLINE_ORDER => RuntimeConstraint, "oci.linux.scheduler.deadline-order";
    SCHEDULER_NICE_RANGE => RuntimeConstraint, "oci.linux.scheduler.nice.range";
    SCHEDULER_PRIORITY_POLICY => RuntimeConstraint, "oci.linux.scheduler.priority.policy";
    SECCOMP_ERRNO_ACTION => RuntimeConstraint, "oci.linux.seccomp.errno-action";
    SECCOMP_LISTENER_METADATA_REQUIRES_PATH => RuntimeConstraint, "oci.linux.seccomp.listener-metadata.requires-path";
    SYSCTL_HOSTNAME_CONFLICT => RuntimeConstraint, "oci.linux.sysctl.hostname-conflict";
    SYSCTL_NO_NUL => RuntimeConstraint, "oci.linux.sysctl.no-nul";
    SYSCTL_NOT_NAMESPACED => RuntimeConstraint, "oci.linux.sysctl.not-namespaced";
    SYSCTL_REQUIRES_IPC_NAMESPACE => RuntimeConstraint, "oci.linux.sysctl.requires-ipc-namespace";
    SYSCTL_REQUIRES_NETWORK_NAMESPACE => RuntimeConstraint, "oci.linux.sysctl.requires-network-namespace";
    SYSCTL_REQUIRES_USER_NAMESPACE => RuntimeConstraint, "oci.linux.sysctl.requires-user-namespace";
    SYSCTL_REQUIRES_UTS_NAMESPACE => RuntimeConstraint, "oci.linux.sysctl.requires-uts-namespace";
    TIME_OFFSET_REQUIRES_NEW_TIME_NAMESPACE => RuntimeConstraint, "oci.linux.time-offset.requires-new-time-namespace";
    USER_NAMESPACE_MAPPING_REQUIRED => RuntimeConstraint, "oci.linux.user-namespace.mapping-required";
    PLATFORM_LINUX_ONLY => PlatformPolicy, "oci.platform.linux-only";
    PLATFORM_WINDOWS_PROCESS_FIELD => PlatformPolicy, "oci.platform.windows-process-field";
    VM_PARAMETER_NO_NUL => RuntimeConstraint, "oci.vm.parameter.no-nul";
    VM_PATH_ABSOLUTE => Normative, "oci.vm.path.absolute";
}
