use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::{
    OciLinuxCgroupPath, OciLinuxSysctlKey, OciLinuxSysctlKeyErrorKind, OciLinuxSysctlNamespace,
};

use super::{contains_nul, is_posix_absolute, rules, OciSemanticRule, ViolationCollector};

#[derive(Default)]
struct NamespaceFacts {
    entries: BTreeMap<String, bool>,
}

impl NamespaceFacts {
    fn contains(&self, namespace: &str) -> bool {
        self.entries.contains_key(namespace)
    }

    fn creates(&self, namespace: &str) -> bool {
        self.entries.get(namespace) == Some(&true)
    }
}

pub(super) fn inspect(value: &Value, collector: &mut ViolationCollector) {
    let Some(configuration) = value.as_object() else {
        return;
    };
    let Some(linux) = configuration.get("linux").and_then(Value::as_object) else {
        return;
    };

    let namespaces = validate_namespaces(linux, collector);
    let uid_specified = linux.contains_key("uidMappings");
    let gid_specified = linux.contains_key("gidMappings");
    let uid_mappings =
        validate_mapping_array(linux, "uidMappings", "/linux/uidMappings", collector);
    let gid_mappings =
        validate_mapping_array(linux, "gidMappings", "/linux/gidMappings", collector);
    if (uid_specified || gid_specified) && !namespaces.creates("user") {
        collector.invalid(
            "/linux/namespaces",
            rules::ID_MAPPING_REQUIRES_NEW_USER_NAMESPACE,
            "Linux UID/GID mappings require a newly created user namespace",
        );
    }
    if namespaces.creates("user") && !(uid_mappings || gid_mappings) {
        collector.invalid(
            "/linux/namespaces",
            rules::USER_NAMESPACE_MAPPING_REQUIRED,
            "a newly created Linux user namespace requires UID or GID mappings",
        );
    }

    validate_mount_id_mappings(
        configuration,
        namespaces.creates("user") && uid_mappings && gid_mappings,
        collector,
    );
    validate_cgroup_path(linux, collector);
    validate_container_paths(linux, collector);
    validate_namespace_dependent_fields(configuration, linux, &namespaces, collector);
    validate_net_devices(linux, &namespaces, collector);
    validate_time_offsets(linux, &namespaces, collector);
    validate_sysctls(linux, &namespaces, collector);
    validate_seccomp(linux, collector);
    validate_resources(linux, collector);
    validate_intel_rdt(linux, collector);
    validate_memory_policy(linux, collector);
    validate_personality(linux, collector);
}

fn validate_cgroup_path(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(path) = linux.get("cgroupsPath").and_then(Value::as_str) else {
        return;
    };
    if let Err(error) = OciLinuxCgroupPath::parse(path) {
        collector.invalid(
            "/linux/cgroupsPath",
            rules::CGROUP_PATH_SAFE,
            error.to_string(),
        );
    }
}

fn validate_namespaces(
    linux: &Map<String, Value>,
    collector: &mut ViolationCollector,
) -> NamespaceFacts {
    let mut facts = NamespaceFacts::default();
    let Some(namespaces) = linux.get("namespaces").and_then(Value::as_array) else {
        return facts;
    };

    for (index, namespace) in namespaces.iter().filter_map(Value::as_object).enumerate() {
        let Some(kind) = namespace.get("type").and_then(Value::as_str) else {
            continue;
        };
        let creates = !namespace.contains_key("path");
        if facts.entries.insert(kind.to_string(), creates).is_some() {
            collector.invalid(
                format!("/linux/namespaces/{index}/type"),
                rules::NAMESPACE_TYPE_UNIQUE,
                format!("duplicate Linux namespace type {kind}"),
            );
        }
        if let Some(path) = namespace.get("path").and_then(Value::as_str) {
            if !is_posix_absolute(path) {
                collector.invalid(
                    format!("/linux/namespaces/{index}/path"),
                    rules::NAMESPACE_PATH_ABSOLUTE,
                    "Linux namespace paths must be absolute",
                );
            }
            if contains_nul(path) {
                collector.invalid(
                    format!("/linux/namespaces/{index}/path"),
                    rules::PATH_NO_NUL,
                    "Linux namespace paths must not contain a NUL byte",
                );
            }
        }
    }
    facts
}

#[derive(Clone, Copy)]
struct MappingRange {
    index: usize,
    container_start: u64,
    container_end: u64,
    host_start: u64,
    host_end: u64,
}

fn validate_mapping_array(
    object: &Map<String, Value>,
    field: &str,
    base_path: &str,
    collector: &mut ViolationCollector,
) -> bool {
    let Some(mappings) = object.get(field).and_then(Value::as_array) else {
        return false;
    };
    let mut ranges = Vec::new();
    for (index, mapping) in mappings.iter().filter_map(Value::as_object).enumerate() {
        let Some(container_start) = mapping.get("containerID").and_then(Value::as_u64) else {
            continue;
        };
        let Some(host_start) = mapping.get("hostID").and_then(Value::as_u64) else {
            continue;
        };
        let Some(size) = mapping.get("size").and_then(Value::as_u64) else {
            continue;
        };
        if size == 0 {
            collector.invalid(
                format!("{base_path}/{index}/size"),
                rules::ID_MAPPING_SIZE_NONZERO,
                "ID mapping size must be greater than zero",
            );
            continue;
        }
        let container_end = container_start.saturating_add(size);
        let host_end = host_start.saturating_add(size);
        let address_space_end = u64::from(u32::MAX) + 1;
        if container_end > address_space_end {
            collector.invalid(
                format!("{base_path}/{index}/containerID"),
                rules::ID_MAPPING_CONTAINER_RANGE,
                "ID mapping exceeds the uint32 container ID space",
            );
            continue;
        }
        if host_end > address_space_end {
            collector.invalid(
                format!("{base_path}/{index}/hostID"),
                rules::ID_MAPPING_HOST_RANGE,
                "ID mapping exceeds the uint32 host ID space",
            );
            continue;
        }
        ranges.push(MappingRange {
            index,
            container_start,
            container_end,
            host_start,
            host_end,
        });
    }

    for left_index in 0..ranges.len() {
        for right_index in (left_index + 1)..ranges.len() {
            let left = ranges[left_index];
            let right = ranges[right_index];
            if ranges_overlap(
                left.container_start,
                left.container_end,
                right.container_start,
                right.container_end,
            ) {
                collector.invalid(
                    format!("{base_path}/{}/containerID", right.index),
                    rules::ID_MAPPING_CONTAINER_RANGE_UNIQUE,
                    format!(
                        "container ID range overlaps mapping at index {}",
                        left.index
                    ),
                );
            }
            if ranges_overlap(
                left.host_start,
                left.host_end,
                right.host_start,
                right.host_end,
            ) {
                collector.invalid(
                    format!("{base_path}/{}/hostID", right.index),
                    rules::ID_MAPPING_HOST_RANGE_UNIQUE,
                    format!("host ID range overlaps mapping at index {}", left.index),
                );
            }
        }
    }
    !mappings.is_empty()
}

const fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    left_start < right_end && right_start < left_end
}

fn validate_mount_id_mappings(
    configuration: &Map<String, Value>,
    container_mapping_available: bool,
    collector: &mut ViolationCollector,
) {
    let Some(mounts) = configuration.get("mounts").and_then(Value::as_array) else {
        return;
    };
    for (index, mount) in mounts.iter().filter_map(Value::as_object).enumerate() {
        let base_path = format!("/mounts/{index}");
        let uid_mappings = validate_mapping_array(
            mount,
            "uidMappings",
            &format!("{base_path}/uidMappings"),
            collector,
        );
        let gid_mappings = validate_mapping_array(
            mount,
            "gidMappings",
            &format!("{base_path}/gidMappings"),
            collector,
        );
        let options = mount
            .get("options")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        let idmap = options.contains("idmap");
        let recursive_idmap = options.contains("ridmap");
        if idmap && recursive_idmap {
            collector.invalid(
                format!("{base_path}/options"),
                rules::MOUNT_IDMAP_MODE_UNIQUE,
                "mount options must not contain both idmap and ridmap",
            );
        }
        if (idmap || recursive_idmap)
            && !(uid_mappings && gid_mappings)
            && !container_mapping_available
        {
            collector.invalid(
                format!("{base_path}/options"),
                rules::MOUNT_IDMAP_MAPPING_REQUIRED,
                "idmapped mounts require paired mount mappings or complete container user mappings",
            );
        }
    }
}

fn validate_container_paths(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    if let Some(devices) = linux.get("devices").and_then(Value::as_array) {
        for (index, device) in devices.iter().filter_map(Value::as_object).enumerate() {
            if let Some(path) = device.get("path").and_then(Value::as_str) {
                validate_posix_path(
                    path,
                    &format!("/linux/devices/{index}/path"),
                    rules::DEVICE_PATH_ABSOLUTE,
                    "Linux device paths must be absolute",
                    collector,
                );
            }
        }
    }
    for field in ["maskedPaths", "readonlyPaths"] {
        let Some(paths) = linux.get(field).and_then(Value::as_array) else {
            continue;
        };
        for (index, path) in paths.iter().filter_map(Value::as_str).enumerate() {
            validate_posix_path(
                path,
                &format!("/linux/{field}/{index}"),
                rules::CONTAINER_PATH_ABSOLUTE,
                "Linux masked and read-only paths must be absolute",
                collector,
            );
        }
    }
}

fn validate_posix_path(
    value: &str,
    instance_path: &str,
    rule: OciSemanticRule,
    message: &'static str,
    collector: &mut ViolationCollector,
) {
    if !is_posix_absolute(value) {
        collector.invalid(instance_path, rule, message);
    }
    if contains_nul(value) {
        collector.invalid(
            instance_path,
            rules::PATH_NO_NUL,
            "Linux container paths must not contain a NUL byte",
        );
    }
}

fn validate_namespace_dependent_fields(
    configuration: &Map<String, Value>,
    linux: &Map<String, Value>,
    namespaces: &NamespaceFacts,
    collector: &mut ViolationCollector,
) {
    if configuration
        .get("hostname")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && !namespaces.contains("uts")
    {
        collector.invalid(
            "/hostname",
            rules::HOSTNAME_REQUIRES_UTS_NAMESPACE,
            "hostname requires an explicit Linux UTS namespace",
        );
    }
    if configuration
        .get("domainname")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && !namespaces.contains("uts")
    {
        collector.invalid(
            "/domainname",
            rules::DOMAINNAME_REQUIRES_UTS_NAMESPACE,
            "domainname requires an explicit Linux UTS namespace",
        );
    }
    let restricts_paths = ["maskedPaths", "readonlyPaths"].into_iter().any(|field| {
        linux
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|paths| !paths.is_empty())
    });
    if restricts_paths && !namespaces.contains("mount") {
        collector.invalid(
            "/linux/namespaces",
            rules::RESTRICTED_PATH_REQUIRES_MOUNT_NAMESPACE,
            "maskedPaths and readonlyPaths require an explicit Linux mount namespace",
        );
    }
}

fn validate_net_devices(
    linux: &Map<String, Value>,
    namespaces: &NamespaceFacts,
    collector: &mut ViolationCollector,
) {
    let Some(devices) = linux.get("netDevices").and_then(Value::as_object) else {
        return;
    };
    if !devices.is_empty() && !namespaces.contains("network") {
        collector.invalid(
            "/linux/netDevices",
            rules::NET_DEVICE_REQUIRES_NETWORK_NAMESPACE,
            "netDevices requires an explicit Linux network namespace",
        );
    }
    for (host_name, device) in devices {
        if !valid_network_device_name(host_name) {
            collector.invalid(
                format!("/linux/netDevices/{}", escape_pointer(host_name)),
                rules::NET_DEVICE_HOST_NAME_VALID,
                "host network device names must be 1-16 bytes and contain no slash, colon, or space",
            );
        }
        if contains_nul(host_name) {
            collector.invalid(
                format!("/linux/netDevices/{}", escape_pointer(host_name)),
                rules::NET_DEVICE_NAME_NO_NUL,
                "network device names must not contain a NUL byte",
            );
        }
        if let Some(name) = device
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(Value::as_str)
        {
            if !name.is_empty() && !valid_network_device_name(name) {
                collector.invalid(
                    format!("/linux/netDevices/{}/name", escape_pointer(host_name)),
                    rules::NET_DEVICE_CONTAINER_NAME_VALID,
                    "container network device names must be 1-16 bytes and contain no slash, colon, or space",
                );
            }
            if contains_nul(name) {
                collector.invalid(
                    format!("/linux/netDevices/{}/name", escape_pointer(host_name)),
                    rules::NET_DEVICE_NAME_NO_NUL,
                    "network device names must not contain a NUL byte",
                );
            }
        }
    }
}

fn valid_network_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 16
        && !matches!(name, "." | "..")
        && !name.contains(['/', ':', ' '])
}

fn validate_time_offsets(
    linux: &Map<String, Value>,
    namespaces: &NamespaceFacts,
    collector: &mut ViolationCollector,
) {
    let has_offsets = linux.contains_key("timeOffsets");
    if has_offsets && !namespaces.creates("time") {
        collector.invalid(
            "/linux/timeOffsets",
            rules::TIME_OFFSET_REQUIRES_NEW_TIME_NAMESPACE,
            "timeOffsets requires a newly created Linux time namespace",
        );
    }
}

fn validate_sysctls(
    linux: &Map<String, Value>,
    namespaces: &NamespaceFacts,
    collector: &mut ViolationCollector,
) {
    let Some(sysctls) = linux.get("sysctl").and_then(Value::as_object) else {
        return;
    };
    for (raw_key, value) in sysctls {
        let path = format!("/linux/sysctl/{}", escape_pointer(raw_key));
        if value.as_str().is_some_and(contains_nul) {
            collector.invalid(
                &path,
                rules::SYSCTL_NO_NUL,
                "sysctl keys and values must not contain a NUL byte",
            );
            continue;
        }
        let key = match OciLinuxSysctlKey::parse(raw_key) {
            Ok(key) => key,
            Err(error) => {
                let (rule, message) = match error.kind() {
                    OciLinuxSysctlKeyErrorKind::Nul => (
                        rules::SYSCTL_NO_NUL,
                        "sysctl keys and values must not contain a NUL byte".to_string(),
                    ),
                    OciLinuxSysctlKeyErrorKind::HostnameConflict => (
                        rules::SYSCTL_HOSTNAME_CONFLICT,
                        "kernel.hostname conflicts with the dedicated OCI hostname field"
                            .to_string(),
                    ),
                    OciLinuxSysctlKeyErrorKind::Empty
                    | OciLinuxSysctlKeyErrorKind::TooLong
                    | OciLinuxSysctlKeyErrorKind::UnsafePath
                    | OciLinuxSysctlKeyErrorKind::NotNamespaced => (
                        rules::SYSCTL_NOT_NAMESPACED,
                        format!("sysctl {raw_key} is not a safe namespaced kernel control"),
                    ),
                };
                collector.invalid(path, rule, message);
                continue;
            }
        };
        let (namespace, rule) = match key.namespace() {
            OciLinuxSysctlNamespace::Ipc => ("ipc", rules::SYSCTL_REQUIRES_IPC_NAMESPACE),
            OciLinuxSysctlNamespace::Network => {
                ("network", rules::SYSCTL_REQUIRES_NETWORK_NAMESPACE)
            }
            OciLinuxSysctlNamespace::Uts => ("uts", rules::SYSCTL_REQUIRES_UTS_NAMESPACE),
            OciLinuxSysctlNamespace::User => ("user", rules::SYSCTL_REQUIRES_USER_NAMESPACE),
        };
        if !namespaces.contains(namespace) {
            collector.invalid(
                path,
                rule,
                format!(
                    "sysctl {} requires an explicit {namespace} namespace",
                    key.canonical()
                ),
            );
        }
    }
}

fn validate_seccomp(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(seccomp) = linux.get("seccomp").and_then(Value::as_object) else {
        return;
    };
    if seccomp.contains_key("listenerMetadata") && !seccomp.contains_key("listenerPath") {
        collector.invalid(
            "/linux/seccomp/listenerMetadata",
            rules::SECCOMP_LISTENER_METADATA_REQUIRES_PATH,
            "seccomp listenerMetadata must not be set without listenerPath",
        );
    }
    if seccomp.contains_key("defaultErrnoRet")
        && seccomp
            .get("defaultAction")
            .and_then(Value::as_str)
            .is_some_and(|action| !action_supports_errno(action))
    {
        collector.invalid(
            "/linux/seccomp/defaultErrnoRet",
            rules::SECCOMP_ERRNO_ACTION,
            "defaultErrnoRet is valid only for SCMP_ACT_ERRNO or SCMP_ACT_TRACE",
        );
    }
    let Some(syscalls) = seccomp.get("syscalls").and_then(Value::as_array) else {
        return;
    };
    for (index, syscall) in syscalls.iter().filter_map(Value::as_object).enumerate() {
        if syscall.contains_key("errnoRet")
            && syscall
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| !action_supports_errno(action))
        {
            collector.invalid(
                format!("/linux/seccomp/syscalls/{index}/errnoRet"),
                rules::SECCOMP_ERRNO_ACTION,
                "errnoRet is valid only for SCMP_ACT_ERRNO or SCMP_ACT_TRACE",
            );
        }
    }
}

fn action_supports_errno(action: &str) -> bool {
    matches!(action, "SCMP_ACT_ERRNO" | "SCMP_ACT_TRACE")
}

fn validate_resources(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(resources) = linux.get("resources").and_then(Value::as_object) else {
        return;
    };
    validate_cpu(resources, collector);
    validate_block_io(resources, collector);
    validate_rdma(resources, collector);
}

fn validate_cpu(resources: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(cpu) = resources.get("cpu").and_then(Value::as_object) else {
        return;
    };
    if let (Some(quota), Some(burst)) = (
        cpu.get("quota").and_then(Value::as_i64),
        cpu.get("burst").and_then(Value::as_u64),
    ) {
        if quota > 0 && burst > quota as u64 {
            collector.invalid(
                "/linux/resources/cpu/burst",
                rules::CPU_BURST_AT_MOST_QUOTA,
                format!("CPU burst {burst} exceeds positive quota {quota}"),
            );
        }
    }
    if let (Some(runtime), Some(period)) = (
        cpu.get("realtimeRuntime").and_then(Value::as_i64),
        cpu.get("realtimePeriod").and_then(Value::as_u64),
    ) {
        if runtime > 0 && runtime as u64 > period {
            collector.invalid(
                "/linux/resources/cpu/realtimeRuntime",
                rules::CPU_REALTIME_RUNTIME_AT_MOST_PERIOD,
                format!("realtime runtime {runtime} exceeds period {period}"),
            );
        }
    }
}

fn validate_block_io(resources: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(devices) = resources
        .get("blockIO")
        .and_then(Value::as_object)
        .and_then(|block_io| block_io.get("weightDevice"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for (index, device) in devices.iter().filter_map(Value::as_object).enumerate() {
        if !device.contains_key("weight") && !device.contains_key("leafWeight") {
            collector.invalid(
                format!("/linux/resources/blockIO/weightDevice/{index}"),
                rules::BLOCK_IO_WEIGHT_DEVICE_WEIGHT_REQUIRED,
                "weightDevice entries require weight, leafWeight, or both",
            );
        }
    }
}

fn validate_rdma(resources: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(rdma) = resources.get("rdma").and_then(Value::as_object) else {
        return;
    };
    for (device, limits) in rdma {
        if limits.as_object().is_some_and(|limit| {
            !limit.contains_key("hcaHandles") && !limit.contains_key("hcaObjects")
        }) {
            collector.invalid(
                format!("/linux/resources/rdma/{}", escape_pointer(device)),
                rules::RDMA_LIMIT_REQUIRED,
                "RDMA entries require hcaHandles, hcaObjects, or both",
            );
        }
    }
}

fn validate_intel_rdt(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(rdt) = linux.get("intelRdt").and_then(Value::as_object) else {
        return;
    };
    if let Some(clos_id) = rdt.get("closID").and_then(Value::as_str) {
        if clos_id.is_empty()
            || clos_id.len() > crate::OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES
            || matches!(clos_id, "." | "..")
            || (clos_id != "/" && clos_id.contains('/'))
            || contains_nul(clos_id)
        {
            collector.invalid(
                "/linux/intelRdt/closID",
                rules::INTEL_RDT_CLOS_ID_SAFE_NAME,
                format!(
                    "Intel RDT closID must be / or a nonempty safe resctrl directory name of at most {} bytes",
                    crate::OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES
                ),
            );
        }
    }
    let mut total_lines = 0_usize;
    let mut total_bytes = 0_usize;
    if let Some(lines) = rdt.get("schemata").and_then(Value::as_array) {
        total_lines = total_lines.saturating_add(lines.len());
        for (index, line) in lines.iter().enumerate() {
            let Some(line) = line.as_str() else {
                continue;
            };
            let pointer = format!("/linux/intelRdt/schemata/{index}");
            if line.is_empty() || contains_nul(line) || line.contains('\r') || line.contains('\n') {
                collector.invalid(
                    pointer.clone(),
                    rules::INTEL_RDT_SCHEMATA_SINGLE_LINE,
                    "Intel RDT schemata entries must be nonempty single lines without NUL bytes",
                );
            }
            validate_intel_rdt_line_bound(&pointer, line, collector);
            total_bytes = total_bytes.saturating_add(line.len().saturating_add(1));
        }
    }
    if let Some(schema) = rdt.get("l3CacheSchema").and_then(Value::as_str) {
        total_lines = total_lines.saturating_add(1);
        if !schema.starts_with("L3:")
            || contains_nul(schema)
            || schema.contains('\r')
            || schema.contains('\n')
        {
            collector.invalid(
                "/linux/intelRdt/l3CacheSchema",
                rules::INTEL_RDT_L3_SCHEMA,
                "l3CacheSchema must start with L3: and contain no newlines",
            );
        }
        validate_intel_rdt_line_bound("/linux/intelRdt/l3CacheSchema", schema, collector);
        total_bytes = total_bytes.saturating_add(schema.len().saturating_add(1));
    }
    if let Some(schema) = rdt.get("memBwSchema").and_then(Value::as_str) {
        total_lines = total_lines.saturating_add(1);
        if !schema.starts_with("MB:")
            || contains_nul(schema)
            || schema.contains('\r')
            || schema.contains('\n')
        {
            collector.invalid(
                "/linux/intelRdt/memBwSchema",
                rules::INTEL_RDT_MEMORY_BANDWIDTH_SCHEMA,
                "memBwSchema must start with MB: and contain no newlines",
            );
        }
        validate_intel_rdt_line_bound("/linux/intelRdt/memBwSchema", schema, collector);
        total_bytes = total_bytes.saturating_add(schema.len().saturating_add(1));
    }
    if total_lines > crate::OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES {
        collector.invalid(
            "/linux/intelRdt",
            rules::INTEL_RDT_SCHEMATA_COUNT_BOUNDED,
            format!(
                "Intel RDT contains {total_lines} schemata lines across all ordered writes; maximum is {}",
                crate::OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES
            ),
        );
    }
    if total_bytes > crate::OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_BYTES {
        collector.invalid(
            "/linux/intelRdt",
            rules::INTEL_RDT_SCHEMATA_TOTAL_BOUNDED,
            format!(
                "Intel RDT schemata consumes {total_bytes} bytes; maximum is {}",
                crate::OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_BYTES
            ),
        );
    }
}

fn validate_intel_rdt_line_bound(pointer: &str, line: &str, collector: &mut ViolationCollector) {
    if line.len() > crate::OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINE_BYTES {
        collector.invalid(
            pointer,
            rules::INTEL_RDT_SCHEMATA_LINE_BOUNDED,
            format!(
                "Intel RDT schemata line is {} bytes; maximum is {}",
                line.len(),
                crate::OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINE_BYTES
            ),
        );
    }
}

fn validate_memory_policy(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(policy) = linux.get("memoryPolicy").and_then(Value::as_object) else {
        return;
    };
    if !policy.contains_key("mode") {
        collector.invalid(
            "/linux/memoryPolicy/mode",
            rules::MEMORY_POLICY_MODE_REQUIRED,
            "linux.memoryPolicy.mode is required when memoryPolicy is configured",
        );
    }
    let Some(mode) = policy.get("mode").and_then(Value::as_str) else {
        return;
    };
    let raw_nodes = policy.get("nodes").and_then(Value::as_str);
    if raw_nodes.is_some_and(|nodes| !valid_memory_node_list(nodes)) {
        collector.invalid(
            "/linux/memoryPolicy/nodes",
            rules::MEMORY_POLICY_NODES_FORMAT,
            format!(
                "linux.memoryPolicy.nodes must contain comma-separated indices and ranges below {}",
                crate::OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS
            ),
        );
    }
    let nodes = raw_nodes.map(str::trim).filter(|nodes| !nodes.is_empty());
    if matches!(mode, "MPOL_DEFAULT" | "MPOL_LOCAL") && nodes.is_some() {
        collector.invalid(
            "/linux/memoryPolicy/nodes",
            rules::MEMORY_POLICY_NODES_FORBIDDEN,
            format!("{mode} must not specify memory nodes"),
        );
    }
    if matches!(
        mode,
        "MPOL_BIND" | "MPOL_INTERLEAVE" | "MPOL_WEIGHTED_INTERLEAVE" | "MPOL_PREFERRED_MANY"
    ) && nodes.is_none()
    {
        collector.invalid(
            "/linux/memoryPolicy/nodes",
            rules::MEMORY_POLICY_NODES_REQUIRED,
            format!("{mode} requires at least one memory node"),
        );
    }
    let flags = policy
        .get("flags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    let relative = flags.contains(&"MPOL_F_RELATIVE_NODES");
    let static_nodes = flags.contains(&"MPOL_F_STATIC_NODES");
    let numa_balancing = flags.contains(&"MPOL_F_NUMA_BALANCING");
    if relative && static_nodes {
        collector.invalid(
            "/linux/memoryPolicy/flags",
            rules::MEMORY_POLICY_FLAGS_COMPATIBLE,
            "MPOL_F_RELATIVE_NODES and MPOL_F_STATIC_NODES are mutually exclusive",
        );
    }
    if numa_balancing && mode != "MPOL_BIND" {
        collector.invalid(
            "/linux/memoryPolicy/flags",
            rules::MEMORY_POLICY_FLAGS_COMPATIBLE,
            "MPOL_F_NUMA_BALANCING is valid only with MPOL_BIND",
        );
    }
    if nodes.is_none() && (relative || static_nodes) {
        collector.invalid(
            "/linux/memoryPolicy/flags",
            rules::MEMORY_POLICY_FLAGS_COMPATIBLE,
            "relative or static NUMA-node flags require a nonempty nodes mask",
        );
    }
}

fn valid_memory_node_list(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 4_096
        && value.split(',').all(|range| {
            let mut bounds = range.split('-');
            let start = bounds.next().and_then(|bound| bound.parse::<usize>().ok());
            let end = bounds
                .next()
                .map(|bound| bound.parse::<usize>().ok())
                .unwrap_or(start);
            bounds.next().is_none()
                && start.is_some_and(|start| {
                    end.is_some_and(|end| {
                        start <= end && end < crate::OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS
                    })
                })
        })
}

fn validate_personality(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(personality) = linux.get("personality").and_then(Value::as_object) else {
        return;
    };
    if !personality.contains_key("domain") {
        collector.invalid(
            "/linux/personality/domain",
            rules::PERSONALITY_DOMAIN_REQUIRED,
            "linux.personality.domain is required when personality is configured",
        );
    }
    if personality
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|flags| !flags.is_empty())
    {
        collector.unsupported(
            "/linux/personality/flags",
            rules::PERSONALITY_FLAGS_EMPTY,
            "linux.personality.flags must be empty because OCI 1.3 defines no supported flag values",
        );
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
