use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::{contains_nul, is_posix_absolute, ViolationCollector};

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
            "oci.linux.id-mapping.requires-new-user-namespace",
            "Linux UID/GID mappings require a newly created user namespace",
        );
    }
    if namespaces.creates("user") && !(uid_mappings || gid_mappings) {
        collector.invalid(
            "/linux/namespaces",
            "oci.linux.user-namespace.mapping-required",
            "a newly created Linux user namespace requires UID or GID mappings",
        );
    }

    validate_mount_id_mappings(
        configuration,
        namespaces.creates("user") && uid_mappings && gid_mappings,
        collector,
    );
    validate_container_paths(linux, collector);
    validate_namespace_dependent_fields(configuration, linux, &namespaces, collector);
    validate_net_devices(linux, &namespaces, collector);
    validate_time_offsets(linux, &namespaces, collector);
    validate_sysctls(linux, &namespaces, collector);
    validate_seccomp(linux, collector);
    validate_resources(linux, collector);
    validate_intel_rdt(linux, collector);
    validate_memory_policy(linux, collector);
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
                "oci.linux.namespace.type.unique",
                format!("duplicate Linux namespace type {kind}"),
            );
        }
        if let Some(path) = namespace.get("path").and_then(Value::as_str) {
            if !is_posix_absolute(path) {
                collector.invalid(
                    format!("/linux/namespaces/{index}/path"),
                    "oci.linux.namespace.path.absolute",
                    "Linux namespace paths must be absolute",
                );
            }
            if contains_nul(path) {
                collector.invalid(
                    format!("/linux/namespaces/{index}/path"),
                    "oci.common.path.no-nul",
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
                "oci.linux.id-mapping.size.nonzero",
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
                "oci.linux.id-mapping.container-range",
                "ID mapping exceeds the uint32 container ID space",
            );
            continue;
        }
        if host_end > address_space_end {
            collector.invalid(
                format!("{base_path}/{index}/hostID"),
                "oci.linux.id-mapping.host-range",
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
                    "oci.linux.id-mapping.container-range.unique",
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
                    "oci.linux.id-mapping.host-range.unique",
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
                "oci.linux.mount.idmap.mode.unique",
                "mount options must not contain both idmap and ridmap",
            );
        }
        if (idmap || recursive_idmap)
            && !(uid_mappings && gid_mappings)
            && !container_mapping_available
        {
            collector.invalid(
                format!("{base_path}/options"),
                "oci.linux.mount.idmap.mapping-required",
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
                    "oci.linux.device.path.absolute",
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
                "oci.linux.container-path.absolute",
                "Linux masked and read-only paths must be absolute",
                collector,
            );
        }
    }
}

fn validate_posix_path(
    value: &str,
    instance_path: &str,
    rule: &'static str,
    message: &'static str,
    collector: &mut ViolationCollector,
) {
    if !is_posix_absolute(value) {
        collector.invalid(instance_path, rule, message);
    }
    if contains_nul(value) {
        collector.invalid(
            instance_path,
            "oci.common.path.no-nul",
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
            "oci.linux.hostname.requires-uts-namespace",
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
            "oci.linux.domainname.requires-uts-namespace",
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
            "oci.linux.restricted-path.requires-mount-namespace",
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
            "oci.linux.net-device.requires-network-namespace",
            "netDevices requires an explicit Linux network namespace",
        );
    }
    for (host_name, device) in devices {
        if !valid_network_device_name(host_name) {
            collector.invalid(
                format!("/linux/netDevices/{}", escape_pointer(host_name)),
                "oci.linux.net-device.host-name.valid",
                "host network device names must be 1-16 bytes and contain no slash, colon, or space",
            );
        }
        if contains_nul(host_name) {
            collector.invalid(
                format!("/linux/netDevices/{}", escape_pointer(host_name)),
                "oci.linux.net-device.name.no-nul",
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
                    "oci.linux.net-device.container-name.valid",
                    "container network device names must be 1-16 bytes and contain no slash, colon, or space",
                );
            }
            if contains_nul(name) {
                collector.invalid(
                    format!("/linux/netDevices/{}/name", escape_pointer(host_name)),
                    "oci.linux.net-device.name.no-nul",
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
            "oci.linux.time-offset.requires-new-time-namespace",
            "timeOffsets requires a newly created Linux time namespace",
        );
    }
}

fn validate_sysctls(
    linux: &Map<String, Value>,
    namespaces: &NamespaceFacts,
    collector: &mut ViolationCollector,
) {
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

    let Some(sysctls) = linux.get("sysctl").and_then(Value::as_object) else {
        return;
    };
    for (raw_key, value) in sysctls {
        let key = normalize_sysctl_key(raw_key);
        let path = format!("/linux/sysctl/{}", escape_pointer(raw_key));
        if contains_nul(raw_key) || value.as_str().is_some_and(contains_nul) {
            collector.invalid(
                &path,
                "oci.linux.sysctl.no-nul",
                "sysctl keys and values must not contain a NUL byte",
            );
            continue;
        }
        if IPC_SYSCTLS.contains(&key.as_str()) || key.starts_with("fs.mqueue.") {
            if !namespaces.contains("ipc") {
                collector.invalid(
                    path,
                    "oci.linux.sysctl.requires-ipc-namespace",
                    format!("sysctl {key} requires an explicit IPC namespace"),
                );
            }
            continue;
        }
        if key.starts_with("net.") {
            if !namespaces.contains("network") {
                collector.invalid(
                    path,
                    "oci.linux.sysctl.requires-network-namespace",
                    format!("sysctl {key} requires an explicit network namespace"),
                );
            }
            continue;
        }
        if key == "kernel.domainname" {
            if !namespaces.contains("uts") {
                collector.invalid(
                    path,
                    "oci.linux.sysctl.requires-uts-namespace",
                    "kernel.domainname requires an explicit UTS namespace",
                );
            }
            continue;
        }
        if key == "kernel.hostname" {
            collector.invalid(
                path,
                "oci.linux.sysctl.hostname-conflict",
                "kernel.hostname conflicts with the dedicated OCI hostname field",
            );
            continue;
        }
        if key.starts_with("user.") {
            if !namespaces.contains("user") {
                collector.invalid(
                    path,
                    "oci.linux.sysctl.requires-user-namespace",
                    format!("sysctl {key} requires an explicit user namespace"),
                );
            }
            continue;
        }
        collector.invalid(
            path,
            "oci.linux.sysctl.not-namespaced",
            format!("sysctl {key} is not known to be isolated by a configured namespace"),
        );
    }
}

fn normalize_sysctl_key(value: &str) -> String {
    let Some(first_separator) = value.find(['.', '/']) else {
        return value.to_string();
    };
    if value.as_bytes()[first_separator] == b'.' {
        return value.to_string();
    }
    value
        .chars()
        .map(|character| match character {
            '.' => '/',
            '/' => '.',
            other => other,
        })
        .collect()
}

fn validate_seccomp(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(seccomp) = linux.get("seccomp").and_then(Value::as_object) else {
        return;
    };
    if seccomp.contains_key("listenerMetadata") && !seccomp.contains_key("listenerPath") {
        collector.invalid(
            "/linux/seccomp/listenerMetadata",
            "oci.linux.seccomp.listener-metadata.requires-path",
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
            "oci.linux.seccomp.errno-action",
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
                "oci.linux.seccomp.errno-action",
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
                "oci.linux.cpu.burst-at-most-quota",
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
                "oci.linux.cpu.realtime-runtime-at-most-period",
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
                "oci.linux.block-io.weight-device.weight-required",
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
                "oci.linux.rdma.limit-required",
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
        if matches!(clos_id, "." | "..")
            || (clos_id != "/" && clos_id.contains('/'))
            || contains_nul(clos_id)
        {
            collector.invalid(
                "/linux/intelRdt/closID",
                "oci.linux.intel-rdt.clos-id.safe-name",
                "Intel RDT closID must be a safe resctrl directory name or /",
            );
        }
    }
    if let Some(lines) = rdt.get("schemata").and_then(Value::as_array) {
        for (index, line) in lines.iter().filter_map(Value::as_str).enumerate() {
            if line.contains('\r') || line.contains('\n') {
                collector.invalid(
                    format!("/linux/intelRdt/schemata/{index}"),
                    "oci.linux.intel-rdt.schemata.single-line",
                    "Intel RDT schemata entries must not contain newlines",
                );
            }
        }
    }
    if let Some(schema) = rdt.get("l3CacheSchema").and_then(Value::as_str) {
        if !schema.starts_with("L3:") || schema.contains('\r') || schema.contains('\n') {
            collector.invalid(
                "/linux/intelRdt/l3CacheSchema",
                "oci.linux.intel-rdt.l3-schema",
                "l3CacheSchema must start with L3: and contain no newlines",
            );
        }
    }
    if let Some(schema) = rdt.get("memBwSchema").and_then(Value::as_str) {
        if !schema.starts_with("MB:") || schema.contains('\r') || schema.contains('\n') {
            collector.invalid(
                "/linux/intelRdt/memBwSchema",
                "oci.linux.intel-rdt.memory-bandwidth-schema",
                "memBwSchema must start with MB: and contain no newlines",
            );
        }
    }
}

fn validate_memory_policy(linux: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(policy) = linux.get("memoryPolicy").and_then(Value::as_object) else {
        return;
    };
    let Some(mode) = policy.get("mode").and_then(Value::as_str) else {
        return;
    };
    let nodes = policy
        .get("nodes")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|nodes| !nodes.is_empty());
    if matches!(mode, "MPOL_DEFAULT" | "MPOL_LOCAL") && nodes.is_some() {
        collector.invalid(
            "/linux/memoryPolicy/nodes",
            "oci.linux.memory-policy.nodes-forbidden",
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
            "oci.linux.memory-policy.nodes-required",
            format!("{mode} requires at least one memory node"),
        );
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
