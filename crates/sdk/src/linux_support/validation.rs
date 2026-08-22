use oci_spec::runtime::{
    Linux, LinuxCapabilities, LinuxMemoryPolicy, LinuxSeccomp, LinuxSeccompAction, Mount, Process,
    Spec,
};

use crate::{
    oci_linux_capability_number, Error, ErrorCode, Result, OCI_LINUX_CAPABILITY_NAMES,
    OCI_LINUX_MOUNT_OPTIONS,
};

use super::{profile_error, OciLinuxSupport, A3S_CUSTOM_LINUX_MOUNT_OPTIONS};

impl OciLinuxSupport {
    /// Reject configuration outside this profile before durable mutation.
    pub fn validate_spec(&self, spec: &Spec, operation: &'static str) -> Result<()> {
        if let Some(process) = spec.process().as_ref() {
            self.validate_process(process, operation)?;
        }
        for (index, mount) in spec
            .mounts()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            self.validate_mount(mount, index, operation)?;
        }
        if let Some(linux) = spec.linux().as_ref() {
            self.validate_linux(linux, operation)?;
        }
        Ok(())
    }

    /// Reject one init or exec process outside this profile.
    pub fn validate_process(&self, process: &Process, operation: &'static str) -> Result<()> {
        if process.apparmor_profile().is_some() && !self.apparmor_enabled() {
            return Err(unsupported(
                "process.apparmorProfile",
                "AppArmor process profiles are not advertised",
                operation,
            ));
        }
        if process.selinux_label().is_some() && !self.selinux_enabled() {
            return Err(unsupported(
                "process.selinuxLabel",
                "SELinux process labels are not advertised",
                operation,
            ));
        }
        if let Some(capabilities) = process.capabilities().as_ref() {
            self.validate_capabilities(capabilities, operation)?;
        }
        Ok(())
    }

    fn validate_mount(&self, mount: &Mount, index: usize, operation: &'static str) -> Result<()> {
        for option in mount.options().as_deref().unwrap_or_default() {
            let standardized = OCI_LINUX_MOUNT_OPTIONS
                .iter()
                .any(|known| known.name() == option)
                || A3S_CUSTOM_LINUX_MOUNT_OPTIONS.contains(&option.as_str());
            if standardized && !self.mount_options.iter().any(|known| known == option) {
                let reason = if option == "tmpcopyup" {
                    "Linux mount option \"tmpcopyup\" is not advertised because tmpfs copy-up is not implemented"
                        .to_string()
                } else {
                    format!("Linux mount option {option:?} is not advertised")
                };
                return Err(unsupported(
                    &format!("mounts[{index}].options"),
                    &reason,
                    operation,
                ));
            }
        }
        if (mount.uid_mappings().is_some() || mount.gid_mappings().is_some())
            && !self.idmap_enabled()
        {
            return Err(unsupported(
                &format!("mounts[{index}].uidMappings/gidMappings"),
                "ID-mapped mounts are not advertised",
                operation,
            ));
        }
        Ok(())
    }

    fn validate_linux(&self, linux: &Linux, operation: &'static str) -> Result<()> {
        let supported_namespaces = self.linux.namespaces().as_deref().unwrap_or_default();
        for (index, namespace) in linux
            .namespaces()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            if !supported_namespaces.contains(&namespace.typ()) {
                return Err(unsupported(
                    &format!("linux.namespaces[{index}].type"),
                    &format!("namespace {:?} is not advertised", namespace.typ()),
                    operation,
                ));
            }
        }

        let cgroup = self.linux.cgroup().as_ref();
        let has_cgroup_manager =
            cgroup.is_some_and(|cgroup| *cgroup.v1() == Some(true) || *cgroup.v2() == Some(true));
        if linux.cgroups_path().is_some() && !has_cgroup_manager {
            return Err(unsupported(
                "linux.cgroupsPath",
                "no cgroup manager is advertised",
                operation,
            ));
        }
        if let Some(resources) = linux.resources().as_ref() {
            self.validate_resources(resources, operation)?;
        }
        if let Some(seccomp) = linux.seccomp().as_ref() {
            self.validate_seccomp(seccomp, operation)?;
        }
        if linux.mount_label().is_some() && !self.selinux_enabled() {
            return Err(unsupported(
                "linux.mountLabel",
                "SELinux mount labeling is not advertised",
                operation,
            ));
        }
        if let Some(intel_rdt) = linux.intel_rdt().as_ref() {
            self.validate_intel_rdt(intel_rdt, operation)?;
        }
        if let Some(memory_policy) = linux.memory_policy().as_ref() {
            self.validate_memory_policy(memory_policy, operation)?;
        }
        if linux.net_devices().is_some() && !self.net_devices_enabled() {
            return Err(unsupported(
                "linux.netDevices",
                "network-device moves are not advertised",
                operation,
            ));
        }
        Ok(())
    }

    fn validate_capabilities(
        &self,
        capabilities: &LinuxCapabilities,
        operation: &'static str,
    ) -> Result<()> {
        let supported = self.linux.capabilities().as_deref().unwrap_or_default();
        for (set, values) in [
            ("bounding", capabilities.bounding().as_ref()),
            ("effective", capabilities.effective().as_ref()),
            ("inheritable", capabilities.inheritable().as_ref()),
            ("permitted", capabilities.permitted().as_ref()),
            ("ambient", capabilities.ambient().as_ref()),
        ] {
            let mut names = values
                .into_iter()
                .flatten()
                .map(|capability| {
                    OCI_LINUX_CAPABILITY_NAMES[oci_linux_capability_number(*capability) as usize]
                })
                .collect::<Vec<_>>();
            names.sort_unstable();
            if let Some(name) = names.into_iter().find(|name| {
                !supported
                    .iter()
                    .any(|supported_name| supported_name == name)
            }) {
                return Err(unsupported(
                    &format!("process.capabilities.{set}"),
                    &format!("Linux capability {name} is not advertised"),
                    operation,
                ));
            }
        }
        Ok(())
    }

    fn validate_seccomp(&self, seccomp: &LinuxSeccomp, operation: &'static str) -> Result<()> {
        let Some(feature) = self.linux.seccomp().as_ref() else {
            return Err(unsupported(
                "linux.seccomp",
                "seccomp is not advertised",
                operation,
            ));
        };
        if *feature.enabled() != Some(true) {
            return Err(unsupported(
                "linux.seccomp",
                "seccomp is not advertised",
                operation,
            ));
        }
        let actions = feature.actions().as_deref().unwrap_or_default();
        self.require_seccomp_action(
            seccomp.default_action(),
            actions,
            "defaultAction",
            operation,
        )?;
        for (index, syscall) in seccomp
            .syscalls()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            self.require_seccomp_action(
                syscall.action(),
                actions,
                &format!("syscalls[{index}].action"),
                operation,
            )?;
            for (argument_index, argument) in syscall
                .args()
                .as_deref()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                let operator = argument.op().to_string();
                if !feature
                    .operators()
                    .as_deref()
                    .unwrap_or_default()
                    .contains(&operator)
                {
                    return Err(unsupported(
                        &format!("linux.seccomp.syscalls[{index}].args[{argument_index}].op"),
                        &format!("seccomp operator {operator} is not advertised"),
                        operation,
                    ));
                }
            }
        }
        for (index, architecture) in seccomp
            .architectures()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            if !feature
                .archs()
                .as_deref()
                .unwrap_or_default()
                .contains(architecture)
            {
                return Err(unsupported(
                    &format!("linux.seccomp.architectures[{index}]"),
                    &format!("seccomp architecture {architecture:?} is not advertised"),
                    operation,
                ));
            }
        }
        let known_flags = feature.known_flags().as_deref().unwrap_or_default();
        let supported_flags = feature.supported_flags().as_deref().unwrap_or_default();
        for (index, flag) in seccomp
            .flags()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let name = flag.to_string();
            let reason = if known_flags.contains(&name) {
                "is recognized but not supported"
            } else {
                "is not recognized"
            };
            if !supported_flags.contains(&name) {
                return Err(unsupported(
                    &format!("linux.seccomp.flags[{index}]"),
                    &format!("seccomp flag {name} {reason}"),
                    operation,
                ));
            }
        }
        if (seccomp.listener_path().is_some() || seccomp.listener_metadata().is_some())
            && !actions.contains(&LinuxSeccompAction::ScmpActNotify)
        {
            return Err(unsupported(
                "linux.seccomp.listenerPath/listenerMetadata",
                "seccomp notification listeners are not advertised",
                operation,
            ));
        }
        Ok(())
    }

    fn require_seccomp_action(
        &self,
        action: LinuxSeccompAction,
        supported: &[LinuxSeccompAction],
        field: &str,
        operation: &'static str,
    ) -> Result<()> {
        if supported.contains(&action) {
            Ok(())
        } else {
            Err(unsupported(
                &format!("linux.seccomp.{field}"),
                &format!("seccomp action {action:?} is not advertised"),
                operation,
            ))
        }
    }

    fn validate_memory_policy(
        &self,
        policy: &LinuxMemoryPolicy,
        operation: &'static str,
    ) -> Result<()> {
        let feature = self.linux.memory_policy().as_ref().ok_or_else(|| {
            unsupported(
                "linux.memoryPolicy",
                "NUMA memory policy is not advertised",
                operation,
            )
        })?;
        let mode = policy.mode().to_string();
        if !feature
            .modes()
            .as_deref()
            .unwrap_or_default()
            .contains(&mode)
        {
            return Err(unsupported(
                "linux.memoryPolicy.mode",
                &format!("memory-policy mode {mode} is not advertised"),
                operation,
            ));
        }
        for (index, flag) in policy
            .flags()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let flag = flag.to_string();
            if !feature
                .flags()
                .as_deref()
                .unwrap_or_default()
                .contains(&flag)
            {
                return Err(unsupported(
                    &format!("linux.memoryPolicy.flags[{index}]"),
                    &format!("memory-policy flag {flag} is not advertised"),
                    operation,
                ));
            }
        }
        Ok(())
    }

    fn validate_intel_rdt(
        &self,
        intel_rdt: &oci_spec::runtime::LinuxIntelRdt,
        operation: &'static str,
    ) -> Result<()> {
        let feature = self.linux.intel_rdt().as_ref().ok_or_else(|| {
            unsupported("linux.intelRdt", "Intel RDT is not advertised", operation)
        })?;
        if *feature.enabled() != Some(true) {
            return Err(unsupported(
                "linux.intelRdt",
                "Intel RDT is not advertised as enabled",
                operation,
            ));
        }
        if (intel_rdt.schemata().is_some()
            || intel_rdt.l3_cache_schema().is_some()
            || intel_rdt.mem_bw_schema().is_some())
            && *feature.schemata() != Some(true)
        {
            return Err(unsupported(
                "linux.intelRdt.schemata",
                "Intel RDT schemata are not advertised",
                operation,
            ));
        }
        if intel_rdt
            .enable_monitoring()
            .as_ref()
            .is_some_and(|enabled| *enabled)
            && *feature.monitoring() != Some(true)
        {
            return Err(unsupported(
                "linux.intelRdt.enableMonitoring",
                "Intel RDT monitoring is not advertised",
                operation,
            ));
        }
        let value = serde_json::to_value(intel_rdt).map_err(|error| {
            profile_error(
                ErrorCode::Internal,
                format!("failed to inspect OCI Intel RDT configuration: {error}"),
                operation,
            )
        })?;
        if let Some(field) = ["enableCMT", "enableMBM"]
            .into_iter()
            .find(|field| value.get(*field).is_some())
        {
            return Err(unsupported(
                &format!("linux.intelRdt.{field}"),
                "deprecated Intel RDT monitoring controls are not advertised",
                operation,
            ));
        }
        Ok(())
    }

    fn apparmor_enabled(&self) -> bool {
        self.linux
            .apparmor()
            .as_ref()
            .is_some_and(|feature| *feature.enabled() == Some(true))
    }

    fn selinux_enabled(&self) -> bool {
        self.linux
            .selinux()
            .as_ref()
            .is_some_and(|feature| *feature.enabled() == Some(true))
    }

    fn idmap_enabled(&self) -> bool {
        self.linux
            .mount_extensions()
            .as_ref()
            .and_then(|extensions| extensions.idmap().as_ref())
            .is_some_and(|feature| *feature.enabled() == Some(true))
    }

    fn net_devices_enabled(&self) -> bool {
        self.linux
            .net_devices()
            .as_ref()
            .is_some_and(|feature| *feature.enabled() == Some(true))
    }
}

fn unsupported(field: &str, reason: &str, operation: &'static str) -> Error {
    profile_error(
        ErrorCode::Unsupported,
        format!("{field}: {reason}"),
        operation,
    )
}
