use std::io;
use std::ptr;

use a3s_oci_sdk::oci_spec::runtime::{
    LinuxMemoryPolicy, MemoryPolicyFlagType, MemoryPolicyModeType,
};
use a3s_oci_sdk::{Error, ErrorCode, Result, OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS};

const MPOL_PREFERRED_MANY: libc::c_int = 5;
const MPOL_WEIGHTED_INTERLEAVE: libc::c_int = 6;
const MPOL_F_MEMS_ALLOWED: libc::c_ulong = 1 << 2;
const BITS_PER_WORD: usize = libc::c_ulong::BITS as usize;
const NODE_MASK_WORDS: usize = OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS.div_ceil(BITS_PER_WORD);

/// Validated NUMA policy retained for the configured init process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MemoryPolicyPlan {
    mode: MemoryPolicyMode,
    flags: libc::c_int,
    nodes: NodeMask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryPolicyMode {
    Default,
    Bind,
    Interleave,
    WeightedInterleave,
    Preferred,
    PreferredMany,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeMask {
    words: [libc::c_ulong; NODE_MASK_WORDS],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyObservation {
    mode: libc::c_int,
    nodes: NodeMask,
}

impl MemoryPolicyPlan {
    pub(super) fn from_oci(value: Option<&LinuxMemoryPolicy>) -> Result<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let mode = MemoryPolicyMode::from_oci(value.mode());
        let nodes = value
            .nodes()
            .as_deref()
            .map(NodeMask::parse)
            .transpose()?
            .unwrap_or_default();
        if mode.forbids_nodes() && !nodes.is_empty() {
            return Err(plan_error(format!(
                "linux.memoryPolicy mode {} must not specify memory nodes",
                mode.oci_name()
            )));
        }
        if mode.requires_nodes() && nodes.is_empty() {
            return Err(plan_error(format!(
                "linux.memoryPolicy mode {} requires at least one memory node",
                mode.oci_name()
            )));
        }

        let mut flags = 0;
        let mut relative_nodes = false;
        let mut static_nodes = false;
        let mut numa_balancing = false;
        for flag in value.flags().as_deref().unwrap_or_default() {
            match flag {
                MemoryPolicyFlagType::MpolFNumaBalancing => {
                    flags |= libc::MPOL_F_NUMA_BALANCING;
                    numa_balancing = true;
                }
                MemoryPolicyFlagType::MpolFRelativeNodes => {
                    flags |= libc::MPOL_F_RELATIVE_NODES;
                    relative_nodes = true;
                }
                MemoryPolicyFlagType::MpolFStaticNodes => {
                    flags |= libc::MPOL_F_STATIC_NODES;
                    static_nodes = true;
                }
            }
        }
        if relative_nodes && static_nodes {
            return Err(plan_error(
                "linux.memoryPolicy flags MPOL_F_RELATIVE_NODES and MPOL_F_STATIC_NODES are mutually exclusive",
            ));
        }
        if numa_balancing && mode != MemoryPolicyMode::Bind {
            return Err(plan_error(
                "linux.memoryPolicy flag MPOL_F_NUMA_BALANCING is valid only with MPOL_BIND",
            ));
        }
        if nodes.is_empty() && (relative_nodes || static_nodes) {
            return Err(plan_error(
                "linux.memoryPolicy relative or static node flags require a nonempty nodes mask",
            ));
        }
        Ok(Some(Self { mode, flags, nodes }))
    }

    fn apply(&self) -> Result<()> {
        let expected_mode = self.expected_kernel_mode();
        let expected_nodes = if self.nodes.is_empty() {
            NodeMask::default()
        } else {
            let allowed = allowed_nodes().map_err(|source| {
                memory_policy_error(
                    error_code_for_io(&source),
                    format!(
                        "failed to resolve the allowed nodes for linux.memoryPolicy mode {}: {source}",
                        self.mode.oci_name()
                    ),
                    "apply-linux-memory-policy",
                )
            })?;
            self.effective_nodes(&allowed)
        };
        let (nodes, maxnode) = self.nodes.syscall_input();
        // SAFETY: `nodes` is null for an empty mask or points to the complete
        // retained fixed-size mask. `maxnode` never exceeds one 4 KiB page of
        // bits, and the call changes only the dedicated init thread.
        if unsafe { libc::syscall(libc::SYS_set_mempolicy, expected_mode, nodes, maxnode) } != 0 {
            let source = io::Error::last_os_error();
            return Err(memory_policy_error(
                error_code_for_io(&source),
                format!(
                    "failed to apply linux.memoryPolicy mode {}: {source}",
                    self.mode.oci_name()
                ),
                "apply-linux-memory-policy",
            ));
        }
        let actual = current().map_err(|source| {
            memory_policy_error(
                error_code_for_io(&source),
                format!(
                    "failed to read back linux.memoryPolicy mode {}: {source}",
                    self.mode.oci_name()
                ),
                "apply-linux-memory-policy",
            )
        })?;
        if actual.mode != expected_mode || actual.nodes != expected_nodes {
            return Err(memory_policy_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "linux.memoryPolicy read-back mismatch: requested {} mode {expected_mode:#x} nodes {}, expected effective nodes {}, observed mode {:#x} nodes {}",
                    self.mode.oci_name(),
                    self.nodes.display(),
                    expected_nodes.display(),
                    actual.mode,
                    actual.nodes.display()
                ),
                "apply-linux-memory-policy",
            ));
        }
        Ok(())
    }

    fn expected_kernel_mode(&self) -> libc::c_int {
        let mode = if self.mode == MemoryPolicyMode::Preferred && self.nodes.is_empty() {
            MemoryPolicyMode::Local
        } else {
            self.mode
        };
        mode.kernel_value() | self.flags
    }

    fn effective_nodes(&self, allowed: &NodeMask) -> NodeMask {
        let mut nodes = if self.flags & libc::MPOL_F_RELATIVE_NODES != 0 {
            self.nodes.relative_to(allowed)
        } else {
            self.nodes.intersection(allowed)
        };
        if self.mode == MemoryPolicyMode::Preferred {
            nodes.retain_first();
        }
        nodes
    }
}

impl MemoryPolicyMode {
    const fn from_oci(value: MemoryPolicyModeType) -> Self {
        match value {
            MemoryPolicyModeType::MpolDefault => Self::Default,
            MemoryPolicyModeType::MpolBind => Self::Bind,
            MemoryPolicyModeType::MpolInterleave => Self::Interleave,
            MemoryPolicyModeType::MpolWeightedInterleave => Self::WeightedInterleave,
            MemoryPolicyModeType::MpolPreferred => Self::Preferred,
            MemoryPolicyModeType::MpolPreferredMany => Self::PreferredMany,
            MemoryPolicyModeType::MpolLocal => Self::Local,
        }
    }

    const fn kernel_value(self) -> libc::c_int {
        match self {
            Self::Default => libc::MPOL_DEFAULT,
            Self::Bind => libc::MPOL_BIND,
            Self::Interleave => libc::MPOL_INTERLEAVE,
            Self::WeightedInterleave => MPOL_WEIGHTED_INTERLEAVE,
            Self::Preferred => libc::MPOL_PREFERRED,
            Self::PreferredMany => MPOL_PREFERRED_MANY,
            Self::Local => libc::MPOL_LOCAL,
        }
    }

    const fn requires_nodes(self) -> bool {
        matches!(
            self,
            Self::Bind | Self::Interleave | Self::WeightedInterleave | Self::PreferredMany
        )
    }

    const fn forbids_nodes(self) -> bool {
        matches!(self, Self::Default | Self::Local)
    }

    const fn oci_name(self) -> &'static str {
        match self {
            Self::Default => "MPOL_DEFAULT",
            Self::Bind => "MPOL_BIND",
            Self::Interleave => "MPOL_INTERLEAVE",
            Self::WeightedInterleave => "MPOL_WEIGHTED_INTERLEAVE",
            Self::Preferred => "MPOL_PREFERRED",
            Self::PreferredMany => "MPOL_PREFERRED_MANY",
            Self::Local => "MPOL_LOCAL",
        }
    }
}

impl Default for NodeMask {
    fn default() -> Self {
        Self {
            words: [0; NODE_MASK_WORDS],
        }
    }
}

impl NodeMask {
    fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() || value.len() > 4_096 {
            return Err(plan_error(
                "linux.memoryPolicy.nodes must be a nonempty bounded node list",
            ));
        }
        let mut mask = Self::default();
        for range in value.split(',') {
            let mut bounds = range.split('-');
            let start = parse_node(bounds.next().unwrap_or_default())?;
            let end = bounds.next().map(parse_node).transpose()?.unwrap_or(start);
            if bounds.next().is_some() || start > end {
                return Err(plan_error(
                    "linux.memoryPolicy.nodes contains an invalid node range",
                ));
            }
            for node in start..=end {
                mask.set(node);
            }
        }
        Ok(mask)
    }

    fn set(&mut self, node: usize) {
        self.words[node / BITS_PER_WORD] |= 1 << (node % BITS_PER_WORD);
    }

    fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    fn retain_first(&mut self) {
        let first = self.nodes().next();
        self.words.fill(0);
        if let Some(node) = first {
            self.set(node);
        }
    }

    fn intersection(&self, other: &Self) -> Self {
        let mut result = Self::default();
        for (result, (left, right)) in result
            .words
            .iter_mut()
            .zip(self.words.iter().zip(other.words.iter()))
        {
            *result = left & right;
        }
        result
    }

    fn relative_to(&self, allowed: &Self) -> Self {
        let allowed = allowed.nodes().collect::<Vec<_>>();
        if allowed.is_empty() {
            return Self::default();
        }
        let mut result = Self::default();
        for node in self.nodes() {
            result.set(allowed[node % allowed.len()]);
        }
        result
    }

    fn nodes(&self) -> impl Iterator<Item = usize> + '_ {
        (0..OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS)
            .filter(|node| self.words[node / BITS_PER_WORD] & (1 << (node % BITS_PER_WORD)) != 0)
    }

    fn syscall_input(&self) -> (*const libc::c_ulong, libc::c_ulong) {
        if self.is_empty() {
            (ptr::null(), 0)
        } else {
            (
                self.words.as_ptr(),
                OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS as libc::c_ulong,
            )
        }
    }

    fn display(&self) -> String {
        let nodes = self
            .nodes()
            .map(|node| node.to_string())
            .collect::<Vec<_>>();
        if nodes.is_empty() {
            "<empty>".to_string()
        } else {
            nodes.join(",")
        }
    }
}

pub(super) fn apply(plan: Option<&MemoryPolicyPlan>) -> Result<()> {
    plan.map_or(Ok(()), MemoryPolicyPlan::apply)
}

fn current() -> io::Result<PolicyObservation> {
    observe(0)
}

fn allowed_nodes() -> io::Result<NodeMask> {
    observe(MPOL_F_MEMS_ALLOWED).map(|observation| observation.nodes)
}

fn observe(flags: libc::c_ulong) -> io::Result<PolicyObservation> {
    let mut mode = 0;
    let mut nodes = NodeMask::default();
    // SAFETY: both output pointers reference complete writable values,
    // `maxnode` matches the fixed mask capacity, `addr` is null, and `flags`
    // either queries the calling thread's default policy or its allowed nodes.
    if unsafe {
        libc::syscall(
            libc::SYS_get_mempolicy,
            &mut mode,
            nodes.words.as_mut_ptr(),
            OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS as libc::c_ulong,
            ptr::null_mut::<libc::c_void>(),
            flags,
        )
    } != 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(PolicyObservation { mode, nodes })
    }
}

fn parse_node(value: &str) -> Result<usize> {
    let node = value.parse::<usize>().map_err(|_| {
        plan_error("linux.memoryPolicy.nodes must contain only node indices and ranges")
    })?;
    if node >= OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS {
        Err(plan_error(format!(
            "linux.memoryPolicy.nodes index {node} exceeds the bounded maximum {}",
            OCI_LINUX_MEMORY_POLICY_MAX_NODE_BITS - 1
        )))
    } else {
        Ok(node)
    }
}

fn error_code_for_io(source: &io::Error) -> ErrorCode {
    match source.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EINVAL | libc::ENODEV) => ErrorCode::InvalidArgument,
        Some(libc::ENOMEM) => ErrorCode::ResourceExhausted,
        Some(libc::ENOSYS | libc::EOPNOTSUPP) => ErrorCode::Unsupported,
        _ => ErrorCode::Internal,
    }
}

fn plan_error(message: impl Into<String>) -> Error {
    memory_policy_error(
        ErrorCode::InvalidArgument,
        message,
        "plan-linux-memory-policy",
    )
}

fn memory_policy_error(
    code: ErrorCode,
    message: impl Into<String>,
    operation: &'static str,
) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::process::Command;

    use a3s_oci_sdk::oci_spec::runtime::LinuxMemoryPolicy;
    use a3s_oci_sdk::ErrorCode;

    use super::{apply, current, error_code_for_io, MemoryPolicyPlan, NodeMask};

    const CHILD_PROBE: &str = "A3S_OCI_MEMORY_POLICY_CHILD_PROBE";
    const APPLY_TEST: &str =
        "executor::memory_policy::tests::applies_and_reads_back_bind_in_an_isolated_process";

    fn policy(mode: &str, nodes: Option<&str>, flags: &[&str]) -> LinuxMemoryPolicy {
        let mut value = serde_json::json!({"mode": mode, "flags": flags});
        if let Some(nodes) = nodes {
            value["nodes"] = serde_json::Value::String(nodes.to_string());
        }
        serde_json::from_value(value).expect("decode Linux memory policy")
    }

    #[test]
    fn plans_every_oci_mode_flag_and_omission() {
        for (mode, nodes) in [
            ("MPOL_DEFAULT", None),
            ("MPOL_BIND", Some("0")),
            ("MPOL_INTERLEAVE", Some("0")),
            ("MPOL_WEIGHTED_INTERLEAVE", Some("0")),
            ("MPOL_PREFERRED", None),
            ("MPOL_PREFERRED_MANY", Some("0")),
            ("MPOL_LOCAL", None),
        ] {
            assert!(MemoryPolicyPlan::from_oci(Some(&policy(mode, nodes, &[])))
                .expect("plan supported memory policy")
                .is_some());
        }
        for flag in [
            "MPOL_F_NUMA_BALANCING",
            "MPOL_F_RELATIVE_NODES",
            "MPOL_F_STATIC_NODES",
        ] {
            assert!(
                MemoryPolicyPlan::from_oci(Some(&policy("MPOL_BIND", Some("0"), &[flag])))
                    .expect("plan supported memory policy flag")
                    .is_some()
            );
        }
        assert!(MemoryPolicyPlan::from_oci(None)
            .expect("omit Linux memory policy")
            .is_none());
    }

    #[test]
    fn validates_node_masks_and_mode_flag_relationships() {
        let parsed = NodeMask::parse("3,1-2,2").expect("normalize bounded node list");
        assert_eq!(parsed.display(), "1,2,3");
        for nodes in ["", "0-", "2-1", "1,,2", "32768"] {
            assert!(
                NodeMask::parse(nodes).is_err(),
                "accepted invalid mask {nodes}"
            );
        }
        for invalid in [
            policy("MPOL_DEFAULT", Some("0"), &[]),
            policy("MPOL_BIND", None, &[]),
            policy(
                "MPOL_BIND",
                Some("0"),
                &["MPOL_F_RELATIVE_NODES", "MPOL_F_STATIC_NODES"],
            ),
            policy("MPOL_LOCAL", None, &["MPOL_F_NUMA_BALANCING"]),
            policy("MPOL_PREFERRED", None, &["MPOL_F_STATIC_NODES"]),
        ] {
            assert!(
                MemoryPolicyPlan::from_oci(Some(&invalid)).is_err(),
                "accepted invalid memory policy {invalid:?}"
            );
        }
    }

    #[test]
    fn preferred_policy_canonicalizes_to_the_first_mask_node() {
        let plan = MemoryPolicyPlan::from_oci(Some(&policy("MPOL_PREFERRED", Some("3,1-2"), &[])))
            .expect("plan preferred policy")
            .expect("present preferred policy");
        let allowed = NodeMask::parse("0-3").expect("parse allowed nodes");
        assert_eq!(plan.effective_nodes(&allowed).display(), "1");
    }

    #[test]
    fn effective_nodes_follow_linux_static_and_relative_resolution() {
        let static_plan = MemoryPolicyPlan::from_oci(Some(&policy(
            "MPOL_BIND",
            Some("0-2"),
            &["MPOL_F_STATIC_NODES"],
        )))
        .expect("plan static policy")
        .expect("present static policy");
        let allowed = NodeMask::parse("1,3").expect("parse sparse allowed nodes");
        assert_eq!(static_plan.effective_nodes(&allowed).display(), "1");

        let relative_plan = MemoryPolicyPlan::from_oci(Some(&policy(
            "MPOL_BIND",
            Some("0,2-3"),
            &["MPOL_F_RELATIVE_NODES"],
        )))
        .expect("plan relative policy")
        .expect("present relative policy");
        assert_eq!(relative_plan.effective_nodes(&allowed).display(), "1,3");
    }

    #[test]
    fn preferred_policy_without_nodes_observes_linux_local_mode() {
        let plan = MemoryPolicyPlan::from_oci(Some(&policy("MPOL_PREFERRED", None, &[])))
            .expect("plan local preferred policy")
            .expect("present preferred policy");
        assert_eq!(plan.expected_kernel_mode(), libc::MPOL_LOCAL);
    }

    #[test]
    fn omission_preserves_the_inherited_policy() {
        let before = current().expect("inspect inherited memory policy");
        apply(None).expect("omit memory-policy application");
        assert_eq!(current().expect("inspect preserved memory policy"), before);
    }

    #[test]
    fn applies_and_reads_back_bind_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let plan = MemoryPolicyPlan::from_oci(Some(&policy(
                "MPOL_BIND",
                Some("0"),
                &["MPOL_F_STATIC_NODES"],
            )))
            .expect("plan MPOL_BIND policy")
            .expect("present MPOL_BIND policy");
            apply(Some(&plan)).expect("apply MPOL_BIND policy");
            let actual = current().expect("read back MPOL_BIND policy");
            assert_eq!(actual.mode, libc::MPOL_BIND | libc::MPOL_F_STATIC_NODES);
            assert_eq!(actual.nodes.display(), "0");
            return;
        }

        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg(APPLY_TEST)
            .arg("--nocapture")
            .env(CHILD_PROBE, "1")
            .status()
            .expect("run isolated memory-policy probe");
        assert!(
            status.success(),
            "isolated memory-policy probe failed: {status}"
        );
    }

    #[test]
    fn syscall_errors_have_stable_types() {
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EPERM)),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EINVAL)),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::ENOMEM)),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::ENOSYS)),
            ErrorCode::Unsupported
        );
        assert_eq!(
            error_code_for_io(&io::Error::from_raw_os_error(libc::EIO)),
            ErrorCode::Internal
        );
    }
}
