use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use a3s_oci_sdk::oci_spec::runtime::{
    Arch, Linux, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompArg, LinuxSeccompOperator,
};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use serde::{Deserialize, Serialize};

const MAX_FILTERS: usize = 32;
const MAX_TOTAL_BPF_INSTRUCTIONS: usize = 32_768;
const FILTER_PATH_PENALTY: usize = 4;
const MAX_SYSCALL_ARGUMENT_INDEX: usize = 5;

/// A serializable, architecture-specific seccomp policy retained for init and exec.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SeccompPlan {
    architecture: Option<SeccompArchitecture>,
    filters: Vec<SeccompFilterPlan>,
}

impl SeccompPlan {
    pub(super) fn from_linux(linux: Option<&Linux>) -> Result<Self> {
        let Some(seccomp) = linux.and_then(|linux| linux.seccomp().as_ref()) else {
            return Ok(Self::default());
        };
        validate_unsupported_properties(seccomp)?;
        let architecture = plan_architecture(seccomp.architectures().as_deref())?;
        let default_action = plan_action(
            seccomp.default_action(),
            seccomp.default_errno_ret(),
            "linux.seccomp.defaultAction",
        )?;
        let rules = plan_rules(seccomp, architecture, &default_action)?;
        let filters = plan_filters(default_action, &rules, architecture)?;
        let plan = Self {
            architecture: Some(architecture),
            filters,
        };
        plan.compile_filters()?;
        Ok(plan)
    }

    pub(super) fn install(&self) -> Result<()> {
        let Some(architecture) = self.architecture else {
            return Ok(());
        };
        let running = SeccompArchitecture::native()?;
        if architecture != running {
            return Err(seccomp_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "seccomp policy architecture {} does not match the running architecture {}",
                    architecture.name(),
                    running.name()
                ),
            ));
        }
        let filters = self.compile_filters()?;
        for filter in &filters {
            seccompiler::apply_filter(filter).map_err(|error| {
                seccomp_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to install compiled seccomp BPF filter: {error}"),
                )
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) const fn is_enabled(&self) -> bool {
        self.architecture.is_some()
    }

    #[cfg(test)]
    pub(super) fn filter_count(&self) -> usize {
        self.filters.len()
    }

    fn compile_filters(&self) -> Result<Vec<BpfProgram>> {
        if self.filters.len() > MAX_FILTERS {
            return Err(seccomp_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "seccomp policy requires {} stacked filters; maximum is {MAX_FILTERS}",
                    self.filters.len()
                ),
            ));
        }
        let Some(architecture) = self.architecture else {
            if self.filters.is_empty() {
                return Ok(Vec::new());
            }
            return Err(seccomp_error(
                ErrorCode::Internal,
                "disabled seccomp plan unexpectedly contains filters",
            ));
        };
        let mut total_instructions = 0_usize;
        let mut compiled = Vec::with_capacity(self.filters.len());
        for (index, filter) in self.filters.iter().enumerate() {
            let program = filter.compile(architecture).map_err(|error| {
                Error::new(
                    error.code,
                    format!("failed to compile seccomp filter {index}: {error}"),
                )
                .for_operation("plan-seccomp")
            })?;
            total_instructions = total_instructions
                .checked_add(program.len())
                .and_then(|total| total.checked_add(FILTER_PATH_PENALTY))
                .ok_or_else(|| {
                    seccomp_error(
                        ErrorCode::ResourceExhausted,
                        "seccomp BPF instruction count overflow",
                    )
                })?;
            if total_instructions > MAX_TOTAL_BPF_INSTRUCTIONS {
                return Err(seccomp_error(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "seccomp policy requires {total_instructions} effective BPF instructions; \
                         maximum is {MAX_TOTAL_BPF_INSTRUCTIONS}"
                    ),
                ));
            }
            compiled.push(program);
        }
        Ok(compiled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SeccompArchitecture {
    Aarch64,
    X86_64,
}

impl SeccompArchitecture {
    fn native() -> Result<Self> {
        match std::env::consts::ARCH {
            "aarch64" => Ok(Self::Aarch64),
            "x86_64" => Ok(Self::X86_64),
            architecture => Err(unsupported(
                "linux.seccomp.architectures",
                format!("seccomp is not implemented for architecture `{architecture}`"),
            )),
        }
    }

    const fn compiler_target(self) -> TargetArch {
        match self {
            Self::Aarch64 => TargetArch::aarch64,
            Self::X86_64 => TargetArch::x86_64,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Aarch64 => "aarch64",
            Self::X86_64 => "x86_64",
        }
    }

    fn syscall_number(self, name: &str) -> Option<i64> {
        match self {
            Self::Aarch64 => syscalls::aarch64::Sysno::from_str(name)
                .ok()
                .map(|syscall| i64::from(syscall.id())),
            Self::X86_64 => syscalls::x86_64::Sysno::from_str(name)
                .ok()
                .map(|syscall| i64::from(syscall.id())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SeccompActionPlan {
    Allow,
    Errno(u32),
    KillThread,
    KillProcess,
    Log,
    Trace(u32),
    Trap,
}

impl SeccompActionPlan {
    fn compiler_action(&self) -> SeccompAction {
        match self {
            Self::Allow => SeccompAction::Allow,
            Self::Errno(errno) => SeccompAction::Errno(*errno),
            Self::KillThread => SeccompAction::KillThread,
            Self::KillProcess => SeccompAction::KillProcess,
            Self::Log => SeccompAction::Log,
            Self::Trace(value) => SeccompAction::Trace(*value),
            Self::Trap => SeccompAction::Trap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActionedRule {
    syscall_number: i64,
    action: SeccompActionPlan,
    conditions: Vec<SeccompConditionPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SeccompRulePlan {
    syscall_number: i64,
    conditions: Vec<SeccompConditionPlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SeccompConditionPlan {
    argument_index: u8,
    operator: SeccompOperatorPlan,
    value: u64,
}

impl SeccompConditionPlan {
    fn compile(&self) -> Result<SeccompCondition> {
        SeccompCondition::new(
            self.argument_index,
            SeccompCmpArgLen::Qword,
            self.operator.compiler_operator(),
            self.value,
        )
        .map_err(|error| {
            seccomp_error(
                ErrorCode::InvalidArgument,
                format!("invalid seccomp syscall argument condition: {error}"),
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SeccompOperatorPlan {
    Equal,
    GreaterEqual,
    GreaterThan,
    LessEqual,
    LessThan,
    MaskedEqual(u64),
    NotEqual,
}

impl SeccompOperatorPlan {
    fn compiler_operator(&self) -> SeccompCmpOp {
        match self {
            Self::Equal => SeccompCmpOp::Eq,
            Self::GreaterEqual => SeccompCmpOp::Ge,
            Self::GreaterThan => SeccompCmpOp::Gt,
            Self::LessEqual => SeccompCmpOp::Le,
            Self::LessThan => SeccompCmpOp::Lt,
            Self::MaskedEqual(mask) => SeccompCmpOp::MaskedEq(*mask),
            Self::NotEqual => SeccompCmpOp::Ne,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SeccompFilterPlan {
    mismatch_action: SeccompActionPlan,
    match_action: SeccompActionPlan,
    rules: Vec<SeccompRulePlan>,
}

impl SeccompFilterPlan {
    fn compile(&self, architecture: SeccompArchitecture) -> Result<BpfProgram> {
        let mut grouped: BTreeMap<i64, Option<Vec<SeccompRule>>> = BTreeMap::new();
        for rule in &self.rules {
            let entry = grouped.entry(rule.syscall_number).or_insert_with(|| {
                if rule.conditions.is_empty() {
                    None
                } else {
                    Some(Vec::new())
                }
            });
            if rule.conditions.is_empty() {
                *entry = None;
                continue;
            }
            let Some(compiled_rules) = entry else {
                continue;
            };
            let conditions = rule
                .conditions
                .iter()
                .map(SeccompConditionPlan::compile)
                .collect::<Result<Vec<_>>>()?;
            compiled_rules.push(SeccompRule::new(conditions).map_err(|error| {
                seccomp_error(
                    ErrorCode::InvalidArgument,
                    format!("invalid seccomp syscall rule: {error}"),
                )
            })?);
        }
        let rules = grouped
            .into_iter()
            .map(|(syscall, rules)| (syscall, rules.unwrap_or_default()))
            .collect();
        let filter = SeccompFilter::new(
            rules,
            self.mismatch_action.compiler_action(),
            self.match_action.compiler_action(),
            architecture.compiler_target(),
        )
        .map_err(|error| {
            seccomp_error(
                ErrorCode::InvalidArgument,
                format!("invalid seccomp filter: {error}"),
            )
        })?;
        filter.try_into().map_err(|error| {
            seccomp_error(
                ErrorCode::ResourceExhausted,
                format!("failed to compile seccomp BPF program: {error}"),
            )
        })
    }
}

fn validate_unsupported_properties(seccomp: &LinuxSeccomp) -> Result<()> {
    if seccomp.listener_path().is_some() || seccomp.listener_metadata().is_some() {
        return Err(unsupported(
            "linux.seccomp.listenerPath/listenerMetadata",
            "seccomp userspace notification listeners are not implemented",
        ));
    }
    if seccomp
        .flags()
        .as_ref()
        .is_some_and(|flags| !flags.is_empty())
    {
        return Err(unsupported(
            "linux.seccomp.flags",
            "seccomp filter flags are not implemented by the bootstrap executor",
        ));
    }
    Ok(())
}

fn plan_architecture(architectures: Option<&[Arch]>) -> Result<SeccompArchitecture> {
    let Some(architectures) = architectures.filter(|architectures| !architectures.is_empty())
    else {
        return SeccompArchitecture::native();
    };
    if architectures.len() != 1 {
        return Err(unsupported(
            "linux.seccomp.architectures",
            "the bootstrap executor currently requires exactly one seccomp architecture",
        ));
    }
    match architectures[0] {
        Arch::ScmpArchNative => SeccompArchitecture::native(),
        Arch::ScmpArchAarch64 => Ok(SeccompArchitecture::Aarch64),
        Arch::ScmpArchX86_64 => Ok(SeccompArchitecture::X86_64),
        architecture => Err(unsupported(
            "linux.seccomp.architectures[0]",
            format!("seccomp architecture `{architecture:?}` is not implemented"),
        )),
    }
}

fn plan_action(
    action: LinuxSeccompAction,
    errno_ret: Option<u32>,
    field: &str,
) -> Result<SeccompActionPlan> {
    match action {
        LinuxSeccompAction::ScmpActAllow => {
            reject_unused_errno(errno_ret, field)?;
            Ok(SeccompActionPlan::Allow)
        }
        LinuxSeccompAction::ScmpActErrno => Ok(SeccompActionPlan::Errno(validate_action_data(
            field,
            errno_ret.unwrap_or(libc::EPERM as u32),
        )?)),
        LinuxSeccompAction::ScmpActKill | LinuxSeccompAction::ScmpActKillThread => {
            reject_unused_errno(errno_ret, field)?;
            Ok(SeccompActionPlan::KillThread)
        }
        LinuxSeccompAction::ScmpActKillProcess => {
            reject_unused_errno(errno_ret, field)?;
            Ok(SeccompActionPlan::KillProcess)
        }
        LinuxSeccompAction::ScmpActLog => {
            reject_unused_errno(errno_ret, field)?;
            Ok(SeccompActionPlan::Log)
        }
        LinuxSeccompAction::ScmpActNotify => Err(unsupported(
            field,
            "SCMP_ACT_NOTIFY requires a userspace notification listener",
        )),
        LinuxSeccompAction::ScmpActTrace => Ok(SeccompActionPlan::Trace(validate_action_data(
            field,
            errno_ret.unwrap_or(libc::EPERM as u32),
        )?)),
        LinuxSeccompAction::ScmpActTrap => {
            reject_unused_errno(errno_ret, field)?;
            Ok(SeccompActionPlan::Trap)
        }
    }
}

fn reject_unused_errno(errno_ret: Option<u32>, field: &str) -> Result<()> {
    if errno_ret.is_some() {
        Err(invalid(format!(
            "{field} must not define errnoRet for this seccomp action"
        )))
    } else {
        Ok(())
    }
}

fn validate_action_data(field: &str, value: u32) -> Result<u32> {
    if value > u32::from(u16::MAX) {
        Err(invalid(format!(
            "{field} seccomp action data {value} exceeds the 16-bit kernel field"
        )))
    } else {
        Ok(value)
    }
}

fn plan_rules(
    seccomp: &LinuxSeccomp,
    architecture: SeccompArchitecture,
    default_action: &SeccompActionPlan,
) -> Result<Vec<ActionedRule>> {
    let mut planned = Vec::new();
    for (syscall_index, syscall) in seccomp
        .syscalls()
        .as_deref()
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let field = format!("linux.seccomp.syscalls[{syscall_index}]");
        if syscall.names().is_empty() {
            return Err(invalid(format!("{field}.names must not be empty")));
        }
        let action = plan_action(
            syscall.action(),
            syscall.errno_ret(),
            &format!("{field}.action"),
        )?;
        let conditions = syscall
            .args()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(argument_index, argument)| {
                plan_condition(argument, &format!("{field}.args[{argument_index}]"))
            })
            .collect::<Result<Vec<_>>>()?;
        for (name_index, name) in syscall.names().iter().enumerate() {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(invalid(format!(
                    "{field}.names[{name_index}] must be a non-empty syscall name without NUL bytes"
                )));
            }
            let Some(syscall_number) = architecture.syscall_number(name) else {
                if action == SeccompActionPlan::Allow && default_action != &SeccompActionPlan::Allow
                {
                    // libseccomp-style portable allowlists commonly contain
                    // legacy names absent from the selected architecture. A
                    // missing allow rule remains fail-closed under a blocking
                    // default action.
                    continue;
                }
                return Err(unsupported(
                    &format!("{field}.names[{name_index}]"),
                    format!("syscall `{name}` is unavailable on {}", architecture.name()),
                ));
            };
            planned.push(ActionedRule {
                syscall_number,
                action: action.clone(),
                conditions: conditions.clone(),
            });
        }
    }
    Ok(planned)
}

fn plan_condition(argument: &LinuxSeccompArg, field: &str) -> Result<SeccompConditionPlan> {
    if argument.index() > MAX_SYSCALL_ARGUMENT_INDEX {
        return Err(invalid(format!(
            "{field}.index {} exceeds the final syscall argument index \
             {MAX_SYSCALL_ARGUMENT_INDEX}",
            argument.index()
        )));
    }
    let argument_index = u8::try_from(argument.index()).map_err(|_| {
        invalid(format!(
            "{field}.index {} does not fit the seccomp BPF model",
            argument.index()
        ))
    })?;
    let operator = match argument.op() {
        LinuxSeccompOperator::ScmpCmpEq => {
            reject_unused_value_two(argument.value_two(), field)?;
            SeccompOperatorPlan::Equal
        }
        LinuxSeccompOperator::ScmpCmpGe => {
            reject_unused_value_two(argument.value_two(), field)?;
            SeccompOperatorPlan::GreaterEqual
        }
        LinuxSeccompOperator::ScmpCmpGt => {
            reject_unused_value_two(argument.value_two(), field)?;
            SeccompOperatorPlan::GreaterThan
        }
        LinuxSeccompOperator::ScmpCmpLe => {
            reject_unused_value_two(argument.value_two(), field)?;
            SeccompOperatorPlan::LessEqual
        }
        LinuxSeccompOperator::ScmpCmpLt => {
            reject_unused_value_two(argument.value_two(), field)?;
            SeccompOperatorPlan::LessThan
        }
        LinuxSeccompOperator::ScmpCmpMaskedEq => {
            let mask = argument.value_two().ok_or_else(|| {
                invalid(format!(
                    "{field}.valueTwo is required for SCMP_CMP_MASKED_EQ"
                ))
            })?;
            SeccompOperatorPlan::MaskedEqual(mask)
        }
        LinuxSeccompOperator::ScmpCmpNe => {
            reject_unused_value_two(argument.value_two(), field)?;
            SeccompOperatorPlan::NotEqual
        }
    };
    Ok(SeccompConditionPlan {
        argument_index,
        operator,
        value: argument.value(),
    })
}

fn reject_unused_value_two(value_two: Option<u64>, field: &str) -> Result<()> {
    if value_two.is_some() {
        Err(invalid(format!(
            "{field}.valueTwo is valid only with SCMP_CMP_MASKED_EQ"
        )))
    } else {
        Ok(())
    }
}

fn plan_filters(
    default_action: SeccompActionPlan,
    rules: &[ActionedRule],
    architecture: SeccompArchitecture,
) -> Result<Vec<SeccompFilterPlan>> {
    let mut filters = Vec::new();
    let actions = rules
        .iter()
        .filter(|rule| rule.action != SeccompActionPlan::Allow)
        .map(|rule| rule.action.clone())
        .collect::<BTreeSet<_>>();
    for action in actions {
        filters.push(SeccompFilterPlan {
            mismatch_action: SeccompActionPlan::Allow,
            match_action: action.clone(),
            rules: normalize_rules(rules.iter().filter(|rule| rule.action == action)),
        });
    }
    if default_action != SeccompActionPlan::Allow {
        filters.push(SeccompFilterPlan {
            mismatch_action: default_action.clone(),
            match_action: SeccompActionPlan::Allow,
            rules: normalize_rules(rules.iter().filter(|rule| rule.action != default_action)),
        });
    }
    validate_install_order(&filters, architecture)?;
    Ok(filters)
}

fn normalize_rules<'a>(rules: impl Iterator<Item = &'a ActionedRule>) -> Vec<SeccompRulePlan> {
    let mut grouped: BTreeMap<i64, BTreeSet<Vec<SeccompConditionPlan>>> = BTreeMap::new();
    for rule in rules {
        let conditions = grouped.entry(rule.syscall_number).or_default();
        if conditions.contains(&Vec::new()) {
            continue;
        }
        if rule.conditions.is_empty() {
            conditions.clear();
        }
        conditions.insert(rule.conditions.clone());
    }
    grouped
        .into_iter()
        .flat_map(|(syscall_number, conditions)| {
            conditions
                .into_iter()
                .map(move |conditions| SeccompRulePlan {
                    syscall_number,
                    conditions,
                })
        })
        .collect()
}

fn validate_install_order(
    filters: &[SeccompFilterPlan],
    architecture: SeccompArchitecture,
) -> Result<()> {
    if filters.len() < 2 {
        return Ok(());
    }
    let bootstrap_syscalls = ["prctl", "seccomp"]
        .into_iter()
        .filter_map(|name| architecture.syscall_number(name))
        .collect::<BTreeSet<_>>();
    for (index, filter) in filters[..filters.len() - 1].iter().enumerate() {
        if filter.match_action != SeccompActionPlan::Allow
            && filter
                .rules
                .iter()
                .any(|rule| bootstrap_syscalls.contains(&rule.syscall_number))
        {
            return Err(unsupported(
                "linux.seccomp.syscalls",
                format!(
                    "filter {index} restricts the seccomp installer before all stacked filters \
                     can be attached"
                ),
            ));
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("plan-seccomp")
}

fn unsupported(field: &str, reason: impl Into<String>) -> Error {
    Error::new(
        ErrorCode::Unsupported,
        format!("{field}: {}", reason.into()),
    )
    .for_operation("plan-seccomp")
}

fn seccomp_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("plan-seccomp")
}
