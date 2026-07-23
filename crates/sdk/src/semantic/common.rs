use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::{contains_nul, is_posix_absolute, OciSemanticPhase, ViolationCollector};

const UNSUPPORTED_PLATFORM_FIELDS: &[&str] = &["freebsd", "solaris", "windows", "zos"];
const HOOK_PHASES: &[&str] = &[
    "prestart",
    "createRuntime",
    "createContainer",
    "startContainer",
    "poststart",
    "poststop",
];

pub(super) fn inspect(value: &Value, phase: OciSemanticPhase, collector: &mut ViolationCollector) {
    let Some(configuration) = value.as_object() else {
        return;
    };

    reject_unsupported_platforms(configuration, collector);
    validate_root(configuration, collector);
    validate_process(configuration, phase, collector);
    validate_mounts(configuration, collector);
    validate_hooks(configuration, collector);
    validate_annotations(configuration, collector);
}

fn reject_unsupported_platforms(
    configuration: &Map<String, Value>,
    collector: &mut ViolationCollector,
) {
    for field in UNSUPPORTED_PLATFORM_FIELDS {
        if configuration.contains_key(*field) {
            collector.unsupported(
                format!("/{field}"),
                "oci.platform.linux-only",
                format!(
                    "native {field} workload configuration is not supported; A3S hosts execute Linux OCI workloads"
                ),
            );
        }
    }
}

fn validate_root(configuration: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(root) = configuration.get("root").and_then(Value::as_object) else {
        collector.invalid(
            "/root",
            "oci.common.root.required",
            "root is required for a Linux OCI workload",
        );
        return;
    };
    let Some(path) = root.get("path").and_then(Value::as_str) else {
        return;
    };
    if path.is_empty() {
        collector.invalid(
            "/root/path",
            "oci.common.root.path.non-empty",
            "root.path must not be empty",
        );
    } else if contains_nul(path) {
        collector.invalid(
            "/root/path",
            "oci.common.path.no-nul",
            "root.path must not contain a NUL byte",
        );
    }
}

fn validate_process(
    configuration: &Map<String, Value>,
    phase: OciSemanticPhase,
    collector: &mut ViolationCollector,
) {
    let Some(process) = configuration.get("process").and_then(Value::as_object) else {
        if phase == OciSemanticPhase::Start {
            collector.invalid(
                "/process",
                "oci.common.process.required-for-start",
                "process is required before OCI start",
            );
        }
        return;
    };

    if let Some(cwd) = process.get("cwd").and_then(Value::as_str) {
        if !is_posix_absolute(cwd) {
            collector.invalid(
                "/process/cwd",
                "oci.common.process.cwd.absolute",
                "process.cwd must be an absolute Linux container path",
            );
        }
        if contains_nul(cwd) {
            collector.invalid(
                "/process/cwd",
                "oci.common.path.no-nul",
                "process.cwd must not contain a NUL byte",
            );
        }
    }

    match process.get("args").and_then(Value::as_array) {
        Some(arguments) if arguments.is_empty() => collector.invalid(
            "/process/args",
            "oci.common.process.args.non-empty",
            "process.args must contain the executable for a Linux workload",
        ),
        Some(arguments) => {
            for (index, argument) in arguments.iter().filter_map(Value::as_str).enumerate() {
                if contains_nul(argument) {
                    collector.invalid(
                        format!("/process/args/{index}"),
                        "oci.common.process.argument.no-nul",
                        "process arguments must not contain a NUL byte",
                    );
                }
            }
            if arguments
                .first()
                .and_then(Value::as_str)
                .is_some_and(str::is_empty)
            {
                collector.invalid(
                    "/process/args/0",
                    "oci.common.process.executable.non-empty",
                    "the first process argument must name an executable",
                );
            }
        }
        None => collector.invalid(
            "/process/args",
            "oci.common.process.args.required-linux",
            "process.args is required for a Linux workload",
        ),
    }

    if process.contains_key("commandLine") {
        collector.unsupported(
            "/process/commandLine",
            "oci.platform.windows-process-field",
            "process.commandLine is a native Windows process field",
        );
    }
    if process
        .get("user")
        .and_then(Value::as_object)
        .is_some_and(|user| user.contains_key("username"))
    {
        collector.unsupported(
            "/process/user/username",
            "oci.platform.windows-process-field",
            "process.user.username is a native Windows process field",
        );
    }

    if let Some(environment) = process.get("env").and_then(Value::as_array) {
        validate_environment(environment, "/process/env", collector);
    }
    validate_rlimits(process, collector);
    validate_io_priority(process, collector);
    validate_scheduler(process, collector);
}

fn validate_environment(
    environment: &[Value],
    base_path: &str,
    collector: &mut ViolationCollector,
) {
    for (index, entry) in environment.iter().filter_map(Value::as_str).enumerate() {
        let path = format!("{base_path}/{index}");
        let Some((name, _)) = entry.split_once('=') else {
            collector.invalid(
                path,
                "oci.common.environment.assignment",
                "environment entries must use NAME=VALUE form",
            );
            continue;
        };
        if name.is_empty() {
            collector.invalid(
                &path,
                "oci.common.environment.name.non-empty",
                "environment variable names must not be empty",
            );
        }
        if contains_nul(entry) {
            collector.invalid(
                path,
                "oci.common.environment.no-nul",
                "environment entries must not contain a NUL byte",
            );
        }
    }
}

fn validate_rlimits(process: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(rlimits) = process.get("rlimits").and_then(Value::as_array) else {
        return;
    };
    let mut seen = BTreeSet::new();
    for (index, rlimit) in rlimits.iter().filter_map(Value::as_object).enumerate() {
        if let Some(kind) = rlimit.get("type").and_then(Value::as_str) {
            if !seen.insert(kind) {
                collector.invalid(
                    format!("/process/rlimits/{index}/type"),
                    "oci.common.rlimit.type.unique",
                    format!("duplicate process rlimit type {kind}"),
                );
            }
        }
        if let (Some(soft), Some(hard)) = (
            rlimit.get("soft").and_then(Value::as_u64),
            rlimit.get("hard").and_then(Value::as_u64),
        ) {
            if soft > hard {
                collector.invalid(
                    format!("/process/rlimits/{index}/soft"),
                    "oci.common.rlimit.soft-at-most-hard",
                    format!("rlimit soft value {soft} exceeds hard value {hard}"),
                );
            }
        }
    }
}

fn validate_io_priority(process: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(priority) = process
        .get("ioPriority")
        .and_then(Value::as_object)
        .and_then(|value| value.get("priority"))
        .and_then(Value::as_i64)
    else {
        return;
    };
    if !(0..=7).contains(&priority) {
        collector.invalid(
            "/process/ioPriority/priority",
            "oci.linux.io-priority.range",
            "Linux I/O priority must be between 0 and 7",
        );
    }
}

fn validate_scheduler(process: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(scheduler) = process.get("scheduler").and_then(Value::as_object) else {
        return;
    };
    let Some(policy) = scheduler.get("policy").and_then(Value::as_str) else {
        return;
    };

    if matches!(policy, "SCHED_OTHER" | "SCHED_BATCH")
        && scheduler
            .get("nice")
            .and_then(Value::as_i64)
            .is_some_and(|nice| !(-20..=19).contains(&nice))
    {
        collector.invalid(
            "/process/scheduler/nice",
            "oci.linux.scheduler.nice.range",
            "scheduler nice must be between -20 and 19 for SCHED_OTHER or SCHED_BATCH",
        );
    }
    if scheduler
        .get("priority")
        .and_then(Value::as_i64)
        .is_some_and(|priority| priority != 0)
        && !matches!(policy, "SCHED_FIFO" | "SCHED_RR")
    {
        collector.invalid(
            "/process/scheduler/priority",
            "oci.linux.scheduler.priority.policy",
            "scheduler priority is valid only for SCHED_FIFO or SCHED_RR",
        );
    }

    let deadline_fields = ["runtime", "deadline", "period"];
    let has_deadline_values = deadline_fields.iter().any(|field| {
        scheduler
            .get(*field)
            .and_then(Value::as_u64)
            .is_some_and(|value| value != 0)
    });
    if policy != "SCHED_DEADLINE" && has_deadline_values {
        collector.invalid(
            "/process/scheduler",
            "oci.linux.scheduler.deadline-fields.policy",
            "scheduler runtime, deadline, and period are valid only for SCHED_DEADLINE",
        );
    }
    if policy == "SCHED_DEADLINE" {
        let runtime = scheduler
            .get("runtime")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let deadline = scheduler
            .get("deadline")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let period = scheduler
            .get("period")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if runtime == 0 || runtime > deadline || deadline > period {
            collector.invalid(
                "/process/scheduler",
                "oci.linux.scheduler.deadline-order",
                "SCHED_DEADLINE requires 0 < runtime <= deadline <= period",
            );
        }
    }
}

fn validate_mounts(configuration: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(mounts) = configuration.get("mounts").and_then(Value::as_array) else {
        return;
    };
    for (index, mount) in mounts.iter().filter_map(Value::as_object).enumerate() {
        if let Some(destination) = mount.get("destination").and_then(Value::as_str) {
            if destination.is_empty() {
                collector.invalid(
                    format!("/mounts/{index}/destination"),
                    "oci.common.mount.destination.non-empty",
                    "mount destination must not be empty",
                );
            } else if contains_nul(destination) {
                collector.invalid(
                    format!("/mounts/{index}/destination"),
                    "oci.common.path.no-nul",
                    "mount destination must not contain a NUL byte",
                );
            }
        }

        let uid_present = mount.contains_key("uidMappings");
        let gid_present = mount.contains_key("gidMappings");
        if uid_present != gid_present {
            let missing = if uid_present {
                "gidMappings"
            } else {
                "uidMappings"
            };
            collector.invalid(
                format!("/mounts/{index}/{missing}"),
                "oci.common.mount.id-mappings.paired",
                "mount uidMappings and gidMappings must be specified together",
            );
        }
    }
}

fn validate_hooks(configuration: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(hooks) = configuration.get("hooks").and_then(Value::as_object) else {
        return;
    };
    for phase in HOOK_PHASES {
        let Some(entries) = hooks.get(*phase).and_then(Value::as_array) else {
            continue;
        };
        for (index, hook) in entries.iter().filter_map(Value::as_object).enumerate() {
            if let Some(path) = hook.get("path").and_then(Value::as_str) {
                if !is_posix_absolute(path) {
                    collector.invalid(
                        format!("/hooks/{phase}/{index}/path"),
                        "oci.common.hook.path.absolute",
                        "hook path must be absolute",
                    );
                }
                if contains_nul(path) {
                    collector.invalid(
                        format!("/hooks/{phase}/{index}/path"),
                        "oci.common.path.no-nul",
                        "hook path must not contain a NUL byte",
                    );
                }
            }
            if let Some(environment) = hook.get("env").and_then(Value::as_array) {
                validate_environment(
                    environment,
                    &format!("/hooks/{phase}/{index}/env"),
                    collector,
                );
            }
        }
    }
}

fn validate_annotations(configuration: &Map<String, Value>, collector: &mut ViolationCollector) {
    let Some(annotations) = configuration.get("annotations").and_then(Value::as_object) else {
        return;
    };
    if annotations.contains_key("") {
        collector.invalid(
            "/annotations/",
            "oci.common.annotation.key.non-empty",
            "annotation keys must not be empty",
        );
    }
}
