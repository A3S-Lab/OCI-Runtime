use std::process::Command;

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxSeccompAction, LinuxSeccompOperator};
use a3s_oci_sdk::{
    ErrorCode, OCI_LINUX_SECCOMP_ACTIONS, OCI_LINUX_SECCOMP_ARCHITECTURES,
    OCI_LINUX_SECCOMP_KNOWN_FLAGS, OCI_LINUX_SECCOMP_OPERATORS,
};
use serde_json::json;

use super::seccomp::SeccompPlan;

const INSTALL_HELPER_ENV: &str = "A3S_OCI_SECCOMP_INSTALL_HELPER";
const INSTALL_HELPER_TEST: &str =
    "executor::seccomp_tests::installs_stacked_seccomp_filters_in_helper";

fn plan(seccomp: serde_json::Value) -> a3s_oci_sdk::Result<SeccompPlan> {
    let linux: Linux =
        serde_json::from_value(json!({"seccomp": seccomp})).expect("valid Linux seccomp fixture");
    SeccompPlan::from_linux(Some(&linux))
}

#[test]
fn rejects_every_unadvertised_seccomp_control_before_mutation() {
    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"]
    }))
    .expect_err("multi-architecture dispatch is not implemented");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("exactly one"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_NOTIFY",
        "listenerPath": "/run/a3s-seccomp.sock"
    }))
    .expect_err("userspace notification is not implemented");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("listener"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "listenerMetadata": "opaque"
    }))
    .expect_err("listener metadata without notification support must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("listener"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "flags": ["SECCOMP_FILTER_FLAG_LOG"]
    }))
    .expect_err("filter flags are not implemented");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("flags"));
}

#[test]
fn plans_omitted_and_empty_optional_seccomp_fields() {
    let omitted = SeccompPlan::from_linux(None).expect("omitted seccomp policy");
    assert!(!omitted.is_enabled());
    assert_eq!(omitted.filter_count(), 0);

    let empty = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": [],
        "flags": [],
        "syscalls": []
    }))
    .expect("empty optional seccomp fields");
    assert!(empty.is_enabled());
    assert_eq!(empty.filter_count(), 0);
}

#[test]
fn plans_the_supported_seccomp_architectures() {
    for architecture in OCI_LINUX_SECCOMP_ARCHITECTURES {
        let plan = plan(json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "architectures": [architecture],
            "syscalls": [{
                "names": ["getpid"],
                "action": "SCMP_ACT_ALLOW"
            }]
        }))
        .expect("supported seccomp architecture");
        assert!(plan.is_enabled());
        assert_eq!(plan.filter_count(), 1);
    }
}

#[test]
fn plans_every_advertised_seccomp_action_and_operator() {
    for action in OCI_LINUX_SECCOMP_ACTIONS {
        let mut configuration = json!({"defaultAction": action});
        if matches!(
            *action,
            LinuxSeccompAction::ScmpActErrno | LinuxSeccompAction::ScmpActTrace
        ) {
            configuration["defaultErrnoRet"] = json!(1);
        }
        plan(configuration)
            .unwrap_or_else(|error| panic!("advertised seccomp action {action} failed: {error}"));
    }

    for operator in OCI_LINUX_SECCOMP_OPERATORS {
        let mut argument = json!({
            "index": 0,
            "value": 1,
            "op": operator
        });
        if *operator == LinuxSeccompOperator::ScmpCmpMaskedEq {
            argument["valueTwo"] = json!(u64::MAX);
        }
        plan(json!({
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 1,
            "syscalls": [{
                "names": ["getpid"],
                "action": "SCMP_ACT_ALLOW",
                "args": [argument]
            }]
        }))
        .unwrap_or_else(|error| {
            panic!("advertised seccomp comparison operator {operator} failed: {error}")
        });
    }
}

#[test]
fn recognizes_but_does_not_advertise_unsupported_seccomp_flags() {
    for flag in OCI_LINUX_SECCOMP_KNOWN_FLAGS {
        let error = plan(json!({
            "defaultAction": "SCMP_ACT_ALLOW",
            "flags": [flag]
        }))
        .expect_err("known but unsupported seccomp flags must fail before mutation");
        assert_eq!(error.code, ErrorCode::Unsupported, "{flag}");
        assert!(error.message.contains("flags"), "{flag}: {error}");
    }
}

#[test]
fn rejects_unsupported_seccomp_architectures_and_notify_actions() {
    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86"]
    }))
    .expect_err("unsupported seccomp architecture must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("architectures[0]"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_NOTIFY"
    }))
    .expect_err("default notification action must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("notification listener"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [{
            "names": ["getpid"],
            "action": "SCMP_ACT_NOTIFY"
        }]
    }))
    .expect_err("syscall notification action must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("notification listener"));
}

#[test]
fn rejects_invalid_seccomp_argument_profiles() {
    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "defaultErrnoRet": 1
    }))
    .expect_err("default errno data requires a supporting action");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("defaultAction"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [{
            "names": ["read"],
            "action": "SCMP_ACT_KILL",
            "errnoRet": 1
        }]
    }))
    .expect_err("syscall errno data requires a supporting action");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("syscalls[0].action"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [{
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{
                "index": 6,
                "value": 0,
                "op": "SCMP_CMP_EQ"
            }]
        }]
    }))
    .expect_err("Linux syscalls have only six arguments");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("final syscall argument index"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [{
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{
                "index": 0,
                "value": 0,
                "op": "SCMP_CMP_MASKED_EQ"
            }]
        }]
    }))
    .expect_err("masked comparison requires valueTwo");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("valueTwo"));

    let error = plan(json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [{
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{
                "index": 0,
                "value": 0,
                "valueTwo": 1,
                "op": "SCMP_CMP_EQ"
            }]
        }]
    }))
    .expect_err("valueTwo is reserved for masked comparisons");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("valueTwo"));
}

#[test]
fn seccomp_plan_survives_the_exec_snapshot_round_trip() {
    let plan = plan(json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "syscalls": [
            {"names": ["exit_group"], "action": "SCMP_ACT_ALLOW"},
            {"names": ["getppid"], "action": "SCMP_ACT_ERRNO", "errnoRet": 77}
        ]
    }))
    .expect("supported stacked policy");
    assert!(plan.is_enabled());
    assert_eq!(plan.filter_count(), 2);

    let encoded = serde_json::to_vec(&plan).expect("encode seccomp plan");
    let decoded: SeccompPlan = serde_json::from_slice(&encoded).expect("decode seccomp plan");
    assert_eq!(decoded, plan);
}

#[test]
fn stacked_seccomp_filters_enforce_default_and_specific_errno_actions() {
    let status = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(INSTALL_HELPER_TEST)
        .arg("--nocapture")
        .env(INSTALL_HELPER_ENV, "1")
        .status()
        .expect("launch isolated seccomp installation helper");
    assert!(
        status.success(),
        "isolated seccomp installation helper failed with {status}"
    );
}

#[test]
fn installs_stacked_seccomp_filters_in_helper() {
    if std::env::var_os(INSTALL_HELPER_ENV).is_none() {
        return;
    }
    let plan = match plan(json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "syscalls": [
            {"names": ["exit_group"], "action": "SCMP_ACT_ALLOW"},
            {"names": ["getppid"], "action": "SCMP_ACT_ERRNO", "errnoRet": 77}
        ]
    })) {
        Ok(plan) => plan,
        Err(_) => exit_helper(10),
    };
    if plan.install().is_err() {
        exit_helper(11);
    }

    // SAFETY: both calls use argument-free Linux system calls solely to
    // verify the installed filter's observable errno actions.
    let specific = unsafe { libc::syscall(libc::SYS_getppid) };
    let specific_errno = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: `getuid` is an argument-free Linux system call.
    let defaulted = unsafe { libc::syscall(libc::SYS_getuid) };
    let default_errno = std::io::Error::last_os_error().raw_os_error();
    if specific == -1 && specific_errno == Some(77) && defaulted == -1 && default_errno == Some(1) {
        exit_helper(0);
    }
    exit_helper(12);
}

fn exit_helper(code: libc::c_int) -> ! {
    // SAFETY: the helper is an isolated process and `_exit` avoids running
    // test-harness cleanup after its intentionally restrictive policy.
    unsafe { libc::_exit(code) }
}
