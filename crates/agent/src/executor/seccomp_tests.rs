use std::process::Command;

use a3s_oci_sdk::oci_spec::runtime::Linux;
use a3s_oci_sdk::ErrorCode;
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
fn rejects_seccomp_features_that_cannot_be_enforced() {
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
        "flags": ["SECCOMP_FILTER_FLAG_LOG"]
    }))
    .expect_err("filter flags are not implemented");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("flags"));
}

#[test]
fn rejects_invalid_seccomp_argument_profiles() {
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
