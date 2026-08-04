use std::path::Path;

use super::{executor_runtime_layout, RecoveryMode};

#[test]
fn utility_vm_layout_keeps_native_recovery_identity_out_of_guest_storage() {
    let parent = Path::new("/runtime");
    let (runtime_root, owner_identity) =
        executor_runtime_layout(parent, RecoveryMode::Transient).expect("transient guest layout");

    let expected_name = format!("a3s-oci-agent-{}", std::process::id());
    assert_eq!(
        runtime_root.file_name().and_then(|name| name.to_str()),
        Some(expected_name.as_str())
    );
    assert!(owner_identity.is_none());
}

#[test]
fn native_layout_retains_pid_reuse_safe_owner_identity() {
    let parent = Path::new("/runtime");
    let (runtime_root, owner_identity) =
        executor_runtime_layout(parent, RecoveryMode::DurableNative)
            .expect("durable native layout");

    assert!(owner_identity.is_some());
    assert!(runtime_root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(&format!("a3s-oci-agent-{}-", std::process::id()))));
}
