use std::path::Path;

use super::{
    executor_device_source_root, executor_runtime_layout, RecoveryMode,
    UTILITY_VM_DEVICE_SOURCE_PARENT,
};

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
fn utility_vm_device_sources_stay_on_guest_local_storage() {
    let runtime_parent = Path::new("/run/a3s-oci-runtime/run");
    let (runtime_root, _) = executor_runtime_layout(runtime_parent, RecoveryMode::Transient)
        .expect("transient guest layout");

    let source_root = executor_device_source_root(
        runtime_parent,
        &runtime_root,
        Some(Path::new(UTILITY_VM_DEVICE_SOURCE_PARENT)),
    )
    .expect("guest-local device source layout");

    assert!(runtime_root.starts_with(runtime_parent));
    assert!(source_root.starts_with(UTILITY_VM_DEVICE_SOURCE_PARENT));
    assert!(!source_root.starts_with(runtime_parent));
    assert_ne!(source_root, runtime_root);
    assert_eq!(source_root.file_name(), runtime_root.file_name());
}

#[test]
fn native_device_sources_remain_in_the_owned_runtime_root() {
    let runtime_parent = Path::new("/runtime");
    let (runtime_root, _) = executor_runtime_layout(runtime_parent, RecoveryMode::DurableNative)
        .expect("durable native layout");

    let source_root = executor_device_source_root(runtime_parent, &runtime_root, None)
        .expect("native device source layout");

    assert_eq!(source_root, runtime_root);
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
