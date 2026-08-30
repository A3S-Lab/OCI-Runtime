use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use a3s_oci_sdk::oci_spec::runtime::{Linux, LinuxResources};
use a3s_oci_sdk::ErrorCode;

use super::{
    canonical_device_source_directory, cleanup_device_target_manifest, load_device_target_manifest,
    load_device_target_manifest_from, verify_ptmx_from_root, write_device_target_manifest,
    DeviceKind, DeviceNode, DevicePlan, DeviceTargetManifest, DeviceTargetRecord,
    PreparedDeviceSource, PreparedDeviceSources, DEVICE_TARGETS_RECORD_NAME,
    DEVICE_TARGETS_SCHEMA_VERSION, ROOTLESS_DEVICE_MOUNT_COUNT,
};
use crate::executor::mount;
use crate::executor::namespace::NamespacePlan;
use tempfile::tempdir;

fn has_effective_capability(capability: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(mask) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
    else {
        return false;
    };
    mask & (1_u64 << capability) != 0
}

struct TestMount(std::ffi::CString);

impl Drop for TestMount {
    fn drop(&mut self) {
        // SAFETY: the test retains the exact NUL-terminated mount path until
        // this guard is dropped. Lazy detachment also handles failed asserts.
        unsafe {
            libc::umount2(self.0.as_ptr(), libc::MNT_DETACH);
        }
    }
}

#[test]
fn device_source_directory_must_be_a_real_directory() {
    let temporary = tempdir().expect("temporary device source parent");
    let directory = temporary.path().join("sources");
    let symlink = temporary.path().join("sources-link");
    std::fs::create_dir(&directory).expect("device source directory");
    std::os::unix::fs::symlink(&directory, &symlink).expect("device source symlink");

    assert_eq!(
        canonical_device_source_directory(&directory).expect("real source directory"),
        directory
            .canonicalize()
            .expect("canonical source directory")
    );
    let error = canonical_device_source_directory(&symlink)
        .expect_err("device source symlink must fail closed");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
}

#[test]
fn device_bind_rejects_a_symlinked_parent_inside_the_rootfs() {
    let temporary = tempdir().expect("temporary device bind workspace");
    let rootfs = temporary.path().join("rootfs");
    let redirected = rootfs.join("redirected-dev");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    std::fs::create_dir(&redirected).expect("redirected device directory");
    std::os::unix::fs::symlink("redirected-dev", rootfs.join("dev"))
        .expect("device parent symlink");

    let node = DeviceNode {
        path: std::path::PathBuf::from("/dev/null"),
        kind: DeviceKind::Character,
        major: 1,
        minor: 3,
        mode: 0o666,
        uid: 0,
        gid: 0,
    };
    let source = std::fs::File::open("/dev/null").expect("device source");
    let source = PreparedDeviceSource::DetachedMount(source.into());
    let prepared = PreparedDeviceSources {
        sources: None,
        console: None,
        verify_ownership: true,
        target_host_owner: None,
        manifest: std::sync::Mutex::new(None),
        manifest_file: std::sync::Mutex::new(None),
        manifest_path: None,
    };

    let error = node
        .bind_source(&rootfs, &source, true, &prepared)
        .expect_err("device bind parent symlinks must fail closed");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(error.message.contains("must be a real directory"));
    assert!(!redirected.join("null").exists());
}

#[test]
fn cleanup_device_target_removes_exact_placeholder_file() {
    let temporary = tempdir().expect("temporary device target directory");
    let path = temporary.path().join("null");
    std::fs::write(&path, b"placeholder").expect("placeholder file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("placeholder permissions");
    let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
    let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
        .expect("capture target");
    let manifest = DeviceTargetManifest {
        schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
        rootfs: super::DeviceRootfsRecord::capture(temporary.path()).expect("rootfs record"),
        targets: vec![record],
    };

    cleanup_device_target_manifest(&manifest).expect("cleanup exact placeholder");

    assert!(!path.exists());
}

#[test]
fn detached_joined_rootfs_receives_guest_local_default_devices() {
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_MKNOD: u32 = 27;
    if !has_effective_capability(CAP_SYS_ADMIN) || !has_effective_capability(CAP_MKNOD) {
        return;
    }

    let temporary = tempdir().expect("temporary detached-rootfs workspace");
    let runtime_directory = temporary.path().join("runtime");
    let device_source_directory = temporary.path().join("sources");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::create_dir(&device_source_directory).expect("device source directory");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    std::fs::create_dir_all(rootfs.join("dev/pts")).expect("rootfs device directories");
    std::os::unix::fs::symlink("pts/ptmx", rootfs.join("dev/ptmx")).expect("rootfs ptmx link");
    let rootfs_path =
        std::ffi::CString::new(rootfs.as_os_str().as_bytes()).expect("rootfs path without NUL");
    if unsafe {
        libc::mount(
            rootfs_path.as_ptr(),
            rootfs_path.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        panic!("bind rootfs mount: {}", std::io::Error::last_os_error());
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            rootfs_path.as_ptr(),
            std::ptr::null(),
            libc::MS_SHARED,
            std::ptr::null(),
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::umount2(rootfs_path.as_ptr(), libc::MNT_DETACH);
        }
        panic!("make rootfs mount shared: {error}");
    }
    let shared_rootfs = TestMount(rootfs_path);

    let plan = DevicePlan::from_linux(Some(&Linux::default()), &[], false, true)
        .expect("default device plan");
    let prepared = plan
        .prepare_sources(
            &NamespacePlan::default(),
            &runtime_directory,
            &device_source_directory,
            false,
            &[],
        )
        .expect("prepare guest-local device mounts");
    prepared
        .bind_rootfs(&rootfs)
        .expect("bind device manifest to rootfs");
    let rootfs_file = std::fs::File::open(&rootfs).expect("open rootfs");
    let original_root = std::fs::File::open("/").expect("retain original root");

    let original_mount_namespace =
        std::fs::File::open("/proc/self/ns/mnt").expect("retain original mount namespace");
    let detached =
        plan.prepare_detached_joined_rootfs(&rootfs, &rootfs_file, &runtime_directory, &prepared);
    // Model the init wrapper entering the requested mount namespace while it
    // retains the complete detached rootfs tree.
    if unsafe { libc::setns(original_mount_namespace.as_raw_fd(), libc::CLONE_NEWNS) } != 0 {
        panic!(
            "restore original mount namespace: {}",
            std::io::Error::last_os_error()
        );
    }
    let detached = detached.expect("prepare detached joined rootfs");
    plan.verify_existing_from_root(&detached)
        .expect("verify detached devices after mount namespace entry");
    crate::executor::rootfs::chroot(&detached).expect("enter detached joined rootfs");
    let current_root = std::fs::File::open("/").expect("open joined root");
    plan.verify_existing_from_root(&current_root)
        .expect("verify devices after mount namespace entry");
    drop(current_root);
    drop(detached);
    let current_root = std::fs::File::open("/").expect("reopen joined root");
    plan.verify_existing_from_root(&current_root)
        .expect("verify devices after releasing the detached mount descriptor");
    drop(current_root);
    crate::executor::rootfs::chroot(&original_root).expect("restore original root");

    for node in &plan.nodes {
        let relative = node.path.strip_prefix("/").expect("relative device path");
        assert!(
            std::fs::symlink_metadata(rootfs.join(relative))
                .expect("shared-root placeholder metadata")
                .file_type()
                .is_file(),
            "{} must remain an ordinary shared-root placeholder",
            node.path.display()
        );
    }

    drop(prepared);
    let manifest = load_device_target_manifest(&runtime_directory)
        .expect("load joined-root device manifest")
        .expect("joined-root device manifest");
    cleanup_device_target_manifest(&manifest).expect("clean joined-root device placeholders");
    drop(shared_rootfs);
}

#[test]
fn restore_preparation_recreates_and_owns_every_default_device_mountpoint() {
    let temporary = tempdir().expect("temporary restore device workspace");
    let runtime_directory = temporary.path().join("runtime");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    std::fs::create_dir(rootfs.join("dev")).expect("rootfs device directory");
    let plan = DevicePlan::from_linux(Some(&Linux::default()), &[], false, true)
        .expect("default device plan");

    plan.prepare_restore_targets(&rootfs, &runtime_directory)
        .expect("prepare restore device targets");

    let manifest = load_device_target_manifest(&runtime_directory)
        .expect("load restore device manifest")
        .expect("restore device manifest");
    assert_eq!(manifest.targets.len(), plan.nodes.len());
    for node in &plan.nodes {
        let relative = node.path.strip_prefix("/").expect("relative device path");
        assert!(rootfs.join(relative).is_file());
        assert!(manifest
            .targets
            .iter()
            .any(|target| target.relative_path == relative));
    }

    cleanup_device_target_manifest(&manifest).expect("cleanup restore device targets");
    assert!(plan.nodes.iter().all(|node| {
        let relative = node.path.strip_prefix("/").expect("relative device path");
        !rootfs.join(relative).exists()
    }));
}

#[test]
fn restore_preparation_preserves_preexisting_device_mountpoints() {
    let temporary = tempdir().expect("temporary restore device workspace");
    let runtime_directory = temporary.path().join("runtime");
    let rootfs = temporary.path().join("rootfs");
    let null = rootfs.join("dev/null");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::create_dir_all(null.parent().expect("device parent"))
        .expect("rootfs device directory");
    std::fs::write(&null, b"bundle-owned").expect("preexisting device mountpoint");
    let plan = DevicePlan::from_linux(Some(&Linux::default()), &[], false, true)
        .expect("default device plan");

    plan.prepare_restore_targets(&rootfs, &runtime_directory)
        .expect("prepare restore device targets");

    let manifest = load_device_target_manifest(&runtime_directory)
        .expect("load restore device manifest")
        .expect("restore device manifest");
    assert_eq!(manifest.targets.len() + 1, plan.nodes.len());
    assert!(!manifest
        .targets
        .iter()
        .any(|target| target.relative_path == std::path::Path::new("dev/null")));
    cleanup_device_target_manifest(&manifest).expect("cleanup restore device targets");
    assert_eq!(
        std::fs::read(&null).expect("preexisting mountpoint after cleanup"),
        b"bundle-owned"
    );
}

#[test]
fn checkpoint_device_mount_contract_is_stable_and_ordered() {
    let plan = DevicePlan::from_linux(Some(&Linux::default()), &[], false, true)
        .expect("default device plan");
    let mounts = plan.checkpoint_external_mounts();

    assert_eq!(mounts.len(), crate::OCI_LINUX_DEFAULT_DEVICE_NODES.len());
    for (index, ((cookie, mountpoint), expected)) in mounts
        .iter()
        .zip(crate::OCI_LINUX_DEFAULT_DEVICE_NODES)
        .enumerate()
    {
        assert_eq!(cookie, &format!("a3s-oci-device-{index:04}"));
        assert_eq!(mountpoint, std::path::Path::new(expected.path));
    }

    let inherited = DevicePlan::from_linux(Some(&Linux::default()), &[], false, false)
        .expect("inherited mount namespace device plan");
    assert!(inherited.checkpoint_external_mounts().is_empty());
}

#[test]
fn cleanup_record_uses_host_owner_for_user_namespace_placeholder() {
    let temporary = tempdir().expect("temporary device target directory");
    let path = temporary.path().join("null");
    std::fs::write(&path, b"placeholder").expect("placeholder file");
    let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
    let namespace_record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
        .expect("capture namespace target");
    let host_owner = (
        namespace_record.uid.wrapping_add(1),
        namespace_record.gid.wrapping_add(1),
    );

    let host_record = DeviceTargetRecord::capture_for_cleanup(
        std::path::Path::new("null"),
        &metadata,
        Some(host_owner),
    )
    .expect("capture mapped target");
    assert_eq!((host_record.uid, host_record.gid), host_owner);
    // Model the initial-user-namespace view used by the supervisor after
    // the container mount namespace has gone away.
    let observed = super::TargetMetadata {
        file_type: libc::S_IFREG,
        dev: metadata.dev(),
        rdev: metadata.rdev(),
        ino: metadata.ino(),
        mode: metadata.mode() & 0o7777,
        uid: host_owner.0,
        gid: host_owner.1,
    };

    assert!(!namespace_record.matches(&observed));
    assert!(host_record.matches(&observed));
}

#[test]
fn cleanup_device_target_fails_closed_on_inode_drift() {
    let temporary = tempdir().expect("temporary device target directory");
    let path = temporary.path().join("null");
    std::fs::write(&path, b"placeholder").expect("placeholder file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("placeholder permissions");
    let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
    let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
        .expect("capture target");
    let manifest = DeviceTargetManifest {
        schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
        rootfs: super::DeviceRootfsRecord::capture(temporary.path()).expect("rootfs record"),
        targets: vec![record],
    };
    let replacement = temporary.path().join("null.replacement");
    std::fs::rename(&path, &replacement).expect("move original placeholder");
    std::fs::write(&path, b"replacement").expect("replacement file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("replacement permissions");

    let error = cleanup_device_target_manifest(&manifest).expect_err("fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(path.exists());
    assert!(replacement.exists());
}

#[test]
fn cleanup_device_target_fails_closed_on_rootfs_inode_drift() {
    let temporary = tempdir().expect("temporary device target directory");
    let rootfs = temporary.path().join("rootfs");
    let retained_rootfs = temporary.path().join("rootfs.retained");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    let path = rootfs.join("null");
    std::fs::write(&path, b"placeholder").expect("placeholder file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("placeholder permissions");
    let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
    let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
        .expect("capture target");
    let manifest = DeviceTargetManifest {
        schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
        rootfs: super::DeviceRootfsRecord::capture(&rootfs).expect("rootfs record"),
        targets: vec![record],
    };

    std::fs::rename(&rootfs, &retained_rootfs).expect("move recorded rootfs");
    std::fs::create_dir(&rootfs).expect("replacement rootfs");
    std::fs::write(rootfs.join("null"), b"replacement").expect("replacement target");

    let error = cleanup_device_target_manifest(&manifest).expect_err("fail closed");
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(error.message.contains("rootfs identity changed"));
    assert_eq!(
        std::fs::read(retained_rootfs.join("null")).expect("retained placeholder"),
        b"placeholder"
    );
    assert_eq!(
        std::fs::read(rootfs.join("null")).expect("replacement target"),
        b"replacement"
    );
}

#[test]
fn cleanup_device_target_rejects_symlink_parent_and_traversal() {
    let temporary = tempdir().expect("temporary device target directory");
    let rootfs = temporary.path().join("rootfs");
    let external = temporary.path().join("external");
    std::fs::create_dir_all(rootfs.join("dev")).expect("rootfs device directory");
    std::fs::create_dir(&external).expect("external directory");
    let path = rootfs.join("dev/null");
    std::fs::write(&path, b"placeholder").expect("placeholder file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("placeholder permissions");
    let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
    let record = DeviceTargetRecord::capture(std::path::Path::new("dev/null"), &metadata)
        .expect("capture target");
    let rootfs_record = super::DeviceRootfsRecord::capture(&rootfs).expect("rootfs record");
    let manifest = DeviceTargetManifest {
        schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
        rootfs: rootfs_record.clone(),
        targets: vec![record.clone()],
    };
    let retained_parent = rootfs.join("dev.retained");
    std::fs::rename(rootfs.join("dev"), &retained_parent).expect("move target parent");
    std::fs::write(external.join("null"), b"external").expect("external target");
    std::os::unix::fs::symlink(&external, rootfs.join("dev")).expect("escaping parent symlink");

    let error = cleanup_device_target_manifest(&manifest).expect_err("reject symlink parent");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        std::fs::read(external.join("null")).expect("external target"),
        b"external"
    );
    assert_eq!(
        std::fs::read(retained_parent.join("null")).expect("retained placeholder"),
        b"placeholder"
    );

    let mut traversal = record;
    traversal.relative_path = std::path::PathBuf::from("../external/null");
    let traversal_manifest = DeviceTargetManifest {
        schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
        rootfs: rootfs_record,
        targets: vec![traversal],
    };
    let error =
        cleanup_device_target_manifest(&traversal_manifest).expect_err("reject traversal target");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        std::fs::read(external.join("null")).expect("external target after traversal"),
        b"external"
    );
}

#[test]
fn device_target_rootfs_binding_is_single_assignment() {
    let temporary = tempdir().expect("temporary plan workspace");
    let runtime_directory = temporary.path().join("runtime");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir_all(&runtime_directory).expect("runtime directory");
    std::fs::create_dir_all(&rootfs).expect("rootfs directory");
    let prepared = PreparedDeviceSources {
        sources: Some(Vec::new()),
        console: None,
        verify_ownership: true,
        target_host_owner: None,
        manifest: std::sync::Mutex::new(None),
        manifest_file: std::sync::Mutex::new(None),
        manifest_path: Some(runtime_directory.join("device-targets.json")),
    };

    prepared.bind_rootfs(&rootfs).expect("bind rootfs once");
    assert!(prepared.bind_rootfs(&rootfs).is_err());
}

#[test]
fn retained_manifest_descriptor_survives_private_path_becoming_unresolvable() {
    let temporary = tempdir().expect("temporary plan workspace");
    let runtime_directory = temporary.path().join("runtime");
    let retained_directory = temporary.path().join("runtime-retained");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    let target = rootfs.join("null");
    std::fs::write(&target, b"placeholder").expect("placeholder file");
    let metadata = std::fs::symlink_metadata(&target).expect("placeholder metadata");
    let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
        .expect("capture target");
    let prepared = PreparedDeviceSources {
        sources: Some(Vec::new()),
        console: None,
        verify_ownership: false,
        target_host_owner: None,
        manifest: std::sync::Mutex::new(None),
        manifest_file: std::sync::Mutex::new(None),
        manifest_path: Some(runtime_directory.join("device-targets.json")),
    };
    prepared.bind_rootfs(&rootfs).expect("bind rootfs");

    std::fs::rename(&runtime_directory, &retained_directory)
        .expect("hide the supervisor runtime directory path");
    std::fs::write(&runtime_directory, b"not a directory")
        .expect("block path-based manifest reopening");
    prepared
        .record_device_target(record.clone())
        .expect("update through the retained manifest descriptor");

    let loaded =
        load_device_target_manifest_from(&retained_directory.join(DEVICE_TARGETS_RECORD_NAME))
            .expect("load retained manifest")
            .expect("retained manifest");
    assert_eq!(loaded.targets, vec![record]);
    std::fs::remove_file(runtime_directory).expect("remove blocking path");
}

#[test]
fn device_target_manifest_failure_rolls_back_new_placeholder() {
    let temporary = tempdir().expect("temporary plan workspace");
    let runtime_directory = temporary.path().join("runtime");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    std::fs::create_dir(rootfs.join("dev")).expect("device directory");
    let manifest_path = runtime_directory.join("device-targets.json");
    let prepared = PreparedDeviceSources {
        sources: Some(Vec::new()),
        console: None,
        verify_ownership: false,
        target_host_owner: None,
        manifest: std::sync::Mutex::new(None),
        manifest_file: std::sync::Mutex::new(None),
        manifest_path: Some(manifest_path.clone()),
    };
    prepared.bind_rootfs(&rootfs).expect("bind rootfs");
    prepared
        .manifest_file
        .lock()
        .expect("manifest file state")
        .take();
    let node = DeviceNode {
        path: std::path::PathBuf::from("/dev/null"),
        kind: DeviceKind::Character,
        major: 1,
        minor: 3,
        mode: 0o666,
        uid: 0,
        gid: 0,
    };
    let source = super::PreparedDeviceSource::DetachedMount(
        std::fs::File::open("/dev/null")
            .expect("device source")
            .into(),
    );

    let error = node
        .bind_source(&rootfs, &source, false, &prepared)
        .expect_err("manifest persistence must fail");
    assert!(error.message.contains("manifest file was not opened"));
    assert!(!rootfs.join("dev/null").exists());
    assert!(manifest_path.is_file());
    assert!(!runtime_directory.join(".device-targets.json.next").exists());
    assert!(prepared
        .manifest
        .lock()
        .expect("manifest state")
        .as_ref()
        .expect("bound manifest")
        .targets
        .is_empty());
}

#[test]
fn invalid_console_record_rolls_back_the_unrecorded_placeholder() {
    let temporary = tempdir().expect("temporary console target workspace");
    let runtime_directory = temporary.path().join("runtime");
    let rootfs = temporary.path().join("rootfs");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    std::fs::create_dir(rootfs.join("dev")).expect("device directory");
    let prepared = PreparedDeviceSources {
        sources: Some(Vec::new()),
        console: None,
        verify_ownership: false,
        target_host_owner: None,
        manifest: std::sync::Mutex::new(None),
        manifest_file: std::sync::Mutex::new(None),
        manifest_path: Some(runtime_directory.join("device-targets.json")),
    };
    prepared.bind_rootfs(&rootfs).expect("bind rootfs");
    let console = rootfs.join("dev/console");
    std::fs::write(&console, b"").expect("console placeholder");

    let error = prepared
        .record_created_target(&console, std::path::Path::new("../dev/console"))
        .expect_err("a traversal record must fail before persistence");

    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(!console.exists());
    assert!(prepared
        .manifest
        .lock()
        .expect("manifest state")
        .as_ref()
        .expect("bound manifest")
        .targets
        .is_empty());
}

#[test]
fn device_target_manifest_round_trips_exact_records() {
    let temporary = tempdir().expect("temporary device target directory");
    let runtime_directory = temporary.path().join("runtime");
    std::fs::create_dir(&runtime_directory).expect("runtime directory");
    std::fs::set_permissions(&runtime_directory, std::fs::Permissions::from_mode(0o700))
        .expect("runtime permissions");
    let rootfs = runtime_directory.join("rootfs");
    std::fs::create_dir(&rootfs).expect("rootfs directory");
    let path = rootfs.join("null");
    std::fs::write(&path, b"placeholder").expect("placeholder file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("placeholder permissions");
    let metadata = std::fs::symlink_metadata(&path).expect("placeholder metadata");
    let record = DeviceTargetRecord::capture(std::path::Path::new("null"), &metadata)
        .expect("capture target");
    let manifest = DeviceTargetManifest {
        schema_version: DEVICE_TARGETS_SCHEMA_VERSION.to_string(),
        rootfs: super::DeviceRootfsRecord::capture(&rootfs).expect("rootfs record"),
        targets: vec![record],
    };
    let manifest_path = runtime_directory.join("device-targets.json");

    write_device_target_manifest(&manifest_path, &manifest).expect("write manifest");
    let loaded = load_device_target_manifest_from(&manifest_path)
        .expect("load manifest")
        .expect("manifest");
    assert_eq!(loaded, manifest);
    assert_eq!(
        load_device_target_manifest(&runtime_directory)
            .expect("load runtime manifest")
            .expect("runtime manifest"),
        manifest
    );
}

#[test]
fn legacy_absolute_device_target_manifest_fails_closed() {
    let temporary = tempdir().expect("temporary device target directory");
    let manifest_path = temporary.path().join("device-targets.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schemaVersion": "a3s.oci.native-linux-device-targets.v1",
            "targets": [{
                "path": "/tmp/untrusted",
                "dev": 1,
                "ino": 2,
                "mode": 384,
                "uid": 0,
                "gid": 0
            }]
        }))
        .expect("encode legacy manifest"),
    )
    .expect("write legacy manifest");
    std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o600))
        .expect("legacy manifest permissions");

    let error = load_device_target_manifest_from(&manifest_path)
        .expect_err("legacy manifest must fail closed");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(error.message.contains("legacy v1 absolute paths"));
}

#[test]
fn plans_the_exact_a3s_box_device_allowlist() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../fixtures/a3s-box/config.json"))
            .expect("decode fixture");
    let linux: Linux =
        serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
    let namespaces = NamespacePlan::from_linux(Some(&linux), 0, 0, &[]).expect("namespace plan");
    let mounts = mount::plan_all(
        serde_json::from_value::<Vec<a3s_oci_sdk::oci_spec::runtime::Mount>>(
            config["mounts"].clone(),
        )
        .expect("decode mounts")
        .as_slice()
        .into(),
        &namespaces,
    )
    .expect("mount plan");
    let plan = DevicePlan::from_linux(Some(&linux), &mounts, false, true).expect("device plan");
    assert_eq!(plan.len(), 6);
    plan.validate_rootless_device_set()
        .expect("A3S Box fixture is the fixed rootless device set");
}

#[test]
fn rootless_default_devices_do_not_require_an_access_policy() {
    let linux: Linux =
        serde_json::from_value(serde_json::json!({})).expect("decode empty Linux configuration");
    let plan = DevicePlan::from_linux(Some(&linux), &[], false, true)
        .expect("plan normative default devices");

    assert_eq!(plan.len(), ROOTLESS_DEVICE_MOUNT_COUNT);
    plan.validate_rootless_device_support()
        .expect("default devices need only the bounded mount helper");
    assert!(plan.validate_rootless_device_set().is_err());
}

#[test]
fn rootless_policy_rejects_devices_outside_the_fixed_safe_set() {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../fixtures/a3s-box/config.json"))
            .expect("decode fixture");
    config["linux"]["devices"][0] = serde_json::json!({
        "path": "/dev/sda",
        "type": "b",
        "major": 8,
        "minor": 0,
        "fileMode": 438,
        "uid": 0,
        "gid": 0
    });
    let linux: Linux =
        serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
    let plan = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
    let error = plan
        .validate_rootless_device_set()
        .expect_err("device outside the fixed safe set must be rejected");
    assert_eq!(error.code, ErrorCode::Unsupported);
}

#[test]
fn rejects_duplicate_device_paths_before_default_merging() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {"path": "/dev/repeated", "type": "c", "major": 10, "minor": 229},
            {"path": "/dev/repeated", "type": "b", "major": 8, "minor": 0}
        ]
    }))
    .expect("decode duplicate device paths");

    let error = DevicePlan::from_linux(Some(&linux), &[], false, true)
        .expect_err("duplicate device paths must not use last-entry-wins semantics");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("duplicate path /dev/repeated"));
}

#[test]
fn rejects_default_device_identity_replacement_but_allows_metadata_override() {
    let conflicting: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {"path": "/dev/null", "type": "b", "major": 8, "minor": 0}
        ]
    }))
    .expect("decode conflicting default device");
    let error = DevicePlan::from_linux(Some(&conflicting), &[], false, true)
        .expect_err("the normative /dev/null identity cannot be replaced");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error
        .message
        .contains("conflicts with normative default device"));

    let metadata_override: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {
                "path": "/dev/null",
                "type": "c",
                "major": 1,
                "minor": 3,
                "fileMode": 384,
                "uid": 7,
                "gid": 8
            }
        ]
    }))
    .expect("decode default metadata override");
    let plan = DevicePlan::from_linux(Some(&metadata_override), &[], false, true)
        .expect("matching default identity may apply requested metadata");
    let node = plan
        .nodes
        .iter()
        .find(|node| node.path == std::path::Path::new("/dev/null"))
        .expect("planned /dev/null");
    assert_eq!((node.mode, node.uid, node.gid), (0o600, 7, 8));
}

#[test]
fn fifo_device_numbers_are_ignored_by_node_creation() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {
                "path": "/run/a3s/fifo",
                "type": "p",
                "major": -1,
                "minor": 9223372036854775807_i64,
                "fileMode": 384
            }
        ]
    }))
    .expect("decode FIFO with irrelevant device numbers");
    let plan = DevicePlan::from_linux(Some(&linux), &[], false, true)
        .expect("FIFO major and minor values have no kernel meaning");
    let fifo = plan
        .nodes
        .iter()
        .find(|node| node.path == std::path::Path::new("/run/a3s/fifo"))
        .expect("planned FIFO");
    assert_eq!((fifo.major, fifo.minor), (0, 0));
}

#[test]
fn plans_all_oci_device_types_outside_dev_with_exact_metadata() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {
                "path": "/run/a3s/character",
                "type": "c",
                "major": 10,
                "minor": 229,
                "fileMode": 384,
                "uid": 1,
                "gid": 2
            },
            {
                "path": "/run/a3s/unbuffered-character",
                "type": "u",
                "major": 10,
                "minor": 230
            },
            {
                "path": "/storage/block",
                "type": "b",
                "major": 8,
                "minor": 0,
                "fileMode": 416,
                "uid": 3,
                "gid": 4
            },
            {
                "path": "/run/a3s/fifo",
                "type": "p",
                "fileMode": 432,
                "uid": 5,
                "gid": 6
            }
        ]
    }))
    .expect("decode every OCI device type");
    let plan =
        DevicePlan::from_linux(Some(&linux), &[], false, true).expect("plan devices outside /dev");

    assert_eq!(plan.nodes.len(), ROOTLESS_DEVICE_MOUNT_COUNT + 4);
    let expected = [
        (
            "/run/a3s/character",
            DeviceKind::Character,
            10,
            229,
            0o600,
            1,
            2,
        ),
        (
            "/run/a3s/unbuffered-character",
            DeviceKind::Character,
            10,
            230,
            0o666,
            0,
            0,
        ),
        ("/storage/block", DeviceKind::Block, 8, 0, 0o640, 3, 4),
        ("/run/a3s/fifo", DeviceKind::Fifo, 0, 0, 0o660, 5, 6),
    ];
    for (path, kind, major, minor, mode, uid, gid) in expected {
        let node = plan
            .nodes
            .iter()
            .find(|node| node.path == std::path::Path::new(path))
            .expect("planned explicit device");
        assert_eq!(
            (node.kind, node.major, node.minor, node.mode, node.uid, node.gid),
            (kind, major, minor, mode, uid, gid)
        );
    }
}

#[test]
fn joined_ptmx_verification_rejects_a_symlinked_dev_parent() {
    let temporary = tempdir().expect("temporary joined rootfs");
    let rootfs = temporary.path().join("rootfs");
    let external = temporary.path().join("external-dev");
    std::fs::create_dir(&rootfs).expect("rootfs");
    std::fs::create_dir(&external).expect("external dev");
    std::os::unix::fs::symlink("pts/ptmx", external.join("ptmx")).expect("external ptmx link");
    std::os::unix::fs::symlink(&external, rootfs.join("dev")).expect("escaping dev parent");
    let rootfs = std::fs::File::open(&rootfs).expect("retained rootfs");

    let error = verify_ptmx_from_root(&rootfs)
        .expect_err("joined /dev inspection must remain beneath the retained rootfs");
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
}

#[test]
fn rejects_duplicate_character_device_identity_across_c_and_u_aliases() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {"path": "/dev/first", "type": "c", "major": 10, "minor": 229},
            {"path": "/outside-dev/second", "type": "u", "major": 10, "minor": 229}
        ]
    }))
    .expect("decode duplicate device identities");
    let error = DevicePlan::from_linux(Some(&linux), &[], false, true)
        .expect_err("duplicate kernel device identities must fail before mutation");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(error.message.contains("duplicate kernel device identity"));
}

#[test]
fn accepts_an_existing_exact_fifo_and_rejects_a_conflicting_file() {
    let temporary = tempdir().expect("temporary device directory");
    let fifo = temporary.path().join("fifo");
    let fifo_c =
        std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path CString");
    // SAFETY: the path is a live NUL-terminated string in an exclusive
    // temporary directory and the mode is valid for mkfifo.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let metadata = std::fs::symlink_metadata(&fifo).expect("FIFO metadata");
    let node = DeviceNode {
        path: fifo,
        kind: DeviceKind::Fifo,
        major: 0,
        minor: 0,
        mode: 0o600,
        uid: metadata.uid(),
        gid: metadata.gid(),
    };
    node.create()
        .expect("matching existing FIFO is already supplied");

    let conflict = temporary.path().join("conflict");
    std::fs::write(&conflict, b"not a FIFO").expect("conflicting file");
    let conflicting = DeviceNode {
        path: conflict,
        ..node
    };
    let error = conflicting
        .create()
        .expect_err("conflicting existing path must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
}

#[test]
fn plans_read_only_device_allowlist_rules() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "devices": [
            {
                "path": "/dev/null",
                "type": "c",
                "major": 1,
                "minor": 3,
                "fileMode": 420,
                "uid": 0,
                "gid": 0
            }
        ],
        "resources": {
            "devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"}
            ]
        }
    }))
    .expect("decode read-only device policy");
    let plan = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
    assert!(plan.requires_setup());
    assert_eq!(plan.len(), 6);
}

#[test]
fn deny_only_device_policy_still_requires_rootfs_enforcement() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "resources": {
            "devices": [{"allow": false, "access": "rwm"}]
        }
    }))
    .expect("decode deny-only device policy");
    let plan = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
    assert!(plan.requires_setup());
    assert_eq!(plan.len(), 6);
}

#[test]
fn replans_device_access_masks_for_live_updates() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "resources": {
            "devices": [
                {"allow": false, "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rwm"}
            ]
        }
    }))
    .expect("decode initial device policy");
    let current = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "devices": [
            {"allow": false, "access": "rwm"},
            {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "r"}
        ]
    }))
    .expect("decode live device update");
    let updated = current
        .update_from_resources(&resources)
        .expect("live device update should replan")
        .expect("live device update should produce a new plan");
    assert_eq!(updated.nodes, current.nodes);
    assert_ne!(updated.access_policy, current.access_policy);
    assert!(updated.requires_setup());
}

#[test]
fn clearing_resource_rules_preserves_the_oci_inventory_filter() {
    let current = DevicePlan::from_linux(Some(&Linux::default()), &[], false, true)
        .expect("default OCI device plan");
    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "devices": []
    }))
    .expect("decode cleared device policy");
    let updated = current
        .update_from_resources(&resources)
        .expect("cleared device policy should replan")
        .expect("cleared device policy should produce a new plan");
    assert_eq!(updated.access_policy, None);
    assert_eq!(updated.nodes, current.nodes);
    assert!(updated.has_device_filter());
    assert!(updated.requires_setup());
}

#[test]
fn all_no_op_device_rules_keep_the_oci_inventory_filter_active() {
    let linux: Linux = serde_json::from_value(serde_json::json!({
        "resources": {
            "devices": [
                {"allow": false},
                {"allow": true, "type": "c", "major": 1, "minor": 3, "access": ""}
            ]
        }
    }))
    .expect("decode no-op device policy");
    let plan = DevicePlan::from_linux(Some(&linux), &[], false, true)
        .expect("no-op rules are valid ordered entries");

    assert!(!plan.has_access_policy());
    assert!(plan.has_device_filter());
}

#[test]
fn fixed_device_nodes_and_inventory_survive_rule_clear_for_restore() {
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../fixtures/a3s-box/config.json"))
            .expect("decode fixture");
    let linux: Linux =
        serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
    let current = DevicePlan::from_linux(Some(&linux), &[], false, true).expect("device plan");
    let cleared: LinuxResources =
        serde_json::from_value(serde_json::json!({"devices": []})).expect("cleared rules");
    let cleared = current
        .update_from_resources(&cleared)
        .expect("clear resource rules")
        .expect("updated policy");
    assert_eq!(cleared.nodes, current.nodes);
    assert!(cleared.has_device_filter());
    assert!(cleared.requires_setup());

    let resources = linux.resources().clone().expect("fixture resources");
    let restored = cleared
        .update_from_resources(&resources)
        .expect("restore resource rules")
        .expect("updated policy");
    assert_eq!(restored.nodes, current.nodes);
    assert_eq!(restored.access_policy, current.access_policy);
    assert!(restored.requires_setup());
}

#[test]
fn keeps_device_access_rules_independent_from_created_nodes() {
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("../../../../../fixtures/a3s-box/config.json"))
            .expect("decode fixture");
    let linux: Linux =
        serde_json::from_value(config["linux"].clone()).expect("decode Linux config");
    let namespaces = NamespacePlan::from_linux(Some(&linux), 0, 0, &[]).expect("namespace plan");
    let mounts = mount::plan_all(
        serde_json::from_value::<Vec<a3s_oci_sdk::oci_spec::runtime::Mount>>(
            config["mounts"].clone(),
        )
        .expect("decode mounts")
        .as_slice()
        .into(),
        &namespaces,
    )
    .expect("mount plan");

    config["linux"]["resources"]["devices"][2]["minor"] = serde_json::json!(6);
    let mutated_linux: Linux =
        serde_json::from_value(config["linux"].clone()).expect("decode mutated Linux config");
    let plan = DevicePlan::from_linux(Some(&mutated_linux), &mounts, false, true)
        .expect("independent access rule");
    assert_eq!(plan.len(), 6);
    assert!(plan.access_policy.is_some());
}
