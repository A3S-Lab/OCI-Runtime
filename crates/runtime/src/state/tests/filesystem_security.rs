use std::os::unix::fs::symlink;

use a3s_oci_core::DriverKind;
use a3s_oci_sdk::ErrorCode;

use super::{create_request, state_root, DurableStateStore};

#[tokio::test]
async fn pinned_root_is_not_redirected_by_ambient_path_replacement() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let retained_root = temporary.path().join("retained-state");
    let redirected_root = temporary.path().join("redirected-state");
    let request = create_request(
        &bundle_directory,
        "pinned-root-container",
        "pinned-root-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    std::fs::rename(&root, &retained_root).expect("rename ambient root path");
    std::fs::create_dir(&redirected_root).expect("redirected root directory");
    symlink(&redirected_root, &root).expect("replace ambient root path with symlink");

    store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect("the pinned root must remain usable");

    assert!(retained_root
        .join("operations/pinned-root-create.json")
        .is_file());
    assert!(retained_root
        .join("containers/pinned-root-container/record.json")
        .is_file());
    assert_eq!(
        std::fs::read_dir(&redirected_root)
            .expect("inspect redirected root")
            .count(),
        0,
        "no durable mutation may follow the replaced ambient root path"
    );
}

#[tokio::test]
async fn replaced_layout_directory_fails_closed_before_external_mutation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let outside = temporary.path().join("outside-operations");
    let retained = root.join("operations-retained");
    let request = create_request(
        &bundle_directory,
        "layout-replacement-container",
        "layout-replacement-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    std::fs::create_dir(&outside).expect("outside operations directory");
    std::fs::rename(root.join("operations"), &retained).expect("retain operations directory");
    symlink(&outside, root.join("operations")).expect("replace operations with symlink");

    let error = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect_err("a replaced layout directory must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        std::fs::read_dir(&outside)
            .expect("inspect outside operations")
            .count(),
        0,
        "the capability traversal must not follow the replacement symlink"
    );
}

#[tokio::test]
async fn symlinked_transaction_file_fails_closed_without_touching_its_target() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let outside = temporary.path().join("outside-transaction");
    let request = create_request(
        &bundle_directory,
        "transaction-symlink-container",
        "transaction-symlink-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    std::fs::write(&outside, b"unchanged").expect("outside transaction target");
    symlink(
        &outside,
        root.join("operations/.transaction-symlink-create.json.next"),
    )
    .expect("symlink transaction file");

    let error = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect_err("a symlinked transaction file must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        std::fs::read(&outside).expect("read outside transaction target"),
        b"unchanged"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn bind_mount_replacement_fails_closed_when_qualification_is_enabled() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    const QUALIFICATION_ENV: &str = "A3S_OCI_DURABLE_STATE_MOUNT_QUALIFICATION";
    if std::env::var_os(QUALIFICATION_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "{QUALIFICATION_ENV}=1 requires root"
    );

    // SAFETY: this test runs alone under its explicit qualification gate and
    // moves only its process into a fresh mount namespace.
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    // SAFETY: a null source/filesystem with MS_PRIVATE|MS_REC is the standard
    // way to stop mount propagation from this private namespace.
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        },
        0
    );

    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let root = state_root(&temporary);
    let replacement = temporary.path().join("replacement-operations");
    let request = create_request(
        &bundle_directory,
        "mount-replacement-container",
        "mount-replacement-create",
    );
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");
    std::fs::create_dir(&replacement).expect("replacement operations directory");

    let source = CString::new(replacement.as_os_str().as_bytes()).expect("mount source");
    let target_path = root.join("operations");
    let target = CString::new(target_path.as_os_str().as_bytes()).expect("mount target");
    // SAFETY: both paths are live NUL-terminated directories and the bind
    // mount is confined to this test's private mount namespace.
    assert_eq!(
        unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        },
        0
    );
    let mount = TestMount(target);

    let error = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect_err("a bind-mounted layout replacement must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("mount boundary"), "{error}");
    assert_eq!(
        std::fs::read_dir(&replacement)
            .expect("inspect replacement mount")
            .count(),
        0
    );
    drop(mount);
}

#[cfg(target_os = "linux")]
struct TestMount(std::ffi::CString);

#[cfg(target_os = "linux")]
impl Drop for TestMount {
    fn drop(&mut self) {
        // SAFETY: this guard owns the one bind mount created by the gated test.
        let result = unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
        assert_eq!(result, 0, "failed to remove qualification bind mount");
    }
}
