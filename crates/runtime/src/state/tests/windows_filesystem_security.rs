use std::fmt;
use std::os::windows::fs::{symlink_dir, symlink_file, MetadataExt as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use a3s_oci_core::DriverKind;
use a3s_oci_sdk::ErrorCode;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::fault::{DurableMutation, FaultInjector, FaultPoint, FileCommitStage};

use super::{create_request, state_root, DurableStateStore};

struct CallbackFaultInjector {
    target: FaultPoint,
    fired: AtomicBool,
    callback: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl CallbackFaultInjector {
    fn new(target: FaultPoint, callback: impl FnOnce() + Send + 'static) -> Self {
        Self {
            target,
            fired: AtomicBool::new(false),
            callback: Mutex::new(Some(Box::new(callback))),
        }
    }

    fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for CallbackFaultInjector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackFaultInjector")
            .field("target", &self.target)
            .field("fired", &self.fired())
            .finish_non_exhaustive()
    }
}

impl FaultInjector for CallbackFaultInjector {
    fn check(&self, point: FaultPoint) -> a3s_oci_sdk::Result<()> {
        if point == self.target && !self.fired.swap(true, Ordering::SeqCst) {
            let callback = self
                .callback
                .lock()
                .expect("callback fault lock")
                .take()
                .expect("callback fault must fire once");
            callback();
        }
        Ok(())
    }
}

#[tokio::test]
async fn rejects_reparse_point_runtime_root_without_touching_its_target() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let external = temporary.path().join("external-root");
    let sentinel = external.join("sentinel.txt");
    std::fs::create_dir(&external).expect("external directory");
    std::fs::write(&sentinel, b"external-root\n").expect("external sentinel");
    symlink_dir(&external, &root).expect("runtime-root directory symlink");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("a reparse-point runtime root must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        std::fs::read(&sentinel).expect("external sentinel remains readable"),
        b"external-root\n"
    );
    assert_eq!(
        std::fs::read_dir(&external)
            .expect("external directory")
            .count(),
        1
    );
}

#[tokio::test]
async fn rejects_layout_directory_replaced_by_a_reparse_point() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle = temporary.path().join("bundle");
    let root = state_root(&temporary);
    let external = temporary.path().join("external-containers");
    let sentinel = external.join("sentinel.txt");
    std::fs::create_dir(&bundle).expect("bundle directory");
    std::fs::create_dir(&external).expect("external directory");
    std::fs::write(&sentinel, b"external-layout\n").expect("external sentinel");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    let containers = root.join("containers");
    let displaced = root.join("containers.displaced");
    std::fs::rename(&containers, &displaced).expect("displace containers directory");
    symlink_dir(&external, &containers).expect("replacement directory symlink");
    let request = create_request(&bundle, "reparse-container", "reparse-create");

    let error = store
        .prepare_create(&request, DriverKind::LibkrunWhpx)
        .await
        .expect_err("a reparse-point layout directory must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(
        std::fs::read(&sentinel).expect("external sentinel remains readable"),
        b"external-layout\n"
    );
    assert_eq!(
        std::fs::read_dir(&external)
            .expect("external directory")
            .count(),
        1
    );
}

#[tokio::test]
async fn rejects_preexisting_transaction_file_reparse_point() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let external = temporary.path().join("external-marker.json");
    let transaction = root.join(".root.json.next");
    std::fs::create_dir(&root).expect("state root");
    std::fs::write(&external, b"external-transaction\n").expect("external file");
    symlink_file(&external, &transaction).expect("transaction file symlink");

    let error = DurableStateStore::open(&root)
        .await
        .expect_err("a transaction-file reparse point must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_reparse_point(&transaction);
    assert_eq!(
        std::fs::read(&external).expect("external file remains readable"),
        b"external-transaction\n"
    );
}

#[tokio::test]
async fn commits_the_open_temporary_file_when_its_name_is_replaced() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let external = temporary.path().join("external-temporary.json");
    let transaction = root.join(".root.json.next");
    let displaced = root.join(".root.json.displaced");
    std::fs::write(&external, b"external-temporary\n").expect("external file");
    let callback_transaction = transaction.clone();
    let callback_displaced = displaced.clone();
    let callback_external = external.clone();
    let point = FaultPoint::DurableFile {
        mutation: DurableMutation::RuntimeRootMarker,
        stage: FileCommitStage::TemporaryFileCreated,
    };
    let injector = Arc::new(CallbackFaultInjector::new(point, move || {
        std::fs::rename(&callback_transaction, &callback_displaced)
            .expect("displace open transaction file");
        symlink_file(&callback_external, &callback_transaction)
            .expect("replace transaction name with a file symlink");
    }));
    let faults: Arc<dyn FaultInjector> = injector.clone();

    let store = DurableStateStore::open_with_fault_injector(&root, faults)
        .await
        .expect("commit the exact open transaction object");

    assert!(injector.fired());
    assert_plain_file(&root.join("root.json"));
    assert_reparse_point(&transaction);
    assert!(!displaced.exists());
    assert_eq!(
        std::fs::read(&external).expect("external file remains readable"),
        b"external-temporary\n"
    );
    drop(store);
}

#[tokio::test]
async fn replaces_a_racing_destination_reparse_point_without_following_it() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let external = temporary.path().join("external-destination.json");
    let destination = root.join("root.json");
    std::fs::write(&external, b"external-destination\n").expect("external file");
    let callback_destination = destination.clone();
    let callback_external = external.clone();
    let point = FaultPoint::DurableFile {
        mutation: DurableMutation::RuntimeRootMarker,
        stage: FileCommitStage::FileSynced,
    };
    let injector = Arc::new(CallbackFaultInjector::new(point, move || {
        symlink_file(&callback_external, &callback_destination)
            .expect("install racing destination symlink");
    }));
    let faults: Arc<dyn FaultInjector> = injector.clone();

    let store = DurableStateStore::open_with_fault_injector(&root, faults)
        .await
        .expect("replace the destination name without following it");

    assert!(injector.fired());
    assert_plain_file(&destination);
    assert_eq!(
        std::fs::read(&external).expect("external file remains readable"),
        b"external-destination\n"
    );
    drop(store);
}

#[tokio::test]
async fn retained_root_and_lock_handles_block_name_replacement() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = state_root(&temporary);
    let moved_root = temporary.path().join("state.moved");
    let lock = root.join(".lock");
    let moved_lock = root.join(".lock.moved");
    let store = DurableStateStore::open(&root)
        .await
        .expect("initialize state root");

    std::fs::rename(&lock, &moved_lock)
        .expect_err("the retained lock handle must block lock-name replacement");
    std::fs::rename(&root, &moved_root)
        .expect_err("the retained root handle must block root-name replacement");
    assert!(root.join("root.json").is_file());

    drop(store);
    std::fs::rename(&lock, &moved_lock).expect("released lock handle permits rename");
    std::fs::rename(&root, &moved_root).expect("released root handle permits rename");
}

fn assert_reparse_point(path: &PathBuf) {
    let metadata = std::fs::symlink_metadata(path).expect("reparse-point metadata");
    assert_ne!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0,
        "{} must be a reparse point",
        path.display()
    );
}

fn assert_plain_file(path: &PathBuf) {
    let metadata = std::fs::symlink_metadata(path).expect("plain-file metadata");
    assert!(metadata.is_file(), "{} must be a file", path.display());
    assert_eq!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
        0,
        "{} must not be a reparse point",
        path.display()
    );
}
