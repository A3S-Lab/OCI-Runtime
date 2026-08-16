use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream as StdUnixStream;

use a3s_oci_sdk::{Error, ErrorCode};

use super::super::capability::{CapabilitySet, CapabilityWarning};
use super::{
    acknowledge_user_mapping, read_outcome, read_start_result, request_user_mapping,
    send_device_mounts, write_capability_warning, write_create_hooks_ready, write_ready,
    write_rejection, InitOutcome,
};

#[tokio::test(flavor = "current_thread")]
async fn user_mapping_handshake_blocks_until_the_parent_acknowledges() {
    let (mut child, parent) = StdUnixStream::pair().expect("create control socket pair");
    parent
        .set_nonblocking(true)
        .expect("make control parent nonblocking");
    let child = tokio::task::spawn_blocking(move || {
        request_user_mapping(&mut child).expect("mapping handshake");
    });
    let mut parent = tokio::net::UnixStream::from_std(parent).expect("register control parent");

    assert_eq!(
        read_outcome(&mut parent)
            .await
            .expect("read mapping request"),
        InitOutcome::UserMappingRequired
    );
    acknowledge_user_mapping(&mut parent)
        .await
        .expect("acknowledge mappings");
    child.await.expect("mapping child");
}

#[tokio::test(flavor = "current_thread")]
async fn parent_sends_device_mounts_over_the_authenticated_control_socket() {
    let (child, parent) = StdUnixStream::pair().expect("create control socket pair");
    parent
        .set_nonblocking(true)
        .expect("make control parent nonblocking");
    let mounts = (0..super::super::device::ROOTLESS_DEVICE_MOUNT_COUNT)
        .map(|_| {
            let file = std::fs::File::open("/dev/null").expect("device fixture");
            OwnedFd::from(file)
        })
        .collect::<Vec<_>>();
    let parent = tokio::net::UnixStream::from_std(parent).expect("register control parent");
    send_device_mounts(&parent, &mounts).expect("send prepared mounts");

    let received =
        super::receive_device_mounts(&child, mounts.len()).expect("receive prepared mounts");
    assert_eq!(received.len(), mounts.len());
}

#[tokio::test(flavor = "current_thread")]
async fn ready_round_trip_carries_the_runtime_and_optional_namespace_init_pids() {
    for namespace_init_pid in [Some(41_999), None] {
        let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
        reader
            .set_nonblocking(true)
            .expect("make control reader nonblocking");
        let writer = tokio::task::spawn_blocking(move || {
            write_ready(&mut writer, 42_001, namespace_init_pid).expect("write readiness");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

        assert_eq!(
            read_outcome(&mut reader).await.expect("read readiness"),
            InitOutcome::Ready {
                pid: 42_001,
                namespace_init_pid,
            }
        );
        writer.await.expect("control writer task");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn create_hook_barrier_is_distinct_from_final_readiness() {
    let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
    reader
        .set_nonblocking(true)
        .expect("make control reader nonblocking");
    let writer = tokio::task::spawn_blocking(move || {
        write_create_hooks_ready(&mut writer, 42_001, Some(41_999))
            .expect("write create-hook readiness");
    });
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

    assert_eq!(
        read_outcome(&mut reader)
            .await
            .expect("read create-hook readiness"),
        InitOutcome::CreateHooksReady {
            pid: 42_001,
            namespace_init_pid: Some(41_999),
        }
    );
    writer.await.expect("control writer task");
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_reader_rejects_non_positive_or_truncated_pids() {
    use std::io::Write;

    for payload in [
        [0_i32.to_be_bytes(), 0_i32.to_be_bytes()].concat(),
        vec![0, 1],
        42_001_i32.to_be_bytes().to_vec(),
        [42_001_i32.to_be_bytes(), (-1_i32).to_be_bytes()].concat(),
        [42_001_i32.to_be_bytes(), 42_001_i32.to_be_bytes()].concat(),
    ] {
        let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
        reader
            .set_nonblocking(true)
            .expect("make control reader nonblocking");
        let writer = tokio::task::spawn_blocking(move || {
            writer.write_all(&[super::READY_BYTE]).expect("kind");
            writer.write_all(&payload).expect("PID payload");
        });
        let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

        let error = read_outcome(&mut reader)
            .await
            .expect_err("invalid readiness PID must fail");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        writer.await.expect("control writer task");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejection_round_trip_preserves_the_typed_error() {
    let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
    reader
        .set_nonblocking(true)
        .expect("make control reader nonblocking");
    let expected = Error::new(ErrorCode::PermissionDenied, "pivot root denied")
        .for_operation("prepare-container-rootfs");
    let reported = expected.clone();
    let writer = tokio::task::spawn_blocking(move || {
        write_rejection(&mut writer, &reported).expect("write rejection");
    });
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

    assert_eq!(
        read_outcome(&mut reader).await.expect("read rejection"),
        InitOutcome::Rejected(expected)
    );
    writer.await.expect("control writer task");
}

#[tokio::test(flavor = "current_thread")]
async fn start_result_distinguishes_exec_close_from_typed_rejection() {
    let (writer, reader) = StdUnixStream::pair().expect("create exec-close socket pair");
    reader
        .set_nonblocking(true)
        .expect("make exec-close reader nonblocking");
    drop(writer);
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register close reader");
    let warnings = read_start_result(&mut reader)
        .await
        .expect("control close proves successful exec");
    assert!(warnings.is_empty());

    let (mut writer, reader) = StdUnixStream::pair().expect("create rejection socket pair");
    reader
        .set_nonblocking(true)
        .expect("make rejection reader nonblocking");
    let expected = Error::new(ErrorCode::FailedPrecondition, "start hook failed")
        .for_operation("run-oci-hook");
    let reported = expected.clone();
    let writer = tokio::task::spawn_blocking(move || {
        write_rejection(&mut writer, &reported).expect("write start rejection");
    });
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register reject reader");
    assert_eq!(
        read_start_result(&mut reader)
            .await
            .expect_err("typed start rejection must fail"),
        expected
    );
    writer.await.expect("start rejection writer");
}

#[tokio::test(flavor = "current_thread")]
async fn start_result_retains_capability_warnings_before_exec_close() {
    let (mut writer, reader) = StdUnixStream::pair().expect("create warning socket pair");
    reader
        .set_nonblocking(true)
        .expect("make warning reader nonblocking");
    let expected = CapabilityWarning::new(
        "CAP_BPF",
        vec![CapabilitySet::Effective, CapabilitySet::Permitted],
    )
    .expect("valid warning");
    let reported = expected.clone();
    let writer = tokio::task::spawn_blocking(move || {
        write_capability_warning(&mut writer, &reported).expect("write warning");
    });
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register warning reader");

    assert_eq!(
        read_start_result(&mut reader)
            .await
            .expect("read warning before exec close"),
        vec![expected]
    );
    writer.await.expect("warning writer");
}

#[tokio::test(flavor = "current_thread")]
async fn start_result_rejects_duplicate_capability_warnings() {
    let (mut writer, reader) = StdUnixStream::pair().expect("create warning socket pair");
    reader
        .set_nonblocking(true)
        .expect("make warning reader nonblocking");
    let warning = CapabilityWarning::new(
        "CAP_BPF",
        vec![CapabilitySet::Bounding, CapabilitySet::Permitted],
    )
    .expect("valid warning");
    let writer = tokio::task::spawn_blocking(move || {
        write_capability_warning(&mut writer, &warning).expect("write first warning");
        write_capability_warning(&mut writer, &warning).expect("write duplicate warning");
    });
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register warning reader");

    let error = read_start_result(&mut reader)
        .await
        .expect_err("duplicate warning must fail closed");
    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert!(error.message.contains("duplicate warning for CAP_BPF"));
    writer.await.expect("warning writer");
}

#[tokio::test(flavor = "current_thread")]
async fn rejection_reader_rejects_an_unbounded_frame() {
    use std::io::Write;

    let (mut writer, reader) = StdUnixStream::pair().expect("create control socket pair");
    reader
        .set_nonblocking(true)
        .expect("make control reader nonblocking");
    let writer = tokio::task::spawn_blocking(move || {
        writer.write_all(&[super::REJECTED_BYTE]).expect("kind");
        writer
            .write_all(&u32::MAX.to_be_bytes())
            .expect("oversized length");
    });
    let mut reader = tokio::net::UnixStream::from_std(reader).expect("register control reader");

    let error = read_outcome(&mut reader)
        .await
        .expect_err("oversized rejection must fail");
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    writer.await.expect("control writer task");
}
