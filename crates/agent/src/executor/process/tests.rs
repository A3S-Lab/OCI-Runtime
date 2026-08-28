use std::io::Write;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus as ProcessExitStatus;

use tokio::io::AsyncReadExt;

use super::{append_cleanup_error, bind_control_listener, convert_exit_status, process_error};
use crate::executor::control::READY_BYTE;

#[tokio::test(flavor = "current_thread")]
async fn abstract_control_listener_reports_the_kernel_peer_pid() {
    let (listener, name) = bind_control_listener().expect("bind abstract control listener");
    tokio::task::spawn_blocking(move || {
        let address = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract address");
        let mut stream = UnixStream::connect_addr(&address).expect("connect control socket");
        stream.write_all(&[READY_BYTE]).expect("write ready byte");
    })
    .await
    .expect("control client task");

    let (mut stream, _) = listener.accept().await.expect("accept control client");
    assert_eq!(
        stream.peer_cred().expect("read peer credentials").pid(),
        i32::try_from(std::process::id()).ok()
    );
    let mut ready = [0_u8; 1];
    stream
        .read_exact(&mut ready)
        .await
        .expect("read ready byte");
    assert_eq!(ready[0], READY_BYTE);
}

#[test]
fn converts_normal_and_signal_process_results() {
    assert_eq!(
        convert_exit_status(ProcessExitStatus::from_raw(42 << 8)).expect("normal result"),
        a3s_oci_sdk::ExitStatus::exited(42).expect("normal SDK result")
    );
    assert_eq!(
        convert_exit_status(ProcessExitStatus::from_raw(libc::SIGKILL)).expect("signal result"),
        a3s_oci_sdk::ExitStatus::signaled(libc::SIGKILL, false).expect("signal SDK result")
    );
}

#[test]
fn failed_create_cleanup_is_returned_without_hiding_the_primary_rejection() {
    let mut primary = process_error(
        a3s_oci_sdk::ErrorCode::PermissionDenied,
        "hostile create rejected",
    );
    let cleanup = a3s_oci_sdk::Error::new(
        a3s_oci_sdk::ErrorCode::Internal,
        "cgroup remained populated",
    )
    .for_operation("configure-container-cgroup")
    .retryable(true);

    append_cleanup_error(&mut primary, "remove the container cgroup", &cleanup);

    assert_eq!(primary.code, a3s_oci_sdk::ErrorCode::PermissionDenied);
    assert_eq!(primary.operation.as_deref(), Some("run-container-init"));
    assert!(primary.message.contains("hostile create rejected"));
    assert!(primary.message.contains("cgroup remained populated"));
    assert!(primary.retryable);
}
