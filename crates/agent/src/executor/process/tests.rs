use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus as ProcessExitStatus;

use a3s_oci_sdk::{IoMode, ProcessIo};
use tokio::io::AsyncReadExt;

use super::launch::{
    prepare_supervised_stdio, supervised_create_unsupported_reason, validate_rootless_device_mounts,
};
use super::{append_cleanup_error, bind_control_listener, convert_exit_status, process_error};
use crate::executor::control::READY_BYTE;
use crate::OCI_LINUX_DEFAULT_DEVICE_NODES;

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

#[test]
fn supervised_create_allows_box_control_and_keeps_other_gates() {
    use a3s_oci_agent_protocol::AgentInheritedDescriptorSchema;

    let pipe_io = ProcessIo {
        stdin: IoMode::Pipe,
        stdout: IoMode::Capture,
        stderr: IoMode::Capture,
        terminal_size: None,
    };
    assert!(
        supervised_create_unsupported_reason(false, None, &pipe_io).is_none(),
        "pipe/capture I/O with rootless device mounts must not be gated Unsupported"
    );
    assert!(
        supervised_create_unsupported_reason(
            false,
            Some(&AgentInheritedDescriptorSchema::a3s_box_control_v1()),
            &pipe_io
        )
        .is_none(),
        "a3s_box_control_v1 must be allowed on supervised create"
    );

    let box_live_io = ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Inherit,
        stderr: IoMode::Inherit,
        terminal_size: None,
    };
    assert!(
        supervised_create_unsupported_reason(
            false,
            Some(&AgentInheritedDescriptorSchema::a3s_box_control_v1()),
            &box_live_io
        )
        .is_none(),
        "Box Live Null+Inherit+Inherit with a3s_box_control_v1 must pass the supervised create gate"
    );

    let terminal_io = ProcessIo {
        stdin: IoMode::Terminal,
        stdout: IoMode::Terminal,
        stderr: IoMode::Terminal,
        terminal_size: None,
    };
    assert!(
        supervised_create_unsupported_reason(false, None, &terminal_io)
            .expect("terminal remains unsupported")
            .contains("terminal")
    );
    assert!(supervised_create_unsupported_reason(true, None, &pipe_io)
        .expect("pinned bundle remains unsupported")
        .contains("utility-VM"));

    let mut unknown = AgentInheritedDescriptorSchema::a3s_box_control_v1();
    unknown.profile = "unknown-inherited-schema".into();
    assert!(
        supervised_create_unsupported_reason(false, Some(&unknown), &pipe_io)
            .expect("unknown inherited schemas remain unsupported")
            .contains("inherited workload")
    );

    // Empty and nonempty prepared mounts remain subject only to count validation.
    validate_rootless_device_mounts(&[], false, false).expect("privileged empty mounts");
    let mounts = (0..OCI_LINUX_DEFAULT_DEVICE_NODES.len())
        .map(|_| OwnedFd::from(std::fs::File::open("/dev/null").expect("fixture")))
        .collect::<Vec<_>>();
    validate_rootless_device_mounts(&mounts, true, true).expect("rootless nonempty mounts");
    validate_rootless_device_mounts(&[], true, true).expect_err("missing mounts must fail closed");
}

#[test]
fn prepare_supervised_stdio_dups_host_fds_for_inherit() {
    let io = ProcessIo {
        stdin: IoMode::Null,
        stdout: IoMode::Inherit,
        stderr: IoMode::Inherit,
        terminal_size: None,
    };
    let (host, child) = prepare_supervised_stdio(&io).expect("inherit prepare");
    assert!(host.stdin.is_none());
    assert!(host.stdout.is_none());
    assert!(host.stderr.is_none());
    assert!(child.stdin.is_none());
    assert!(
        child.stdout.is_some(),
        "Inherit stdout must supply a child install FD"
    );
    assert!(
        child.stderr.is_some(),
        "Inherit stderr must supply a child install FD"
    );
}
