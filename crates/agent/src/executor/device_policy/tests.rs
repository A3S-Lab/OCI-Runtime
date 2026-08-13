use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use a3s_oci_sdk::ErrorCode;

use super::{
    apply_request, read_message, validate_hello, validate_key, validate_relative_cgroup,
    write_message, DevicePolicyAuthority, DevicePolicyRequest, DevicePolicyResponse,
    DEVICE_POLICY_SCHEMA_VERSION, MAX_DEVICE_POLICY_MESSAGE_BYTES,
};

#[test]
fn helper_rejects_absolute_parent_and_non_normal_cgroup_paths() {
    for path in ["/manager/leaf", "../leaf", "manager/../leaf", ".", ""] {
        assert!(
            validate_relative_cgroup(Path::new(path)).is_err(),
            "accepted {path:?}"
        );
    }
    assert_eq!(
        validate_relative_cgroup(Path::new("manager/workload")).expect("bounded path"),
        Path::new("manager/workload")
    );
}

#[test]
fn helper_policy_keys_are_bounded_and_control_free() {
    assert_eq!(
        validate_key("container:1").expect("valid key"),
        "container:1"
    );
    assert!(validate_key("").is_err());
    assert!(validate_key("container\n1").is_err());
    assert!(validate_key(&"x".repeat(513)).is_err());
}

#[test]
fn helper_rejects_replayed_hello_and_unknown_policy_without_mutation() {
    let (root, mut peer) = UnixStream::pair().expect("helper channel");
    let authority = DevicePolicyAuthority::from_transport(root);
    let helper = std::thread::spawn(move || {
        for _ in 0..2 {
            let request = read_message(&mut peer).expect("read helper request");
            let response = match apply_request(
                &invalid_descriptor(),
                &mut std::collections::BTreeMap::new(),
                request,
            ) {
                Ok(()) => DevicePolicyResponse::Applied,
                Err(error) => DevicePolicyResponse::Rejected(error),
            };
            write_message(&mut peer, &response).expect("write helper response");
        }
    });

    let error = authority
        .helper_request(DevicePolicyRequest::Hello {
            schema_version: "forged".to_string(),
            expected_helper_pid: 1,
        })
        .expect_err("replayed hello must fail");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    let error = authority
        .remove("missing")
        .expect_err("unknown remove must fail");
    assert_eq!(error.code, ErrorCode::NotFound);
    helper.join().expect("helper thread");
}

#[test]
fn helper_authenticates_schema_and_exact_receiving_pid() {
    let pid = i32::try_from(std::process::id()).expect("process ID fits pid_t");
    validate_hello(
        DevicePolicyRequest::Hello {
            schema_version: DEVICE_POLICY_SCHEMA_VERSION.to_string(),
            expected_helper_pid: pid,
        },
        pid,
    )
    .expect("exact hello");

    for request in [
        DevicePolicyRequest::Hello {
            schema_version: "forged".to_string(),
            expected_helper_pid: pid,
        },
        DevicePolicyRequest::Hello {
            schema_version: DEVICE_POLICY_SCHEMA_VERSION.to_string(),
            expected_helper_pid: pid.saturating_add(1),
        },
        DevicePolicyRequest::Remove {
            key: "not-a-hello".to_string(),
        },
    ] {
        assert!(validate_hello(request, pid).is_err());
    }
}

#[test]
fn authority_fails_closed_after_helper_channel_eof() {
    let (root, peer) = UnixStream::pair().expect("helper channel");
    let authority = DevicePolicyAuthority::from_transport(root);
    drop(peer);

    let first = authority
        .remove("policy")
        .expect_err("closed helper channel must fail");
    assert_eq!(first.code, ErrorCode::Unavailable);
    assert!(first.retryable);
    let second = authority
        .remove("policy")
        .expect_err("unavailable authority must remain unavailable");
    assert_eq!(second.code, ErrorCode::Unavailable);
    assert!(second.retryable);
}

#[test]
fn authority_rejects_a_forged_response_and_stays_unavailable() {
    let (root, mut peer) = UnixStream::pair().expect("helper channel");
    let authority = DevicePolicyAuthority::from_transport(root);
    let helper = std::thread::spawn(move || {
        let _: DevicePolicyRequest = read_message(&mut peer).expect("read request");
        let forged = br#"{"outcome":"applied","extra":true}"#;
        peer.write_all(&(forged.len() as u32).to_be_bytes())
            .and_then(|()| peer.write_all(forged))
            .expect("write forged response");
    });

    let error = authority
        .remove("policy")
        .expect_err("forged response must fail closed");
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.retryable);
    let repeated = authority
        .remove("policy")
        .expect_err("authority must not reuse a corrupted channel");
    assert_eq!(repeated.code, ErrorCode::Unavailable);
    helper.join().expect("helper thread");
}

#[test]
fn normal_shutdown_is_explicit_and_idempotent() {
    let (root, mut peer) = UnixStream::pair().expect("helper channel");
    let authority = DevicePolicyAuthority::from_transport(root);
    let helper = std::thread::spawn(move || {
        let request: DevicePolicyRequest = read_message(&mut peer).expect("read shutdown");
        assert!(matches!(request, DevicePolicyRequest::Shutdown));
        write_message(&mut peer, &DevicePolicyResponse::Applied).expect("acknowledge shutdown");
    });

    authority.shutdown().expect("normal shutdown");
    authority.shutdown().expect("repeated shutdown");
    let error = authority
        .remove("policy")
        .expect_err("shutdown authority must be unavailable");
    assert_eq!(error.code, ErrorCode::Unavailable);
    helper.join().expect("helper thread");
}

#[test]
fn message_framing_rejects_empty_oversized_and_invalid_payloads() {
    for length in [0_u32, (MAX_DEVICE_POLICY_MESSAGE_BYTES as u32) + 1] {
        let (mut reader, mut writer) = UnixStream::pair().expect("helper channel");
        writer
            .write_all(&length.to_be_bytes())
            .expect("write invalid length");
        let error = read_message::<DevicePolicyRequest>(&mut reader)
            .expect_err("invalid message length must fail");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
    }

    let (mut reader, mut writer) = UnixStream::pair().expect("helper channel");
    writer
        .write_all(&1_u32.to_be_bytes())
        .expect("write length");
    writer.write_all(b"{").expect("write invalid JSON");
    let error =
        read_message::<DevicePolicyRequest>(&mut reader).expect_err("invalid payload must fail");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

#[test]
fn helper_rejects_traversal_before_opening_delegated_descriptor() {
    let error = apply_request(
        &invalid_descriptor(),
        &mut std::collections::BTreeMap::new(),
        DevicePolicyRequest::Install {
            key: "escape".to_string(),
            relative_cgroup: "../outside".into(),
            plan: Default::default(),
        },
    )
    .expect_err("traversal must fail");
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

fn invalid_descriptor() -> OwnedFd {
    std::fs::File::open("/")
        .expect("open stable invalid cgroup descriptor")
        .into()
}
