use std::process::Command;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::fs::{self, OpenOptions};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::io::Write;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::os::unix::fs::symlink;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use std::os::unix::process::CommandExt;

#[test]
fn context_smoke_emits_consistent_versioned_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"))
        .arg("context-smoke")
        .output()
        .expect("context smoke command must start");

    let report: a3s_oci_krun::KrunContextSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(report.schema_version, "a3s.oci.krun-context-smoke.v2");
    assert_eq!(output.status.success(), report.is_success());

    if cfg!(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )) {
        assert!(
            output.status.success(),
            "supported context smoke failed: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(report.runtime_bundle_loaded);
        assert!(report.context_created);
        assert!(report.vm_configured);
        assert!(report.agent_vsock_configured);
        assert!(report.context_released);
    } else {
        assert_eq!(output.status.code(), Some(2));
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn linux_context_smoke_rejects_a_tampered_adjacent_runtime() {
    let (directory, shim, runtime) = copied_linux_context_fixture();
    let mut libkrun = OpenOptions::new()
        .append(true)
        .open(runtime.join("libkrun.so.1.17.0"))
        .expect("open copied libkrun");
    libkrun.write_all(&[0]).expect("tamper copied libkrun");
    drop(libkrun);

    let report = failed_linux_context_smoke(&shim);
    assert!(report
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("size mismatch")));
    drop(directory);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn linux_context_smoke_rejects_an_adjacent_runtime_symlink() {
    let source_shim = PathBuf::from(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"));
    let source_runtime = source_shim
        .parent()
        .expect("shim executable directory")
        .join("a3s-oci-krun-runtime");
    let directory = tempfile::tempdir().expect("temporary shim directory");
    let shim = directory.path().join("a3s-oci-krun-shim");
    fs::copy(&source_shim, &shim).expect("copy context-smoke shim");
    symlink(
        &source_runtime,
        directory.path().join("a3s-oci-krun-runtime"),
    )
    .expect("create adjacent runtime symlink");

    let report = failed_linux_context_smoke(&shim);
    assert!(report
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("runtime path must be a real directory")));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn copied_linux_context_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let source_shim = PathBuf::from(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"));
    let source_runtime = source_shim
        .parent()
        .expect("shim executable directory")
        .join("a3s-oci-krun-runtime");
    let directory = tempfile::tempdir().expect("temporary shim directory");
    let shim = directory.path().join("a3s-oci-krun-shim");
    fs::copy(&source_shim, &shim).expect("copy context-smoke shim");
    let runtime = directory.path().join("a3s-oci-krun-runtime");
    fs::create_dir(&runtime).expect("create copied runtime directory");
    for name in ["libkrun.so.1.17.0", "libkrunfw.so.5"] {
        fs::copy(source_runtime.join(name), runtime.join(name))
            .expect("copy context-smoke runtime asset");
    }
    (directory, shim, runtime)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn failed_linux_context_smoke(shim: &Path) -> a3s_oci_krun::KrunContextSmokeReport {
    let output = Command::new(shim)
        .arg("context-smoke")
        .output()
        .expect("context smoke command must start");
    assert_eq!(output.status.code(), Some(2));
    let report: a3s_oci_krun::KrunContextSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert!(!report.is_success());
    assert!(!report.runtime_bundle_loaded);
    assert!(!report.context_created);
    report
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn linux_system_image_context_smoke_rejects_a_missing_manifest_before_context_creation() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time must follow the Unix epoch")
        .as_nanos();
    let missing_manifest = std::env::temp_dir().join(format!(
        "a3s-oci-missing-linux-system-image-{}-{nonce}.json",
        std::process::id(),
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"))
        .arg("system-image-context-smoke")
        .arg("--system-image-manifest")
        .arg(&missing_manifest)
        .output()
        .expect("system-image context smoke command must start");

    assert_eq!(output.status.code(), Some(2));
    let report: a3s_oci_krun::KrunSystemImageContextSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(
        report.schema_version,
        "a3s.oci.krun-system-image-context-smoke.v1"
    );
    assert!(!report.is_success());
    assert!(report.runtime_bundle_loaded);
    assert!(!report.system_image_verified);
    assert!(!report.context_created);
    assert!(report
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("system-image manifest")));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn vm_smoke_rejects_a_missing_system_image_before_starting_a_worker() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time must follow the Unix epoch")
        .as_nanos();
    let missing_rootfs = std::env::temp_dir().join(format!(
        "a3s-oci-missing-vm-rootfs-{}-{nonce}",
        std::process::id(),
    ));
    let missing_manifest = std::env::temp_dir().join(format!(
        "a3s-oci-missing-system-image-{}-{nonce}.json",
        std::process::id(),
    ));
    let runtime_share = tempfile::tempdir().expect("runtime share");
    std::fs::set_permissions(runtime_share.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private runtime share mode");
    let runtime_state = runtime_share.path().join("run");
    std::fs::create_dir(&runtime_state).expect("runtime state directory");
    std::fs::set_permissions(&runtime_state, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime state mode");
    let console = std::env::temp_dir().join(format!(
        "a3s-oci-missing-vm-console-{}-{nonce}.log",
        std::process::id(),
    ));

    let output = Command::new(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"))
        .args(["vm-smoke", "--rootfs"])
        .arg(&missing_rootfs)
        .arg("--system-image-manifest")
        .arg(&missing_manifest)
        .arg("--runtime-share")
        .arg(runtime_share.path())
        .arg("--console")
        .arg(&console)
        .output()
        .expect("VM smoke command must start");

    let report: a3s_oci_krun::KrunVmSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report.schema_version, "a3s.oci.krun-vm-smoke.v2");
    assert!(!report.is_success());
    assert!(report.runtime_bundle_loaded);
    assert!(!report.context_created);
    assert!(!report.vm_entered);
    assert!(!report.marker_verified);
    assert!(!console.exists());
    assert!(report
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("system-image manifest")));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn agent_vm_smoke_rejects_a_missing_system_image_before_starting_a_worker() {
    use a3s_oci_agent_protocol::{SessionToken, AGENT_SESSION_TOKEN_ENV};
    use std::os::unix::net::UnixListener;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time must follow the Unix epoch")
        .as_nanos();
    let missing_rootfs = std::env::temp_dir().join(format!(
        "a3s-oci-missing-agent-rootfs-{}-{nonce}",
        std::process::id(),
    ));
    let missing_manifest = std::env::temp_dir().join(format!(
        "a3s-oci-missing-agent-system-image-{}-{nonce}.json",
        std::process::id(),
    ));
    let runtime_share = tempfile::tempdir().expect("runtime share");
    std::fs::set_permissions(runtime_share.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private runtime share mode");
    let runtime_state = runtime_share.path().join("run");
    std::fs::create_dir(&runtime_state).expect("runtime state directory");
    std::fs::set_permissions(&runtime_state, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime state mode");
    let console = std::env::temp_dir().join(format!(
        "a3s-oci-missing-agent-console-{}-{nonce}.log",
        std::process::id(),
    ));
    let pipe_name = format!("a3s-oci-agent-missing-image-{}-{nonce}", std::process::id());
    let socket_directory = std::path::Path::new("/private/tmp").join(&pipe_name);
    std::fs::create_dir(&socket_directory).expect("private socket directory");
    std::fs::set_permissions(&socket_directory, std::fs::Permissions::from_mode(0o700))
        .expect("private socket directory mode");
    let missing_socket = socket_directory.join("agent.sock");
    let listener = UnixListener::bind(&missing_socket).expect("private Unix socket");
    std::fs::set_permissions(&missing_socket, std::fs::Permissions::from_mode(0o600))
        .expect("private socket mode");
    let token = SessionToken::generate().expect("operating-system random source");
    let encoded = token.expose_hex();

    let mut command = Command::new(env!("CARGO_BIN_EXE_a3s-oci-krun-shim"));
    command
        .process_group(0)
        .args(["agent-vm-smoke", "--rootfs"])
        .arg(&missing_rootfs)
        .arg("--system-image-manifest")
        .arg(&missing_manifest)
        .arg("--runtime-share")
        .arg(runtime_share.path())
        .arg("--console")
        .arg(&console)
        .arg("--pipe-name")
        .arg(&pipe_name)
        .arg("--socket-path")
        .arg(&missing_socket)
        .arg("--owner-pid")
        .arg(std::process::id().to_string())
        .env(AGENT_SESSION_TOKEN_ENV, encoded.as_str());
    let output = command.output().expect("agent VM smoke command must start");
    drop(listener);
    std::fs::remove_file(&missing_socket).expect("remove private Unix socket");
    std::fs::remove_dir(&socket_directory).expect("remove private socket directory");

    let report: a3s_oci_krun::KrunAgentVmSmokeReport =
        serde_json::from_slice(&output.stdout).expect("smoke output must be valid JSON");
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(report.schema_version, "a3s.oci.krun-agent-vm-smoke.v7");
    assert!(!report.is_success());
    assert!(report.runtime_bundle_loaded);
    assert!(!report.context_created);
    assert!(!report.vm_entered);
    assert!(!report.agent_binary_present);
    assert!(!console.exists());
    assert!(report
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("system-image manifest")));
}
