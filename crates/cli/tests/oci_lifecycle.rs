#![cfg(any(unix, windows))]

#[path = "support/oci_lifecycle.rs"]
mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use a3s_oci_sdk::oci_spec::runtime::{ContainerState, State};
use serde_json::json;

use support::{LifecycleService, TestServer};

const CONTAINER_ID: &str = "short-process-lifecycle";

#[tokio::test]
async fn short_process_cli_uses_real_local_ipc_and_reuses_container_id() {
    let temporary = tempfile::tempdir().expect("temporary lifecycle directory");
    let canonical_root = fs::canonicalize(temporary.path()).expect("canonical temporary root");
    let state_root = canonical_root.join("state");
    create_private_directory(&state_root);
    let bundle = write_bundle(canonical_root.join("bundle"));
    let pid_file = canonical_root.join("container.pid");
    let service = Arc::new(LifecycleService::default());
    let server = TestServer::start(&canonical_root, Arc::clone(&service));

    assert_success(
        "create",
        &invoke_create(&server, &state_root, &bundle, &pid_file).await,
    );
    assert_eq!(fs::read_to_string(&pid_file).expect("created PID"), "4201");

    assert_state(
        "created state",
        invoke(&server, &state_root, ["state", CONTAINER_ID]).await,
        ContainerState::Created,
        Some(4_201),
    );
    assert_success(
        "start",
        &invoke(&server, &state_root, ["start", CONTAINER_ID]).await,
    );
    assert_state(
        "running state",
        invoke(&server, &state_root, ["state", CONTAINER_ID]).await,
        ContainerState::Running,
        Some(4_201),
    );
    assert_success(
        "kill",
        &invoke(
            &server,
            &state_root,
            ["kill", CONTAINER_ID, "TERM", "--all"],
        )
        .await,
    );
    assert_state(
        "stopped state",
        invoke(&server, &state_root, ["state", CONTAINER_ID]).await,
        ContainerState::Stopped,
        None,
    );
    assert_success(
        "delete",
        &invoke(&server, &state_root, ["delete", CONTAINER_ID]).await,
    );

    let missing = invoke(&server, &state_root, ["state", CONTAINER_ID]).await;
    assert!(
        !missing.status.success(),
        "state after delete unexpectedly succeeded"
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("does not exist"),
        "unexpected state-after-delete error: {}",
        String::from_utf8_lossy(&missing.stderr)
    );

    assert_success(
        "recreate",
        &invoke_create(&server, &state_root, &bundle, &pid_file).await,
    );
    assert_eq!(fs::read_to_string(&pid_file).expect("reused PID"), "4202");
    assert_success(
        "force delete",
        &invoke(&server, &state_root, ["delete", "--force", CONTAINER_ID]).await,
    );

    server.finish().await;
    service.assert_complete_lifecycle();
}

async fn invoke_create(
    server: &TestServer,
    state_root: &Path,
    bundle: &Path,
    pid_file: &Path,
) -> Output {
    let mut command = configured_command(server, state_root);
    command
        .arg("create")
        .arg("--bundle")
        .arg(bundle)
        .arg("--pid-file")
        .arg(pid_file)
        .arg(CONTAINER_ID);
    run_command(command).await
}

async fn invoke<const N: usize>(
    server: &TestServer,
    state_root: &Path,
    arguments: [&str; N],
) -> Output {
    let mut command = configured_command(server, state_root);
    command.args(arguments);
    run_command(command).await
}

async fn run_command(mut command: Command) -> Output {
    tokio::task::spawn_blocking(move || command.output())
        .await
        .expect("a3s-oci task must join")
        .expect("start a3s-oci")
}

fn configured_command(server: &TestServer, state_root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_a3s-oci"));
    command
        .env("A3S_OCI_RUNTIME_ENDPOINT", server.endpoint())
        .env("A3S_OCI_CLI_STATE_ROOT", state_root)
        .env("A3S_OCI_CLI_ISOLATION", "shared-host-kernel")
        .env("LISTEN_FDS", "0")
        .env_remove("A3S_OCI_RUNTIME_SOCKET")
        .env_remove("A3S_OCI_CLI_TRUST_DOMAIN");
    command
}

fn assert_success(operation: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_state(
    operation: &str,
    output: Output,
    expected_status: ContainerState,
    expected_pid: Option<i32>,
) {
    assert_success(operation, &output);
    let state: State = serde_json::from_slice(&output.stdout).expect("decode OCI state output");
    assert_eq!(*state.status(), expected_status);
    assert_eq!(*state.pid(), expected_pid);
    assert_eq!(state.id(), CONTAINER_ID);
}

fn write_bundle(path: PathBuf) -> PathBuf {
    fs::create_dir(&path).expect("bundle directory");
    fs::create_dir(path.join("rootfs")).expect("bundle rootfs");
    fs::write(
        path.join("config.json"),
        serde_json::to_vec_pretty(&json!({
            "ociVersion": "1.3.0",
            "root": { "path": "rootfs", "readonly": false },
            "process": {
                "terminal": false,
                "user": { "uid": 0, "gid": 0 },
                "args": ["/bin/true"],
                "env": ["PATH=/bin"],
                "cwd": "/"
            },
            "linux": { "namespaces": [] }
        }))
        .expect("encode OCI configuration"),
    )
    .expect("write OCI configuration");
    path
}

#[cfg(unix)]
fn create_private_directory(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir(path).expect("private state directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("private state permissions");
}

#[cfg(windows)]
fn create_private_directory(path: &Path) {
    a3s_oci_runtime::windows_security::create_private_directory(path)
        .expect("private Windows state directory");
}
