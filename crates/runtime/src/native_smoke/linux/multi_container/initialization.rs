use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, Error, ExitStatus, ListRequest, OciBundle,
    RuntimeClient, StartRequest,
};
use serde_json::{json, Map, Value};
use tokio::time::timeout;

use super::super::QUALIFICATION_CALL_TIMEOUT as CALL_TIMEOUT;
use super::lifecycle::{
    container_id, create_request, native_call, operation, require, require_created,
    state_is_missing, wait_request, wait_until_stopped,
};
use crate::NativeLinuxMultiContainerSmokeReport;

const EXTERNAL_SCRIPT_EVIDENCE: &[u8] = b"a3s-oci-external-init-v1\n";
const INLINE_EVIDENCE: &[u8] = b"a3s-oci-inline-init-v1\n";
const HOOK_DESCENDANT_STARTED: &str = "hook-timeout-descendant-started";
const HOOK_DESCENDANT_ESCAPED: &str = "hook-timeout-descendant-escaped";
const HOOK_DESCENDANT_OBSERVATION: Duration = Duration::from_secs(3);

pub(super) struct InitializationFixture {
    inline: OciBundle,
    external_script: OciBundle,
    direct_argv: OciBundle,
    nonzero_exit: OciBundle,
    prestart_failure: OciBundle,
    create_runtime_failure: OciBundle,
    create_container_failure: OciBundle,
    start_container_failure: OciBundle,
    poststart_failure: OciBundle,
    hook_timeout: OciBundle,
    poststop_failure: OciBundle,
    evidence_directory: PathBuf,
    rootfs_target: PathBuf,
    script_path: PathBuf,
}

impl InitializationFixture {
    pub(super) async fn prepare(
        base: &OciBundle,
        rootfs: &Path,
        source_parent: &Path,
        nonce: &str,
    ) -> Result<Self, String> {
        // This bind source is consumed after the executor enters the mapped
        // user namespace, so it must remain outside the private runtime state.
        let evidence_directory = source_parent.join(format!("init-evidence-{nonce}"));
        tokio::fs::create_dir(&evidence_directory)
            .await
            .map_err(|error| {
                format!(
                    "failed to create init evidence directory {}: {error}",
                    evidence_directory.display()
                )
            })?;
        tokio::fs::set_permissions(&evidence_directory, std::fs::Permissions::from_mode(0o777))
            .await
            .map_err(|error| {
                format!(
                    "failed to make init evidence directory writable {}: {error}",
                    evidence_directory.display()
                )
            })?;

        let target_name = format!(".a3s-oci-init-{nonce}");
        let target = format!("/{target_name}");
        let script_name = format!("a3s-oci-init-{nonce}");
        let script_path = rootfs.join("bin").join(&script_name);
        let script = format!(
            "#!/bin/sh\nset -eu\ntest \"$PWD\" = \"{target}\"\n\
             test \"${{A3S_INIT_PROFILE:-}}\" = external\n\
             test \"$(/bin/busybox id -u)\" = 0\n\
             test \"$(/bin/busybox id -g)\" = 0\n\
             test \"$(umask)\" = 0022\n\
             case \" $(/bin/busybox id -G) \" in *\" 1 \"*) ;; *) exit 1 ;; esac\n\
             printf 'a3s-oci-external-init-v1\\n' > {target}/evidence/external\n"
        );
        tokio::fs::write(&script_path, script)
            .await
            .map_err(|error| {
                format!(
                    "failed to write external init script {}: {error}",
                    script_path.display()
                )
            })?;
        tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .await
            .map_err(|error| {
                format!(
                    "failed to make external init script executable {}: {error}",
                    script_path.display()
                )
            })?;

        let mount = EvidenceMount {
            source: &evidence_directory,
            target: &target,
        };
        let inline = build_profile(
            base,
            mount,
            json!([
                "/bin/sh",
                "-c",
                format!(
                    "set -eu; printf 'a3s-oci-inline-init-v1\\n' > \
                     {target}/evidence/inline"
                )
            ]),
            json!(["PATH=/bin"]),
            None,
            &format!("a3s-oci-init-inline-{nonce}"),
        )?;
        let external_script = build_profile(
            base,
            mount,
            json!([format!("/bin/{script_name}")]),
            json!(["PATH=/bin", "A3S_INIT_PROFILE=external"]),
            None,
            &format!("a3s-oci-init-script-{nonce}"),
        )?;
        let external_script = with_exact_process_profile(&external_script, &target)?;
        let direct_argv = build_profile(
            base,
            mount,
            json!(["/bin/busybox", "touch", format!("{target}/evidence/direct")]),
            json!(["PATH=/bin"]),
            None,
            &format!("a3s-oci-init-direct-{nonce}"),
        )?;
        let nonzero_exit = build_profile(
            base,
            mount,
            json!(["/bin/busybox", "sh", "-c", "exit 42"]),
            json!(["PATH=/bin"]),
            None,
            &format!("a3s-oci-init-nonzero-{nonce}"),
        )?;
        let prestart_failure = build_profile(
            base,
            mount,
            sleeping_init(),
            json!(["PATH=/bin"]),
            Some(hooks("prestart", "exit 11", 2)),
            &format!("a3s-oci-hook-prestart-{nonce}"),
        )?;
        let create_runtime_failure = build_profile(
            base,
            mount,
            sleeping_init(),
            json!(["PATH=/bin"]),
            Some(hooks("createRuntime", "exit 13", 2)),
            &format!("a3s-oci-hook-create-runtime-{nonce}"),
        )?;
        let create_container_failure = build_profile(
            base,
            mount,
            sleeping_init(),
            json!(["PATH=/bin"]),
            Some(hooks("createContainer", "exit 17", 2)),
            &format!("a3s-oci-hook-create-container-{nonce}"),
        )?;
        let start_container_failure = build_profile(
            base,
            mount,
            sleeping_init(),
            json!(["PATH=/bin"]),
            Some(hooks("startContainer", "exit 19", 2)),
            &format!("a3s-oci-hook-start-container-{nonce}"),
        )?;
        let poststart_failure = build_profile(
            base,
            mount,
            sleeping_init(),
            json!(["PATH=/bin"]),
            Some(hooks("poststart", "exit 21", 2)),
            &format!("a3s-oci-hook-poststart-{nonce}"),
        )?;
        let hook_timeout = build_profile(
            base,
            mount,
            sleeping_init(),
            json!(["PATH=/bin"]),
            Some(timeout_hooks(&evidence_directory)?),
            &format!("a3s-oci-hook-timeout-{nonce}"),
        )?;
        let poststop_failure = build_profile(
            base,
            mount,
            json!(["/bin/busybox", "true"]),
            json!(["PATH=/bin"]),
            Some(hooks("poststop", "exit 23", 2)),
            &format!("a3s-oci-hook-poststop-{nonce}"),
        )?;

        Ok(Self {
            inline,
            external_script,
            direct_argv,
            nonzero_exit,
            prestart_failure,
            create_runtime_failure,
            create_container_failure,
            start_container_failure,
            poststart_failure,
            hook_timeout,
            poststop_failure,
            evidence_directory,
            rootfs_target: rootfs.join(target_name),
            script_path,
        })
    }

    pub(super) async fn cleanup(&self) -> Result<bool, String> {
        remove_file(&self.script_path, "external init script").await?;
        remove_tree(&self.rootfs_target, "init-profile rootfs target").await?;
        remove_tree(&self.evidence_directory, "init evidence directory").await?;
        Ok(!self.script_path.exists()
            && !self.rootfs_target.exists()
            && !self.evidence_directory.exists())
    }
}

pub(super) async fn exercise(
    client: &RuntimeClient,
    fixture: &InitializationFixture,
    nonce: &str,
    report: &mut NativeLinuxMultiContainerSmokeReport,
) -> Result<(), String> {
    let inline_target = run_expected_exit(client, &fixture.inline, nonce, "init-inline", 0).await?;
    report.initialization.inline_shell_verified =
        read_exact(&fixture.evidence_directory.join("inline"), INLINE_EVIDENCE).await?;

    let script_target =
        run_expected_exit(client, &fixture.external_script, nonce, "init-script", 0).await?;
    report.initialization.executable_script_verified = read_exact(
        &fixture.evidence_directory.join("external"),
        EXTERNAL_SCRIPT_EVIDENCE,
    )
    .await?;

    let direct_target =
        run_expected_exit(client, &fixture.direct_argv, nonce, "init-direct", 0).await?;
    report.initialization.direct_argv_verified =
        fixture.evidence_directory.join("direct").is_file();
    require(
        report.initialization.direct_argv_verified,
        "direct argv init did not emit its exact evidence file",
    )?;

    let nonzero_target =
        run_expected_exit(client, &fixture.nonzero_exit, nonce, "init-nonzero", 42).await?;
    report.initialization.nonzero_exit_verified = true;

    let prestart_failure_target = run_create_failure(
        client,
        &fixture.prestart_failure,
        nonce,
        "hook-prestart-failure",
        "prestart hook",
    )
    .await?;
    report.initialization.prestart_failure_rolled_back = state_is_missing(
        client,
        &prestart_failure_target,
        "prestart-hook failure after rollback",
    )
    .await?;

    let create_runtime_failure_target = run_create_failure(
        client,
        &fixture.create_runtime_failure,
        nonce,
        "hook-create-runtime-failure",
        "createRuntime hook",
    )
    .await?;
    report.initialization.create_runtime_failure_rolled_back = state_is_missing(
        client,
        &create_runtime_failure_target,
        "createRuntime-hook failure after rollback",
    )
    .await?;

    let create_container_failure_target = run_create_failure(
        client,
        &fixture.create_container_failure,
        nonce,
        "hook-create-container-failure",
        "createContainer hook",
    )
    .await?;
    report.initialization.create_container_failure_rolled_back = state_is_missing(
        client,
        &create_container_failure_target,
        "createContainer-hook failure after rollback",
    )
    .await?;

    let timeout_target = run_create_failure(
        client,
        &fixture.hook_timeout,
        nonce,
        "hook-timeout",
        "prestart hook",
    )
    .await?;
    report.initialization.hook_timeout_rolled_back =
        state_is_missing(client, &timeout_target, "timed-out hook after rollback").await?;
    report.initialization.hook_timeout_process_group_terminated =
        verify_timeout_process_group(fixture).await?;

    let start_container_failure_target = run_start_failure(
        client,
        &fixture.start_container_failure,
        nonce,
        "hook-start-container-failure",
        "startContainer hook",
    )
    .await?;
    report.initialization.start_container_failure_rolled_back = state_is_missing(
        client,
        &start_container_failure_target,
        "startContainer-hook failure after force delete",
    )
    .await?;

    let poststart_failure_target = run_start_failure(
        client,
        &fixture.poststart_failure,
        nonce,
        "hook-poststart-failure",
        "poststart hook",
    )
    .await?;
    report.initialization.poststart_failure_rolled_back = state_is_missing(
        client,
        &poststart_failure_target,
        "poststart-hook failure after force delete",
    )
    .await?;

    let poststop_target =
        run_expected_exit(client, &fixture.poststop_failure, nonce, "hook-poststop", 0).await?;
    report.initialization.poststop_failure_warning_only = true;

    let listed = native_call(
        "list after initialization matrix",
        client.list(ListRequest::default()),
    )
    .await?;
    report.initialization.all_profiles_removed = listed.is_empty()
        && state_is_missing(client, &inline_target, "inline init after delete").await?
        && state_is_missing(client, &script_target, "script init after delete").await?
        && state_is_missing(client, &direct_target, "direct init after delete").await?
        && state_is_missing(client, &nonzero_target, "nonzero init after delete").await?
        && state_is_missing(
            client,
            &prestart_failure_target,
            "prestart hook after matrix",
        )
        .await?
        && state_is_missing(
            client,
            &create_runtime_failure_target,
            "createRuntime hook after matrix",
        )
        .await?
        && state_is_missing(
            client,
            &create_container_failure_target,
            "createContainer hook after matrix",
        )
        .await?
        && state_is_missing(client, &timeout_target, "timeout hook after matrix").await?
        && state_is_missing(
            client,
            &start_container_failure_target,
            "startContainer hook after matrix",
        )
        .await?
        && state_is_missing(
            client,
            &poststart_failure_target,
            "poststart hook after matrix",
        )
        .await?
        && state_is_missing(client, &poststop_target, "poststop hook after delete").await?;
    require(
        report.initialization.is_success(),
        "initialization and hook matrix did not produce complete evidence",
    )
}

async fn run_expected_exit(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
    label: &str,
    exit_code: i32,
) -> Result<ContainerTarget, String> {
    let id = container_id(nonce, label)?;
    let created = native_call(
        &format!("create {label}"),
        client.create(create_request(
            nonce,
            &format!("{label}-create"),
            id.clone(),
            bundle,
        )?),
    )
    .await?;
    require_created(&created, label)?;
    let target = ContainerTarget::exact(id, created.generation);
    native_call(
        &format!("start {label}"),
        client.start(StartRequest {
            context: operation(nonce, &format!("{label}-start"))?,
            target: target.clone(),
        }),
    )
    .await?;
    let status = native_call(
        &format!("wait for {label}"),
        client.wait(wait_request(target.clone())),
    )
    .await?;
    let expected = ExitStatus::exited(exit_code)
        .map_err(|error| format!("failed to construct expected {label} exit: {error}"))?;
    require(
        status == expected,
        format!("{label} returned {status:?}, expected {expected:?}"),
    )?;
    require(
        wait_until_stopped(client, &target).await?,
        format!("{label} did not stop"),
    )?;
    native_call(
        &format!("delete {label}"),
        client.delete(DeleteRequest {
            context: operation(nonce, &format!("{label}-delete"))?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    Ok(target)
}

async fn run_create_failure(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
    label: &str,
    expected_message: &str,
) -> Result<ContainerTarget, String> {
    let id = container_id(nonce, label)?;
    let request = create_request(nonce, &format!("{label}-create"), id.clone(), bundle)?;
    let error = expected_error(&format!("create {label}"), client.create(request)).await?;
    require(
        error.message.contains(expected_message),
        format!(
            "create {label} error omitted {expected_message:?}: {}",
            error.message
        ),
    )?;
    Ok(ContainerTarget::current(id))
}

async fn run_start_failure(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
    label: &str,
    expected_message: &str,
) -> Result<ContainerTarget, String> {
    let id = container_id(nonce, label)?;
    let created = native_call(
        &format!("create {label}"),
        client.create(create_request(
            nonce,
            &format!("{label}-create"),
            id.clone(),
            bundle,
        )?),
    )
    .await?;
    require_created(&created, label)?;
    let target = ContainerTarget::exact(id, created.generation);
    let error = expected_error(
        &format!("start {label}"),
        client.start(StartRequest {
            context: operation(nonce, &format!("{label}-start"))?,
            target: target.clone(),
        }),
    )
    .await?;
    require(
        error.message.contains(expected_message),
        format!(
            "start {label} error omitted {expected_message:?}: {}",
            error.message
        ),
    )?;
    native_call(
        &format!("force delete {label}"),
        client.delete(DeleteRequest {
            context: operation(nonce, &format!("{label}-delete"))?,
            target: target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    Ok(target)
}

async fn expected_error<T>(
    operation_name: &str,
    future: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<Error, String> {
    match timeout(CALL_TIMEOUT, future).await {
        Ok(Err(error)) => Ok(error),
        Ok(Ok(_)) => Err(format!("{operation_name} unexpectedly succeeded")),
        Err(_) => Err(format!("{operation_name} timed out")),
    }
}

#[derive(Clone, Copy)]
struct EvidenceMount<'a> {
    source: &'a Path,
    target: &'a str,
}

fn build_profile(
    base: &OciBundle,
    mount: EvidenceMount<'_>,
    args: Value,
    environment: Value,
    hooks: Option<Value>,
    cgroup_path: &str,
) -> Result<OciBundle, String> {
    let mut config: Value = serde_json::from_str(base.config_json())
        .map_err(|error| format!("failed to decode init profile: {error}"))?;
    let root = object_mut(&mut config, "config")?;
    let mounts = root
        .entry("mounts")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| "init profile mounts must be an array".to_string())?;
    mounts.push(json!({
        "destination": format!("{}/evidence", mount.target),
        "type": "none",
        "source": mount.source,
        "options": ["rbind", "rw", "nosuid", "nodev"]
    }));
    let process = root
        .get_mut("process")
        .ok_or_else(|| "init profile process is required".to_string())?;
    let process = object_mut(process, "process")?;
    process.insert("args".to_string(), args);
    process.insert("env".to_string(), environment);
    match hooks {
        Some(hooks) => {
            root.insert("hooks".to_string(), hooks);
        }
        None => {
            root.remove("hooks");
        }
    }
    let linux = root
        .get_mut("linux")
        .ok_or_else(|| "init profile linux config is required".to_string())?;
    object_mut(linux, "linux")?.insert(
        "cgroupsPath".to_string(),
        Value::String(cgroup_path.to_string()),
    );
    let encoded = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode init profile: {error}"))?;
    OciBundle::from_json(base.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate init profile: {error}"))
}

fn with_exact_process_profile(bundle: &OciBundle, cwd: &str) -> Result<OciBundle, String> {
    let mut config: Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode exact process profile: {error}"))?;
    let process = config
        .get_mut("process")
        .ok_or_else(|| "exact process profile requires process".to_string())?;
    let process = object_mut(process, "process")?;
    process.insert("cwd".to_string(), Value::String(cwd.to_string()));
    process.insert(
        "user".to_string(),
        json!({"uid": 0, "gid": 0, "umask": 18, "additionalGids": [1]}),
    );
    let encoded = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode exact process profile: {error}"))?;
    OciBundle::from_json(bundle.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate exact process profile: {error}"))
}

fn sleeping_init() -> Value {
    json!(["/bin/busybox", "sleep", "300"])
}

fn hooks(phase: &str, command: &str, timeout_seconds: u32) -> Value {
    let mut hooks = Map::new();
    hooks.insert(
        phase.to_string(),
        json!([{
            "path": "/bin/sh",
            "args": ["sh", "-c", command],
            "timeout": timeout_seconds
        }]),
    );
    Value::Object(hooks)
}

fn timeout_hooks(evidence_directory: &Path) -> Result<Value, String> {
    let started = evidence_directory.join(HOOK_DESCENDANT_STARTED);
    let escaped = evidence_directory.join(HOOK_DESCENDANT_ESCAPED);
    let started = started
        .to_str()
        .ok_or_else(|| "Hook descendant startup path must be UTF-8".to_string())?;
    let escaped = escaped
        .to_str()
        .ok_or_else(|| "Hook descendant escape path must be UTF-8".to_string())?;
    Ok(json!({
        "prestart": [{
            "path": "/bin/sh",
            "args": [
                "sh",
                "-c",
                "set -eu; (trap '' HUP TERM; /bin/busybox sleep 2; \
                 /bin/busybox touch \"$A3S_HOOK_DESCENDANT_ESCAPED\") & \
                 printf '%s\\n' \"$!\" > \"$A3S_HOOK_DESCENDANT_STARTED\"; \
                 exec /bin/busybox sleep 30"
            ],
            "env": [
                format!("A3S_HOOK_DESCENDANT_STARTED={started}"),
                format!("A3S_HOOK_DESCENDANT_ESCAPED={escaped}")
            ],
            "timeout": 1
        }]
    }))
}

async fn verify_timeout_process_group(fixture: &InitializationFixture) -> Result<bool, String> {
    let started_path = fixture.evidence_directory.join(HOOK_DESCENDANT_STARTED);
    let started = tokio::fs::read_to_string(&started_path)
        .await
        .map_err(|error| {
            format!(
                "timed-out Hook descendant did not publish {}: {error}",
                started_path.display()
            )
        })?;
    require(
        started.trim().parse::<u32>().is_ok_and(|pid| pid > 0),
        format!("timed-out Hook descendant published invalid PID {started:?}"),
    )?;

    tokio::time::sleep(HOOK_DESCENDANT_OBSERVATION).await;
    let escaped_path = fixture.evidence_directory.join(HOOK_DESCENDANT_ESCAPED);
    let escaped = tokio::fs::try_exists(&escaped_path)
        .await
        .map_err(|error| {
            format!(
                "failed to inspect timed-out Hook descendant marker {}: {error}",
                escaped_path.display()
            )
        })?;
    require(
        !escaped,
        format!(
            "timed-out Hook descendant escaped process-group cleanup and created {}",
            escaped_path.display()
        ),
    )?;
    Ok(true)
}

async fn read_exact(path: &Path, expected: &[u8]) -> Result<bool, String> {
    let actual = tokio::fs::read(path)
        .await
        .map_err(|error| format!("failed to read init evidence {}: {error}", path.display()))?;
    require(
        actual == expected,
        format!("init evidence mismatch: expected {expected:?}, got {actual:?}"),
    )?;
    Ok(true)
}

async fn remove_tree(path: &Path, description: &str) -> Result<(), String> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove {description} {}: {error}",
            path.display()
        )),
    }
}

async fn remove_file(path: &Path, description: &str) -> Result<(), String> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "failed to remove {description} {}: {error}",
            path.display()
        )),
    }
}

fn object_mut<'a>(
    value: &'a mut Value,
    description: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    value
        .as_object_mut()
        .ok_or_else(|| format!("init profile {description} must be an object"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_sdk::OciBundle;
    use serde_json::{json, Value};

    use super::{
        build_profile, hooks, timeout_hooks, with_exact_process_profile, EvidenceMount,
        HOOK_DESCENDANT_ESCAPED, HOOK_DESCENDANT_STARTED,
    };

    const CONFIG: &str = include_str!("../../../../../../fixtures/native-linux/config.json");

    #[test]
    fn init_profiles_replace_commands_hooks_and_cgroup_identity() {
        let directory = std::env::current_dir()
            .expect("current directory")
            .join("init-profile-bundle");
        let base = OciBundle::from_json(directory, CONFIG).expect("base bundle");
        let bundle = build_profile(
            &base,
            EvidenceMount {
                source: Path::new("/tmp/a3s-oci-init-evidence"),
                target: "/.matrix",
            },
            json!(["/bin/busybox", "true"]),
            json!(["PATH=/bin"]),
            Some(hooks("poststop", "exit 7", 2)),
            "a3s-oci-init-test",
        )
        .expect("init profile");
        let config: Value = serde_json::from_str(bundle.config_json()).expect("profile JSON");

        assert_eq!(config["process"]["args"], json!(["/bin/busybox", "true"]));
        assert_eq!(config["linux"]["cgroupsPath"], "a3s-oci-init-test");
        assert_eq!(config["hooks"]["poststop"][0]["timeout"], 2);
        assert!(config["mounts"]
            .as_array()
            .expect("mount list")
            .iter()
            .any(|mount| mount["destination"] == "/.matrix/evidence"));

        let exact = with_exact_process_profile(&bundle, "/.matrix")
            .expect("exact process execution profile");
        let config: Value = serde_json::from_str(exact.config_json()).expect("exact profile JSON");
        assert_eq!(config["process"]["cwd"], "/.matrix");
        assert_eq!(config["process"]["user"]["uid"], 0);
        assert_eq!(config["process"]["user"]["gid"], 0);
        assert_eq!(config["process"]["user"]["umask"], 18);
        assert_eq!(config["process"]["user"]["additionalGids"], json!([1]));

        let timeout =
            timeout_hooks(Path::new("/tmp/a3s-oci-hook-evidence")).expect("timeout Hook profile");
        assert_eq!(timeout["prestart"][0]["timeout"], 1);
        assert_eq!(
            timeout["prestart"][0]["env"],
            json!([
                format!(
                    "A3S_HOOK_DESCENDANT_STARTED=/tmp/a3s-oci-hook-evidence/{HOOK_DESCENDANT_STARTED}"
                ),
                format!(
                    "A3S_HOOK_DESCENDANT_ESCAPED=/tmp/a3s-oci-hook-evidence/{HOOK_DESCENDANT_ESCAPED}"
                )
            ])
        );
    }
}
