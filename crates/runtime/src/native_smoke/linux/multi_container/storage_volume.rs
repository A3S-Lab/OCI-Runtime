use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ExitStatus, OciBundle, RuntimeClient, StartRequest,
};
use serde_json::{json, Map, Value};
use tokio::time::{sleep, Instant};

use super::lifecycle::{
    container_id, create_request, kill_request, native_call, operation, require, require_created,
    require_kill_state, require_running, state_is_missing, wait_request, wait_until_stopped,
};
use crate::NativeLinuxMultiContainerSmokeReport;

const PAYLOAD: &[u8] = b"a3s-oci-shared-volume-v1\n";
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const POLL_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct StorageVolumeFixture {
    writer: OciBundle,
    reader: OciBundle,
    shared_directory: PathBuf,
    rootfs_targets: [PathBuf; 2],
}

impl StorageVolumeFixture {
    pub(super) async fn prepare(
        writer_base: &OciBundle,
        reader_base: &OciBundle,
        rootfs: [&Path; 2],
        source_parent: &Path,
        nonce: &str,
    ) -> Result<Self, String> {
        // The executor resolves bind sources after entering the container's
        // user namespace. Keep this deliberately external volume outside the
        // mode-0700 runtime session so the mapped root can traverse to it.
        let shared_directory = source_parent.join(format!("volume-source-{nonce}"));
        tokio::fs::create_dir(&shared_directory)
            .await
            .map_err(|error| {
                format!(
                    "failed to create shared volume source {}: {error}",
                    shared_directory.display()
                )
            })?;
        tokio::fs::set_permissions(&shared_directory, std::fs::Permissions::from_mode(0o777))
            .await
            .map_err(|error| {
                format!(
                    "failed to make shared volume source writable {}: {error}",
                    shared_directory.display()
                )
            })?;

        let target_name = format!(".a3s-oci-volume-{nonce}");
        let target = format!("/{target_name}");
        let writer = build_profile(
            writer_base,
            &shared_directory,
            &target,
            false,
            &writer_command(&target),
            &format!("a3s-oci-volume-writer-{nonce}"),
        )?;
        let reader = build_profile(
            reader_base,
            &shared_directory,
            &target,
            true,
            &reader_command(&target),
            &format!("a3s-oci-volume-reader-{nonce}"),
        )?;

        Ok(Self {
            writer,
            reader,
            shared_directory,
            rootfs_targets: [rootfs[0].join(&target_name), rootfs[1].join(target_name)],
        })
    }

    pub(super) async fn cleanup(&self) -> Result<bool, String> {
        for target in &self.rootfs_targets {
            remove_tree(target, "storage-profile rootfs target").await?;
        }
        remove_tree(&self.shared_directory, "shared volume source").await?;
        Ok(
            self.rootfs_targets.iter().all(|path| !path.exists())
                && !self.shared_directory.exists(),
        )
    }
}

pub(super) async fn exercise(
    client: &RuntimeClient,
    fixture: &StorageVolumeFixture,
    nonce: &str,
    report: &mut NativeLinuxMultiContainerSmokeReport,
) -> Result<(), String> {
    let writer_id = container_id(nonce, "volume-writer")?;
    let writer = native_call(
        "create shared-volume writer",
        client.create(create_request(
            nonce,
            "volume-writer-create",
            writer_id.clone(),
            &fixture.writer,
        )?),
    )
    .await?;
    require_created(&writer, "shared-volume writer")?;
    let writer_target = ContainerTarget::exact(writer_id, writer.generation);
    let started = native_call(
        "start shared-volume writer",
        client.start(StartRequest {
            context: operation(nonce, "volume-writer-start")?,
            target: writer_target.clone(),
        }),
    )
    .await?;
    require_running(&started, "shared-volume writer")?;
    wait_for_payload(&fixture.shared_directory.join("payload")).await?;
    report.storage_volumes.shared_bind_write_visible = true;

    let reader_target = run_reader(client, fixture, nonce, "volume-reader").await?;
    let forbidden = fixture.shared_directory.join("forbidden");
    report.storage_volumes.readonly_bind_enforced = !forbidden.exists();
    report.storage_volumes.private_tmpfs_isolated = true;
    require(
        report.storage_volumes.readonly_bind_enforced,
        "read-only shared bind accepted a reader mutation",
    )?;

    let killed = native_call(
        "kill shared-volume writer",
        client.kill(kill_request(
            nonce,
            "volume-writer-kill",
            writer_target.clone(),
        )?),
    )
    .await?;
    require_kill_state(&killed, "shared-volume writer")?;
    let writer_status = native_call(
        "wait for shared-volume writer",
        client.wait(wait_request(writer_target.clone())),
    )
    .await?;
    let expected_signal = ExitStatus::signaled(libc::SIGKILL, false)
        .map_err(|error| format!("failed to construct expected writer exit: {error}"))?;
    require(
        writer_status == expected_signal,
        format!("shared-volume writer returned {writer_status:?}"),
    )?;
    require(
        wait_until_stopped(client, &writer_target).await?,
        "shared-volume writer did not stop",
    )?;
    native_call(
        "delete shared-volume writer",
        client.delete(DeleteRequest {
            context: operation(nonce, "volume-writer-delete")?,
            target: writer_target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;

    let persistence_target = run_reader(client, fixture, nonce, "volume-persist").await?;
    report.storage_volumes.bind_data_persisted_after_recreate =
        tokio::fs::read(fixture.shared_directory.join("payload"))
            .await
            .map_err(|error| format!("failed to read persisted shared volume payload: {error}"))?
            == PAYLOAD;
    require(
        report.storage_volumes.bind_data_persisted_after_recreate,
        "shared bind data changed after writer deletion and reader recreation",
    )?;

    report.storage_volumes.all_profiles_removed =
        state_is_missing(client, &writer_target, "shared-volume writer after delete").await?
            && state_is_missing(client, &reader_target, "shared-volume reader after delete")
                .await?
            && state_is_missing(
                client,
                &persistence_target,
                "shared-volume persistence reader after delete",
            )
            .await?;
    require(
        report.storage_volumes.all_profiles_removed,
        "storage-volume matrix left runtime state",
    )
}

async fn run_reader(
    client: &RuntimeClient,
    fixture: &StorageVolumeFixture,
    nonce: &str,
    label: &str,
) -> Result<ContainerTarget, String> {
    let id = container_id(nonce, label)?;
    let created = native_call(
        &format!("create {label}"),
        client.create(create_request(
            nonce,
            &format!("{label}-create"),
            id.clone(),
            &fixture.reader,
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
    let expected = ExitStatus::exited(0)
        .map_err(|error| format!("failed to construct expected reader exit: {error}"))?;
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

fn build_profile(
    base: &OciBundle,
    shared_directory: &Path,
    target: &str,
    readonly: bool,
    command: &str,
    cgroup_path: &str,
) -> Result<OciBundle, String> {
    let mut config: Value = serde_json::from_str(base.config_json())
        .map_err(|error| format!("failed to decode storage profile: {error}"))?;
    let root = object_mut(&mut config, "config")?;
    let mounts = root
        .entry("mounts")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| "storage profile mounts must be an array".to_string())?;
    mounts.push(json!({
        "destination": format!("{target}/shared"),
        "type": "none",
        "source": shared_directory,
        "options": if readonly {
            vec!["rbind", "ro", "nosuid", "nodev"]
        } else {
            vec!["rbind", "rw", "nosuid", "nodev"]
        }
    }));
    mounts.push(json!({
        "destination": format!("{target}/private"),
        "type": "tmpfs",
        "source": "tmpfs",
        "options": ["rw", "nosuid", "nodev", "mode=0700", "size=64k"]
    }));
    let process = root
        .get_mut("process")
        .ok_or_else(|| "storage profile process is required".to_string())?;
    object_mut(process, "process")?.insert("args".to_string(), json!(["/bin/sh", "-c", command]));
    let linux = root
        .get_mut("linux")
        .ok_or_else(|| "storage profile linux config is required".to_string())?;
    object_mut(linux, "linux")?.insert(
        "cgroupsPath".to_string(),
        Value::String(cgroup_path.to_string()),
    );
    let encoded = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode storage profile: {error}"))?;
    OciBundle::from_json(base.directory().to_path_buf(), encoded)
        .map_err(|error| format!("failed to validate storage profile: {error}"))
}

fn writer_command(target: &str) -> String {
    format!(
        "set -eu; test ! -e {target}/private/writer-only; \
         printf 'a3s-oci-private-writer-v1\\n' > {target}/private/writer-only; \
         printf 'a3s-oci-shared-volume-v1\\n' > {target}/shared/payload; \
         exec /bin/busybox sleep 300"
    )
}

fn reader_command(target: &str) -> String {
    format!(
        "set -eu; test \"$(/bin/busybox cat {target}/shared/payload)\" = \
         a3s-oci-shared-volume-v1; test ! -e {target}/private/writer-only; \
         if printf forbidden > {target}/shared/forbidden 2>/dev/null; then exit 91; fi; \
         printf 'a3s-oci-private-reader-v1\\n' > {target}/private/reader-only; exit 0"
    )
}

async fn wait_for_payload(path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + POLL_TIMEOUT;
    loop {
        match tokio::fs::read(path).await {
            Ok(contents) if contents == PAYLOAD => return Ok(()),
            Ok(contents) => {
                return Err(format!(
                    "shared volume payload mismatch: expected {PAYLOAD:?}, got {contents:?}"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to read shared volume payload {}: {error}",
                    path.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for shared volume writer".into());
        }
        sleep(POLL_INTERVAL).await;
    }
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

fn object_mut<'a>(
    value: &'a mut Value,
    description: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    value
        .as_object_mut()
        .ok_or_else(|| format!("storage profile {description} must be an object"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_sdk::OciBundle;
    use serde_json::Value;

    use super::{build_profile, reader_command, writer_command};

    const CONFIG: &str = include_str!("../../../../../../fixtures/native-linux/config.json");

    #[test]
    fn storage_profiles_encode_rw_ro_and_private_mounts() {
        let directory = std::env::current_dir()
            .expect("current directory")
            .join("storage-profile-bundle");
        let base = OciBundle::from_json(directory, CONFIG).expect("base bundle");
        for (readonly, command) in [
            (false, writer_command("/.matrix")),
            (true, reader_command("/.matrix")),
        ] {
            let bundle = build_profile(
                &base,
                Path::new("/tmp/a3s-oci-volume-source"),
                "/.matrix",
                readonly,
                &command,
                "a3s-oci-volume-test",
            )
            .expect("storage profile");
            let config: Value = serde_json::from_str(bundle.config_json()).expect("profile JSON");
            let mounts = config["mounts"].as_array().expect("mount list");
            let shared = mounts
                .iter()
                .find(|mount| mount["destination"] == "/.matrix/shared")
                .expect("shared bind");
            let options = shared["options"].as_array().expect("shared options");
            assert_eq!(options.iter().any(|option| option == "ro"), readonly);
            assert!(mounts.iter().any(
                |mount| mount["destination"] == "/.matrix/private" && mount["type"] == "tmpfs"
            ));
        }
    }
}
