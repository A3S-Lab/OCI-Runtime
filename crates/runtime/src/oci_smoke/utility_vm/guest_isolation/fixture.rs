use std::io;
use std::path::{Path, PathBuf};

use a3s_oci_agent_protocol::{
    GuestPath, AGENT_RUNTIME_SHARE_GUEST_ROOT, AGENT_RUNTIME_SHARE_STATE_GUEST_ROOT,
};
use a3s_oci_sdk::OciBundle;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use super::CANARY_CONTENTS;
use crate::oci_smoke::utility_vm::guest_path;

const BUNDLE_SCOPE_OPERATION: &str = "validate-utility-vm-bundle-scope";
const MOUNT_SCOPE_OPERATION: &str = "prepare-container-mounts";
const INIT_OPERATION: &str = "run-container-init";

pub(super) struct PreparedCreateCase {
    pub(super) name: String,
    pub(super) expected_operation: &'static str,
    pub(super) bundle: OciBundle,
    pub(super) guest_directory: GuestPath,
}

pub(super) struct IsolationFixture {
    root: PathBuf,
    pub(super) canary: PathBuf,
    pub(super) canary_name: String,
    pub(super) create_cases: Vec<PreparedCreateCase>,
    pub(super) container_api_bundle: OciBundle,
}

impl IsolationFixture {
    pub(super) async fn prepare(
        runtime_share: &Path,
        base: &OciBundle,
        nonce: &str,
    ) -> Result<Self, String> {
        let container_api_bundle = container_api_bundle(base)?;
        let root = runtime_share.join(format!(".a3s-oci-guest-isolation-{nonce}"));
        let canary_name = format!(".a3s-oci-guest-isolation-canary-{nonce}");
        let canary = runtime_share.join("run").join(&canary_name);
        require_absent(&root, "Guest isolation fixture").await?;
        require_absent(&canary, "Guest isolation canary").await?;
        tokio::fs::create_dir(&root).await.map_err(|error| {
            format!(
                "failed to create Guest isolation fixture {}: {error}",
                root.display()
            )
        })?;
        let mut canary_file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&canary)
            .await
        {
            Ok(file) => file,
            Err(error) => {
                let _ = tokio::fs::remove_dir_all(&root).await;
                return Err(format!(
                    "failed to create Guest isolation canary {}: {error}",
                    canary.display()
                ));
            }
        };
        if let Err(error) = canary_file.write_all(CANARY_CONTENTS).await {
            let _ = tokio::fs::remove_file(&canary).await;
            let _ = tokio::fs::remove_dir_all(&root).await;
            return Err(format!(
                "failed to write Guest isolation canary {}: {error}",
                canary.display()
            ));
        }
        drop(canary_file);

        match prepare_cases(runtime_share, base, &root).await {
            Ok(create_cases) => Ok(Self {
                root,
                canary,
                canary_name,
                create_cases,
                container_api_bundle,
            }),
            Err(reason) => {
                let _ = tokio::fs::remove_file(&canary).await;
                let _ = tokio::fs::remove_dir_all(&root).await;
                Err(reason)
            }
        }
    }

    pub(super) async fn cleanup(self) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Err(error) = tokio::fs::remove_dir_all(&self.root).await {
            if error.kind() != io::ErrorKind::NotFound {
                failures.push(format!(
                    "failed to remove Guest isolation fixture {}: {error}",
                    self.root.display()
                ));
            }
        }
        if let Err(error) = tokio::fs::remove_file(&self.canary).await {
            if error.kind() != io::ErrorKind::NotFound {
                failures.push(format!(
                    "failed to remove Guest isolation canary {}: {error}",
                    self.canary.display()
                ));
            }
        }
        if path_exists(&self.root).await.unwrap_or(true) {
            failures.push(format!(
                "Guest isolation fixture remained after cleanup: {}",
                self.root.display()
            ));
        }
        if path_exists(&self.canary).await.unwrap_or(true) {
            failures.push(format!(
                "Guest isolation canary remained after cleanup: {}",
                self.canary.display()
            ));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

async fn prepare_cases(
    runtime_share: &Path,
    base: &OciBundle,
    root: &Path,
) -> Result<Vec<PreparedCreateCase>, String> {
    let mut cases = vec![
        PreparedCreateCase {
            name: "bundle-system-directory".to_string(),
            expected_operation: BUNDLE_SCOPE_OPERATION,
            bundle: base.clone(),
            guest_directory: GuestPath::new("/etc")
                .map_err(|error| format!("failed to construct system Guest path: {error}"))?,
        },
        PreparedCreateCase {
            name: "bundle-runtime-share-root".to_string(),
            expected_operation: BUNDLE_SCOPE_OPERATION,
            bundle: base.clone(),
            guest_directory: GuestPath::new(AGENT_RUNTIME_SHARE_GUEST_ROOT).map_err(|error| {
                format!("failed to construct runtime-share Guest path: {error}")
            })?,
        },
        PreparedCreateCase {
            name: "bundle-agent-state-root".to_string(),
            expected_operation: BUNDLE_SCOPE_OPERATION,
            bundle: base.clone(),
            guest_directory: GuestPath::new(AGENT_RUNTIME_SHARE_STATE_GUEST_ROOT)
                .map_err(|error| format!("failed to construct Agent-state Guest path: {error}"))?,
        },
    ];

    let mut absolute_rootfs = decode_base_config(base)?;
    absolute_rootfs["root"]["path"] = Value::String("/etc".to_string());
    cases.push(
        prepare_bundle_case(
            runtime_share,
            root,
            "absolute-rootfs",
            INIT_OPERATION,
            absolute_rootfs,
            FixturePath::None,
        )
        .await?,
    );
    cases.push(
        prepare_bundle_case(
            runtime_share,
            root,
            "rootfs-symlink-escape",
            INIT_OPERATION,
            decode_base_config(base)?,
            FixturePath::RootfsSymlink,
        )
        .await?,
    );
    cases.push(
        prepare_bundle_case(
            runtime_share,
            root,
            "absolute-bind-source",
            MOUNT_SCOPE_OPERATION,
            config_with_bind(base, "/etc")?,
            FixturePath::RootfsDirectory,
        )
        .await?,
    );
    cases.push(
        prepare_bundle_case(
            runtime_share,
            root,
            "relative-bind-traversal",
            MOUNT_SCOPE_OPERATION,
            config_with_bind(base, "../run")?,
            FixturePath::RootfsDirectory,
        )
        .await?,
    );
    cases.push(
        prepare_bundle_case(
            runtime_share,
            root,
            "bind-source-symlink-escape",
            MOUNT_SCOPE_OPERATION,
            config_with_bind(base, "linked")?,
            FixturePath::RootfsAndBindSymlink,
        )
        .await?,
    );
    Ok(cases)
}

enum FixturePath {
    None,
    RootfsDirectory,
    RootfsSymlink,
    RootfsAndBindSymlink,
}

async fn prepare_bundle_case(
    runtime_share: &Path,
    fixture_root: &Path,
    name: &str,
    expected_operation: &'static str,
    config: Value,
    fixture_path: FixturePath,
) -> Result<PreparedCreateCase, String> {
    let directory = fixture_root.join(name);
    tokio::fs::create_dir(&directory).await.map_err(|error| {
        format!(
            "failed to create Guest isolation case {}: {error}",
            directory.display()
        )
    })?;
    match fixture_path {
        FixturePath::None => {}
        FixturePath::RootfsDirectory => {
            tokio::fs::create_dir(directory.join("rootfs"))
                .await
                .map_err(|error| format!("failed to create case rootfs: {error}"))?;
        }
        FixturePath::RootfsSymlink => {
            tokio::fs::symlink(
                AGENT_RUNTIME_SHARE_STATE_GUEST_ROOT,
                directory.join("rootfs"),
            )
            .await
            .map_err(|error| format!("failed to create escaping rootfs symlink: {error}"))?;
        }
        FixturePath::RootfsAndBindSymlink => {
            tokio::fs::create_dir(directory.join("rootfs"))
                .await
                .map_err(|error| format!("failed to create case rootfs: {error}"))?;
            tokio::fs::symlink(
                AGENT_RUNTIME_SHARE_STATE_GUEST_ROOT,
                directory.join("linked"),
            )
            .await
            .map_err(|error| format!("failed to create escaping bind symlink: {error}"))?;
        }
    }
    let config_json = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode Guest isolation config: {error}"))?;
    tokio::fs::write(directory.join("config.json"), config_json.as_bytes())
        .await
        .map_err(|error| format!("failed to write Guest isolation config: {error}"))?;
    let bundle = OciBundle::from_json(directory.clone(), config_json)
        .map_err(|error| format!("failed to build Guest isolation bundle: {error}"))?;
    let guest_directory = guest_path(runtime_share, &directory)?;
    Ok(PreparedCreateCase {
        name: name.to_string(),
        expected_operation,
        bundle,
        guest_directory,
    })
}

fn decode_base_config(base: &OciBundle) -> Result<Value, String> {
    serde_json::from_str(base.config_json())
        .map_err(|error| format!("failed to decode known-good OCI configuration: {error}"))
}

fn config_with_bind(base: &OciBundle, source: &str) -> Result<Value, String> {
    let mut config = decode_base_config(base)?;
    let mounts = config
        .as_object_mut()
        .ok_or_else(|| "known-good OCI configuration is not an object".to_string())?
        .entry("mounts")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| "known-good OCI mounts property is not an array".to_string())?;
    mounts.insert(
        0,
        json!({
            "destination": "/a3s-guest-isolation-bind",
            "type": "bind",
            "source": source,
            "options": ["bind"]
        }),
    );
    Ok(config)
}

fn container_api_bundle(base: &OciBundle) -> Result<OciBundle, String> {
    let mut config = decode_base_config(base)?;
    let namespaces = config
        .pointer_mut("/linux/namespaces")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "known-good OCI namespaces property is not an array".to_string())?;
    let original_count = namespaces.len();
    namespaces.retain(|namespace| {
        !matches!(
            namespace.get("type").and_then(Value::as_str),
            Some("pid" | "user")
        )
    });
    if namespaces.len().checked_add(2) != Some(original_count) {
        return Err(
            "known-good OCI configuration must contain exactly one PID and user namespace"
                .to_string(),
        );
    }
    let linux = config
        .get_mut("linux")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "known-good OCI linux property is not an object".to_string())?;
    linux.remove("uidMappings");
    linux.remove("gidMappings");

    // The filesystem helper joins only the retained user and mount
    // namespaces. Keeping this dedicated container in the Agent's PID and
    // user namespaces makes its procfs `/proc/self/root` magic link resolve
    // to the helper's Guest system root, outside the retained container-root
    // descriptor. The two API cases can therefore prove that openat2 rejects
    // a reachable escape, rather than accepting a NotFound result from an
    // isolated procfs view.
    let config_json = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode container API isolation config: {error}"))?;
    OciBundle::from_json(base.directory().to_path_buf(), config_json)
        .map_err(|error| format!("failed to build container API isolation bundle: {error}"))
}

async fn require_absent(path: &Path, description: &str) -> Result<(), String> {
    match tokio::fs::symlink_metadata(path).await {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(format!(
            "refusing to overwrite existing {description}: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )),
    }
}

async fn path_exists(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use a3s_oci_sdk::OciBundle;
    use tempfile::tempdir;

    use super::{config_with_bind, container_api_bundle, IsolationFixture};
    use crate::oci_smoke::utility_vm::guest_isolation::CANARY_CONTENTS;

    fn base_bundle(directory: &Path) -> OciBundle {
        OciBundle::from_json(
            directory.to_path_buf(),
            serde_json::json!({
                "ociVersion": "1.3.0",
                "root": {"path": "rootfs", "readonly": false},
                "process": {
                    "terminal": false,
                    "user": {"uid": 0, "gid": 0},
                    "args": ["/bin/true"],
                    "cwd": "/",
                    "noNewPrivileges": true
                },
                "linux": {
                    "namespaces": [
                        {"type": "mount"},
                        {"type": "pid"},
                        {"type": "user"}
                    ],
                    "uidMappings": [
                        {"containerID": 0, "hostID": 0, "size": 1}
                    ],
                    "gidMappings": [
                        {"containerID": 0, "hostID": 0, "size": 1}
                    ]
                }
            })
            .to_string(),
        )
        .expect("base bundle")
    }

    #[test]
    fn hostile_bind_is_inserted_before_known_good_mounts() {
        let temporary = tempdir().expect("temporary bundle");
        let base = base_bundle(temporary.path());
        let config = config_with_bind(&base, "../run").expect("hostile bind config");
        assert_eq!(config["mounts"][0]["source"], "../run");
        assert_eq!(config["mounts"][0]["options"][0], "bind");
    }

    #[test]
    fn container_api_fixture_inherits_the_agent_pid_and_user_namespaces() {
        let temporary = tempdir().expect("temporary bundle");
        let base = base_bundle(temporary.path());
        let bundle = container_api_bundle(&base).expect("container API bundle");
        let config: serde_json::Value =
            serde_json::from_str(bundle.config_json()).expect("container API config");
        assert_eq!(
            config["linux"]["namespaces"],
            serde_json::json!([{"type": "mount"}])
        );
        assert!(config["linux"].get("uidMappings").is_none());
        assert!(config["linux"].get("gidMappings").is_none());
    }

    #[tokio::test]
    async fn fixture_cleanup_removes_cases_and_canary() {
        let temporary = tempdir().expect("temporary runtime share");
        let share = temporary.path().join("share");
        let bundle_directory = share.join("bundle");
        std::fs::create_dir_all(bundle_directory.join("rootfs")).expect("base rootfs");
        std::fs::create_dir(share.join("run")).expect("runtime state");
        let base = base_bundle(&bundle_directory);
        let fixture = IsolationFixture::prepare(&share, &base, "fixture-test")
            .await
            .expect("isolation fixture");
        assert_eq!(
            tokio::fs::read(&fixture.canary)
                .await
                .expect("canary contents"),
            CANARY_CONTENTS
        );
        let root = fixture.root.clone();
        let canary = fixture.canary.clone();
        fixture.cleanup().await.expect("fixture cleanup");
        assert!(!root.exists());
        assert!(!canary.exists());
    }
}
