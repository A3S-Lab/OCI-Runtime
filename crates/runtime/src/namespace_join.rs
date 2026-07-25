use std::path::Path;

use a3s_oci_sdk::OciBundle;
use serde_json::{json, Map, Value};

pub(crate) struct NamespaceJoinBundles {
    pub(crate) non_mount: OciBundle,
    pub(crate) mount: OciBundle,
    pub(crate) wrong_type: OciBundle,
}

pub(crate) fn build_bundles(
    base: &OciBundle,
    donor_pid: i32,
) -> Result<NamespaceJoinBundles, String> {
    if donor_pid <= 0 {
        return Err(format!(
            "namespace donor PID must be positive, received {donor_pid}"
        ));
    }
    let base_config: Value = serde_json::from_str(base.config_json())
        .map_err(|error| format!("failed to decode namespace join base config: {error}"))?;

    let mut non_mount = base_config.clone();
    replace_linux_profile(&mut non_mount, joined_non_mount_namespaces(donor_pid))?;
    replace_process_command(&mut non_mount, join_workload_command())?;

    let mut mount = base_config.clone();
    remove_root_fields(&mut mount, &["hostname", "domainname", "mounts"])?;
    replace_linux_profile(
        &mut mount,
        vec![json!({
            "type": "mount",
            "path": namespace_path(donor_pid, "mnt")
        })],
    )?;
    replace_process_command(&mut mount, join_workload_command())?;

    let mut wrong_type = base_config;
    remove_root_fields(&mut wrong_type, &["hostname", "domainname", "mounts"])?;
    replace_linux_profile(
        &mut wrong_type,
        vec![json!({
            "type": "uts",
            "path": namespace_path(donor_pid, "net")
        })],
    )?;

    Ok(NamespaceJoinBundles {
        non_mount: bundle_from_value(base.directory(), non_mount)?,
        mount: bundle_from_value(base.directory(), mount)?,
        wrong_type: bundle_from_value(base.directory(), wrong_type)?,
    })
}

fn joined_non_mount_namespaces(donor_pid: i32) -> Vec<Value> {
    [
        ("time", "time"),
        ("pid", "pid"),
        ("user", "user"),
        ("mount", ""),
        ("network", "net"),
        ("ipc", "ipc"),
        ("cgroup", "cgroup"),
        ("uts", "uts"),
    ]
    .into_iter()
    .map(|(namespace_type, proc_name)| {
        if proc_name.is_empty() {
            json!({"type": namespace_type})
        } else {
            json!({
                "type": namespace_type,
                "path": namespace_path(donor_pid, proc_name)
            })
        }
    })
    .collect()
}

fn replace_linux_profile(config: &mut Value, namespaces: Vec<Value>) -> Result<(), String> {
    let root = object_mut(config, "config")?;
    let linux = root
        .entry("linux")
        .or_insert_with(|| Value::Object(Map::new()));
    let linux = object_mut(linux, "linux")?;
    linux.clear();
    linux.insert("namespaces".to_string(), Value::Array(namespaces));
    Ok(())
}

fn remove_root_fields(config: &mut Value, fields: &[&str]) -> Result<(), String> {
    let root = object_mut(config, "config")?;
    for field in fields {
        root.remove(*field);
    }
    Ok(())
}

fn replace_process_command(config: &mut Value, replacement: String) -> Result<(), String> {
    *process_command_mut(config)? = replacement;
    Ok(())
}

fn process_command_mut(config: &mut Value) -> Result<&mut String, String> {
    let command = config
        .get_mut("process")
        .and_then(Value::as_object_mut)
        .and_then(|process| process.get_mut("args"))
        .and_then(Value::as_array_mut)
        .and_then(|args| args.get_mut(2))
        .ok_or_else(|| {
            "namespace join fixture requires process.args[2] to be a shell command".to_string()
        })?;
    match command {
        Value::String(command) => Ok(command),
        _ => Err("namespace join fixture requires process.args[2] to be a shell command".into()),
    }
}

fn object_mut<'a>(value: &'a mut Value, field: &str) -> Result<&'a mut Map<String, Value>, String> {
    value
        .as_object_mut()
        .ok_or_else(|| format!("namespace join {field} must be an object"))
}

fn namespace_path(pid: i32, namespace: &str) -> String {
    format!("/proc/{pid}/ns/{namespace}")
}

fn join_workload_command() -> String {
    "set -eu; trap 'exit 0' TERM; while :; do /bin/busybox sleep 1; done".into()
}

fn bundle_from_value(directory: &Path, config: Value) -> Result<OciBundle, String> {
    let config = serde_json::to_string(&config)
        .map_err(|error| format!("failed to encode namespace join config: {error}"))?;
    OciBundle::from_json(directory.to_path_buf(), config)
        .map_err(|error| format!("failed to validate namespace join bundle: {error}"))
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::OciBundle;
    use serde_json::Value;

    use super::build_bundles;

    const CONFIG: &str = include_str!("../../../fixtures/utility-vm/config.json");

    #[test]
    fn derives_positive_and_negative_join_profiles_from_the_qualified_bundle() {
        let bundle_directory = std::env::current_dir()
            .expect("current test directory")
            .join("namespace-join-bundle");
        let base = OciBundle::from_json(bundle_directory, CONFIG).expect("qualified base bundle");
        let bundles = build_bundles(&base, 4242).expect("namespace join bundles");

        let non_mount: Value =
            serde_json::from_str(bundles.non_mount.config_json()).expect("non-mount JSON");
        let namespaces = non_mount["linux"]["namespaces"]
            .as_array()
            .expect("namespace list");
        assert_eq!(namespaces.len(), 8);
        assert_eq!(
            namespaces[0]["path"],
            Value::String("/proc/4242/ns/time".into())
        );
        assert_eq!(namespaces[3], serde_json::json!({"type": "mount"}));
        assert!(non_mount["linux"].get("uidMappings").is_none());
        assert!(non_mount["linux"].get("timeOffsets").is_none());
        assert!(non_mount["process"]["args"][2]
            .as_str()
            .expect("join command")
            .contains("/bin/busybox sleep 1"));

        let mount: Value = serde_json::from_str(bundles.mount.config_json()).expect("mount JSON");
        assert_eq!(
            mount["linux"]["namespaces"],
            serde_json::json!([
                {"type": "mount", "path": "/proc/4242/ns/mnt"}
            ])
        );
        assert!(mount.get("mounts").is_none());
        assert!(mount.get("hostname").is_none());
        assert!(mount["process"]["args"][2]
            .as_str()
            .expect("mount command")
            .contains("/bin/busybox sleep 1"));

        let wrong_type: Value =
            serde_json::from_str(bundles.wrong_type.config_json()).expect("wrong-type JSON");
        assert_eq!(
            wrong_type["linux"]["namespaces"],
            serde_json::json!([
                {"type": "uts", "path": "/proc/4242/ns/net"}
            ])
        );
    }
}
