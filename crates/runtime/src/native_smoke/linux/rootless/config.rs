use std::os::unix::fs::MetadataExt;
use std::path::Path;

use a3s_oci_sdk::OciBundle;

const SUBORDINATE_FILE_NAME: &str = ".a3s-oci-rootless-subordinate";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Mapping {
    container_id: u32,
    host_id: u32,
    size: u32,
}

#[derive(Debug)]
pub(super) struct MappingPlan {
    pub(super) uid: Vec<Mapping>,
    pub(super) gid: Vec<Mapping>,
}

pub(super) fn validate_mapping_plan(
    bundle: &OciBundle,
    effective_uid: u32,
    effective_gid: u32,
) -> Result<MappingPlan, String> {
    let config: serde_json::Value = serde_json::from_str(bundle.config_json())
        .map_err(|error| format!("failed to decode rootless OCI configuration: {error}"))?;
    if config
        .pointer("/linux/cgroupsPath")
        .is_some_and(|value| !value.is_null())
    {
        return Err("rootless smoke bundle must not configure linux.cgroupsPath".into());
    }
    if config
        .pointer("/process/user/uid")
        .and_then(serde_json::Value::as_u64)
        != Some(0)
        || config
            .pointer("/process/user/gid")
            .and_then(serde_json::Value::as_u64)
            != Some(0)
        || config
            .pointer("/process/user/additionalGids")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|groups| !groups.is_empty())
    {
        return Err("rootless smoke process must use UID/GID 0 without additionalGids".into());
    }
    let namespaces = config
        .pointer("/linux/namespaces")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "rootless smoke requires linux.namespaces".to_string())?;
    for required in ["user", "mount", "pid"] {
        if !namespaces.iter().any(|namespace| {
            namespace.get("type").and_then(serde_json::Value::as_str) == Some(required)
                && namespace.get("path").is_none()
        }) {
            return Err(format!(
                "rootless smoke requires a newly created {required} namespace"
            ));
        }
    }
    let uid = parse_config_mappings(&config, "uidMappings")?;
    let gid = parse_config_mappings(&config, "gidMappings")?;
    validate_root_mapping("UID", &uid, effective_uid)?;
    validate_root_mapping("GID", &gid, effective_gid)?;
    Ok(MappingPlan { uid, gid })
}

fn parse_config_mappings(config: &serde_json::Value, field: &str) -> Result<Vec<Mapping>, String> {
    let values = config
        .pointer(&format!("/linux/{field}"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("rootless smoke requires linux.{field}"))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let get = |name: &str| {
                value
                    .get(name)
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| format!("linux.{field}[{index}].{name} is invalid"))
            };
            Ok(Mapping {
                container_id: get("containerID")?,
                host_id: get("hostID")?,
                size: get("size")?,
            })
        })
        .collect()
}

fn validate_root_mapping(
    kind: &str,
    mappings: &[Mapping],
    effective_id: u32,
) -> Result<(), String> {
    let root = Mapping {
        container_id: 0,
        host_id: effective_id,
        size: 1,
    };
    if mappings.len() < 2 || mappings.iter().filter(|mapping| **mapping == root).count() != 1 {
        return Err(format!(
            "rootless {kind} mappings must map container root to effective host ID {effective_id} with size 1 and include a subordinate range"
        ));
    }
    if mappings.iter().any(|mapping| mapping.host_id == 0) {
        return Err(format!("rootless {kind} mappings must not map host ID 0"));
    }
    if mapped_host_id(mappings, 1).is_none() {
        return Err(format!(
            "rootless {kind} mappings must cover container ID 1 with a subordinate range"
        ));
    }
    Ok(())
}

pub(super) fn validate_rootfs_ownership(
    rootfs: &Path,
    mappings: &MappingPlan,
    effective_uid: u32,
    effective_gid: u32,
) -> Result<(), String> {
    let root = std::fs::symlink_metadata(rootfs).map_err(|error| {
        format!(
            "failed to inspect rootless rootfs {}: {error}",
            rootfs.display()
        )
    })?;
    if root.uid() != effective_uid || root.gid() != effective_gid {
        return Err(format!(
            "rootless rootfs must be owned by effective host identity {effective_uid}:{effective_gid}"
        ));
    }
    let subordinate_path = rootfs.join(SUBORDINATE_FILE_NAME);
    let subordinate = std::fs::symlink_metadata(&subordinate_path).map_err(|error| {
        format!(
            "failed to inspect subordinate-ID fixture {}: {error}",
            subordinate_path.display()
        )
    })?;
    let expected_uid = mapped_host_id(&mappings.uid, 1)
        .ok_or_else(|| "rootless UID mappings do not cover container ID 1".to_string())?;
    let expected_gid = mapped_host_id(&mappings.gid, 1)
        .ok_or_else(|| "rootless GID mappings do not cover container ID 1".to_string())?;
    if !subordinate.is_file()
        || subordinate.file_type().is_symlink()
        || subordinate.uid() != expected_uid
        || subordinate.gid() != expected_gid
    {
        return Err(format!(
            "subordinate-ID fixture must be a regular file owned by mapped host identity {expected_uid}:{expected_gid}"
        ));
    }
    Ok(())
}

fn mapped_host_id(mappings: &[Mapping], container_id: u32) -> Option<u32> {
    mappings.iter().find_map(|mapping| {
        let offset = container_id.checked_sub(mapping.container_id)?;
        (offset < mapping.size)
            .then(|| mapping.host_id.checked_add(offset))
            .flatten()
    })
}

pub(super) async fn read_mapping_file(path: &Path, kind: &str) -> Result<Vec<Mapping>, String> {
    let contents = tokio::fs::read_to_string(path).await.map_err(|error| {
        format!(
            "failed to read rootless {kind} map {}: {error}",
            path.display()
        )
    })?;
    let mut mappings = contents
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(format!(
                    "rootless {kind} map line {} did not contain three fields",
                    index + 1
                ));
            }
            let parse = |value: &str| {
                value.parse::<u32>().map_err(|error| {
                    format!("rootless {kind} map contains invalid value {value:?}: {error}")
                })
            };
            Ok(Mapping {
                container_id: parse(fields[0])?,
                host_id: parse(fields[1])?,
                size: parse(fields[2])?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    mappings.sort_unstable();
    Ok(mappings)
}

pub(super) fn sorted_mappings(mappings: &[Mapping]) -> Vec<Mapping> {
    let mut mappings = mappings.to_vec();
    mappings.sort_unstable();
    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_host_id_applies_mapping_offset() {
        let mappings = [
            Mapping {
                container_id: 0,
                host_id: 20_000,
                size: 1,
            },
            Mapping {
                container_id: 1,
                host_id: 300_000,
                size: 65_535,
            },
        ];
        assert_eq!(mapped_host_id(&mappings, 0), Some(20_000));
        assert_eq!(mapped_host_id(&mappings, 1), Some(300_000));
        assert_eq!(mapped_host_id(&mappings, 65_535), Some(365_534));
        assert_eq!(mapped_host_id(&mappings, 65_536), None);
    }
}
