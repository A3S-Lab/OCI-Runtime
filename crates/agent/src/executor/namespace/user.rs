use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{namespace_error, IdMapping, NamespacePlan};

pub(in crate::executor) async fn install_user_mappings(
    plan: &NamespacePlan,
    pid: i32,
) -> Result<()> {
    if !plan.new_user() {
        return Err(namespace_error(
            ErrorCode::FailedPrecondition,
            "container init requested mappings without a new user namespace",
        ));
    }
    if pid <= 0 {
        return Err(namespace_error(
            ErrorCode::InvalidArgument,
            format!("cannot map non-positive container init PID {pid}"),
        ));
    }
    let uid_mappings = plan.uid_mappings().to_vec();
    let gid_mappings = plan.gid_mappings().to_vec();
    tokio::task::spawn_blocking(move || {
        install_user_mappings_blocking(
            pid,
            &uid_mappings,
            &gid_mappings,
            SetgroupsPolicy::RequireAllow,
        )
    })
    .await
    .map_err(|join| {
        namespace_error(
            ErrorCode::Internal,
            format!("user namespace mapping worker failed: {join}"),
        )
    })?
}

fn install_user_mappings_blocking(
    pid: i32,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
    setgroups_policy: SetgroupsPolicy,
) -> Result<()> {
    let child_namespace = std::fs::read_link(format!("/proc/{pid}/ns/user")).map_err(|error| {
        namespace_error(
            ErrorCode::PermissionDenied,
            format!("failed to inspect container init user namespace: {error}"),
        )
    })?;
    let runtime_namespace = std::fs::read_link("/proc/self/ns/user").map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!("failed to inspect runtime user namespace: {error}"),
        )
    })?;
    if child_namespace == runtime_namespace {
        return Err(namespace_error(
            ErrorCode::PermissionDenied,
            "container init requested mappings before entering a distinct user namespace",
        ));
    }

    let proc_root = format!("/proc/{pid}");
    write_mapping_file(&Path::new(&proc_root).join("uid_map"), "UID", uid_mappings)?;
    verify_mapping_file(&Path::new(&proc_root).join("uid_map"), "UID", uid_mappings)?;

    apply_setgroups_policy(&Path::new(&proc_root).join("setgroups"), setgroups_policy)?;

    write_mapping_file(&Path::new(&proc_root).join("gid_map"), "GID", gid_mappings)?;
    verify_mapping_file(&Path::new(&proc_root).join("gid_map"), "GID", gid_mappings)
}

pub(super) fn install_idmap_user_mappings(
    pid: i32,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
) -> Result<()> {
    if pid <= 0 {
        return Err(namespace_error(
            ErrorCode::InvalidArgument,
            format!("cannot map non-positive ID-mapping helper PID {pid}"),
        ));
    }
    install_user_mappings_blocking(pid, uid_mappings, gid_mappings, SetgroupsPolicy::Deny)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetgroupsPolicy {
    RequireAllow,
    Deny,
}

fn apply_setgroups_policy(path: &Path, policy: SetgroupsPolicy) -> Result<()> {
    let inspect = || {
        std::fs::read_to_string(path).map_err(|error| {
            namespace_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to inspect user namespace setgroups policy {}: {error}",
                    path.display()
                ),
            )
        })
    };
    let current = inspect()?;
    match policy {
        SetgroupsPolicy::RequireAllow if current.trim() == "allow" => Ok(()),
        SetgroupsPolicy::RequireAllow => Err(namespace_error(
            ErrorCode::FailedPrecondition,
            "new container user namespace does not permit the required supplementary-group setup",
        )),
        SetgroupsPolicy::Deny => {
            if current.trim() != "deny" {
                let mut file = OpenOptions::new().write(true).open(path).map_err(|error| {
                    namespace_error(
                        ErrorCode::PermissionDenied,
                        format!(
                            "failed to open user namespace setgroups policy {}: {error}",
                            path.display()
                        ),
                    )
                })?;
                let written = file.write(b"deny").map_err(|error| {
                    namespace_error(
                        ErrorCode::PermissionDenied,
                        format!(
                            "failed to deny setgroups for ID-mapping namespace {}: {error}",
                            path.display()
                        ),
                    )
                })?;
                if written != b"deny".len() {
                    return Err(namespace_error(
                        ErrorCode::Internal,
                        format!(
                            "setgroups policy write to {} was partial: {written}/{} bytes",
                            path.display(),
                            b"deny".len()
                        ),
                    ));
                }
            }
            if inspect()?.trim() == "deny" {
                Ok(())
            } else {
                Err(namespace_error(
                    ErrorCode::FailedPrecondition,
                    "ID-mapping user namespace did not retain setgroups=deny",
                ))
            }
        }
    }
}

fn write_mapping_file(path: &Path, kind: &str, mappings: &[IdMapping]) -> Result<()> {
    let payload = mappings
        .iter()
        .map(|mapping| {
            format!(
                "{} {} {}\n",
                mapping.container_id, mapping.host_id, mapping.size
            )
        })
        .collect::<String>();
    let mut file = OpenOptions::new().write(true).open(path).map_err(|error| {
        namespace_error(
            ErrorCode::PermissionDenied,
            format!(
                "failed to open {kind} mapping file {}: {error}",
                path.display()
            ),
        )
    })?;
    let written = file.write(payload.as_bytes()).map_err(|error| {
        namespace_error(
            ErrorCode::PermissionDenied,
            format!(
                "failed to write {kind} mappings to {}: {error}",
                path.display()
            ),
        )
    })?;
    if written != payload.len() {
        return Err(namespace_error(
            ErrorCode::Internal,
            format!(
                "{kind} mapping write to {} was partial: {written}/{} bytes",
                path.display(),
                payload.len()
            ),
        ));
    }
    Ok(())
}

fn verify_mapping_file(path: &Path, kind: &str, expected: &[IdMapping]) -> Result<()> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!(
                "failed to verify {kind} mapping file {}: {error}",
                path.display()
            ),
        )
    })?;
    let actual = parse_mapping_file(path, &contents)?;
    let mut expected = expected.to_vec();
    expected.sort_by_key(|mapping| (mapping.container_id, mapping.host_id, mapping.size));
    if actual == expected {
        Ok(())
    } else {
        Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!("{kind} mappings read back differently from the requested OCI mapping"),
        ))
    }
}

fn parse_mapping_file(path: &Path, contents: &str) -> Result<Vec<IdMapping>> {
    let mut mappings = contents
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let values = line.split_ascii_whitespace().collect::<Vec<_>>();
            if values.len() != 3 {
                return Err(namespace_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "mapping file {} line {} does not contain three fields",
                        path.display(),
                        index + 1
                    ),
                ));
            }
            let parse = |value: &str| {
                value.parse::<u32>().map_err(|error| {
                    namespace_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "mapping file {} contains invalid value `{value}`: {error}",
                            path.display()
                        ),
                    )
                })
            };
            Ok(IdMapping {
                container_id: parse(values[0])?,
                host_id: parse(values[1])?,
                size: parse(values[2])?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    mappings.sort_by_key(|mapping| (mapping.container_id, mapping.host_id, mapping.size));
    Ok(mappings)
}
