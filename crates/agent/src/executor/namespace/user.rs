use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use a3s_oci_sdk::{ErrorCode, Result};

use super::{namespace_error, IdMapping, NamespacePlan};

const NEWUIDMAP_CANDIDATES: [&str; 2] = ["/usr/bin/newuidmap", "/bin/newuidmap"];
const NEWGIDMAP_CANDIDATES: [&str; 2] = ["/usr/bin/newgidmap", "/bin/newgidmap"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::executor) enum UserMappingRuntime {
    Privileged,
    Rootless {
        effective_uid: u32,
        effective_gid: u32,
        newuidmap: PathBuf,
        newgidmap: PathBuf,
    },
}

impl UserMappingRuntime {
    pub(in crate::executor) fn detect() -> Result<Self> {
        // SAFETY: these credential queries have no pointer arguments or
        // failure return values.
        let (effective_uid, effective_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        if effective_uid == 0 {
            return Ok(Self::Privileged);
        }
        if effective_gid == 0 {
            return Err(namespace_error(
                ErrorCode::PermissionDenied,
                "the rootless Linux executor must not retain effective GID 0",
            ));
        }
        ensure_unprivileged_user_namespaces_enabled()?;
        ensure_no_supplementary_groups("open the rootless Linux executor")?;
        Ok(Self::Rootless {
            effective_uid,
            effective_gid,
            newuidmap: resolve_mapping_helper("newuidmap", &NEWUIDMAP_CANDIDATES)?,
            newgidmap: resolve_mapping_helper("newgidmap", &NEWGIDMAP_CANDIDATES)?,
        })
    }

    pub(in crate::executor) const fn is_rootless(&self) -> bool {
        matches!(self, Self::Rootless { .. })
    }

    pub(in crate::executor) const fn effective_ids(&self) -> Option<(u32, u32)> {
        match self {
            Self::Privileged => None,
            Self::Rootless {
                effective_uid,
                effective_gid,
                ..
            } => Some((*effective_uid, *effective_gid)),
        }
    }
}

pub(in crate::executor) async fn install_user_mappings(
    plan: &NamespacePlan,
    pid: i32,
    runtime: &UserMappingRuntime,
    additional_gids: &[u32],
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
    let runtime = runtime.clone();
    let additional_gids = additional_gids.to_vec();
    tokio::task::spawn_blocking(move || match runtime {
        UserMappingRuntime::Privileged => install_user_mappings_direct(
            pid,
            &uid_mappings,
            &gid_mappings,
            SetgroupsPolicy::RequireAllow,
        ),
        UserMappingRuntime::Rootless {
            effective_uid,
            effective_gid,
            newuidmap,
            newgidmap,
        } => install_user_mappings_with_helpers(
            pid,
            &uid_mappings,
            &gid_mappings,
            &additional_gids,
            effective_uid,
            effective_gid,
            &newuidmap,
            &newgidmap,
        ),
    })
    .await
    .map_err(|join| {
        namespace_error(
            ErrorCode::Internal,
            format!("user namespace mapping worker failed: {join}"),
        )
    })?
}

fn install_user_mappings_direct(
    pid: i32,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
    setgroups_policy: SetgroupsPolicy,
) -> Result<()> {
    let proc_root = distinct_user_namespace_proc_root(pid)?;
    write_mapping_file(&Path::new(&proc_root).join("uid_map"), "UID", uid_mappings)?;
    verify_mapping_file(&Path::new(&proc_root).join("uid_map"), "UID", uid_mappings)?;

    apply_setgroups_policy(&Path::new(&proc_root).join("setgroups"), setgroups_policy)?;

    write_mapping_file(&Path::new(&proc_root).join("gid_map"), "GID", gid_mappings)?;
    verify_mapping_file(&Path::new(&proc_root).join("gid_map"), "GID", gid_mappings)
}

#[allow(clippy::too_many_arguments)]
fn install_user_mappings_with_helpers(
    pid: i32,
    uid_mappings: &[IdMapping],
    gid_mappings: &[IdMapping],
    additional_gids: &[u32],
    effective_uid: u32,
    effective_gid: u32,
    newuidmap: &Path,
    newgidmap: &Path,
) -> Result<()> {
    if !additional_gids.is_empty() {
        return Err(namespace_error(
            ErrorCode::Unsupported,
            "rootless user namespaces use setgroups=deny and cannot apply process.user.additionalGids",
        ));
    }
    validate_rootless_mappings("UID", uid_mappings, effective_uid)?;
    validate_rootless_mappings("GID", gid_mappings, effective_gid)?;
    let proc_root = distinct_user_namespace_proc_root(pid)?;
    run_mapping_helper(newuidmap, "UID", pid, uid_mappings)?;
    verify_mapping_file(&proc_root.join("uid_map"), "UID", uid_mappings)?;
    apply_setgroups_policy(&proc_root.join("setgroups"), SetgroupsPolicy::Deny)?;
    run_mapping_helper(newgidmap, "GID", pid, gid_mappings)?;
    verify_mapping_file(&proc_root.join("gid_map"), "GID", gid_mappings)
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
    install_user_mappings_direct(pid, uid_mappings, gid_mappings, SetgroupsPolicy::Deny)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetgroupsPolicy {
    RequireAllow,
    Deny,
}

pub(in crate::executor) fn apply_supplementary_groups(
    groups: &[u32],
    operation: &str,
) -> Result<()> {
    let policy = match std::fs::read_to_string("/proc/self/setgroups") {
        Ok(policy) => Some(policy),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return apply_supplementary_groups_without_proc(groups, operation, Some(error));
        }
    };
    match policy.as_deref().map(str::trim) {
        Some("allow") => set_supplementary_groups(groups, operation),
        Some("deny") if groups.is_empty() => ensure_no_supplementary_groups(operation),
        Some("deny") => Err(namespace_error(
            ErrorCode::Unsupported,
            format!("cannot {operation} because this rootless user namespace has setgroups=deny"),
        )),
        Some(value) => Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!("user namespace exposes unknown setgroups policy {value:?}"),
        )),
        None => apply_supplementary_groups_without_proc(groups, operation, None),
    }
}

fn apply_supplementary_groups_without_proc(
    groups: &[u32],
    operation: &str,
    policy_error: Option<io::Error>,
) -> Result<()> {
    match set_supplementary_groups(groups, operation) {
        Ok(()) => Ok(()),
        Err(_) if groups.is_empty() => ensure_no_supplementary_groups(operation),
        Err(error) => {
            let detail = policy_error.map_or_else(String::new, |policy_error| {
                format!("; setgroups policy could not be inspected: {policy_error}")
            });
            Err(namespace_error(
                error.code,
                format!("{}{detail}", error.message),
            ))
        }
    }
}

fn set_supplementary_groups(groups: &[u32], operation: &str) -> Result<()> {
    // SAFETY: `groups` is a live bounded slice of Linux gid_t values.
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr().cast()) } == 0 {
        Ok(())
    } else {
        Err(namespace_error(
            ErrorCode::PermissionDenied,
            format!("failed to {operation}: {}", io::Error::last_os_error()),
        ))
    }
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

pub(super) fn parse_mapping_file(path: &Path, contents: &str) -> Result<Vec<IdMapping>> {
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

fn ensure_unprivileged_user_namespaces_enabled() -> Result<()> {
    for (path, disabled_value, setting) in [
        (
            Path::new("/proc/sys/kernel/unprivileged_userns_clone"),
            "0",
            "kernel.unprivileged_userns_clone",
        ),
        (
            Path::new("/proc/sys/user/max_user_namespaces"),
            "0",
            "user.max_user_namespaces",
        ),
    ] {
        let value = match std::fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(namespace_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to inspect {setting}: {error}"),
                ));
            }
        };
        if value.trim() == disabled_value {
            return Err(namespace_error(
                ErrorCode::PermissionDenied,
                format!("rootless user namespaces are disabled by {setting}"),
            ));
        }
    }
    Ok(())
}

fn ensure_no_supplementary_groups(operation: &str) -> Result<()> {
    // SAFETY: a zero-sized query accepts a null pointer and returns the number
    // of supplementary groups attached to the calling thread.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect supplementary groups before attempting to {operation}: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if count == 0 {
        Ok(())
    } else {
        Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!(
                "cannot {operation} while {count} supplementary group(s) are active; launch the executor with supplementary groups cleared"
            ),
        ))
    }
}

fn resolve_mapping_helper(name: &str, candidates: &[&str]) -> Result<PathBuf> {
    for candidate in candidates {
        let path = Path::new(candidate);
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(namespace_error(
                    ErrorCode::FailedPrecondition,
                    format!("failed to inspect rootless mapping helper {candidate}: {error}"),
                ));
            }
        };
        if !metadata.file_type().is_file() {
            return Err(namespace_error(
                ErrorCode::FailedPrecondition,
                format!("rootless mapping helper {candidate} is not a regular file"),
            ));
        }
        if metadata.uid() != 0 {
            return Err(namespace_error(
                ErrorCode::PermissionDenied,
                format!("rootless mapping helper {candidate} is not owned by root"),
            ));
        }
        let mode = metadata.mode();
        if mode & 0o4000 == 0 || mode & 0o001 == 0 || mode & 0o022 != 0 {
            return Err(namespace_error(
                ErrorCode::PermissionDenied,
                format!(
                    "rootless mapping helper {candidate} must be setuid-root, executable by unprivileged users, and not group/world writable"
                ),
            ));
        }
        return Ok(path.to_path_buf());
    }
    Err(namespace_error(
        ErrorCode::Unsupported,
        format!(
            "rootless user namespaces require the setuid-root {name} helper at one of: {}",
            candidates.join(", ")
        ),
    ))
}

fn distinct_user_namespace_proc_root(pid: i32) -> Result<PathBuf> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let target_namespace = proc_root.join("ns/user");
    let target = std::fs::metadata(&target_namespace).map_err(|error| {
        namespace_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to inspect container init user namespace {}: {error}",
                target_namespace.display()
            ),
        )
    })?;
    let current = std::fs::metadata("/proc/self/ns/user").map_err(|error| {
        namespace_error(
            ErrorCode::FailedPrecondition,
            format!("failed to inspect executor user namespace: {error}"),
        )
    })?;
    if target.dev() == current.dev() && target.ino() == current.ino() {
        return Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!("container init PID {pid} did not enter a distinct user namespace"),
        ));
    }
    Ok(proc_root)
}

fn validate_rootless_mappings(kind: &str, mappings: &[IdMapping], effective_id: u32) -> Result<()> {
    if mappings.iter().any(|mapping| mapping.host_id == 0) {
        return Err(namespace_error(
            ErrorCode::PermissionDenied,
            format!("rootless {kind} mappings must never map host ID 0"),
        ));
    }
    let expected_root = IdMapping {
        container_id: 0,
        host_id: effective_id,
        size: 1,
    };
    if mappings
        .iter()
        .filter(|mapping| mapping.container_id == 0)
        .count()
        != 1
        || !mappings.contains(&expected_root)
    {
        return Err(namespace_error(
            ErrorCode::FailedPrecondition,
            format!(
                "rootless {kind} mappings must map container ID 0 exclusively to effective host ID {effective_id} with size 1"
            ),
        ));
    }
    Ok(())
}

fn mapping_helper_arguments(pid: i32, mappings: &[IdMapping]) -> Vec<OsString> {
    let mut arguments = Vec::with_capacity(1 + mappings.len() * 3);
    arguments.push(pid.to_string().into());
    for mapping in mappings {
        arguments.push(mapping.container_id.to_string().into());
        arguments.push(mapping.host_id.to_string().into());
        arguments.push(mapping.size.to_string().into());
    }
    arguments
}

fn run_mapping_helper(path: &Path, kind: &str, pid: i32, mappings: &[IdMapping]) -> Result<()> {
    let output = Command::new(path)
        .args(mapping_helper_arguments(pid, mappings))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| {
            namespace_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to execute {kind} mapping helper {}: {error}",
                    path.display()
                ),
            )
        })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(1_024)
        .collect::<String>();
    let detail = if stderr.is_empty() {
        String::new()
    } else {
        format!(": {stderr}")
    };
    Err(namespace_error(
        ErrorCode::PermissionDenied,
        format!(
            "{kind} mapping helper {} exited with {}{detail}",
            path.display(),
            output.status
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(container_id: u32, host_id: u32, size: u32) -> IdMapping {
        IdMapping {
            container_id,
            host_id,
            size,
        }
    }

    #[test]
    fn rootless_mapping_requires_exact_effective_id_root_entry() {
        validate_rootless_mappings(
            "UID",
            &[mapping(0, 20_000, 1), mapping(1, 300_000, 65_535)],
            20_000,
        )
        .expect("the exact rootless mapping should pass");

        for mappings in [
            vec![mapping(0, 20_000, 2)],
            vec![mapping(0, 20_001, 1)],
            vec![mapping(1, 300_000, 65_535)],
        ] {
            let error = validate_rootless_mappings("UID", &mappings, 20_000)
                .expect_err("an inexact rootless mapping must fail");
            assert_eq!(error.code, ErrorCode::FailedPrecondition);
        }
    }

    #[test]
    fn rootless_mapping_rejects_host_root() {
        let error =
            validate_rootless_mappings("GID", &[mapping(0, 20_000, 1), mapping(1, 0, 1)], 20_000)
                .expect_err("host root must never be mapped");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn helper_arguments_preserve_oci_mapping_order() {
        let arguments =
            mapping_helper_arguments(42, &[mapping(0, 20_000, 1), mapping(1, 300_000, 65_535)]);
        assert_eq!(
            arguments,
            ["42", "0", "20000", "1", "1", "300000", "65535"].map(OsString::from)
        );
    }

    #[test]
    fn rootless_mapping_rejects_additional_groups_before_helpers() {
        let error = install_user_mappings_with_helpers(
            42,
            &[mapping(0, 20_000, 1)],
            &[mapping(0, 20_000, 1)],
            &[7],
            20_000,
            20_000,
            Path::new("/missing/newuidmap"),
            Path::new("/missing/newgidmap"),
        )
        .expect_err("rootless supplementary groups must fail before helper execution");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn mapping_parser_sorts_kernel_rows_for_exact_comparison() {
        let mappings = parse_mapping_file(
            Path::new("/proc/example/uid_map"),
            "1 300000 65535\n0 20000 1\n",
        )
        .expect("mapping rows should parse");
        assert_eq!(
            mappings,
            [mapping(0, 20_000, 1), mapping(1, 300_000, 65_535)]
        );
    }
}
