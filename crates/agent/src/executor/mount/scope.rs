use std::io;
use std::path::{Component, Path};

use a3s_oci_sdk::Result;

use super::{permission_denied, MountPlan};
use crate::executor::RootfsScope;

/// Reject bind-source syntax that can name content outside a bundle-only executor.
pub(in crate::executor) fn validate_bundle_source_syntax(
    plans: &[MountPlan],
    rootfs_scope: RootfsScope,
) -> Result<()> {
    if rootfs_scope != RootfsScope::BundleOnly {
        return Ok(());
    }
    for plan in plans.iter().filter(|plan| plan.bind) {
        let source = plan.source.as_deref().ok_or_else(|| {
            permission_denied(format!(
                "mounts[{}].source is required for a bundle-scoped bind mount",
                plan.index
            ))
        })?;
        if source.is_absolute() {
            return Err(permission_denied(format!(
                "mounts[{}].source must be relative for bundle-scoped execution: {}",
                plan.index,
                source.display()
            )));
        }
        if source.as_os_str().is_empty()
            || source
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(permission_denied(format!(
                "mounts[{}].source must be a normalized relative path inside its guest bundle: {}",
                plan.index,
                source.display()
            )));
        }
    }
    Ok(())
}

/// Re-resolve existing bind sources and reject every symbolic or escaping path.
pub(in crate::executor) fn validate_bundle_scoped_sources(
    plans: &[MountPlan],
    bundle_directory: &Path,
    rootfs_scope: RootfsScope,
) -> Result<()> {
    validate_bundle_source_syntax(plans, rootfs_scope)?;
    if rootfs_scope != RootfsScope::BundleOnly {
        return Ok(());
    }
    let canonical_bundle = bundle_directory.canonicalize().map_err(|error| {
        permission_denied(format!(
            "failed to resolve bundle-scoped mount root {}: {error}",
            bundle_directory.display()
        ))
    })?;
    for plan in plans.iter().filter(|plan| plan.bind) {
        let source = plan.source.as_deref().ok_or_else(|| {
            permission_denied(format!(
                "mounts[{}].source is required for a bundle-scoped bind mount",
                plan.index
            ))
        })?;
        let candidate = canonical_bundle.join(source);
        let metadata = match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // A source produced by an earlier mount does not exist at this
                // pre-namespace boundary. Its normalized relative syntax still
                // confines the later lookup below the canonical bundle.
                continue;
            }
            Err(error) => {
                return Err(permission_denied(format!(
                    "failed to inspect mounts[{}].source {}: {error}",
                    plan.index,
                    candidate.display()
                )));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(permission_denied(format!(
                "mounts[{}].source must not be a symbolic link: {}",
                plan.index,
                candidate.display()
            )));
        }
        let canonical_source = candidate.canonicalize().map_err(|error| {
            permission_denied(format!(
                "failed to resolve mounts[{}].source {}: {error}",
                plan.index,
                candidate.display()
            ))
        })?;
        if canonical_source != candidate
            || (canonical_source != canonical_bundle
                && !canonical_source.starts_with(&canonical_bundle))
        {
            return Err(permission_denied(format!(
                "mounts[{}].source must resolve without symbolic links inside its guest bundle {}: {}",
                plan.index,
                canonical_bundle.display(),
                canonical_source.display()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use a3s_oci_sdk::{ErrorCode, IoMode, OciBundle, ProcessIo};
    use serde_json::json;
    use tempfile::tempdir;

    use super::{validate_bundle_scoped_sources, validate_bundle_source_syntax};
    use crate::executor::plan::InitPlan;
    use crate::executor::RootfsScope;

    fn plan(bundle_directory: &Path, source: &str) -> InitPlan {
        let config = json!({
            "ociVersion": "1.3.0",
            "root": {"path": "rootfs", "readonly": false},
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/true"],
                "cwd": "/",
                "noNewPrivileges": true
            },
            "mounts": [{
                "destination": "/data",
                "type": "bind",
                "source": source,
                "options": ["bind"]
            }],
            "linux": {"namespaces": [{"type": "mount"}]}
        });
        let bundle = OciBundle::from_json(bundle_directory.to_path_buf(), config.to_string())
            .expect("schema-valid bundle");
        InitPlan::from_bundle(
            &bundle,
            &ProcessIo {
                stdin: IoMode::Null,
                stdout: IoMode::Null,
                stderr: IoMode::Null,
                terminal_size: None,
            },
        )
        .expect("mount plan")
    }

    #[test]
    fn bundle_scope_rejects_absolute_and_traversing_bind_sources() {
        let temporary = tempdir().expect("temporary bundle");
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).expect("bundle directory");

        for source in ["/etc", "../runtime", "rootfs/../runtime", "."] {
            let error = validate_bundle_source_syntax(
                &plan(&bundle, source).mounts,
                RootfsScope::BundleOnly,
            )
            .expect_err("escaping syntax must fail closed");
            assert_eq!(error.code, ErrorCode::PermissionDenied, "{source}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn bundle_scope_rejects_a_bind_symlink_even_when_it_resolves_inside() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary bundle");
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).expect("bundle directory");
        fs::create_dir(bundle.join("source")).expect("real source");
        symlink("source", bundle.join("linked")).expect("linked source");
        let plan = plan(&bundle, "linked");

        let error = validate_bundle_scoped_sources(&plan.mounts, &bundle, RootfsScope::BundleOnly)
            .expect_err("symbolic bind source must fail closed");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn native_scope_retains_explicit_absolute_bind_semantics() {
        let temporary = tempdir().expect("temporary bundle");
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).expect("bundle directory");
        let plan = plan(&bundle, "/srv/authorized");

        validate_bundle_source_syntax(&plan.mounts, RootfsScope::NativeAbsolute)
            .expect("native absolute source");
        validate_bundle_scoped_sources(&plan.mounts, &bundle, RootfsScope::NativeAbsolute)
            .expect("native source scope");
    }
}
