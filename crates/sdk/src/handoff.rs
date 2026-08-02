use std::path::{Path, PathBuf};

use crate::{ContainerId, Error, ErrorCode, OperationId, Result};

/// Runtime-root child reserved for operation-scoped bundle ownership handoff.
pub const RUNTIME_BUNDLE_HANDOFF_ROOT_DIRECTORY: &str = "bundle-handoffs";
/// Fixed leaf containing the portable OCI bundle transferred by one create.
pub const RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY: &str = "bundle";

/// Resolve the protected parent shared by every operation-scoped handoff.
pub fn runtime_bundle_handoff_root(runtime_root: impl AsRef<Path>) -> Result<PathBuf> {
    let runtime_root = runtime_root.as_ref();
    if !runtime_root.is_absolute() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "runtime bundle-handoff root must be absolute: {}",
                runtime_root.display()
            ),
        )
        .for_operation("resolve-bundle-handoff"));
    }
    Ok(runtime_root.join(RUNTIME_BUNDLE_HANDOFF_ROOT_DIRECTORY))
}

/// Resolve the only bundle directory accepted for one container/create identity.
///
/// Both identifiers have already been validated as portable path components.
/// The runtime creates and protects the root; a local product prepares the
/// complete portable bundle below this deterministic operation directory.
pub fn runtime_bundle_handoff_directory(
    runtime_root: impl AsRef<Path>,
    container_id: &ContainerId,
    operation_id: &OperationId,
) -> Result<PathBuf> {
    Ok(runtime_bundle_handoff_root(runtime_root)?
        .join(container_id.as_str())
        .join(operation_id.as_str())
        .join(RUNTIME_BUNDLE_HANDOFF_BUNDLE_DIRECTORY))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{ContainerId, ErrorCode, OperationId};

    use super::{runtime_bundle_handoff_directory, runtime_bundle_handoff_root};

    #[test]
    fn layout_is_exact_and_uses_only_validated_components() {
        let root = if cfg!(windows) {
            Path::new(r"C:\a3s-runtime")
        } else {
            Path::new("/var/lib/a3s-oci")
        };
        let container = ContainerId::new("box-1").expect("container ID");
        let operation = OperationId::new("create-7").expect("operation ID");

        assert_eq!(
            runtime_bundle_handoff_directory(root, &container, &operation)
                .expect("handoff directory"),
            root.join("bundle-handoffs/box-1/create-7/bundle")
        );
    }

    #[test]
    fn relative_runtime_root_fails_before_path_construction() {
        let error = runtime_bundle_handoff_root("relative/runtime")
            .expect_err("relative runtime root must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}
