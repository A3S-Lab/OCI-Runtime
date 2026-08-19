use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::{cgroup_error, CgroupSetting};

const MAX_ENTRIES: usize = 256;
const MAX_FILE_NAME_BYTES: usize = 255;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_VALUE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct UnifiedPlan {
    settings: BTreeMap<String, String>,
    controllers: BTreeSet<String>,
}

impl UnifiedPlan {
    pub(super) fn from_oci(unified: Option<&HashMap<String, String>>) -> Result<Self> {
        let Some(unified) = unified else {
            return Ok(Self::default());
        };
        if unified.len() > MAX_ENTRIES {
            return Err(invalid(format!(
                "linux.resources.unified contains more than {MAX_ENTRIES} entries"
            )));
        }

        let mut settings = BTreeMap::new();
        let mut controllers = BTreeSet::new();
        let mut total_value_bytes = 0_usize;
        for (file, value) in unified {
            let controller = validate_file_name(file)?;
            validate_value(file, value)?;
            total_value_bytes = total_value_bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid("linux.resources.unified values exceed the size bound"))?;
            if total_value_bytes > MAX_TOTAL_VALUE_BYTES {
                return Err(invalid(format!(
                    "linux.resources.unified values exceed {MAX_TOTAL_VALUE_BYTES} bytes"
                )));
            }
            settings.insert(file.clone(), value.clone());
            controllers.insert(controller.to_string());
        }
        Ok(Self {
            settings,
            controllers,
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }

    pub(super) fn controllers(&self) -> impl Iterator<Item = &str> {
        self.controllers.iter().map(String::as_str)
    }

    pub(super) fn settings(&self) -> Vec<CgroupSetting> {
        self.settings
            .iter()
            .map(|(file, value)| CgroupSetting::kernel_defined(file.clone(), value.clone()))
            .collect()
    }

    pub(super) fn validate_conflicts(&self, owned_files: &BTreeSet<String>) -> Result<()> {
        if let Some(file) = self
            .settings
            .keys()
            .find(|file| owned_files.contains(*file))
        {
            return Err(invalid(format!(
                "linux.resources.unified key {file:?} conflicts with a typed OCI resource"
            )));
        }
        Ok(())
    }

    pub(super) fn preflight_create(&self, path: &Path) -> Result<()> {
        for file in self.settings.keys() {
            let control = path.join(file);
            let metadata = std::fs::symlink_metadata(&control).map_err(|error| {
                inspect_error(
                    if error.kind() == io::ErrorKind::NotFound {
                        ErrorCode::Unsupported
                    } else {
                        ErrorCode::FailedPrecondition
                    },
                    &control,
                    error,
                )
            })?;
            if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o222 == 0 {
                return Err(cgroup_error(
                    ErrorCode::Unsupported,
                    format!(
                        "unified cgroup control {} is not a writable control file",
                        control.display()
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn validate_file_name(file: &str) -> Result<&str> {
    if file.is_empty() || file.len() > MAX_FILE_NAME_BYTES {
        return Err(invalid(format!(
            "linux.resources.unified key {file:?} must contain 1 to {MAX_FILE_NAME_BYTES} bytes"
        )));
    }
    if !file
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(format!(
            "linux.resources.unified key {file:?} is not one cgroup control-file name"
        )));
    }
    let Some((controller, parameter)) = file.split_once('.') else {
        return Err(invalid(format!(
            "linux.resources.unified key {file:?} has no controller prefix"
        )));
    };
    if controller.is_empty() || parameter.is_empty() {
        return Err(invalid(format!(
            "linux.resources.unified key {file:?} has an empty controller or parameter"
        )));
    }
    if controller == "cgroup" {
        return Err(invalid(format!(
            "linux.resources.unified key {file:?} targets runtime-owned cgroup state"
        )));
    }
    Ok(controller)
}

fn validate_value(file: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_VALUE_BYTES || value.contains('\0') {
        return Err(invalid(format!(
            "linux.resources.unified value for {file:?} must contain 1 to {MAX_VALUE_BYTES} non-NUL bytes"
        )));
    }
    if value.split_ascii_whitespace().next().is_none() {
        return Err(invalid(format!(
            "linux.resources.unified value for {file:?} must not be whitespace-only"
        )));
    }
    Ok(())
}

fn inspect_error(code: ErrorCode, path: &Path, error: io::Error) -> Error {
    cgroup_error(
        code,
        format!(
            "failed to inspect unified cgroup control {}: {error}",
            path.display()
        ),
    )
}

fn invalid(message: impl Into<String>) -> Error {
    cgroup_error(ErrorCode::InvalidArgument, message)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::os::unix::fs::{symlink, PermissionsExt};

    use a3s_oci_sdk::ErrorCode;

    use super::{
        UnifiedPlan, MAX_ENTRIES, MAX_FILE_NAME_BYTES, MAX_TOTAL_VALUE_BYTES, MAX_VALUE_BYTES,
    };

    #[test]
    fn plans_unknown_controller_files_in_deterministic_order() {
        let plan = UnifiedPlan::from_oci(Some(&HashMap::from([
            ("memory.high".to_string(), "1048576".to_string()),
            ("misc.example.limit".to_string(), "7\n8".to_string()),
        ])))
        .expect("unified plan");
        let settings = plan.settings();

        assert_eq!(
            settings
                .iter()
                .map(|setting| (setting.file(), setting.value()))
                .collect::<Vec<_>>(),
            [("memory.high", "1048576"), ("misc.example.limit", "7\n8"),]
        );
        assert_eq!(plan.controllers().collect::<Vec<_>>(), ["memory", "misc"]);
    }

    #[test]
    fn rejects_unsafe_or_runtime_owned_control_names() {
        for file in [
            "",
            "memory",
            ".max",
            "memory.",
            "memory/max",
            "../memory.max",
            "memory high",
            "mémoire.high",
            "cgroup.freeze",
        ] {
            let error =
                UnifiedPlan::from_oci(Some(&HashMap::from([(file.to_string(), "1".to_string())])))
                    .expect_err("unsafe unified key must fail planning");
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{file:?}");
        }
    }

    #[test]
    fn bounds_entry_count_and_values() {
        for value in [
            String::new(),
            " \n\t".to_string(),
            "contains\0nul".to_string(),
            "x".repeat(MAX_VALUE_BYTES + 1),
        ] {
            let error =
                UnifiedPlan::from_oci(Some(&HashMap::from([("memory.high".to_string(), value)])))
                    .expect_err("invalid unified value must fail planning");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }

        let entries = (0..=MAX_ENTRIES)
            .map(|index| (format!("misc.limit{index}"), "1".to_string()))
            .collect::<HashMap<_, _>>();
        let error = UnifiedPlan::from_oci(Some(&entries))
            .expect_err("oversized unified map must fail planning");
        assert_eq!(error.code, ErrorCode::InvalidArgument);

        let values = (0..=(MAX_TOTAL_VALUE_BYTES / MAX_VALUE_BYTES))
            .map(|index| (format!("misc.limit{index}"), "x".repeat(MAX_VALUE_BYTES)))
            .collect::<HashMap<_, _>>();
        let error = UnifiedPlan::from_oci(Some(&values))
            .expect_err("oversized unified value total must fail planning");
        assert_eq!(error.code, ErrorCode::InvalidArgument);

        let oversized_key = format!("misc.{}", "x".repeat(MAX_FILE_NAME_BYTES));
        let error = UnifiedPlan::from_oci(Some(&HashMap::from([(oversized_key, "1".to_string())])))
            .expect_err("oversized unified key must fail planning");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn rejects_typed_resource_file_conflicts() {
        let plan = UnifiedPlan::from_oci(Some(&HashMap::from([(
            "memory.max".to_string(),
            "1048576".to_string(),
        )])))
        .expect("unified plan");
        let error = plan
            .validate_conflicts(&BTreeSet::from(["memory.max".to_string()]))
            .expect_err("typed/unified conflict must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn preflights_readable_and_write_only_control_files() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        let control = directory.path().join("memory.high");
        std::fs::write(&control, "max").expect("unified control");
        let plan = UnifiedPlan::from_oci(Some(&HashMap::from([(
            "memory.high".to_string(),
            "1048576".to_string(),
        )])))
        .expect("unified plan");

        plan.preflight_create(directory.path())
            .expect("writable state file");
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o200))
            .expect("write-only control");
        plan.preflight_create(directory.path())
            .expect("write-only cgroup control");
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o444))
            .expect("read-only control");
        let error = plan
            .preflight_create(directory.path())
            .expect_err("read-only state file must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn rejects_missing_or_non_file_controls_during_create_preflight() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        let plan = UnifiedPlan::from_oci(Some(&HashMap::from([(
            "memory.high".to_string(),
            "1048576".to_string(),
        )])))
        .expect("unified plan");
        let error = plan
            .preflight_create(directory.path())
            .expect_err("missing unified control must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);

        let target = directory.path().join("target");
        std::fs::write(&target, "max").expect("symlink target");
        symlink(&target, directory.path().join("memory.high")).expect("control symlink");
        let error = plan
            .preflight_create(directory.path())
            .expect_err("symlinked unified control must fail");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }
}
