use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::ContainerTarget;

const BUNDLE_HANDOFF_DIRECTORY: &str = "bundle-handoffs";
const CONSOLE_DIRECTORY: &str = "console";
const RECOVERY_DIRECTORY: &str = "recovery";
const SHARE_DIRECTORY: &str = "shares";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RuntimeInventory {
    pub(super) bundle_handoffs_clean: bool,
    pub(super) runtime_shares_clean: bool,
    pub(super) recovery_reports_clean: bool,
    pub(super) console_files: BTreeSet<PathBuf>,
}

pub(super) fn inventory(runtime_root: &Path) -> Result<RuntimeInventory, String> {
    Ok(RuntimeInventory {
        bundle_handoffs_clean: directory_is_empty(&runtime_root.join(BUNDLE_HANDOFF_DIRECTORY))?,
        runtime_shares_clean: directory_is_empty(&runtime_root.join(SHARE_DIRECTORY))?,
        recovery_reports_clean: directory_is_empty(&runtime_root.join(RECOVERY_DIRECTORY))?,
        console_files: files(&runtime_root.join(CONSOLE_DIRECTORY))?,
    })
}

pub(super) fn recovery_report_path(
    runtime_root: &Path,
    target: &ContainerTarget,
) -> Result<PathBuf, String> {
    let generation = target
        .generation
        .ok_or_else(|| "recovery report lookup requires an exact generation".to_string())?;
    Ok(runtime_root
        .join(RECOVERY_DIRECTORY)
        .join(format!("{}-{}.json", target.id, generation.0)))
}

pub(super) fn durable_container_removed(
    service_root: &Path,
    target: &ContainerTarget,
) -> Result<bool, String> {
    path_absent(
        &service_root
            .join("state")
            .join("containers")
            .join(target.id.as_str()),
    )
}

pub(super) fn socket_absent(service_root: &Path) -> Result<bool, String> {
    path_absent(&service_root.join("runtime.sock"))
}

fn directory_is_empty(path: &Path) -> Result<bool, String> {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries
            .next()
            .transpose()
            .map(|entry| entry.is_none())
            .map_err(|error| format!("failed to enumerate {}: {error}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("failed to enumerate {}: {error}", path.display())),
    }
}

fn files(path: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(format!("failed to enumerate {}: {error}", path.display())),
    };
    let mut files = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!("failed to inspect entry below {}: {error}", path.display())
        })?;
        let metadata = entry
            .metadata()
            .map_err(|error| format!("failed to inspect {}: {error}", entry.path().display()))?;
        if metadata.is_file() {
            files.insert(entry.path());
        }
    }
    Ok(files)
}

fn path_absent(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!("failed to inspect {}: {error}", path.display())),
    }
}
