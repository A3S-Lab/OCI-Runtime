use std::collections::BTreeSet;
use std::path::{Component, Path};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "a3s.oci.krun-runtime-assets.v1";
const RUNTIME_ASSETS_JSON: &str = include_str!("../runtime/runtime-assets.json");
const SUPPORTED_TARGETS: &[(&str, &str, &str)] = &[
    ("windows", "x86_64", "windows-x86_64"),
    ("macos", "aarch64", "macos-aarch64"),
    ("linux", "aarch64", "linux-aarch64"),
    ("linux", "x86_64", "linux-x86_64"),
];

/// Semantic purpose of one exact native runtime file.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RuntimeFileRole {
    Library,
    Firmware,
    ImportLibrary,
}

impl RuntimeFileRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Firmware => "firmware",
            Self::ImportLibrary => "import-library",
        }
    }
}

/// One exact native file carried by a runtime bundle.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeFile {
    pub(crate) role: RuntimeFileRole,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

/// Exact guest-kernel bundle exported by one firmware object.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeKernel {
    pub(crate) size: u64,
    pub(crate) sha256: String,
    pub(crate) guest_load_address: u64,
    pub(crate) entry_address: u64,
}

/// One target-specific, checksum-pinned libkrun runtime bundle.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeBundle {
    pub(crate) target_os: String,
    pub(crate) target_arch: String,
    pub(crate) platform: String,
    pub(crate) archive: String,
    pub(crate) archive_size: u64,
    pub(crate) archive_sha256: String,
    pub(crate) files: Vec<RuntimeFile>,
    pub(crate) kernel: RuntimeKernel,
}

impl RuntimeBundle {
    pub(crate) fn file(&self, role: RuntimeFileRole) -> Option<&RuntimeFile> {
        self.files.iter().find(|file| file.role == role)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAssetManifest {
    schema_version: String,
    bundles: Vec<RuntimeBundle>,
}

static RUNTIME_BUNDLES: OnceLock<Result<Vec<RuntimeBundle>, String>> = OnceLock::new();

pub(crate) fn runtime_bundles() -> Result<&'static [RuntimeBundle], &'static str> {
    RUNTIME_BUNDLES
        .get_or_init(|| parse_runtime_manifest(RUNTIME_ASSETS_JSON))
        .as_ref()
        .map(Vec::as_slice)
        .map_err(String::as_str)
}

pub(crate) fn runtime_bundle(
    target_os: &str,
    target_arch: &str,
) -> Result<Option<&'static RuntimeBundle>, &'static str> {
    Ok(runtime_bundles()?
        .iter()
        .find(|bundle| bundle.target_os == target_os && bundle.target_arch == target_arch))
}

fn parse_runtime_manifest(contents: &str) -> Result<Vec<RuntimeBundle>, String> {
    let manifest: RuntimeAssetManifest = serde_json::from_str(contents)
        .map_err(|error| format!("runtime asset manifest is invalid JSON: {error}"))?;
    validate_runtime_manifest(&manifest)?;
    Ok(manifest.bundles)
}

fn validate_runtime_manifest(manifest: &RuntimeAssetManifest) -> Result<(), String> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "runtime asset manifest schema must be {SCHEMA_VERSION}, found {}",
            manifest.schema_version
        ));
    }
    if manifest.bundles.len() != SUPPORTED_TARGETS.len() {
        return Err(format!(
            "runtime asset manifest must declare exactly {} supported targets, found {}",
            SUPPORTED_TARGETS.len(),
            manifest.bundles.len()
        ));
    }

    let mut targets = BTreeSet::new();
    let mut platforms = BTreeSet::new();
    for bundle in &manifest.bundles {
        let target = (bundle.target_os.as_str(), bundle.target_arch.as_str());
        if !targets.insert(target) {
            return Err(format!(
                "runtime asset manifest contains duplicate target {} {}",
                bundle.target_os, bundle.target_arch
            ));
        }
        if !platforms.insert(bundle.platform.as_str()) {
            return Err(format!(
                "runtime asset manifest contains duplicate platform {}",
                bundle.platform
            ));
        }

        let Some((_, _, expected_platform)) = SUPPORTED_TARGETS
            .iter()
            .find(|(os, arch, _)| *os == bundle.target_os && *arch == bundle.target_arch)
        else {
            return Err(format!(
                "runtime asset manifest declares unsupported target {} {}",
                bundle.target_os, bundle.target_arch
            ));
        };
        if bundle.platform != *expected_platform {
            return Err(format!(
                "runtime asset target {} {} must use platform {expected_platform}, found {}",
                bundle.target_os, bundle.target_arch, bundle.platform
            ));
        }

        validate_archive(bundle)?;
        validate_runtime_files(bundle)?;
        validate_kernel(bundle)?;
    }

    for (target_os, target_arch, _) in SUPPORTED_TARGETS {
        if !targets.contains(&(*target_os, *target_arch)) {
            return Err(format!(
                "runtime asset manifest is missing target {target_os} {target_arch}"
            ));
        }
    }
    Ok(())
}

fn validate_archive(bundle: &RuntimeBundle) -> Result<(), String> {
    if bundle.archive_size == 0 {
        return Err(format!(
            "{} runtime archive size must be positive",
            bundle.platform
        ));
    }
    validate_sha256(
        &bundle.archive_sha256,
        &format!("{} archive", bundle.platform),
    )?;
    validate_relative_path(
        &bundle.archive,
        false,
        &format!("{} archive", bundle.platform),
    )?;

    let expected_prefix = format!("runtime/{}/", bundle.platform);
    if !bundle.archive.starts_with(&expected_prefix) || !bundle.archive.ends_with(".tar.xz") {
        return Err(format!(
            "{} runtime archive must be a .tar.xz file below {expected_prefix}",
            bundle.platform
        ));
    }
    Ok(())
}

fn validate_runtime_files(bundle: &RuntimeBundle) -> Result<(), String> {
    let expected_file_count = if bundle.target_os == "windows" { 3 } else { 2 };
    if bundle.files.len() != expected_file_count {
        return Err(format!(
            "{} runtime bundle must declare exactly {expected_file_count} files, found {}",
            bundle.platform,
            bundle.files.len()
        ));
    }

    let mut roles = BTreeSet::new();
    let mut names = BTreeSet::new();
    for file in &bundle.files {
        if !roles.insert(file.role) {
            return Err(format!(
                "{} runtime bundle contains duplicate {} role",
                bundle.platform,
                file.role.as_str()
            ));
        }
        if !names.insert(file.name.as_str()) {
            return Err(format!(
                "{} runtime bundle contains duplicate file {}",
                bundle.platform, file.name
            ));
        }
        if file.role == RuntimeFileRole::ImportLibrary && bundle.target_os != "windows" {
            return Err(format!(
                "{} runtime bundle may not declare an import library",
                bundle.platform
            ));
        }
        if file.size == 0 {
            return Err(format!(
                "{} runtime file {} size must be positive",
                bundle.platform, file.name
            ));
        }
        validate_relative_path(
            &file.name,
            true,
            &format!("{} runtime file", bundle.platform),
        )?;
        validate_sha256(
            &file.sha256,
            &format!("{} runtime file {}", bundle.platform, file.name),
        )?;
    }

    for role in [RuntimeFileRole::Library, RuntimeFileRole::Firmware] {
        if !roles.contains(&role) {
            return Err(format!(
                "{} runtime bundle is missing the {} role",
                bundle.platform,
                role.as_str()
            ));
        }
    }
    if bundle.target_os == "windows" && !roles.contains(&RuntimeFileRole::ImportLibrary) {
        return Err(format!(
            "{} runtime bundle is missing the import-library role",
            bundle.platform
        ));
    }
    Ok(())
}

fn validate_kernel(bundle: &RuntimeBundle) -> Result<(), String> {
    if bundle.kernel.size == 0 {
        return Err(format!(
            "{} firmware kernel size must be positive",
            bundle.platform
        ));
    }
    validate_sha256(
        &bundle.kernel.sha256,
        &format!("{} firmware kernel", bundle.platform),
    )?;
    if bundle.kernel.guest_load_address == 0 || bundle.kernel.entry_address == 0 {
        return Err(format!(
            "{} firmware kernel addresses must be positive",
            bundle.platform
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, description: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "{description} SHA-256 must contain exactly 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
}

fn validate_relative_path(
    value: &str,
    single_component: bool,
    description: &str,
) -> Result<(), String> {
    let path = Path::new(value);
    let components = path.components().collect::<Vec<_>>();
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || (single_component && components.len() != 1)
    {
        return Err(format!("{description} path is unsafe: {value}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use xz2::read::XzDecoder;

    use super::{
        parse_runtime_manifest, runtime_bundle, runtime_bundles, RuntimeBundle, RuntimeFileRole,
        RUNTIME_ASSETS_JSON,
    };

    #[test]
    fn every_supported_target_has_one_complete_bundle() {
        let bundles = runtime_bundles().expect("checked-in runtime manifest must be valid");
        assert_eq!(bundles.len(), 4);

        for bundle in bundles {
            assert_eq!(
                runtime_bundle(&bundle.target_os, &bundle.target_arch)
                    .expect("checked-in runtime manifest must remain valid"),
                Some(bundle)
            );
            assert!(bundle.file(RuntimeFileRole::Library).is_some());
            assert!(bundle.file(RuntimeFileRole::Firmware).is_some());
            assert_eq!(
                bundle.file(RuntimeFileRole::ImportLibrary).is_some(),
                bundle.target_os == "windows"
            );
        }

        assert!(runtime_bundle("linux", "riscv64")
            .expect("checked-in runtime manifest must remain valid")
            .is_none());
        assert!(runtime_bundle("freebsd", "x86_64")
            .expect("checked-in runtime manifest must remain valid")
            .is_none());
    }

    #[test]
    fn malformed_manifests_fail_closed() {
        assert_manifest_error(
            |manifest| manifest["schema_version"] = Value::String("future".to_string()),
            "schema",
        );
        assert_manifest_error(
            |manifest| {
                manifest["unexpected"] = Value::Bool(true);
            },
            "unknown field",
        );
        assert_manifest_error(
            |manifest| {
                manifest["bundles"][1]["target_os"] = Value::String("windows".to_string());
                manifest["bundles"][1]["target_arch"] = Value::String("x86_64".to_string());
                manifest["bundles"][1]["platform"] = Value::String("windows-x86_64".to_string());
            },
            "duplicate target",
        );
        assert_manifest_error(
            |manifest| {
                manifest["bundles"][2]["files"][1]["role"] = Value::String("library".to_string());
            },
            "duplicate library role",
        );
        assert_manifest_error(
            |manifest| {
                manifest["bundles"][2]["files"][0]["name"] =
                    Value::String("../libkrun.so".to_string());
            },
            "unsafe",
        );
        assert_manifest_error(
            |manifest| {
                manifest["bundles"][2]["archive_sha256"] = Value::String("A".repeat(64));
            },
            "lowercase hexadecimal",
        );
        assert_manifest_error(
            |manifest| {
                manifest["bundles"][2]["kernel"]["entry_address"] = Value::from(0_u64);
            },
            "addresses must be positive",
        );

        let trailing = format!("{RUNTIME_ASSETS_JSON}\ntrue");
        assert!(parse_runtime_manifest(&trailing)
            .expect_err("trailing JSON must fail closed")
            .contains("invalid JSON"));
    }

    #[test]
    fn every_checked_in_archive_matches_its_manifest() {
        for bundle in runtime_bundles().expect("checked-in runtime manifest must be valid") {
            verify_archive(bundle);
        }
    }

    fn assert_manifest_error(mutate: impl FnOnce(&mut Value), expected: &str) {
        let mut manifest: Value =
            serde_json::from_str(RUNTIME_ASSETS_JSON).expect("parse checked-in test fixture");
        mutate(&mut manifest);
        let contents = serde_json::to_string(&manifest).expect("serialize mutated fixture");
        let error = parse_runtime_manifest(&contents).expect_err("invalid manifest must fail");
        assert!(error.contains(expected), "unexpected error: {error}");
    }

    fn verify_archive(bundle: &RuntimeBundle) {
        let archive_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&bundle.archive);
        let metadata = std::fs::metadata(&archive_path).expect("inspect runtime archive");
        assert_eq!(metadata.len(), bundle.archive_size, "{}", bundle.platform);
        assert_eq!(
            sha256_reader(File::open(&archive_path).expect("open runtime archive")),
            bundle.archive_sha256,
            "{}",
            bundle.platform
        );

        let decoder = XzDecoder::new(File::open(&archive_path).expect("open runtime archive"));
        let mut archive = tar::Archive::new(decoder);
        let mut seen = BTreeSet::new();
        for entry in archive.entries().expect("read runtime archive") {
            let mut entry = entry.expect("read runtime entry");
            assert!(entry.header().entry_type().is_file(), "{}", bundle.platform);
            let path = entry.path().expect("read runtime entry path");
            assert_eq!(path.components().count(), 1, "{}", bundle.platform);
            let name = path.to_str().expect("runtime entry path is UTF-8");
            let expected = bundle
                .files
                .iter()
                .find(|file| file.name == name)
                .expect("runtime entry is declared");
            assert!(seen.insert(name.to_string()), "{}", bundle.platform);
            assert_eq!(entry.size(), expected.size, "{}", bundle.platform);
            assert_eq!(
                sha256_reader(&mut entry),
                expected.sha256,
                "{}",
                bundle.platform
            );

            if bundle.target_os == "linux" {
                assert_eq!(entry.header().uid().expect("read entry uid"), 0);
                assert_eq!(entry.header().gid().expect("read entry gid"), 0);
                assert_eq!(entry.header().mtime().expect("read entry mtime"), 0);
            }
        }

        assert_eq!(seen.len(), bundle.files.len(), "{}", bundle.platform);
    }

    fn sha256_reader(mut reader: impl Read) -> String {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).expect("read hashed content");
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        format!("{:x}", hasher.finalize())
    }
}
