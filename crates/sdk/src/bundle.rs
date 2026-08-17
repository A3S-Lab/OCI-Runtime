use std::path::{Path, PathBuf};

#[cfg(windows)]
use cap_fs_ext::OsMetadataExt as _;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use oci_spec::runtime::Spec;
use semver::Version;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::{
    Error, ErrorCode, OciSchemaDocument, OciSchemaValidator, OciSemanticPhase,
    OciSemanticValidator, Result, Signal, OCI_IMAGE_STOP_SIGNAL_ANNOTATION,
};

/// File containing the OCI runtime configuration in a bundle.
pub const CONFIG_FILE_NAME: &str = "config.json";
/// Maximum accepted `config.json` size.
pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
/// Oldest OCI Runtime Specification version recognized by this SDK.
pub const OCI_RUNTIME_SPEC_VERSION_MIN: &str = "1.0.0";
/// Newest OCI Runtime Specification version recognized by this SDK.
pub const OCI_RUNTIME_SPEC_VERSION_MAX: &str = "1.3.0";

/// Immutable, digest-bound OCI bundle submitted to the runtime service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciBundle {
    directory: PathBuf,
    config_digest: String,
    config_json: String,
    spec: Spec,
}

impl OciBundle {
    /// Load and strictly decode `config.json` from an existing bundle.
    pub async fn load(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = tokio::fs::canonicalize(directory.as_ref())
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "failed to resolve OCI bundle {}: {error}",
                        directory.as_ref().display()
                    ),
                )
                .for_operation("load-bundle")
            })?;

        let metadata = tokio::fs::metadata(&directory).await.map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to inspect OCI bundle {}: {error}",
                    directory.display()
                ),
            )
            .for_operation("load-bundle")
        })?;
        if !metadata.is_dir() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("OCI bundle is not a directory: {}", directory.display()),
            )
            .for_operation("load-bundle"));
        }

        let config_path = directory.join(CONFIG_FILE_NAME);
        let (file, config_size) = open_root_config(&directory).await?;
        if config_size > MAX_CONFIG_BYTES {
            return Err(config_too_large(&config_path, config_size));
        }

        let mut bytes = Vec::with_capacity(config_size as usize);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "failed to read OCI configuration {}: {error}",
                        config_path.display()
                    ),
                )
                .for_operation("load-bundle")
            })?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(config_too_large(&config_path, bytes.len() as u64));
        }

        let config_json = String::from_utf8(bytes).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "OCI configuration {} is not valid UTF-8: {error}",
                    config_path.display()
                ),
            )
            .for_operation("load-bundle")
        })?;
        Self::from_json(directory, config_json)
    }

    /// Construct an immutable bundle from an already decoded complete OCI spec.
    pub fn from_spec(directory: impl Into<PathBuf>, spec: Spec) -> Result<Self> {
        let mut value = serde_json::to_value(&spec).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to encode OCI configuration: {error}"),
            )
            .for_operation("build-bundle")
        })?;
        if let Some(process) = value.get_mut("process") {
            crate::process_serde::normalize_for_wire(process);
        }
        let config_json = serde_json::to_string(&value).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to encode OCI configuration: {error}"),
            )
            .for_operation("build-bundle")
        })?;
        Self::from_json(directory, config_json)
    }

    /// Construct an immutable bundle from exact UTF-8 `config.json` contents.
    ///
    /// Whitespace and property ordering are retained so the digest and
    /// durable snapshot bind the exact caller-provided document.
    pub fn from_json(
        directory: impl Into<PathBuf>,
        config_json: impl Into<String>,
    ) -> Result<Self> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("OCI bundle path must be absolute: {}", directory.display()),
            )
            .for_operation("build-bundle"));
        }

        let config_json = config_json.into();
        let config_bytes = config_json.as_bytes();
        if config_bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(config_too_large(
                &directory.join(CONFIG_FILE_NAME),
                config_bytes.len() as u64,
            ));
        }
        let spec = decode_spec(config_bytes, &directory.join(CONFIG_FILE_NAME))?;

        Ok(Self {
            directory,
            config_digest: digest(config_bytes),
            config_json,
            spec,
        })
    }

    /// Canonical absolute bundle directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// SHA-256 digest of the exact loaded configuration bytes.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Exact validated `config.json` text retained for durable snapshotting.
    #[must_use]
    pub fn config_json(&self) -> &str {
        &self.config_json
    }

    /// Exact validated `config.json` bytes retained for durable snapshotting.
    #[must_use]
    pub fn config_bytes(&self) -> &[u8] {
        self.config_json.as_bytes()
    }

    /// Complete typed OCI runtime configuration.
    #[must_use]
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Resolve the validated OCI image stop-signal annotation for this bundle.
    ///
    /// The result is a Linux signal number on every host platform because A3S
    /// utility VMs and the native driver execute Linux OCI workloads.
    pub fn configured_stop_signal(&self) -> Result<Option<Signal>> {
        let Some(value) = self
            .spec
            .annotations()
            .as_ref()
            .and_then(|annotations| annotations.get(OCI_IMAGE_STOP_SIGNAL_ANNOTATION))
        else {
            return Ok(None);
        };
        let number = crate::image_annotation::parse_stop_signal(value).ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "validated OCI image stop signal could not be resolved",
            )
            .for_operation("resolve-oci-image-stop-signal")
        })?;
        Signal::new(number).map(Some)
    }

    /// Revalidate this immutable bundle for one OCI lifecycle phase.
    ///
    /// Construction has already applied configuration semantics, so create is
    /// a no-op for the immutable value. Start reparses the retained exact
    /// document and additionally requires a runnable process.
    pub fn validate_for_phase(&self, phase: OciSemanticPhase) -> Result<()> {
        if phase != OciSemanticPhase::Start {
            return Ok(());
        }
        let raw = serde_json::from_str(&self.config_json).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("validated OCI configuration could not be decoded again: {error}"),
            )
            .for_operation("validate-bundle")
        })?;
        OciSemanticValidator::new()?.validate(phase, &raw)
    }
}

async fn open_root_config(directory: &Path) -> Result<(tokio::fs::File, u64)> {
    let directory = directory.to_path_buf();
    let config_path = directory.join(CONFIG_FILE_NAME);
    let (file, size) = tokio::task::spawn_blocking(move || {
        let root = Dir::open_ambient_dir(&directory, ambient_authority()).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to pin OCI bundle directory {}: {error}",
                    directory.display()
                ),
            )
            .for_operation("load-bundle")
        })?;
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = root
            .open_with(CONFIG_FILE_NAME, &options)
            .map_err(|error| {
                Error::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "OCI configuration is missing or not a plain file: {}: {error}",
                        config_path.display()
                    ),
                )
                .for_operation("load-bundle")
            })?;
        let metadata = file.metadata().map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to inspect OCI configuration {}: {error}",
                    config_path.display()
                ),
            )
            .for_operation("load-bundle")
        })?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata_is_reparse_point(&metadata)
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "OCI configuration is not a plain file: {}",
                    config_path.display()
                ),
            )
            .for_operation("load-bundle"));
        }
        Ok((file.into_std(), metadata.len()))
    })
    .await
    .map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("OCI bundle configuration task failed: {error}"),
        )
        .for_operation("load-bundle")
    })??;
    Ok((tokio::fs::File::from_std(file), size))
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &cap_std::fs::Metadata) -> bool {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn metadata_is_reparse_point(_metadata: &cap_std::fs::Metadata) -> bool {
    false
}

impl Serialize for OciBundle {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerializedOciBundleRef {
            directory: &self.directory,
            config_digest: &self.config_digest,
            config_json: &self.config_json,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OciBundle {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serialized = SerializedOciBundle::deserialize(deserializer)?;
        let bundle = Self::from_json(serialized.directory, serialized.config_json)
            .map_err(de::Error::custom)?;
        if serialized.config_digest != bundle.config_digest {
            return Err(de::Error::custom(format!(
                "OCI configuration digest mismatch: expected {}, found {}",
                bundle.config_digest, serialized.config_digest
            )));
        }
        Ok(bundle)
    }
}

#[derive(Serialize)]
struct SerializedOciBundleRef<'a> {
    directory: &'a Path,
    config_digest: &'a str,
    config_json: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedOciBundle {
    directory: PathBuf,
    config_digest: String,
    config_json: String,
}

fn decode_spec(bytes: &[u8], path: &Path) -> Result<Spec> {
    let raw: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid OCI configuration {}: {error}", path.display()),
        )
        .for_operation("load-bundle")
    })?;
    OciSchemaValidator::new()?.validate(OciSchemaDocument::Configuration, &raw)?;
    if let Some(object) = raw.as_object() {
        let invalid_top_level_mappings = ["uidMappings", "gidMappings"]
            .into_iter()
            .filter(|field| object.contains_key(*field))
            .collect::<Vec<_>>();
        if !invalid_top_level_mappings.is_empty() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "OCI configuration {} contains non-standard top-level properties: {}",
                    path.display(),
                    invalid_top_level_mappings.join(", ")
                ),
            )
            .for_operation("load-bundle"));
        }
    }

    let mut typed = raw.clone();
    if let Some(process) = typed.get_mut("process") {
        crate::process_serde::normalize_for_typed_model(process);
    }
    let typed_bytes = serde_json::to_vec(&typed).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!(
                "failed to prepare typed OCI configuration {}: {error}",
                path.display()
            ),
        )
        .for_operation("load-bundle")
    })?;
    let mut deserializer = serde_json::Deserializer::from_slice(&typed_bytes);
    let mut unknown = Vec::new();
    let spec: Spec = serde_ignored::deserialize(&mut deserializer, |field| {
        unknown.push(field.to_string());
    })
    .map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid OCI configuration {}: {error}", path.display()),
        )
        .for_operation("load-bundle")
    })?;
    deserializer.end().map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "trailing data in OCI configuration {}: {error}",
                path.display()
            ),
        )
        .for_operation("load-bundle")
    })?;

    unknown.sort();
    unknown.dedup();
    if !unknown.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "OCI configuration {} contains unknown properties: {}",
                path.display(),
                unknown.join(", ")
            ),
        )
        .for_operation("load-bundle"));
    }

    validate_version(&spec)?;
    OciSemanticValidator::new()?.validate_schema_valid(OciSemanticPhase::Configuration, &raw)?;

    Ok(spec)
}

fn validate_version(spec: &Spec) -> Result<()> {
    let version = Version::parse(spec.version()).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "invalid OCI specification version {:?}: {error}",
                spec.version()
            ),
        )
        .for_operation("validate-bundle")
    })?;
    let minimum = Version::new(1, 0, 0);
    let maximum = Version::new(1, 3, 0);
    if version < minimum || version > maximum {
        return Err(Error::new(
            ErrorCode::Unsupported,
            format!(
                "OCI specification version {version} is outside the recognized range \
                 {OCI_RUNTIME_SPEC_VERSION_MIN} through {OCI_RUNTIME_SPEC_VERSION_MAX}"
            ),
        )
        .for_operation("validate-bundle"));
    }
    Ok(())
}

fn config_too_large(path: &Path, actual: u64) -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        format!(
            "OCI configuration {} is {actual} bytes; maximum is {MAX_CONFIG_BYTES}",
            path.display()
        ),
    )
    .for_operation("load-bundle")
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use oci_spec::runtime::Spec;
    use serde_json::json;

    use super::{OciBundle, OCI_RUNTIME_SPEC_VERSION_MAX};
    use crate::{ErrorCode, OciSemanticPhase};

    fn complete_v1_3_fixture() -> serde_json::Value {
        json!({
            "ociVersion": OCI_RUNTIME_SPEC_VERSION_MAX,
            "process": {
                "terminal": false,
                "user": { "uid": 1000, "gid": 1000 },
                "args": ["/bin/sh", "-c", "id"],
                "env": ["PATH=/usr/bin:/bin"],
                "cwd": "/",
                "noNewPrivileges": true
            },
            "root": { "path": "rootfs", "readonly": true },
            "hostname": "sdk-fixture",
            "mounts": [{
                "destination": "/proc",
                "type": "proc",
                "source": "proc",
                "options": ["nosuid", "noexec", "nodev"]
            }],
            "linux": {
                "namespaces": [
                    { "type": "pid" },
                    { "type": "mount" },
                    { "type": "uts" }
                ],
                "resources": {
                    "memory": { "limit": 134217728 },
                    "pids": { "limit": 64 }
                },
                "intelRdt": {
                    "closID": "a3s",
                    "enableMonitoring": true
                },
                "maskedPaths": ["/proc/kcore"],
                "readonlyPaths": ["/proc/sys"]
            },
            "annotations": {
                "dev.a3s.test": "full-spec-pass-through",
                "com.example.empty": "",
                "com.example.structured": "{\"nested\":true}"
            }
        })
    }

    #[tokio::test]
    async fn loads_v1_3_fields_without_losing_them() {
        let temporary = tempfile::tempdir().expect("create temporary bundle");
        let config = complete_v1_3_fixture();
        let config_json = serde_json::to_string_pretty(&config).expect("encode fixture");
        std::fs::write(temporary.path().join("config.json"), &config_json).expect("write fixture");

        let bundle = OciBundle::load(temporary.path())
            .await
            .expect("load complete OCI 1.3 fixture");
        let encoded = serde_json::to_value(bundle.spec()).expect("encode loaded spec");

        assert_eq!(
            encoded["linux"]["intelRdt"]["enableMonitoring"],
            json!(true)
        );
        assert_eq!(
            encoded["annotations"]["dev.a3s.test"],
            json!("full-spec-pass-through")
        );
        assert_eq!(encoded["annotations"]["com.example.empty"], json!(""));
        assert_eq!(
            encoded["annotations"]["com.example.structured"],
            json!("{\"nested\":true}")
        );
        assert!(bundle.config_digest().starts_with("sha256:"));
        assert_eq!(bundle.config_json(), config_json);
        assert_eq!(bundle.config_bytes(), config_json.as_bytes());
        assert!(bundle.directory().is_absolute());
    }

    #[tokio::test]
    async fn requires_config_json_at_bundle_root() {
        let temporary = tempfile::tempdir().expect("create temporary bundle");
        let nested = temporary.path().join("nested");
        std::fs::create_dir(&nested).expect("create nested directory");
        let config = serde_json::to_vec(&complete_v1_3_fixture()).expect("encode fixture");
        std::fs::write(temporary.path().join("configuration.json"), &config)
            .expect("write wrong configuration name");
        std::fs::write(nested.join("config.json"), config).expect("write nested configuration");

        let error = OciBundle::load(temporary.path())
            .await
            .expect_err("only a root config.json may define the bundle");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("config.json"));

        std::fs::create_dir(temporary.path().join("config.json"))
            .expect("create directory at configuration path");
        let error = OciBundle::load(temporary.path())
            .await
            .expect_err("bundle config.json must be a plain file");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("not a plain file"));
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn rejects_symlinked_config_json() {
        let temporary = tempfile::tempdir().expect("create temporary directory");
        let bundle = temporary.path().join("bundle");
        std::fs::create_dir(&bundle).expect("create bundle directory");
        let external = temporary.path().join("external-config.json");
        std::fs::write(
            &external,
            serde_json::to_vec(&complete_v1_3_fixture()).expect("encode fixture"),
        )
        .expect("write external configuration");
        create_file_symlink(&external, &bundle.join("config.json"));

        let error = OciBundle::load(&bundle)
            .await
            .expect_err("bundle config.json must be a plain file in the bundle root");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("not a plain file"));
    }

    #[cfg(unix)]
    fn create_file_symlink(source: &Path, destination: &Path) {
        std::os::unix::fs::symlink(source, destination)
            .expect("link external configuration into bundle");
    }

    #[cfg(windows)]
    fn create_file_symlink(source: &Path, destination: &Path) {
        std::os::windows::fs::symlink_file(source, destination)
            .expect("link external configuration into bundle");
    }

    #[tokio::test]
    async fn rejects_unknown_configuration_properties() {
        let temporary = tempfile::tempdir().expect("create temporary bundle");
        let mut config = complete_v1_3_fixture();
        config["unknownSecurityControl"] = json!(true);
        std::fs::write(
            temporary.path().join("config.json"),
            serde_json::to_vec(&config).expect("encode fixture"),
        )
        .expect("write fixture");

        let error = OciBundle::load(temporary.path())
            .await
            .expect_err("unknown fields must not be ignored");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("unknownSecurityControl"));
    }

    #[tokio::test]
    async fn rejects_non_standard_top_level_id_mappings() {
        let temporary = tempfile::tempdir().expect("create temporary bundle");
        let mut config = complete_v1_3_fixture();
        config["uidMappings"] = json!([{
            "containerID": 0,
            "hostID": 1000,
            "size": 1
        }]);
        std::fs::write(
            temporary.path().join("config.json"),
            serde_json::to_vec(&config).expect("encode fixture"),
        )
        .expect("write fixture");

        let error = OciBundle::load(temporary.path())
            .await
            .expect_err("deprecated non-standard top-level field must be rejected");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("uidMappings"));
    }

    #[test]
    fn rejects_relative_in_memory_bundle_path() {
        let spec = serde_json::from_value(complete_v1_3_fixture()).expect("decode fixture");
        let error = OciBundle::from_spec(Path::new("relative/bundle"), spec)
            .expect_err("relative path must be rejected");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn rejects_missing_specification_version() {
        let mut fixture = complete_v1_3_fixture();
        fixture
            .as_object_mut()
            .expect("configuration object")
            .remove("ociVersion");
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("bundle");

        let error = OciBundle::from_json(
            absolute,
            serde_json::to_string(&fixture).expect("encode fixture"),
        )
        .expect_err("ociVersion must be required");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("ociVersion"));
    }

    #[test]
    fn rejects_non_semver_specification_version() {
        let mut fixture = complete_v1_3_fixture();
        fixture["ociVersion"] = json!("1.3");
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("bundle");

        let error = OciBundle::from_json(
            absolute,
            serde_json::to_string(&fixture).expect("encode fixture"),
        )
        .expect_err("ociVersion must use SemVer 2.0.0 syntax");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("invalid OCI specification version"));
    }

    #[test]
    fn rejects_future_specification_version() {
        let mut fixture = complete_v1_3_fixture();
        fixture["ociVersion"] = json!("1.4.0");
        let spec = serde_json::from_value(fixture).expect("decode fixture");
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("bundle");

        let error =
            OciBundle::from_spec(absolute, spec).expect_err("future version must be rejected");
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn typed_model_preserves_every_explicit_field_in_upstream_linux_fixtures() {
        const FIXTURES: &[(&str, &str)] = &[
            (
                "linux-netdevice.json",
                include_str!(
                    "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/linux-netdevice.json"
                ),
            ),
            (
                "linux-rdma.json",
                include_str!(
                    "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/linux-rdma.json"
                ),
            ),
            (
                "minimal-for-start.json",
                include_str!(
                    "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/minimal-for-start.json"
                ),
            ),
            (
                "minimal.json",
                include_str!(
                    "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/minimal.json"
                ),
            ),
        ];

        for (name, source) in FIXTURES {
            let original: serde_json::Value =
                serde_json::from_str(source).expect("upstream fixture must be JSON");
            let spec: Spec = serde_json::from_str(source)
                .unwrap_or_else(|error| panic!("{name} must decode without loss: {error}"));
            let encoded = serde_json::to_value(spec).expect("encode decoded OCI spec");
            assert_explicit_fields_preserved(&original, &encoded, "");
        }
    }

    #[test]
    fn bundle_round_trip_preserves_standard_scheduler_flag_names() {
        let mut fixture = complete_v1_3_fixture();
        fixture["process"]["scheduler"] = json!({
            "policy": "SCHED_DEADLINE",
            "flags": [
                "SCHED_FLAG_RESET_ON_FORK",
                "SCHED_FLAG_DL_OVERRUN"
            ],
            "runtime": 1024,
            "deadline": 2048,
            "period": 4096
        });
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("scheduler-bundle");
        let config_json = serde_json::to_string(&fixture).expect("encode scheduler fixture");
        let bundle = OciBundle::from_json(&absolute, config_json.clone())
            .expect("decode standard scheduler flags");
        let flags = bundle
            .spec()
            .process()
            .as_ref()
            .and_then(|process| process.scheduler().as_ref())
            .and_then(|scheduler| scheduler.flags().as_deref())
            .expect("typed scheduler flags");
        assert_eq!(flags.len(), 2);
        assert_eq!(bundle.config_json(), config_json);

        let rebuilt = OciBundle::from_spec(absolute, bundle.spec().clone())
            .expect("rebuild standard scheduler bundle");
        let rebuilt: serde_json::Value =
            serde_json::from_str(rebuilt.config_json()).expect("decode rebuilt bundle");
        assert_eq!(
            rebuilt["process"]["scheduler"]["flags"],
            json!(["SCHED_FLAG_RESET_ON_FORK", "SCHED_FLAG_DL_OVERRUN"])
        );
    }

    #[test]
    fn resolves_validated_image_stop_signal() {
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("image-stop-signal-bundle");

        for (source, expected) in [("SIGTERM", 15), ("15", 15), ("SIGRTMIN+3", 37)] {
            let bundle = OciBundle::from_json(
                &absolute,
                format!(
                    r#"{{"ociVersion":"1.3.0","root":{{"path":"rootfs"}},"annotations":{{"org.opencontainers.image.stopSignal":"{source}"}}}}"#
                ),
            )
            .expect("valid OCI image stop signal");
            assert_eq!(
                bundle
                    .configured_stop_signal()
                    .expect("resolve validated stop signal")
                    .expect("configured stop signal")
                    .get(),
                expected
            );
        }

        let unconfigured = OciBundle::from_json(
            absolute,
            r#"{"ociVersion":"1.3.0","root":{"path":"rootfs"}}"#,
        )
        .expect("bundle without image stop signal");
        assert_eq!(
            unconfigured
                .configured_stop_signal()
                .expect("resolve absent stop signal"),
            None
        );
    }

    #[test]
    fn wire_round_trip_revalidates_and_preserves_exact_configuration() {
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("wire-bundle");
        let config_json =
            " {\n  \"ociVersion\": \"1.3.0\",\n  \"root\": {\"path\": \"rootfs\"}\n}\n";
        let bundle =
            OciBundle::from_json(absolute, config_json).expect("build exact immutable bundle");
        let encoded = serde_json::to_vec(&bundle).expect("serialize bundle");
        let decoded: OciBundle = serde_json::from_slice(&encoded).expect("deserialize bundle");

        assert_eq!(decoded, bundle);
        assert_eq!(decoded.config_json(), config_json);
    }

    #[test]
    fn wire_deserialization_rejects_digest_tampering() {
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("wire-bundle");
        let bundle = OciBundle::from_json(
            absolute,
            r#"{"ociVersion":"1.3.0","root":{"path":"rootfs"}}"#,
        )
        .expect("build bundle");
        let mut encoded = serde_json::to_value(bundle).expect("serialize bundle");
        encoded["config_digest"] =
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");

        let error = serde_json::from_value::<OciBundle>(encoded)
            .expect_err("tampered digest must be rejected");
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn start_phase_revalidates_the_immutable_bundle_process() {
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("phase-bundle");
        let bundle = OciBundle::from_json(
            absolute,
            r#"{"ociVersion":"1.3.0","root":{"path":"rootfs"}}"#,
        )
        .expect("configuration without process is valid");

        bundle
            .validate_for_phase(OciSemanticPhase::Create)
            .expect("create may omit process");
        let error = bundle
            .validate_for_phase(OciSemanticPhase::Start)
            .expect_err("start requires process");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error
            .message
            .contains("oci.common.process.required-for-start"));
    }

    #[test]
    fn wire_deserialization_cannot_bypass_absolute_path_validation() {
        let absolute = std::env::current_dir()
            .expect("current directory")
            .join("wire-bundle");
        let bundle = OciBundle::from_json(
            absolute,
            r#"{"ociVersion":"1.3.0","root":{"path":"rootfs"}}"#,
        )
        .expect("build bundle");
        let mut encoded = serde_json::to_value(bundle).expect("serialize bundle");
        encoded["directory"] = json!("relative/bundle");

        let error = serde_json::from_value::<OciBundle>(encoded)
            .expect_err("relative wire path must be rejected");
        assert!(error.to_string().contains("must be absolute"));
    }

    fn assert_explicit_fields_preserved(
        original: &serde_json::Value,
        encoded: &serde_json::Value,
        path: &str,
    ) {
        match original {
            serde_json::Value::Object(object) => {
                let encoded = encoded
                    .as_object()
                    .unwrap_or_else(|| panic!("{path} changed from an object"));
                for (key, value) in object {
                    let child_path = format!("{path}/{key}");
                    let encoded_value = encoded
                        .get(key)
                        .unwrap_or_else(|| panic!("{child_path} disappeared during round trip"));
                    assert_explicit_fields_preserved(value, encoded_value, &child_path);
                }
            }
            serde_json::Value::Array(array) => {
                let encoded = encoded
                    .as_array()
                    .unwrap_or_else(|| panic!("{path} changed from an array"));
                assert_eq!(encoded.len(), array.len(), "{path} changed array length");
                for (index, value) in array.iter().enumerate() {
                    assert_explicit_fields_preserved(
                        value,
                        &encoded[index],
                        &format!("{path}/{index}"),
                    );
                }
            }
            value => assert_eq!(encoded, value, "{path} changed value"),
        }
    }
}
