use std::path::{Path, PathBuf};

use oci_spec::runtime::Spec;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::{Error, ErrorCode, OciSchemaDocument, OciSchemaValidator, Result};

/// File containing the OCI runtime configuration in a bundle.
pub const CONFIG_FILE_NAME: &str = "config.json";
/// Maximum accepted `config.json` size.
pub const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
/// Oldest OCI Runtime Specification version recognized by this SDK.
pub const OCI_RUNTIME_SPEC_VERSION_MIN: &str = "1.0.0";
/// Newest OCI Runtime Specification version recognized by this SDK.
pub const OCI_RUNTIME_SPEC_VERSION_MAX: &str = "1.3.0";

/// Immutable, digest-bound OCI bundle submitted to the runtime service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciBundle {
    directory: PathBuf,
    config_digest: String,
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
        let file = tokio::fs::File::open(&config_path).await.map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to open OCI configuration {}: {error}",
                    config_path.display()
                ),
            )
            .for_operation("load-bundle")
        })?;
        let config_metadata = file.metadata().await.map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to inspect OCI configuration {}: {error}",
                    config_path.display()
                ),
            )
            .for_operation("load-bundle")
        })?;
        if !config_metadata.is_file() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!(
                    "OCI configuration is not a regular file: {}",
                    config_path.display()
                ),
            )
            .for_operation("load-bundle"));
        }
        if config_metadata.len() > MAX_CONFIG_BYTES {
            return Err(config_too_large(&config_path, config_metadata.len()));
        }

        let mut bytes = Vec::with_capacity(config_metadata.len() as usize);
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

        let spec = decode_spec(&bytes, &config_path)?;
        validate_version(&spec)?;

        Ok(Self {
            directory,
            config_digest: digest(&bytes),
            spec,
        })
    }

    /// Construct an immutable bundle from an already decoded complete OCI spec.
    pub fn from_spec(directory: impl Into<PathBuf>, spec: Spec) -> Result<Self> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                format!("OCI bundle path must be absolute: {}", directory.display()),
            )
            .for_operation("build-bundle"));
        }
        validate_version(&spec)?;
        OciSchemaValidator::new()?.validate_spec(&spec)?;
        let bytes = serde_json::to_vec(&spec).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to encode OCI configuration: {error}"),
            )
            .for_operation("build-bundle")
        })?;

        Ok(Self {
            directory,
            config_digest: digest(&bytes),
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

    /// Complete typed OCI runtime configuration.
    #[must_use]
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }
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

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
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

    use serde_json::json;

    use super::{decode_spec, OciBundle, OCI_RUNTIME_SPEC_VERSION_MAX};
    use crate::ErrorCode;

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
                    { "type": "mount" }
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
                "dev.a3s.test": "full-spec-pass-through"
            }
        })
    }

    #[tokio::test]
    async fn loads_v1_3_fields_without_losing_them() {
        let temporary = tempfile::tempdir().expect("create temporary bundle");
        let config = complete_v1_3_fixture();
        std::fs::write(
            temporary.path().join("config.json"),
            serde_json::to_vec_pretty(&config).expect("encode fixture"),
        )
        .expect("write fixture");

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
        assert!(bundle.config_digest().starts_with("sha256:"));
        assert!(bundle.directory().is_absolute());
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
    fn preserves_every_explicit_field_in_upstream_linux_fixtures() {
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
            let spec = decode_spec(source.as_bytes(), Path::new(name))
                .unwrap_or_else(|error| panic!("{name} must decode without loss: {error}"));
            let encoded = serde_json::to_value(spec).expect("encode decoded OCI spec");
            assert_explicit_fields_preserved(&original, &encoded, "");
        }
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
