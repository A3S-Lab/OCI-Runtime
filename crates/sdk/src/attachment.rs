use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, ErrorCode, OciBundle, ProcessIo, Result};

/// First public create-time attachment contract understood by A3S OCI Runtime.
pub const ATTACHMENT_SCHEMA_V1: &str = "a3s.oci.attachments.v1";
/// Required extension declaring an operation-scoped transfer of bundle ownership.
pub const RUNTIME_BUNDLE_HANDOFF_EXTENSION: &str = "dev.a3s.bundle-handoff";
/// First bundle-handoff contract version.
pub const RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION: u16 = 1;
/// Exact annotation value for an atomic move into runtime-owned storage.
pub const RUNTIME_BUNDLE_HANDOFF_MOVE_V1: &str = "move-to-runtime-v1";

const MAX_MOUNT_ATTACHMENTS: usize = 4_096;
const MAX_NETWORK_ATTACHMENTS: usize = 256;
const MAX_SECRET_ATTACHMENTS: usize = 256;
const MAX_RUNTIME_EXTENSIONS: usize = 64;

/// Digest-bound reference to one exact value in the immutable OCI configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigurationAttachment {
    json_pointer: String,
    value_digest: String,
}

impl ConfigurationAttachment {
    /// JSON Pointer selecting the exact configuration value.
    #[must_use]
    pub fn json_pointer(&self) -> &str {
        &self.json_pointer
    }

    /// SHA-256 digest of the selected canonical JSON value.
    #[must_use]
    pub fn value_digest(&self) -> &str {
        &self.value_digest
    }

    fn at(configuration: &Value, json_pointer: impl Into<String>) -> Result<Self> {
        let json_pointer = json_pointer.into();
        let value = configuration.pointer(&json_pointer).ok_or_else(|| {
            invalid_attachment(format!(
                "attachment JSON Pointer does not exist in config.json: {json_pointer}"
            ))
        })?;
        Ok(Self {
            json_pointer,
            value_digest: digest_json(value)?,
        })
    }

    fn validate(&self, configuration: &Value) -> Result<()> {
        let expected = Self::at(configuration, self.json_pointer.clone())?;
        if *self != expected {
            return Err(invalid_attachment(format!(
                "attachment evidence drifted at {}",
                self.json_pointer
            )));
        }
        Ok(())
    }
}

/// Source of a network or secret attachment.
///
/// Standard OCI resources are bound to an exact `config.json` value. Runtime
/// extensions are referenced only by their namespaced declaration; extension
/// configuration itself must live in the same immutable OCI annotations map.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AttachmentSource {
    /// Exact value from the immutable OCI configuration.
    OciConfiguration {
        configuration: ConfigurationAttachment,
    },
    /// Versioned runtime extension declared by this attachment set.
    RuntimeExtension { name: String },
}

impl AttachmentSource {
    fn configuration(configuration: ConfigurationAttachment) -> Self {
        Self::OciConfiguration { configuration }
    }

    fn extension(name: impl Into<String>) -> Self {
        Self::RuntimeExtension { name: name.into() }
    }
}

/// One optional, namespaced runtime mechanism configured through an OCI annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeExtensionAttachment {
    name: String,
    version: u16,
    required: bool,
    configuration: ConfigurationAttachment,
}

impl RuntimeExtensionAttachment {
    fn from_annotation(
        configuration: &Value,
        name: impl Into<String>,
        version: u16,
        required: bool,
    ) -> Result<Self> {
        let name = name.into();
        validate_extension_name(&name)?;
        if version == 0 {
            return Err(invalid_attachment(format!(
                "runtime extension {name} uses reserved version zero"
            )));
        }
        let pointer = format!("/annotations/{name}");
        Ok(Self {
            name,
            version,
            required,
            configuration: ConfigurationAttachment::at(configuration, pointer)?,
        })
    }

    /// Reverse-DNS extension name and OCI annotation key.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Positive extension contract version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Whether create must fail if the selected runtime cannot enforce it.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    fn validate(&self, configuration: &Value) -> Result<()> {
        validate_extension_name(&self.name)?;
        if self.version == 0 {
            return Err(invalid_attachment(format!(
                "runtime extension {} uses reserved version zero",
                self.name
            )));
        }
        let expected_pointer = format!("/annotations/{}", self.name);
        if self.configuration.json_pointer != expected_pointer {
            return Err(invalid_attachment(format!(
                "runtime extension {} must be configured by annotation {}",
                self.name, self.name
            )));
        }
        self.configuration.validate(configuration)
    }
}

/// Complete versioned attachment manifest for OCI create or restore.
///
/// The manifest contains no secret bytes, product policy, raw descriptor
/// numbers, process IDs, VM handles, sockets, pipes, or cgroup identities. It
/// classifies immutable configuration values and process I/O so retries and
/// recovery can bind the exact same contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateAttachments {
    schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rootfs: Option<ConfigurationAttachment>,
    mounts: Vec<ConfigurationAttachment>,
    network: Vec<AttachmentSource>,
    process_io: ProcessIo,
    secrets: Vec<AttachmentSource>,
    extensions: BTreeMap<String, RuntimeExtensionAttachment>,
}

impl CreateAttachments {
    /// Derive the complete standard attachment inventory from an immutable bundle.
    pub fn from_bundle(bundle: &OciBundle, process_io: ProcessIo) -> Result<Self> {
        let attachments = Self::from_bundle_unchecked(bundle, process_io)?;
        attachments.validate(bundle)?;
        Ok(attachments)
    }

    /// Classify one existing OCI mount as carrying already-authorized secret data.
    ///
    /// Only the mount index is retained. Secret names, values, authorization
    /// policy, and materialization credentials remain outside the runtime.
    pub fn mark_secret_mount(mut self, mount_index: usize) -> Result<Self> {
        let mount = self.mounts.get(mount_index).cloned().ok_or_else(|| {
            invalid_attachment(format!(
                "secret attachment references missing OCI mount index {mount_index}"
            ))
        })?;
        insert_unique_source(
            &mut self.secrets,
            AttachmentSource::configuration(mount),
            "secret",
        )?;
        Ok(self)
    }

    /// Declare a namespaced runtime extension configured by the same OCI annotation.
    pub fn add_extension_from_annotation(
        mut self,
        bundle: &OciBundle,
        name: impl Into<String>,
        version: u16,
        required: bool,
    ) -> Result<Self> {
        let configuration = decode_configuration(bundle)?;
        let extension =
            RuntimeExtensionAttachment::from_annotation(&configuration, name, version, required)?;
        if self.extensions.contains_key(extension.name()) {
            return Err(invalid_attachment(format!(
                "runtime extension {} is declared more than once",
                extension.name()
            )));
        }
        self.extensions
            .insert(extension.name().to_string(), extension);
        self.validate(bundle)?;
        Ok(self)
    }

    /// Transfer a portable bundle from the protected operation handoff path.
    ///
    /// The immutable OCI configuration must carry the exact namespaced
    /// annotation value. Declaring this required extension makes ownership
    /// transfer explicit, digest-bound, and fail-closed on runtimes or drivers
    /// that do not implement it.
    pub fn with_runtime_bundle_handoff(mut self, bundle: &OciBundle) -> Result<Self> {
        let configured = bundle
            .spec()
            .annotations()
            .as_ref()
            .and_then(|annotations| annotations.get(RUNTIME_BUNDLE_HANDOFF_EXTENSION));
        if configured.map(String::as_str) != Some(RUNTIME_BUNDLE_HANDOFF_MOVE_V1) {
            return Err(invalid_attachment(format!(
                "runtime bundle handoff requires annotation {RUNTIME_BUNDLE_HANDOFF_EXTENSION}={RUNTIME_BUNDLE_HANDOFF_MOVE_V1}"
            )));
        }
        self = self.add_extension_from_annotation(
            bundle,
            RUNTIME_BUNDLE_HANDOFF_EXTENSION,
            RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
            true,
        )?;
        Ok(self)
    }

    /// Whether this exact manifest requests runtime bundle ownership transfer.
    #[must_use]
    pub fn uses_runtime_bundle_handoff(&self) -> bool {
        self.extensions
            .get(RUNTIME_BUNDLE_HANDOFF_EXTENSION)
            .is_some_and(|extension| {
                extension.version() == RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION
                    && extension.required()
            })
    }

    /// Classify one declared runtime extension as a network attachment mechanism.
    pub fn attach_network_extension(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        self.require_extension(&name)?;
        insert_unique_source(
            &mut self.network,
            AttachmentSource::extension(name),
            "network",
        )?;
        Ok(self)
    }

    /// Classify one declared runtime extension as an ephemeral secret mechanism.
    pub fn attach_secret_extension(mut self, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        self.require_extension(&name)?;
        insert_unique_source(
            &mut self.secrets,
            AttachmentSource::extension(name),
            "secret",
        )?;
        Ok(self)
    }

    /// Attachment contract schema identifier.
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Versioned process-I/O attachment for the init process.
    #[must_use]
    pub const fn process_io(&self) -> &ProcessIo {
        &self.process_io
    }

    /// Replace the init-process I/O contract while retaining every resource classification.
    #[must_use]
    pub fn with_process_io(mut self, process_io: ProcessIo) -> Self {
        self.process_io = process_io;
        self
    }

    /// Declared runtime extensions keyed by reverse-DNS name.
    #[must_use]
    pub const fn extensions(&self) -> &BTreeMap<String, RuntimeExtensionAttachment> {
        &self.extensions
    }

    /// SHA-256 evidence for the complete canonical attachment manifest.
    pub fn digest(&self) -> Result<String> {
        let encoded = serde_json::to_vec(self).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to encode attachment evidence: {error}"),
            )
            .for_operation("digest-attachments")
        })?;
        Ok(digest_bytes(&encoded))
    }

    /// Revalidate every pointer, digest, classification, and extension declaration.
    pub fn validate(&self, bundle: &OciBundle) -> Result<()> {
        if self.schema_version != ATTACHMENT_SCHEMA_V1 {
            return Err(invalid_attachment(format!(
                "unsupported attachment schema {}",
                self.schema_version
            )));
        }
        if self.mounts.len() > MAX_MOUNT_ATTACHMENTS
            || self.network.len() > MAX_NETWORK_ATTACHMENTS
            || self.secrets.len() > MAX_SECRET_ATTACHMENTS
            || self.extensions.len() > MAX_RUNTIME_EXTENSIONS
        {
            return Err(invalid_attachment(
                "attachment manifest exceeds a bounded category limit",
            ));
        }

        let configuration = decode_configuration(bundle)?;
        let baseline = Self::from_bundle_unchecked(bundle, self.process_io.clone())?;
        if self.rootfs != baseline.rootfs || self.mounts != baseline.mounts {
            return Err(invalid_attachment(
                "rootfs or mount attachment inventory differs from config.json",
            ));
        }

        if let Some(rootfs) = &self.rootfs {
            rootfs.validate(&configuration)?;
        }
        for mount in &self.mounts {
            mount.validate(&configuration)?;
        }

        let standard_network = self
            .network
            .iter()
            .filter(|source| matches!(source, AttachmentSource::OciConfiguration { .. }))
            .cloned()
            .collect::<Vec<_>>();
        if standard_network != baseline.network {
            return Err(invalid_attachment(
                "network attachment inventory differs from config.json",
            ));
        }
        ensure_unique_sources(&self.network, "network")?;
        ensure_unique_sources(&self.secrets, "secret")?;

        for (name, extension) in &self.extensions {
            if name != extension.name() {
                return Err(invalid_attachment(format!(
                    "runtime extension map key {name} differs from its declaration"
                )));
            }
            extension.validate(&configuration)?;
        }
        for source in self.network.iter().chain(&self.secrets) {
            match source {
                AttachmentSource::OciConfiguration {
                    configuration: attachment,
                } => {
                    attachment.validate(&configuration)?;
                }
                AttachmentSource::RuntimeExtension { name } => self.require_extension(name)?,
            }
        }

        let mounts = self.mounts.iter().collect::<BTreeSet<_>>();
        for source in &self.secrets {
            if let AttachmentSource::OciConfiguration { configuration } = source {
                if !mounts.contains(configuration) {
                    return Err(invalid_attachment(format!(
                        "secret attachment {} does not reference an OCI mount",
                        configuration.json_pointer
                    )));
                }
            }
        }
        Ok(())
    }

    fn from_bundle_unchecked(bundle: &OciBundle, process_io: ProcessIo) -> Result<Self> {
        let configuration = decode_configuration(bundle)?;
        let rootfs = configuration
            .get("root")
            .map(|_| ConfigurationAttachment::at(&configuration, "/root"))
            .transpose()?;
        let mounts = configuration
            .get("mounts")
            .and_then(Value::as_array)
            .map_or(Ok(Vec::new()), |mounts| {
                mounts
                    .iter()
                    .enumerate()
                    .map(|(index, _)| {
                        ConfigurationAttachment::at(&configuration, format!("/mounts/{index}"))
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
        let mut network = Vec::new();
        if let Some(namespaces) = configuration
            .pointer("/linux/namespaces")
            .and_then(Value::as_array)
        {
            for (index, namespace) in namespaces.iter().enumerate() {
                if namespace.get("type").and_then(Value::as_str) == Some("network") {
                    network.push(AttachmentSource::configuration(
                        ConfigurationAttachment::at(
                            &configuration,
                            format!("/linux/namespaces/{index}"),
                        )?,
                    ));
                }
            }
        }
        if let Some(devices) = configuration
            .pointer("/linux/netDevices")
            .and_then(Value::as_object)
        {
            for name in devices.keys() {
                network.push(AttachmentSource::configuration(
                    ConfigurationAttachment::at(
                        &configuration,
                        format!("/linux/netDevices/{}", escape_json_pointer(name)),
                    )?,
                ));
            }
        }
        if configuration.pointer("/windows/network").is_some() {
            network.push(AttachmentSource::configuration(
                ConfigurationAttachment::at(&configuration, "/windows/network")?,
            ));
        }
        network.sort();
        Ok(Self {
            schema_version: ATTACHMENT_SCHEMA_V1.to_string(),
            rootfs,
            mounts,
            network,
            process_io,
            secrets: Vec::new(),
            extensions: BTreeMap::new(),
        })
    }

    fn require_extension(&self, name: &str) -> Result<()> {
        if self.extensions.contains_key(name) {
            Ok(())
        } else {
            Err(invalid_attachment(format!(
                "attachment references undeclared runtime extension {name}"
            )))
        }
    }
}

/// Attachment schemas and runtime extensions supported by one exact host service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentCapabilities {
    schemas: Vec<String>,
    extensions: BTreeMap<String, Vec<u16>>,
}

impl AttachmentCapabilities {
    /// Base service support for the public v1 manifest without optional extensions.
    #[must_use]
    pub fn base_v1() -> Self {
        Self {
            schemas: vec![ATTACHMENT_SCHEMA_V1.to_string()],
            extensions: BTreeMap::new(),
        }
    }

    /// Add one implemented extension and its positive, sorted contract versions.
    pub fn with_extension(
        mut self,
        name: impl Into<String>,
        mut versions: Vec<u16>,
    ) -> Result<Self> {
        let name = name.into();
        validate_extension_name(&name)?;
        versions.sort_unstable();
        versions.dedup();
        if versions.is_empty() || versions.first() == Some(&0) {
            return Err(invalid_attachment(format!(
                "runtime extension capability {name} must advertise positive versions"
            )));
        }
        if self.extensions.insert(name.clone(), versions).is_some() {
            return Err(invalid_attachment(format!(
                "runtime extension capability {name} is duplicated"
            )));
        }
        Ok(self)
    }

    /// Merge another service or driver capability set into this inventory.
    #[must_use]
    pub fn merged(mut self, other: &Self) -> Self {
        for schema in &other.schemas {
            if !self.schemas.contains(schema) {
                self.schemas.push(schema.clone());
            }
        }
        self.schemas.sort();
        for (name, versions) in &other.extensions {
            let retained = self.extensions.entry(name.clone()).or_default();
            retained.extend(versions.iter().copied());
            retained.sort_unstable();
            retained.dedup();
        }
        self
    }

    /// Whether this service supports an attachment schema.
    #[must_use]
    pub fn supports_schema(&self, schema: &str) -> bool {
        self.schemas.iter().any(|candidate| candidate == schema)
    }

    /// Whether this service implements one exact extension version.
    #[must_use]
    pub fn supports_extension(&self, name: &str, version: u16) -> bool {
        self.extensions
            .get(name)
            .is_some_and(|versions| versions.binary_search(&version).is_ok())
    }

    /// Reject unsupported schemas and required extensions before runtime mutation.
    pub fn require(&self, attachments: &CreateAttachments) -> Result<()> {
        if !self.supports_schema(attachments.schema_version()) {
            return Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "runtime does not support attachment schema {}",
                    attachments.schema_version()
                ),
            )
            .for_operation("create"));
        }
        for extension in attachments.extensions().values() {
            if extension.required()
                && !self.supports_extension(extension.name(), extension.version())
            {
                return Err(Error::new(
                    ErrorCode::Unsupported,
                    format!(
                        "runtime does not support required extension {} version {}",
                        extension.name(),
                        extension.version()
                    ),
                )
                .for_operation("create"));
            }
        }
        Ok(())
    }
}

fn decode_configuration(bundle: &OciBundle) -> Result<Value> {
    serde_json::from_str(bundle.config_json()).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("validated OCI configuration could not be decoded: {error}"),
        )
        .for_operation("validate-attachments")
    })
}

fn digest_json(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to encode attachment configuration: {error}"),
        )
        .for_operation("digest-attachments")
    })?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn escape_json_pointer(component: &str) -> String {
    component.replace('~', "~0").replace('/', "~1")
}

fn insert_unique_source(
    sources: &mut Vec<AttachmentSource>,
    source: AttachmentSource,
    category: &str,
) -> Result<()> {
    if sources.contains(&source) {
        return Err(invalid_attachment(format!(
            "duplicate {category} attachment source"
        )));
    }
    sources.push(source);
    sources.sort();
    Ok(())
}

fn ensure_unique_sources(sources: &[AttachmentSource], category: &str) -> Result<()> {
    if sources.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_attachment(format!(
            "{category} attachment sources must be unique and canonically ordered"
        )));
    }
    Ok(())
}

fn validate_extension_name(name: &str) -> Result<()> {
    let valid = (3..=253).contains(&name.len())
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if valid {
        Ok(())
    } else {
        Err(invalid_attachment(format!(
            "runtime extension name must be a lowercase reverse-DNS name: {name:?}"
        )))
    }
}

fn invalid_attachment(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-attachments")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        AttachmentCapabilities, AttachmentSource, CreateAttachments, ATTACHMENT_SCHEMA_V1,
        RUNTIME_BUNDLE_HANDOFF_EXTENSION, RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION,
        RUNTIME_BUNDLE_HANDOFF_MOVE_V1,
    };
    use crate::{ErrorCode, OciBundle, ProcessIo};

    fn bundle() -> OciBundle {
        OciBundle::from_json(
            std::env::temp_dir().join("a3s-attachment-bundle"),
            serde_json::to_string(&json!({
                "ociVersion": "1.3.0",
                "root": {"path": "rootfs", "readonly": true},
                "process": {
                    "cwd": "/",
                    "args": ["/bin/true"],
                    "user": {"uid": 0, "gid": 0}
                },
                "mounts": [
                    {"destination": "/data", "type": "bind", "source": "data", "options": ["ro"]},
                    {"destination": "/run/secret", "type": "bind", "source": "secret", "options": ["ro"]}
                ],
                "linux": {
                    "namespaces": [{"type": "mount"}, {"type": "network"}],
                    "netDevices": {"tap0": {"name": "eth0"}}
                },
                "annotations": {
                    "dev.a3s.network.tsi": "{\"mode\":\"proxy\"}",
                    "dev.a3s.secret.channel": "fd-broker"
                }
            }))
            .expect("encode configuration"),
        )
        .expect("attachment fixture bundle")
    }

    fn handoff_bundle() -> OciBundle {
        let mut configuration: serde_json::Value =
            serde_json::from_str(bundle().config_json()).expect("fixture configuration");
        configuration["annotations"][RUNTIME_BUNDLE_HANDOFF_EXTENSION] =
            json!(RUNTIME_BUNDLE_HANDOFF_MOVE_V1);
        OciBundle::from_json(
            std::env::temp_dir().join("a3s-bundle-handoff"),
            serde_json::to_string(&configuration).expect("handoff configuration"),
        )
        .expect("handoff bundle")
    }

    #[test]
    fn derives_and_digest_binds_every_standard_attachment_category() {
        let bundle = bundle();
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("derive attachments")
            .mark_secret_mount(1)
            .expect("classify secret mount")
            .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 1, true)
            .expect("declare network extension")
            .attach_network_extension("dev.a3s.network.tsi")
            .expect("classify network extension")
            .add_extension_from_annotation(&bundle, "dev.a3s.secret.channel", 1, false)
            .expect("declare secret extension")
            .attach_secret_extension("dev.a3s.secret.channel")
            .expect("classify secret extension");

        attachments.validate(&bundle).expect("valid attachments");
        assert_eq!(attachments.schema_version(), ATTACHMENT_SCHEMA_V1);
        assert!(attachments
            .digest()
            .expect("attachment digest")
            .starts_with("sha256:"));
        assert_eq!(attachments.mounts.len(), 2);
        assert_eq!(attachments.network.len(), 3);
        assert_eq!(attachments.secrets.len(), 2);
        assert_eq!(attachments.extensions.len(), 2);
    }

    #[test]
    fn rejects_drift_unknown_references_and_unversioned_extensions() {
        let bundle = bundle();
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("derive attachments");
        assert!(attachments.clone().mark_secret_mount(9).is_err());
        assert!(attachments
            .clone()
            .attach_network_extension("dev.a3s.missing")
            .is_err());
        assert!(attachments
            .clone()
            .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 0, true)
            .is_err());

        let mut encoded = serde_json::to_value(&attachments).expect("encode attachments");
        encoded["rootfs"]["valueDigest"] = json!("sha256:deadbeef");
        let corrupt: CreateAttachments =
            serde_json::from_value(encoded).expect("decode structurally valid corruption");
        let error = corrupt
            .validate(&bundle)
            .expect_err("configuration evidence drift must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);

        let mut encoded = serde_json::to_value(&attachments).expect("encode attachments");
        encoded["network"]
            .as_array_mut()
            .expect("network array")
            .push(json!({
                "kind": "runtime-extension",
                "name": "dev.a3s.missing"
            }));
        let corrupt: CreateAttachments =
            serde_json::from_value(encoded).expect("decode missing extension reference");
        assert!(corrupt.validate(&bundle).is_err());
    }

    #[test]
    fn required_extensions_are_fail_closed_but_advisory_extensions_are_explicit() {
        let bundle = bundle();
        let base = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("derive attachments");
        let required = base
            .clone()
            .add_extension_from_annotation(&bundle, "dev.a3s.network.tsi", 1, true)
            .expect("required extension");
        let unsupported = AttachmentCapabilities::base_v1()
            .require(&required)
            .expect_err("required unsupported extension must fail");
        assert_eq!(unsupported.code, ErrorCode::Unsupported);

        let supported = AttachmentCapabilities::base_v1()
            .with_extension("dev.a3s.network.tsi", vec![2, 1, 2])
            .expect("extension capability");
        supported.require(&required).expect("supported extension");

        let advisory = base
            .add_extension_from_annotation(&bundle, "dev.a3s.secret.channel", 1, false)
            .expect("advisory extension");
        AttachmentCapabilities::base_v1()
            .require(&advisory)
            .expect("unsupported advisory extension remains explicit and non-enforcing");
    }

    #[test]
    fn runtime_bundle_handoff_is_explicit_digest_bound_and_capability_checked() {
        let handoff = handoff_bundle();
        let attachments = CreateAttachments::from_bundle(&handoff, ProcessIo::default())
            .expect("base attachments")
            .with_runtime_bundle_handoff(&handoff)
            .expect("bundle handoff extension");
        assert!(attachments.uses_runtime_bundle_handoff());

        let unsupported = AttachmentCapabilities::base_v1()
            .require(&attachments)
            .expect_err("base runtime must reject required handoff");
        assert_eq!(unsupported.code, ErrorCode::Unsupported);
        AttachmentCapabilities::base_v1()
            .with_extension(
                RUNTIME_BUNDLE_HANDOFF_EXTENSION,
                vec![RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION],
            )
            .expect("handoff capability")
            .require(&attachments)
            .expect("handoff-capable runtime");

        let ordinary = bundle();
        let error = CreateAttachments::from_bundle(&ordinary, ProcessIo::default())
            .expect("ordinary attachments")
            .with_runtime_bundle_handoff(&ordinary)
            .expect_err("missing exact annotation must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn serialized_manifest_contains_no_secret_value_or_runtime_identity() {
        let bundle = bundle();
        let encoded = serde_json::to_string(
            &CreateAttachments::from_bundle(&bundle, ProcessIo::default())
                .expect("derive attachments")
                .mark_secret_mount(1)
                .expect("classify secret mount"),
        )
        .expect("encode attachments");
        assert!(!encoded.contains("fd-broker"));
        assert!(!encoded.contains("secret.channel"));
        assert!(!encoded.contains("pid"));
        assert!(encoded.contains("/mounts/1"));
        assert!(encoded.contains("valueDigest"));
        assert!(matches!(
            serde_json::from_str::<CreateAttachments>(&encoded)
                .expect("round trip")
                .secrets[0],
            AttachmentSource::OciConfiguration { .. }
        ));
    }
}
