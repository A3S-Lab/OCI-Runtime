use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    Error, ErrorCode, GuestSessionId, IsolationRequest, OciBundle, ProcessIo, Result,
    StorageAttachmentId,
};

mod guest_session;
mod network;
mod storage;

pub use guest_session::{
    GuestSessionAttachment, GuestSessionCapacity, GuestSessionGeneration, GuestSessionOwnership,
    GuestSessionReset, MAX_GUEST_SESSION_CAPACITY,
};
pub use network::{NetworkAttachment, NetworkAttachmentIdentity, NetworkCleanup, NetworkOwnership};
pub use storage::{StorageAccessMode, StorageAttachment, StorageCleanup, StorageOwnership};

/// First public create-time attachment contract understood by A3S OCI Runtime.
pub const ATTACHMENT_SCHEMA_V1: &str = "a3s.oci.attachments.v1";
/// Storage-aware create-time attachment contract.
pub const ATTACHMENT_SCHEMA_V2: &str = "a3s.oci.attachments.v2";
/// Network-aware create-time attachment contract.
pub const ATTACHMENT_SCHEMA_V3: &str = "a3s.oci.attachments.v3";
/// Reusable-guest-session-aware create-time attachment contract.
pub const ATTACHMENT_SCHEMA_V4: &str = "a3s.oci.attachments.v4";
/// Required extension declaring an operation-scoped transfer of bundle ownership.
pub const RUNTIME_BUNDLE_HANDOFF_EXTENSION: &str = "dev.a3s.bundle-handoff";
/// First bundle-handoff contract version.
pub const RUNTIME_BUNDLE_HANDOFF_EXTENSION_VERSION: u16 = 1;
/// Exact annotation value for an atomic move into runtime-owned storage.
pub const RUNTIME_BUNDLE_HANDOFF_MOVE_V1: &str = "move-to-runtime-v1";

const MAX_MOUNT_ATTACHMENTS: usize = 4_096;
const MAX_NETWORK_ATTACHMENTS: usize = 256;
const MAX_AUTHORIZED_NETWORK_ATTACHMENTS: usize = MAX_NETWORK_ATTACHMENTS;
const MAX_SECRET_ATTACHMENTS: usize = 256;
const MAX_STORAGE_ATTACHMENTS: usize = MAX_MOUNT_ATTACHMENTS;
const MAX_RUNTIME_EXTENSIONS: usize = 64;
const MAX_ATTACHMENT_SCHEMAS: usize = 16;

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    network_attachments: Vec<NetworkAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_session: Option<GuestSessionAttachment>,
    process_io: ProcessIo,
    secrets: Vec<AttachmentSource>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    storage: Vec<StorageAttachment>,
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
        if self.storage.iter().any(|storage| storage.mount() == &mount) {
            return Err(invalid_attachment(format!(
                "OCI mount index {mount_index} is already classified as storage"
            )));
        }
        insert_unique_source(
            &mut self.secrets,
            AttachmentSource::configuration(mount),
            "secret",
        )?;
        Ok(self)
    }

    /// Bind one already-authorized storage allocation to an existing OCI mount.
    ///
    /// The caller must provide an immutable allocation identity and explicitly
    /// acknowledge the v2 caller-owned, detach-only lifetime boundary. Named
    /// volume lookup, snapshot selection, authorization, and backing-resource
    /// deletion remain outside the runtime.
    pub fn attach_storage_mount(
        mut self,
        bundle: &OciBundle,
        mount_index: usize,
        identity: StorageAttachmentId,
        access_mode: StorageAccessMode,
        ownership: StorageOwnership,
        cleanup: StorageCleanup,
    ) -> Result<Self> {
        self.validate(bundle)?;
        let mount = self.mounts.get(mount_index).cloned().ok_or_else(|| {
            invalid_attachment(format!(
                "storage attachment references missing OCI mount index {mount_index}"
            ))
        })?;
        if self
            .storage
            .iter()
            .any(|storage| storage.identity() == &identity)
        {
            return Err(invalid_attachment(format!(
                "storage attachment identity {identity} is declared more than once"
            )));
        }
        if self.storage.iter().any(|storage| storage.mount() == &mount) {
            return Err(invalid_attachment(format!(
                "OCI mount index {mount_index} is classified as storage more than once"
            )));
        }
        if self.secrets.iter().any(|source| {
            matches!(
                source,
                AttachmentSource::OciConfiguration { configuration } if configuration == &mount
            )
        }) {
            return Err(invalid_attachment(format!(
                "OCI mount index {mount_index} cannot be both secret and storage"
            )));
        }

        if self.schema_version == ATTACHMENT_SCHEMA_V1 {
            self.schema_version = ATTACHMENT_SCHEMA_V2.to_string();
        }
        self.storage.push(StorageAttachment::new(
            identity,
            mount,
            access_mode,
            ownership,
            cleanup,
        ));
        self.storage.sort();
        self.validate(bundle)?;
        Ok(self)
    }

    /// Bind an already-authorized Linux interface to one exact OCI network namespace.
    ///
    /// The caller supplies immutable namespace, interface, and cleanup
    /// identities. Runtime validates only the prepared OCI mechanism and its
    /// lifetime boundary; IPAM, DNS, routes, aliases, network policy, and
    /// backing-network deletion remain caller-owned.
    pub fn attach_linux_network_interface(
        mut self,
        bundle: &OciBundle,
        namespace_index: usize,
        host_interface_name: &str,
        identity: NetworkAttachmentIdentity,
        cleanup: NetworkCleanup,
    ) -> Result<Self> {
        self.validate(bundle)?;
        let configuration = decode_configuration(bundle)?;
        let namespace_pointer = format!("/linux/namespaces/{namespace_index}");
        let namespace_value = configuration.pointer(&namespace_pointer).ok_or_else(|| {
            invalid_attachment(format!(
                "network attachment references missing OCI namespace index {namespace_index}"
            ))
        })?;
        if namespace_value.get("type").and_then(Value::as_str) != Some("network") {
            return Err(invalid_attachment(format!(
                "OCI namespace index {namespace_index} is not a network namespace"
            )));
        }
        let interface_pointer = format!(
            "/linux/netDevices/{}",
            escape_json_pointer(host_interface_name)
        );
        if configuration.pointer(&interface_pointer).is_none() {
            return Err(invalid_attachment(format!(
                "network attachment references missing linux.netDevices interface {host_interface_name}"
            )));
        }

        if matches!(
            self.schema_version.as_str(),
            ATTACHMENT_SCHEMA_V1 | ATTACHMENT_SCHEMA_V2
        ) {
            self.schema_version = ATTACHMENT_SCHEMA_V3.to_string();
        }
        self.network_attachments.push(NetworkAttachment::new(
            identity,
            ConfigurationAttachment::at(&configuration, namespace_pointer)?,
            ConfigurationAttachment::at(&configuration, interface_pointer)?,
            cleanup,
        ));
        self.network_attachments.sort();
        self.validate(bundle)?;
        Ok(self)
    }

    /// Bind this create to one exact reusable guest-session incarnation.
    ///
    /// The caller declares the trust domain and logical grouping; Runtime
    /// owns the actual guest process, enforces capacity, and never reassigns
    /// one retained incarnation across trust domains.
    pub fn attach_reusable_guest_session(
        mut self,
        bundle: &OciBundle,
        isolation: &IsolationRequest,
        id: GuestSessionId,
        generation: GuestSessionGeneration,
        capacity: GuestSessionCapacity,
        reset: GuestSessionReset,
    ) -> Result<Self> {
        self.validate(bundle)?;
        if self.guest_session.is_some() {
            return Err(invalid_attachment(
                "one create request may bind only one reusable guest session",
            ));
        }
        let IsolationRequest::SharedGuestKernel { trust_domain } = isolation else {
            return Err(invalid_attachment(
                "a reusable guest session requires shared-guest-kernel isolation",
            ));
        };
        self.schema_version = ATTACHMENT_SCHEMA_V4.to_string();
        self.guest_session = Some(GuestSessionAttachment::new(
            id,
            generation,
            trust_domain.clone(),
            capacity,
            reset,
        ));
        self.validate(bundle)?;
        self.validate_isolation(isolation)?;
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

    /// Already-authorized storage allocations in canonical identity order.
    #[must_use]
    pub fn storage(&self) -> &[StorageAttachment] {
        &self.storage
    }

    /// Already-authorized network bindings in canonical identity order.
    #[must_use]
    pub fn network_attachments(&self) -> &[NetworkAttachment] {
        &self.network_attachments
    }

    /// Exact reusable guest-session ownership contract, when requested.
    #[must_use]
    pub const fn guest_session(&self) -> Option<&GuestSessionAttachment> {
        self.guest_session.as_ref()
    }

    /// Bind reusable-session evidence to the create or restore isolation request.
    pub fn validate_isolation(&self, isolation: &IsolationRequest) -> Result<()> {
        match (&self.guest_session, isolation) {
            (Some(session), _) => session.validate_isolation(isolation),
            (None, IsolationRequest::SharedGuestKernel { .. }) => Err(invalid_attachment(
                "shared-guest-kernel isolation requires an explicit reusable guest session",
            )),
            (None, _) => Ok(()),
        }
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
        match self.schema_version.as_str() {
            ATTACHMENT_SCHEMA_V1
                if !self.storage.is_empty()
                    || !self.network_attachments.is_empty()
                    || self.guest_session.is_some() =>
            {
                return Err(invalid_attachment(
                    "attachment schema v1 cannot carry storage, authorized network, or guest-session attachments",
                ));
            }
            ATTACHMENT_SCHEMA_V1 => {}
            ATTACHMENT_SCHEMA_V2
                if !self.network_attachments.is_empty() || self.guest_session.is_some() =>
            {
                return Err(invalid_attachment(
                    "attachment schema v2 cannot carry authorized network or guest-session attachments",
                ));
            }
            ATTACHMENT_SCHEMA_V2 if self.storage.is_empty() => {
                return Err(invalid_attachment(
                    "attachment schema v2 requires at least one storage attachment",
                ));
            }
            ATTACHMENT_SCHEMA_V2 => {}
            ATTACHMENT_SCHEMA_V3 if self.guest_session.is_some() => {
                return Err(invalid_attachment(
                    "attachment schema v3 cannot carry a reusable guest session",
                ));
            }
            ATTACHMENT_SCHEMA_V3 if self.network_attachments.is_empty() => {
                return Err(invalid_attachment(
                    "attachment schema v3 requires at least one authorized network attachment",
                ));
            }
            ATTACHMENT_SCHEMA_V3 => {}
            ATTACHMENT_SCHEMA_V4 if self.guest_session.is_none() => {
                return Err(invalid_attachment(
                    "attachment schema v4 requires one reusable guest session",
                ));
            }
            ATTACHMENT_SCHEMA_V4 => {}
            _ => {
                return Err(invalid_attachment(format!(
                    "unsupported attachment schema {}",
                    self.schema_version
                )));
            }
        }
        if !self.storage.is_empty() && self.uses_runtime_bundle_handoff() {
            return Err(invalid_attachment(
                "caller-owned storage attachments cannot be placed in a runtime-owned bundle handoff",
            ));
        }
        if self.mounts.len() > MAX_MOUNT_ATTACHMENTS
            || self.network.len() > MAX_NETWORK_ATTACHMENTS
            || self.network_attachments.len() > MAX_AUTHORIZED_NETWORK_ATTACHMENTS
            || self.secrets.len() > MAX_SECRET_ATTACHMENTS
            || self.storage.len() > MAX_STORAGE_ATTACHMENTS
            || self.extensions.len() > MAX_RUNTIME_EXTENSIONS
        {
            return Err(invalid_attachment(
                "attachment manifest exceeds a bounded category limit",
            ));
        }

        let configuration = decode_configuration(bundle)?;
        let baseline = Self::from_bundle_unchecked(bundle, self.process_io.clone())?;
        if self.rootfs != baseline.rootfs
            || self.mounts != baseline.mounts
            || self.process_io != baseline.process_io
        {
            return Err(invalid_attachment(
                "rootfs, mount, or process I/O attachment inventory differs from config.json",
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
        storage::validate_attachments(&self.storage, &self.mounts, &self.secrets, &configuration)?;
        network::validate_attachments(&self.network_attachments, &self.network, &configuration)?;
        if let Some(session) = &self.guest_session {
            session.validate()?;
        }
        Ok(())
    }

    fn from_bundle_unchecked(bundle: &OciBundle, process_io: ProcessIo) -> Result<Self> {
        let process_io = match bundle.spec().process().as_ref() {
            Some(process) => process_io.resolve_for_process(process)?,
            None => process_io,
        };
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
            network_attachments: Vec::new(),
            guest_session: None,
            process_io,
            secrets: Vec::new(),
            storage: Vec::new(),
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

    /// Support both the legacy v1 manifest and storage-aware v2 manifests.
    #[must_use]
    pub fn base_v2() -> Self {
        Self {
            schemas: vec![
                ATTACHMENT_SCHEMA_V1.to_string(),
                ATTACHMENT_SCHEMA_V2.to_string(),
            ],
            extensions: BTreeMap::new(),
        }
    }

    /// Support legacy v1, storage-aware v2, and network-aware v3 manifests.
    #[must_use]
    pub fn base_v3() -> Self {
        Self {
            schemas: vec![
                ATTACHMENT_SCHEMA_V1.to_string(),
                ATTACHMENT_SCHEMA_V2.to_string(),
                ATTACHMENT_SCHEMA_V3.to_string(),
            ],
            extensions: BTreeMap::new(),
        }
    }

    /// Support cumulative v1-v4 manifests including reusable guest sessions.
    #[must_use]
    pub fn base_v4() -> Self {
        Self {
            schemas: vec![
                ATTACHMENT_SCHEMA_V1.to_string(),
                ATTACHMENT_SCHEMA_V2.to_string(),
                ATTACHMENT_SCHEMA_V3.to_string(),
                ATTACHMENT_SCHEMA_V4.to_string(),
            ],
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

    /// Retain only schemas and extension versions supported by both inventories.
    #[must_use]
    pub fn common_with(mut self, other: &Self) -> Self {
        self.schemas
            .retain(|schema| other.schemas.binary_search(schema).is_ok());
        self.extensions.retain(|name, versions| {
            let Some(other_versions) = other.extensions.get(name) else {
                return false;
            };
            versions.retain(|version| other_versions.binary_search(version).is_ok());
            !versions.is_empty()
        });
        self
    }

    /// Validate canonical schema, extension-name, and extension-version ordering.
    pub fn validate(&self) -> Result<()> {
        if self.schemas.is_empty()
            || self.schemas.len() > MAX_ATTACHMENT_SCHEMAS
            || self
                .schemas
                .iter()
                .any(|schema| schema.is_empty() || schema.len() > 128)
            || !strictly_increasing(&self.schemas)
        {
            return Err(invalid_attachment(format!(
                "attachment capabilities must advertise between 1 and {MAX_ATTACHMENT_SCHEMAS} canonical schemas"
            )));
        }
        if self.extensions.len() > MAX_RUNTIME_EXTENSIONS {
            return Err(invalid_attachment(format!(
                "attachment capabilities exceed {MAX_RUNTIME_EXTENSIONS} runtime extensions"
            )));
        }
        for (name, versions) in &self.extensions {
            validate_extension_name(name)?;
            if versions.is_empty() || versions.first() == Some(&0) || !strictly_increasing(versions)
            {
                return Err(invalid_attachment(format!(
                    "runtime extension capability {name} must advertise canonical positive versions"
                )));
            }
        }
        Ok(())
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

    /// Supported extension names in canonical byte order.
    pub fn extension_names(&self) -> impl Iterator<Item = &str> {
        self.extensions.keys().map(String::as_str)
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

pub(crate) fn validate_extension_name(name: &str) -> Result<()> {
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

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn invalid_attachment(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-attachments")
}

#[cfg(test)]
mod tests;
