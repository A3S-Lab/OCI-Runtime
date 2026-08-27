use std::collections::BTreeSet;

use a3s_oci_sdk::{
    ConfigurationAttachment, ContainerTarget, Error, ErrorCode, NetworkAttachmentIdentity,
    NetworkCleanup, OciBundle, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{GuestPath, AGENT_RUNTIME_SHARE_GUEST_ROOT};

/// Immutable Host-to-shim-to-Guest network transport manifest schema.
pub const AGENT_VM_ATTACHMENT_MANIFEST_SCHEMA_VERSION: &str = "a3s.oci.agent-vm-attachments.v1";
/// Fixed file name inside one exact utility-VM runtime share.
pub const AGENT_VM_ATTACHMENT_MANIFEST_FILE_NAME: &str = ".a3s-oci-agent-vm-attachments.json";
/// Guest environment key carrying the exact encoded-manifest SHA-256 digest.
pub const AGENT_VM_ATTACHMENT_MANIFEST_SHA256_ENV: &str =
    "A3S_OCI_AGENT_VM_ATTACHMENT_MANIFEST_SHA256";
/// Maximum encoded attachment transport manifest size.
pub const AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES: usize = 64 * 1024;

const MAX_NETWORK_ATTACHMENTS: usize = 256;
const LINUX_INTERFACE_NAME_BYTES: usize = 15;
const TRANSPORT_MAC_DOMAIN: &[u8] = b"a3s.oci.agent-vm-network-mac.v1\0";

/// Exact locally administered unicast MAC assigned to one Guest virtio NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentVmMacAddress([u8; 6]);

impl AgentVmMacAddress {
    /// Validate an exact six-byte locally administered unicast address.
    pub fn new(bytes: [u8; 6]) -> Result<Self> {
        if bytes[0] & 0x01 != 0 || bytes[0] & 0x02 == 0 || bytes.iter().all(|byte| *byte == 0) {
            return Err(manifest_error(
                "utility-VM transport MAC must be a nonzero locally administered unicast address",
            ));
        }
        Ok(Self(bytes))
    }

    /// Deterministically derive a transport-local address from immutable evidence.
    pub fn derive(
        attachment_digest: &str,
        identity: &NetworkAttachmentIdentity,
        tap_name: &str,
    ) -> Result<Self> {
        validate_digest(attachment_digest, "attachment digest")?;
        validate_interface_name(tap_name)?;
        let mut hasher = Sha256::new();
        hasher.update(TRANSPORT_MAC_DOMAIN);
        for value in [
            attachment_digest,
            identity.namespace().as_str(),
            identity.interface().as_str(),
            identity.cleanup().as_str(),
            tap_name,
        ] {
            let length = u64::try_from(value.len()).map_err(|error| {
                manifest_error(format!(
                    "utility-VM network MAC evidence length is not portable: {error}"
                ))
            })?;
            hasher.update(length.to_le_bytes());
            hasher.update(value.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 6];
        bytes.copy_from_slice(&digest[..6]);
        bytes[0] = (bytes[0] & 0xfc) | 0x02;
        Self::new(bytes)
    }

    /// Borrow the exact six bytes passed to the VMM and matched in the Guest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// One caller-authorized TAP carried into a dedicated Linux utility VM.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVmNetworkAttachment {
    identity: NetworkAttachmentIdentity,
    tap_name: String,
    namespace: ConfigurationAttachment,
    interface: ConfigurationAttachment,
    cleanup: NetworkCleanup,
    mac_address: AgentVmMacAddress,
}

impl AgentVmNetworkAttachment {
    /// Bind one exact public attachment entry to its VMM TAP transport.
    pub fn new(
        identity: NetworkAttachmentIdentity,
        tap_name: impl Into<String>,
        namespace: ConfigurationAttachment,
        interface: ConfigurationAttachment,
        cleanup: NetworkCleanup,
        mac_address: AgentVmMacAddress,
    ) -> Result<Self> {
        let entry = Self {
            identity,
            tap_name: tap_name.into(),
            namespace,
            interface,
            cleanup,
            mac_address,
        };
        entry.validate_shape()?;
        Ok(entry)
    }

    /// Immutable caller-issued network identities.
    #[must_use]
    pub const fn identity(&self) -> &NetworkAttachmentIdentity {
        &self.identity
    }

    /// Host TAP name consumed by libkrun and recreated as the Guest source name.
    #[must_use]
    pub fn tap_name(&self) -> &str {
        &self.tap_name
    }

    /// Exact OCI network namespace descriptor.
    #[must_use]
    pub const fn namespace(&self) -> &ConfigurationAttachment {
        &self.namespace
    }

    /// Exact OCI `linux.netDevices` descriptor.
    #[must_use]
    pub const fn interface(&self) -> &ConfigurationAttachment {
        &self.interface
    }

    /// Caller-declared namespace cleanup boundary.
    #[must_use]
    pub const fn cleanup(&self) -> NetworkCleanup {
        self.cleanup
    }

    /// Exact MAC configured in libkrun and matched before Guest protocol startup.
    #[must_use]
    pub const fn mac_address(&self) -> AgentVmMacAddress {
        self.mac_address
    }

    fn validate_shape(&self) -> Result<()> {
        validate_interface_name(&self.tap_name)?;
        if self.cleanup != NetworkCleanup::ReleaseRuntimeNamespace {
            return Err(manifest_error(
                "KVM TAP transport requires release-runtime-namespace cleanup",
            ));
        }
        let expected_pointer = format!("/linux/netDevices/{}", escape_json_pointer(&self.tap_name));
        if self.interface.json_pointer() != expected_pointer {
            return Err(manifest_error(format!(
                "KVM TAP {} does not match interface attachment {}",
                self.tap_name,
                self.interface.json_pointer()
            )));
        }
        if !self
            .namespace
            .json_pointer()
            .starts_with("/linux/namespaces/")
        {
            return Err(manifest_error(format!(
                "KVM TAP {} does not reference an OCI Linux namespace",
                self.tap_name
            )));
        }
        validate_digest(self.namespace.value_digest(), "namespace value digest")?;
        validate_digest(self.interface.value_digest(), "interface value digest")?;
        AgentVmMacAddress::new(*self.mac_address.as_bytes())?;
        Ok(())
    }

    fn validate_configuration(&self, configuration: &Value) -> Result<()> {
        validate_configuration_attachment(configuration, &self.namespace, "network namespace")?;
        validate_configuration_attachment(configuration, &self.interface, "network interface")?;
        let namespace = configuration
            .pointer(self.namespace.json_pointer())
            .and_then(Value::as_object)
            .ok_or_else(|| manifest_error("network namespace attachment is not an object"))?;
        if namespace.get("type").and_then(Value::as_str) != Some("network") {
            return Err(manifest_error(format!(
                "KVM TAP {} does not select an OCI network namespace",
                self.tap_name
            )));
        }
        if namespace.contains_key("path") {
            return Err(manifest_error(format!(
                "KVM TAP {} cannot enter a caller-owned joined network namespace",
                self.tap_name
            )));
        }
        Ok(())
    }
}

/// Complete immutable network transport authority for one dedicated utility VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentVmAttachmentManifest {
    schema_version: String,
    target: ContainerTarget,
    guest_bundle: GuestPath,
    config_digest: String,
    attachment_digest: String,
    network: Vec<AgentVmNetworkAttachment>,
}

impl AgentVmAttachmentManifest {
    /// Construct and validate one canonical, non-empty network transport manifest.
    pub fn new(
        target: ContainerTarget,
        guest_bundle: GuestPath,
        config_digest: impl Into<String>,
        attachment_digest: impl Into<String>,
        network: Vec<AgentVmNetworkAttachment>,
    ) -> Result<Self> {
        let manifest = Self {
            schema_version: AGENT_VM_ATTACHMENT_MANIFEST_SCHEMA_VERSION.to_string(),
            target,
            guest_bundle,
            config_digest: config_digest.into(),
            attachment_digest: attachment_digest.into(),
            network,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Exact container generation owning this dedicated VM.
    #[must_use]
    pub const fn target(&self) -> &ContainerTarget {
        &self.target
    }

    /// Guest-visible bundle directory bound to the later create request.
    #[must_use]
    pub const fn guest_bundle(&self) -> &GuestPath {
        &self.guest_bundle
    }

    /// SHA-256 digest of the exact OCI configuration bytes.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// SHA-256 digest of the complete public create attachment contract.
    #[must_use]
    pub fn attachment_digest(&self) -> &str {
        &self.attachment_digest
    }

    /// Canonically ordered VMM network transports.
    #[must_use]
    pub fn network(&self) -> &[AgentVmNetworkAttachment] {
        &self.network
    }

    /// Encode the exact bounded JSON representation used for persistence and hashing.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|error| {
            manifest_error(format!(
                "failed to encode utility-VM attachment manifest: {error}"
            ))
        })?;
        if encoded.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES {
            return Err(manifest_error(
                "encoded utility-VM attachment manifest exceeds its bounded size",
            ));
        }
        Ok(encoded)
    }

    /// Decode and validate one bounded JSON representation.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.is_empty() || encoded.len() > AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES {
            return Err(manifest_error(
                "utility-VM attachment manifest must have a bounded nonzero size",
            ));
        }
        let manifest: Self = serde_json::from_slice(encoded).map_err(|error| {
            manifest_error(format!(
                "failed to decode utility-VM attachment manifest: {error}"
            ))
        })?;
        manifest.validate()?;
        if manifest.to_bytes()?.as_slice() != encoded {
            return Err(manifest_error(
                "utility-VM attachment manifest is not canonically encoded",
            ));
        }
        Ok(manifest)
    }

    /// SHA-256 digest of the exact encoded manifest.
    pub fn digest(&self) -> Result<String> {
        Ok(digest_bytes(&self.to_bytes()?))
    }

    /// Revalidate all public attachment pointers against the exact OCI bundle.
    pub fn validate_bundle(&self, bundle: &OciBundle) -> Result<()> {
        self.validate()?;
        if bundle.config_digest() != self.config_digest {
            return Err(manifest_error(format!(
                "utility-VM attachment manifest expects configuration {}, received {}",
                self.config_digest,
                bundle.config_digest()
            )));
        }
        let configuration: Value = serde_json::from_str(bundle.config_json()).map_err(|error| {
            manifest_error(format!(
                "validated OCI configuration could not be decoded for VM attachments: {error}"
            ))
        })?;
        for attachment in &self.network {
            attachment.validate_configuration(&configuration)?;
        }
        Ok(())
    }

    /// Validate schema, target, digests, canonical order, and transport uniqueness.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != AGENT_VM_ATTACHMENT_MANIFEST_SCHEMA_VERSION {
            return Err(manifest_error(format!(
                "unsupported utility-VM attachment manifest schema {}",
                self.schema_version
            )));
        }
        if !self
            .target
            .generation
            .is_some_and(|generation| generation.0 > 0)
        {
            return Err(manifest_error(format!(
                "utility-VM attachment manifest for {} requires a positive exact generation",
                self.target.id
            )));
        }
        let guest_bundle = self.guest_bundle.as_str();
        let expected_prefix = format!("{AGENT_RUNTIME_SHARE_GUEST_ROOT}/");
        if !guest_bundle.starts_with(&expected_prefix) {
            return Err(manifest_error(format!(
                "utility-VM attachment bundle must remain inside {AGENT_RUNTIME_SHARE_GUEST_ROOT}: {guest_bundle}"
            )));
        }
        validate_digest(&self.config_digest, "configuration digest")?;
        validate_digest(&self.attachment_digest, "attachment digest")?;
        if self.network.is_empty() || self.network.len() > MAX_NETWORK_ATTACHMENTS {
            return Err(manifest_error(format!(
                "utility-VM attachment manifest must carry 1..={MAX_NETWORK_ATTACHMENTS} network entries"
            )));
        }
        if self.network.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(manifest_error(
                "utility-VM network attachments must be unique and canonically ordered",
            ));
        }

        let mut tap_names = BTreeSet::new();
        let mut mac_addresses = BTreeSet::new();
        for attachment in &self.network {
            attachment.validate_shape()?;
            let expected_mac = AgentVmMacAddress::derive(
                &self.attachment_digest,
                attachment.identity(),
                attachment.tap_name(),
            )?;
            if attachment.mac_address() != expected_mac {
                return Err(manifest_error(format!(
                    "KVM TAP {} MAC is not derived from its immutable attachment evidence",
                    attachment.tap_name()
                )));
            }
            if !tap_names.insert(attachment.tap_name()) {
                return Err(manifest_error(format!(
                    "KVM TAP {} is declared more than once",
                    attachment.tap_name()
                )));
            }
            if !mac_addresses.insert(attachment.mac_address()) {
                return Err(manifest_error(format!(
                    "KVM TAP {} collides with another derived transport MAC",
                    attachment.tap_name()
                )));
            }
        }
        Ok(())
    }
}

fn validate_configuration_attachment(
    configuration: &Value,
    attachment: &ConfigurationAttachment,
    label: &str,
) -> Result<()> {
    let value = configuration
        .pointer(attachment.json_pointer())
        .ok_or_else(|| {
            manifest_error(format!(
                "{label} pointer does not exist in config.json: {}",
                attachment.json_pointer()
            ))
        })?;
    let digest = serde_json::to_vec(value)
        .map(|encoded| digest_bytes(&encoded))
        .map_err(|error| manifest_error(format!("failed to encode {label} evidence: {error}")))?;
    if digest != attachment.value_digest() {
        return Err(manifest_error(format!(
            "{label} evidence drifted at {}",
            attachment.json_pointer()
        )));
    }
    Ok(())
}

fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > LINUX_INTERFACE_NAME_BYTES
        || matches!(name, "." | "..")
        || name
            .bytes()
            .any(|byte| matches!(byte, b'/' | b':' | 0) || byte.is_ascii_whitespace())
    {
        return Err(manifest_error(format!(
            "KVM TAP name must be a valid 1..={LINUX_INTERFACE_NAME_BYTES} byte Linux interface name: {name:?}"
        )));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(manifest_error(format!(
            "utility-VM {label} must use a sha256 digest"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(manifest_error(format!(
            "utility-VM {label} must contain exactly 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn manifest_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-agent-vm-attachments")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{
        oci_spec::runtime::Spec, ContainerTarget, CreateAttachments, Generation,
        NetworkAttachmentIdentity, NetworkCleanup, NetworkCleanupId, NetworkInterfaceId,
        NetworkNamespaceId, OciBundle, ProcessIo,
    };
    use serde_json::{json, Value};

    use super::{
        AgentVmAttachmentManifest, AgentVmMacAddress, AgentVmNetworkAttachment,
        AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES,
    };
    use crate::GuestPath;

    fn fixture() -> (OciBundle, CreateAttachments, AgentVmAttachmentManifest) {
        let mut value = serde_json::to_value(Spec::default()).expect("default OCI spec");
        value["linux"] = json!({
            "namespaces": [{"type": "network"}, {"type": "uts"}],
            "netDevices": {"tap0": {"name": "eth0"}}
        });
        let bundle = OciBundle::from_json(
            std::env::temp_dir().join("a3s-agent-vm-manifest-fixture"),
            serde_json::to_string(&value).expect("fixture JSON"),
        )
        .expect("valid OCI bundle");
        let identity = NetworkAttachmentIdentity::new(
            NetworkNamespaceId::new("namespace-1").expect("namespace identity"),
            NetworkInterfaceId::new("interface-1").expect("interface identity"),
            NetworkCleanupId::new("cleanup-1").expect("cleanup identity"),
        );
        let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("base attachments")
            .attach_linux_network_interface(
                &bundle,
                0,
                "tap0",
                identity,
                NetworkCleanup::ReleaseRuntimeNamespace,
            )
            .expect("authorized network attachment");
        let digest = attachments.digest().expect("attachment digest");
        let public = attachments.network_attachments()[0].clone();
        let mac =
            AgentVmMacAddress::derive(&digest, public.identity(), "tap0").expect("transport MAC");
        let network = AgentVmNetworkAttachment::new(
            public.identity().clone(),
            "tap0",
            public.namespace().clone(),
            public.interface().clone(),
            public.cleanup(),
            mac,
        )
        .expect("network transport");
        let manifest = AgentVmAttachmentManifest::new(
            ContainerTarget::exact(
                a3s_oci_sdk::ContainerId::new("networked").expect("container ID"),
                Generation(1),
            ),
            GuestPath::new("/run/a3s-oci-runtime/bundle").expect("guest bundle"),
            bundle.config_digest(),
            digest,
            vec![network],
        )
        .expect("VM attachment manifest");
        (bundle, attachments, manifest)
    }

    #[test]
    fn round_trips_and_binds_the_exact_oci_configuration() {
        let (bundle, _, manifest) = fixture();
        let encoded = manifest.to_bytes().expect("encoded manifest");
        assert!(encoded.len() < AGENT_VM_ATTACHMENT_MANIFEST_MAX_BYTES);
        let decoded = AgentVmAttachmentManifest::from_bytes(&encoded).expect("decoded manifest");
        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded.digest().expect("manifest digest"),
            manifest.digest().unwrap()
        );
        decoded
            .validate_bundle(&bundle)
            .expect("exact bundle binding");
        assert_eq!(decoded.network()[0].tap_name(), "tap0");
        assert_eq!(
            decoded.network()[0].mac_address().as_bytes()[0] & 0x03,
            0x02
        );
    }

    #[test]
    fn mac_derivation_has_an_architecture_independent_vector() {
        let identity = NetworkAttachmentIdentity::new(
            NetworkNamespaceId::new("namespace-1").expect("namespace identity"),
            NetworkInterfaceId::new("interface-1").expect("interface identity"),
            NetworkCleanupId::new("cleanup-1").expect("cleanup identity"),
        );
        let mac =
            AgentVmMacAddress::derive(&format!("sha256:{}", "1".repeat(64)), &identity, "tap0")
                .expect("transport MAC");
        assert_eq!(mac.as_bytes(), &[0x8e, 0x5c, 0xc9, 0xe1, 0x8d, 0x4c]);
    }

    #[test]
    fn rejects_joined_namespaces_and_configuration_drift() {
        let (bundle, _, manifest) = fixture();
        let mut joined: Value = serde_json::from_str(bundle.config_json()).expect("fixture JSON");
        joined["linux"]["namespaces"][0]["path"] = json!("/proc/1/ns/net");
        let joined = OciBundle::from_json(
            std::env::temp_dir().join("a3s-agent-vm-joined-fixture"),
            serde_json::to_string(&joined).expect("joined JSON"),
        )
        .expect("joined OCI bundle");
        let error = manifest
            .validate_bundle(&joined)
            .expect_err("a different config digest must fail closed");
        assert!(error.message.contains("expects configuration"));

        let mut encoded: Value =
            serde_json::from_slice(&manifest.to_bytes().expect("manifest bytes"))
                .expect("manifest JSON");
        encoded["network"][0]["cleanup"] = json!("preserve-caller-namespace");
        let error = AgentVmAttachmentManifest::from_bytes(
            &serde_json::to_vec(&encoded).expect("mutated manifest"),
        )
        .expect_err("joined cleanup must be rejected");
        assert!(error.message.contains("release-runtime-namespace"));
    }

    #[test]
    fn rejects_reordered_duplicates_and_digest_drift() {
        let (_, _, manifest) = fixture();
        let mut noncanonical = manifest.to_bytes().expect("manifest bytes");
        noncanonical.push(b'\n');
        assert!(AgentVmAttachmentManifest::from_bytes(&noncanonical).is_err());

        let mut encoded: Value =
            serde_json::from_slice(&manifest.to_bytes().expect("manifest bytes"))
                .expect("manifest JSON");
        let duplicate = encoded["network"][0].clone();
        encoded["network"]
            .as_array_mut()
            .expect("network array")
            .push(duplicate);
        assert!(AgentVmAttachmentManifest::from_bytes(
            &serde_json::to_vec(&encoded).expect("duplicate manifest")
        )
        .is_err());

        let mut encoded: Value =
            serde_json::from_slice(&manifest.to_bytes().expect("manifest bytes"))
                .expect("manifest JSON");
        encoded["attachmentDigest"] = json!(format!("sha256:{}", "A".repeat(64)));
        assert!(AgentVmAttachmentManifest::from_bytes(
            &serde_json::to_vec(&encoded).expect("drifted manifest")
        )
        .is_err());

        let mut encoded: Value =
            serde_json::from_slice(&manifest.to_bytes().expect("manifest bytes"))
                .expect("manifest JSON");
        encoded["attachmentDigest"] = json!(format!("sha256:{}", "0".repeat(64)));
        let error = AgentVmAttachmentManifest::from_bytes(
            &serde_json::to_vec(&encoded).expect("digest-rebound manifest"),
        )
        .expect_err("transport MAC must remain bound to the attachment digest");
        assert!(error.message.contains("not derived"));
    }
}
