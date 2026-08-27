use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{escape_json_pointer, invalid_attachment, AttachmentSource, ConfigurationAttachment};
use crate::{NetworkCleanupId, NetworkInterfaceId, NetworkNamespaceId, Result};

/// Immutable caller-issued identities for one authorized network binding.
///
/// These values identify allocation incarnations, not mutable interface names,
/// namespace paths, IP addresses, DNS names, or policy selectors.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkAttachmentIdentity {
    namespace: NetworkNamespaceId,
    interface: NetworkInterfaceId,
    cleanup: NetworkCleanupId,
}

impl NetworkAttachmentIdentity {
    /// Bind one namespace, interface, and cleanup incarnation.
    #[must_use]
    pub const fn new(
        namespace: NetworkNamespaceId,
        interface: NetworkInterfaceId,
        cleanup: NetworkCleanupId,
    ) -> Self {
        Self {
            namespace,
            interface,
            cleanup,
        }
    }

    /// Caller-issued namespace allocation identity.
    #[must_use]
    pub const fn namespace(&self) -> &NetworkNamespaceId {
        &self.namespace
    }

    /// Caller-issued interface allocation identity.
    #[must_use]
    pub const fn interface(&self) -> &NetworkInterfaceId {
        &self.interface
    }

    /// Caller-issued identity for the matching cleanup obligation.
    #[must_use]
    pub const fn cleanup(&self) -> &NetworkCleanupId {
        &self.cleanup
    }
}

/// Authority that retains ownership of the network allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkOwnership {
    /// The caller retains IPAM, DNS, route, policy, and backing-network authority.
    Caller,
}

/// Namespace cleanup behavior for an authorized network binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkCleanup {
    /// Release the runtime-created network namespace with the container.
    ReleaseRuntimeNamespace,
    /// Leave a joined, caller-owned namespace and its interface intact.
    PreserveCallerNamespace,
}

/// Exact OCI namespace and interface descriptors for one authorized network endpoint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkAttachment {
    identity: NetworkAttachmentIdentity,
    namespace: ConfigurationAttachment,
    interface: ConfigurationAttachment,
    ownership: NetworkOwnership,
    cleanup: NetworkCleanup,
}

impl NetworkAttachment {
    pub(super) const fn new(
        identity: NetworkAttachmentIdentity,
        namespace: ConfigurationAttachment,
        interface: ConfigurationAttachment,
        cleanup: NetworkCleanup,
    ) -> Self {
        Self {
            identity,
            namespace,
            interface,
            ownership: NetworkOwnership::Caller,
            cleanup,
        }
    }

    /// Immutable logical identities supplied by the caller.
    #[must_use]
    pub const fn identity(&self) -> &NetworkAttachmentIdentity {
        &self.identity
    }

    /// Digest-bound OCI Linux network namespace descriptor.
    #[must_use]
    pub const fn namespace(&self) -> &ConfigurationAttachment {
        &self.namespace
    }

    /// Digest-bound OCI `linux.netDevices` descriptor.
    #[must_use]
    pub const fn interface(&self) -> &ConfigurationAttachment {
        &self.interface
    }

    /// Authority that owns the network allocation and product policy.
    #[must_use]
    pub const fn ownership(&self) -> NetworkOwnership {
        self.ownership
    }

    /// Exact namespace cleanup behavior.
    #[must_use]
    pub const fn cleanup(&self) -> NetworkCleanup {
        self.cleanup
    }
}

pub(super) fn validate_attachments(
    attachments: &[NetworkAttachment],
    network_sources: &[AttachmentSource],
    configuration: &Value,
) -> Result<()> {
    if attachments.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_attachment(
            "network attachments must be unique and canonically ordered",
        ));
    }

    let configured_sources = network_sources
        .iter()
        .filter_map(|source| match source {
            AttachmentSource::OciConfiguration { configuration } => Some(configuration),
            AttachmentSource::RuntimeExtension { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let mut interface_identities = BTreeSet::new();
    let mut interfaces = BTreeSet::new();
    let mut namespaces_by_identity = BTreeMap::new();
    let mut namespace_identities = BTreeMap::new();
    let mut namespaces_by_cleanup = BTreeMap::new();

    for attachment in attachments {
        if !interface_identities.insert(attachment.identity.interface()) {
            return Err(invalid_attachment(format!(
                "network interface identity {} is declared more than once",
                attachment.identity.interface()
            )));
        }
        if !interfaces.insert(&attachment.interface) {
            return Err(invalid_attachment(format!(
                "network interface {} is declared more than once",
                attachment.interface.json_pointer()
            )));
        }
        if !configured_sources.contains(&attachment.namespace)
            || !configured_sources.contains(&attachment.interface)
        {
            return Err(invalid_attachment(
                "authorized network attachment does not reference the OCI network inventory",
            ));
        }

        attachment.namespace.validate(configuration)?;
        attachment.interface.validate(configuration)?;
        validate_interface(configuration, &attachment.interface)?;
        let joined = validate_namespace(configuration, &attachment.namespace)?;
        match (joined, attachment.cleanup) {
            (false, NetworkCleanup::ReleaseRuntimeNamespace)
            | (true, NetworkCleanup::PreserveCallerNamespace) => {}
            (false, NetworkCleanup::PreserveCallerNamespace) => {
                return Err(invalid_attachment(
                    "a new OCI network namespace requires release-runtime-namespace cleanup",
                ));
            }
            (true, NetworkCleanup::ReleaseRuntimeNamespace) => {
                return Err(invalid_attachment(
                    "a joined OCI network namespace requires preserve-caller-namespace cleanup",
                ));
            }
        }

        let namespace_identity = attachment.identity.namespace();
        let cleanup_identity = attachment.identity.cleanup();
        if let Some((known_namespace, known_cleanup, known_mode)) =
            namespaces_by_identity.get(namespace_identity)
        {
            if *known_namespace != &attachment.namespace {
                return Err(invalid_attachment(format!(
                    "network namespace identity {namespace_identity} selects more than one OCI namespace"
                )));
            }
            if *known_cleanup != cleanup_identity || *known_mode != attachment.cleanup {
                return Err(invalid_attachment(format!(
                    "network namespace identity {namespace_identity} has conflicting cleanup identity or mode"
                )));
            }
        } else {
            namespaces_by_identity.insert(
                namespace_identity,
                (&attachment.namespace, cleanup_identity, attachment.cleanup),
            );
        }
        if let Some(known_identity) = namespace_identities.get(&attachment.namespace) {
            if *known_identity != namespace_identity {
                return Err(invalid_attachment(format!(
                    "OCI network namespace {} has conflicting namespace identities",
                    attachment.namespace.json_pointer()
                )));
            }
        } else {
            namespace_identities.insert(&attachment.namespace, namespace_identity);
        }
        if let Some(known_namespace) = namespaces_by_cleanup.get(cleanup_identity) {
            if *known_namespace != namespace_identity {
                return Err(invalid_attachment(format!(
                    "network cleanup identity {cleanup_identity} selects more than one namespace identity"
                )));
            }
        } else {
            namespaces_by_cleanup.insert(cleanup_identity, namespace_identity);
        }
    }
    Ok(())
}

fn validate_namespace(configuration: &Value, attachment: &ConfigurationAttachment) -> Result<bool> {
    let namespace = configuration
        .pointer(attachment.json_pointer())
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_attachment("network namespace attachment is not an object"))?;
    if namespace.get("type").and_then(Value::as_str) != Some("network") {
        return Err(invalid_attachment(format!(
            "network namespace attachment {} does not select an OCI network namespace",
            attachment.json_pointer()
        )));
    }
    match namespace.get("path") {
        None => Ok(false),
        Some(Value::String(path)) if !path.is_empty() => Ok(true),
        Some(_) => Err(invalid_attachment(
            "OCI network namespace path must be a non-empty string when present",
        )),
    }
}

fn validate_interface(configuration: &Value, attachment: &ConfigurationAttachment) -> Result<()> {
    let devices = configuration
        .pointer("/linux/netDevices")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            invalid_attachment("network interface attachment requires linux.netDevices")
        })?;
    let selected = devices.iter().find(|(host_name, _)| {
        format!("/linux/netDevices/{}", escape_json_pointer(host_name)) == attachment.json_pointer()
    });
    let Some((host_name, device)) = selected else {
        return Err(invalid_attachment(format!(
            "network interface attachment {} does not select a linux.netDevices entry",
            attachment.json_pointer()
        )));
    };
    let target = device
        .as_object()
        .and_then(|device| device.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(host_name);
    if target.contains('%') {
        return Err(invalid_attachment(format!(
            "authorized network interface {host_name} requires an exact target name, not template {target}"
        )));
    }
    Ok(())
}
