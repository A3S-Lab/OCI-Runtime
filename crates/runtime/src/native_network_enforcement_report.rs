use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{
    ExitStatus, NetworkCleanupId, NetworkEnforcementAttachment, NetworkInterfaceId, Result,
};
use serde::{Deserialize, Serialize};

/// Schema emitted by the Native Linux OAR-01 qualification.
pub const NATIVE_LINUX_NETWORK_ENFORCEMENT_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-network-enforcement-smoke.v1";

/// Caller-owned fixture identity used only by the Native Linux OAR-01 gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLinuxNetworkEnforcementSmokeConfig {
    source_interface: String,
    interface_id: NetworkInterfaceId,
    cleanup_id: NetworkCleanupId,
    redirect_port: u16,
    rejected_port: u16,
}

impl NativeLinuxNetworkEnforcementSmokeConfig {
    /// Construct one policy-neutral qualification profile.
    pub fn new(
        source_interface: impl Into<String>,
        interface_id: NetworkInterfaceId,
        cleanup_id: NetworkCleanupId,
        redirect_port: u16,
        rejected_port: u16,
    ) -> Result<Self> {
        let source_interface = source_interface.into();
        if source_interface.is_empty() {
            return Err(a3s_oci_sdk::Error::new(
                a3s_oci_sdk::ErrorCode::InvalidArgument,
                "network-enforcement qualification requires a source interface",
            )
            .for_operation("native-linux-network-enforcement-config"));
        }
        if redirect_port == 0 || rejected_port == 0 || redirect_port == rejected_port {
            return Err(a3s_oci_sdk::Error::new(
                a3s_oci_sdk::ErrorCode::InvalidArgument,
                "network-enforcement qualification ports must be positive and distinct",
            )
            .for_operation("native-linux-network-enforcement-config"));
        }
        Ok(Self {
            source_interface,
            interface_id,
            cleanup_id,
            redirect_port,
            rejected_port,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn source_interface(&self) -> &str {
        &self.source_interface
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn interface_id(&self) -> &NetworkInterfaceId {
        &self.interface_id
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn cleanup_id(&self) -> &NetworkCleanupId {
        &self.cleanup_id
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn redirect_port(&self) -> u16 {
        self.redirect_port
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn rejected_port(&self) -> u16 {
        self.rejected_port
    }
}

/// Real-host Native Linux evidence for one opaque caller-owned network mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxNetworkEnforcementSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the qualified mechanism path.
    pub status: CapabilityStatus,
    /// Whether `/dev/kvm` existed while the independent Native path ran.
    pub kvm_device_present: bool,
    /// Whether the exact submitted OCI bundle loaded successfully.
    pub bundle_loaded: bool,
    /// Whether the selected Native driver advertised OAR-01 version 1.
    pub extension_advertised: bool,
    /// Opaque attachment decoded from the exact annotation and retained state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<NetworkEnforcementAttachment>,
    /// Whether the caller-owned redirect and rejection mechanisms worked before Create.
    pub mechanism_verified_before_create: bool,
    /// Whether Create returned the exact OCI created barrier.
    pub create_returned_created: bool,
    /// Whether retrying Create returned the exact original result.
    pub create_replayed: bool,
    /// Host-visible init PID returned while the container was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether init joined the exact caller-owned network namespace.
    pub container_namespace_verified: bool,
    /// Whether the exact source interface moved to its authorized target name.
    pub interface_binding_verified: bool,
    /// Whether the configured workload observed the caller-owned local redirect.
    pub local_redirect_verified: bool,
    /// Whether the configured workload observed the caller-owned rejection boundary.
    pub enforcement_rejection_verified: bool,
    /// Whether reopening the durable Host service retained the live container.
    pub host_service_reopened: bool,
    /// Whether Host reopen retained the exact Runtime generation.
    pub generation_reused_after_reopen: bool,
    /// Whether Host reopen retained the exact live init PID.
    pub pid_reused_after_reopen: bool,
    /// Whether the exact opaque attachment evidence survived Host reopen.
    pub attachment_replayed_after_reopen: bool,
    /// Whether retrying Start after Host reopen avoided a second mutation.
    pub start_replayed_after_reopen: bool,
    /// Exact terminal result returned after the qualification kill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_exit_status: Option<ExitStatus>,
    /// Whether Delete and its exact replay both succeeded.
    pub delete_replayed: bool,
    /// Whether state became NotFound after exact-generation deletion.
    pub durable_state_removed: bool,
    /// Whether the joined namespace inode remained caller-owned after Delete.
    pub namespace_preserved_after_delete: bool,
    /// Whether the authorized target interface remained in that namespace.
    pub interface_preserved_after_delete: bool,
    /// Whether redirect and rejection behavior remained active after Delete.
    pub mechanism_preserved_after_delete: bool,
    /// Whether qualification-only workload markers were removed.
    pub markers_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the diagnostic removed its durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxNetworkEnforcementSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: NATIVE_LINUX_NETWORK_ENFORCEMENT_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            kvm_device_present: false,
            bundle_loaded: false,
            extension_advertised: false,
            attachment: None,
            mechanism_verified_before_create: false,
            create_returned_created: false,
            create_replayed: false,
            created_pid: None,
            container_namespace_verified: false,
            interface_binding_verified: false,
            local_redirect_verified: false,
            enforcement_rejection_verified: false,
            host_service_reopened: false,
            generation_reused_after_reopen: false,
            pid_reused_after_reopen: false,
            attachment_replayed_after_reopen: false,
            start_replayed_after_reopen: false,
            wait_exit_status: None,
            delete_replayed: false,
            durable_state_removed: false,
            namespace_preserved_after_delete: false,
            interface_preserved_after_delete: false,
            mechanism_preserved_after_delete: false,
            markers_removed: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("Native network-enforcement qualification requires Linux".into());
        report
    }

    /// Return whether every OAR-01 identity, lifecycle, and cleanup invariant passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.bundle_loaded
            && self.extension_advertised
            && self.attachment.is_some()
            && self.mechanism_verified_before_create
            && self.create_returned_created
            && self.create_replayed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.container_namespace_verified
            && self.interface_binding_verified
            && self.local_redirect_verified
            && self.enforcement_rejection_verified
            && self.host_service_reopened
            && self.generation_reused_after_reopen
            && self.pid_reused_after_reopen
            && self.attachment_replayed_after_reopen
            && self.start_replayed_after_reopen
            && self.wait_exit_status
                == Some(ExitStatus {
                    exit_code: None,
                    signal: Some(9),
                    oom_killed: false,
                })
            && self.delete_replayed
            && self.durable_state_removed
            && self.namespace_preserved_after_delete
            && self.interface_preserved_after_delete
            && self.mechanism_preserved_after_delete
            && self.markers_removed
            && self.executor_runtime_clean
            && self.session_root_clean
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{
        LocalNetworkRedirectAttachment, NetworkEnforcementId, NetworkMechanismDigest,
        NetworkMechanismGeneration, NetworkNamespaceId, NetworkRedirectId,
    };

    use super::*;

    fn interface_id() -> NetworkInterfaceId {
        NetworkInterfaceId::new("oar01-interface").expect("interface identity")
    }

    fn cleanup_id() -> NetworkCleanupId {
        NetworkCleanupId::new("oar01-cleanup").expect("cleanup identity")
    }

    fn attachment() -> NetworkEnforcementAttachment {
        let generation = NetworkMechanismGeneration::new(1).expect("mechanism generation");
        NetworkEnforcementAttachment::new(
            NetworkEnforcementId::new("oar01-policy").expect("enforcement identity"),
            generation,
            NetworkMechanismDigest::new(format!("sha256:{}", "1".repeat(64)))
                .expect("compiled-policy digest"),
            NetworkNamespaceId::new("oar01-namespace").expect("namespace identity"),
            Some(LocalNetworkRedirectAttachment::new(
                NetworkRedirectId::new("oar01-redirect").expect("redirect identity"),
                generation,
                NetworkMechanismDigest::new(format!("sha256:{}", "2".repeat(64)))
                    .expect("redirect digest"),
            )),
        )
    }

    #[test]
    fn qualification_config_rejects_invalid_ports_and_source() {
        assert!(NativeLinuxNetworkEnforcementSmokeConfig::new(
            "",
            interface_id(),
            cleanup_id(),
            18080,
            18082,
        )
        .is_err());
        for (redirect, rejected) in [(0, 18082), (18080, 0), (18080, 18080)] {
            assert!(NativeLinuxNetworkEnforcementSmokeConfig::new(
                "eth0",
                interface_id(),
                cleanup_id(),
                redirect,
                rejected,
            )
            .is_err());
        }
    }

    #[test]
    fn success_requires_every_identity_lifecycle_and_cleanup_evidence() {
        let mut report = NativeLinuxNetworkEnforcementSmokeReport::initial(HostPlatform::Linux);
        report.status = CapabilityStatus::Available;
        report.bundle_loaded = true;
        report.extension_advertised = true;
        report.attachment = Some(attachment());
        report.mechanism_verified_before_create = true;
        report.create_returned_created = true;
        report.create_replayed = true;
        report.created_pid = Some(42);
        report.container_namespace_verified = true;
        report.interface_binding_verified = true;
        report.local_redirect_verified = true;
        report.enforcement_rejection_verified = true;
        report.host_service_reopened = true;
        report.generation_reused_after_reopen = true;
        report.pid_reused_after_reopen = true;
        report.attachment_replayed_after_reopen = true;
        report.start_replayed_after_reopen = true;
        report.wait_exit_status = Some(ExitStatus {
            exit_code: None,
            signal: Some(9),
            oom_killed: false,
        });
        report.delete_replayed = true;
        report.durable_state_removed = true;
        report.namespace_preserved_after_delete = true;
        report.interface_preserved_after_delete = true;
        report.mechanism_preserved_after_delete = true;
        report.markers_removed = true;
        report.executor_runtime_clean = true;
        report.session_root_clean = true;

        assert!(report.is_success());
        report.attachment_replayed_after_reopen = false;
        assert!(!report.is_success());
    }
}
