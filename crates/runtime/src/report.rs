use a3s_oci_agent_protocol::{AgentOperation, AGENT_PROTOCOL_VERSION_MAX};
use a3s_oci_core::CapabilityStatus;
use a3s_oci_core::HostPlatform;
use a3s_oci_sdk::{ExitStatus, RuntimeOperation};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema emitted by the WHPX smoke command.
pub const WHPX_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.whpx-smoke.v1";
/// Schema emitted by the Hypervisor.framework VM-object smoke.
pub const HVF_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.hvf-smoke.v1";
/// Schema emitted by the authenticated guest-agent VM smoke.
pub const AGENT_VM_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.agent-vm-smoke.v9";
/// Schema emitted by the fixed OCI core-lifecycle utility-VM smoke.
pub const OCI_VM_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.oci-vm-smoke.v9";
/// Schema emitted by the native Linux SDK lifecycle smoke.
pub const NATIVE_LINUX_SMOKE_SCHEMA_VERSION: &str = "a3s.oci.native-linux-smoke.v12";
/// Schema emitted by the native Linux rootless lifecycle smoke.
pub const NATIVE_LINUX_ROOTLESS_SMOKE_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-rootless-smoke.v3";

/// Result of querying WHPX and creating then deleting a partition object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhpxSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host status of the Windows Hypervisor Platform prerequisite.
    pub status: CapabilityStatus,
    /// Whether `WinHvPlatform.dll` loaded from the system search scope.
    pub dll_loaded: bool,
    /// Whether WHPX reported the Windows hypervisor present.
    pub hypervisor_present: bool,
    /// Whether a partition object was created and deleted successfully.
    pub partition_object_round_trip: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WhpxSmokeReport {
    #[cfg(windows)]
    pub(crate) fn unavailable(
        dll_loaded: bool,
        hypervisor_present: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unavailable,
            dll_loaded,
            hypervisor_present,
            partition_object_round_trip: false,
            reason: Some(reason.into()),
        }
    }

    #[cfg(not(windows))]
    pub(crate) fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Unsupported,
            dll_loaded: false,
            hypervisor_present: false,
            partition_object_round_trip: false,
            reason: Some(reason.into()),
        }
    }

    #[cfg(windows)]
    pub(crate) fn success() -> Self {
        Self {
            schema_version: WHPX_SMOKE_SCHEMA_VERSION.to_string(),
            status: CapabilityStatus::Available,
            dll_loaded: true,
            hypervisor_present: true,
            partition_object_round_trip: true,
            reason: None,
        }
    }

    /// Return whether every smoke step succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.dll_loaded
            && self.hypervisor_present
            && self.partition_object_round_trip
    }
}

/// Result of querying Hypervisor.framework and creating then destroying a VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HvfSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// Host status of the Hypervisor.framework prerequisite.
    pub status: CapabilityStatus,
    /// Whether the runtime target is Apple Silicon.
    pub apple_silicon: bool,
    /// Value returned by the direct `kern.hv_support` query.
    pub hypervisor_supported: Option<bool>,
    /// Whether `hv_vm_create` created a process-owned VM object.
    pub vm_created: bool,
    /// Whether `hv_vm_destroy` released that VM object.
    pub vm_destroyed: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl HvfSmokeReport {
    pub(crate) fn initial(
        platform: HostPlatform,
        apple_silicon: bool,
        hypervisor_supported: Option<bool>,
    ) -> Self {
        Self {
            schema_version: HVF_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            apple_silicon,
            hypervisor_supported,
            vm_created: false,
            vm_destroyed: false,
            reason: None,
        }
    }

    pub(crate) fn unsupported(platform: HostPlatform, reason: impl Into<String>) -> Self {
        let mut report = Self::initial(platform, false, None);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some(reason.into());
        report
    }

    /// Return whether the real VM-object round trip succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.platform == HostPlatform::Macos
            && self.apple_silicon
            && self.hypervisor_supported == Some(true)
            && self.vm_created
            && self.vm_destroyed
    }
}

/// macOS host-resource evidence captured around one guest-agent VM session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosHostCleanupEvidence {
    /// Whether the exact runtime-owned Unix endpoint was removed.
    pub endpoint_removed: bool,
    /// Whether the public libkrun shim process disappeared after it was waited.
    pub shim_reaped: bool,
    /// Whether the direct libkrun VM worker disappeared after session cleanup.
    pub bridge_reaped: bool,
    /// Number of host descriptors open before the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_descriptors_before: Option<u32>,
    /// Number of host descriptors open after the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_descriptors_after: Option<u32>,
    /// Whether the complete host `(descriptor, type)` inventory was restored.
    pub descriptor_inventory_restored: bool,
    /// Diagnostic reason when cleanup verification was incomplete or failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MacosHostCleanupEvidence {
    /// Return whether every tracked macOS host resource returned to baseline.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.endpoint_removed
            && self.shim_reaped
            && self.bridge_reaped
            && self
                .open_descriptors_before
                .is_some_and(|descriptor_count| descriptor_count > 0)
            && self.open_descriptors_before == self.open_descriptors_after
            && self.descriptor_inventory_restored
            && self.reason.is_none()
    }
}

/// End-to-end evidence from host endpoint binding through guest-agent negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentVmSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Whether an exclusive, protected host endpoint was bound.
    pub endpoint_bound: bool,
    /// Portable basename of the exact host endpoint allocated for this session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_name: Option<String>,
    /// Whether the isolated libkrun shim process was started.
    pub shim_spawned: bool,
    /// Process ID of the public libkrun shim parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_process_id: Option<u32>,
    /// Process ID of the verified bridge peer.
    ///
    /// This is the shim itself on Windows and its direct VM worker child on
    /// macOS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge_process_id: Option<u32>,
    /// Whether the connected bridge peer matched the required process identity.
    pub shim_client_verified: bool,
    /// Whether token authentication and protocol negotiation succeeded.
    pub protocol_negotiated: bool,
    /// Selected guest-agent protocol version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_protocol: Option<u16>,
    /// Version reported by the agent started at the fixed guest path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// Guest architecture reported during negotiation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_architecture: Option<String>,
    /// Exact operations advertised by the guest.
    pub advertised_operations: Vec<AgentOperation>,
    /// Whether the shim's bounded machine-readable evidence was valid.
    pub shim_report_verified: bool,
    /// Exit code returned by the isolated shim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_exit_code: Option<i32>,
    /// Whether libkrun created the requested guest console file.
    pub console_created: bool,
    /// Exact shim evidence retained without linking libkrun into the runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shim_report: Option<Value>,
    /// Host endpoint, process, and descriptor cleanup evidence on macOS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macos_cleanup: Option<MacosHostCleanupEvidence>,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AgentVmSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: AGENT_VM_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            endpoint_bound: false,
            endpoint_name: None,
            shim_spawned: false,
            shim_process_id: None,
            bridge_process_id: None,
            shim_client_verified: false,
            protocol_negotiated: false,
            selected_protocol: None,
            agent_version: None,
            guest_architecture: None,
            advertised_operations: Vec::new(),
            shim_report_verified: false,
            shim_exit_code: None,
            console_created: false,
            shim_report: None,
            macos_cleanup: None,
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some(
            "the authenticated guest-agent VM smoke is implemented only for Windows x86_64/WHPX \
             and macOS aarch64/HVF"
                .into(),
        );
        report
    }

    /// Return whether host authentication, guest negotiation, and VM exit succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.session_is_success()
            && match self.platform {
                HostPlatform::Macos => self
                    .macos_cleanup
                    .as_ref()
                    .is_some_and(MacosHostCleanupEvidence::is_success),
                _ => self.macos_cleanup.is_none(),
            }
    }

    /// Return whether the owned VM session completed its authenticated contract.
    ///
    /// A long-lived Host Service can own multiple concurrent macOS sessions, so
    /// one session cannot compare the process-wide descriptor inventory against
    /// a baseline captured before every other session. Product owners use this
    /// narrower result after reaping their exact shim and worker. Standalone
    /// qualification must continue to use [`Self::is_success`], which also
    /// requires endpoint, process, and descriptor cleanup evidence.
    pub(crate) fn session_is_success(&self) -> bool {
        let process_identity_matches =
            match (self.platform, self.shim_process_id, self.bridge_process_id) {
                (HostPlatform::Windows, Some(shim), Some(bridge)) => shim != 0 && bridge == shim,
                (HostPlatform::Macos, Some(shim), Some(bridge)) => {
                    shim != 0 && bridge != 0 && bridge != shim
                }
                _ => false,
            };
        let expected_architecture = match self.platform {
            HostPlatform::Windows => Some("x86_64"),
            HostPlatform::Macos => Some("aarch64"),
            _ => None,
        };
        matches!(self.status, CapabilityStatus::Available)
            && self.endpoint_bound
            && self.shim_spawned
            && process_identity_matches
            && self.shim_client_verified
            && self.protocol_negotiated
            && self.selected_protocol == Some(AGENT_PROTOCOL_VERSION_MAX)
            && self.agent_version.as_deref() == Some(env!("CARGO_PKG_VERSION"))
            && self.guest_architecture.as_deref() == expected_architecture
            && self.advertised_operations
                == [
                    AgentOperation::Create,
                    AgentOperation::State,
                    AgentOperation::Start,
                    AgentOperation::Kill,
                    AgentOperation::Delete,
                    AgentOperation::Wait,
                    AgentOperation::Exec,
                    AgentOperation::SignalProcess,
                    AgentOperation::WaitProcess,
                    AgentOperation::Pause,
                    AgentOperation::Resume,
                    AgentOperation::Processes,
                    AgentOperation::Update,
                    AgentOperation::Stats,
                    AgentOperation::ReadOutput,
                    AgentOperation::WriteStdin,
                    AgentOperation::CloseStdin,
                    AgentOperation::Resize,
                    AgentOperation::File,
                    AgentOperation::Filesystem,
                ]
            && self.shim_report_verified
            && self.shim_exit_code == Some(0)
            && self.console_created
            && self.shim_report.is_some()
    }
}

/// End-to-end SDK evidence for the native Linux executor path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the native lifecycle path.
    pub status: CapabilityStatus,
    /// Whether `/dev/kvm` existed while the independent native path ran.
    pub kvm_device_present: bool,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Whether host-created A3S Box listener and log descriptors passed validation.
    pub control_descriptors_prepared: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Whether dedicated-VM isolation failed before claiming the create ID.
    pub dedicated_vm_rejected_before_create: bool,
    /// Whether create returned the exact OCI `created` barrier.
    pub create_returned_created: bool,
    /// Whether retrying create replayed its exact original result.
    pub create_replayed: bool,
    /// Whether retrying that operation without the attachment schema failed.
    pub create_without_control_descriptors_rejected: bool,
    /// Whether unfiltered and isolation-filtered list returned the exact created record.
    pub list_visible_after_create: bool,
    /// Whether the durable lifecycle and process event stream was exact and ordered.
    pub events_verified: bool,
    /// OCI hook phases advertised by the configured native driver.
    pub hook_phases: Vec<String>,
    /// Whether all six hook phases received exact state in normative order.
    pub hooks_verified: bool,
    /// Host-visible init PID returned while the container was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether the workload marker remained absent before start.
    pub marker_absent_after_create: bool,
    /// Whether start released the prepared init wrapper.
    pub start_released: bool,
    /// Whether the configured process was observed running.
    pub running_observed: bool,
    /// Whether process inventory contained the exact live init and exec processes.
    pub processes_verified: bool,
    /// Whether captured stdout/stderr and piped stdin passed end-to-end.
    pub process_io_verified: bool,
    /// Whether PTY allocation, resize, interactive I/O, and EOF passed end-to-end.
    pub terminal_io_verified: bool,
    /// Whether binary upload/download and mutation replay passed end-to-end.
    pub file_transfer_verified: bool,
    /// Whether directory, stat, list, move, and recursive cleanup passed end-to-end.
    pub filesystem_operations_verified: bool,
    /// Whether live OCI Linux resources were applied and exactly replayed.
    pub resources_updated: bool,
    /// Whether normalized cgroup counters were exact and generation-fenced.
    pub stats_verified: bool,
    /// Whether a real progress-producing workload stopped while its cgroup was frozen.
    pub pause_froze_workload: bool,
    /// Whether the frozen workload advanced again after resume.
    pub resume_advanced_workload: bool,
    /// Whether the driver accepted the exact signal request.
    pub kill_delivered: bool,
    /// Whether retrying kill replayed its exact original result.
    pub kill_replayed: bool,
    /// Whether a bounded wait while running returned `deadline-exceeded`.
    pub wait_timeout_enforced: bool,
    /// Exact terminal result returned after SIGKILL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_exit_status: Option<ExitStatus>,
    /// Whether repeated wait returned the exact same terminal result.
    pub wait_replayed: bool,
    /// Whether state eventually reported the workload stopped.
    pub stopped_observed: bool,
    /// Whether the workload produced the exact expected marker.
    pub marker_verified: bool,
    /// Whether both inherited listener paths accepted host connections.
    pub control_listener_connectivity_verified: bool,
    /// Whether FD 5 received the exact workload-written init-log bytes.
    pub control_init_log_verified: bool,
    /// Whether stopped-only delete succeeded.
    pub delete_succeeded: bool,
    /// Whether retrying delete replayed its exact success.
    pub delete_replayed: bool,
    /// Whether state returned `not-found` after delete.
    pub state_missing_after_delete: bool,
    /// Whether durable list became empty after delete.
    pub list_empty_after_delete: bool,
    /// Whether neither inherited listener accepted connections after delete.
    pub control_descriptors_closed_after_delete: bool,
    /// Whether the host removed the known marker.
    pub marker_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the smoke removed its isolated durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: NATIVE_LINUX_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            kvm_device_present: false,
            bundle_loaded: false,
            control_descriptors_prepared: false,
            service_operations: Vec::new(),
            dedicated_vm_rejected_before_create: false,
            create_returned_created: false,
            create_replayed: false,
            create_without_control_descriptors_rejected: false,
            list_visible_after_create: false,
            events_verified: false,
            hook_phases: Vec::new(),
            hooks_verified: false,
            created_pid: None,
            marker_absent_after_create: false,
            start_released: false,
            running_observed: false,
            processes_verified: false,
            process_io_verified: false,
            terminal_io_verified: false,
            file_transfer_verified: false,
            filesystem_operations_verified: false,
            resources_updated: false,
            stats_verified: false,
            pause_froze_workload: false,
            resume_advanced_workload: false,
            kill_delivered: false,
            kill_replayed: false,
            wait_timeout_enforced: false,
            wait_exit_status: None,
            wait_replayed: false,
            stopped_observed: false,
            marker_verified: false,
            control_listener_connectivity_verified: false,
            control_init_log_verified: false,
            delete_succeeded: false,
            delete_replayed: false,
            state_missing_after_delete: false,
            list_empty_after_delete: false,
            control_descriptors_closed_after_delete: false,
            marker_removed: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("the native OCI lifecycle smoke requires a Linux host".into());
        report
    }

    /// Return whether the complete native lifecycle and cleanup passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.lifecycle_succeeded()
    }

    pub(crate) fn lifecycle_succeeded(&self) -> bool {
        self.bundle_loaded
            && self.control_descriptors_prepared
            && self.service_operations
                == [
                    RuntimeOperation::Features,
                    RuntimeOperation::Create,
                    RuntimeOperation::State,
                    RuntimeOperation::Start,
                    RuntimeOperation::Kill,
                    RuntimeOperation::Delete,
                    RuntimeOperation::Exec,
                    RuntimeOperation::Wait,
                    RuntimeOperation::List,
                    RuntimeOperation::Pause,
                    RuntimeOperation::Resume,
                    RuntimeOperation::Update,
                    RuntimeOperation::Processes,
                    RuntimeOperation::Stats,
                    RuntimeOperation::Events,
                    RuntimeOperation::ReadOutput,
                    RuntimeOperation::WriteStdin,
                    RuntimeOperation::CloseStdin,
                    RuntimeOperation::Resize,
                    RuntimeOperation::SignalProcess,
                    RuntimeOperation::WaitProcess,
                    RuntimeOperation::File,
                    RuntimeOperation::Filesystem,
                ]
            && self.dedicated_vm_rejected_before_create
            && self.create_returned_created
            && self.create_replayed
            && self.create_without_control_descriptors_rejected
            && self.list_visible_after_create
            && self.events_verified
            && self.hook_phases
                == [
                    "prestart",
                    "createRuntime",
                    "createContainer",
                    "startContainer",
                    "poststart",
                    "poststop",
                ]
            && self.hooks_verified
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.marker_absent_after_create
            && self.start_released
            && self.running_observed
            && self.processes_verified
            && self.process_io_verified
            && self.terminal_io_verified
            && self.file_transfer_verified
            && self.filesystem_operations_verified
            && self.resources_updated
            && self.stats_verified
            && self.pause_froze_workload
            && self.resume_advanced_workload
            && self.kill_delivered
            && self.kill_replayed
            && self.wait_timeout_enforced
            && self.wait_exit_status
                == Some(ExitStatus {
                    exit_code: None,
                    signal: Some(9),
                    oom_killed: false,
                })
            && self.wait_replayed
            && self.stopped_observed
            && self.marker_verified
            && self.control_listener_connectivity_verified
            && self.control_init_log_verified
            && self.delete_succeeded
            && self.delete_replayed
            && self.state_missing_after_delete
            && self.list_empty_after_delete
            && self.control_descriptors_closed_after_delete
            && self.marker_removed
            && self.executor_runtime_clean
            && self.session_root_clean
    }
}

/// End-to-end evidence for the helper-backed native Linux rootless lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxRootlessSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the rootless lifecycle path.
    pub status: CapabilityStatus,
    /// Effective host UID used for container-root mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_uid: Option<u32>,
    /// Effective host GID used for container-root mapping.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_gid: Option<u32>,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Whether the bundle selected exact root and subordinate ID mappings.
    pub mapping_plan_verified: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Whether create returned the OCI `created` barrier.
    pub create_returned_created: bool,
    /// Whether retrying create replayed its exact original result.
    pub create_replayed: bool,
    /// Host-visible init PID returned while the container was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether `/proc/<pid>/uid_map` exactly matched the OCI request.
    pub uid_map_verified: bool,
    /// Whether `/proc/<pid>/gid_map` exactly matched the OCI request.
    pub gid_map_verified: bool,
    /// Whether the created namespace exposed `setgroups=deny`.
    pub setgroups_denied: bool,
    /// Whether the submitted bundle requested cgroup-v2 delegation.
    pub cgroup_delegation_requested: bool,
    /// Whether an explicit rootless cgroup-v2 delegation was exercised.
    pub cgroup_delegation_verified: bool,
    /// Whether live cgroup resource updates replayed exactly.
    pub resources_updated: bool,
    /// Whether normalized cgroup statistics matched the updated profile.
    pub stats_verified: bool,
    /// Whether pause and resume reached and replayed their exact freezer states.
    pub freezer_verified: bool,
    /// Progress observed immediately before the workload was frozen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_before_pause: Option<u64>,
    /// Progress observed after a bounded interval while frozen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_while_paused: Option<u64>,
    /// Progress observed after the workload was resumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_after_resume: Option<u64>,
    /// Whether shutdown removed every runtime-owned cgroup below the delegation.
    pub cgroup_delegation_clean: bool,
    /// Whether start ran the rootless ownership and credential assertions.
    pub workload_verified: bool,
    /// Whether exec create and replay remained exact.
    pub exec_replayed: bool,
    /// Whether exec signal and replay completed successfully.
    pub exec_signal_replayed: bool,
    /// Exact terminal result returned for the signaled exec process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_wait_status: Option<ExitStatus>,
    /// Whether init kill and replay completed successfully.
    pub init_kill_replayed: bool,
    /// Exact terminal result returned for the killed init process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_wait_status: Option<ExitStatus>,
    /// Whether the durable rootless lifecycle event stream was exact and ordered.
    pub events_verified: bool,
    /// Whether delete and replay completed successfully.
    pub delete_replayed: bool,
    /// Whether state and list were empty after delete.
    pub durable_state_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the smoke removed its isolated durable and transient workspace.
    pub session_root_clean: bool,
    /// Whether the rootless workload marker was removed.
    pub marker_removed: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxRootlessSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: NATIVE_LINUX_ROOTLESS_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            effective_uid: None,
            effective_gid: None,
            bundle_loaded: false,
            mapping_plan_verified: false,
            service_operations: Vec::new(),
            create_returned_created: false,
            create_replayed: false,
            created_pid: None,
            uid_map_verified: false,
            gid_map_verified: false,
            setgroups_denied: false,
            cgroup_delegation_requested: false,
            cgroup_delegation_verified: false,
            resources_updated: false,
            stats_verified: false,
            freezer_verified: false,
            progress_before_pause: None,
            progress_while_paused: None,
            progress_after_resume: None,
            cgroup_delegation_clean: false,
            workload_verified: false,
            exec_replayed: false,
            exec_signal_replayed: false,
            exec_wait_status: None,
            init_kill_replayed: false,
            init_wait_status: None,
            events_verified: false,
            delete_replayed: false,
            durable_state_removed: false,
            executor_runtime_clean: false,
            session_root_clean: false,
            marker_removed: false,
            reason: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.reason = Some("the rootless lifecycle smoke requires a Linux host".into());
        report
    }

    /// Return whether the complete helper-backed rootless lifecycle passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available) && self.lifecycle_succeeded()
    }

    pub(crate) fn lifecycle_succeeded(&self) -> bool {
        let signaled = ExitStatus {
            exit_code: None,
            signal: Some(9),
            oom_killed: false,
        };
        self.effective_uid.is_some_and(|uid| uid > 0)
            && self.effective_gid.is_some_and(|gid| gid > 0)
            && self.bundle_loaded
            && self.mapping_plan_verified
            && self.service_operations
                == [
                    RuntimeOperation::Features,
                    RuntimeOperation::Create,
                    RuntimeOperation::State,
                    RuntimeOperation::Start,
                    RuntimeOperation::Kill,
                    RuntimeOperation::Delete,
                    RuntimeOperation::Exec,
                    RuntimeOperation::Wait,
                    RuntimeOperation::List,
                    RuntimeOperation::Pause,
                    RuntimeOperation::Resume,
                    RuntimeOperation::Update,
                    RuntimeOperation::Processes,
                    RuntimeOperation::Stats,
                    RuntimeOperation::Events,
                    RuntimeOperation::ReadOutput,
                    RuntimeOperation::WriteStdin,
                    RuntimeOperation::CloseStdin,
                    RuntimeOperation::Resize,
                    RuntimeOperation::SignalProcess,
                    RuntimeOperation::WaitProcess,
                    RuntimeOperation::File,
                    RuntimeOperation::Filesystem,
                ]
            && self.create_returned_created
            && self.create_replayed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.uid_map_verified
            && self.gid_map_verified
            && self.setgroups_denied
            && (!self.cgroup_delegation_requested
                || (self.cgroup_delegation_verified
                    && self.resources_updated
                    && self.stats_verified
                    && self.freezer_verified
                    && self.cgroup_delegation_clean))
            && self.workload_verified
            && self.exec_replayed
            && self.exec_signal_replayed
            && self.exec_wait_status == Some(signaled.clone())
            && self.init_kill_replayed
            && self.init_wait_status == Some(signaled)
            && self.events_verified
            && self.delete_replayed
            && self.durable_state_removed
            && self.executor_runtime_clean
            && self.session_root_clean
            && self.marker_removed
    }
}

/// End-to-end evidence for the fixed OCI core lifecycle in a real utility VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the smoke was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this diagnostic path.
    pub status: CapabilityStatus,
    /// Whether the host loaded and validated the submitted OCI bundle.
    pub bundle_loaded: bool,
    /// Whether create returned the exact OCI `created` barrier.
    pub create_returned_created: bool,
    /// Whether retrying create replayed its exact original result.
    pub create_replayed: bool,
    /// Guest init-wrapper PID returned while the container was created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid: Option<i32>,
    /// Whether the workload marker remained absent before start.
    pub marker_absent_after_create: bool,
    /// Whether start released the prepared init wrapper.
    pub start_released: bool,
    /// Whether the configured process was observed running.
    pub running_observed: bool,
    /// Whether process inventory contained the exact live init and exec processes.
    pub processes_verified: bool,
    /// Whether captured stdout/stderr and piped stdin passed in the guest.
    pub process_io_verified: bool,
    /// Whether guest PTY allocation, resize, interactive I/O, and EOF passed.
    pub terminal_io_verified: bool,
    /// Whether binary upload/download and mutation replay passed in the guest.
    pub file_transfer_verified: bool,
    /// Whether directory, stat, list, move, and recursive cleanup passed in the guest.
    pub filesystem_operations_verified: bool,
    /// Whether live OCI Linux resources were applied and exactly replayed.
    pub resources_updated: bool,
    /// Whether normalized cgroup counters were exact and generation-fenced.
    pub stats_verified: bool,
    /// Whether a real progress-producing workload stopped while its cgroup was frozen.
    pub pause_froze_workload: bool,
    /// Whether the frozen workload advanced again after resume.
    pub resume_advanced_workload: bool,
    /// Whether the guest accepted the exact signal request.
    pub kill_delivered: bool,
    /// Whether retrying kill replayed its exact original result.
    pub kill_replayed: bool,
    /// Whether a bounded wait while running returned `deadline-exceeded`.
    pub wait_timeout_enforced: bool,
    /// Exact terminal result returned after the configured SIGTERM trap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_exit_status: Option<ExitStatus>,
    /// Whether repeated wait returned the exact same terminal result.
    pub wait_replayed: bool,
    /// Whether state eventually reported the workload stopped.
    pub stopped_observed: bool,
    /// Whether the workload produced the exact expected marker.
    pub marker_verified: bool,
    /// Whether stopped-only delete succeeded.
    pub delete_succeeded: bool,
    /// Whether retrying delete replayed its exact success.
    pub delete_replayed: bool,
    /// Whether state returned `not-found` after delete.
    pub state_missing_after_delete: bool,
    /// Whether the host removed the known marker.
    pub marker_removed: bool,
    /// Whether VM shutdown left no new guest-agent runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated host/guest and shim evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: OCI_VM_SMOKE_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundle_loaded: false,
            create_returned_created: false,
            create_replayed: false,
            created_pid: None,
            marker_absent_after_create: false,
            start_released: false,
            running_observed: false,
            processes_verified: false,
            process_io_verified: false,
            terminal_io_verified: false,
            file_transfer_verified: false,
            filesystem_operations_verified: false,
            resources_updated: false,
            stats_verified: false,
            pause_froze_workload: false,
            resume_advanced_workload: false,
            kill_delivered: false,
            kill_replayed: false,
            wait_timeout_enforced: false,
            wait_exit_status: None,
            wait_replayed: false,
            stopped_observed: false,
            marker_verified: false,
            delete_succeeded: false,
            delete_replayed: false,
            state_missing_after_delete: false,
            marker_removed: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    )))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.bridge.status = CapabilityStatus::Unsupported;
        report.bridge.reason =
            Some("the authenticated guest bridge was not attempted for this OCI VM smoke".into());
        report.reason = Some(
            "the fixed OCI VM smoke is implemented only for Windows x86_64/WHPX and \
             macOS aarch64/HVF"
                .into(),
        );
        report
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.bundle_loaded
            && self.create_returned_created
            && self.create_replayed
            && self.created_pid.is_some_and(|pid| pid > 0)
            && self.marker_absent_after_create
            && self.start_released
            && self.running_observed
            && self.processes_verified
            && self.process_io_verified
            && self.terminal_io_verified
            && self.file_transfer_verified
            && self.filesystem_operations_verified
            && self.resources_updated
            && self.stats_verified
            && self.pause_froze_workload
            && self.resume_advanced_workload
            && self.kill_delivered
            && self.kill_replayed
            && self.wait_timeout_enforced
            && self.wait_exit_status
                == Some(ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                    oom_killed: false,
                })
            && self.wait_replayed
            && self.stopped_observed
            && self.marker_verified
            && self.delete_succeeded
            && self.delete_replayed
            && self.state_missing_after_delete
            && self.marker_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{AgentOperation, AGENT_PROTOCOL_VERSION_MAX};
    use a3s_oci_core::{CapabilityStatus, HostPlatform};

    use super::{AgentVmSmokeReport, MacosHostCleanupEvidence};

    fn complete_macos_session() -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Macos);
        report.status = CapabilityStatus::Available;
        report.endpoint_bound = true;
        report.endpoint_name = Some("a3s-oci-agent-00000000000000000000000000000000".into());
        report.shim_spawned = true;
        report.shim_process_id = Some(41);
        report.bridge_process_id = Some(42);
        report.shim_client_verified = true;
        report.protocol_negotiated = true;
        report.selected_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.agent_version = Some(env!("CARGO_PKG_VERSION").into());
        report.guest_architecture = Some("aarch64".into());
        report.advertised_operations = AgentOperation::ALL.to_vec();
        report.shim_report_verified = true;
        report.shim_exit_code = Some(0);
        report.console_created = true;
        report.shim_report = Some(serde_json::json!({"status": "available"}));
        report
    }

    fn complete_macos_cleanup() -> MacosHostCleanupEvidence {
        MacosHostCleanupEvidence {
            endpoint_removed: true,
            shim_reaped: true,
            bridge_reaped: true,
            open_descriptors_before: Some(7),
            open_descriptors_after: Some(7),
            descriptor_inventory_restored: true,
            reason: None,
        }
    }

    #[test]
    fn macos_session_success_does_not_impersonate_full_cleanup_qualification() {
        let mut report = complete_macos_session();
        assert!(report.session_is_success());
        assert!(!report.is_success());

        report.macos_cleanup = Some(complete_macos_cleanup());
        assert!(report.is_success());
    }

    #[test]
    fn macos_cleanup_requires_every_host_resource_to_return_to_baseline() {
        let evidence = complete_macos_cleanup();
        assert!(evidence.is_success());

        for incomplete in [
            MacosHostCleanupEvidence {
                endpoint_removed: false,
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                shim_reaped: false,
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                bridge_reaped: false,
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                open_descriptors_before: None,
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                open_descriptors_before: Some(0),
                open_descriptors_after: Some(0),
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                open_descriptors_after: Some(8),
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                descriptor_inventory_restored: false,
                ..evidence.clone()
            },
            MacosHostCleanupEvidence {
                reason: Some("cleanup failed".into()),
                ..evidence.clone()
            },
        ] {
            assert!(!incomplete.is_success(), "{incomplete:?}");
        }
    }
}
