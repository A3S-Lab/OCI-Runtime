use a3s_oci_core::{CapabilityStatus, HostPlatform};
use a3s_oci_sdk::{ExitStatus, RuntimeOperation};
use serde::{Deserialize, Serialize};

use crate::AgentVmSmokeReport;

/// Schema emitted by the native Linux multi-container lifecycle diagnostic.
pub const NATIVE_LINUX_MULTI_CONTAINER_SCHEMA_VERSION: &str =
    "a3s.oci.native-linux-multi-container-smoke.v14";
/// Schema emitted by the utility-VM multi-container lifecycle diagnostic.
pub const OCI_VM_MULTI_CONTAINER_SCHEMA_VERSION: &str = "a3s.oci.oci-vm-multi-container-smoke.v9";
/// Schema emitted by the Windows bootstrap-profile multi-container diagnostic.
pub const WINDOWS_OCI_VM_MULTI_CONTAINER_SCHEMA_VERSION: &str =
    "a3s.oci.windows-oci-vm-multi-container-smoke.v1";

/// Rootfs and mount enforcement evidence shared by native and utility-VM paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsMountEvidence {
    /// Whether create returned only after rootfs and mount setup completed.
    pub created_before_start: bool,
    /// Whether every missing directory and file destination existed before start.
    pub mount_targets_created_before_start: bool,
    /// Whether no workload evidence existed before the start barrier.
    pub evidence_absent_before_start: bool,
    /// Whether start released the prepared enforcement workload.
    pub start_released: bool,
    /// Whether the workload observed the root mount in a new shared peer group.
    pub rootfs_propagation_shared: bool,
    /// Whether the configured path had a distinct read-only mount.
    pub readonly_path_enforced: bool,
    /// Whether the configured file was backed by a private empty source.
    pub masked_path_enforced: bool,
    /// Whether recursive VFS attributes reached a bind mount and its submount.
    pub recursive_mount_attributes_enforced: bool,
    /// Whether explicit OCI ID mappings changed detached filesystem-mount
    /// ownership to their exact requested UID/GID.
    pub idmapped_mounts_enforced: bool,
    /// Whether the original bind source and its nested submount retained their
    /// exact UID/GID after mapped clones were attached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idmap_source_ownership_unchanged: Option<bool>,
    /// Whether a bind source mounted by the initial user namespace was cloned,
    /// attached read-only, and rejected writes inside the container user
    /// namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foreign_readonly_bind_enforced: Option<bool>,
    /// Whether `idmap` changed only the top-level rbind mount and left its
    /// nested submount unmapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idmap_nonrecursive_enforced: Option<bool>,
    /// Whether `ridmap` changed both the top-level rbind mount and its nested
    /// submount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ridmap_recursive_enforced: Option<bool>,
    /// Whether the root mount was read-only and rejected a write.
    pub readonly_rootfs_enforced: bool,
    /// Whether the workload emitted the exact ordered enforcement evidence.
    pub exact_evidence: bool,
    /// Exact terminal result returned by the enforcement workload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status: Option<ExitStatus>,
    /// Whether deletion made the enforcement container unobservable.
    pub state_removed: bool,
    /// Whether host cleanup removed the temporary source and target paths.
    pub artifacts_removed: bool,
}

impl RootfsMountEvidence {
    /// Return whether every rootfs and mount invariant was proven.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.created_before_start
            && self.mount_targets_created_before_start
            && self.evidence_absent_before_start
            && self.start_released
            && self.rootfs_propagation_shared
            && self.readonly_path_enforced
            && self.masked_path_enforced
            && self.recursive_mount_attributes_enforced
            && self.idmapped_mounts_enforced
            && self.readonly_rootfs_enforced
            && self.exact_evidence
            && self.wait_status
                == Some(ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                    oom_killed: false,
                })
            && self.state_removed
            && self.artifacts_removed
    }

    /// Return whether native Linux proved parent-mount read-only enforcement
    /// and bind/rbind ID-map recursion without mutating the source mount tree.
    #[must_use]
    pub fn native_bind_is_success(&self) -> bool {
        self.idmap_source_ownership_unchanged == Some(true)
            && self.foreign_readonly_bind_enforced == Some(true)
            && self.idmap_nonrecursive_enforced == Some(true)
            && self.ridmap_recursive_enforced == Some(true)
    }
}

/// Namespace PID 1 supervision and adopted-child reaping evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PidSupervisionEvidence {
    /// Whether the workload ran as PID 2+ under a dedicated namespace PID 1
    /// in the same PID namespace.
    pub pid1_supervision_enforced: bool,
    /// Whether namespace PID 1 reaped an adopted grandchild while the workload
    /// remained alive.
    pub orphan_reaping_enforced: bool,
}

impl PidSupervisionEvidence {
    /// Return whether the namespace-internal supervision invariants passed.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.pid1_supervision_enforced && self.orphan_reaping_enforced
    }
}

/// Existing-namespace join evidence shared by native and utility-VM paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceJoinEvidence {
    /// Positive runtime-visible PID of the prepared namespace donor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub donor_pid: Option<i32>,
    /// Whether a path whose namespace type disagreed with `type` was rejected
    /// before any container state became visible.
    pub wrong_type_rejected_before_state: bool,
    /// Whether one init joined the donor UTS, IPC, network, cgroup, PID, user,
    /// and time namespaces while creating its own mount namespace.
    pub joined_non_mount_namespaces: bool,
    /// Whether the joined PID/time workload crossed start, reached exec, and
    /// remained running for the bounded observation window.
    pub joined_pid_time_workload_verified: bool,
    /// Whether a second init joined the donor mount namespace.
    pub joined_mount_namespace: bool,
    /// Whether the rootfs retained before `setns` remained usable for exec
    /// after the donor mount namespace made the original path unreachable.
    pub retained_rootfs_verified: bool,
    /// Whether both joiner lifecycles completed without changing the donor's
    /// created state.
    pub donor_unchanged_after_joins: bool,
    /// Whether the donor, both joiners, and the negative case left no state.
    pub all_state_removed: bool,
}

impl NamespaceJoinEvidence {
    /// Return whether every existing-namespace join invariant was proven.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.donor_pid.is_some_and(|pid| pid > 0)
            && self.wrong_type_rejected_before_state
            && self.joined_non_mount_namespaces
            && self.joined_pid_time_workload_verified
            && self.joined_mount_namespace
            && self.retained_rootfs_verified
            && self.donor_unchanged_after_joins
            && self.all_state_removed
    }
}

/// Native Linux network-mode identity and cleanup evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkModeEvidence {
    /// Whether a container requesting a new network namespace received an
    /// identity distinct from the host network namespace.
    pub private_namespace_verified: bool,
    /// Whether omitting the network namespace made the container inherit the
    /// exact host network namespace identity.
    pub host_namespace_verified: bool,
    /// Whether a joiner requesting `/proc/<pid>/ns/net` received the exact
    /// donor network namespace identity.
    pub shared_namespace_verified: bool,
    /// Whether all private, host, and shared-network containers were removed.
    pub all_profiles_removed: bool,
}

impl NetworkModeEvidence {
    /// Return whether every native network namespace profile passed.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.private_namespace_verified
            && self.host_namespace_verified
            && self.shared_namespace_verified
            && self.all_profiles_removed
    }
}

/// Native Linux shared-bind and private-tmpfs lifecycle evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageVolumeEvidence {
    /// Whether a writer made data visible through a shared read-write bind.
    pub shared_bind_write_visible: bool,
    /// Whether a second container read the exact shared data through a
    /// read-only bind and was unable to mutate it.
    pub readonly_bind_enforced: bool,
    /// Whether two simultaneously live containers received isolated tmpfs
    /// instances at the same destination.
    pub private_tmpfs_isolated: bool,
    /// Whether the shared bind retained exact data after the writer was
    /// deleted and a fresh reader generation was created.
    pub bind_data_persisted_after_recreate: bool,
    /// Whether every storage-profile container and fixture artifact was removed.
    pub all_profiles_removed: bool,
}

impl StorageVolumeEvidence {
    /// Return whether every native storage-volume profile passed.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.shared_bind_write_visible
            && self.readonly_bind_enforced
            && self.private_tmpfs_isolated
            && self.bind_data_persisted_after_recreate
            && self.all_profiles_removed
    }
}

/// Native Linux init-command and OCI hook failure-path evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializationEvidence {
    /// Whether an inline shell init completed and emitted exact evidence.
    pub inline_shell_verified: bool,
    /// Whether an executable file init received its requested environment and
    /// completed with exact evidence.
    pub executable_script_verified: bool,
    /// Whether a direct argv init completed without a shell wrapper.
    pub direct_argv_verified: bool,
    /// Whether a non-zero init exit remained an exact normal exit status.
    pub nonzero_exit_verified: bool,
    /// Whether a failing createContainer hook rejected create and rolled back
    /// all visible runtime state.
    pub create_hook_failure_rolled_back: bool,
    /// Whether a failing startContainer hook rejected start and allowed exact
    /// force cleanup of the created record.
    pub start_hook_failure_rolled_back: bool,
    /// Whether a timed-out prestart hook was terminated and rolled back before
    /// any container state became visible.
    pub hook_timeout_rolled_back: bool,
    /// Whether a failing poststop hook remained warning-only and did not block
    /// wait or deletion.
    pub poststop_failure_warning_only: bool,
    /// Whether every init/hook profile and fixture artifact was removed.
    pub all_profiles_removed: bool,
}

impl InitializationEvidence {
    /// Return whether every native initialization and hook profile passed.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.inline_shell_verified
            && self.executable_script_verified
            && self.direct_argv_verified
            && self.nonzero_exit_verified
            && self.create_hook_failure_rolled_back
            && self.start_hook_failure_rolled_back
            && self.hook_timeout_rolled_back
            && self.poststop_failure_warning_only
            && self.all_profiles_removed
    }
}

/// Exact multi-container lifecycle and isolation evidence shared by both paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiContainerLifecycleEvidence {
    /// Whether the two submitted bundles resolved to different directories.
    pub distinct_bundle_directories: bool,
    /// Whether the bundles resolved to different container root filesystems.
    pub distinct_rootfs_directories: bool,
    /// Whether both creates reached the OCI `created` barrier before either start.
    pub both_created_before_start: bool,
    /// First generation allocated to container A.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_generation_a: Option<u64>,
    /// First generation allocated to container B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_generation_b: Option<u64>,
    /// Generation allocated when container A was recreated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recreated_generation_a: Option<u64>,
    /// Initial host- or guest-visible PID for container A.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid_a: Option<i32>,
    /// Host- or guest-visible PID for container B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_pid_b: Option<i32>,
    /// Whether both initial PIDs were positive and distinct.
    pub distinct_created_pids: bool,
    /// Whether both create mutations replayed their exact original results.
    pub create_replays_exact: bool,
    /// Whether neither workload marker existed before the first start.
    pub both_markers_absent_before_start: bool,
    /// Whether starting container A replayed exactly.
    pub start_a_replayed: bool,
    /// Whether container A produced its exact marker after start.
    pub marker_a_verified: bool,
    /// Whether container B remained at the same created barrier after A started.
    pub b_unchanged_after_a_start: bool,
    /// Whether container B's marker remained absent after A started.
    pub marker_b_absent_after_a_start: bool,
    /// Whether waiting on running container A left container B independently queryable.
    pub wait_a_did_not_block_b: bool,
    /// Whether killing container A replayed exactly.
    pub kill_a_replayed: bool,
    /// Whether container A was observed stopped.
    pub a_stopped: bool,
    /// Exact terminal result returned for container A.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status_a: Option<ExitStatus>,
    /// Whether repeated wait for container A returned the same result.
    pub wait_a_replayed: bool,
    /// Whether container B remained at the same created barrier after A was killed.
    pub b_unchanged_after_a_kill: bool,
    /// Whether container B's marker remained absent after A was killed.
    pub marker_b_absent_after_a_kill: bool,
    /// Whether deleting the first generation of A replayed exactly.
    pub delete_a_replayed: bool,
    /// Whether the deleted first generation of A became unobservable.
    pub a_missing_after_delete: bool,
    /// Whether container B remained unchanged after A was deleted.
    pub b_unchanged_after_a_delete: bool,
    /// Whether a stale first-generation request for A was rejected.
    pub stale_generation_rejected: bool,
    /// Whether recreating A allocated exactly the next generation.
    pub generation_a_monotonic: bool,
    /// Whether recreating container A replayed its exact result.
    pub recreate_a_replayed: bool,
    /// Whether recreated A remained behind the start barrier.
    pub marker_a_absent_after_recreate: bool,
    /// Whether reusing A's operation ID for B was rejected without mutation.
    pub cross_container_operation_rejected: bool,
    /// Whether B remained unchanged after the cross-container replay conflict.
    pub b_unchanged_after_replay_conflict: bool,
    /// Whether recreated A was removed without altering B.
    pub recreated_a_deleted: bool,
    /// Whether starting container B replayed exactly.
    pub start_b_replayed: bool,
    /// Whether container B produced its exact marker after start.
    pub marker_b_verified: bool,
    /// Whether killing container B replayed exactly.
    pub kill_b_replayed: bool,
    /// Whether container B was observed stopped.
    pub b_stopped: bool,
    /// Exact terminal result returned for container B.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_status_b: Option<ExitStatus>,
    /// Whether repeated wait for container B returned the same result.
    pub wait_b_replayed: bool,
    /// Whether deleting container B replayed exactly.
    pub delete_b_replayed: bool,
    /// Whether container B became unobservable after delete.
    pub b_missing_after_delete: bool,
}

impl MultiContainerLifecycleEvidence {
    /// Return whether every fixed multi-container invariant was proven.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.distinct_bundle_directories
            && self.distinct_rootfs_directories
            && self.both_created_before_start
            && self.initial_generation_a == Some(1)
            && self.initial_generation_b == Some(1)
            && self.recreated_generation_a == Some(2)
            && self.created_pid_a.is_some_and(|pid| pid > 0)
            && self.created_pid_b.is_some_and(|pid| pid > 0)
            && self.distinct_created_pids
            && self.create_replays_exact
            && self.both_markers_absent_before_start
            && self.start_a_replayed
            && self.marker_a_verified
            && self.b_unchanged_after_a_start
            && self.marker_b_absent_after_a_start
            && self.wait_a_did_not_block_b
            && self.kill_a_replayed
            && self.a_stopped
            && self
                .wait_status_a
                .as_ref()
                .is_some_and(|status| status.validate().is_ok())
            && self.wait_a_replayed
            && self.b_unchanged_after_a_kill
            && self.marker_b_absent_after_a_kill
            && self.delete_a_replayed
            && self.a_missing_after_delete
            && self.b_unchanged_after_a_delete
            && self.stale_generation_rejected
            && self.generation_a_monotonic
            && self.recreate_a_replayed
            && self.marker_a_absent_after_recreate
            && self.cross_container_operation_rejected
            && self.b_unchanged_after_replay_conflict
            && self.recreated_a_deleted
            && self.start_b_replayed
            && self.marker_b_verified
            && self.kill_b_replayed
            && self.b_stopped
            && self
                .wait_status_b
                .as_ref()
                .is_some_and(|status| status.validate().is_ok())
            && self.wait_status_a == self.wait_status_b
            && self.wait_b_replayed
            && self.delete_b_replayed
            && self.b_missing_after_delete
    }
}

/// Windows evidence for two containers sharing one authenticated WHPX utility VM.
///
/// This profile proves lifecycle and generation isolation without claiming the
/// user/time namespace and ID-mapped mount coverage required by the broader
/// cross-platform utility-VM diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsOciVmMultiContainerSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of this Windows bootstrap profile.
    pub status: CapabilityStatus,
    /// Whether both submitted OCI bundles loaded successfully.
    pub bundles_loaded: bool,
    /// Per-container generation, replay, isolation, and lifecycle evidence.
    pub lifecycle: MultiContainerLifecycleEvidence,
    /// Whether both workload markers were removed.
    pub markers_removed: bool,
    /// Whether VM shutdown left no new guest-agent runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated host/guest and shim evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the profile was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WindowsOciVmMultiContainerSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: WINDOWS_OCI_VM_MULTI_CONTAINER_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundles_loaded: false,
            lifecycle: MultiContainerLifecycleEvidence::default(),
            markers_removed: false,
            guest_runtime_clean: false,
            bridge: AgentVmSmokeReport::initial(platform),
            reason: None,
        }
    }

    #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
    pub(crate) fn unsupported(platform: HostPlatform) -> Self {
        let mut report = Self::initial(platform);
        report.status = CapabilityStatus::Unsupported;
        report.bridge.status = CapabilityStatus::Unsupported;
        report.bridge.reason = Some("the Windows authenticated bridge was not attempted".into());
        report.reason =
            Some("the Windows multi-container diagnostic requires Windows x86_64/WHPX".into());
        report
    }

    /// Return whether every Windows lifecycle-isolation and cleanup invariant passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.platform == HostPlatform::Windows
            && matches!(self.status, CapabilityStatus::Available)
            && self.bundles_loaded
            && self.lifecycle.is_success()
            && self.markers_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
            && self.reason.is_none()
    }
}

/// End-to-end evidence for two native Linux containers sharing one executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeLinuxMultiContainerSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Whether `/dev/kvm` existed while the independent native path ran.
    pub kvm_device_present: bool,
    /// Whether both submitted OCI bundles loaded successfully.
    pub bundles_loaded: bool,
    /// Operations advertised by the explicitly opened native service.
    pub service_operations: Vec<RuntimeOperation>,
    /// Per-container generation, replay, isolation, and lifecycle evidence.
    pub lifecycle: MultiContainerLifecycleEvidence,
    /// Existing-namespace type validation, joins, and lifecycle evidence.
    pub namespace_join: NamespaceJoinEvidence,
    /// Private, host-inherited, and donor-shared network namespace evidence.
    pub network_modes: NetworkModeEvidence,
    /// Mount-target, propagation, masking, and read-only enforcement evidence.
    pub rootfs_mount: RootfsMountEvidence,
    /// Shared bind, read-only bind, private tmpfs, and persistence evidence.
    pub storage_volumes: StorageVolumeEvidence,
    /// Init command forms and OCI hook failure/timeout cleanup evidence.
    pub initialization: InitializationEvidence,
    /// Namespace PID 1 supervision and orphan-reaping evidence.
    pub pid_supervision: PidSupervisionEvidence,
    /// Whether both workload markers were removed.
    pub markers_removed: bool,
    /// Whether executor shutdown removed its private transient root.
    pub executor_runtime_clean: bool,
    /// Whether the diagnostic removed its durable and transient workspace.
    pub session_root_clean: bool,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl NativeLinuxMultiContainerSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: NATIVE_LINUX_MULTI_CONTAINER_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            kvm_device_present: false,
            bundles_loaded: false,
            service_operations: Vec::new(),
            lifecycle: MultiContainerLifecycleEvidence::default(),
            namespace_join: NamespaceJoinEvidence::default(),
            network_modes: NetworkModeEvidence::default(),
            rootfs_mount: RootfsMountEvidence::default(),
            storage_volumes: StorageVolumeEvidence::default(),
            initialization: InitializationEvidence::default(),
            pid_supervision: PidSupervisionEvidence::default(),
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
        report.reason = Some("the native multi-container diagnostic requires a Linux host".into());
        report
    }

    /// Return whether all native lifecycle and cleanup evidence passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.bundles_loaded
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
                ]
            && self.lifecycle.is_success()
            && self.lifecycle.wait_status_a
                == Some(ExitStatus {
                    exit_code: None,
                    signal: Some(9),
                    oom_killed: false,
                })
            && self.lifecycle.wait_status_b == self.lifecycle.wait_status_a
            && self.namespace_join.is_success()
            && self.network_modes.is_success()
            && self.rootfs_mount.is_success()
            && self.rootfs_mount.native_bind_is_success()
            && self.storage_volumes.is_success()
            && self.initialization.is_success()
            && self.pid_supervision.is_success()
            && self.markers_removed
            && self.executor_runtime_clean
            && self.session_root_clean
    }
}

/// End-to-end evidence for two containers inside one authenticated utility VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciVmMultiContainerSmokeReport {
    /// Version of this JSON-compatible schema.
    pub schema_version: String,
    /// Host on which the diagnostic was attempted.
    pub platform: HostPlatform,
    /// End-to-end availability of the diagnostic path.
    pub status: CapabilityStatus,
    /// Whether both submitted OCI bundles loaded successfully.
    pub bundles_loaded: bool,
    /// Per-container generation, replay, isolation, and lifecycle evidence.
    pub lifecycle: MultiContainerLifecycleEvidence,
    /// Existing-namespace type validation, joins, and lifecycle evidence.
    pub namespace_join: NamespaceJoinEvidence,
    /// Mount-target, propagation, masking, and read-only enforcement evidence.
    pub rootfs_mount: RootfsMountEvidence,
    /// Namespace PID 1 supervision and orphan-reaping evidence.
    pub pid_supervision: PidSupervisionEvidence,
    /// Whether both workload markers were removed.
    pub markers_removed: bool,
    /// Whether VM shutdown left no new guest-agent runtime directory.
    pub guest_runtime_clean: bool,
    /// Nested authenticated host/guest and shim evidence.
    pub bridge: AgentVmSmokeReport,
    /// Diagnostic reason when the smoke was not successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl OciVmMultiContainerSmokeReport {
    pub(crate) fn initial(platform: HostPlatform) -> Self {
        Self {
            schema_version: OCI_VM_MULTI_CONTAINER_SCHEMA_VERSION.to_string(),
            platform,
            status: CapabilityStatus::Unavailable,
            bundles_loaded: false,
            lifecycle: MultiContainerLifecycleEvidence::default(),
            namespace_join: NamespaceJoinEvidence::default(),
            rootfs_mount: RootfsMountEvidence::default(),
            pid_supervision: PidSupervisionEvidence::default(),
            markers_removed: false,
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
        report.bridge.reason = Some("the authenticated guest bridge was not attempted".into());
        report.reason = Some(
            "the utility-VM multi-container diagnostic is implemented only for \
             Windows x86_64/WHPX and macOS aarch64/HVF"
                .into(),
        );
        report
    }

    /// Return whether all utility-VM lifecycle and cleanup evidence passed.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, CapabilityStatus::Available)
            && self.evidence_succeeded()
            && self.reason.is_none()
    }

    pub(crate) fn evidence_succeeded(&self) -> bool {
        self.bundles_loaded
            && self.lifecycle.is_success()
            && self.lifecycle.wait_status_a
                == Some(ExitStatus {
                    exit_code: Some(0),
                    signal: None,
                    oom_killed: false,
                })
            && self.lifecycle.wait_status_b == self.lifecycle.wait_status_a
            && self.namespace_join.is_success()
            && self.rootfs_mount.is_success()
            && self.pid_supervision.is_success()
            && self.markers_removed
            && self.guest_runtime_clean
            && self.bridge.is_success()
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::{AgentOperation, AGENT_PROTOCOL_VERSION_MAX};
    use a3s_oci_core::{CapabilityStatus, HostPlatform};
    use a3s_oci_sdk::ExitStatus;
    use serde_json::json;

    use super::{
        InitializationEvidence, MultiContainerLifecycleEvidence, NamespaceJoinEvidence,
        NetworkModeEvidence, PidSupervisionEvidence, RootfsMountEvidence, StorageVolumeEvidence,
        WindowsOciVmMultiContainerSmokeReport,
    };
    use crate::AgentVmSmokeReport;

    #[test]
    fn multi_container_success_requires_every_isolation_invariant() {
        let complete = complete_lifecycle();
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.b_unchanged_after_a_delete = false;
        assert!(!incomplete.is_success());
    }

    #[test]
    fn windows_multi_container_success_requires_bridge_lifecycle_and_cleanup() {
        let mut report = WindowsOciVmMultiContainerSmokeReport::initial(HostPlatform::Windows);
        report.status = CapabilityStatus::Available;
        report.bundles_loaded = true;
        report.lifecycle = complete_lifecycle();
        report.markers_removed = true;
        report.guest_runtime_clean = true;
        report.bridge = complete_windows_bridge();
        assert!(report.is_success());

        report.lifecycle.b_unchanged_after_a_delete = false;
        assert!(!report.is_success());
    }

    #[test]
    fn namespace_join_success_requires_positive_negative_and_cleanup_evidence() {
        let complete = NamespaceJoinEvidence {
            donor_pid: Some(303),
            wrong_type_rejected_before_state: true,
            joined_non_mount_namespaces: true,
            joined_pid_time_workload_verified: true,
            joined_mount_namespace: true,
            retained_rootfs_verified: true,
            donor_unchanged_after_joins: true,
            all_state_removed: true,
        };
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.wrong_type_rejected_before_state = false;
        assert!(!incomplete.is_success());
    }

    #[test]
    fn network_mode_success_requires_private_host_shared_and_cleanup_evidence() {
        let complete = NetworkModeEvidence {
            private_namespace_verified: true,
            host_namespace_verified: true,
            shared_namespace_verified: true,
            all_profiles_removed: true,
        };
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.host_namespace_verified = false;
        assert!(!incomplete.is_success());
    }

    #[test]
    fn storage_success_requires_sharing_isolation_persistence_and_cleanup() {
        let complete = StorageVolumeEvidence {
            shared_bind_write_visible: true,
            readonly_bind_enforced: true,
            private_tmpfs_isolated: true,
            bind_data_persisted_after_recreate: true,
            all_profiles_removed: true,
        };
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.private_tmpfs_isolated = false;
        assert!(!incomplete.is_success());
    }

    #[test]
    fn initialization_success_requires_commands_negative_hooks_and_cleanup() {
        let complete = InitializationEvidence {
            inline_shell_verified: true,
            executable_script_verified: true,
            direct_argv_verified: true,
            nonzero_exit_verified: true,
            create_hook_failure_rolled_back: true,
            start_hook_failure_rolled_back: true,
            hook_timeout_rolled_back: true,
            poststop_failure_warning_only: true,
            all_profiles_removed: true,
        };
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.hook_timeout_rolled_back = false;
        assert!(!incomplete.is_success());
    }

    #[test]
    fn pid_supervision_success_requires_pid1_and_orphan_reaping_evidence() {
        let complete = PidSupervisionEvidence {
            pid1_supervision_enforced: true,
            orphan_reaping_enforced: true,
        };
        assert!(complete.is_success());

        let mut incomplete = complete;
        incomplete.orphan_reaping_enforced = false;
        assert!(!incomplete.is_success());
    }

    #[test]
    fn rootfs_mount_success_requires_enforcement_and_cleanup_evidence() {
        let complete = RootfsMountEvidence {
            created_before_start: true,
            mount_targets_created_before_start: true,
            evidence_absent_before_start: true,
            start_released: true,
            rootfs_propagation_shared: true,
            readonly_path_enforced: true,
            masked_path_enforced: true,
            recursive_mount_attributes_enforced: true,
            idmapped_mounts_enforced: true,
            idmap_source_ownership_unchanged: Some(true),
            foreign_readonly_bind_enforced: Some(true),
            idmap_nonrecursive_enforced: Some(true),
            ridmap_recursive_enforced: Some(true),
            readonly_rootfs_enforced: true,
            exact_evidence: true,
            wait_status: Some(ExitStatus::exited(0).expect("zero exit")),
            state_removed: true,
            artifacts_removed: true,
        };
        assert!(complete.is_success());
        assert!(complete.native_bind_is_success());

        let mut incomplete = complete;
        incomplete.idmap_nonrecursive_enforced = Some(false);
        assert!(!incomplete.native_bind_is_success());
        incomplete.idmapped_mounts_enforced = false;
        assert!(!incomplete.is_success());
    }

    fn complete_lifecycle() -> MultiContainerLifecycleEvidence {
        MultiContainerLifecycleEvidence {
            distinct_bundle_directories: true,
            distinct_rootfs_directories: true,
            both_created_before_start: true,
            initial_generation_a: Some(1),
            initial_generation_b: Some(1),
            recreated_generation_a: Some(2),
            created_pid_a: Some(101),
            created_pid_b: Some(202),
            distinct_created_pids: true,
            create_replays_exact: true,
            both_markers_absent_before_start: true,
            start_a_replayed: true,
            marker_a_verified: true,
            b_unchanged_after_a_start: true,
            marker_b_absent_after_a_start: true,
            wait_a_did_not_block_b: true,
            kill_a_replayed: true,
            a_stopped: true,
            wait_status_a: Some(ExitStatus::signaled(9, false).expect("exit status")),
            wait_a_replayed: true,
            b_unchanged_after_a_kill: true,
            marker_b_absent_after_a_kill: true,
            delete_a_replayed: true,
            a_missing_after_delete: true,
            b_unchanged_after_a_delete: true,
            stale_generation_rejected: true,
            generation_a_monotonic: true,
            recreate_a_replayed: true,
            marker_a_absent_after_recreate: true,
            cross_container_operation_rejected: true,
            b_unchanged_after_replay_conflict: true,
            recreated_a_deleted: true,
            start_b_replayed: true,
            marker_b_verified: true,
            kill_b_replayed: true,
            b_stopped: true,
            wait_status_b: Some(ExitStatus::signaled(9, false).expect("exit status")),
            wait_b_replayed: true,
            delete_b_replayed: true,
            b_missing_after_delete: true,
        }
    }

    fn complete_windows_bridge() -> AgentVmSmokeReport {
        let mut report = AgentVmSmokeReport::initial(HostPlatform::Windows);
        report.status = CapabilityStatus::Available;
        report.endpoint_bound = true;
        report.endpoint_name = Some("a3s-oci-agent-00000000000000000000000000000000".into());
        report.shim_spawned = true;
        report.shim_process_id = Some(41);
        report.bridge_process_id = Some(41);
        report.shim_client_verified = true;
        report.protocol_negotiated = true;
        report.selected_protocol = Some(AGENT_PROTOCOL_VERSION_MAX);
        report.agent_version = Some(env!("CARGO_PKG_VERSION").into());
        report.guest_architecture = Some("x86_64".into());
        report.advertised_operations = vec![
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
        ];
        report.shim_report_verified = true;
        report.shim_exit_code = Some(0);
        report.console_created = true;
        report.shim_report = Some(json!({}));
        report
    }
}
