use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
use a3s_oci_core::HostPlatform;

use crate::{
    LifecycleFaultPoint, NativeLinuxCheckpointSmokeReport, NativeLinuxFaultCleanupReport,
    NativeLinuxMultiContainerSmokeReport, NativeLinuxNetworkEnforcementSmokeConfig,
    NativeLinuxNetworkEnforcementSmokeReport, NativeLinuxRootlessSmokeReport,
    NativeLinuxSmokeReport, NativeLinuxSoakConfig, NativeLinuxSoakReport,
};

#[cfg(target_os = "linux")]
mod linux;

/// Exercise the real native Linux driver through the public Rust SDK.
///
/// This diagnostic is an explicit experimental opt-in. Default feature
/// discovery remains `probe-only`.
pub async fn native_linux_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> NativeLinuxSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run(init_executable, bundle, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise the complete native Linux lifecycle over the packaged Unix SDK service.
///
/// This gate binds the same single-container service used by A3S Box, connects
/// through [`a3s_oci_sdk::RuntimeClient::connect`], and verifies service-owned
/// descriptor, process, socket, and executor cleanup.
pub async fn native_linux_service_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> NativeLinuxSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_service(init_executable, bundle, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise the native Linux core lifecycle as an unprivileged host user.
///
/// The diagnostic requires helper-backed subordinate UID/GID mappings. A
/// bundle with `linux.cgroupsPath` additionally requires an explicit delegated
/// cgroup-v2 root. It fails closed when invoked as host root.
pub async fn native_linux_rootless_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
) -> NativeLinuxRootlessSmokeReport {
    native_linux_rootless_smoke_with_cgroup_delegation(init_executable, bundle, work_parent, None)
        .await
}

/// Exercise rootless native Linux with an explicit cgroup-v2 delegation.
///
/// The delegated root is required when the bundle contains
/// `linux.cgroupsPath` and rejected otherwise.
pub async fn native_linux_rootless_smoke_with_cgroup_delegation(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    delegated_cgroup_root: Option<&Path>,
) -> NativeLinuxRootlessSmokeReport {
    native_linux_rootless_smoke_with_cgroup_delegation_barrier(
        init_executable,
        bundle,
        work_parent,
        delegated_cgroup_root,
        None,
        None,
    )
    .await
}

/// Exercise rootless native Linux with a qualification-only post-open barrier.
///
/// Supplying both marker paths publishes `ready_file` after the executor has
/// retained the delegation identity, then waits for `continue_file` before the
/// first runtime mutation. This is reserved for deterministic real-host drift
/// tests and has no effect on ordinary callers.
#[doc(hidden)]
pub async fn native_linux_rootless_smoke_with_cgroup_delegation_barrier(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    delegated_cgroup_root: Option<&Path>,
    ready_file: Option<&Path>,
    continue_file: Option<&Path>,
) -> NativeLinuxRootlessSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_rootless(
            init_executable,
            bundle,
            work_parent,
            delegated_cgroup_root,
            ready_file,
            continue_file,
        )
        .await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            init_executable,
            bundle,
            work_parent,
            delegated_cgroup_root,
            ready_file,
            continue_file,
        );
        NativeLinuxRootlessSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise rootless native Linux with a synchronous default-device bootstrap.
///
/// The bootstrap retains the exact delegated cgroup and fixed default-device
/// sources before permanently dropping the owner to its non-root identity. The
/// delegation is required even when `linux.cgroupsPath` is omitted because the
/// executor creates a private path for the immutable device boundary.
#[doc(hidden)]
pub async fn native_linux_rootless_smoke_with_device_bootstrap_barrier(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    bootstrap: crate::RootlessDevicePolicyBootstrap,
    ready_file: Option<&Path>,
    continue_file: Option<&Path>,
) -> NativeLinuxRootlessSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_rootless_device_bootstrap(
            init_executable,
            bundle,
            work_parent,
            bootstrap,
            ready_file,
            continue_file,
        )
        .await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            init_executable,
            bundle,
            work_parent,
            bootstrap,
            ready_file,
            continue_file,
        );
        NativeLinuxRootlessSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise the rootless device-policy profile from an effective-root bootstrap.
///
/// The Linux implementation permanently drops the caller to its non-root real
/// identity during driver construction. The process must therefore be a
/// dedicated qualification or service owner.
#[doc(hidden)]
pub async fn native_linux_rootless_device_policy_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    bootstrap: crate::RootlessDevicePolicyBootstrap,
) -> NativeLinuxRootlessSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_rootless_device_policy(init_executable, bundle, work_parent, bootstrap).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent, bootstrap);
        NativeLinuxRootlessSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Exercise two independently fenced containers through the native Rust SDK path.
///
/// The diagnostic uses distinct bundles, retains both create barriers
/// concurrently, recreates one container with the next durable generation,
/// and verifies that every mutation remains scoped to its exact container.
pub async fn native_linux_multi_container_smoke(
    init_executable: &Path,
    bundle_a: &Path,
    bundle_b: &Path,
    work_parent: &Path,
) -> NativeLinuxMultiContainerSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_multi_container(init_executable, bundle_a, bundle_b, work_parent).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle_a, bundle_b, work_parent);
        NativeLinuxMultiContainerSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Qualify immutable CRIU checkpoint creation and driver/Host replay on Linux.
pub async fn native_linux_checkpoint_smoke(
    init_executable: &Path,
    criu_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    source_revision: String,
) -> NativeLinuxCheckpointSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_checkpoint(
            init_executable,
            criu_executable,
            bundle,
            work_parent,
            source_revision,
        )
        .await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, criu_executable, bundle, work_parent);
        NativeLinuxCheckpointSmokeReport::unsupported(HostPlatform::current(), source_revision)
    }
}

/// Run one qualification-only Native restore owner until its exact crash point.
///
/// The hidden CLI worker exits without destructors after publishing durable
/// readiness. It is not a product runtime entry point.
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn native_linux_checkpoint_restore_owner(
    init_executable: &Path,
    criu_executable: &Path,
    state_root: &Path,
    executor_parent: &Path,
    request_file: &Path,
    ready_file: &Path,
    crash_point: crate::NativeLinuxCheckpointRestoreCrashPoint,
) -> a3s_oci_sdk::Result<()> {
    linux::run_checkpoint_restore_owner(
        init_executable,
        criu_executable,
        state_root,
        executor_parent,
        request_file,
        ready_file,
        crash_point,
    )
    .await
}

/// Qualify one opaque caller-owned network enforcement and redirect mechanism.
///
/// The diagnostic binds only incarnation identities and mechanism digests to
/// the public attachment contract. The caller prepares the joined namespace,
/// interface, and mechanism; Runtime never receives policy or endpoint data.
pub async fn native_linux_network_enforcement_smoke(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    configuration: NativeLinuxNetworkEnforcementSmokeConfig,
) -> NativeLinuxNetworkEnforcementSmokeReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_network_enforcement(init_executable, bundle, work_parent, configuration).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent, configuration);
        NativeLinuxNetworkEnforcementSmokeReport::unsupported(HostPlatform::current())
    }
}

/// Repeatedly exercise concurrent native Linux containers through lifecycle,
/// query, exec, pause/reopen/resume, termination, generation reuse, and cleanup.
///
/// Each concurrent slot requires its own writable bundle, rootfs, and cgroup
/// path. The versioned report records successful operation counts and fails
/// closed on process, descriptor, marker, executor, or session leakage.
pub async fn native_linux_soak(
    init_executable: &Path,
    bundles: &[PathBuf],
    work_parent: &Path,
    configuration: NativeLinuxSoakConfig,
) -> NativeLinuxSoakReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_soak(init_executable, bundles, work_parent, configuration).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundles, work_parent);
        NativeLinuxSoakReport::unsupported(HostPlatform::current(), configuration)
    }
}

/// Interrupt the native lifecycle at one explicit boundary and prove shutdown cleanup.
///
/// This diagnostic never calls the normal OCI delete operation. It verifies
/// that executor shutdown owns process and transient-state cleanup even after
/// create, start, or kill has completed.
pub async fn native_linux_fault_cleanup(
    init_executable: &Path,
    bundle: &Path,
    work_parent: &Path,
    fault: LifecycleFaultPoint,
) -> NativeLinuxFaultCleanupReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_fault_cleanup(init_executable, bundle, work_parent, fault).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (init_executable, bundle, work_parent);
        NativeLinuxFaultCleanupReport::unsupported(HostPlatform::current(), fault)
    }
}
