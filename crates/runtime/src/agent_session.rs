use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use a3s_oci_agent_protocol::{
    AgentClient, AgentOperation, AgentTransportFaultInjector, AgentTransportQualificationRequest,
    AgentVsockEndpoint, NoAgentTransportFaultInjector, SessionToken, AGENT_PROTOCOL_VERSION_MAX,
    AGENT_SESSION_TOKEN_ENV, AGENT_TRANSPORT_QUALIFICATION_ENV,
};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use a3s_oci_agent_protocol::{AGENT_SESSION_TOKEN_DIRECTORY_PREFIX, AGENT_SESSION_TOKEN_FILE_NAME};
use a3s_oci_core::{CapabilityStatus, HostPlatform};
use serde_json::Value;
#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use sha2::{Digest, Sha256};
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
use crate::agent_pipe::WindowsAgentPipeListener;
use crate::agent_smoke_process::{BoundedOutput, CompletedShim, RunningShim, MAX_CAPTURE_BYTES};
#[cfg(unix)]
use crate::agent_socket::UnixAgentSocketListener;
use crate::report::AgentVmSmokeReport;

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(60);
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_DIAGNOSTIC_CHARS: usize = 2_048;
const SHIM_REPORT_SCHEMA_VERSION: &str = "a3s.oci.krun-agent-vm-smoke.v7";
const SHIM_TRUE_FIELDS: &[&str] = &[
    "runtime_bundle_loaded",
    "context_created",
    "vm_configured",
    "rootfs_configured",
    "agent_binary_present",
    "agent_vsock_configured",
    "workload_configured",
    "console_configured",
    "vm_entered",
    "console_created",
];

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
type PlatformAgentStream = NamedPipeServer;
#[cfg(unix)]
type PlatformAgentStream = UnixStream;

pub(crate) struct AgentVmSession {
    report: AgentVmSmokeReport,
    client: AgentClient<PlatformAgentStream>,
    running: RunningShim,
    console: PathBuf,
    runtime_share_required: bool,
    expected_system_image_manifest_sha256: Option<String>,
}

/// Shareable guest client with single-owner, idempotent VM shutdown.
///
/// Driver operations may retain cloned clients. Shutdown actively closes the
/// shared transport, consumes the sole VM owner once, and caches the exact
/// cleanup report for repeated callers.
pub(crate) struct UtilityVmSession {
    client: AgentClient<PlatformAgentStream>,
    state: Mutex<UtilityVmSessionState>,
}

struct UtilityVmSessionState {
    owner: Option<AgentVmSession>,
    completed: Option<AgentVmSmokeReport>,
}

struct AgentVmConnectOptions<'a> {
    system_image_manifest: Option<&'a Path>,
    expected_system_image_manifest_sha256: Option<&'a str>,
    runtime_share: Option<&'a Path>,
    recovery_report: Option<&'a Path>,
    vm_attachment_manifest_sha256: Option<&'a str>,
    faults: Arc<dyn AgentTransportFaultInjector>,
    guest_qualification: Option<&'a AgentTransportQualificationRequest>,
    qualify_kvm_post_probe_failure: bool,
    qualify_kvm_compatibility_drift: Option<&'a str>,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) struct VerifiedLinuxUtilityVmConnectOptions<'a> {
    pub(crate) rootfs: &'a Path,
    pub(crate) system_image_manifest: &'a Path,
    pub(crate) expected_system_image_manifest_sha256: &'a str,
    pub(crate) runtime_share: &'a Path,
    pub(crate) console: &'a Path,
    pub(crate) recovery_report: Option<&'a Path>,
    pub(crate) vm_attachment_manifest_sha256: Option<&'a str>,
}

// Connection failures intentionally return the complete retained qualification
// report. Keeping that structured evidence by value is part of this internal
// API; boxing it would make every report consumer heap-aware.
#[allow(clippy::result_large_err)]
impl UtilityVmSession {
    pub(crate) async fn connect(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        console: &Path,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect(
            shim,
            rootfs,
            system_image_manifest,
            None,
            None,
            console,
            None,
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    pub(crate) async fn connect_with_separate_runtime_share(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        runtime_share: &Path,
        console: &Path,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect(
            shim,
            rootfs,
            system_image_manifest,
            None,
            Some(runtime_share),
            console,
            None,
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) async fn connect_with_runtime_share(
        shim: &Path,
        system_image_manifest: &Path,
        expected_system_image_manifest_sha256: &str,
        runtime_share: &Path,
        console: &Path,
        recovery_report: Option<&Path>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        Self::connect_with_verified_runtime_share(
            shim,
            runtime_share,
            system_image_manifest,
            expected_system_image_manifest_sha256,
            runtime_share,
            console,
            recovery_report,
        )
        .await
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) async fn connect_with_verified_runtime_share(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: &Path,
        expected_system_image_manifest_sha256: &str,
        runtime_share: &Path,
        console: &Path,
        recovery_report: Option<&Path>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect(
            shim,
            rootfs,
            Some(system_image_manifest),
            Some(expected_system_image_manifest_sha256),
            Some(runtime_share),
            console,
            recovery_report,
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) async fn connect_with_verified_runtime_share_and_vm_attachments(
        shim: &Path,
        options: VerifiedLinuxUtilityVmConnectOptions<'_>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let VerifiedLinuxUtilityVmConnectOptions {
            rootfs,
            system_image_manifest,
            expected_system_image_manifest_sha256,
            runtime_share,
            console,
            recovery_report,
            vm_attachment_manifest_sha256,
        } = options;
        let owner = AgentVmSession::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest: Some(system_image_manifest),
                expected_system_image_manifest_sha256: Some(expected_system_image_manifest_sha256),
                runtime_share: Some(runtime_share),
                recovery_report,
                vm_attachment_manifest_sha256,
                faults: Arc::new(NoAgentTransportFaultInjector),
                guest_qualification: None,
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) async fn connect_with_host_fault_injector(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        console: &Path,
        faults: Arc<dyn AgentTransportFaultInjector>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect_with_fault_injector(
            shim,
            rootfs,
            system_image_manifest,
            console,
            faults,
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) async fn connect_with_guest_qualification(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        console: &Path,
        qualification: &AgentTransportQualificationRequest,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect_with_guest_qualification(
            shim,
            rootfs,
            system_image_manifest,
            console,
            qualification,
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) async fn connect_with_separate_runtime_share_and_host_fault_injector(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        runtime_share: &Path,
        console: &Path,
        faults: Arc<dyn AgentTransportFaultInjector>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256: None,
                runtime_share: Some(runtime_share),
                recovery_report: None,
                vm_attachment_manifest_sha256: None,
                faults,
                guest_qualification: None,
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) async fn connect_with_separate_runtime_share_and_guest_qualification(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        runtime_share: &Path,
        console: &Path,
        qualification: &AgentTransportQualificationRequest,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256: None,
                runtime_share: Some(runtime_share),
                recovery_report: None,
                vm_attachment_manifest_sha256: None,
                faults: Arc::new(NoAgentTransportFaultInjector),
                guest_qualification: Some(qualification),
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub(crate) async fn connect_with_recovery(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: &Path,
        expected_system_image_manifest_sha256: &str,
        runtime_share: &Path,
        console: &Path,
        recovery_report: &Path,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let owner = AgentVmSession::connect(
            shim,
            rootfs,
            Some(system_image_manifest),
            Some(expected_system_image_manifest_sha256),
            Some(runtime_share),
            console,
            Some(recovery_report),
        )
        .await?;
        Ok(Self {
            client: owner.client().clone(),
            state: Mutex::new(UtilityVmSessionState {
                owner: Some(owner),
                completed: None,
            }),
        })
    }

    pub(crate) fn client(&self) -> AgentClient<PlatformAgentStream> {
        self.client.clone()
    }

    pub(crate) async fn shutdown(&self) -> AgentVmSmokeReport {
        self.shutdown_inner(None).await
    }

    #[cfg(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    pub(crate) async fn shutdown_with_failure(
        &self,
        reason: impl Into<String>,
    ) -> AgentVmSmokeReport {
        self.shutdown_inner(Some(reason.into())).await
    }

    async fn shutdown_inner(&self, reason: Option<String>) -> AgentVmSmokeReport {
        let mut state = self.state.lock().await;
        if let Some(report) = &state.completed {
            return report.clone();
        }
        let Some(owner) = state.owner.take() else {
            let report = failed(
                AgentVmSmokeReport::initial(HostPlatform::current()),
                "utility-VM session lost its sole owner before shutdown",
            );
            state.completed = Some(report.clone());
            return report;
        };
        let report = match reason {
            Some(reason) => owner.finish_with_failure(reason).await,
            None => owner.finish().await,
        };
        state.completed = Some(report.clone());
        report
    }
}

// Every connector below uses AgentVmSmokeReport as structured failure evidence.
#[allow(clippy::result_large_err)]
impl AgentVmSession {
    pub(crate) async fn connect(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        expected_system_image_manifest_sha256: Option<&str>,
        runtime_share: Option<&Path>,
        console: &Path,
        recovery_report: Option<&Path>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        Self::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256,
                runtime_share,
                recovery_report,
                vm_attachment_manifest_sha256: None,
                faults: Arc::new(NoAgentTransportFaultInjector),
                guest_qualification: None,
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) async fn connect_with_kvm_post_probe_failure(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        runtime_share: Option<&Path>,
        console: &Path,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        Self::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256: None,
                runtime_share,
                recovery_report: None,
                vm_attachment_manifest_sha256: None,
                faults: Arc::new(NoAgentTransportFaultInjector),
                guest_qualification: None,
                qualify_kvm_post_probe_failure: true,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    pub(crate) async fn connect_with_kvm_compatibility_drift(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        runtime_share: Option<&Path>,
        console: &Path,
        case: &str,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        Self::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256: None,
                runtime_share,
                recovery_report: None,
                vm_attachment_manifest_sha256: None,
                faults: Arc::new(NoAgentTransportFaultInjector),
                guest_qualification: None,
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: Some(case),
            },
        )
        .await
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    async fn connect_with_fault_injector(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        console: &Path,
        faults: Arc<dyn AgentTransportFaultInjector>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let runtime_share = system_image_manifest.map(|_| rootfs);
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        let runtime_share = None;
        Self::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256: None,
                runtime_share,
                recovery_report: None,
                vm_attachment_manifest_sha256: None,
                faults,
                guest_qualification: None,
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    async fn connect_with_guest_qualification(
        shim: &Path,
        rootfs: &Path,
        system_image_manifest: Option<&Path>,
        console: &Path,
        qualification: &AgentTransportQualificationRequest,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let runtime_share = system_image_manifest.map(|_| rootfs);
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        let runtime_share = None;
        Self::connect_inner(
            shim,
            rootfs,
            console,
            AgentVmConnectOptions {
                system_image_manifest,
                expected_system_image_manifest_sha256: None,
                runtime_share,
                recovery_report: None,
                vm_attachment_manifest_sha256: None,
                faults: Arc::new(NoAgentTransportFaultInjector),
                guest_qualification: Some(qualification),
                qualify_kvm_post_probe_failure: false,
                qualify_kvm_compatibility_drift: None,
            },
        )
        .await
    }

    async fn connect_inner(
        shim: &Path,
        rootfs: &Path,
        console: &Path,
        options: AgentVmConnectOptions<'_>,
    ) -> std::result::Result<Self, AgentVmSmokeReport> {
        let AgentVmConnectOptions {
            system_image_manifest,
            expected_system_image_manifest_sha256,
            runtime_share,
            recovery_report,
            vm_attachment_manifest_sha256,
            faults,
            guest_qualification,
            qualify_kvm_post_probe_failure,
            qualify_kvm_compatibility_drift,
        } = options;
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        let _ = (
            qualify_kvm_post_probe_failure,
            qualify_kvm_compatibility_drift,
        );
        let platform = HostPlatform::current();
        let mut report = AgentVmSmokeReport::initial(platform);
        if let Some(digest) = vm_attachment_manifest_sha256 {
            if let Err(reason) = validate_vm_attachment_manifest_digest(digest) {
                return Err(failed(report, reason));
            }
        }
        let shim = match canonical_file(shim, "libkrun shim").await {
            Ok(path) => path,
            Err(reason) => return Err(failed(report, reason)),
        };
        let rootfs = match canonical_directory(rootfs, "guest rootfs").await {
            Ok(path) => path,
            Err(reason) => return Err(failed(report, reason)),
        };
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        let (system_image_manifest, expected_system_image_manifest_sha256) = {
            let Some(path) = system_image_manifest else {
                return Err(failed(
                    report,
                    "utility-VM sessions require an explicit system-image manifest",
                ));
            };
            let path = match canonical_file(path, "system-image manifest").await {
                Ok(path) => path,
                Err(reason) => return Err(failed(report, reason)),
            };
            let Some(system_image_directory) = path.parent() else {
                return Err(failed(
                    report,
                    "system-image manifest has no trusted parent directory",
                ));
            };
            if paths_overlap(system_image_directory, &rootfs) {
                return Err(failed(
                    report,
                    "system-image assets and VM bootstrap root must be disjoint",
                ));
            }
            let digest = match sha256_path(&path).await {
                Ok(digest) => digest,
                Err(reason) => return Err(failed(report, reason)),
            };
            if let Err(reason) =
                require_expected_manifest_digest(&digest, expected_system_image_manifest_sha256)
            {
                return Err(failed(report, reason));
            }
            (Some(path), Some(digest))
        };
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        let expected_system_image_manifest_sha256 = {
            let _ = system_image_manifest;
            None::<String>
        };
        let console = match prepare_console_path(console).await {
            Ok(path) => path,
            Err(reason) => return Err(failed(report, reason)),
        };
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let runtime_share = match runtime_share {
            Some(path) => match canonical_directory(path, "per-generation runtime share").await {
                Ok(path) => {
                    let state = match canonical_directory(
                        &path.join("run"),
                        "per-generation runtime-state directory",
                    )
                    .await
                    {
                        Ok(state) => state,
                        Err(reason) => return Err(failed(report, reason)),
                    };
                    if state.parent() != Some(path.as_path()) {
                        return Err(failed(
                            report,
                            "Windows runtime-state directory must remain inside the exact runtime share",
                        ));
                    }
                    Some(path)
                }
                Err(reason) => return Err(failed(report, reason)),
            },
            None => {
                return Err(failed(
                    report,
                    "Windows utility-VM sessions require a writable runtime share",
                ))
            }
        };
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if runtime_share
            .as_ref()
            .is_some_and(|share| paths_overlap(&rootfs, share))
        {
            return Err(failed(
                report,
                "Linux KVM bootstrap root and writable runtime share must be disjoint",
            ));
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if runtime_share
            .as_ref()
            .is_some_and(|share| paths_overlap(&rootfs, share))
        {
            return Err(failed(
                report,
                "Windows VM bootstrap root and writable runtime share must be disjoint",
            ));
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let runtime_share =
            match prepare_macos_runtime_share(runtime_share.unwrap_or(&rootfs)).await {
                Ok(path) => Some(path),
                Err(reason) => return Err(failed(report, reason)),
            };
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        let runtime_share = match runtime_share {
            Some(path) => match prepare_linux_runtime_share(path).await {
                Ok(path) => Some(path),
                Err(reason) => return Err(failed(report, reason)),
            },
            None => return Err(failed(
                report,
                "Linux KVM utility-VM sessions require a protected per-generation runtime share",
            )),
        };
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        let system_image_manifest_path = match system_image_manifest.as_deref() {
            Some(path) => path,
            None => {
                return Err(failed(
                    report,
                    "utility-VM session lost its validated system-image manifest",
                ))
            }
        };
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        let system_image_directory = match system_image_manifest_path.parent() {
            Some(path) => path,
            None => {
                return Err(failed(
                    report,
                    "system-image manifest lost its trusted parent directory",
                ))
            }
        };
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        let runtime_share_path = match runtime_share.as_deref() {
            Some(path) => path,
            None => {
                return Err(failed(
                    report,
                    "utility-VM session lost its validated writable runtime share",
                ))
            }
        };
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        if paths_overlap(system_image_directory, runtime_share_path) {
            return Err(failed(
                report,
                "system-image manifest and writable runtime share must be disjoint",
            ));
        }
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        let _ = runtime_share;
        #[cfg(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))]
        let recovery_report = match recovery_report {
            Some(path) => match prepare_recovery_report_path(path).await {
                Ok(path) => Some(path),
                Err(reason) => return Err(failed(report, reason)),
            },
            None => None,
        };
        #[cfg(not(any(
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "macos", target_arch = "aarch64"),
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        )))]
        let _ = recovery_report;

        let endpoint = match AgentVsockEndpoint::generate() {
            Ok(endpoint) => endpoint,
            Err(error) => return Err(failed(report, error.to_string())),
        };
        report.endpoint_name = Some(endpoint.pipe_name().to_string());
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let bootstrap_cleanup = BootstrapTokenCleanup::new(runtime_share_path, &endpoint);
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let listener = match WindowsAgentPipeListener::bind(endpoint.clone()) {
            Ok(listener) => {
                report.endpoint_bound = true;
                listener
            }
            Err(error) => return Err(failed(report, error.to_string())),
        };
        #[cfg(unix)]
        let listener = match UnixAgentSocketListener::bind(endpoint.clone()) {
            Ok(listener) => {
                report.endpoint_bound = true;
                listener
            }
            Err(error) => return Err(failed(report, error.to_string())),
        };
        let token = match SessionToken::generate() {
            Ok(token) => token,
            Err(error) => return Err(failed(report, error.to_string())),
        };

        let encoded_token = token.expose_hex();
        let encoded_qualification = match guest_qualification
            .map(AgentTransportQualificationRequest::to_json)
            .transpose()
        {
            Ok(encoded) => encoded,
            Err(error) => return Err(failed(report, error.to_string())),
        };
        let mut command = Command::new(&shim);
        command
            .arg("agent-vm-smoke")
            .arg("--rootfs")
            .arg(&rootfs)
            .arg("--console")
            .arg(&console)
            .arg("--pipe-name")
            .arg(endpoint.pipe_name());
        #[cfg(unix)]
        {
            command
                .arg("--system-image-manifest")
                .arg(system_image_manifest_path)
                .arg("--runtime-share")
                .arg(runtime_share_path)
                .arg("--socket-path")
                .arg(listener.socket_path())
                .arg("--owner-pid")
                .arg(std::process::id().to_string());
            if let Some(path) = recovery_report {
                command.arg("--recovery-report").arg(path);
            }
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if qualify_kvm_post_probe_failure {
            command.arg("--qualify-kvm-post-probe-failure");
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if let Some(case) = qualify_kvm_compatibility_drift {
            command.arg("--qualify-kvm-compatibility-drift").arg(case);
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        if let Some(digest) = vm_attachment_manifest_sha256 {
            command.arg("--vm-attachment-manifest-sha256").arg(digest);
        }
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            command
                .arg("--system-image-manifest")
                .arg(system_image_manifest_path)
                .arg("--runtime-share")
                .arg(runtime_share_path)
                .arg("--owner-pid")
                .arg(std::process::id().to_string());
            if let Some(path) = recovery_report {
                command.arg("--recovery-report").arg(path);
            }
        }
        command
            .env_remove(AGENT_TRANSPORT_QUALIFICATION_ENV)
            .env(AGENT_SESSION_TOKEN_ENV, encoded_token.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(encoded) = &encoded_qualification {
            command.env(AGENT_TRANSPORT_QUALIFICATION_ENV, encoded);
        }
        let mut running = match RunningShim::spawn(&mut command) {
            Ok(running) => running,
            Err(error) => {
                return Err(failed(
                    report,
                    format!("failed to start libkrun shim {}: {error}", shim.display()),
                ));
            }
        };
        drop(command);
        drop(encoded_token);
        report.shim_spawned = true;

        let Some(shim_process_id) = running.process_id() else {
            let completed = running.terminate_and_collect().await;
            apply_completed(&mut report, &completed);
            return Err(failed_with_output(
                report,
                "spawned libkrun shim has no live process ID",
                &completed,
            ));
        };
        report.shim_process_id = Some(shim_process_id);

        enum BridgeOutcome {
            Connected(a3s_oci_sdk::Result<(PlatformAgentStream, u32)>),
            ShimExited(io::Result<ExitStatus>),
        }
        let accept = accept_bridge(listener, shim_process_id);
        tokio::pin!(accept);
        let bridge_outcome = timeout(BRIDGE_TIMEOUT, async {
            tokio::select! {
                result = &mut accept => BridgeOutcome::Connected(result),
                status = running.child_mut().wait() => BridgeOutcome::ShimExited(status),
            }
        })
        .await;
        let stream = match bridge_outcome {
            Ok(BridgeOutcome::Connected(Ok((stream, bridge_process_id)))) => {
                report.shim_client_verified = true;
                report.bridge_process_id = Some(bridge_process_id);
                stream
            }
            Ok(BridgeOutcome::Connected(Err(error))) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return Err(failed_with_output(report, &error.to_string(), &completed));
            }
            Ok(BridgeOutcome::ShimExited(status)) => {
                let completed = running.collect_after_wait(status).await;
                apply_completed(&mut report, &completed);
                return Err(failed_with_output(
                    report,
                    "libkrun shim exited before connecting the authenticated agent bridge",
                    &completed,
                ));
            }
            Err(_) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return Err(failed_with_output(
                    report,
                    "timed out waiting for the libkrun shim to connect the agent bridge",
                    &completed,
                ));
            }
        };

        let client = match timeout(
            NEGOTIATION_TIMEOUT,
            AgentClient::connect_with_fault_injector(stream, token, faults),
        )
        .await
        {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return Err(failed_with_output(report, &error.to_string(), &completed));
            }
            Err(_) => {
                let completed = running.terminate_and_collect().await;
                apply_completed(&mut report, &completed);
                return Err(failed_with_output(
                    report,
                    "timed out authenticating and negotiating with the guest agent",
                    &completed,
                ));
            }
        };
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        if let Err(reason) = bootstrap_cleanup.cleanup() {
            drop(client);
            let completed = running.terminate_and_collect().await;
            apply_completed(&mut report, &completed);
            return Err(failed_with_output(report, &reason, &completed));
        }
        report.protocol_negotiated = true;
        report.selected_protocol = Some(client.hello().selected_version());
        report.agent_version = Some(client.hello().capabilities().agent_version().to_string());
        report.guest_architecture = Some(client.hello().capabilities().architecture().to_string());
        report.advertised_operations = client.hello().capabilities().operations().to_vec();

        let session = Self {
            report,
            client,
            running,
            console,
            runtime_share_required: {
                #[cfg(any(
                    all(target_os = "windows", target_arch = "x86_64"),
                    all(target_os = "macos", target_arch = "aarch64"),
                    all(
                        target_os = "linux",
                        any(target_arch = "x86_64", target_arch = "aarch64")
                    )
                ))]
                {
                    runtime_share.is_some()
                }
                #[cfg(not(any(
                    all(target_os = "windows", target_arch = "x86_64"),
                    all(target_os = "macos", target_arch = "aarch64"),
                    all(
                        target_os = "linux",
                        any(target_arch = "x86_64", target_arch = "aarch64")
                    )
                )))]
                {
                    false
                }
            },
            expected_system_image_manifest_sha256,
        };
        if let Some(reason) = session.contract_failure() {
            return Err(session.finish_with_failure(reason).await);
        }
        Ok(session)
    }

    pub(crate) const fn client(&self) -> &AgentClient<PlatformAgentStream> {
        &self.client
    }

    pub(crate) async fn finish(self) -> AgentVmSmokeReport {
        self.finish_inner(None).await
    }

    pub(crate) async fn finish_with_failure(self, reason: impl Into<String>) -> AgentVmSmokeReport {
        self.finish_inner(Some(reason.into())).await
    }

    fn contract_failure(&self) -> Option<String> {
        if self.report.selected_protocol != Some(AGENT_PROTOCOL_VERSION_MAX) {
            return Some("guest selected an unexpected protocol version".into());
        }
        if self.report.advertised_operations != expected_operations() {
            return Some(
                "guest agent did not advertise the exact lifecycle and wait contract".into(),
            );
        }
        if self.report.agent_version.as_deref() != Some(env!("CARGO_PKG_VERSION")) {
            return Some("guest agent version does not match the host runtime version".into());
        }
        let expected_architecture = expected_guest_architecture(self.report.platform);
        if self.report.guest_architecture.as_deref() != Some(expected_architecture) {
            return Some(format!(
                "guest agent did not report the required {expected_architecture} architecture"
            ));
        }
        None
    }

    async fn finish_inner(self, forced_failure: Option<String>) -> AgentVmSmokeReport {
        let Self {
            mut report,
            client,
            running,
            console,
            runtime_share_required,
            expected_system_image_manifest_sha256,
        } = self;
        let close_error = client.close().await.err();
        drop(client);
        let completed = running.wait_and_collect().await;
        apply_completed(&mut report, &completed);
        if completed.timed_out {
            return failed_with_output(
                report,
                "guest agent did not exit after the host closed the negotiated connection",
                &completed,
            );
        }
        if !completed.status.as_ref().is_some_and(ExitStatus::success) {
            return failed_with_output(
                report,
                "libkrun shim returned an unsuccessful status",
                &completed,
            );
        }
        let shim_report = match parse_shim_report(
            &completed.stdout,
            report.platform,
            runtime_share_required,
            expected_system_image_manifest_sha256.as_deref(),
        ) {
            Ok(shim_report) => shim_report,
            Err(reason) => return failed_with_output(report, &reason, &completed),
        };
        report.shim_report_verified = true;
        report.shim_report = Some(shim_report);
        report.console_created = tokio::fs::metadata(&console)
            .await
            .is_ok_and(|metadata| metadata.is_file());
        if !report.console_created {
            return failed_with_output(
                report,
                &format!(
                    "libkrun did not create the requested guest console file {}",
                    console.display()
                ),
                &completed,
            );
        }
        if let Some(error) = close_error {
            return failed_with_output(
                report,
                &format!("failed to close the shared guest-agent session: {error}"),
                &completed,
            );
        }
        if let Some(reason) = forced_failure {
            return failed_with_output(report, &reason, &completed);
        }

        report.status = CapabilityStatus::Available;
        report.reason = None;
        report
    }
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn require_expected_manifest_digest(actual: &str, expected: Option<&str>) -> Result<(), String> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if !is_canonical_hex(expected, 64) {
        return Err("driver retained a noncanonical system-image manifest digest".to_string());
    }
    if actual != expected {
        return Err(format!(
            "system-image manifest changed after the runtime driver was opened: expected {expected}, found {actual}"
        ));
    }
    Ok(())
}

fn validate_vm_attachment_manifest_digest(value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(
            "KVM attachment manifest digest must use the canonical sha256 form".to_string(),
        );
    };
    if !is_canonical_hex(hex, 64) {
        return Err(
            "KVM attachment manifest digest must contain 64 lowercase hexadecimal characters"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
struct BootstrapTokenCleanup {
    file: PathBuf,
    directory: PathBuf,
    cleaned: bool,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl BootstrapTokenCleanup {
    fn new(rootfs: &Path, endpoint: &AgentVsockEndpoint) -> Self {
        let directory = rootfs.join(format!(
            "{AGENT_SESSION_TOKEN_DIRECTORY_PREFIX}{}",
            endpoint.pipe_name()
        ));
        Self {
            file: directory.join(AGENT_SESSION_TOKEN_FILE_NAME),
            directory,
            cleaned: false,
        }
    }

    fn cleanup(mut self) -> Result<(), String> {
        let result = self.remove();
        self.cleaned = result.is_ok();
        result
    }

    fn remove(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        match std::fs::remove_file(&self.file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!(
                "failed to remove one-time guest bootstrap file {}: {error}",
                self.file.display()
            )),
        }
        match std::fs::remove_dir(&self.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!(
                "failed to remove one-time guest bootstrap directory {}: {error}",
                self.directory.display()
            )),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
impl Drop for BootstrapTokenCleanup {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.remove();
        }
    }
}

async fn canonical_file(path: &Path, description: &str) -> Result<PathBuf, String> {
    canonical_path(path, description, true).await
}

async fn canonical_directory(path: &Path, description: &str) -> Result<PathBuf, String> {
    canonical_path(path, description, false).await
}

async fn canonical_path(
    path: &Path,
    description: &str,
    require_file: bool,
) -> Result<PathBuf, String> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        format!(
            "failed to inspect {description} {}: {error}",
            path.display()
        )
    })?;
    let expected_kind = if require_file { "file" } else { "directory" };
    let kind_matches = if require_file {
        metadata.file_type().is_file()
    } else {
        metadata.file_type().is_dir()
    };
    if metadata.file_type().is_symlink() || !kind_matches {
        return Err(format!(
            "{description} must be a real {expected_kind}, not a symlink: {}",
            path.display()
        ));
    }
    let canonical = tokio::fs::canonicalize(path).await.map_err(|error| {
        format!(
            "failed to resolve {description} {}: {error}",
            path.display()
        )
    })?;
    let metadata = tokio::fs::metadata(&canonical).await.map_err(|error| {
        format!(
            "failed to inspect {description} {}: {error}",
            canonical.display()
        )
    })?;
    let kind_matches = if require_file {
        metadata.is_file()
    } else {
        metadata.is_dir()
    };
    if !kind_matches {
        return Err(format!(
            "{description} is not a regular {expected_kind}: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

async fn prepare_console_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(path).map_err(|error| {
        format!(
            "failed to make console path {} absolute: {error}",
            path.display()
        )
    })?;
    let file_name = absolute.file_name().ok_or_else(|| {
        format!(
            "console path must name a file rather than a root directory: {}",
            absolute.display()
        )
    })?;
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("console path has no parent: {}", absolute.display()))?;
    tokio::fs::create_dir_all(parent).await.map_err(|error| {
        format!(
            "failed to create console directory {}: {error}",
            parent.display()
        )
    })?;
    let parent = tokio::fs::canonicalize(parent).await.map_err(|error| {
        format!(
            "failed to resolve console directory {}: {error}",
            parent.display()
        )
    })?;
    let console = parent.join(file_name);
    if tokio::fs::try_exists(&console).await.map_err(|error| {
        format!(
            "failed to inspect console destination {}: {error}",
            console.display()
        )
    })? {
        return Err(format!(
            "refusing to overwrite an existing console destination: {}",
            console.display()
        ));
    }
    Ok(console)
}

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
async fn prepare_recovery_report_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "trusted recovery report path must be absolute: {}",
            path.display()
        ));
    }
    let file_name = path.file_name().ok_or_else(|| {
        format!(
            "trusted recovery report path must name a file: {}",
            path.display()
        )
    })?;
    let parent = path.parent().ok_or_else(|| {
        format!(
            "trusted recovery report path has no parent: {}",
            path.display()
        )
    })?;
    let metadata = tokio::fs::symlink_metadata(parent).await.map_err(|error| {
        format!(
            "failed to inspect trusted recovery directory {}: {error}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "trusted recovery directory must be a plain directory: {}",
            parent.display()
        ));
    }
    let parent = tokio::fs::canonicalize(parent).await.map_err(|error| {
        format!(
            "failed to resolve trusted recovery directory {}: {error}",
            parent.display()
        )
    })?;
    let path = parent.join(file_name);
    if tokio::fs::try_exists(&path).await.map_err(|error| {
        format!(
            "failed to inspect trusted recovery destination {}: {error}",
            path.display()
        )
    })? {
        return Err(format!(
            "refusing to overwrite trusted recovery destination: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn parse_shim_report(
    output: &BoundedOutput,
    platform: HostPlatform,
    runtime_share_required: bool,
    expected_system_image_manifest_sha256: Option<&str>,
) -> Result<Value, String> {
    if output.truncated {
        return Err(format!(
            "libkrun shim report exceeded the {MAX_CAPTURE_BYTES}-byte evidence limit"
        ));
    }
    let report: Value = serde_json::from_slice(&output.bytes)
        .map_err(|error| format!("libkrun shim emitted invalid JSON evidence: {error}"))?;
    let object = report
        .as_object()
        .ok_or_else(|| "libkrun shim evidence must be a JSON object".to_string())?;
    if object.get("schema_version").and_then(Value::as_str) != Some(SHIM_REPORT_SCHEMA_VERSION) {
        return Err("libkrun shim evidence has an unexpected schema version".into());
    }
    if object.get("status").and_then(Value::as_str) != Some("available") {
        return Err("libkrun shim did not report the guest-agent VM path available".into());
    }
    let expected_platform = match platform {
        HostPlatform::Linux => "linux",
        HostPlatform::Windows => "windows",
        HostPlatform::Macos => "macos",
        _ => return Err("guest-agent session ran on an unsupported host platform".into()),
    };
    if object.get("platform").and_then(Value::as_str) != Some(expected_platform) {
        return Err(format!(
            "libkrun shim evidence did not identify the {expected_platform} host"
        ));
    }
    for field in SHIM_TRUE_FIELDS {
        if object.get(*field).and_then(Value::as_bool) != Some(true) {
            return Err(format!("libkrun shim evidence field `{field}` is not true"));
        }
    }
    if runtime_share_required
        && object
            .get("runtime_share_configured")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err(
            "libkrun shim did not configure the required per-generation runtime share".into(),
        );
    }
    if matches!(platform, HostPlatform::Linux) {
        if object
            .get("kvm_post_probe_failure_injected")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err(
                "libkrun shim unexpectedly injected the Linux KVM post-probe failure".into(),
            );
        }
        for field in ["kvm_device_opened", "kvm_api_verified"] {
            if object.get(field).and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "libkrun shim Linux KVM evidence field `{field}` is not true"
                ));
            }
        }
        let expected = expected_system_image_manifest_sha256.ok_or_else(|| {
            "host did not retain the required Linux KVM system-image manifest digest".to_string()
        })?;
        let assets = object
            .get("linux_boot_assets")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                "libkrun shim did not retain Linux KVM immutable boot-asset evidence".to_string()
            })?;
        if assets.get("manifest_sha256").and_then(Value::as_str) != Some(expected) {
            return Err(
                "libkrun shim Linux KVM manifest digest does not match the host digest".into(),
            );
        }
        if assets.get("target_arch").and_then(Value::as_str) != Some(std::env::consts::ARCH) {
            return Err("libkrun shim Linux KVM target architecture is unexpected".into());
        }
        if assets.get("root_disk_read_only").and_then(Value::as_bool) != Some(true) {
            return Err(
                "libkrun shim Linux KVM boot asset `root_disk_read_only` is not true".into(),
            );
        }
        for field in [
            "system_image_sha256",
            "guest_agent_sha256",
            "runtime_archive_sha256",
            "libkrun_sha256",
            "firmware_sha256",
            "kernel_bundle_sha256",
        ] {
            let digest = assets.get(field).and_then(Value::as_str).ok_or_else(|| {
                format!("libkrun shim Linux KVM boot-asset field `{field}` is missing")
            })?;
            if !is_canonical_hex(digest, 64) {
                return Err(format!(
                    "libkrun shim Linux KVM boot-asset field `{field}` is not a canonical SHA-256"
                ));
            }
        }
        if assets.get("system_image_size").and_then(Value::as_u64) != Some(67_108_864)
            || assets
                .get("guest_agent_size")
                .and_then(Value::as_u64)
                .is_none_or(|size| size == 0)
            || assets
                .get("kernel_bundle_size")
                .and_then(Value::as_u64)
                .is_none_or(|size| size == 0)
            || !assets
                .get("kernel_guest_load_address")
                .and_then(Value::as_str)
                .is_some_and(|address| address.starts_with("0x"))
            || !assets
                .get("kernel_entry_address")
                .and_then(Value::as_str)
                .is_some_and(|address| address.starts_with("0x"))
        {
            return Err("libkrun shim Linux KVM boot-asset provenance is unexpected".into());
        }
    }
    if matches!(platform, HostPlatform::Windows) {
        let expected = expected_system_image_manifest_sha256.ok_or_else(|| {
            "host did not retain the required Windows system-image manifest digest".to_string()
        })?;
        let assets = object
            .get("windows_boot_assets")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                "libkrun shim did not retain Windows immutable boot-asset evidence".to_string()
            })?;
        if assets.get("manifest_sha256").and_then(Value::as_str) != Some(expected) {
            return Err(
                "libkrun shim system-image manifest digest does not match the host digest".into(),
            );
        }
        for field in ["root_disk_read_only", "runtime_share_separate"] {
            if assets.get(field).and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "libkrun shim Windows boot-asset field `{field}` is not true"
                ));
            }
        }
        for field in [
            "system_image_sha256",
            "runtime_archive_sha256",
            "krun_dll_sha256",
            "firmware_sha256",
            "kernel_source_sha256",
            "kernel_bundle_sha256",
        ] {
            let digest = assets.get(field).and_then(Value::as_str).ok_or_else(|| {
                format!("libkrun shim Windows boot-asset field `{field}` is missing")
            })?;
            if !is_canonical_hex(digest, 64) {
                return Err(format!(
                    "libkrun shim Windows boot-asset field `{field}` is not a canonical SHA-256"
                ));
            }
        }
        for field in [
            "box_revision",
            "libkrun_revision",
            "firmware_wrapper_revision",
            "libkrunfw_revision",
        ] {
            let revision = assets.get(field).and_then(Value::as_str).ok_or_else(|| {
                format!("libkrun shim Windows boot-asset field `{field}` is missing")
            })?;
            if !is_canonical_hex(revision, 40) {
                return Err(format!(
                    "libkrun shim Windows boot-asset field `{field}` is not a canonical revision"
                ));
            }
        }
        if assets.get("kernel_version").and_then(Value::as_str) != Some("6.12.91")
            || assets.get("system_image_size").and_then(Value::as_u64) != Some(67_108_864)
            || assets.get("kernel_bundle_size").and_then(Value::as_u64) != Some(21_364_736)
            || assets
                .get("kernel_guest_load_address")
                .and_then(Value::as_str)
                != Some("0x0000000001000000")
            || assets.get("kernel_entry_address").and_then(Value::as_str)
                != Some("0x0000000001000123")
        {
            return Err("libkrun shim Windows boot-asset provenance is unexpected".into());
        }
        let handles_before = object
            .get("windows_handles_before_vm")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                "libkrun shim Windows pre-entry handle inventory is missing or invalid".to_string()
            })?;
        let handles_after = object
            .get("windows_handles_after_vm")
            .and_then(Value::as_u64)
            .and_then(|count| u32::try_from(count).ok())
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                "libkrun shim Windows post-entry handle inventory is missing or invalid".to_string()
            })?;
        if object
            .get("windows_handle_inventory_restored")
            .and_then(Value::as_bool)
            != Some(true)
            || handles_after != handles_before
        {
            return Err(format!(
                "libkrun shim did not reclaim the in-process Windows handle inventory: \
                 {handles_before} to {handles_after}"
            ));
        }
    }
    if matches!(platform, HostPlatform::Macos) {
        let expected = expected_system_image_manifest_sha256.ok_or_else(|| {
            "host did not retain the required macOS system-image manifest digest".to_string()
        })?;
        let assets = object
            .get("macos_boot_assets")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                "libkrun shim did not retain macOS immutable boot-asset evidence".to_string()
            })?;
        if assets.get("manifest_sha256").and_then(Value::as_str) != Some(expected) {
            return Err(
                "libkrun shim system-image manifest digest does not match the host digest".into(),
            );
        }
        for field in ["root_disk_read_only", "runtime_share_separate"] {
            if assets.get(field).and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "libkrun shim macOS boot-asset field `{field}` is not true"
                ));
            }
        }
        for field in [
            "system_image_sha256",
            "runtime_archive_sha256",
            "libkrun_sha256",
            "firmware_sha256",
            "kernel_bundle_sha256",
        ] {
            let digest = assets.get(field).and_then(Value::as_str).ok_or_else(|| {
                format!("libkrun shim macOS boot-asset field `{field}` is missing")
            })?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(format!(
                    "libkrun shim macOS boot-asset field `{field}` is not a canonical SHA-256"
                ));
            }
        }
        if assets.get("system_image_size").and_then(Value::as_u64) != Some(67_108_864)
            || assets.get("kernel_bundle_size").and_then(Value::as_u64) != Some(22_740_992)
        {
            return Err("libkrun shim macOS boot-asset sizes are unexpected".into());
        }
    }
    if object.get("guest_exit_code").and_then(Value::as_i64) != Some(0) {
        return Err("libkrun shim did not report a zero guest-agent exit code".into());
    }
    if object.get("reason").is_some_and(|reason| !reason.is_null()) {
        return Err("successful libkrun shim evidence unexpectedly contains a reason".into());
    }
    if object.get("vcpus").and_then(Value::as_u64) != Some(1)
        || object.get("memory_mib").and_then(Value::as_u64) != Some(512)
    {
        return Err("libkrun shim evidence has unexpected VM resources".into());
    }
    Ok(report)
}

fn is_canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
async fn prepare_macos_runtime_share(path: &Path) -> Result<PathBuf, String> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        format!(
            "failed to inspect writable runtime share {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(format!(
            "writable runtime share must be a real directory, not a symlink: {}",
            path.display()
        ));
    }
    let path = tokio::fs::canonicalize(path).await.map_err(|error| {
        format!(
            "failed to canonicalize writable runtime share {}: {error}",
            path.display()
        )
    })?;
    let state = path.join("run");
    match tokio::fs::symlink_metadata(&state).await {
        Ok(metadata) if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(format!(
                "runtime-state path must be a real directory inside the writable share: {}",
                state.display()
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tokio::fs::create_dir(&state).await.map_err(|error| {
                format!(
                    "failed to create runtime-state directory {}: {error}",
                    state.display()
                )
            })?;
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect runtime-state directory {}: {error}",
                state.display()
            ))
        }
    }
    Ok(path)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
async fn prepare_linux_runtime_share(path: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

    if !path.is_absolute() {
        return Err(format!(
            "Linux KVM runtime share must be absolute: {}",
            path.display()
        ));
    }
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        format!(
            "failed to inspect Linux KVM runtime share {}: {error}",
            path.display()
        )
    })?;
    // SAFETY: geteuid has no arguments and cannot fail.
    let effective_user_id = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != effective_user_id
        || metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(format!(
            "Linux KVM runtime share must be a real UID-{effective_user_id} directory with mode {PRIVATE_DIRECTORY_MODE:03o}: {}",
            path.display()
        ));
    }
    let path = tokio::fs::canonicalize(path).await.map_err(|error| {
        format!(
            "failed to canonicalize Linux KVM runtime share {}: {error}",
            path.display()
        )
    })?;
    let state = path.join("run");
    match tokio::fs::symlink_metadata(&state).await {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == effective_user_id
                && metadata.mode() & 0o777 == PRIVATE_DIRECTORY_MODE => {}
        Ok(_) => {
            return Err(format!(
                "Linux KVM runtime-state path must be a real private directory: {}",
                state.display()
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tokio::fs::create_dir(&state).await.map_err(|error| {
                format!(
                    "failed to create Linux KVM runtime-state directory {}: {error}",
                    state.display()
                )
            })?;
            tokio::fs::set_permissions(
                &state,
                std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
            )
            .await
            .map_err(|error| {
                format!(
                    "failed to protect Linux KVM runtime-state directory {}: {error}",
                    state.display()
                )
            })?;
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect Linux KVM runtime-state directory {}: {error}",
                state.display()
            ))
        }
    }
    Ok(path)
}

#[cfg(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
pub(crate) async fn sha256_path(path: &Path) -> Result<String, String> {
    use tokio::io::AsyncReadExt;

    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        format!(
            "failed to inspect system-image manifest {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "system-image manifest must be a real regular file, not a symlink: {}",
            path.display()
        ));
    }
    let mut file = tokio::fs::File::open(path).await.map_err(|error| {
        format!(
            "failed to open system-image manifest {}: {error}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer).await.map_err(|error| {
            format!(
                "failed to read system-image manifest {}: {error}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        size += read as u64;
        if size > 64 * 1024 {
            return Err(format!(
                "system-image manifest exceeds 65536 bytes: {}",
                path.display()
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn expected_operations() -> Vec<AgentOperation> {
    AgentOperation::ALL.to_vec()
}

const fn expected_guest_architecture(platform: HostPlatform) -> &'static str {
    match platform {
        HostPlatform::Linux => std::env::consts::ARCH,
        HostPlatform::Windows => "x86_64",
        HostPlatform::Macos => "aarch64",
        _ => "",
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
async fn accept_bridge(
    listener: WindowsAgentPipeListener,
    shim_process_id: u32,
) -> a3s_oci_sdk::Result<(PlatformAgentStream, u32)> {
    let stream = listener.accept_from_process(shim_process_id).await?;
    Ok((stream, shim_process_id))
}

#[cfg(unix)]
async fn accept_bridge(
    listener: UnixAgentSocketListener,
    shim_process_id: u32,
) -> a3s_oci_sdk::Result<(PlatformAgentStream, u32)> {
    listener.accept_from_child(shim_process_id).await
}

fn apply_completed(report: &mut AgentVmSmokeReport, completed: &CompletedShim) {
    report.shim_exit_code = completed.status.as_ref().and_then(ExitStatus::code);
}

fn failed(mut report: AgentVmSmokeReport, reason: impl Into<String>) -> AgentVmSmokeReport {
    report.reason = Some(reason.into());
    report
}

fn failed_with_output(
    mut report: AgentVmSmokeReport,
    reason: &str,
    completed: &CompletedShim,
) -> AgentVmSmokeReport {
    if report.shim_report.is_none() {
        report.shim_report = bounded_unverified_shim_report(&completed.stdout);
    }
    let mut details = Vec::new();
    details.extend(completed.collection_errors.iter().cloned());
    if let Some(stderr) = diagnostic(&completed.stderr) {
        details.push(format!("shim stderr: {stderr}"));
    }
    if let Some(stdout) = diagnostic(&completed.stdout) {
        details.push(format!("shim stdout: {stdout}"));
    }
    let reason = if details.is_empty() {
        reason.to_string()
    } else {
        format!("{reason}; {}", details.join("; "))
    };
    failed(report, reason)
}

fn bounded_unverified_shim_report(output: &BoundedOutput) -> Option<Value> {
    if output.truncated {
        return None;
    }
    let report: Value = serde_json::from_slice(&output.bytes).ok()?;
    let object = report.as_object()?;
    if object.get("schema_version").and_then(Value::as_str) != Some(SHIM_REPORT_SCHEMA_VERSION) {
        return None;
    }
    Some(report)
}

fn diagnostic(output: &BoundedOutput) -> Option<String> {
    if output.bytes.is_empty() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.bytes);
    let mut diagnostic = text
        .trim()
        .chars()
        .take(MAX_DIAGNOSTIC_CHARS)
        .collect::<String>();
    if output.truncated || text.trim().chars().count() > MAX_DIAGNOSTIC_CHARS {
        diagnostic.push_str("...[truncated]");
    }
    Some(diagnostic)
}

#[cfg(test)]
mod tests;
