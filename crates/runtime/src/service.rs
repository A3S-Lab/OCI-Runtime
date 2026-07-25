use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use a3s_oci_core::{CapabilityStatus, DriverCapability, RuntimeFeatures};
use a3s_oci_sdk::oci_spec::runtime::{
    ApparmorBuilder, Arch, CgroupBuilder, ContainerState, FeaturesBuilder, IDMapBuilder,
    IntelRdtBuilder, LinuxFeature, LinuxFeatureBuilder, LinuxNamespaceType, LinuxSeccompAction,
    MountExtensionsBuilder, NetDevicesBuilder, SeccompBuilder, SelinuxBuilder,
};
use a3s_oci_sdk::{
    async_trait, CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, ContainerRecord,
    ContainerStats, ContainerTarget, CreateRequest, DeleteRequest, Error, ErrorCode, EventBatch,
    EventsRequest, ExecRequest, ExitStatus, KillRequest, ListRequest, OciRuntimeService,
    OutputChunk, ProcessId, ProcessRecord, ProcessTarget, ProcessesRequest, ReadOutputRequest,
    ResizeRequest, RestoreRequest, Result, RuntimeInfo, RuntimeOperation, SignalProcessRequest,
    StartRequest, StateRequest, StatsRequest, UpdateRequest, ValidateRequest, WaitProcessRequest,
    WaitRequest, WriteStdinRequest, OCI_RUNTIME_SPEC_VERSION_MAX, OCI_RUNTIME_SPEC_VERSION_MIN,
};

use crate::driver::{
    DriverContainerOperationRequest, DriverCreateRequest, DriverDeleteRequest, DriverExecRequest,
    DriverKillRequest, DriverSignalProcessRequest, DriverStartRequest, DriverWaitProcessRequest,
    DriverWaitRequest, RuntimeDriver,
};
use crate::fault::{
    DriverBoundaryStage, DriverOperation, FaultInjector, FaultPoint, NoFaultInjector,
};
use crate::state::{
    DeletePreparation, DurableStateStore, ProcessOperationPreparation, ProcessWaitPreparation,
    RecordOperationPreparation, SignalProcessPreparation,
};

const RECOGNIZED_LINUX_MOUNT_OPTIONS: &[&str] = &[
    "async",
    "atime",
    "bind",
    "defaults",
    "dev",
    "diratime",
    "dirsync",
    "exec",
    "idmap",
    "iversion",
    "lazytime",
    "loud",
    "mand",
    "noatime",
    "nodev",
    "nodiratime",
    "noexec",
    "noiversion",
    "nolazytime",
    "nomand",
    "norelatime",
    "nostrictatime",
    "nosuid",
    "nosymfollow",
    "private",
    "ratime",
    "rbind",
    "rdev",
    "rdiratime",
    "relatime",
    "remount",
    "rexec",
    "ridmap",
    "rnoatime",
    "rnodev",
    "rnodiratime",
    "rnoexec",
    "rnorelatime",
    "rnostrictatime",
    "rnosuid",
    "rnosymfollow",
    "ro",
    "rprivate",
    "rrelatime",
    "rro",
    "rrw",
    "rshared",
    "rslave",
    "rstrictatime",
    "rsuid",
    "rsymfollow",
    "runbindable",
    "rw",
    "shared",
    "silent",
    "slave",
    "strictatime",
    "suid",
    "symfollow",
    "sync",
    "unbindable",
];

const SUPPORTED_LINUX_CAPABILITIES: &[&str] = &[
    "CAP_AUDIT_CONTROL",
    "CAP_AUDIT_READ",
    "CAP_AUDIT_WRITE",
    "CAP_BLOCK_SUSPEND",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_LINUX_IMMUTABLE",
    "CAP_MAC_ADMIN",
    "CAP_MAC_OVERRIDE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_RAW",
    "CAP_PERFMON",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_CHROOT",
    "CAP_SYS_MODULE",
    "CAP_SYS_NICE",
    "CAP_SYS_PACCT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
];

/// In-process host implementation used by the CLI and A3S Box adapter.
#[derive(Clone, Default)]
pub struct HostRuntimeService {
    lifecycle: Option<Arc<LifecycleHost>>,
}

struct LifecycleHost {
    store: DurableStateStore,
    driver: Arc<dyn RuntimeDriver>,
    capability: DriverCapability,
    operations: BTreeSet<RuntimeOperation>,
    faults: Arc<dyn FaultInjector>,
}

impl fmt::Debug for HostRuntimeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostRuntimeService")
            .field(
                "driver",
                &self
                    .lifecycle
                    .as_ref()
                    .map(|lifecycle| lifecycle.capability.driver),
            )
            .finish()
    }
}

impl HostRuntimeService {
    /// Construct the probe-only local host service.
    #[must_use]
    pub const fn new() -> Self {
        Self { lifecycle: None }
    }

    /// Open durable lifecycle orchestration around one fully enforcing driver.
    pub async fn open(
        state_root: impl AsRef<Path>,
        driver: Arc<dyn RuntimeDriver>,
    ) -> Result<Self> {
        Self::open_with_fault_injector(state_root, driver, Arc::new(NoFaultInjector)).await
    }

    pub(crate) async fn open_with_fault_injector(
        state_root: impl AsRef<Path>,
        driver: Arc<dyn RuntimeDriver>,
        faults: Arc<dyn FaultInjector>,
    ) -> Result<Self> {
        faults.check(FaultPoint::DriverBoundary {
            operation: DriverOperation::Capability,
            stage: DriverBoundaryStage::BeforeCall,
        })?;
        let capability = driver.capability();
        faults.check(FaultPoint::DriverBoundary {
            operation: DriverOperation::Capability,
            stage: DriverBoundaryStage::AfterCall,
        })?;
        if !capability.can_launch() {
            let code = if capability.status == CapabilityStatus::Unavailable {
                ErrorCode::Unavailable
            } else {
                ErrorCode::Unsupported
            };
            return Err(Error::new(
                code,
                format!(
                    "driver {:?} is not launch-ready: status {:?}, readiness {:?}",
                    capability.driver, capability.status, capability.readiness
                ),
            )
            .for_operation("open-host-runtime"));
        }
        if capability.isolation_classes.is_empty() {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!(
                    "launch-ready driver {:?} advertises no isolation class",
                    capability.driver
                ),
            )
            .for_operation("open-host-runtime"));
        }
        let operations = validate_driver_operations(driver.operations())?;
        let store =
            DurableStateStore::open_with_fault_injector(state_root, Arc::clone(&faults)).await?;
        Ok(Self {
            lifecycle: Some(Arc::new(LifecycleHost {
                store,
                driver,
                capability,
                operations,
                faults,
            })),
        })
    }

    fn lifecycle(&self, operation: &'static str) -> Result<&LifecycleHost> {
        self.lifecycle
            .as_deref()
            .ok_or_else(|| Error::unsupported(operation))
    }

    fn runtime_features(&self) -> RuntimeFeatures {
        let mut features = crate::features();
        if let Some(lifecycle) = &self.lifecycle {
            if let Some(existing) = features
                .drivers
                .iter_mut()
                .find(|entry| entry.driver == lifecycle.capability.driver)
            {
                *existing = lifecycle.capability.clone();
            } else {
                features.drivers.push(lifecycle.capability.clone());
            }
        }
        features
    }
}

impl LifecycleHost {
    fn driver_boundary(
        &self,
        operation: DriverOperation,
        stage: DriverBoundaryStage,
    ) -> Result<()> {
        self.faults
            .check(FaultPoint::DriverBoundary { operation, stage })
    }

    fn ensure_isolation(&self, request: &CreateRequest) -> Result<()> {
        let isolation = request.isolation.class();
        if self.capability.isolation_classes.contains(&isolation) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorCode::Unsupported,
                format!(
                    "driver {:?} does not provide requested isolation {isolation:?}",
                    self.capability.driver
                ),
            )
            .for_operation("create"))
        }
    }

    fn ensure_operation(&self, operation: RuntimeOperation, name: &'static str) -> Result<()> {
        if self.operations.contains(&operation) {
            Ok(())
        } else {
            Err(Error::unsupported(name))
        }
    }

    async fn fail_driver_operation<T>(
        &self,
        operation_id: &a3s_oci_sdk::OperationId,
        error: Error,
    ) -> Result<T> {
        if error.retryable {
            return Err(error);
        }
        self.store.fail_operation(operation_id, &error).await?;
        Err(error)
    }

    async fn complete_process_wait(
        &self,
        target: &ProcessTarget,
        status: ExitStatus,
    ) -> Result<ExitStatus> {
        if target.process_id.is_init() {
            self.store
                .observe_state(&target.container, ContainerState::Stopped, None)
                .await?;
        }
        self.store.complete_process_wait(target, status).await
    }
}

fn validate_driver_operations(
    operations: &[RuntimeOperation],
) -> Result<BTreeSet<RuntimeOperation>> {
    const REQUIRED: [RuntimeOperation; 5] = [
        RuntimeOperation::Create,
        RuntimeOperation::State,
        RuntimeOperation::Start,
        RuntimeOperation::Kill,
        RuntimeOperation::Delete,
    ];
    const HOST_SUPPORTED: [RuntimeOperation; 12] = [
        RuntimeOperation::Create,
        RuntimeOperation::State,
        RuntimeOperation::Start,
        RuntimeOperation::Kill,
        RuntimeOperation::Delete,
        RuntimeOperation::Wait,
        RuntimeOperation::Exec,
        RuntimeOperation::SignalProcess,
        RuntimeOperation::WaitProcess,
        RuntimeOperation::Pause,
        RuntimeOperation::Resume,
        RuntimeOperation::Processes,
    ];
    let reported = operations.iter().copied().collect::<BTreeSet<_>>();
    if reported.len() != operations.len() {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            "runtime driver advertises duplicate operations",
        )
        .for_operation("open-host-runtime"));
    }
    if let Some(operation) = operations
        .iter()
        .find(|operation| !HOST_SUPPORTED.contains(operation))
    {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!("runtime driver advertises unsupported host operation {operation:?}"),
        )
        .for_operation("open-host-runtime"));
    }
    if let Some(operation) = REQUIRED
        .iter()
        .find(|operation| !reported.contains(operation))
    {
        return Err(Error::new(
            ErrorCode::FailedPrecondition,
            format!("runtime driver does not advertise required operation {operation:?}"),
        )
        .for_operation("open-host-runtime"));
    }
    Ok(reported)
}

fn driver_state_error(
    operation: &'static str,
    expected: ContainerState,
    observed: ContainerState,
) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!(
            "driver violated the OCI {operation} barrier: expected {expected}, observed {observed}"
        ),
    )
    .for_operation(operation)
}

fn compiled_linux_features() -> Result<LinuxFeature> {
    let cgroup = CgroupBuilder::default()
        .v1(false)
        .v2(true)
        .systemd(false)
        .systemd_user(false)
        .rdma(false)
        .build()
        .map_err(feature_build_error)?;
    let seccomp = SeccompBuilder::default()
        .enabled(true)
        .actions(vec![
            LinuxSeccompAction::ScmpActAllow,
            LinuxSeccompAction::ScmpActErrno,
            LinuxSeccompAction::ScmpActKill,
            LinuxSeccompAction::ScmpActKillProcess,
            LinuxSeccompAction::ScmpActKillThread,
            LinuxSeccompAction::ScmpActLog,
            LinuxSeccompAction::ScmpActTrace,
            LinuxSeccompAction::ScmpActTrap,
        ])
        .operators(
            [
                "SCMP_CMP_EQ",
                "SCMP_CMP_GE",
                "SCMP_CMP_GT",
                "SCMP_CMP_LE",
                "SCMP_CMP_LT",
                "SCMP_CMP_MASKED_EQ",
                "SCMP_CMP_NE",
            ]
            .map(str::to_string)
            .to_vec(),
        )
        .archs(vec![Arch::ScmpArchAarch64, Arch::ScmpArchX86_64])
        .known_flags(
            [
                "SECCOMP_FILTER_FLAG_LOG",
                "SECCOMP_FILTER_FLAG_SPEC_ALLOW",
                "SECCOMP_FILTER_FLAG_TSYNC",
                "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV",
            ]
            .map(str::to_string)
            .to_vec(),
        )
        .supported_flags(Vec::<String>::new())
        .build()
        .map_err(feature_build_error)?;
    let apparmor = ApparmorBuilder::default()
        .enabled(false)
        .build()
        .map_err(feature_build_error)?;
    let selinux = SelinuxBuilder::default()
        .enabled(false)
        .build()
        .map_err(feature_build_error)?;
    let intel_rdt = IntelRdtBuilder::default()
        .enabled(false)
        .schemata(false)
        .monitoring(false)
        .build()
        .map_err(feature_build_error)?;
    let net_devices = NetDevicesBuilder::default()
        .enabled(false)
        .build()
        .map_err(feature_build_error)?;
    let idmap = IDMapBuilder::default()
        .enabled(true)
        .build()
        .map_err(feature_build_error)?;
    let mount_extensions = MountExtensionsBuilder::default()
        .idmap(idmap)
        .build()
        .map_err(feature_build_error)?;
    LinuxFeatureBuilder::default()
        .namespaces(vec![
            LinuxNamespaceType::Cgroup,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Network,
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Time,
            LinuxNamespaceType::User,
            LinuxNamespaceType::Uts,
        ])
        .capabilities(
            SUPPORTED_LINUX_CAPABILITIES
                .iter()
                .map(|capability| (*capability).to_string())
                .collect::<Vec<_>>(),
        )
        .cgroup(cgroup)
        .seccomp(seccomp)
        .apparmor(apparmor)
        .selinux(selinux)
        .intel_rdt(intel_rdt)
        .mount_extensions(mount_extensions)
        .net_devices(net_devices)
        .build()
        .map_err(feature_build_error)
}

fn feature_build_error(error: impl fmt::Display) -> Error {
    Error::new(
        ErrorCode::Internal,
        format!("failed to construct OCI feature report: {error}"),
    )
    .for_operation("features")
}

#[async_trait]
impl OciRuntimeService for HostRuntimeService {
    async fn features(&self) -> Result<RuntimeInfo> {
        let annotations = HashMap::from([
            (
                "dev.a3s.oci.runtime.version".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
            ),
            (
                "dev.a3s.oci.runtime.lifecycle".to_string(),
                if self.lifecycle.is_some() {
                    "durable-core"
                } else {
                    "probe-only"
                }
                .to_string(),
            ),
        ]);
        let oci = FeaturesBuilder::default()
            .oci_version_min(OCI_RUNTIME_SPEC_VERSION_MIN)
            .oci_version_max(OCI_RUNTIME_SPEC_VERSION_MAX)
            .hooks(Vec::<String>::new())
            .mount_options(
                RECOGNIZED_LINUX_MOUNT_OPTIONS
                    .iter()
                    .map(|option| (*option).to_string())
                    .collect::<Vec<_>>(),
            )
            .linux(compiled_linux_features()?)
            .annotations(annotations)
            .potentially_unsafe_config_annotations(Vec::<String>::new())
            .build()
            .map_err(feature_build_error)?;

        let mut operations = vec![RuntimeOperation::Features];
        if let Some(lifecycle) = &self.lifecycle {
            operations.extend(lifecycle.operations.iter().copied());
        }
        Ok(RuntimeInfo {
            oci,
            drivers: self.runtime_features(),
            operations,
        })
    }

    async fn create(&self, request: CreateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("create")?;
        lifecycle.ensure_isolation(&request)?;
        let prepared = lifecycle
            .store
            .prepare_create(&request, lifecycle.capability.driver)
            .await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.id.clone(), record.generation);
        let durable_bundle = lifecycle.store.bundle(&target).await?;
        lifecycle.driver_boundary(DriverOperation::Create, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .create(DriverCreateRequest {
                context: request.context.clone(),
                target,
                bundle: durable_bundle,
                isolation: request.isolation,
                io: request.io,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Create, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        if observed.status() != ContainerState::Created {
            let error = driver_state_error("create", ContainerState::Created, observed.status());
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        let pid = observed.pid().ok_or_else(|| {
            Error::new(
                ErrorCode::Internal,
                "created driver state did not contain an init PID",
            )
            .for_operation("create")
        })?;
        lifecycle
            .store
            .complete_create(&request.context.operation_id, pid)
            .await
    }

    async fn state(&self, request: StateRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("state")?;
        request.validate()?;
        let durable = lifecycle.store.state(&request.target).await?;
        if *durable.state.status() == ContainerState::Creating {
            return Ok(durable);
        }
        let target = ContainerTarget::exact(request.target.id, durable.generation);
        lifecycle.driver_boundary(DriverOperation::State, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle.driver.state(target.clone()).await;
        lifecycle.driver_boundary(DriverOperation::State, DriverBoundaryStage::AfterCall)?;
        let observed = result?;
        lifecycle
            .store
            .observe_state_with_pause(
                &target,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await
    }

    async fn start(&self, request: StartRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("start")?;
        let prepared = lifecycle.store.prepare_start(&request).await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        let bundle = lifecycle.store.bundle(&target).await?;
        lifecycle.driver_boundary(DriverOperation::Start, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .start(DriverStartRequest {
                context: request.context.clone(),
                target,
                bundle,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Start, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        if !matches!(
            observed.status(),
            ContainerState::Running | ContainerState::Stopped
        ) {
            let error = driver_state_error("start", ContainerState::Running, observed.status());
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        lifecycle
            .store
            .complete_start(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
            )
            .await
    }

    async fn kill(&self, request: KillRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("kill")?;
        let prepared = lifecycle.store.prepare_kill(&request).await?;
        let record = match prepared {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Kill, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .kill(DriverKillRequest {
                context: request.context.clone(),
                target,
                signal: request.signal,
                all: request.all,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Kill, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        lifecycle
            .store
            .complete_kill(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
            )
            .await
    }

    async fn delete(&self, request: DeleteRequest) -> Result<()> {
        let lifecycle = self.lifecycle("delete")?;
        let prepared = lifecycle.store.prepare_delete(&request).await?;
        let record = match prepared {
            DeletePreparation::Replayed => return Ok(()),
            DeletePreparation::Prepared(record) | DeletePreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Delete, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .delete(DriverDeleteRequest {
                context: request.context.clone(),
                target,
                mode: request.mode,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Delete, DriverBoundaryStage::AfterCall)?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        lifecycle
            .store
            .complete_delete(&request.context.operation_id)
            .await
    }

    async fn exec(&self, request: ExecRequest) -> Result<ProcessRecord> {
        let lifecycle = self.lifecycle("exec")?;
        lifecycle.ensure_operation(RuntimeOperation::Exec, "exec")?;
        let prepared = lifecycle.store.prepare_exec(&request).await?;
        let durable = match prepared {
            ProcessOperationPreparation::Replayed(record) => return Ok(record),
            ProcessOperationPreparation::Prepared(record)
            | ProcessOperationPreparation::Resume(record) => record,
        };
        let target = durable.target;
        lifecycle.driver_boundary(DriverOperation::Exec, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .exec(DriverExecRequest {
                context: request.context.clone(),
                target,
                process: request.process,
                io: request.io,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Exec, DriverBoundaryStage::AfterCall)?;
        let process = match result {
            Ok(process) => process,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        lifecycle
            .store
            .complete_exec(
                &request.context.operation_id,
                process.pid(),
                process.terminal(),
            )
            .await
    }

    async fn wait(&self, request: WaitRequest) -> Result<ExitStatus> {
        let lifecycle = self.lifecycle("wait")?;
        lifecycle.ensure_operation(RuntimeOperation::Wait, "wait")?;
        request.validate()?;
        let process_request = WaitProcessRequest {
            process: ProcessTarget {
                container: request.target,
                process_id: ProcessId::init(),
            },
            timeout_ms: request.timeout_ms,
        };
        let target = match lifecycle
            .store
            .prepare_wait_process(&process_request)
            .await?
        {
            ProcessWaitPreparation::Replayed(status) => return Ok(status),
            ProcessWaitPreparation::Prepared(target) => target,
        };
        lifecycle.driver_boundary(DriverOperation::Wait, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .wait(DriverWaitRequest {
                target: target.container.clone(),
                timeout_ms: request.timeout_ms,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Wait, DriverBoundaryStage::AfterCall)?;
        let status = result?;
        status.validate()?;
        lifecycle.complete_process_wait(&target, status).await
    }

    async fn list(&self, _request: ListRequest) -> Result<Vec<ContainerRecord>> {
        Err(Error::unsupported("list"))
    }

    async fn pause(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("pause")?;
        lifecycle.ensure_operation(RuntimeOperation::Pause, "pause")?;
        let record = match lifecycle.store.prepare_pause(&request).await? {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Pause, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .pause(DriverContainerOperationRequest {
                context: request.context.clone(),
                target,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Pause, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        lifecycle
            .store
            .complete_pause(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await
    }

    async fn resume(&self, request: ContainerOperationRequest) -> Result<ContainerRecord> {
        let lifecycle = self.lifecycle("resume")?;
        lifecycle.ensure_operation(RuntimeOperation::Resume, "resume")?;
        let record = match lifecycle.store.prepare_resume(&request).await? {
            RecordOperationPreparation::Replayed(record) => return Ok(record),
            RecordOperationPreparation::Prepared(record)
            | RecordOperationPreparation::Resume(record) => record,
        };
        let target = ContainerTarget::exact(request.target.id.clone(), record.generation);
        lifecycle.driver_boundary(DriverOperation::Resume, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle
            .driver
            .resume(DriverContainerOperationRequest {
                context: request.context.clone(),
                target,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::Resume, DriverBoundaryStage::AfterCall)?;
        let observed = match result {
            Ok(observed) => observed,
            Err(error) => {
                return lifecycle
                    .fail_driver_operation(&request.context.operation_id, error)
                    .await;
            }
        };
        lifecycle
            .store
            .complete_resume(
                &request.context.operation_id,
                observed.status(),
                observed.pid(),
                observed.paused(),
            )
            .await
    }

    async fn update(&self, _request: UpdateRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("update"))
    }

    async fn processes(&self, request: ProcessesRequest) -> Result<Vec<ProcessRecord>> {
        let lifecycle = self.lifecycle("processes")?;
        lifecycle.ensure_operation(RuntimeOperation::Processes, "processes")?;
        request.validate()?;
        let record = lifecycle.store.state(&request.target).await?;
        let target = ContainerTarget::exact(request.target.id, record.generation);
        lifecycle.driver_boundary(DriverOperation::Processes, DriverBoundaryStage::BeforeCall)?;
        let result = lifecycle.driver.processes(target.clone()).await;
        lifecycle.driver_boundary(DriverOperation::Processes, DriverBoundaryStage::AfterCall)?;
        let mut processes = result?;
        for (index, process) in processes.iter().enumerate() {
            if process.target.container != target
                || process.pid.is_none_or(|pid| pid == 0)
                || processes[..index]
                    .iter()
                    .any(|candidate| candidate.target.process_id == process.target.process_id)
            {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "runtime driver returned an invalid process inventory",
                )
                .for_operation("processes"));
            }
        }
        if *record.state.status() != ContainerState::Stopped
            && !processes
                .iter()
                .any(|process| process.target.process_id.is_init())
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "runtime driver omitted the live init process from its inventory",
            )
            .for_operation("processes"));
        }
        processes.sort_by(|left, right| {
            left.target
                .process_id
                .as_ref()
                .cmp(right.target.process_id.as_ref())
        });
        Ok(processes)
    }

    async fn stats(&self, _request: StatsRequest) -> Result<ContainerStats> {
        Err(Error::unsupported("stats"))
    }

    async fn events(&self, _request: EventsRequest) -> Result<EventBatch> {
        Err(Error::unsupported("events"))
    }

    async fn read_output(&self, _request: ReadOutputRequest) -> Result<Vec<OutputChunk>> {
        Err(Error::unsupported("read-output"))
    }

    async fn write_stdin(&self, _request: WriteStdinRequest) -> Result<()> {
        Err(Error::unsupported("write-stdin"))
    }

    async fn close_stdin(&self, _request: CloseStdinRequest) -> Result<()> {
        Err(Error::unsupported("close-stdin"))
    }

    async fn resize(&self, _request: ResizeRequest) -> Result<()> {
        Err(Error::unsupported("resize"))
    }

    async fn signal_process(&self, request: SignalProcessRequest) -> Result<()> {
        let lifecycle = self.lifecycle("signal-process")?;
        lifecycle.ensure_operation(RuntimeOperation::SignalProcess, "signal-process")?;
        let target = match lifecycle.store.prepare_signal_process(&request).await? {
            SignalProcessPreparation::Replayed => return Ok(()),
            SignalProcessPreparation::Prepared(target)
            | SignalProcessPreparation::Resume(target) => target,
        };
        lifecycle.driver_boundary(
            DriverOperation::SignalProcess,
            DriverBoundaryStage::BeforeCall,
        )?;
        let result = lifecycle
            .driver
            .signal_process(DriverSignalProcessRequest {
                context: request.context.clone(),
                target,
                signal: request.signal,
            })
            .await;
        lifecycle.driver_boundary(
            DriverOperation::SignalProcess,
            DriverBoundaryStage::AfterCall,
        )?;
        if let Err(error) = result {
            return lifecycle
                .fail_driver_operation(&request.context.operation_id, error)
                .await;
        }
        lifecycle
            .store
            .complete_signal_process(&request.context.operation_id)
            .await
    }

    async fn wait_process(&self, request: WaitProcessRequest) -> Result<ExitStatus> {
        let lifecycle = self.lifecycle("wait-process")?;
        lifecycle.ensure_operation(RuntimeOperation::WaitProcess, "wait-process")?;
        let target = match lifecycle.store.prepare_wait_process(&request).await? {
            ProcessWaitPreparation::Replayed(status) => return Ok(status),
            ProcessWaitPreparation::Prepared(target) => target,
        };
        lifecycle.driver_boundary(
            DriverOperation::WaitProcess,
            DriverBoundaryStage::BeforeCall,
        )?;
        let result = lifecycle
            .driver
            .wait_process(DriverWaitProcessRequest {
                target: target.clone(),
                timeout_ms: request.timeout_ms,
            })
            .await;
        lifecycle.driver_boundary(DriverOperation::WaitProcess, DriverBoundaryStage::AfterCall)?;
        let status = result?;
        status.validate()?;
        lifecycle.complete_process_wait(&target, status).await
    }

    async fn checkpoint(&self, _request: CheckpointRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("checkpoint"))
    }

    async fn restore(&self, _request: RestoreRequest) -> Result<ContainerRecord> {
        Err(Error::unsupported("restore"))
    }
}

#[cfg(test)]
mod tests;
