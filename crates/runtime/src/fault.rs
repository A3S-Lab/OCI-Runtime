use std::fmt;

use a3s_oci_sdk::Result;

/// One semantic mutation of runtime-owned durable state.
///
/// Every file replacement and directory move in the lifecycle store must carry
/// exactly one of these identities. The test matrix treats `ALL` as the
/// auditable coverage registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DurableMutation {
    RuntimeRootMarker,
    AllocateGeneration,
    PrepareCreateOperation,
    StoreCreateConfig,
    StoreCreatingContainer,
    ClaimCreateOperation,
    CompleteCreateContainer,
    CompleteCreateOperation,
    PrepareStartOperation,
    ClaimStartOperation,
    ReconcileStartContainer,
    ReconcileStartOperation,
    CompleteStartContainer,
    CompleteStartOperation,
    PrepareKillOperation,
    ClaimKillOperation,
    ReconcileKillContainer,
    ReconcileKillOperation,
    CompleteKillContainer,
    CompleteKillOperation,
    PreparePauseOperation,
    ClaimPauseOperation,
    ReconcilePauseContainer,
    ReconcilePauseOperation,
    CompletePauseContainer,
    CompletePauseOperation,
    PrepareResumeOperation,
    ClaimResumeOperation,
    ReconcileResumeContainer,
    ReconcileResumeOperation,
    CompleteResumeContainer,
    CompleteResumeOperation,
    PrepareUpdateOperation,
    ClaimUpdateOperation,
    CompleteUpdateContainer,
    CompleteUpdateOperation,
    PrepareDeleteOperation,
    ClaimDeleteOperation,
    ReconcileDeleteOperation,
    MoveDeleteTombstone,
    CompleteDeleteOperation,
    PrepareExecOperation,
    StoreExecutingProcess,
    ClaimExecOperation,
    ReconcileExecProcess,
    ReconcileExecOperation,
    CompleteExecProcess,
    CompleteExecOperation,
    PrepareSignalProcessOperation,
    ClaimSignalProcessOperation,
    CompleteSignalProcessRecord,
    CompleteSignalProcessOperation,
    PrepareWriteStdinOperation,
    ClaimWriteStdinOperation,
    CompleteWriteStdinRecord,
    CompleteWriteStdinOperation,
    PrepareCloseStdinOperation,
    ClaimCloseStdinOperation,
    CompleteCloseStdinRecord,
    CompleteCloseStdinOperation,
    PrepareResizeOperation,
    ClaimResizeOperation,
    CompleteResizeRecord,
    CompleteResizeOperation,
    PrepareFileOperation,
    ClaimFileOperation,
    CompleteFileContainer,
    CompleteFileOperation,
    PrepareFilesystemOperation,
    ClaimFilesystemOperation,
    CompleteFilesystemContainer,
    CompleteFilesystemOperation,
    PrepareCheckpointOperation,
    ClaimCheckpointOperation,
    CompleteCheckpointContainer,
    CompleteCheckpointOperation,
    PrepareRestoreOperation,
    StoreRestoreConfig,
    StoreRestoringContainer,
    ClaimRestoreOperation,
    CompleteRestoreContainer,
    CompleteRestoreOperation,
    CacheInitWait,
    CacheProcessWait,
    AdvanceEventSequence,
    ClaimRuntimeEvent,
    StoreRuntimeEvent,
    RecordCreateFailure,
    MoveFailedCreateTombstone,
    ReleaseFailedStartClaim,
    RecordStartFailure,
    ReleaseFailedKillClaim,
    RecordKillFailure,
    ReleaseFailedPauseClaim,
    RecordPauseFailure,
    ReleaseFailedResumeClaim,
    RecordResumeFailure,
    ReleaseFailedUpdateClaim,
    RecordUpdateFailure,
    ReleaseFailedDeleteClaim,
    RecordDeleteFailure,
    ReleaseFailedExecClaim,
    RecordExecFailure,
    ReleaseFailedSignalProcessClaim,
    RecordSignalProcessFailure,
    ReleaseFailedWriteStdinClaim,
    RecordWriteStdinFailure,
    ReleaseFailedCloseStdinClaim,
    RecordCloseStdinFailure,
    ReleaseFailedResizeClaim,
    RecordResizeFailure,
    ReleaseFailedFileClaim,
    RecordFileFailure,
    ReleaseFailedFilesystemClaim,
    RecordFilesystemFailure,
    ReleaseFailedCheckpointClaim,
    RecordCheckpointFailure,
    RecordRestoreFailure,
    MoveFailedRestoreTombstone,
    ObserveContainer,
    CompleteObservedOperation,
}

impl DurableMutation {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 121] = [
        Self::RuntimeRootMarker,
        Self::AllocateGeneration,
        Self::PrepareCreateOperation,
        Self::StoreCreateConfig,
        Self::StoreCreatingContainer,
        Self::ClaimCreateOperation,
        Self::CompleteCreateContainer,
        Self::CompleteCreateOperation,
        Self::PrepareStartOperation,
        Self::ClaimStartOperation,
        Self::ReconcileStartContainer,
        Self::ReconcileStartOperation,
        Self::CompleteStartContainer,
        Self::CompleteStartOperation,
        Self::PrepareKillOperation,
        Self::ClaimKillOperation,
        Self::ReconcileKillContainer,
        Self::ReconcileKillOperation,
        Self::CompleteKillContainer,
        Self::CompleteKillOperation,
        Self::PreparePauseOperation,
        Self::ClaimPauseOperation,
        Self::ReconcilePauseContainer,
        Self::ReconcilePauseOperation,
        Self::CompletePauseContainer,
        Self::CompletePauseOperation,
        Self::PrepareResumeOperation,
        Self::ClaimResumeOperation,
        Self::ReconcileResumeContainer,
        Self::ReconcileResumeOperation,
        Self::CompleteResumeContainer,
        Self::CompleteResumeOperation,
        Self::PrepareUpdateOperation,
        Self::ClaimUpdateOperation,
        Self::CompleteUpdateContainer,
        Self::CompleteUpdateOperation,
        Self::PrepareDeleteOperation,
        Self::ClaimDeleteOperation,
        Self::ReconcileDeleteOperation,
        Self::MoveDeleteTombstone,
        Self::CompleteDeleteOperation,
        Self::PrepareExecOperation,
        Self::StoreExecutingProcess,
        Self::ClaimExecOperation,
        Self::ReconcileExecProcess,
        Self::ReconcileExecOperation,
        Self::CompleteExecProcess,
        Self::CompleteExecOperation,
        Self::PrepareSignalProcessOperation,
        Self::ClaimSignalProcessOperation,
        Self::CompleteSignalProcessRecord,
        Self::CompleteSignalProcessOperation,
        Self::PrepareWriteStdinOperation,
        Self::ClaimWriteStdinOperation,
        Self::CompleteWriteStdinRecord,
        Self::CompleteWriteStdinOperation,
        Self::PrepareCloseStdinOperation,
        Self::ClaimCloseStdinOperation,
        Self::CompleteCloseStdinRecord,
        Self::CompleteCloseStdinOperation,
        Self::PrepareResizeOperation,
        Self::ClaimResizeOperation,
        Self::CompleteResizeRecord,
        Self::CompleteResizeOperation,
        Self::PrepareFileOperation,
        Self::ClaimFileOperation,
        Self::CompleteFileContainer,
        Self::CompleteFileOperation,
        Self::PrepareFilesystemOperation,
        Self::ClaimFilesystemOperation,
        Self::CompleteFilesystemContainer,
        Self::CompleteFilesystemOperation,
        Self::PrepareCheckpointOperation,
        Self::ClaimCheckpointOperation,
        Self::CompleteCheckpointContainer,
        Self::CompleteCheckpointOperation,
        Self::PrepareRestoreOperation,
        Self::StoreRestoreConfig,
        Self::StoreRestoringContainer,
        Self::ClaimRestoreOperation,
        Self::CompleteRestoreContainer,
        Self::CompleteRestoreOperation,
        Self::CacheInitWait,
        Self::CacheProcessWait,
        Self::AdvanceEventSequence,
        Self::ClaimRuntimeEvent,
        Self::StoreRuntimeEvent,
        Self::RecordCreateFailure,
        Self::MoveFailedCreateTombstone,
        Self::ReleaseFailedStartClaim,
        Self::RecordStartFailure,
        Self::ReleaseFailedKillClaim,
        Self::RecordKillFailure,
        Self::ReleaseFailedPauseClaim,
        Self::RecordPauseFailure,
        Self::ReleaseFailedResumeClaim,
        Self::RecordResumeFailure,
        Self::ReleaseFailedUpdateClaim,
        Self::RecordUpdateFailure,
        Self::ReleaseFailedDeleteClaim,
        Self::RecordDeleteFailure,
        Self::ReleaseFailedExecClaim,
        Self::RecordExecFailure,
        Self::ReleaseFailedSignalProcessClaim,
        Self::RecordSignalProcessFailure,
        Self::ReleaseFailedWriteStdinClaim,
        Self::RecordWriteStdinFailure,
        Self::ReleaseFailedCloseStdinClaim,
        Self::RecordCloseStdinFailure,
        Self::ReleaseFailedResizeClaim,
        Self::RecordResizeFailure,
        Self::ReleaseFailedFileClaim,
        Self::RecordFileFailure,
        Self::ReleaseFailedFilesystemClaim,
        Self::RecordFilesystemFailure,
        Self::ReleaseFailedCheckpointClaim,
        Self::RecordCheckpointFailure,
        Self::RecordRestoreFailure,
        Self::MoveFailedRestoreTombstone,
        Self::ObserveContainer,
        Self::CompleteObservedOperation,
    ];

    #[must_use]
    pub(crate) const fn is_directory_move(self) -> bool {
        matches!(
            self,
            Self::MoveDeleteTombstone
                | Self::MoveFailedCreateTombstone
                | Self::MoveFailedRestoreTombstone
        )
    }
}

/// Crash boundary within one atomic file replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FileCommitStage {
    TemporaryFileCreated,
    TemporaryFileProtected,
    DataWritten,
    DataFlushed,
    FileSynced,
    FileReplaced,
    ParentDirectorySynced,
}

impl FileCommitStage {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [
        Self::TemporaryFileCreated,
        Self::TemporaryFileProtected,
        Self::DataWritten,
        Self::DataFlushed,
        Self::FileSynced,
        Self::FileReplaced,
        Self::ParentDirectorySynced,
    ];
}

/// Crash boundary within one atomic directory move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DirectoryCommitStage {
    DirectoryMoved,
    SourceParentSynced,
    DestinationParentSynced,
}

impl DirectoryCommitStage {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 3] = [
        Self::DirectoryMoved,
        Self::SourceParentSynced,
        Self::DestinationParentSynced,
    ];
}

/// Runtime driver method crossed by host orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DriverOperation {
    Capability,
    Recover,
    Create,
    State,
    Start,
    Kill,
    Delete,
    Wait,
    Exec,
    SignalProcess,
    WaitProcess,
    Pause,
    Resume,
    Processes,
    Update,
    Stats,
    ReadOutput,
    WriteStdin,
    CloseStdin,
    Resize,
    File,
    Filesystem,
    Checkpoint,
    RestoreValidation,
    Restore,
}

impl DriverOperation {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 25] = [
        Self::Capability,
        Self::Recover,
        Self::Create,
        Self::State,
        Self::Start,
        Self::Kill,
        Self::Delete,
        Self::Wait,
        Self::Exec,
        Self::SignalProcess,
        Self::WaitProcess,
        Self::Pause,
        Self::Resume,
        Self::Processes,
        Self::Update,
        Self::Stats,
        Self::ReadOutput,
        Self::WriteStdin,
        Self::CloseStdin,
        Self::Resize,
        Self::File,
        Self::Filesystem,
        Self::Checkpoint,
        Self::RestoreValidation,
        Self::Restore,
    ];
}

/// Side of one host/driver call boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DriverBoundaryStage {
    BeforeCall,
    AfterCall,
}

impl DriverBoundaryStage {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 2] = [Self::BeforeCall, Self::AfterCall];
}

/// Typed, enumerable fault identity used by deterministic recovery tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FaultPoint {
    DurableFile {
        mutation: DurableMutation,
        stage: FileCommitStage,
    },
    DurableDirectory {
        mutation: DurableMutation,
        stage: DirectoryCommitStage,
    },
    DriverBoundary {
        operation: DriverOperation,
        stage: DriverBoundaryStage,
    },
}

impl fmt::Display for FaultPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[cfg(test)]
impl FaultPoint {
    pub(crate) fn durable_registry() -> Vec<Self> {
        DurableMutation::ALL
            .into_iter()
            .flat_map(|mutation| {
                if mutation.is_directory_move() {
                    DirectoryCommitStage::ALL
                        .into_iter()
                        .map(move |stage| Self::DurableDirectory { mutation, stage })
                        .collect::<Vec<_>>()
                } else {
                    FileCommitStage::ALL
                        .into_iter()
                        .map(move |stage| Self::DurableFile { mutation, stage })
                        .collect::<Vec<_>>()
                }
            })
            .collect()
    }

    pub(crate) fn driver_registry() -> Vec<Self> {
        DriverOperation::ALL
            .into_iter()
            .flat_map(|operation| {
                DriverBoundaryStage::ALL
                    .into_iter()
                    .map(move |stage| Self::DriverBoundary { operation, stage })
            })
            .collect()
    }
}

/// Synchronous checkpoint called immediately after durable commit stages and
/// immediately before or after host/driver calls.
pub(crate) trait FaultInjector: fmt::Debug + Send + Sync {
    fn check(&self, point: FaultPoint) -> Result<()>;
}

#[derive(Debug, Default)]
pub(crate) struct NoFaultInjector;

impl FaultInjector for NoFaultInjector {
    fn check(&self, _point: FaultPoint) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use a3s_oci_sdk::{Error, ErrorCode, Result};

    use super::{FaultInjector, FaultPoint};

    #[derive(Debug)]
    pub(crate) struct RecordingFaultInjector {
        target: FaultPoint,
        fired: AtomicBool,
        events: Mutex<Vec<FaultPoint>>,
    }

    impl RecordingFaultInjector {
        pub(crate) fn fail_once(target: FaultPoint) -> Self {
            Self {
                target,
                fired: AtomicBool::new(false),
                events: Mutex::new(Vec::new()),
            }
        }

        pub(crate) fn fired(&self) -> bool {
            self.fired.load(Ordering::SeqCst)
        }

        pub(crate) fn events(&self) -> Vec<FaultPoint> {
            self.events.lock().expect("fault event lock").clone()
        }
    }

    impl FaultInjector for RecordingFaultInjector {
        fn check(&self, point: FaultPoint) -> Result<()> {
            self.events.lock().expect("fault event lock").push(point);
            if self.target == point && !self.fired.swap(true, Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    format!("injected fault at {point}"),
                )
                .for_operation("fault-injection")
                .retryable(true));
            }
            Ok(())
        }
    }
}
