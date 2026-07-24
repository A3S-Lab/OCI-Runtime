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
    PrepareDeleteOperation,
    ClaimDeleteOperation,
    ReconcileDeleteOperation,
    MoveDeleteTombstone,
    CompleteDeleteOperation,
    RecordCreateFailure,
    MoveFailedCreateTombstone,
    ReleaseFailedStartClaim,
    RecordStartFailure,
    ReleaseFailedKillClaim,
    RecordKillFailure,
    ReleaseFailedDeleteClaim,
    RecordDeleteFailure,
    ObserveContainer,
    CompleteObservedOperation,
}

impl DurableMutation {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 35] = [
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
        Self::PrepareDeleteOperation,
        Self::ClaimDeleteOperation,
        Self::ReconcileDeleteOperation,
        Self::MoveDeleteTombstone,
        Self::CompleteDeleteOperation,
        Self::RecordCreateFailure,
        Self::MoveFailedCreateTombstone,
        Self::ReleaseFailedStartClaim,
        Self::RecordStartFailure,
        Self::ReleaseFailedKillClaim,
        Self::RecordKillFailure,
        Self::ReleaseFailedDeleteClaim,
        Self::RecordDeleteFailure,
        Self::ObserveContainer,
        Self::CompleteObservedOperation,
    ];

    #[must_use]
    pub(crate) const fn is_directory_move(self) -> bool {
        matches!(
            self,
            Self::MoveDeleteTombstone | Self::MoveFailedCreateTombstone
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
    Create,
    State,
    Start,
    Kill,
    Delete,
}

impl DriverOperation {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::Capability,
        Self::Create,
        Self::State,
        Self::Start,
        Self::Kill,
        Self::Delete,
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
