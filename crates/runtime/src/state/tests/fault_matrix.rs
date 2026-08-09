use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a3s_oci_sdk::ContainerRecord;

mod process;
mod process_io;

use super::*;
use crate::driver::DriverState;
use crate::fault::testing::RecordingFaultInjector;
use crate::fault::{DurableMutation, FaultInjector, FaultPoint, FileCommitStage};
use crate::state::model::{StoredContainer, StoredGeneration};
use crate::state::oci_state::{rebuild_paused_state, rebuild_state};
use crate::state::DeletePreparation;
use process::{
    exercise_exec_claim_recovery, exercise_exec_failure, exercise_exec_reconcile,
    exercise_process_success, exercise_signal_process_failure,
};
use process_io::{exercise_process_io_failure, exercise_process_io_success};

#[derive(Debug, Clone, Copy)]
enum Scenario {
    RuntimeRoot,
    SuccessfulLifecycle,
    CreateClaimRecovery,
    StartRecovery,
    KillRecovery,
    FreezerSuccess,
    PauseRecovery,
    ResumeRecovery,
    DeleteRecovery,
    CreateFailure,
    StartFailure,
    KillFailure,
    PauseFailure,
    ResumeFailure,
    UpdateSuccess,
    UpdateFailure,
    DeleteFailure,
    Observation,
    ProcessSuccess,
    ExecClaimRecovery,
    ExecReconcile,
    ExecFailure,
    SignalProcessFailure,
    ProcessIoSuccess,
    ProcessIoFailure,
}

struct Fixture {
    _temporary: TempDir,
    root: PathBuf,
    bundle: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = state_root(&temporary);
        let bundle = temporary.path().join("bundle");
        fs::create_dir(&bundle).expect("bundle directory");
        Self {
            _temporary: temporary,
            root,
            bundle,
        }
    }

    fn create(&self, operation: &str) -> CreateRequest {
        create_request(&self.bundle, "fault-container", operation)
    }
}

#[tokio::test]
async fn every_registered_durable_commit_stage_recovers_after_reopen() {
    let registry = FaultPoint::durable_registry();
    assert_eq!(
        registry.len(),
        657,
        "update the durable fault contract when the registry changes"
    );
    for point in registry {
        let mutation = match point {
            FaultPoint::DurableFile { mutation, .. }
            | FaultPoint::DurableDirectory { mutation, .. } => mutation,
            FaultPoint::DriverBoundary { .. } => {
                panic!("durable registry contained driver point {point}")
            }
        };
        exercise(scenario_for(mutation), point).await;
    }
}

#[tokio::test]
async fn recreated_created_pid_and_create_journal_repair_survive_commit_faults() {
    for mutation in [
        DurableMutation::ObserveContainer,
        DurableMutation::CompleteCreateOperation,
    ] {
        for stage in FileCommitStage::ALL {
            exercise_recreated_created_recovery(FaultPoint::DurableFile { mutation, stage }).await;
        }
    }
}

async fn exercise_recreated_created_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("recreated-created-fault");
    let setup = DurableStateStore::open(&fixture.root)
        .await
        .expect("open recreated-process setup");
    let original = drive_create(&setup, &create)
        .await
        .expect("complete original create");
    let target = ContainerTarget::exact(create.id.clone(), original.generation);
    if matches!(
        point,
        FaultPoint::DurableFile {
            mutation: DurableMutation::CompleteCreateOperation,
            ..
        }
    ) {
        setup
            .observe_recreated_created_process(
                &target,
                DriverState::created(5_252).expect("replacement created state"),
            )
            .await
            .expect("store replacement PID before journal fault");
    }
    drop(setup);

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let injected = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open recreated-process fault store");
    let result = match point {
        FaultPoint::DurableFile {
            mutation: DurableMutation::ObserveContainer,
            ..
        } => injected
            .observe_recreated_created_process(
                &target,
                DriverState::created(5_252).expect("replacement created state"),
            )
            .await
            .map(|_| ()),
        FaultPoint::DurableFile {
            mutation: DurableMutation::CompleteCreateOperation,
            ..
        } => injected
            .prepare_create(&create, DriverKind::LibkrunWhpx)
            .await
            .map(|_| ()),
        _ => unreachable!("recreated-process test uses only selected file faults"),
    };
    let error = result.expect_err("recreated-process checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(injected);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen recreated-process state");
    recovered
        .observe_recreated_created_process(
            &target,
            DriverState::created(5_252).expect("replacement created state"),
        )
        .await
        .unwrap_or_else(|error| panic!("recover replacement PID after {point}: {error}"));
    let replayed = recovered
        .prepare_create(&create, DriverKind::LibkrunWhpx)
        .await
        .unwrap_or_else(|error| panic!("repair Create journal after {point}: {error}"));
    let RecordOperationPreparation::Replayed(replayed) = replayed else {
        panic!("Create journal did not replay after {point}");
    };
    assert_eq!(*replayed.state.pid(), Some(5_252), "{point}");
    assert_consistent_layout(recovered.root());
}

const fn scenario_for(mutation: DurableMutation) -> Scenario {
    match mutation {
        DurableMutation::RuntimeRootMarker => Scenario::RuntimeRoot,
        DurableMutation::ClaimCreateOperation => Scenario::CreateClaimRecovery,
        DurableMutation::ReconcileStartContainer | DurableMutation::ReconcileStartOperation => {
            Scenario::StartRecovery
        }
        DurableMutation::ReconcileKillContainer | DurableMutation::ReconcileKillOperation => {
            Scenario::KillRecovery
        }
        DurableMutation::ReconcilePauseContainer | DurableMutation::ReconcilePauseOperation => {
            Scenario::PauseRecovery
        }
        DurableMutation::ReconcileResumeContainer | DurableMutation::ReconcileResumeOperation => {
            Scenario::ResumeRecovery
        }
        DurableMutation::ReconcileDeleteOperation => Scenario::DeleteRecovery,
        DurableMutation::RecordCreateFailure | DurableMutation::MoveFailedCreateTombstone => {
            Scenario::CreateFailure
        }
        DurableMutation::ReleaseFailedStartClaim | DurableMutation::RecordStartFailure => {
            Scenario::StartFailure
        }
        DurableMutation::ReleaseFailedKillClaim | DurableMutation::RecordKillFailure => {
            Scenario::KillFailure
        }
        DurableMutation::ReleaseFailedPauseClaim | DurableMutation::RecordPauseFailure => {
            Scenario::PauseFailure
        }
        DurableMutation::ReleaseFailedResumeClaim | DurableMutation::RecordResumeFailure => {
            Scenario::ResumeFailure
        }
        DurableMutation::ReleaseFailedUpdateClaim | DurableMutation::RecordUpdateFailure => {
            Scenario::UpdateFailure
        }
        DurableMutation::ReleaseFailedDeleteClaim | DurableMutation::RecordDeleteFailure => {
            Scenario::DeleteFailure
        }
        DurableMutation::ObserveContainer | DurableMutation::CompleteObservedOperation => {
            Scenario::Observation
        }
        DurableMutation::PrepareExecOperation
        | DurableMutation::StoreExecutingProcess
        | DurableMutation::CompleteExecProcess
        | DurableMutation::CompleteExecOperation
        | DurableMutation::PrepareSignalProcessOperation
        | DurableMutation::ClaimSignalProcessOperation
        | DurableMutation::CompleteSignalProcessRecord
        | DurableMutation::CompleteSignalProcessOperation
        | DurableMutation::CacheInitWait
        | DurableMutation::CacheProcessWait => Scenario::ProcessSuccess,
        DurableMutation::ClaimExecOperation => Scenario::ExecClaimRecovery,
        DurableMutation::ReconcileExecProcess | DurableMutation::ReconcileExecOperation => {
            Scenario::ExecReconcile
        }
        DurableMutation::ReleaseFailedExecClaim | DurableMutation::RecordExecFailure => {
            Scenario::ExecFailure
        }
        DurableMutation::ReleaseFailedSignalProcessClaim
        | DurableMutation::RecordSignalProcessFailure => Scenario::SignalProcessFailure,
        DurableMutation::PrepareWriteStdinOperation
        | DurableMutation::ClaimWriteStdinOperation
        | DurableMutation::CompleteWriteStdinRecord
        | DurableMutation::CompleteWriteStdinOperation
        | DurableMutation::PrepareCloseStdinOperation
        | DurableMutation::ClaimCloseStdinOperation
        | DurableMutation::CompleteCloseStdinRecord
        | DurableMutation::CompleteCloseStdinOperation
        | DurableMutation::PrepareResizeOperation
        | DurableMutation::ClaimResizeOperation
        | DurableMutation::CompleteResizeRecord
        | DurableMutation::CompleteResizeOperation => Scenario::ProcessIoSuccess,
        DurableMutation::ReleaseFailedWriteStdinClaim
        | DurableMutation::RecordWriteStdinFailure
        | DurableMutation::ReleaseFailedCloseStdinClaim
        | DurableMutation::RecordCloseStdinFailure
        | DurableMutation::ReleaseFailedResizeClaim
        | DurableMutation::RecordResizeFailure => Scenario::ProcessIoFailure,
        DurableMutation::AllocateGeneration
        | DurableMutation::AdvanceEventSequence
        | DurableMutation::ClaimRuntimeEvent
        | DurableMutation::StoreRuntimeEvent
        | DurableMutation::PrepareCreateOperation
        | DurableMutation::StoreCreateConfig
        | DurableMutation::StoreCreatingContainer
        | DurableMutation::CompleteCreateContainer
        | DurableMutation::CompleteCreateOperation
        | DurableMutation::PrepareStartOperation
        | DurableMutation::ClaimStartOperation
        | DurableMutation::CompleteStartContainer
        | DurableMutation::CompleteStartOperation
        | DurableMutation::PrepareKillOperation
        | DurableMutation::ClaimKillOperation
        | DurableMutation::CompleteKillContainer
        | DurableMutation::CompleteKillOperation
        | DurableMutation::PreparePauseOperation
        | DurableMutation::ClaimPauseOperation
        | DurableMutation::CompletePauseContainer
        | DurableMutation::CompletePauseOperation
        | DurableMutation::PrepareResumeOperation
        | DurableMutation::ClaimResumeOperation
        | DurableMutation::CompleteResumeContainer
        | DurableMutation::CompleteResumeOperation
        | DurableMutation::PrepareUpdateOperation
        | DurableMutation::ClaimUpdateOperation
        | DurableMutation::CompleteUpdateContainer
        | DurableMutation::CompleteUpdateOperation
        | DurableMutation::PrepareDeleteOperation
        | DurableMutation::ClaimDeleteOperation
        | DurableMutation::MoveDeleteTombstone
        | DurableMutation::CompleteDeleteOperation => {
            if matches!(
                mutation,
                DurableMutation::PreparePauseOperation
                    | DurableMutation::ClaimPauseOperation
                    | DurableMutation::CompletePauseContainer
                    | DurableMutation::CompletePauseOperation
                    | DurableMutation::PrepareResumeOperation
                    | DurableMutation::ClaimResumeOperation
                    | DurableMutation::CompleteResumeContainer
                    | DurableMutation::CompleteResumeOperation
            ) {
                Scenario::FreezerSuccess
            } else if matches!(
                mutation,
                DurableMutation::PrepareUpdateOperation
                    | DurableMutation::ClaimUpdateOperation
                    | DurableMutation::CompleteUpdateContainer
                    | DurableMutation::CompleteUpdateOperation
            ) {
                Scenario::UpdateSuccess
            } else {
                Scenario::SuccessfulLifecycle
            }
        }
    }
}

async fn exercise(scenario: Scenario, point: FaultPoint) {
    match scenario {
        Scenario::RuntimeRoot => exercise_runtime_root(point).await,
        Scenario::SuccessfulLifecycle => exercise_successful_lifecycle(point).await,
        Scenario::CreateClaimRecovery => exercise_create_claim_recovery(point).await,
        Scenario::StartRecovery => exercise_start_recovery(point).await,
        Scenario::KillRecovery => exercise_kill_recovery(point).await,
        Scenario::FreezerSuccess => exercise_freezer_success(point).await,
        Scenario::PauseRecovery => exercise_pause_recovery(point).await,
        Scenario::ResumeRecovery => exercise_resume_recovery(point).await,
        Scenario::DeleteRecovery => exercise_delete_recovery(point).await,
        Scenario::CreateFailure => exercise_create_failure(point).await,
        Scenario::StartFailure => exercise_start_failure(point).await,
        Scenario::KillFailure => exercise_kill_failure(point).await,
        Scenario::PauseFailure => exercise_pause_failure(point).await,
        Scenario::ResumeFailure => exercise_resume_failure(point).await,
        Scenario::UpdateSuccess => exercise_update_success(point).await,
        Scenario::UpdateFailure => exercise_update_failure(point).await,
        Scenario::DeleteFailure => exercise_delete_failure(point).await,
        Scenario::Observation => exercise_observation(point).await,
        Scenario::ProcessSuccess => exercise_process_success(point).await,
        Scenario::ExecClaimRecovery => exercise_exec_claim_recovery(point).await,
        Scenario::ExecReconcile => exercise_exec_reconcile(point).await,
        Scenario::ExecFailure => exercise_exec_failure(point).await,
        Scenario::SignalProcessFailure => exercise_signal_process_failure(point).await,
        Scenario::ProcessIoSuccess => exercise_process_io_success(point).await,
        Scenario::ProcessIoFailure => exercise_process_io_failure(point).await,
    }
}

async fn exercise_runtime_root(point: FaultPoint) {
    let fixture = Fixture::new();
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let error = open_injected(&fixture.root, injector.clone())
        .await
        .expect_err("root marker checkpoint must inject");
    assert_injected(&error, point, &injector);

    let store = DurableStateStore::open(&fixture.root)
        .await
        .unwrap_or_else(|error| panic!("recover root marker after {point}: {error}"));
    assert!(store.root().join("root.json").is_file(), "{point}");
    assert_consistent_layout(store.root());
}

async fn exercise_successful_lifecycle(point: FaultPoint) {
    let fixture = Fixture::new();
    initialize_root(&fixture.root).await;
    let create = fixture.create("matrix-create");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open injected lifecycle store");
    let error = drive_successful_lifecycle(&store, &create)
        .await
        .expect_err("selected lifecycle checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .unwrap_or_else(|error| panic!("reopen after {point}: {error}"));
    let generation = drive_successful_lifecycle(&recovered, &create)
        .await
        .unwrap_or_else(|error| panic!("recover lifecycle after {point}: {error}"));
    assert!(generation.0 > 0, "{point}");
    assert_eq!(
        drive_successful_lifecycle(&recovered, &create)
            .await
            .expect("replay recovered lifecycle"),
        generation,
        "{point}"
    );
    let durable_generation: StoredGeneration = serde_json::from_slice(
        &fs::read(
            recovered
                .root()
                .join("generations")
                .join(format!("{}.json", create.id.as_str())),
        )
        .expect("read generation record"),
    )
    .expect("decode generation record");
    assert_eq!(durable_generation.last_generation, generation, "{point}");
    let missing = recovered
        .state(&ContainerTarget::current(create.id))
        .await
        .expect_err("recovered lifecycle must finish delete");
    assert_eq!(missing.code, ErrorCode::NotFound, "{point}");
    assert_consistent_layout(recovered.root());
}

async fn exercise_create_claim_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    initialize_root(&fixture.root).await;
    let create = fixture.create("claim-create");
    prepare_created_record_without_outcome(&fixture.root, &create).await;

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open create-claim recovery");
    let error = drive_create(&store, &create)
        .await
        .expect_err("create claim checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen create-claim recovery");
    let record = drive_create(&recovered, &create)
        .await
        .unwrap_or_else(|error| panic!("recover create claim after {point}: {error}"));
    assert_eq!(*record.state.status(), ContainerState::Created, "{point}");
    assert_consistent_layout(recovered.root());
}

async fn exercise_start_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("start-recovery-create");
    let (target, start) = prepare_split_start_state(&fixture.root, &create).await;
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open start recovery");
    let error = store
        .prepare_start(&start)
        .await
        .expect_err("start recovery checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen start recovery");
    let replayed = recovered
        .prepare_start(&start)
        .await
        .unwrap_or_else(|error| panic!("recover start after {point}: {error}"));
    assert!(matches!(replayed, RecordOperationPreparation::Replayed(_)));
    assert_eq!(
        *recovered
            .state(&target)
            .await
            .expect("running state")
            .state
            .status(),
        ContainerState::Running
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_kill_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("kill-recovery-create");
    let (target, kill) = prepare_split_kill_state(&fixture.root, &create).await;
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open kill recovery");
    let error = store
        .prepare_kill(&kill)
        .await
        .expect_err("kill recovery checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen kill recovery");
    let replayed = recovered
        .prepare_kill(&kill)
        .await
        .unwrap_or_else(|error| panic!("recover kill after {point}: {error}"));
    assert!(matches!(replayed, RecordOperationPreparation::Replayed(_)));
    assert_eq!(
        *recovered
            .state(&target)
            .await
            .expect("stopped state")
            .state
            .status(),
        ContainerState::Stopped
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_freezer_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("freezer-success-create");
    let target = prepare_running_for_freezer(&fixture.root, &create).await;
    let pause = ContainerOperationRequest {
        context: OperationContext::new(operation_id("matrix-pause")),
        target: target.clone(),
    };
    let resume = ContainerOperationRequest {
        context: OperationContext::new(operation_id("matrix-resume")),
        target,
    };
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open freezer lifecycle store");
    let error = drive_freezer_lifecycle(&store, &pause, &resume)
        .await
        .expect_err("selected freezer checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen freezer lifecycle");
    let running = drive_freezer_lifecycle(&recovered, &pause, &resume)
        .await
        .unwrap_or_else(|error| panic!("recover freezer lifecycle after {point}: {error}"));
    assert!(!running.is_paused(), "{point}");
    assert_eq!(
        drive_freezer_lifecycle(&recovered, &pause, &resume)
            .await
            .expect("replay recovered freezer lifecycle"),
        running,
        "{point}"
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_update_success(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("update-success-create");
    let target = prepare_running_for_freezer(&fixture.root, &create).await;
    let request = resource_update(target, "matrix-update");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open update lifecycle store");
    let error = drive_update(&store, &request)
        .await
        .expect_err("selected update checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen update lifecycle");
    let running = drive_update(&recovered, &request)
        .await
        .unwrap_or_else(|error| panic!("recover update lifecycle after {point}: {error}"));
    assert_eq!(*running.state.status(), ContainerState::Running, "{point}");
    assert_eq!(
        drive_update(&recovered, &request)
            .await
            .expect("replay recovered update"),
        running,
        "{point}"
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_pause_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("pause-recovery-create");
    let (target, request) = prepare_split_pause_state(&fixture.root, &create).await;
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open pause recovery");
    let error = store
        .prepare_pause(&request)
        .await
        .expect_err("pause recovery checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen pause recovery");
    let replayed = recovered
        .prepare_pause(&request)
        .await
        .unwrap_or_else(|error| panic!("recover pause after {point}: {error}"));
    assert!(matches!(replayed, RecordOperationPreparation::Replayed(_)));
    assert!(
        recovered
            .state(&target)
            .await
            .expect("paused state")
            .is_paused(),
        "{point}"
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_resume_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("resume-recovery-create");
    let (target, request) = prepare_split_resume_state(&fixture.root, &create).await;
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open resume recovery");
    let error = store
        .prepare_resume(&request)
        .await
        .expect_err("resume recovery checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen resume recovery");
    let replayed = recovered
        .prepare_resume(&request)
        .await
        .unwrap_or_else(|error| panic!("recover resume after {point}: {error}"));
    assert!(matches!(replayed, RecordOperationPreparation::Replayed(_)));
    assert!(
        !recovered
            .state(&target)
            .await
            .expect("resumed state")
            .is_paused(),
        "{point}"
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_delete_recovery(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("delete-recovery-create");
    let delete = prepare_moved_delete(&fixture.root, &create).await;
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open delete recovery");
    let error = store
        .prepare_delete(&delete)
        .await
        .expect_err("delete recovery checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen delete recovery");
    assert_eq!(
        recovered
            .prepare_delete(&delete)
            .await
            .unwrap_or_else(|error| panic!("recover delete after {point}: {error}")),
        DeletePreparation::Replayed
    );
    assert_consistent_layout(recovered.root());
}

async fn exercise_create_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    initialize_root(&fixture.root).await;
    let create = fixture.create("failed-create");
    let failure = terminal_failure("create");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open create failure store");
    let error = drive_failed_create(&store, &create, &failure)
        .await
        .expect_err("create failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen create failure");
    drive_failed_create(&recovered, &create, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover create failure after {point}: {error}"));
    assert_consistent_layout(recovered.root());
}

async fn exercise_start_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("start-failure-create");
    let (target, request) = prepare_created_for_start(&fixture.root, &create).await;
    let failure = terminal_failure("start");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open start failure store");
    let error = drive_failed_start(&store, &request, &failure)
        .await
        .expect_err("start failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen start failure");
    drive_failed_start(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover start failure after {point}: {error}"));
    drive_start(
        &recovered,
        &StartRequest {
            context: OperationContext::new(operation_id("start-after-failure")),
            target,
        },
    )
    .await
    .expect("claim released after failed start");
    assert_consistent_layout(recovered.root());
}

async fn exercise_kill_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("kill-failure-create");
    let (target, request) = prepare_running_for_kill(&fixture.root, &create).await;
    let failure = terminal_failure("kill");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open kill failure store");
    let error = drive_failed_kill(&store, &request, &failure)
        .await
        .expect_err("kill failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen kill failure");
    drive_failed_kill(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover kill failure after {point}: {error}"));
    drive_kill(
        &recovered,
        &KillRequest {
            context: OperationContext::new(operation_id("kill-after-failure")),
            target,
            signal: Signal::new(9).expect("signal"),
            all: false,
        },
    )
    .await
    .expect("claim released after failed kill");
    assert_consistent_layout(recovered.root());
}

async fn exercise_pause_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("pause-failure-create");
    let target = prepare_running_for_freezer(&fixture.root, &create).await;
    let request = ContainerOperationRequest {
        context: OperationContext::new(operation_id("failure-pause")),
        target: target.clone(),
    };
    let failure = terminal_failure("pause");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open pause failure store");
    let error = drive_failed_freezer(&store, &request, &failure, true)
        .await
        .expect_err("pause failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen pause failure");
    drive_failed_freezer(&recovered, &request, &failure, true)
        .await
        .unwrap_or_else(|error| panic!("recover pause failure after {point}: {error}"));
    let paused = drive_pause(
        &recovered,
        &ContainerOperationRequest {
            context: OperationContext::new(operation_id("pause-after-failure")),
            target,
        },
    )
    .await
    .expect("claim released after failed pause");
    assert!(paused.is_paused(), "{point}");
    assert_consistent_layout(recovered.root());
}

async fn exercise_resume_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("resume-failure-create");
    let target = prepare_paused_for_resume(&fixture.root, &create).await;
    let request = ContainerOperationRequest {
        context: OperationContext::new(operation_id("failure-resume")),
        target: target.clone(),
    };
    let failure = terminal_failure("resume");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open resume failure store");
    let error = drive_failed_freezer(&store, &request, &failure, false)
        .await
        .expect_err("resume failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen resume failure");
    drive_failed_freezer(&recovered, &request, &failure, false)
        .await
        .unwrap_or_else(|error| panic!("recover resume failure after {point}: {error}"));
    let running = drive_resume(
        &recovered,
        &ContainerOperationRequest {
            context: OperationContext::new(operation_id("resume-after-failure")),
            target,
        },
    )
    .await
    .expect("claim released after failed resume");
    assert!(!running.is_paused(), "{point}");
    assert_consistent_layout(recovered.root());
}

async fn exercise_update_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("update-failure-create");
    let target = prepare_running_for_freezer(&fixture.root, &create).await;
    let request = resource_update(target.clone(), "failure-update");
    let failure = terminal_failure("update");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open update failure store");
    let error = drive_failed_update(&store, &request, &failure)
        .await
        .expect_err("update failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen update failure");
    drive_failed_update(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover update failure after {point}: {error}"));
    drive_update(&recovered, &resource_update(target, "update-after-failure"))
        .await
        .expect("claim released after failed update");
    assert_consistent_layout(recovered.root());
}

async fn exercise_delete_failure(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("delete-failure-create");
    let request = prepare_stopped_for_delete(&fixture.root, &create).await;
    let failure = terminal_failure("delete");
    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open delete failure store");
    let error = drive_failed_delete(&store, &request, &failure)
        .await
        .expect_err("delete failure checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen delete failure");
    drive_failed_delete(&recovered, &request, &failure)
        .await
        .unwrap_or_else(|error| panic!("recover delete failure after {point}: {error}"));
    let delete = DeleteRequest {
        context: OperationContext::new(operation_id("delete-after-failure")),
        target: request.target,
        mode: DeleteMode::StoppedOnly,
    };
    drive_delete(&recovered, &delete)
        .await
        .expect("claim released after failed delete");
    assert_consistent_layout(recovered.root());
}

async fn exercise_observation(point: FaultPoint) {
    let fixture = Fixture::new();
    let create = fixture.create("observation-create");
    let (target, start) = prepare_created_for_start(&fixture.root, &create).await;
    let setup = DurableStateStore::open(&fixture.root)
        .await
        .expect("open observation setup");
    setup.prepare_start(&start).await.expect("prepare start");
    drop(setup);

    let injector = Arc::new(RecordingFaultInjector::fail_once(point));
    let store = open_injected(&fixture.root, injector.clone())
        .await
        .expect("open observation store");
    let error = store
        .observe_state(&target, ContainerState::Running, Some(4_242))
        .await
        .expect_err("observation checkpoint must inject");
    assert_injected(&error, point, &injector);
    drop(store);

    let recovered = DurableStateStore::open(&fixture.root)
        .await
        .expect("reopen observation");
    recovered
        .observe_state(&target, ContainerState::Running, Some(4_242))
        .await
        .unwrap_or_else(|error| panic!("recover observation after {point}: {error}"));
    let replayed = recovered
        .prepare_start(&start)
        .await
        .unwrap_or_else(|error| panic!("complete observed start after {point}: {error}"));
    assert!(matches!(replayed, RecordOperationPreparation::Replayed(_)));
    assert_consistent_layout(recovered.root());
}

async fn open_injected(
    root: &Path,
    injector: Arc<RecordingFaultInjector>,
) -> a3s_oci_sdk::Result<DurableStateStore> {
    let faults: Arc<dyn FaultInjector> = injector;
    DurableStateStore::open_with_fault_injector(root, faults).await
}

async fn initialize_root(root: &Path) {
    drop(
        DurableStateStore::open(root)
            .await
            .expect("initialize state root"),
    );
}

async fn drive_successful_lifecycle(
    store: &DurableStateStore,
    create: &CreateRequest,
) -> a3s_oci_sdk::Result<Generation> {
    let created = drive_create(store, create).await?;
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    drive_start(
        store,
        &StartRequest {
            context: OperationContext::new(operation_id("matrix-start")),
            target: target.clone(),
        },
    )
    .await?;
    drive_kill(
        store,
        &KillRequest {
            context: OperationContext::new(operation_id("matrix-kill")),
            target: target.clone(),
            signal: Signal::new(15).expect("signal"),
            all: true,
        },
    )
    .await?;
    drive_delete(
        store,
        &DeleteRequest {
            context: OperationContext::new(operation_id("matrix-delete")),
            target,
            mode: DeleteMode::StoppedOnly,
        },
    )
    .await?;
    Ok(created.generation)
}

async fn drive_create(
    store: &DurableStateStore,
    request: &CreateRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    match store
        .prepare_create(request, DriverKind::LibkrunWhpx)
        .await?
    {
        RecordOperationPreparation::Prepared(_) | RecordOperationPreparation::Resume(_) => {
            store
                .complete_create(&request.context.operation_id, 4_242)
                .await
        }
        RecordOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_start(
    store: &DurableStateStore,
    request: &StartRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    match store.prepare_start(request).await? {
        RecordOperationPreparation::Prepared(_) | RecordOperationPreparation::Resume(_) => {
            store
                .complete_start(
                    &request.context.operation_id,
                    ContainerState::Running,
                    Some(4_242),
                )
                .await
        }
        RecordOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_freezer_lifecycle(
    store: &DurableStateStore,
    pause: &ContainerOperationRequest,
    resume: &ContainerOperationRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    let paused = drive_pause(store, pause).await?;
    assert!(paused.is_paused());
    let running = drive_resume(store, resume).await?;
    assert!(!running.is_paused());
    Ok(running)
}

async fn drive_pause(
    store: &DurableStateStore,
    request: &ContainerOperationRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    match store.prepare_pause(request).await? {
        RecordOperationPreparation::Prepared(_) | RecordOperationPreparation::Resume(_) => {
            store
                .complete_pause(
                    &request.context.operation_id,
                    ContainerState::Running,
                    Some(4_242),
                    true,
                )
                .await
        }
        RecordOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_resume(
    store: &DurableStateStore,
    request: &ContainerOperationRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    match store.prepare_resume(request).await? {
        RecordOperationPreparation::Prepared(_) | RecordOperationPreparation::Resume(_) => {
            store
                .complete_resume(
                    &request.context.operation_id,
                    ContainerState::Running,
                    Some(4_242),
                    false,
                )
                .await
        }
        RecordOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_update(
    store: &DurableStateStore,
    request: &UpdateRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    match store.prepare_update(request).await? {
        RecordOperationPreparation::Prepared(_) | RecordOperationPreparation::Resume(_) => {
            store
                .complete_update(
                    &request.context.operation_id,
                    ContainerState::Running,
                    Some(4_242),
                    false,
                )
                .await
        }
        RecordOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_kill(
    store: &DurableStateStore,
    request: &KillRequest,
) -> a3s_oci_sdk::Result<ContainerRecord> {
    match store.prepare_kill(request).await? {
        RecordOperationPreparation::Prepared(_) | RecordOperationPreparation::Resume(_) => {
            store
                .complete_kill(&request.context.operation_id, ContainerState::Stopped, None)
                .await
        }
        RecordOperationPreparation::Replayed(record) => Ok(record),
    }
}

async fn drive_delete(
    store: &DurableStateStore,
    request: &DeleteRequest,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_delete(request).await? {
        DeletePreparation::Prepared(_) | DeletePreparation::Resume(_) => {
            store.complete_delete(&request.context.operation_id).await
        }
        DeletePreparation::Replayed => Ok(()),
    }
}

async fn drive_failed_create(
    store: &DurableStateStore,
    request: &CreateRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_create(request, DriverKind::LibkrunWhpx).await {
        Ok(RecordOperationPreparation::Prepared(_)) | Ok(RecordOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(RecordOperationPreparation::Replayed(_)) => {
            panic!("failed create unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(
        store.prepare_create(request, DriverKind::LibkrunWhpx).await,
        failure,
    )
}

async fn drive_failed_start(
    store: &DurableStateStore,
    request: &StartRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_start(request).await {
        Ok(RecordOperationPreparation::Prepared(_)) | Ok(RecordOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(RecordOperationPreparation::Replayed(_)) => {
            panic!("failed start unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_start(request).await, failure)
}

async fn drive_failed_kill(
    store: &DurableStateStore,
    request: &KillRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_kill(request).await {
        Ok(RecordOperationPreparation::Prepared(_)) | Ok(RecordOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(RecordOperationPreparation::Replayed(_)) => {
            panic!("failed kill unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_kill(request).await, failure)
}

async fn drive_failed_freezer(
    store: &DurableStateStore,
    request: &ContainerOperationRequest,
    failure: &Error,
    pause: bool,
) -> a3s_oci_sdk::Result<()> {
    let prepared = if pause {
        store.prepare_pause(request).await
    } else {
        store.prepare_resume(request).await
    };
    match prepared {
        Ok(RecordOperationPreparation::Prepared(_)) | Ok(RecordOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(RecordOperationPreparation::Replayed(_)) => {
            panic!("failed freezer operation unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    let replayed = if pause {
        store.prepare_pause(request).await
    } else {
        store.prepare_resume(request).await
    };
    expect_failure(replayed, failure)
}

async fn drive_failed_update(
    store: &DurableStateStore,
    request: &UpdateRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_update(request).await {
        Ok(RecordOperationPreparation::Prepared(_)) | Ok(RecordOperationPreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(RecordOperationPreparation::Replayed(_)) => {
            panic!("failed update unexpectedly replayed success")
        }
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_update(request).await, failure)
}

async fn drive_failed_delete(
    store: &DurableStateStore,
    request: &DeleteRequest,
    failure: &Error,
) -> a3s_oci_sdk::Result<()> {
    match store.prepare_delete(request).await {
        Ok(DeletePreparation::Prepared(_)) | Ok(DeletePreparation::Resume(_)) => {
            store
                .fail_operation(&request.context.operation_id, failure)
                .await?;
        }
        Ok(DeletePreparation::Replayed) => panic!("failed delete unexpectedly replayed success"),
        Err(error) if error == *failure => return Ok(()),
        Err(error) => return Err(error),
    }
    expect_failure(store.prepare_delete(request).await, failure)
}

fn expect_failure<T>(result: a3s_oci_sdk::Result<T>, expected: &Error) -> a3s_oci_sdk::Result<()> {
    match result {
        Err(error) if error == *expected => Ok(()),
        Err(error) => Err(error),
        Ok(_) => panic!("terminal operation unexpectedly succeeded"),
    }
}

fn terminal_failure(operation: &'static str) -> Error {
    Error::new(
        ErrorCode::FailedPrecondition,
        format!("injected terminal {operation} failure"),
    )
    .for_operation(operation)
}

fn resource_update(target: ContainerTarget, operation: &str) -> UpdateRequest {
    let resources: LinuxResources = serde_json::from_value(serde_json::json!({
        "memory": {"limit": 4096},
        "cpu": {"shares": 1024},
        "pids": {"limit": 16}
    }))
    .expect("valid resource update");
    UpdateRequest {
        context: OperationContext::new(operation_id(operation)),
        target,
        resources,
    }
}

async fn prepare_created_for_start(
    root: &Path,
    create: &CreateRequest,
) -> (ContainerTarget, StartRequest) {
    let store = DurableStateStore::open(root)
        .await
        .expect("open create setup");
    let created = drive_create(&store, create)
        .await
        .expect("create setup container");
    let target = ContainerTarget::exact(create.id.clone(), created.generation);
    let request = StartRequest {
        context: OperationContext::new(operation_id("failure-start")),
        target: target.clone(),
    };
    drop(store);
    (target, request)
}

async fn prepare_running_for_kill(
    root: &Path,
    create: &CreateRequest,
) -> (ContainerTarget, KillRequest) {
    let target = prepare_running_for_freezer(root, create).await;
    let request = KillRequest {
        context: OperationContext::new(operation_id("failure-kill")),
        target: target.clone(),
        signal: Signal::new(15).expect("signal"),
        all: false,
    };
    (target, request)
}

async fn prepare_running_for_freezer(root: &Path, create: &CreateRequest) -> ContainerTarget {
    let (target, start) = prepare_created_for_start(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open start setup");
    drive_start(&store, &start)
        .await
        .expect("start setup container");
    drop(store);
    target
}

async fn prepare_paused_for_resume(root: &Path, create: &CreateRequest) -> ContainerTarget {
    let target = prepare_running_for_freezer(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open pause setup");
    drive_pause(
        &store,
        &ContainerOperationRequest {
            context: OperationContext::new(operation_id("setup-pause")),
            target: target.clone(),
        },
    )
    .await
    .expect("pause setup container");
    drop(store);
    target
}

async fn prepare_stopped_for_delete(root: &Path, create: &CreateRequest) -> DeleteRequest {
    let (target, kill) = prepare_running_for_kill(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open kill setup");
    drive_kill(&store, &kill)
        .await
        .expect("stop setup container");
    drop(store);
    DeleteRequest {
        context: OperationContext::new(operation_id("failure-delete")),
        target,
        mode: DeleteMode::StoppedOnly,
    }
}

async fn prepare_created_record_without_outcome(root: &Path, create: &CreateRequest) {
    let setup_point = FaultPoint::DurableFile {
        mutation: DurableMutation::CompleteCreateOperation,
        stage: FileCommitStage::TemporaryFileCreated,
    };
    let injector = Arc::new(RecordingFaultInjector::fail_once(setup_point));
    let store = open_injected(root, injector.clone())
        .await
        .expect("open create-claim setup");
    let error = drive_create(&store, create)
        .await
        .expect_err("interrupt create outcome");
    assert_injected(&error, setup_point, &injector);
}

async fn prepare_split_start_state(
    root: &Path,
    create: &CreateRequest,
) -> (ContainerTarget, StartRequest) {
    let (target, start) = prepare_created_for_start(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open split-start setup");
    store
        .prepare_start(&start)
        .await
        .expect("prepare split start");
    write_split_container_state(
        store.root(),
        &create.id,
        ContainerState::Running,
        Some(4_242),
    );
    drop(store);
    (target, start)
}

async fn prepare_split_kill_state(
    root: &Path,
    create: &CreateRequest,
) -> (ContainerTarget, KillRequest) {
    let (target, kill) = prepare_running_for_kill(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open split-kill setup");
    store.prepare_kill(&kill).await.expect("prepare split kill");
    write_split_container_state(store.root(), &create.id, ContainerState::Stopped, None);
    drop(store);
    (target, kill)
}

async fn prepare_split_pause_state(
    root: &Path,
    create: &CreateRequest,
) -> (ContainerTarget, ContainerOperationRequest) {
    let target = prepare_running_for_freezer(root, create).await;
    let request = ContainerOperationRequest {
        context: OperationContext::new(operation_id("recovery-pause")),
        target: target.clone(),
    };
    let store = DurableStateStore::open(root)
        .await
        .expect("open split-pause setup");
    store
        .prepare_pause(&request)
        .await
        .expect("prepare split pause");
    write_split_freezer_state(store.root(), &create.id, true);
    drop(store);
    (target, request)
}

async fn prepare_split_resume_state(
    root: &Path,
    create: &CreateRequest,
) -> (ContainerTarget, ContainerOperationRequest) {
    let target = prepare_paused_for_resume(root, create).await;
    let request = ContainerOperationRequest {
        context: OperationContext::new(operation_id("recovery-resume")),
        target: target.clone(),
    };
    let store = DurableStateStore::open(root)
        .await
        .expect("open split-resume setup");
    store
        .prepare_resume(&request)
        .await
        .expect("prepare split resume");
    write_split_freezer_state(store.root(), &create.id, false);
    drop(store);
    (target, request)
}

async fn prepare_moved_delete(root: &Path, create: &CreateRequest) -> DeleteRequest {
    let delete = prepare_stopped_for_delete(root, create).await;
    let store = DurableStateStore::open(root)
        .await
        .expect("open moved-delete setup");
    store
        .prepare_delete(&delete)
        .await
        .expect("prepare moved delete");
    fs::rename(
        store.root().join("containers").join(create.id.as_str()),
        store
            .root()
            .join("quarantine")
            .join(format!("{}.deleted", delete.context.operation_id.as_str())),
    )
    .expect("move delete tombstone");
    drop(store);
    delete
}

fn write_split_container_state(
    root: &Path,
    id: &ContainerId,
    status: ContainerState,
    pid: Option<i32>,
) {
    let path = root
        .join("containers")
        .join(id.as_str())
        .join("record.json");
    let mut stored: StoredContainer =
        serde_json::from_slice(&fs::read(&path).expect("read container record"))
            .expect("decode container record");
    stored.record.state =
        rebuild_state(&stored.record.state, status, pid).expect("rebuild split state");
    let mut bytes = serde_json::to_vec_pretty(&stored).expect("encode split state");
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("open split state");
    file.write_all(&bytes).expect("write split state");
    file.sync_all().expect("sync split state");
}

fn write_split_freezer_state(root: &Path, id: &ContainerId, paused: bool) {
    let path = root
        .join("containers")
        .join(id.as_str())
        .join("record.json");
    let mut stored: StoredContainer =
        serde_json::from_slice(&fs::read(&path).expect("read container record"))
            .expect("decode container record");
    stored.record.state =
        rebuild_paused_state(&stored.record.state, paused).expect("rebuild split freezer state");
    let mut bytes = serde_json::to_vec_pretty(&stored).expect("encode split freezer state");
    bytes.push(b'\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("open split freezer state");
    file.write_all(&bytes).expect("write split freezer state");
    file.sync_all().expect("sync split freezer state");
}

fn assert_injected(error: &Error, point: FaultPoint, injector: &RecordingFaultInjector) {
    assert_eq!(error.code, ErrorCode::Unavailable, "{point}");
    assert_eq!(
        error.operation.as_deref(),
        Some("fault-injection"),
        "{point}"
    );
    assert!(error.retryable, "{point}");
    assert!(error.message.contains(&point.to_string()), "{point}");
    assert!(injector.fired(), "fault point was not reached: {point}");
    assert!(injector.events().contains(&point), "{point}");
}

fn assert_consistent_layout(root: &Path) {
    for directory in [
        "containers",
        "generations",
        "operations",
        "quarantine",
        "events",
    ] {
        assert!(root.join(directory).is_dir(), "missing {directory}");
    }
    for directory in ["records", "keys"] {
        assert!(
            root.join("events").join(directory).is_dir(),
            "missing events/{directory}"
        );
    }
    assert_no_transaction_files(root);

    let containers = root.join("containers");
    let quarantine = root.join("quarantine");
    for entry in fs::read_dir(&quarantine).expect("inspect quarantine") {
        let entry = entry.expect("quarantine entry");
        if !entry.path().is_dir() {
            continue;
        }
        let record_path = entry.path().join("record.json");
        if !record_path.exists() {
            continue;
        }
        let quarantined: StoredContainer =
            serde_json::from_slice(&fs::read(record_path).expect("read quarantine record"))
                .expect("decode quarantine record");
        let live_path = containers.join(quarantined.id.as_str()).join("record.json");
        if live_path.exists() {
            let live: StoredContainer =
                serde_json::from_slice(&fs::read(live_path).expect("read live record"))
                    .expect("decode live record");
            assert_ne!(
                live.record.generation, quarantined.record.generation,
                "one generation cannot be both live and quarantined"
            );
        }
    }
}

fn assert_no_transaction_files(root: &Path) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("inspect state directory") {
            let entry = entry.expect("state directory entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    !entry.file_name().to_string_lossy().ends_with(".next"),
                    "stale transaction file after recovery: {}",
                    path.display()
                );
            }
        }
    }
}
