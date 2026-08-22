use super::*;
use a3s_oci_sdk::OciSchemaDocument;

#[derive(Debug, Clone)]
struct DriverSchemaProfile {
    name: &'static str,
    driver: DriverKind,
    isolation: IsolationRequest,
    configuration: &'static str,
}

const NATIVE_LINUX_CONFIGURATION: &str =
    include_str!("../../../../../fixtures/native-linux/config.json");
const UTILITY_VM_CONFIGURATION: &str =
    include_str!("../../../../../fixtures/utility-vm/config.json");
const WHPX_CONFIGURATION: &str =
    include_str!("../../../../../fixtures/utility-vm/config.windows.json");

const DRIVER_PROFILES: &[DriverSchemaProfile] = &[
    DriverSchemaProfile {
        name: "native-linux",
        driver: DriverKind::NativeLinux,
        isolation: IsolationRequest::SharedHostKernel,
        configuration: NATIVE_LINUX_CONFIGURATION,
    },
    DriverSchemaProfile {
        name: "linux-kvm",
        driver: DriverKind::LibkrunKvm,
        isolation: IsolationRequest::DedicatedVm,
        configuration: UTILITY_VM_CONFIGURATION,
    },
    DriverSchemaProfile {
        name: "macos-hvf",
        driver: DriverKind::LibkrunHvf,
        isolation: IsolationRequest::DedicatedVm,
        configuration: UTILITY_VM_CONFIGURATION,
    },
    DriverSchemaProfile {
        name: "windows-whpx",
        driver: DriverKind::LibkrunWhpx,
        isolation: IsolationRequest::DedicatedVm,
        configuration: WHPX_CONFIGURATION,
    },
];

#[tokio::test]
async fn every_launch_profile_emits_schema_valid_configuration_state_and_features() {
    let validator = OciSchemaValidator::new().expect("compile pinned schemas");

    for profile in DRIVER_PROFILES {
        exercise_profile_schema(profile, validator).await;
    }
}

async fn exercise_profile_schema(profile: &DriverSchemaProfile, validator: OciSchemaValidator) {
    let configuration: serde_json::Value = serde_json::from_str(profile.configuration)
        .unwrap_or_else(|error| panic!("{} configuration must be JSON: {error}", profile.name));
    validator
        .validate(OciSchemaDocument::Configuration, &configuration)
        .unwrap_or_else(|error| {
            panic!(
                "{} configuration must match the pinned schema: {error}",
                profile.name
            )
        });

    let temporary = tempfile::tempdir().expect("temporary profile directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("profile bundle directory");
    let bundle = OciBundle::from_json(&bundle_directory, profile.configuration)
        .unwrap_or_else(|error| panic!("{} bundle must be valid: {error}", profile.name));

    let mut recording = RecordingDriver::with_control_operations();
    recording.capability.driver = profile.driver;
    recording.capability.readiness = DriverReadiness::Experimental;
    recording.capability.isolation_classes = vec![profile.isolation.class()];
    recording.hooks = OciHookPhase::ALL.to_vec();
    let driver = Arc::new(recording);
    let service = open_service(&temporary, driver).await;

    let info = service
        .features()
        .await
        .unwrap_or_else(|error| panic!("{} features must be emitted: {error}", profile.name));
    let advertised = info
        .drivers
        .driver(profile.driver)
        .unwrap_or_else(|| panic!("{} driver must be advertised", profile.name));
    assert!(
        advertised.can_launch(),
        "{} schema profile must represent a launch-ready driver",
        profile.name
    );
    validator
        .validate_features(&info.oci)
        .unwrap_or_else(|error| {
            panic!(
                "{} features must match the pinned schema: {error}",
                profile.name
            )
        });

    let create = CreateRequest {
        context: OperationContext::new(operation_id(&format!("{}-create", profile.name))),
        id: container_id(&format!("{}-schema", profile.name)),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("profile attachment contract"),
        bundle,
        isolation: profile.isolation.clone(),
    };
    let created = service
        .create(create.clone())
        .await
        .unwrap_or_else(|error| panic!("{} create must succeed: {error}", profile.name));
    assert_eq!(*created.state.status(), ContainerState::Created);
    validate_profile_state(profile.name, validator, &created);

    let target = ContainerTarget::exact(create.id, created.generation);
    let queried = service
        .state(StateRequest {
            target: target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("{} state must succeed: {error}", profile.name));
    assert_eq!(*queried.state.status(), ContainerState::Created);
    validate_profile_state(profile.name, validator, &queried);

    let running = service
        .start(StartRequest {
            context: OperationContext::new(operation_id(&format!("{}-start", profile.name))),
            target: target.clone(),
        })
        .await
        .unwrap_or_else(|error| panic!("{} start must succeed: {error}", profile.name));
    assert_eq!(*running.state.status(), ContainerState::Running);
    validate_profile_state(profile.name, validator, &running);

    let stopped = service
        .kill(KillRequest {
            context: OperationContext::new(operation_id(&format!("{}-kill", profile.name))),
            target: target.clone(),
            signal: Signal::new(15).expect("SIGTERM"),
            all: true,
        })
        .await
        .unwrap_or_else(|error| panic!("{} kill must succeed: {error}", profile.name));
    assert_eq!(*stopped.state.status(), ContainerState::Stopped);
    validate_profile_state(profile.name, validator, &stopped);

    service
        .delete(DeleteRequest {
            context: OperationContext::new(operation_id(&format!("{}-delete", profile.name))),
            target,
            mode: DeleteMode::StoppedOnly,
        })
        .await
        .unwrap_or_else(|error| panic!("{} delete must succeed: {error}", profile.name));
}

fn validate_profile_state(profile: &str, validator: OciSchemaValidator, record: &ContainerRecord) {
    validator
        .validate_state(&record.state)
        .unwrap_or_else(|error| panic!("{profile} state must match the pinned schema: {error}"));
}
