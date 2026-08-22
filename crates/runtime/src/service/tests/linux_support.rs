use super::*;

fn support_with_mount_options(options: &[&str]) -> OciLinuxSupport {
    let shared = OciLinuxSupport::shared_executor().expect("shared Linux support");
    OciLinuxSupport::new(
        options.iter().map(|option| (*option).to_string()).collect(),
        shared.linux().clone(),
    )
    .expect("reduced Linux support")
}

fn create_request_from_config(
    directory: &Path,
    operation: &str,
    id: &str,
    config: serde_json::Value,
) -> CreateRequest {
    let bundle = OciBundle::from_json(directory.to_path_buf(), config.to_string())
        .expect("schema-valid unsupported Linux bundle");
    CreateRequest {
        context: OperationContext::new(operation_id(operation)),
        id: container_id(id),
        attachments: CreateAttachments::from_bundle(&bundle, ProcessIo::default())
            .expect("valid attachment contract"),
        bundle,
        isolation: IsolationRequest::DedicatedVm,
    }
}

fn base_config() -> serde_json::Value {
    serde_json::from_str(TEST_CONFIG).expect("base OCI configuration")
}

#[tokio::test]
async fn configured_features_are_built_from_the_frozen_driver_linux_support() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let mut driver = RecordingDriver::supported();
    driver.linux_support = support_with_mount_options(&["bind"]);
    let expected_linux = driver.linux_support.linux().clone();
    let service = open_service(&temporary, Arc::new(driver)).await;

    let info = service.features().await.expect("configured feature report");

    assert_eq!(
        info.oci.mount_options().as_deref(),
        Some(["bind".to_string()].as_slice())
    );
    assert_eq!(info.oci.linux().as_ref(), Some(&expected_linux));
}

#[tokio::test]
async fn service_open_rejects_drivers_with_different_linux_support_profiles() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let dedicated = RecordingDriver::supported();
    let mut shared_guest = RecordingDriver::shared_guest_supported();
    shared_guest.linux_support = support_with_mount_options(&["bind"]);

    let error = HostRuntimeService::open_with_drivers(
        temporary.path().join("state"),
        vec![Arc::new(dedicated), Arc::new(shared_guest)],
    )
    .await
    .expect_err("mixed Linux support profiles must fail closed");

    assert_eq!(error.code, ErrorCode::FailedPrecondition);
    assert_eq!(error.operation.as_deref(), Some("open-host-runtime"));
    assert!(error.message.contains("different Linux support profile"));
    assert!(!temporary.path().join("state").exists());
}

#[tokio::test]
async fn create_rejects_unadvertised_linux_features_before_durable_mutation() {
    let mut apparmor = base_config();
    apparmor["process"]["apparmorProfile"] = serde_json::json!("a3s-test-profile");

    let mut selinux = base_config();
    selinux["process"]["selinuxLabel"] = serde_json::json!("system_u:system_r:container_t:s0");

    let mut seccomp = base_config();
    seccomp["linux"] = serde_json::json!({
        "seccomp": {"defaultAction": "SCMP_ACT_NOTIFY"}
    });

    let mut cgroup_v1 = base_config();
    cgroup_v1["linux"] = serde_json::json!({
        "resources": {"memory": {"swappiness": 60}}
    });

    for (name, config, field) in [
        ("apparmor", apparmor, "process.apparmorProfile"),
        ("selinux", selinux, "process.selinuxLabel"),
        ("seccomp", seccomp, "linux.seccomp.defaultAction"),
        ("cgroup-v1", cgroup_v1, "linux.resources.memory.swappiness"),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let operation = format!("linux-support-{name}");
        let request = create_request_from_config(
            &temporary.path().join("unsupported-bundle"),
            &operation,
            name,
            config,
        );
        let driver = Arc::new(RecordingDriver::supported());
        let service = open_service(&temporary, Arc::clone(&driver)).await;

        let error = match service.create(request).await {
            Ok(record) => {
                panic!("{field} unexpectedly created durable record {record:?}")
            }
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::Unsupported, "{field}");
        assert!(error.message.contains(field), "{field}: {error}");
        assert!(driver.calls().is_empty(), "{field} reached the driver");
        assert!(
            service
                .list(ListRequest::default())
                .await
                .expect("list durable records")
                .is_empty(),
            "{field} created durable state"
        );

        service
            .create(create_request(
                &temporary.path().join("valid-bundle"),
                &operation,
            ))
            .await
            .unwrap_or_else(|error| {
                panic!("{field} must not claim the rejected operation ID: {error}")
            });
        assert_eq!(
            driver
                .calls()
                .iter()
                .filter(|call| matches!(call, DriverCall::Create(_)))
                .count(),
            1,
            "{field} retry dispatch count"
        );
    }
}

#[tokio::test]
async fn exec_and_update_linux_support_checks_run_before_operation_claims() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let bundle_directory = temporary.path().join("bundle");
    std::fs::create_dir(&bundle_directory).expect("bundle directory");
    let driver = Arc::new(RecordingDriver::with_control_operations());
    let service = open_service(&temporary, Arc::clone(&driver)).await;
    let create = create_request(&bundle_directory, "linux-support-create");
    let created = service.create(create.clone()).await.expect("create");
    let target = ContainerTarget::exact(create.id, created.generation);
    service
        .start(StartRequest {
            context: OperationContext::new(operation_id("linux-support-start")),
            target: target.clone(),
        })
        .await
        .expect("start");

    let mut unsupported_exec =
        exec_request(target.clone(), "linux-support-exec", "linux-support-worker");
    unsupported_exec.process = serde_json::from_value(serde_json::json!({
        "terminal": false,
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/true"],
        "cwd": "/",
        "noNewPrivileges": true,
        "apparmorProfile": "a3s-test-profile"
    }))
    .expect("schema-valid unsupported exec process");
    let error = service
        .exec(unsupported_exec)
        .await
        .expect_err("unadvertised AppArmor exec must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("process.apparmorProfile"));
    service
        .exec(exec_request(
            target.clone(),
            "linux-support-exec",
            "linux-support-worker",
        ))
        .await
        .expect("reused exec operation ID must remain unclaimed");

    let unsupported_resources = serde_json::from_value(serde_json::json!({
        "memory": {"swappiness": 60}
    }))
    .expect("schema-valid cgroup-v1 update");
    let error = service
        .update(UpdateRequest {
            context: OperationContext::new(operation_id("linux-support-update")),
            target: target.clone(),
            resources: unsupported_resources,
        })
        .await
        .expect_err("unadvertised cgroup-v1 update must fail");
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert!(error.message.contains("linux.resources.memory.swappiness"));
    service
        .update(update_request(target, "linux-support-update"))
        .await
        .expect("reused update operation ID must remain unclaimed");

    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Exec(_)))
            .count(),
        1
    );
    assert_eq!(
        driver
            .calls()
            .iter()
            .filter(|call| matches!(call, DriverCall::Update(_)))
            .count(),
        1
    );
}
