use std::collections::BTreeSet;

use super::*;

#[tokio::test]
async fn exact_session_delegates_every_advertised_workload_operation() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.driver.operations(),
        &crate::agent_driver::AGENT_DRIVER_OPERATIONS
    );
    assert_eq!(
        fixture.driver.hooks(),
        &crate::agent_driver::AGENT_DRIVER_HOOKS
    );

    let request = fixture
        .stage(fixture.handoff_request("delegate-create"))
        .await;
    let bundle = request.bundle.clone();
    let process = bundle
        .spec()
        .process()
        .as_ref()
        .expect("fixture process")
        .clone();
    fixture.driver.create(request).await.expect("create");
    fixture.driver.state(target()).await.expect("state");
    fixture
        .driver
        .start(crate::DriverStartRequest {
            context: context("delegate-start"),
            target: target(),
            bundle,
        })
        .await
        .expect("start");

    let process_target = ProcessTarget {
        container: target(),
        process_id: ProcessId::new("exec-one").expect("process ID"),
    };
    fixture
        .driver
        .exec(crate::DriverExecRequest {
            context: context("delegate-exec"),
            target: process_target.clone(),
            process,
            io: ProcessIo::default(),
        })
        .await
        .expect("exec");
    fixture
        .driver
        .signal_process(crate::DriverSignalProcessRequest {
            context: context("delegate-signal-process"),
            target: process_target.clone(),
            signal: Signal::new(15).expect("signal"),
        })
        .await
        .expect("signal process");
    fixture
        .driver
        .wait_process(crate::DriverWaitProcessRequest {
            target: process_target.clone(),
            timeout_ms: Some(1),
        })
        .await
        .expect("wait process");
    fixture
        .driver
        .pause(crate::DriverContainerOperationRequest {
            context: context("delegate-pause"),
            target: target(),
        })
        .await
        .expect("pause");
    fixture
        .driver
        .resume(crate::DriverContainerOperationRequest {
            context: context("delegate-resume"),
            target: target(),
        })
        .await
        .expect("resume");
    fixture.driver.processes(target()).await.expect("processes");
    fixture
        .driver
        .update(crate::DriverUpdateRequest {
            context: context("delegate-update"),
            target: target(),
            resources: serde_json::from_str("{}").expect("empty Linux resources"),
        })
        .await
        .expect("update");
    fixture.driver.stats(target()).await.expect("stats");
    fixture
        .driver
        .read_output(crate::DriverReadOutputRequest {
            target: process_target.clone(),
            after_sequence: 0,
            max_bytes: 1,
            wait_timeout_ms: Some(1),
        })
        .await
        .expect("read output");
    fixture
        .driver
        .write_stdin(crate::DriverWriteStdinRequest {
            context: context("delegate-write-stdin"),
            target: process_target.clone(),
            data: vec![1],
        })
        .await
        .expect("write stdin");
    fixture
        .driver
        .close_stdin(crate::DriverCloseStdinRequest {
            context: context("delegate-close-stdin"),
            target: process_target.clone(),
        })
        .await
        .expect("close stdin");
    fixture
        .driver
        .resize(crate::DriverResizeRequest {
            context: context("delegate-resize"),
            target: process_target,
            size: TerminalSize {
                width: 80,
                height: 24,
            },
        })
        .await
        .expect("resize");
    fixture
        .driver
        .file(FileRequest {
            target: target(),
            op: FileOp::Download,
            path: "/file".to_string(),
            data: None,
            user: None,
            context: None,
        })
        .await
        .expect("file");
    fixture
        .driver
        .filesystem(FilesystemRequest {
            target: target(),
            op: FilesystemOp::Stat,
            path: "/".to_string(),
            destination: None,
            depth: 0,
            user: None,
            context: None,
        })
        .await
        .expect("filesystem");
    fixture
        .driver
        .wait(crate::DriverWaitRequest {
            target: target(),
            timeout_ms: Some(1),
        })
        .await
        .expect("wait");
    fixture
        .driver
        .kill(crate::DriverKillRequest {
            context: context("delegate-kill"),
            target: target(),
            signal: Signal::new(9).expect("signal"),
            all: true,
        })
        .await
        .expect("kill");
    fixture
        .driver
        .delete(DriverDeleteRequest {
            context: context("delegate-delete"),
            target: target(),
            mode: DeleteMode::Force,
        })
        .await
        .expect("delete");

    let dispatches = fixture
        .guest
        .dispatches
        .lock()
        .expect("dispatch lock")
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(dispatches.len(), 20);
    assert_eq!(
        dispatches,
        crate::agent_driver::AGENT_DRIVER_OPERATIONS
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
}
