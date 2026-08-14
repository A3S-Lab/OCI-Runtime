use std::path::{Path, PathBuf};
use std::time::Duration;

use a3s_oci_sdk::{
    ContainerTarget, DeleteMode, DeleteRequest, ErrorCode, ExitStatus, OciBundle, RuntimeClient,
    StartRequest, WaitRequest,
};
use tokio::time::timeout;

use super::super::filesystem::remove_marker;
use super::lifecycle::{
    container_id, create_request, kill_request, native_call, operation, require, require_created,
    require_kill_state, require_running, state_equals, state_is_missing, wait_request,
    wait_until_stopped,
};
use crate::namespace_join::{build_bundles, build_host_network_bundle};
use crate::NativeLinuxMultiContainerSmokeReport;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) async fn exercise(
    client: &RuntimeClient,
    donor_bundle: &OciBundle,
    joiner_bundle: &OciBundle,
    nonce: &str,
    markers: [&Path; 2],
    report: &mut NativeLinuxMultiContainerSmokeReport,
) -> Result<(), String> {
    remove_marker(markers[0]).await?;
    remove_marker(markers[1]).await?;

    let donor_id = container_id(nonce, "namespace-donor")?;
    let donor_create = create_request(
        nonce,
        "namespace-donor-create",
        donor_id.clone(),
        donor_bundle,
    )?;
    let donor = native_call("create namespace donor", client.create(donor_create)).await?;
    require_created(&donor, "namespace donor")?;
    let donor_target = ContainerTarget::exact(donor_id, donor.generation);
    let donor_pid = donor
        .state
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "namespace donor did not report a positive PID".to_string())?;
    report.namespace_join.donor_pid = Some(donor_pid);
    report.network_modes.private_namespace_verified =
        !same_network_namespace_with_host(donor_pid).await?;
    require(
        report.network_modes.private_namespace_verified,
        "private-network donor inherited the host network namespace",
    )?;
    verify_private_loopback(donor_pid)?;

    let bundles = build_bundles(joiner_bundle, donor_pid)?;
    let host_network =
        build_host_network_bundle(joiner_bundle, &format!("a3s-oci-host-network-{nonce}"))?;
    verify_wrong_type_rejection(client, &bundles.wrong_type, nonce).await?;
    report.namespace_join.wrong_type_rejected_before_state = true;

    let non_mount_id = container_id(nonce, "namespace-non-mount")?;
    let non_mount_create = create_request(
        nonce,
        "namespace-non-mount-create",
        non_mount_id.clone(),
        &bundles.non_mount,
    )?;
    let non_mount = native_call(
        "create non-mount namespace joiner",
        client.create(non_mount_create),
    )
    .await?;
    require_created(&non_mount, "non-mount namespace joiner")?;
    report.namespace_join.joined_non_mount_namespaces = true;
    let non_mount_pid = non_mount
        .state
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "non-mount namespace joiner did not report a positive PID".to_string())?;
    report.network_modes.shared_namespace_verified =
        same_network_namespace(donor_pid, non_mount_pid).await?;
    require(
        report.network_modes.shared_namespace_verified,
        "network joiner did not enter the donor network namespace",
    )?;
    let non_mount_target = ContainerTarget::exact(non_mount_id, non_mount.generation);
    run_joiner(client, nonce, "namespace-non-mount", &non_mount_target).await?;
    report.namespace_join.joined_pid_time_workload_verified = true;
    report.namespace_join.joined_user_default_devices_verified = true;

    let mount_id = container_id(nonce, "namespace-mount")?;
    let mount_create = create_request(
        nonce,
        "namespace-mount-create",
        mount_id.clone(),
        &bundles.mount,
    )?;
    let mount = native_call("create mount namespace joiner", client.create(mount_create)).await?;
    require_created(&mount, "mount namespace joiner")?;
    report.namespace_join.joined_mount_namespace = true;
    let mount_target = ContainerTarget::exact(mount_id, mount.generation);
    run_joiner(client, nonce, "namespace-mount", &mount_target).await?;
    report.namespace_join.retained_rootfs_verified = true;

    let host_id = container_id(nonce, "network-host")?;
    let host_create = create_request(nonce, "network-host-create", host_id.clone(), &host_network)?;
    let host = native_call(
        "create host-network inheritance container",
        client.create(host_create),
    )
    .await?;
    require_created(&host, "host-network inheritance container")?;
    let host_pid = host
        .state
        .pid()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| "host-network container did not report a positive PID".to_string())?;
    report.network_modes.host_namespace_verified =
        same_network_namespace_with_host(host_pid).await?;
    require(
        report.network_modes.host_namespace_verified,
        "host-network container did not inherit the host network namespace",
    )?;
    let host_target = ContainerTarget::exact(host_id, host.generation);
    run_joiner(client, nonce, "network-host", &host_target).await?;

    report.namespace_join.donor_unchanged_after_joins = state_equals(
        client,
        &donor_target,
        &donor,
        "namespace donor after joiners",
    )
    .await?;
    require(
        report.namespace_join.donor_unchanged_after_joins,
        "namespace joiners changed the prepared donor state",
    )?;

    native_call(
        "delete namespace donor",
        client.delete(DeleteRequest {
            context: operation(nonce, "namespace-donor-delete")?,
            target: donor_target.clone(),
            mode: DeleteMode::Force,
        }),
    )
    .await?;
    report.namespace_join.all_state_removed =
        state_is_missing(client, &donor_target, "namespace donor after delete").await?
            && state_is_missing(
                client,
                &non_mount_target,
                "non-mount namespace joiner after delete",
            )
            .await?
            && state_is_missing(client, &mount_target, "mount namespace joiner after delete")
                .await?
            && state_is_missing(client, &host_target, "host-network container after delete")
                .await?;
    report.network_modes.all_profiles_removed = report.namespace_join.all_state_removed;
    require(
        report.namespace_join.all_state_removed,
        "namespace join qualification left container state",
    )
}

async fn same_network_namespace_with_host(pid: i32) -> Result<bool, String> {
    let container = PathBuf::from(format!("/proc/{pid}/ns/net"));
    same_namespace_paths(Path::new("/proc/self/ns/net"), &container).await
}

fn verify_private_loopback(pid: i32) -> Result<(), String> {
    let check = std::thread::Builder::new()
        .name(format!("a3s-oci-loopback-{pid}"))
        .spawn(move || {
            use std::fs::File;
            use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
            use std::os::fd::AsRawFd;

            let namespace_path = format!("/proc/{pid}/ns/net");
            let namespace = File::open(&namespace_path).map_err(|error| {
                format!("failed to open private network namespace {namespace_path}: {error}")
            })?;
            // SAFETY: namespace pins the exact network namespace descriptor,
            // and this dedicated thread exits immediately after the probe.
            if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(format!(
                    "failed to enter private network namespace {namespace_path}: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
                .map_err(|error| format!("failed to bind private loopback listener: {error}"))?;
            let address = listener
                .local_addr()
                .map_err(|error| format!("failed to inspect private loopback listener: {error}"))?;
            TcpStream::connect_timeout(&address, Duration::from_secs(1)).map_err(|error| {
                format!("failed to connect through the private loopback interface: {error}")
            })?;
            Ok(())
        })
        .map_err(|error| format!("failed to start private loopback probe: {error}"))?;
    check
        .join()
        .map_err(|_| "private loopback probe panicked".to_string())?
}

async fn same_network_namespace(first_pid: i32, second_pid: i32) -> Result<bool, String> {
    let first = PathBuf::from(format!("/proc/{first_pid}/ns/net"));
    let second = PathBuf::from(format!("/proc/{second_pid}/ns/net"));
    same_namespace_paths(&first, &second).await
}

async fn same_namespace_paths(first: &Path, second: &Path) -> Result<bool, String> {
    use std::os::linux::fs::MetadataExt;

    let first_metadata = tokio::fs::metadata(first)
        .await
        .map_err(|error| format!("failed to inspect namespace {}: {error}", first.display()))?;
    let second_metadata = tokio::fs::metadata(second)
        .await
        .map_err(|error| format!("failed to inspect namespace {}: {error}", second.display()))?;
    Ok(first_metadata.st_dev() == second_metadata.st_dev()
        && first_metadata.st_ino() == second_metadata.st_ino())
}

async fn verify_wrong_type_rejection(
    client: &RuntimeClient,
    bundle: &OciBundle,
    nonce: &str,
) -> Result<(), String> {
    let id = container_id(nonce, "namespace-wrong-type")?;
    let create = create_request(nonce, "namespace-wrong-type-create", id.clone(), bundle)?;
    match timeout(CALL_TIMEOUT, client.create(create)).await {
        Ok(Err(error)) if error.code == ErrorCode::InvalidArgument => {}
        Ok(Err(error)) => {
            return Err(format!(
                "wrong namespace type returned {:?}, expected InvalidArgument: {}",
                error.code, error.message
            ));
        }
        Ok(Ok(_)) => return Err("wrong namespace type unexpectedly created a container".into()),
        Err(_) => return Err("wrong namespace type create timed out".into()),
    }
    let target = ContainerTarget::current(id);
    require(
        state_is_missing(client, &target, "wrong namespace type after rejection").await?,
        "wrong namespace type rejection left container state",
    )
}

async fn run_joiner(
    client: &RuntimeClient,
    nonce: &str,
    label: &str,
    target: &ContainerTarget,
) -> Result<(), String> {
    let started = native_call(
        &format!("start {label} joiner"),
        client.start(StartRequest {
            context: operation(nonce, &format!("{label}-start"))?,
            target: target.clone(),
        }),
    )
    .await?;
    require_running(&started, label)?;
    match timeout(
        CALL_TIMEOUT,
        client.wait(WaitRequest {
            target: target.clone(),
            timeout_ms: Some(300),
        }),
    )
    .await
    {
        Ok(Err(error)) if error.code == ErrorCode::DeadlineExceeded => {}
        Ok(Err(error)) => {
            return Err(format!(
                "{label} bounded running wait failed with {:?}: {}",
                error.code, error.message
            ));
        }
        Ok(Ok(status)) => {
            return Err(format!(
                "{label} exited during the running observation window: {status:?}"
            ));
        }
        Err(_) => return Err(format!("{label} bounded running wait call timed out")),
    }
    require(
        state_equals(
            client,
            target,
            &started,
            &format!("{label} after bounded running wait"),
        )
        .await?,
        format!("{label} did not remain running after exec"),
    )?;

    let killed = native_call(
        &format!("kill {label} joiner"),
        client.kill(kill_request(
            nonce,
            &format!("{label}-kill"),
            target.clone(),
        )?),
    )
    .await?;
    require_kill_state(&killed, label)?;
    let waited = native_call(
        &format!("wait for {label} joiner"),
        client.wait(wait_request(target.clone())),
    )
    .await?;
    require(
        waited
            == ExitStatus::signaled(libc::SIGKILL, false)
                .map_err(|error| format!("failed to construct expected joiner exit: {error}"))?,
        format!("{label} joiner returned unexpected exit status {waited:?}"),
    )?;
    require(
        wait_until_stopped(client, target).await?,
        format!("{label} joiner did not stop"),
    )?;
    native_call(
        &format!("delete {label} joiner"),
        client.delete(DeleteRequest {
            context: operation(nonce, &format!("{label}-delete"))?,
            target: target.clone(),
            mode: DeleteMode::StoppedOnly,
        }),
    )
    .await?;
    require(
        state_is_missing(client, target, &format!("{label} after delete")).await?,
        format!("{label} joiner remained visible after delete"),
    )
}
