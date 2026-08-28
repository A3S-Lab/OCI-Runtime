use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as StdSocketAddr, UnixListener as StdUnixListener};

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use a3s_oci_sdk::{Error, ErrorCode, Result};
use tokio::net::UnixListener;
use tokio::process::Child;

use super::super::bundle_scope::{PinnedBundleDirectory, PinnedRootfsDirectory};
use super::super::cgroup::CgroupHandle;
use super::super::plan::InitPlan;
use super::{append_cleanup_error, process_error};

pub(super) fn validate_rootless_device_mounts(
    mounts: &[OwnedFd],
    rootless: bool,
    devices_required: bool,
) -> Result<()> {
    let expected = if rootless && devices_required {
        super::super::device::ROOTLESS_DEVICE_MOUNT_COUNT
    } else {
        0
    };
    if mounts.len() != expected {
        return Err(process_error(
            ErrorCode::PermissionDenied,
            format!(
                "prepared rootless device mount count {} does not match expected {expected}",
                mounts.len()
            ),
        ));
    }
    Ok(())
}

pub(super) async fn retain_original_rootfs(
    plan: &InitPlan,
    pinned_bundle: Option<&PinnedBundleDirectory>,
) -> Result<(File, Option<PinnedRootfsDirectory>)> {
    if let Some(bundle) = pinned_bundle {
        let relative = plan.rootfs.strip_prefix(&plan.bundle_directory).map_err(|_| {
            process_error(
                ErrorCode::PermissionDenied,
                format!(
                    "container rootfs must be relative to its descriptor-pinned utility-VM bundle: {}",
                    plan.rootfs.display()
                ),
            )
        })?;
        let rootfs = bundle
            .open_relative(
                relative,
                libc::O_PATH,
                true,
                "container rootfs",
                "run-container-init",
            )?
            .ok_or_else(|| {
                process_error(
                    ErrorCode::InvalidArgument,
                    format!("container rootfs does not exist: {}", plan.rootfs.display()),
                )
            })?;
        let child_rootfs = bundle.prepare_rootfs_for_child(&rootfs)?;
        return Ok((rootfs, Some(child_rootfs)));
    }
    let path = &plan.rootfs;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| {
            process_error(
                ErrorCode::InvalidArgument,
                format!(
                    "failed to retain container rootfs {} before init launch: {error}",
                    path.display()
                ),
            )
        })?
        .into_std()
        .await;
    Ok((file, None))
}

pub(in crate::executor) fn bind_control_listener() -> Result<(UnixListener, String)> {
    let endpoint = AgentVsockEndpoint::generate()?;
    let control_name = format!("a3s-oci-init-{}", endpoint.pipe_name());
    let address = StdSocketAddr::from_abstract_name(control_name.as_bytes()).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to construct abstract init control address: {error}"),
        )
    })?;
    let listener = StdUnixListener::bind_addr(&address).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to bind abstract init control socket: {error}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to make init control socket nonblocking: {error}"),
        )
    })?;
    let listener = UnixListener::from_std(listener).map_err(|error| {
        process_error(
            ErrorCode::Internal,
            format!("failed to register init control socket with Tokio: {error}"),
        )
    })?;
    Ok((listener, control_name))
}

pub(in crate::executor) async fn terminate(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

pub(super) fn cleanup_unstarted_cgroup(
    cgroup: &mut Option<CgroupHandle>,
    mut primary: Error,
) -> Error {
    if let Some(mut cgroup) = cgroup.take() {
        if let Err(error) = cgroup.cleanup() {
            append_cleanup_error(
                &mut primary,
                "remove the unstarted container cgroup",
                &error,
            );
        }
    }
    primary
}

pub(super) async fn cleanup_uncommitted_create(
    child: &mut Child,
    cgroup: &mut Option<CgroupHandle>,
    mut primary: Error,
) -> Error {
    let termination = match cgroup.as_ref() {
        Some(cgroup) => cgroup.terminate_all().await,
        None => Ok(()),
    };
    terminate(child).await;
    if let Err(error) = termination {
        append_cleanup_error(&mut primary, "terminate the container cgroup", &error);
    }
    if let Some(mut cgroup) = cgroup.take() {
        if let Err(error) = cgroup.cleanup() {
            append_cleanup_error(&mut primary, "remove the container cgroup", &error);
        }
    }
    primary
}
