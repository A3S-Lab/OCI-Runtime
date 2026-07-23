use a3s_oci_core::LifecycleState;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, State, StateBuilder};
use a3s_oci_sdk::{ContainerId, ErrorCode, OciBundle, Result};

use super::filesystem::state_error;

pub(super) fn build_state(
    id: &ContainerId,
    bundle: &OciBundle,
    status: ContainerState,
    pid: Option<i32>,
) -> Result<State> {
    let mut builder = StateBuilder::default()
        .version(bundle.spec().version())
        .id(id.as_str())
        .status(status)
        .bundle(bundle.directory().to_path_buf());
    if let Some(pid) = pid {
        builder = builder.pid(pid);
    }
    if let Some(annotations) = bundle.spec().annotations().clone() {
        builder = builder.annotations(annotations);
    }
    builder.build().map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "build-oci-state",
            format!("failed to construct OCI state for {id}: {error}"),
        )
    })
}

pub(super) fn rebuild_state(
    state: &State,
    status: ContainerState,
    pid: Option<i32>,
) -> Result<State> {
    let mut builder = StateBuilder::default()
        .version(state.version())
        .id(state.id())
        .status(status)
        .bundle(state.bundle().clone());
    if let Some(pid) = pid {
        builder = builder.pid(pid);
    }
    if let Some(annotations) = state.annotations().clone() {
        builder = builder.annotations(annotations);
    }
    builder.build().map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "build-oci-state",
            format!("failed to update OCI state for {}: {error}", state.id()),
        )
    })
}

pub(super) const fn container_state(state: LifecycleState) -> ContainerState {
    match state {
        LifecycleState::Creating => ContainerState::Creating,
        LifecycleState::Created => ContainerState::Created,
        LifecycleState::Running => ContainerState::Running,
        LifecycleState::Stopped => ContainerState::Stopped,
    }
}
