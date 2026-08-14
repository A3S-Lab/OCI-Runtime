use a3s_oci_core::LifecycleState;
use a3s_oci_sdk::oci_spec::runtime::{ContainerState, State, StateBuilder};
use a3s_oci_sdk::{ContainerId, ErrorCode, OciBundle, Result, PAUSED_STATE_ANNOTATION};

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
        if annotations.contains_key(PAUSED_STATE_ANNOTATION) {
            return Err(state_error(
                ErrorCode::InvalidArgument,
                "build-oci-state",
                format!("OCI annotation {PAUSED_STATE_ANNOTATION} is reserved for runtime state"),
            ));
        }
        if !annotations.is_empty() {
            builder = builder.annotations(annotations);
        }
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
    if let Some(mut annotations) = state.annotations().clone() {
        if status == ContainerState::Stopped {
            annotations.remove(PAUSED_STATE_ANNOTATION);
        }
        if !annotations.is_empty() {
            builder = builder.annotations(annotations);
        }
    }
    builder.build().map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "build-oci-state",
            format!("failed to update OCI state for {}: {error}", state.id()),
        )
    })
}

pub(super) fn rebuild_paused_state(state: &State, paused: bool) -> Result<State> {
    if state.status() != &ContainerState::Running {
        return Err(state_error(
            ErrorCode::FailedPrecondition,
            "update-container-freezer-state",
            format!(
                "container {} cannot change freezer state while {}",
                state.id(),
                state.status()
            ),
        ));
    }
    let mut annotations = state.annotations().clone().unwrap_or_default();
    if paused {
        annotations.insert(PAUSED_STATE_ANNOTATION.to_string(), "true".to_string());
    } else {
        annotations.remove(PAUSED_STATE_ANNOTATION);
    }
    let mut builder = StateBuilder::default()
        .version(state.version())
        .id(state.id())
        .status(*state.status())
        .bundle(state.bundle().clone());
    if !annotations.is_empty() {
        builder = builder.annotations(annotations);
    }
    if let Some(pid) = state.pid() {
        builder = builder.pid(*pid);
    }
    builder.build().map_err(|error| {
        state_error(
            ErrorCode::Internal,
            "update-container-freezer-state",
            format!(
                "failed to update freezer state for container {}: {error}",
                state.id()
            ),
        )
    })
}

pub(super) fn is_paused(state: &State) -> bool {
    state
        .annotations()
        .as_ref()
        .and_then(|annotations| annotations.get(PAUSED_STATE_ANNOTATION))
        .is_some_and(|value| value == "true")
}

pub(super) const fn container_state(state: LifecycleState) -> ContainerState {
    match state {
        LifecycleState::Creating => ContainerState::Creating,
        LifecycleState::Created => ContainerState::Created,
        LifecycleState::Running => ContainerState::Running,
        LifecycleState::Stopped => ContainerState::Stopped,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use a3s_oci_sdk::oci_spec::runtime::{ContainerState, StateBuilder};

    use super::rebuild_paused_state;

    #[test]
    fn resume_restores_absent_annotations_instead_of_retaining_an_empty_map() {
        let running = StateBuilder::default()
            .version("1.3.0")
            .id("annotation-free-container")
            .status(ContainerState::Running)
            .pid(42)
            .bundle("/bundle")
            .build()
            .expect("running state");

        let paused = rebuild_paused_state(&running, true).expect("pause state");
        let resumed = rebuild_paused_state(&paused, false).expect("resume state");

        assert_eq!(resumed.annotations(), &None);
    }

    #[test]
    fn resume_preserves_non_freezer_annotations() {
        let running = StateBuilder::default()
            .version("1.3.0")
            .id("annotated-container")
            .status(ContainerState::Running)
            .pid(42)
            .bundle("/bundle")
            .annotations(HashMap::from([(
                "dev.a3s.test".to_string(),
                "retained".to_string(),
            )]))
            .build()
            .expect("running state");

        let paused = rebuild_paused_state(&running, true).expect("pause state");
        let resumed = rebuild_paused_state(&paused, false).expect("resume state");

        assert_eq!(
            resumed
                .annotations()
                .as_ref()
                .and_then(|annotations| annotations.get("dev.a3s.test"))
                .map(String::as_str),
            Some("retained")
        );
    }
}
