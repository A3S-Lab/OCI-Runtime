use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Durable OCI lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LifecycleState {
    /// Create-time resources are being prepared.
    Creating,
    /// Create completed and the configured user process has not started.
    Created,
    /// The configured user process is running.
    Running,
    /// The configured user process exited.
    Stopped,
}

/// Event that changes durable lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleEvent {
    /// All create-time work completed successfully.
    CreateCompleted,
    /// The explicit start operation released the user process.
    StartCompleted,
    /// The init process exited naturally or after a signal.
    ProcessExited,
}

/// Invalid lifecycle event for the current durable state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("cannot apply lifecycle event {event:?} while container is {state:?}")]
pub struct TransitionError {
    /// State that rejected the event.
    pub state: LifecycleState,
    /// Event rejected by the state machine.
    pub event: LifecycleEvent,
}

impl LifecycleState {
    /// Apply one validated lifecycle event.
    pub fn transition(self, event: LifecycleEvent) -> Result<Self, TransitionError> {
        match (self, event) {
            (Self::Creating, LifecycleEvent::CreateCompleted) => Ok(Self::Created),
            (Self::Created, LifecycleEvent::StartCompleted) => Ok(Self::Running),
            (Self::Running, LifecycleEvent::ProcessExited) => Ok(Self::Stopped),
            (state, event) => Err(TransitionError { state, event }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LifecycleEvent, LifecycleState};

    #[test]
    fn create_and_start_are_distinct_transitions() {
        let created = LifecycleState::Creating
            .transition(LifecycleEvent::CreateCompleted)
            .expect("create completion must be valid");
        assert_eq!(created, LifecycleState::Created);

        let running = created
            .transition(LifecycleEvent::StartCompleted)
            .expect("start completion must be valid");
        assert_eq!(running, LifecycleState::Running);
    }

    #[test]
    fn process_cannot_run_before_explicit_start() {
        let error = LifecycleState::Creating
            .transition(LifecycleEvent::StartCompleted)
            .expect_err("start must be rejected during create");

        assert_eq!(error.state, LifecycleState::Creating);
        assert_eq!(error.event, LifecycleEvent::StartCompleted);
    }

    #[test]
    fn stopped_state_is_terminal_for_current_events() {
        for event in [
            LifecycleEvent::CreateCompleted,
            LifecycleEvent::StartCompleted,
            LifecycleEvent::ProcessExited,
        ] {
            assert!(LifecycleState::Stopped.transition(event).is_err());
        }
    }
}
