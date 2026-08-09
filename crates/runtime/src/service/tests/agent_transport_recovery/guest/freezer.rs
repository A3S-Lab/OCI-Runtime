use a3s_oci_agent_protocol::{AgentContainerOperationRequest, AgentState};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::super::guest_journal::{already_exists, changed_request};
use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(super) fn set_paused(
        &self,
        request: AgentContainerOperationRequest,
        paused: bool,
    ) -> Result<AgentState> {
        let (operation, agent_operation, required_state) = if paused {
            ("pause", "agent-pause", "unfrozen")
        } else {
            ("resume", "agent-resume", "frozen")
        };
        let mut journal = self.journal.lock().expect("guest journal lock");
        {
            let operation_journal = if paused {
                &mut journal.pause
            } else {
                &mut journal.resume
            };
            operation_journal.requests += 1;
            if let Some((recorded, response)) = operation_journal.entry.as_ref() {
                if recorded.context.operation_id == request.context.operation_id {
                    if recorded != &request {
                        return Err(changed_request(operation));
                    }
                    return Ok(response.clone());
                }
                return Err(already_exists(operation));
            }
        }

        let current = journal.current.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation(agent_operation)
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation(agent_operation));
        }
        if current.status() != ContainerState::Running || current.paused() == paused {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                format!("guest {operation} requires a {required_state} running container"),
            )
            .for_operation(agent_operation));
        }

        let response = AgentState::new_with_pause(
            request.target.clone(),
            ContainerState::Running,
            current.pid(),
            current.config_digest(),
            paused,
        )?;
        let operation_journal = if paused {
            &mut journal.pause
        } else {
            &mut journal.resume
        };
        operation_journal.effects += 1;
        operation_journal.entry = Some((request, response.clone()));
        journal.current = Some(response.clone());
        Ok(response)
    }
}
