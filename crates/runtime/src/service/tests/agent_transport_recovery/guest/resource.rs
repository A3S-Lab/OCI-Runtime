use a3s_oci_agent_protocol::{AgentState, AgentUpdateRequest};
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::super::guest_journal::{already_exists, changed_request};
use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(super) fn update_resources(&self, request: AgentUpdateRequest) -> Result<AgentState> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.update.requests += 1;
        if let Some((recorded, response)) = journal.update.entry.as_ref() {
            if recorded.context.operation_id == request.context.operation_id {
                if recorded != &request {
                    return Err(changed_request("update"));
                }
                return Ok(response.clone());
            }
            return Err(already_exists("update"));
        }

        let current = journal.current.clone().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-update")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-update"));
        }
        if !matches!(
            current.status(),
            ContainerState::Created | ContainerState::Running
        ) {
            return Err(Error::new(
                ErrorCode::FailedPrecondition,
                "guest update requires a created or running container",
            )
            .for_operation("agent-update"));
        }

        journal.update.effects += 1;
        journal.update.entry = Some((request, current.clone()));
        Ok(current)
    }
}
