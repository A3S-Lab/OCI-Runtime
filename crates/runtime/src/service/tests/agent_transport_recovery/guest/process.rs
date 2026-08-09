use a3s_oci_agent_protocol::AgentProcessesRequest;
use a3s_oci_sdk::oci_spec::runtime::ContainerState;
use a3s_oci_sdk::{Error, ErrorCode, ProcessId, ProcessRecord, ProcessTarget, Result};

use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(super) fn list_processes(
        &self,
        request: AgentProcessesRequest,
    ) -> Result<Vec<ProcessRecord>> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.processes_requests += 1;
        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-processes")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-processes"));
        }

        let mut processes = Vec::new();
        if current.status() != ContainerState::Stopped {
            processes.push(ProcessRecord {
                target: ProcessTarget {
                    container: request.target,
                    process_id: ProcessId::init(),
                },
                pid: current.pid().and_then(|pid| u32::try_from(pid).ok()),
                terminal: false,
            });
        }
        if journal.exec_exit_status.is_none() {
            if let Some((_, process)) = journal.exec.entry.as_ref() {
                processes.push(ProcessRecord {
                    target: process.target().clone(),
                    pid: u32::try_from(process.pid()).ok(),
                    terminal: process.terminal(),
                });
            }
        }
        Ok(processes)
    }
}
