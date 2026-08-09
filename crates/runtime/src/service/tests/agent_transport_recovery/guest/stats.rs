use std::collections::BTreeMap;

use a3s_oci_agent_protocol::AgentStatsRequest;
use a3s_oci_sdk::{ContainerStats, CpuStats, Error, ErrorCode, MemoryStats, Result};

use super::JournaledLifecycleGuest;

impl JournaledLifecycleGuest {
    pub(super) fn read_stats(&self, request: AgentStatsRequest) -> Result<ContainerStats> {
        let mut journal = self.journal.lock().expect("guest journal lock");
        journal.stats_requests += 1;
        let current = journal.current.as_ref().ok_or_else(|| {
            Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-stats")
        })?;
        if current.target() != &request.target {
            return Err(Error::new(
                ErrorCode::NotFound,
                "guest container generation is unavailable",
            )
            .for_operation("agent-stats"));
        }

        Ok(ContainerStats {
            target: request.target,
            timestamp_unix_ns: 1,
            cpu: CpuStats {
                usage_ns: 30,
                user_ns: 10,
                system_ns: 20,
                throttled_ns: 0,
            },
            memory: MemoryStats {
                usage_bytes: 1_024,
                limit_bytes: Some(4_096),
                peak_bytes: Some(2_048),
            },
            process_count: u64::from(current.pid().is_some()),
            metrics: BTreeMap::from([("memory.events.oom_kill".to_string(), 0)]),
        })
    }
}
