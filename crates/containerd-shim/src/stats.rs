use a3s_oci_sdk::{ContainerStats, Error, ErrorCode, PIDS_LIMIT_METRIC};
use containerd_shim_protos::cgroups_v2::metrics::{
    CPUStat, MemoryEvents, MemoryStat, Metrics, PidsStat,
};
use containerd_shim_protos::protobuf::well_known_types::any::Any;

const CPU_NR_PERIODS: &str = "cpu.stat.nr_periods";
const CPU_NR_THROTTLED: &str = "cpu.stat.nr_throttled";
const CPU_NR_BURSTS: &str = "cpu.stat.nr_bursts";
const CPU_BURST_USEC: &str = "cpu.stat.burst_usec";
const MEMORY_EVENT_LOW: &str = "memory.events.low";
const MEMORY_EVENT_HIGH: &str = "memory.events.high";
const MEMORY_EVENT_MAX: &str = "memory.events.max";
const MEMORY_EVENT_OOM: &str = "memory.events.oom";
const MEMORY_EVENT_OOM_KILL: &str = "memory.events.oom_kill";
const MEMORY_EVENT_OOM_GROUP_KILL: &str = "memory.events.oom_group_kill";

pub(crate) fn encode(stats: &ContainerStats) -> Result<Any, Error> {
    stats.validate()?;
    let metrics = normalize(stats)?;
    containerd_shim::util::convert_to_any(Box::new(metrics)).map_err(|error| {
        Error::new(
            ErrorCode::Internal,
            format!("failed to encode containerd cgroup v2 metrics: {error}"),
        )
        .for_operation("containerd-shim-stats")
    })
}

fn normalize(stats: &ContainerStats) -> Result<Metrics, Error> {
    let process_limit = required_metric(stats, PIDS_LIMIT_METRIC)?;

    let mut pids = PidsStat::new();
    pids.set_current(stats.process_count);
    pids.set_limit(process_limit);

    let mut cpu = CPUStat::new();
    cpu.set_usage_usec(stats.cpu.usage_ns / 1_000);
    cpu.set_user_usec(stats.cpu.user_ns / 1_000);
    cpu.set_system_usec(stats.cpu.system_ns / 1_000);
    cpu.set_throttled_usec(stats.cpu.throttled_ns / 1_000);
    cpu.set_nr_periods(metric(stats, CPU_NR_PERIODS));
    cpu.set_nr_throttled(metric(stats, CPU_NR_THROTTLED));
    cpu.set_nr_bursts(metric(stats, CPU_NR_BURSTS));
    cpu.set_burst_usec(metric(stats, CPU_BURST_USEC));

    let mut memory = MemoryStat::new();
    memory.set_usage(stats.memory.usage_bytes);
    memory.set_usage_limit(stats.memory.limit_bytes.unwrap_or(u64::MAX));
    memory.set_max_usage(stats.memory.peak_bytes.unwrap_or_default());

    let mut metrics = Metrics::new();
    metrics.set_pids(pids);
    metrics.set_cpu(cpu);
    metrics.set_memory(memory);

    let event_names = [
        MEMORY_EVENT_LOW,
        MEMORY_EVENT_HIGH,
        MEMORY_EVENT_MAX,
        MEMORY_EVENT_OOM,
        MEMORY_EVENT_OOM_KILL,
        MEMORY_EVENT_OOM_GROUP_KILL,
    ];
    if event_names
        .iter()
        .any(|name| stats.metrics.contains_key(*name))
    {
        let mut events = MemoryEvents::new();
        events.set_low(metric(stats, MEMORY_EVENT_LOW));
        events.set_high(metric(stats, MEMORY_EVENT_HIGH));
        events.set_max(metric(stats, MEMORY_EVENT_MAX));
        events.set_oom(metric(stats, MEMORY_EVENT_OOM));
        events.set_oom_kill(metric(stats, MEMORY_EVENT_OOM_KILL));
        events.set_oom_group_kill(metric(stats, MEMORY_EVENT_OOM_GROUP_KILL));
        metrics.set_memory_events(events);
    }

    Ok(metrics)
}

fn metric(stats: &ContainerStats, name: &str) -> u64 {
    stats.metrics.get(name).copied().unwrap_or_default()
}

fn required_metric(stats: &ContainerStats, name: &str) -> Result<u64, Error> {
    stats.metrics.get(name).copied().ok_or_else(|| {
        Error::new(
            ErrorCode::FailedPrecondition,
            format!("runtime stats omitted required normalized metric {name}"),
        )
        .for_operation("containerd-shim-stats")
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, CpuStats, Generation, MemoryStats, PIDS_LIMIT_METRIC,
    };
    use containerd_shim_protos::protobuf::Message;

    use super::*;

    fn runtime_stats() -> ContainerStats {
        ContainerStats {
            target: ContainerTarget::exact(
                ContainerId::new("containerd-stats").expect("container ID"),
                Generation(7),
            ),
            timestamp_unix_ns: 1,
            cpu: CpuStats {
                usage_ns: 30_000,
                user_ns: 10_000,
                system_ns: 20_000,
                throttled_ns: 2_000,
            },
            memory: MemoryStats {
                usage_bytes: 1_024,
                limit_bytes: Some(4_096),
                peak_bytes: Some(2_048),
            },
            process_count: 2,
            metrics: BTreeMap::from([
                (PIDS_LIMIT_METRIC.to_string(), 64),
                (CPU_NR_PERIODS.to_string(), 3),
                (CPU_NR_THROTTLED.to_string(), 1),
                (MEMORY_EVENT_HIGH.to_string(), 4),
                (MEMORY_EVENT_OOM_KILL.to_string(), 2),
            ]),
        }
    }

    #[test]
    fn emits_the_containerd_cgroup_v2_metrics_contract() {
        let any = encode(&runtime_stats()).expect("encode metrics");

        assert_eq!(any.type_url, "io.containerd.cgroups.v2.Metrics");
        let metrics = Metrics::parse_from_bytes(&any.value).expect("decode metrics");
        assert_eq!(metrics.pids().current(), 2);
        assert_eq!(metrics.pids().limit(), 64);
        assert_eq!(metrics.cpu().usage_usec(), 30);
        assert_eq!(metrics.cpu().user_usec(), 10);
        assert_eq!(metrics.cpu().system_usec(), 20);
        assert_eq!(metrics.cpu().throttled_usec(), 2);
        assert_eq!(metrics.cpu().nr_periods(), 3);
        assert_eq!(metrics.cpu().nr_throttled(), 1);
        assert_eq!(metrics.memory().usage(), 1_024);
        assert_eq!(metrics.memory().usage_limit(), 4_096);
        assert_eq!(metrics.memory().max_usage(), 2_048);
        assert_eq!(metrics.memory_events().high(), 4);
        assert_eq!(metrics.memory_events().oom_kill(), 2);
    }

    #[test]
    fn refuses_to_invent_an_unknown_process_limit() {
        let mut stats = runtime_stats();
        stats.metrics.remove(PIDS_LIMIT_METRIC);

        let error = encode(&stats).expect_err("missing process limit must fail closed");

        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains(PIDS_LIMIT_METRIC));
    }

    #[test]
    fn preserves_unbounded_cgroup_limits() {
        let mut stats = runtime_stats();
        stats.memory.limit_bytes = None;
        stats
            .metrics
            .insert(PIDS_LIMIT_METRIC.to_string(), u64::MAX);

        let any = encode(&stats).expect("encode unbounded metrics");
        let metrics = Metrics::parse_from_bytes(&any.value).expect("decode metrics");

        assert_eq!(metrics.pids().limit(), u64::MAX);
        assert_eq!(metrics.memory().usage_limit(), u64::MAX);
    }
}
