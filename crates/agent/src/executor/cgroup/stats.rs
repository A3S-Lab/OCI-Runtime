use std::collections::BTreeMap;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use a3s_oci_sdk::{
    ContainerStats, ContainerTarget, CpuStats, MemoryStats, Result, IO_READ_BYTES_METRIC,
    IO_WRITE_BYTES_METRIC,
};

use super::{parse_max_value, parse_u64_value, read_required, stats_error, CgroupHandle};

const STATS_OPERATION: &str = "read-container-cgroup-stats";

impl CgroupHandle {
    pub(in crate::executor) async fn stats(
        &self,
        target: ContainerTarget,
    ) -> Result<ContainerStats> {
        let cpu_values = parse_keyed_counters(
            "cpu.stat",
            &read_required(&self.leaf, "cpu.stat", STATS_OPERATION).await?,
        )?;
        let usage_ns = counter_microseconds_to_nanoseconds(&cpu_values, "usage_usec", true)?;
        let user_ns = counter_microseconds_to_nanoseconds(&cpu_values, "user_usec", true)?;
        let system_ns = counter_microseconds_to_nanoseconds(&cpu_values, "system_usec", true)?;
        let throttled_ns =
            counter_microseconds_to_nanoseconds(&cpu_values, "throttled_usec", false)?;

        let memory_usage = parse_u64_value(
            "memory.current",
            &read_required(&self.leaf, "memory.current", STATS_OPERATION).await?,
        )?;
        let memory_limit = parse_max_value(
            "memory.max",
            &read_required(&self.leaf, "memory.max", STATS_OPERATION).await?,
        )?;
        let memory_peak = match tokio::fs::read_to_string(self.leaf.join("memory.peak")).await {
            Ok(value) => Some(parse_u64_value("memory.peak", &value)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(stats_error(format!(
                    "failed to read {}: {error}",
                    self.leaf.join("memory.peak").display()
                )));
            }
        };
        let process_count = parse_u64_value(
            "pids.current",
            &read_required(&self.leaf, "pids.current", STATS_OPERATION).await?,
        )?;

        let mut metrics = BTreeMap::new();
        for (name, value) in cpu_values {
            if !matches!(
                name.as_str(),
                "usage_usec" | "user_usec" | "system_usec" | "throttled_usec"
            ) {
                metrics.insert(format!("cpu.stat.{name}"), value);
            }
        }
        append_event_metrics(
            &mut metrics,
            "memory.events",
            &read_required(&self.leaf, "memory.events", STATS_OPERATION).await?,
        )?;
        append_event_metrics(
            &mut metrics,
            "pids.events",
            &read_required(&self.leaf, "pids.events", STATS_OPERATION).await?,
        )?;
        match tokio::fs::read_to_string(self.leaf.join("io.stat")).await {
            Ok(value) => {
                if let Some((read_bytes, write_bytes)) = parse_io_stat_bytes(&value)? {
                    metrics.insert(IO_READ_BYTES_METRIC.to_string(), read_bytes);
                    metrics.insert(IO_WRITE_BYTES_METRIC.to_string(), write_bytes);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(stats_error(format!(
                    "failed to read {}: {error}",
                    self.leaf.join("io.stat").display()
                )));
            }
        }

        let timestamp_unix_ns = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| {
                    stats_error(format!("system clock is before the Unix epoch: {error}"))
                })?
                .as_nanos(),
        )
        .map_err(|error| stats_error(format!("Unix nanosecond timestamp overflowed: {error}")))?;
        let stats = ContainerStats {
            target,
            timestamp_unix_ns,
            cpu: CpuStats {
                usage_ns,
                user_ns,
                system_ns,
                throttled_ns,
            },
            memory: MemoryStats {
                usage_bytes: memory_usage,
                limit_bytes: memory_limit,
                peak_bytes: memory_peak,
            },
            process_count,
            metrics,
        };
        stats.validate()?;
        Ok(stats)
    }
}

fn parse_keyed_counters(field: &str, value: &str) -> Result<BTreeMap<String, u64>> {
    let mut counters = BTreeMap::new();
    for line in value.lines() {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().ok_or_else(|| {
            stats_error(format!(
                "cgroup counter file {field} contains an empty line"
            ))
        })?;
        let raw = fields
            .next()
            .ok_or_else(|| stats_error(format!("cgroup counter {field}.{name} has no value")))?;
        if fields.next().is_some() {
            return Err(stats_error(format!(
                "cgroup counter {field}.{name} contains extra fields"
            )));
        }
        let counter = raw.parse::<u64>().map_err(|error| {
            stats_error(format!("cgroup counter {field}.{name} is invalid: {error}"))
        })?;
        if counters.insert(name.to_string(), counter).is_some() {
            return Err(stats_error(format!(
                "cgroup counter file {field} contains duplicate key {name}"
            )));
        }
    }
    Ok(counters)
}

fn counter_microseconds_to_nanoseconds(
    counters: &BTreeMap<String, u64>,
    name: &str,
    required: bool,
) -> Result<u64> {
    let Some(value) = counters.get(name).copied() else {
        if required {
            return Err(stats_error(format!("cpu.stat is missing {name}")));
        }
        return Ok(0);
    };
    value.checked_mul(1_000).ok_or_else(|| {
        stats_error(format!(
            "cpu.stat {name} microsecond counter overflows nanoseconds"
        ))
    })
}

fn append_event_metrics(
    metrics: &mut BTreeMap<String, u64>,
    field: &str,
    value: &str,
) -> Result<()> {
    for (name, counter) in parse_keyed_counters(field, value)? {
        metrics.insert(format!("{field}.{name}"), counter);
    }
    Ok(())
}

fn parse_io_stat_bytes(value: &str) -> Result<Option<(u64, u64)>> {
    let mut read_bytes = 0u64;
    let mut write_bytes = 0u64;
    let mut saw_device = false;

    for (index, line) in value.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_number = index + 1;
        let mut fields = line.split_ascii_whitespace();
        let device = fields.next().ok_or_else(|| {
            stats_error(format!(
                "io.stat line {line_number} has no device identifier"
            ))
        })?;
        let Some((major, minor)) = device.split_once(':') else {
            return Err(stats_error(format!(
                "io.stat line {line_number} has invalid device identifier {device:?}"
            )));
        };
        if major.is_empty()
            || minor.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(stats_error(format!(
                "io.stat line {line_number} has invalid device identifier {device:?}"
            )));
        }

        let mut device_read_bytes = None;
        let mut device_write_bytes = None;
        for field in fields {
            let Some((name, raw)) = field.split_once('=') else {
                return Err(stats_error(format!(
                    "io.stat line {line_number} contains invalid counter {field:?}"
                )));
            };
            let counter = raw.parse::<u64>().map_err(|error| {
                stats_error(format!("io.stat {name} counter is invalid: {error}"))
            })?;
            match name {
                "rbytes" => {
                    record_io_stat_counter(&mut device_read_bytes, counter, "rbytes", line_number)?
                }
                "wbytes" => {
                    record_io_stat_counter(&mut device_write_bytes, counter, "wbytes", line_number)?
                }
                _ => {}
            }
        }

        let device_read_bytes = device_read_bytes
            .ok_or_else(|| stats_error(format!("io.stat line {line_number} is missing rbytes")))?;
        let device_write_bytes = device_write_bytes
            .ok_or_else(|| stats_error(format!("io.stat line {line_number} is missing wbytes")))?;
        read_bytes = read_bytes
            .checked_add(device_read_bytes)
            .ok_or_else(|| stats_error("io.stat aggregate read byte counter overflowed"))?;
        write_bytes = write_bytes
            .checked_add(device_write_bytes)
            .ok_or_else(|| stats_error("io.stat aggregate write byte counter overflowed"))?;
        saw_device = true;
    }

    Ok(saw_device.then_some((read_bytes, write_bytes)))
}

fn record_io_stat_counter(
    slot: &mut Option<u64>,
    counter: u64,
    name: &str,
    line_number: usize,
) -> Result<()> {
    if slot.replace(counter).is_some() {
        return Err(stats_error(format!(
            "io.stat line {line_number} contains duplicate {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::{
        ContainerId, ContainerTarget, Generation, IO_READ_BYTES_METRIC, IO_WRITE_BYTES_METRIC,
    };

    use super::{parse_io_stat_bytes, CgroupHandle};

    #[tokio::test]
    async fn normalizes_typed_stats_from_cgroup_v2_files() {
        let directory = tempfile::tempdir().expect("temporary cgroup");
        for (name, value) in [
            (
                "cpu.stat",
                "usage_usec 30\nuser_usec 10\nsystem_usec 20\nnr_periods 3\nnr_throttled 1\nthrottled_usec 2\n",
            ),
            ("memory.current", "1024\n"),
            ("memory.max", "4096\n"),
            ("memory.peak", "2048\n"),
            ("memory.events", "low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\n"),
            ("pids.current", "2\n"),
            ("pids.events", "max 1\n"),
            (
                "io.stat",
                "8:0 rbytes=4096 wbytes=1024 rios=4 wios=1 dbytes=0 dios=0\n8:16 rbytes=512 wbytes=2048 rios=1 wios=2 dbytes=0 dios=0\n",
            ),
            ("cgroup.procs", ""),
        ] {
            std::fs::write(directory.path().join(name), value).expect("write cgroup fixture");
        }
        let procs = std::fs::OpenOptions::new()
            .write(true)
            .open(directory.path().join("cgroup.procs"))
            .expect("open cgroup.procs");
        let handle = CgroupHandle {
            created: Vec::new(),
            leaf: directory.path().to_path_buf(),
            init_procs: procs,
            control_workload: None,
        };
        let target = ContainerTarget::exact(
            ContainerId::new("stats-fixture").expect("container ID"),
            Generation(1),
        );
        let stats = handle.stats(target.clone()).await.expect("stats");
        assert_eq!(stats.target, target);
        assert_eq!(stats.cpu.usage_ns, 30_000);
        assert_eq!(stats.cpu.throttled_ns, 2_000);
        assert_eq!(stats.memory.limit_bytes, Some(4_096));
        assert_eq!(stats.memory.peak_bytes, Some(2_048));
        assert_eq!(stats.process_count, 2);
        assert_eq!(stats.metrics["cpu.stat.nr_throttled"], 1);
        assert_eq!(stats.metrics["memory.events.max"], 2);
        assert_eq!(stats.metrics["pids.events.max"], 1);
        assert_eq!(stats.metrics[IO_READ_BYTES_METRIC], 4_608);
        assert_eq!(stats.metrics[IO_WRITE_BYTES_METRIC], 3_072);
    }

    #[test]
    fn aggregates_io_bytes_across_devices_without_publishing_partial_values() {
        assert_eq!(
            parse_io_stat_bytes(
                "8:0 rbytes=7 wbytes=11 rios=1 wios=2\n259:0 rbytes=13 wbytes=17 rios=3 wios=4\n"
            )
            .expect("valid io.stat"),
            Some((20, 28))
        );

        let error = parse_io_stat_bytes("8:0 rbytes=7 wbytes=invalid")
            .expect_err("invalid counters must fail closed");
        assert!(error.to_string().contains("io.stat wbytes"));
    }
}
