use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{namespace_error, NamespacePlan, TimeOffset};

pub(super) fn apply_offsets(plan: &NamespacePlan) -> Result<()> {
    let mut requested = BTreeMap::new();
    if let Some(offset) = plan.monotonic_offset() {
        requested.insert("monotonic", offset);
    }
    if let Some(offset) = plan.boottime_offset() {
        requested.insert("boottime", offset);
    }
    if requested.is_empty() {
        return Ok(());
    }

    let payload = requested
        .iter()
        .map(|(clock, offset)| format!("{clock} {} {}\n", offset.secs, offset.nanosecs))
        .collect::<String>();
    let path = Path::new("/proc/self/timens_offsets");
    let mut file = OpenOptions::new().write(true).open(path).map_err(|error| {
        namespace_error(
            ErrorCode::FailedPrecondition,
            format!("failed to open Linux time namespace offsets: {error}"),
        )
    })?;
    let written = file.write(payload.as_bytes()).map_err(|error| {
        namespace_error(
            ErrorCode::PermissionDenied,
            format!("failed to apply Linux time namespace offsets: {error}"),
        )
    })?;
    if written != payload.len() {
        return Err(namespace_error(
            ErrorCode::Internal,
            format!(
                "Linux time namespace offset write was partial: {written}/{} bytes",
                payload.len()
            ),
        ));
    }
    let actual = std::fs::read_to_string(path).map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!("failed to verify Linux time namespace offsets: {error}"),
        )
    })?;
    let actual = parse_offsets(&actual)?;
    if actual == requested {
        Ok(())
    } else {
        Err(namespace_error(
            ErrorCode::FailedPrecondition,
            "Linux time namespace offsets read back differently from the OCI configuration",
        ))
    }
}

fn parse_offsets(contents: &str) -> Result<BTreeMap<&str, TimeOffset>> {
    contents
        .lines()
        .map(|line| {
            let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
            if fields.len() != 3 {
                return Err(namespace_error(
                    ErrorCode::FailedPrecondition,
                    "Linux time namespace offset line does not contain three fields",
                ));
            }
            let clock = match fields[0] {
                "monotonic" => "monotonic",
                "boottime" => "boottime",
                other => {
                    return Err(namespace_error(
                        ErrorCode::FailedPrecondition,
                        format!("Linux returned unexpected time namespace clock `{other}`"),
                    ));
                }
            };
            let secs = fields[1].parse::<i64>().map_err(|error| {
                namespace_error(
                    ErrorCode::FailedPrecondition,
                    format!("Linux returned invalid {clock} seconds: {error}"),
                )
            })?;
            let nanosecs = fields[2].parse::<u32>().map_err(|error| {
                namespace_error(
                    ErrorCode::FailedPrecondition,
                    format!("Linux returned invalid {clock} nanoseconds: {error}"),
                )
            })?;
            Ok((clock, TimeOffset { secs, nanosecs }))
        })
        .collect()
}
