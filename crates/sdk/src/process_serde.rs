//! Exact OCI process serialization across SDK and guest-protocol boundaries.
//!
//! `oci-spec` 0.10 derives two Linux scheduler flag spellings from Rust
//! identifiers that do not match the OCI 1.3 schema. This adapter keeps the
//! public and wire representation standards-compliant while retaining the
//! upstream typed process model internally.

use oci_spec::runtime::Process;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::{Error, ErrorCode, Result};

const OCI_RESET_ON_FORK: &str = "SCHED_FLAG_RESET_ON_FORK";
const OCI_DEADLINE_OVERRUN: &str = "SCHED_FLAG_DL_OVERRUN";
const TYPED_RESET_ON_FORK: &str = "SCHED_RESET_ON_FORK";
const TYPED_DEADLINE_OVERRUN: &str = "SCHED_FLAG_D_L_OVERRUN";

/// Serialize an OCI process with the exact scheduler flag names from OCI 1.3.
pub fn serialize<S>(process: &Process, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut value = serde_json::to_value(process).map_err(serde::ser::Error::custom)?;
    normalize_for_wire(&mut value);
    value.serialize(serializer)
}

/// Deserialize an OCI process while accepting the exact scheduler flag names
/// required by OCI 1.3.
pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Process, D::Error>
where
    D: Deserializer<'de>,
{
    let mut value = Value::deserialize(deserializer)?;
    normalize_for_typed_model(&mut value);
    serde_json::from_value(value).map_err(de::Error::custom)
}

/// Decode a standalone standards-compliant OCI process value.
pub fn decode(mut value: Value) -> Result<Process> {
    normalize_for_typed_model(&mut value);
    serde_json::from_value(value).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("invalid OCI process configuration: {error}"),
        )
        .for_operation("decode-oci-process")
    })
}

pub(crate) fn normalize_for_wire(process: &mut Value) {
    normalize_flags(process, |flag| match flag {
        TYPED_RESET_ON_FORK => OCI_RESET_ON_FORK,
        TYPED_DEADLINE_OVERRUN => OCI_DEADLINE_OVERRUN,
        flag => flag,
    });
}

pub(crate) fn normalize_for_typed_model(process: &mut Value) {
    normalize_flags(process, |flag| match flag {
        OCI_RESET_ON_FORK => TYPED_RESET_ON_FORK,
        OCI_DEADLINE_OVERRUN => TYPED_DEADLINE_OVERRUN,
        flag => flag,
    });
}

fn normalize_flags(process: &mut Value, rename: impl Fn(&str) -> &str) {
    let Some(flags) = process
        .get_mut("scheduler")
        .and_then(|scheduler| scheduler.get_mut("flags"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for flag in flags {
        let Some(name) = flag.as_str() else {
            continue;
        };
        let normalized = rename(name);
        if normalized != name {
            *flag = Value::String(normalized.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::{LinuxSchedulerFlag, LinuxSchedulerPolicy};
    use serde::{Deserialize, Serialize};

    use super::decode;

    #[derive(Debug, Serialize, Deserialize)]
    struct ProcessEnvelope {
        #[serde(with = "super")]
        process: oci_spec::runtime::Process,
    }

    fn standard_process() -> serde_json::Value {
        serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/",
            "scheduler": {
                "policy": "SCHED_DEADLINE",
                "flags": [
                    "SCHED_FLAG_RESET_ON_FORK",
                    "SCHED_FLAG_DL_OVERRUN"
                ],
                "runtime": 1024,
                "deadline": 2048,
                "period": 4096
            },
            "noNewPrivileges": true
        })
    }

    #[test]
    fn standalone_decoder_accepts_exact_oci_scheduler_flag_names() {
        let process = decode(standard_process()).expect("decode standard OCI process");
        let scheduler = process.scheduler().as_ref().expect("scheduler");
        assert_eq!(*scheduler.policy(), LinuxSchedulerPolicy::SchedDeadline);
        assert_eq!(
            scheduler.flags().as_deref(),
            Some(
                [
                    LinuxSchedulerFlag::SchedResetOnFork,
                    LinuxSchedulerFlag::SchedFlagDLOverrun,
                ]
                .as_slice()
            )
        );
    }

    #[test]
    fn serde_adapter_round_trips_only_standard_flag_names() {
        let envelope: ProcessEnvelope = serde_json::from_value(serde_json::json!({
            "process": standard_process()
        }))
        .expect("decode process envelope");
        let encoded = serde_json::to_value(envelope).expect("encode process envelope");
        assert_eq!(
            encoded["process"]["scheduler"]["flags"],
            serde_json::json!(["SCHED_FLAG_RESET_ON_FORK", "SCHED_FLAG_DL_OVERRUN"])
        );
    }
}
