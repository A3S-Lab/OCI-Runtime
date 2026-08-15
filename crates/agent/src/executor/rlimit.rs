use std::collections::BTreeSet;
use std::io;

use a3s_oci_sdk::oci_spec::runtime::{PosixRlimit, PosixRlimitType};
use a3s_oci_sdk::{Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

const MAX_RLIMITS: usize = 16;

#[cfg(target_env = "musl")]
type NativeRlimitResource = libc::c_int;
#[cfg(not(target_env = "musl"))]
type NativeRlimitResource = libc::__rlimit_resource_t;

/// Validated resource limits retained for init and exec process launch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RlimitPlan {
    limits: Vec<RlimitEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RlimitEntry {
    resource: RlimitResource,
    hard: u64,
    soft: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RlimitResource {
    Cpu,
    Fsize,
    Data,
    Stack,
    Core,
    Rss,
    Nproc,
    Nofile,
    Memlock,
    AddressSpace,
    Locks,
    Sigpending,
    Msgqueue,
    Nice,
    Rtprio,
    Rttime,
}

impl RlimitPlan {
    pub(super) fn from_oci(limits: Option<&[PosixRlimit]>) -> Result<Self> {
        let limits = limits.unwrap_or_default();
        if limits.len() > MAX_RLIMITS {
            return Err(rlimit_error(
                ErrorCode::ResourceExhausted,
                format!(
                    "process.rlimits contains {} entries; maximum is {MAX_RLIMITS}",
                    limits.len()
                ),
                "plan-process-rlimits",
            ));
        }

        let mut resources = BTreeSet::new();
        let mut planned = Vec::with_capacity(limits.len());
        for (index, limit) in limits.iter().enumerate() {
            let resource = RlimitResource::from_oci(limit.typ());
            if !resources.insert(resource) {
                return Err(rlimit_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "process.rlimits contains duplicate {} at index {index}",
                        resource.oci_name()
                    ),
                    "plan-process-rlimits",
                ));
            }
            if limit.soft() > limit.hard() {
                return Err(rlimit_error(
                    ErrorCode::InvalidArgument,
                    format!(
                        "process.rlimits[{index}] {} soft must not exceed hard",
                        resource.oci_name()
                    ),
                    "plan-process-rlimits",
                ));
            }
            planned.push(RlimitEntry {
                resource,
                hard: limit.hard(),
                soft: limit.soft(),
            });
        }
        Ok(Self { limits: planned })
    }

    pub(super) fn apply(&self) -> Result<()> {
        for (index, limit) in self.limits.iter().enumerate() {
            let native = limit.as_libc();
            // SAFETY: `native` is a fully initialized Linux rlimit structure,
            // and the resource identifier is selected from libc constants.
            if unsafe { libc::setrlimit(limit.resource.as_libc(), &native) } != 0 {
                let source = io::Error::last_os_error();
                let code = match source.raw_os_error() {
                    Some(libc::EPERM | libc::EACCES) => ErrorCode::PermissionDenied,
                    Some(libc::EINVAL) => ErrorCode::InvalidArgument,
                    _ => ErrorCode::Internal,
                };
                return Err(rlimit_error(
                    code,
                    format!(
                        "failed to apply process.rlimits[{index}] {} soft={} hard={}: {source}",
                        limit.resource.oci_name(),
                        limit.soft,
                        limit.hard
                    ),
                    "apply-process-rlimits",
                ));
            }

            let mut actual = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `actual` is writable and the resource identifier is
            // selected from the same bounded libc constant table as setrlimit.
            if unsafe { libc::getrlimit(limit.resource.as_libc(), &mut actual) } != 0 {
                let source = io::Error::last_os_error();
                return Err(rlimit_error(
                    ErrorCode::Internal,
                    format!(
                        "failed to read back process.rlimits[{index}] {} after apply: {source}",
                        limit.resource.oci_name()
                    ),
                    "verify-process-rlimits",
                ));
            }
            limit.verify_readback(index, actual)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.limits.len()
    }
}

impl RlimitEntry {
    const fn as_libc(self) -> libc::rlimit {
        libc::rlimit {
            rlim_cur: self.soft,
            rlim_max: self.hard,
        }
    }

    fn verify_readback(self, index: usize, actual: libc::rlimit) -> Result<()> {
        if actual.rlim_cur == self.soft && actual.rlim_max == self.hard {
            return Ok(());
        }
        Err(rlimit_error(
            ErrorCode::Internal,
            format!(
                "process.rlimits[{index}] {} read back soft={} hard={}, expected soft={} hard={}",
                self.resource.oci_name(),
                actual.rlim_cur,
                actual.rlim_max,
                self.soft,
                self.hard
            ),
            "verify-process-rlimits",
        ))
    }
}

impl RlimitResource {
    const fn from_oci(resource: PosixRlimitType) -> Self {
        match resource {
            PosixRlimitType::RlimitCpu => Self::Cpu,
            PosixRlimitType::RlimitFsize => Self::Fsize,
            PosixRlimitType::RlimitData => Self::Data,
            PosixRlimitType::RlimitStack => Self::Stack,
            PosixRlimitType::RlimitCore => Self::Core,
            PosixRlimitType::RlimitRss => Self::Rss,
            PosixRlimitType::RlimitNproc => Self::Nproc,
            PosixRlimitType::RlimitNofile => Self::Nofile,
            PosixRlimitType::RlimitMemlock => Self::Memlock,
            PosixRlimitType::RlimitAs => Self::AddressSpace,
            PosixRlimitType::RlimitLocks => Self::Locks,
            PosixRlimitType::RlimitSigpending => Self::Sigpending,
            PosixRlimitType::RlimitMsgqueue => Self::Msgqueue,
            PosixRlimitType::RlimitNice => Self::Nice,
            PosixRlimitType::RlimitRtprio => Self::Rtprio,
            PosixRlimitType::RlimitRttime => Self::Rttime,
        }
    }

    const fn as_libc(self) -> NativeRlimitResource {
        match self {
            Self::Cpu => libc::RLIMIT_CPU,
            Self::Fsize => libc::RLIMIT_FSIZE,
            Self::Data => libc::RLIMIT_DATA,
            Self::Stack => libc::RLIMIT_STACK,
            Self::Core => libc::RLIMIT_CORE,
            Self::Rss => libc::RLIMIT_RSS,
            Self::Nproc => libc::RLIMIT_NPROC,
            Self::Nofile => libc::RLIMIT_NOFILE,
            Self::Memlock => libc::RLIMIT_MEMLOCK,
            Self::AddressSpace => libc::RLIMIT_AS,
            Self::Locks => libc::RLIMIT_LOCKS,
            Self::Sigpending => libc::RLIMIT_SIGPENDING,
            Self::Msgqueue => libc::RLIMIT_MSGQUEUE,
            Self::Nice => libc::RLIMIT_NICE,
            Self::Rtprio => libc::RLIMIT_RTPRIO,
            Self::Rttime => libc::RLIMIT_RTTIME,
        }
    }

    const fn oci_name(self) -> &'static str {
        match self {
            Self::Cpu => "RLIMIT_CPU",
            Self::Fsize => "RLIMIT_FSIZE",
            Self::Data => "RLIMIT_DATA",
            Self::Stack => "RLIMIT_STACK",
            Self::Core => "RLIMIT_CORE",
            Self::Rss => "RLIMIT_RSS",
            Self::Nproc => "RLIMIT_NPROC",
            Self::Nofile => "RLIMIT_NOFILE",
            Self::Memlock => "RLIMIT_MEMLOCK",
            Self::AddressSpace => "RLIMIT_AS",
            Self::Locks => "RLIMIT_LOCKS",
            Self::Sigpending => "RLIMIT_SIGPENDING",
            Self::Msgqueue => "RLIMIT_MSGQUEUE",
            Self::Nice => "RLIMIT_NICE",
            Self::Rtprio => "RLIMIT_RTPRIO",
            Self::Rttime => "RLIMIT_RTTIME",
        }
    }
}

fn rlimit_error(code: ErrorCode, message: impl Into<String>, operation: &'static str) -> Error {
    Error::new(code, message).for_operation(operation)
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use a3s_oci_sdk::oci_spec::runtime::{PosixRlimit, PosixRlimitType};

    use super::{RlimitEntry, RlimitPlan, RlimitResource};

    const CHILD_PROBE: &str = "A3S_OCI_RLIMIT_CHILD_PROBE";
    const APPLY_TEST: &str = "executor::rlimit::tests::applies_nofile_in_an_isolated_process";

    #[test]
    fn maps_every_oci_resource_to_the_architecture_libc_constant() {
        let cases = [
            (PosixRlimitType::RlimitCpu, libc::RLIMIT_CPU),
            (PosixRlimitType::RlimitFsize, libc::RLIMIT_FSIZE),
            (PosixRlimitType::RlimitData, libc::RLIMIT_DATA),
            (PosixRlimitType::RlimitStack, libc::RLIMIT_STACK),
            (PosixRlimitType::RlimitCore, libc::RLIMIT_CORE),
            (PosixRlimitType::RlimitRss, libc::RLIMIT_RSS),
            (PosixRlimitType::RlimitNproc, libc::RLIMIT_NPROC),
            (PosixRlimitType::RlimitNofile, libc::RLIMIT_NOFILE),
            (PosixRlimitType::RlimitMemlock, libc::RLIMIT_MEMLOCK),
            (PosixRlimitType::RlimitAs, libc::RLIMIT_AS),
            (PosixRlimitType::RlimitLocks, libc::RLIMIT_LOCKS),
            (PosixRlimitType::RlimitSigpending, libc::RLIMIT_SIGPENDING),
            (PosixRlimitType::RlimitMsgqueue, libc::RLIMIT_MSGQUEUE),
            (PosixRlimitType::RlimitNice, libc::RLIMIT_NICE),
            (PosixRlimitType::RlimitRtprio, libc::RLIMIT_RTPRIO),
            (PosixRlimitType::RlimitRttime, libc::RLIMIT_RTTIME),
        ];
        for (oci, native) in cases {
            assert_eq!(RlimitResource::from_oci(oci).as_libc(), native);
        }
    }

    #[test]
    fn rejects_mismatched_kernel_readback() {
        let limit = RlimitEntry {
            resource: RlimitResource::Nofile,
            hard: 64,
            soft: 63,
        };
        let error = limit
            .verify_readback(
                0,
                libc::rlimit {
                    rlim_cur: 62,
                    rlim_max: 64,
                },
            )
            .expect_err("mismatched kernel rlimit readback must fail closed");
        assert_eq!(error.code, a3s_oci_sdk::ErrorCode::Internal);
        assert!(error.message.contains("read back soft=62 hard=64"));
        assert!(error.message.contains("expected soft=63 hard=64"));
    }

    #[test]
    fn applies_nofile_in_an_isolated_process() {
        if std::env::var_os(CHILD_PROBE).is_some() {
            let limit: PosixRlimit = serde_json::from_value(serde_json::json!({
                "type": "RLIMIT_NOFILE",
                "hard": 64,
                "soft": 63
            }))
            .expect("decode child rlimit");
            RlimitPlan::from_oci(Some(&[limit]))
                .expect("plan child rlimit")
                .apply()
                .expect("apply child rlimit");

            let mut actual = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `actual` is writable and the resource is a valid libc constant.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut actual) },
                0
            );
            assert_eq!(actual.rlim_cur, 63);
            assert_eq!(actual.rlim_max, 64);
            return;
        }

        let output = Command::new(std::env::current_exe().expect("resolve test executable"))
            .args(["--exact", APPLY_TEST, "--nocapture"])
            .env(CHILD_PROBE, "1")
            .output()
            .expect("run isolated rlimit probe");
        assert!(
            output.status.success(),
            "isolated rlimit probe failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
