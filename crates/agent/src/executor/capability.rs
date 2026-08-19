use std::io;

use a3s_oci_sdk::oci_spec::runtime::{Capabilities, Capability, LinuxCapabilities};
use a3s_oci_sdk::{oci_linux_capability_number, Error, ErrorCode, Result};
use serde::{Deserialize, Serialize};

mod warning;

use warning::capability_warnings;
pub(super) use warning::report_capability_warnings;
#[cfg(test)]
pub(super) use warning::CapabilitySet;
pub(super) use warning::CapabilityWarning;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_SETPCAP_NUMBER: u32 = oci_linux_capability_number(Capability::Setpcap);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CapabilityPlan {
    bounding: u64,
    effective: u64,
    inheritable: u64,
    permitted: u64,
    ambient: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PreparedCapabilities {
    applied: CapabilityPlan,
    warnings: Vec<CapabilityWarning>,
}

impl PreparedCapabilities {
    pub(super) fn warnings(&self) -> &[CapabilityWarning] {
        &self.warnings
    }

    pub(super) fn apply_after_credentials(&self, target_uid: u32) -> Result<()> {
        self.applied.apply_after_credentials(target_uid)
    }
}

impl CapabilityPlan {
    pub(super) fn from_oci(capabilities: Option<&LinuxCapabilities>) -> Result<Self> {
        let Some(capabilities) = capabilities else {
            return Ok(Self::default());
        };
        let plan = Self {
            bounding: capability_mask(capabilities.bounding().as_ref()),
            effective: capability_mask(capabilities.effective().as_ref()),
            inheritable: capability_mask(capabilities.inheritable().as_ref()),
            permitted: capability_mask(capabilities.permitted().as_ref()),
            ambient: capability_mask(capabilities.ambient().as_ref()),
        };
        if plan.effective & !plan.permitted != 0 {
            return Err(invalid(
                "process.capabilities.effective must be a subset of permitted",
            ));
        }
        if plan.permitted & !plan.bounding != 0 {
            return Err(invalid(
                "process.capabilities.permitted must be a subset of bounding",
            ));
        }
        if plan.inheritable & !plan.bounding != 0 {
            return Err(invalid(
                "process.capabilities.inheritable must be a subset of bounding",
            ));
        }
        if plan.ambient & !(plan.permitted & plan.inheritable) != 0 {
            return Err(invalid(
                "process.capabilities.ambient must be a subset of permitted and inheritable",
            ));
        }
        Ok(plan)
    }

    #[cfg(test)]
    pub(super) const fn bounding_count(self) -> u32 {
        self.bounding.count_ones()
    }

    pub(super) fn validate_exec_ceiling(self, container: Self) -> Result<()> {
        if self.bounding & !container.bounding != 0 {
            Err(invalid(
                "exec process.capabilities.bounding exceeds the configured container ceiling",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn prepare_for_credentials(self, target_uid: u32) -> Result<PreparedCapabilities> {
        let resolved = self.resolve_for_kernel(probe_kernel_capabilities()?);
        resolved.applied.prepare_bounding_set(target_uid)?;
        Ok(resolved)
    }

    fn resolve_for_kernel(self, kernel: KernelCapabilityState) -> PreparedCapabilities {
        // The live bounding set is the hard ceiling for both retained and
        // inheritable capability values. A future recognized OCI name may be
        // above an older kernel's last capability, so mask the probe result by
        // the kernel ceiling before resolving individual process sets.
        let kernel_bounding = kernel.bounding & kernel.supported_mask();
        // Linux permits a process with effective CAP_SETPCAP to add any value
        // from its bounding set to inheritable. Without it, inheritable may
        // only retain values already present in inheritable or permitted.
        let inheritable_authority = if kernel.effective & (1_u64 << CAP_SETPCAP_NUMBER) != 0 {
            kernel_bounding
        } else {
            (kernel.inheritable | kernel.permitted) & kernel_bounding
        };
        let bounding = self.bounding & kernel_bounding;
        // capset cannot raise permitted beyond the caller's current permitted
        // set. Effective and ambient are then constrained by their normative
        // subset relationships, preserving a coherent applied profile after
        // unavailable values are removed.
        let permitted = self.permitted & kernel.permitted & bounding;
        let inheritable = self.inheritable & inheritable_authority & bounding;
        let applied = Self {
            bounding,
            effective: self.effective & permitted,
            inheritable,
            permitted,
            ambient: self.ambient & permitted & inheritable,
        };
        PreparedCapabilities {
            applied,
            warnings: capability_warnings(self, applied),
        }
    }

    fn prepare_bounding_set(self, target_uid: u32) -> Result<()> {
        let last_capability = probe_kernel_capabilities()?.last_capability;
        for capability in 0..=last_capability {
            if self.bounding & (1_u64 << capability) == 0 {
                // SAFETY: `PR_CAPBSET_DROP` consumes the integer capability
                // number and the remaining variadic arguments must be zero.
                if unsafe {
                    libc::prctl(
                        libc::PR_CAPBSET_DROP,
                        libc::c_ulong::from(capability),
                        0,
                        0,
                        0,
                    )
                } != 0
                {
                    return Err(last_os_error(format!(
                        "drop capability {capability} from the bounding set"
                    )));
                }
            }
        }
        if target_uid != 0 && self.permitted != 0 {
            // SAFETY: `PR_SET_KEEPCAPS` takes a boolean integer and zero
            // padding arguments.
            if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
                return Err(last_os_error(
                    "preserve permitted capabilities across the UID transition",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn apply_after_credentials(self, target_uid: u32) -> Result<()> {
        let header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapabilityData {
                effective: self.effective as u32,
                permitted: self.permitted as u32,
                inheritable: self.inheritable as u32,
            },
            CapabilityData {
                effective: (self.effective >> 32) as u32,
                permitted: (self.permitted >> 32) as u32,
                inheritable: (self.inheritable >> 32) as u32,
            },
        ];
        // SAFETY: the header and two-element data array implement the stable
        // Linux capability ABI v3 for the calling thread.
        if unsafe { libc::syscall(libc::SYS_capset, std::ptr::from_ref(&header), data.as_ptr()) }
            != 0
        {
            return Err(last_os_error("apply final process capability sets"));
        }

        // SAFETY: `PR_CAP_AMBIENT_CLEAR_ALL` takes only zero padding.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
        {
            return Err(last_os_error("clear inherited ambient capabilities"));
        }
        for capability in 0..=probe_kernel_capabilities()?.last_capability {
            if self.ambient & (1_u64 << capability) != 0
                // SAFETY: the capability number was validated against the
                // running kernel's cap_last_cap value.
                && unsafe {
                    libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE,
                        libc::c_ulong::from(capability),
                        0,
                        0,
                    )
                } != 0
            {
                return Err(last_os_error(format!(
                    "raise ambient capability {capability}"
                )));
            }
        }
        if target_uid != 0 && self.permitted != 0 {
            // SAFETY: disable the temporary keep-caps mode after the final
            // capability sets have been applied.
            if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) } != 0 {
                return Err(last_os_error("disable keep-caps mode"));
            }
        }
        verify_sets(self)
    }
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn capability_mask(capabilities: Option<&Capabilities>) -> u64 {
    capabilities
        .into_iter()
        .flatten()
        .fold(0_u64, |mask, capability| {
            mask | (1_u64 << oci_linux_capability_number(*capability))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelCapabilityState {
    last_capability: u32,
    bounding: u64,
    effective: u64,
    permitted: u64,
    inheritable: u64,
}

impl KernelCapabilityState {
    const fn supported_mask(self) -> u64 {
        if self.last_capability == 63 {
            u64::MAX
        } else {
            (1_u64 << (self.last_capability + 1)) - 1
        }
    }
}

fn probe_kernel_capabilities() -> Result<KernelCapabilityState> {
    let mut last_capability = None;
    let mut bounding = 0_u64;
    for capability in 0..=64 {
        // SAFETY: `PR_CAPBSET_READ` consumes the integer capability number
        // and zero padding arguments without mutating process state.
        let result = unsafe {
            libc::prctl(
                libc::PR_CAPBSET_READ,
                libc::c_ulong::from(capability),
                0,
                0,
                0,
            )
        };
        if result >= 0 {
            if capability == 64 {
                return Err(security_error(
                    ErrorCode::Unsupported,
                    "kernel capability ceiling exceeds the 64-bit OCI capability model",
                ));
            }
            if result == 1 {
                bounding |= 1_u64 << capability;
            } else if result != 0 {
                return Err(security_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "kernel returned invalid bounding-set value {result} for capability \
                         {capability}"
                    ),
                ));
            }
            last_capability = Some(capability);
            continue;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINVAL) {
            break;
        }
        return Err(security_error(
            ErrorCode::FailedPrecondition,
            format!("failed to probe kernel capability {capability}: {error}"),
        ));
    }
    let value = last_capability.ok_or_else(|| {
        security_error(
            ErrorCode::Unsupported,
            "kernel did not expose a supported capability range",
        )
    })?;
    let current = read_thread_capability_sets("inspect current process capability sets")?;
    Ok(KernelCapabilityState {
        last_capability: value,
        bounding,
        effective: current.effective,
        permitted: current.permitted,
        inheritable: current.inheritable,
    })
}

fn read_thread_capability_sets(operation: &str) -> Result<CapabilityPlan> {
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData::default(), CapabilityData::default()];
    // SAFETY: the writable header and two-element data array implement the
    // stable Linux capability ABI v3 for the calling thread.
    if unsafe {
        libc::syscall(
            libc::SYS_capget,
            std::ptr::from_mut(&mut header),
            data.as_mut_ptr(),
        )
    } != 0
    {
        return Err(last_os_error(operation));
    }
    Ok(CapabilityPlan {
        bounding: 0,
        effective: u64::from(data[0].effective) | (u64::from(data[1].effective) << 32),
        permitted: u64::from(data[0].permitted) | (u64::from(data[1].permitted) << 32),
        inheritable: u64::from(data[0].inheritable) | (u64::from(data[1].inheritable) << 32),
        ambient: 0,
    })
}

fn verify_sets(expected: CapabilityPlan) -> Result<()> {
    let current = read_thread_capability_sets("verify final process capability sets")?;
    let kernel = probe_kernel_capabilities()?;
    let actual = CapabilityPlan {
        bounding: kernel.bounding,
        effective: current.effective,
        permitted: current.permitted,
        inheritable: current.inheritable,
        ambient: ambient_mask(kernel.last_capability)?,
    };
    ensure_exact_sets(expected, actual)
}

fn ensure_exact_sets(expected: CapabilityPlan, actual: CapabilityPlan) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(security_error(
            ErrorCode::FailedPrecondition,
            format!(
                "process capability sets differ after enforcement: expected {expected:?}, actual \
                 {actual:?}"
            ),
        ))
    }
}

fn ambient_mask(last_capability: u32) -> Result<u64> {
    let mut mask = 0_u64;
    for capability in 0..=last_capability {
        // SAFETY: `PR_CAP_AMBIENT_IS_SET` reads the validated capability bit.
        let value = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                libc::c_ulong::from(capability),
                0,
                0,
            )
        };
        if value < 0 {
            return Err(last_os_error(format!(
                "inspect ambient capability {capability}"
            )));
        }
        if value == 1 {
            mask |= 1_u64 << capability;
        }
    }
    Ok(mask)
}

fn invalid(message: impl Into<String>) -> Error {
    security_error(ErrorCode::InvalidArgument, message)
}

fn last_os_error(operation: impl Into<String>) -> Error {
    security_error(
        ErrorCode::PermissionDenied,
        format!(
            "failed to {}: {}",
            operation.into(),
            io::Error::last_os_error()
        ),
    )
}

fn security_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("apply-process-capabilities")
}

#[cfg(test)]
mod tests;
