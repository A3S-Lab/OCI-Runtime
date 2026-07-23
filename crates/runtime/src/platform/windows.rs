use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem;
use std::ptr;

use a3s_oci_core::{
    CapabilityStatus, DriverCapability, DriverKind, DriverReadiness, IsolationClass,
    RuntimeFeatures,
};
use thiserror::Error;
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use crate::WhpxSmokeReport;

const WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT: u32 = 0;

type WhvGetCapability = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type WhvCreatePartition = unsafe extern "system" fn(*mut *mut c_void) -> i32;
type WhvDeletePartition = unsafe extern "system" fn(*mut c_void) -> i32;
type RawProc = unsafe extern "system" fn() -> isize;

#[derive(Debug, Error)]
enum WhpxApiError {
    #[error("failed to load WinHvPlatform.dll from System32: {0}")]
    Load(std::io::Error),
    #[error("WinHvPlatform.dll does not export {symbol}: {source}")]
    MissingSymbol {
        symbol: &'static str,
        source: std::io::Error,
    },
    #[error("{operation} failed with HRESULT 0x{hresult:08X}")]
    Hresult {
        operation: &'static str,
        hresult: u32,
    },
    #[error("{operation} returned only {written} capability bytes")]
    ShortCapability {
        operation: &'static str,
        written: u32,
    },
    #[error("WHvCreatePartition succeeded without returning a partition handle")]
    MissingPartitionHandle,
}

struct Module(HMODULE);

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-null module returned by `LoadLibraryExW`
        // and this guard owns exactly one reference to it.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

struct WhpxApi {
    _module: Module,
    get_capability: WhvGetCapability,
    create_partition: WhvCreatePartition,
    delete_partition: WhvDeletePartition,
}

impl WhpxApi {
    fn load() -> Result<Self, WhpxApiError> {
        let mut dll_name: Vec<u16> = "WinHvPlatform.dll".encode_utf16().collect();
        dll_name.push(0);

        // SAFETY: `dll_name` is NUL terminated and valid for the duration of
        // the call. Restricting lookup to System32 prevents current-directory
        // DLL preloading.
        let module = unsafe {
            LoadLibraryExW(
                dll_name.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(WhpxApiError::Load(std::io::Error::last_os_error()));
        }
        let module = Module(module);

        let get_capability_raw =
            resolve_symbol(module.0, b"WHvGetCapability\0", "WHvGetCapability")?;
        let create_partition_raw =
            resolve_symbol(module.0, b"WHvCreatePartition\0", "WHvCreatePartition")?;
        let delete_partition_raw =
            resolve_symbol(module.0, b"WHvDeletePartition\0", "WHvDeletePartition")?;

        // SAFETY: These signatures are defined by WinHvPlatform.h and the
        // symbols were loaded from the system WinHvPlatform.dll.
        let get_capability =
            unsafe { mem::transmute::<RawProc, WhvGetCapability>(get_capability_raw) };
        // SAFETY: See the signature and module provenance above.
        let create_partition =
            unsafe { mem::transmute::<RawProc, WhvCreatePartition>(create_partition_raw) };
        // SAFETY: See the signature and module provenance above.
        let delete_partition =
            unsafe { mem::transmute::<RawProc, WhvDeletePartition>(delete_partition_raw) };

        Ok(Self {
            _module: module,
            get_capability,
            create_partition,
            delete_partition,
        })
    }

    fn hypervisor_present(&self) -> Result<bool, WhpxApiError> {
        let mut capability = 0_u64;
        let mut written = 0_u32;

        // SAFETY: The output buffer is writable for eight bytes, which the
        // WHPX documentation requires for currently defined capabilities.
        let result = unsafe {
            (self.get_capability)(
                WHV_CAPABILITY_CODE_HYPERVISOR_PRESENT,
                ptr::from_mut(&mut capability).cast(),
                mem::size_of_val(&capability) as u32,
                &mut written,
            )
        };
        check_hresult("WHvGetCapability(HypervisorPresent)", result)?;
        if written < mem::size_of::<i32>() as u32 {
            return Err(WhpxApiError::ShortCapability {
                operation: "WHvGetCapability(HypervisorPresent)",
                written,
            });
        }

        Ok((capability as u32) != 0)
    }

    fn partition_object_round_trip(&self) -> Result<(), WhpxApiError> {
        let mut partition = ptr::null_mut();

        // SAFETY: `partition` is a valid writable out pointer.
        let create_result = unsafe { (self.create_partition)(&mut partition) };
        if let Err(error) = check_hresult("WHvCreatePartition", create_result) {
            if !partition.is_null() {
                // SAFETY: A failing create unexpectedly returned a handle.
                // Attempting deletion is the only documented cleanup path.
                unsafe {
                    (self.delete_partition)(partition);
                }
            }
            return Err(error);
        }
        if partition.is_null() {
            return Err(WhpxApiError::MissingPartitionHandle);
        }

        // SAFETY: The handle was returned by `WHvCreatePartition` and is
        // deleted exactly once before this function returns.
        let delete_result = unsafe { (self.delete_partition)(partition) };
        check_hresult("WHvDeletePartition", delete_result)
    }
}

fn resolve_symbol(
    module: HMODULE,
    symbol: &'static [u8],
    display_name: &'static str,
) -> Result<RawProc, WhpxApiError> {
    // SAFETY: `module` is live and `symbol` is a NUL-terminated static byte
    // string.
    let address = unsafe { GetProcAddress(module, symbol.as_ptr()) };
    address.ok_or_else(|| WhpxApiError::MissingSymbol {
        symbol: display_name,
        source: std::io::Error::last_os_error(),
    })
}

fn check_hresult(operation: &'static str, result: i32) -> Result<(), WhpxApiError> {
    if result >= 0 {
        Ok(())
    } else {
        Err(WhpxApiError::Hresult {
            operation,
            hresult: result as u32,
        })
    }
}

struct ProbeObservation {
    dll_loaded: bool,
    hypervisor_present: bool,
    reason: Option<String>,
}

fn observe_whpx() -> ProbeObservation {
    let api = match WhpxApi::load() {
        Ok(api) => api,
        Err(error) => {
            return ProbeObservation {
                dll_loaded: false,
                hypervisor_present: false,
                reason: Some(error.to_string()),
            };
        }
    };

    match api.hypervisor_present() {
        Ok(true) => ProbeObservation {
            dll_loaded: true,
            hypervisor_present: true,
            reason: None,
        },
        Ok(false) => ProbeObservation {
            dll_loaded: true,
            hypervisor_present: false,
            reason: Some("Windows hypervisor is not running".to_string()),
        },
        Err(error) => ProbeObservation {
            dll_loaded: true,
            hypervisor_present: false,
            reason: Some(error.to_string()),
        },
    }
}

fn capability_from_observation(observation: ProbeObservation) -> DriverCapability {
    let status = if observation.dll_loaded && observation.hypervisor_present {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::Unavailable
    };
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "win_hv_platform_dll".to_string(),
        observation.dll_loaded.to_string(),
    );
    evidence.insert(
        "hypervisor_present".to_string(),
        observation.hypervisor_present.to_string(),
    );

    DriverCapability {
        driver: DriverKind::LibkrunWhpx,
        status,
        readiness: DriverReadiness::ProbeOnly,
        isolation_classes: vec![
            IsolationClass::DedicatedVm,
            IsolationClass::SharedGuestKernel,
        ],
        reason: observation.reason,
        evidence,
    }
}

pub(crate) fn features() -> RuntimeFeatures {
    RuntimeFeatures::current(vec![capability_from_observation(observe_whpx())])
}

pub(crate) fn whpx_smoke() -> WhpxSmokeReport {
    let api = match WhpxApi::load() {
        Ok(api) => api,
        Err(error) => return WhpxSmokeReport::unavailable(false, false, error.to_string()),
    };

    match api.hypervisor_present() {
        Ok(true) => {}
        Ok(false) => {
            return WhpxSmokeReport::unavailable(true, false, "Windows hypervisor is not running");
        }
        Err(error) => return WhpxSmokeReport::unavailable(true, false, error.to_string()),
    }

    match api.partition_object_round_trip() {
        Ok(()) => WhpxSmokeReport::success(),
        Err(error) => WhpxSmokeReport::unavailable(true, true, error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use a3s_oci_core::{CapabilityStatus, DriverReadiness};

    use super::{capability_from_observation, features, ProbeObservation};

    #[test]
    fn available_whpx_remains_probe_only() {
        let capability = capability_from_observation(ProbeObservation {
            dll_loaded: true,
            hypervisor_present: true,
            reason: None,
        });

        assert_eq!(capability.status, CapabilityStatus::Available);
        assert_eq!(capability.readiness, DriverReadiness::ProbeOnly);
        assert!(!capability.can_launch());
    }

    #[test]
    fn missing_hypervisor_is_reported_without_launch_support() {
        let capability = capability_from_observation(ProbeObservation {
            dll_loaded: true,
            hypervisor_present: false,
            reason: Some("Windows hypervisor is not running".to_string()),
        });

        assert_eq!(capability.status, CapabilityStatus::Unavailable);
        assert!(!capability.can_launch());
        assert_eq!(
            capability.reason.as_deref(),
            Some("Windows hypervisor is not running")
        );
    }

    #[test]
    fn real_probe_returns_one_whpx_entry() {
        let inventory = features();
        assert_eq!(inventory.drivers.len(), 1);
        assert_eq!(inventory.drivers[0].readiness, DriverReadiness::ProbeOnly);
    }
}
