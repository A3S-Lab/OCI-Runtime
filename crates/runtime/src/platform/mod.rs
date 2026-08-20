#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) use linux::{kvm_driver_capability, native_driver_capability};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use macos::hvf_driver_capability;
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub(crate) use windows::whpx_driver_capability;

use a3s_oci_core::RuntimeFeatures;

use crate::{HvfSmokeReport, WhpxSmokeReport};

pub(crate) fn features() -> RuntimeFeatures {
    #[cfg(windows)]
    {
        windows::features()
    }

    #[cfg(target_os = "linux")]
    {
        linux::features()
    }

    #[cfg(target_os = "macos")]
    {
        macos::features()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        unsupported::features()
    }
}

pub(crate) fn whpx_smoke() -> WhpxSmokeReport {
    #[cfg(windows)]
    {
        windows::whpx_smoke()
    }

    #[cfg(not(windows))]
    {
        unsupported::whpx_smoke()
    }
}

pub(crate) fn hvf_smoke() -> HvfSmokeReport {
    #[cfg(target_os = "macos")]
    {
        macos::hvf_smoke()
    }

    #[cfg(not(target_os = "macos"))]
    {
        unsupported::hvf_smoke()
    }
}
