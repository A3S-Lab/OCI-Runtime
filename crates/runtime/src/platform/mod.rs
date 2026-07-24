#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

use a3s_oci_core::RuntimeFeatures;

use crate::WhpxSmokeReport;

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
