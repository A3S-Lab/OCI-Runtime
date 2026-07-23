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

    #[cfg(not(windows))]
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
