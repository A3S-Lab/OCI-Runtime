use std::ffi::c_void;

const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x0000_1000;
const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x0000_0200;
const ERROR_ACCESS_DENIED: u32 = 5;
const INVALID_WHPX_CAPABILITY: i32 = i32::MAX;
const WHPX_PROCESSOR_COUNT_PROPERTY: i32 = 8191;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
const WINDOWS_RNG_INITIALIZATION_STAGES: usize = 2;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn FormatMessageW(
        flags: u32,
        source: *const c_void,
        message_id: u32,
        language_id: u32,
        buffer: *mut u16,
        size: u32,
        arguments: *const c_void,
    ) -> u32;
}

#[link(name = "WinHvPlatform")]
unsafe extern "system" {
    fn WHvGetCapability(
        capability_code: i32,
        capability_buffer: *mut c_void,
        capability_buffer_size_in_bytes: u32,
        written_size_in_bytes: *mut u32,
    ) -> i32;
    fn WHvCreatePartition(partition: *mut *mut c_void) -> i32;
    fn WHvSetPartitionProperty(
        partition: *mut c_void,
        property_code: i32,
        property: *const c_void,
        property_size: u32,
    ) -> i32;
    fn WHvSetupPartition(partition: *mut c_void) -> i32;
    fn WHvCreateVirtualProcessor(partition: *mut c_void, index: u32, flags: u32) -> i32;
    fn WHvDeleteVirtualProcessor(partition: *mut c_void, index: u32) -> i32;
    fn WHvDeletePartition(partition: *mut c_void) -> i32;
}

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        algorithm: *mut c_void,
        buffer: *mut u8,
        buffer_size: u32,
        flags: u32,
    ) -> i32;
}

trait BaselineApi {
    fn format_system_message(&mut self) -> u32;
    fn query_invalid_whpx_capability(&mut self) -> i32;
    fn create_partition(&mut self) -> (i32, usize);
    fn set_processor_count(&mut self, partition: usize) -> i32;
    fn setup_partition(&mut self, partition: usize) -> i32;
    fn create_virtual_processor(&mut self, partition: usize) -> i32;
    fn delete_virtual_processor(&mut self, partition: usize) -> i32;
    fn delete_partition(&mut self, partition: usize) -> i32;
    fn generate_random_byte(&mut self) -> i32;
}

struct NativeBaselineApi;

impl BaselineApi for NativeBaselineApi {
    fn format_system_message(&mut self) -> u32 {
        let mut message = [0u16; 512];
        // SAFETY: the output buffer is writable for the declared number of
        // UTF-16 units. A null source requests the operating-system table.
        unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                std::ptr::null(),
                ERROR_ACCESS_DENIED,
                0,
                message.as_mut_ptr(),
                message.len() as u32,
                std::ptr::null(),
            )
        }
    }

    fn query_invalid_whpx_capability(&mut self) -> i32 {
        let mut capability = 0u64;
        let mut written = 0u32;
        // SAFETY: both output pointers are writable. The invalid capability
        // code has no side effects and initializes WHPX failure-reporting
        // process state before the handle baseline is captured.
        unsafe {
            WHvGetCapability(
                INVALID_WHPX_CAPABILITY,
                (&mut capability as *mut u64).cast(),
                std::mem::size_of::<u64>() as u32,
                &mut written,
            )
        }
    }

    fn create_partition(&mut self) -> (i32, usize) {
        let mut partition = std::ptr::null_mut();
        // SAFETY: `partition` is a writable out pointer.
        let status = unsafe { WHvCreatePartition(&mut partition) };
        (status, partition as usize)
    }

    fn set_processor_count(&mut self, partition: usize) -> i32 {
        let processor_count = 1u32;
        // SAFETY: `partition` came from WHvCreatePartition and the property is
        // the documented four-byte processor-count value.
        unsafe {
            WHvSetPartitionProperty(
                partition as *mut c_void,
                WHPX_PROCESSOR_COUNT_PROPERTY,
                (&processor_count as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
            )
        }
    }

    fn setup_partition(&mut self, partition: usize) -> i32 {
        // SAFETY: the partition is live and has a processor-count property.
        unsafe { WHvSetupPartition(partition as *mut c_void) }
    }

    fn create_virtual_processor(&mut self, partition: usize) -> i32 {
        // SAFETY: the set-up partition exposes exactly one virtual processor.
        unsafe { WHvCreateVirtualProcessor(partition as *mut c_void, 0, 0) }
    }

    fn delete_virtual_processor(&mut self, partition: usize) -> i32 {
        // SAFETY: virtual processor zero was created by this initialization
        // lifecycle and has never been entered.
        unsafe { WHvDeleteVirtualProcessor(partition as *mut c_void, 0) }
    }

    fn delete_partition(&mut self, partition: usize) -> i32 {
        // SAFETY: the handle came from WHvCreatePartition and is released once.
        unsafe { WHvDeletePartition(partition as *mut c_void) }
    }

    fn generate_random_byte(&mut self) -> i32 {
        let mut byte = 0u8;
        // SAFETY: the one-byte output is writable and a null algorithm handle
        // is valid with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
        unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                &mut byte,
                1,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        }
    }
}

pub(crate) fn initialize_windows_handle_baseline() -> Result<(), String> {
    initialize_with(&mut NativeBaselineApi)
}

fn initialize_with(api: &mut impl BaselineApi) -> Result<(), String> {
    if api.format_system_message() == 0 {
        return Err(format!(
            "failed to initialize Windows localized error resources: {}",
            std::io::Error::last_os_error()
        ));
    }

    let capability_status = api.query_invalid_whpx_capability();
    if capability_status >= 0 {
        return Err("the invalid WHPX capability initialization unexpectedly succeeded".into());
    }

    initialize_whpx_partition(api)?;

    for stage in 1..=WINDOWS_RNG_INITIALIZATION_STAGES {
        let status = api.generate_random_byte();
        if status < 0 {
            return Err(format!(
                "failed to initialize Windows system RNG stage {stage}: 0x{:08x}",
                status as u32
            ));
        }
    }

    Ok(())
}

fn initialize_whpx_partition(api: &mut impl BaselineApi) -> Result<(), String> {
    let (create_status, partition) = api.create_partition();
    if create_status < 0 {
        let primary = whpx_error("WHvCreatePartition", create_status);
        if partition == 0 {
            return Err(primary);
        }
        return Err(with_cleanup(
            primary,
            cleanup_partition(api, partition, false),
        ));
    }
    if partition == 0 {
        return Err("WHvCreatePartition succeeded without returning a partition handle".into());
    }

    let property_status = api.set_processor_count(partition);
    if property_status < 0 {
        return Err(with_cleanup(
            whpx_error("WHvSetPartitionProperty(ProcessorCount)", property_status),
            cleanup_partition(api, partition, false),
        ));
    }

    let setup_status = api.setup_partition(partition);
    if setup_status < 0 {
        return Err(with_cleanup(
            whpx_error("WHvSetupPartition", setup_status),
            cleanup_partition(api, partition, false),
        ));
    }

    let processor_status = api.create_virtual_processor(partition);
    if processor_status < 0 {
        return Err(with_cleanup(
            whpx_error("WHvCreateVirtualProcessor", processor_status),
            cleanup_partition(api, partition, false),
        ));
    }

    cleanup_partition(api, partition, true)
}

fn cleanup_partition(
    api: &mut impl BaselineApi,
    partition: usize,
    processor_created: bool,
) -> Result<(), String> {
    let processor_error = processor_created
        .then(|| api.delete_virtual_processor(partition))
        .filter(|status| *status < 0)
        .map(|status| whpx_error("WHvDeleteVirtualProcessor", status));
    let partition_status = api.delete_partition(partition);
    let partition_error =
        (partition_status < 0).then(|| whpx_error("WHvDeletePartition", partition_status));

    match (processor_error, partition_error) {
        (None, None) => Ok(()),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (Some(processor), Some(partition)) => Err(format!("{processor}; {partition}")),
    }
}

fn with_cleanup(primary: String, cleanup: Result<(), String>) -> String {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => format!("{primary}; cleanup failed: {cleanup}"),
    }
}

fn whpx_error(operation: &str, status: i32) -> String {
    format!("{operation} failed with HRESULT 0x{:08x}", status as u32)
}

#[cfg(test)]
mod tests {
    use super::{initialize_with, BaselineApi};

    struct FakeApi {
        calls: Vec<&'static str>,
        format_length: u32,
        capability_status: i32,
        create_status: i32,
        partition: usize,
        property_status: i32,
        setup_status: i32,
        processor_status: i32,
        delete_processor_status: i32,
        delete_partition_status: i32,
        random_status: i32,
    }

    impl Default for FakeApi {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                format_length: 1,
                capability_status: -1,
                create_status: 0,
                partition: 1,
                property_status: 0,
                setup_status: 0,
                processor_status: 0,
                delete_processor_status: 0,
                delete_partition_status: 0,
                random_status: 0,
            }
        }
    }

    impl BaselineApi for FakeApi {
        fn format_system_message(&mut self) -> u32 {
            self.calls.push("format-message");
            self.format_length
        }

        fn query_invalid_whpx_capability(&mut self) -> i32 {
            self.calls.push("invalid-capability");
            self.capability_status
        }

        fn create_partition(&mut self) -> (i32, usize) {
            self.calls.push("create-partition");
            (self.create_status, self.partition)
        }

        fn set_processor_count(&mut self, _partition: usize) -> i32 {
            self.calls.push("set-processor-count");
            self.property_status
        }

        fn setup_partition(&mut self, _partition: usize) -> i32 {
            self.calls.push("setup-partition");
            self.setup_status
        }

        fn create_virtual_processor(&mut self, _partition: usize) -> i32 {
            self.calls.push("create-vcpu");
            self.processor_status
        }

        fn delete_virtual_processor(&mut self, _partition: usize) -> i32 {
            self.calls.push("delete-vcpu");
            self.delete_processor_status
        }

        fn delete_partition(&mut self, _partition: usize) -> i32 {
            self.calls.push("delete-partition");
            self.delete_partition_status
        }

        fn generate_random_byte(&mut self) -> i32 {
            self.calls.push("random");
            self.random_status
        }
    }

    #[test]
    fn initialization_runs_the_stable_process_global_sequence() {
        let mut api = FakeApi::default();

        initialize_with(&mut api).expect("initialize handle baseline");

        assert_eq!(
            api.calls,
            [
                "format-message",
                "invalid-capability",
                "create-partition",
                "set-processor-count",
                "setup-partition",
                "create-vcpu",
                "delete-vcpu",
                "delete-partition",
                "random",
                "random",
            ]
        );
    }

    #[test]
    fn setup_failure_releases_the_partition() {
        let mut api = FakeApi {
            setup_status: -1,
            ..FakeApi::default()
        };

        let error = initialize_with(&mut api).expect_err("setup must fail");

        assert!(error.contains("WHvSetupPartition"));
        assert_eq!(
            api.calls,
            [
                "format-message",
                "invalid-capability",
                "create-partition",
                "set-processor-count",
                "setup-partition",
                "delete-partition",
            ]
        );
    }

    #[test]
    fn create_failure_releases_an_unexpected_partition_handle() {
        let mut api = FakeApi {
            create_status: -1,
            ..FakeApi::default()
        };

        let error = initialize_with(&mut api).expect_err("create must fail");

        assert!(error.contains("WHvCreatePartition"));
        assert_eq!(
            api.calls,
            [
                "format-message",
                "invalid-capability",
                "create-partition",
                "delete-partition",
            ]
        );
    }

    #[test]
    fn cleanup_attempts_both_releases_and_reports_both_failures() {
        let mut api = FakeApi {
            delete_processor_status: -1,
            delete_partition_status: -2,
            ..FakeApi::default()
        };

        let error = initialize_with(&mut api).expect_err("cleanup must fail");

        assert!(error.contains("WHvDeleteVirtualProcessor"));
        assert!(error.contains("WHvDeletePartition"));
        assert!(api.calls.ends_with(&["delete-vcpu", "delete-partition"]));
        assert!(!api.calls.contains(&"random"));
    }
}
