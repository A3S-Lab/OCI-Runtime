//! Fixed OCI Linux device inventory shared by executor and qualification code.

/// One normative default character device made available to Linux containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciLinuxDefaultDeviceNode {
    /// Absolute path inside the container root filesystem.
    pub path: &'static str,
    /// Linux character-device major number.
    pub major: u32,
    /// Linux character-device minor number.
    pub minor: u32,
    /// Exact POSIX permission bits.
    pub mode: u32,
}

/// Fixed OCI Linux default character-device set.
pub const OCI_LINUX_DEFAULT_DEVICE_NODES: [OciLinuxDefaultDeviceNode; 6] = [
    OciLinuxDefaultDeviceNode {
        path: "/dev/null",
        major: 1,
        minor: 3,
        mode: 0o666,
    },
    OciLinuxDefaultDeviceNode {
        path: "/dev/zero",
        major: 1,
        minor: 5,
        mode: 0o666,
    },
    OciLinuxDefaultDeviceNode {
        path: "/dev/full",
        major: 1,
        minor: 7,
        mode: 0o666,
    },
    OciLinuxDefaultDeviceNode {
        path: "/dev/random",
        major: 1,
        minor: 8,
        mode: 0o666,
    },
    OciLinuxDefaultDeviceNode {
        path: "/dev/urandom",
        major: 1,
        minor: 9,
        mode: 0o666,
    },
    OciLinuxDefaultDeviceNode {
        path: "/dev/tty",
        major: 5,
        minor: 0,
        mode: 0o666,
    },
];
