/// One exact native file carried by a runtime bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeFile {
    pub(crate) name: &'static str,
    pub(crate) size: u64,
    pub(crate) sha256: &'static str,
}

/// Exact guest-kernel bundle exported by one firmware object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeKernel {
    pub(crate) size: usize,
    pub(crate) sha256: &'static str,
    pub(crate) guest_load_address: u64,
    pub(crate) entry_address: u64,
}

/// One target-specific, checksum-pinned libkrun runtime bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuntimeBundle {
    pub(crate) target_os: &'static str,
    pub(crate) target_arch: &'static str,
    pub(crate) platform: &'static str,
    pub(crate) archive: &'static str,
    pub(crate) archive_size: u64,
    pub(crate) archive_sha256: &'static str,
    pub(crate) files: &'static [RuntimeFile],
    pub(crate) kernel: RuntimeKernel,
}

const WINDOWS_X86_64_FILES: &[RuntimeFile] = &[
    RuntimeFile {
        name: "krun.dll",
        size: 7_428_608,
        sha256: "f21293b65ee16058c9014b543c708d84c50dc28d7775dbd77bac32faabafa59e",
    },
    RuntimeFile {
        name: "krun.lib",
        size: 11_870,
        sha256: "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d",
    },
    RuntimeFile {
        name: "libkrunfw.dll",
        size: 21_473_280,
        sha256: "44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077",
    },
];

const MACOS_AARCH64_FILES: &[RuntimeFile] = &[
    RuntimeFile {
        name: "libkrun.1.17.0.dylib",
        size: 4_557_488,
        sha256: "c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d",
    },
    RuntimeFile {
        name: "libkrunfw.5.dylib",
        size: 22_952_096,
        sha256: "841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4",
    },
];

const LINUX_AARCH64_FILES: &[RuntimeFile] = &[
    RuntimeFile {
        name: "libkrun.so.1.17.0",
        size: 4_918_753,
        sha256: "02236ec44afac5a1d1831fea1dda9a6250a67a5c5c6d47550dfdb72591b0fde3",
    },
    RuntimeFile {
        name: "libkrunfw.so.5",
        size: 23_004_041,
        sha256: "b440b30751cefb2e9325d39853c64cc397acc9d72cdedc5a07a5e56daf553e46",
    },
];

const LINUX_X86_64_FILES: &[RuntimeFile] = &[
    RuntimeFile {
        name: "libkrun.so.1.17.0",
        size: 5_824_233,
        sha256: "5a1fdec0e6fc3021aaa6314703b939c4094694662251f6219e8a7ebb1a91390c",
    },
    RuntimeFile {
        name: "libkrunfw.so.5",
        size: 19_206_985,
        sha256: "dfe9796599c397ef914f6948e81f47384aca33a404aea32c82ca9134472936d6",
    },
];

pub(crate) const RUNTIME_BUNDLES: &[RuntimeBundle] = &[
    RuntimeBundle {
        target_os: "windows",
        target_arch: "x86_64",
        platform: "windows-x86_64",
        archive: "runtime/windows-x86_64/krun-windows-x64.tar.xz",
        archive_size: 8_106_464,
        archive_sha256: "ce178184bc9e309c9f8fef181312cd6c398fc825807124e31afab949b790627e",
        files: WINDOWS_X86_64_FILES,
        kernel: RuntimeKernel {
            size: 21_364_736,
            sha256: "781375ea09f4279ec5bfeab26ecc7067358a3fc98190467e2ab01cc6e98936dd",
            guest_load_address: 0x0100_0000,
            entry_address: 0x0100_0123,
        },
    },
    RuntimeBundle {
        target_os: "macos",
        target_arch: "aarch64",
        platform: "macos-aarch64",
        archive: "runtime/macos-aarch64/krun-macos-arm64.tar.xz",
        archive_size: 11_701_136,
        archive_sha256: "5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56",
        files: MACOS_AARCH64_FILES,
        kernel: RuntimeKernel {
            size: 22_740_992,
            sha256: "b1180b50148ed14f5fbeadf17288ce8abcf245daa468255b7ff41113bbf01199",
            guest_load_address: 0x8000_0000,
            entry_address: 0x8000_0000,
        },
    },
    RuntimeBundle {
        target_os: "linux",
        target_arch: "aarch64",
        platform: "linux-aarch64",
        archive: "runtime/linux-aarch64/krun-linux-aarch64.tar.xz",
        archive_size: 11_538_808,
        archive_sha256: "f930a75945862ce039646b521783b06268c49cd9470f9d64a66fc585350ce7e4",
        files: LINUX_AARCH64_FILES,
        kernel: RuntimeKernel {
            size: 22_740_992,
            sha256: "b1180b50148ed14f5fbeadf17288ce8abcf245daa468255b7ff41113bbf01199",
            guest_load_address: 0x8000_0000,
            entry_address: 0x8000_0000,
        },
    },
    RuntimeBundle {
        target_os: "linux",
        target_arch: "x86_64",
        platform: "linux-x86_64",
        archive: "runtime/linux-x86_64/krun-linux-x86_64.tar.xz",
        archive_size: 7_471_288,
        archive_sha256: "8df72533d8006ee0a929048e015192f23f57b0582a155a47a616f9272a2bc719",
        files: LINUX_X86_64_FILES,
        kernel: RuntimeKernel {
            size: 19_070_976,
            sha256: "bd183424e2ef6e3adefab5e3820acc647171c960336504cd0751e62aff381819",
            guest_load_address: 0x0100_0000,
            entry_address: 0x0100_0123,
        },
    },
];

pub(crate) fn runtime_bundle(target_os: &str, target_arch: &str) -> Option<&'static RuntimeBundle> {
    RUNTIME_BUNDLES
        .iter()
        .find(|bundle| bundle.target_os == target_os && bundle.target_arch == target_arch)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs::File;
    use std::io::Read;
    use std::path::{Component, Path, PathBuf};

    use sha2::{Digest, Sha256};
    use xz2::read::XzDecoder;

    use super::{runtime_bundle, RuntimeBundle, RUNTIME_BUNDLES};

    #[test]
    fn every_supported_target_has_one_complete_bundle() {
        let mut targets = BTreeSet::new();
        let mut platforms = BTreeSet::new();
        for bundle in RUNTIME_BUNDLES {
            assert!(targets.insert((bundle.target_os, bundle.target_arch)));
            assert!(platforms.insert(bundle.platform));
            assert_eq!(
                runtime_bundle(bundle.target_os, bundle.target_arch),
                Some(bundle)
            );
            assert!(bundle.archive_size > 0);
            assert_sha256(bundle.archive_sha256);
            assert_safe_relative_name(bundle.archive);
            assert!(bundle.kernel.size > 0);
            assert_sha256(bundle.kernel.sha256);
            assert!(bundle.kernel.guest_load_address > 0);
            assert!(bundle.kernel.entry_address > 0);

            let mut names = BTreeSet::new();
            for file in bundle.files {
                assert!(names.insert(file.name));
                assert!(file.size > 0);
                assert_sha256(file.sha256);
                assert_safe_relative_name(file.name);
            }
        }

        assert!(runtime_bundle("linux", "riscv64").is_none());
        assert!(runtime_bundle("freebsd", "x86_64").is_none());
    }

    #[test]
    fn every_checked_in_archive_matches_its_manifest() {
        for bundle in RUNTIME_BUNDLES {
            verify_archive(bundle);
        }
    }

    fn verify_archive(bundle: &RuntimeBundle) {
        let archive_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(bundle.archive);
        let metadata = std::fs::metadata(&archive_path).expect("inspect runtime archive");
        assert_eq!(metadata.len(), bundle.archive_size, "{}", bundle.platform);
        assert_eq!(
            sha256_reader(File::open(&archive_path).expect("open runtime archive")),
            bundle.archive_sha256,
            "{}",
            bundle.platform
        );

        let decoder = XzDecoder::new(File::open(&archive_path).expect("open runtime archive"));
        let mut archive = tar::Archive::new(decoder);
        let mut seen = BTreeSet::new();
        for entry in archive.entries().expect("read runtime archive") {
            let mut entry = entry.expect("read runtime entry");
            assert!(entry.header().entry_type().is_file(), "{}", bundle.platform);
            let path = entry.path().expect("read runtime entry path");
            assert_eq!(path.components().count(), 1, "{}", bundle.platform);
            let name = path.to_str().expect("runtime entry path is UTF-8");
            let expected = bundle
                .files
                .iter()
                .find(|file| file.name == name)
                .expect("runtime entry is declared");
            assert!(seen.insert(name.to_string()), "{}", bundle.platform);
            assert_eq!(entry.size(), expected.size, "{}", bundle.platform);
            assert_eq!(
                sha256_reader(&mut entry),
                expected.sha256,
                "{}",
                bundle.platform
            );

            if bundle.target_os == "linux" {
                assert_eq!(entry.header().uid().expect("read entry uid"), 0);
                assert_eq!(entry.header().gid().expect("read entry gid"), 0);
                assert_eq!(entry.header().mtime().expect("read entry mtime"), 0);
            }
        }

        assert_eq!(seen.len(), bundle.files.len(), "{}", bundle.platform);
    }

    fn assert_sha256(value: &str) {
        assert_eq!(value.len(), 64);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(value, value.to_ascii_lowercase());
    }

    fn assert_safe_relative_name(value: &str) {
        let path = Path::new(value);
        assert!(!path.is_absolute());
        assert!(path
            .components()
            .all(|component| matches!(component, Component::Normal(_))));
    }

    fn sha256_reader(mut reader: impl Read) -> String {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).expect("read hashed content");
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        format!("{:x}", hasher.finalize())
    }
}
