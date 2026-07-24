use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

const WINDOWS_RUNTIME_ARCHIVE: &str = "runtime/windows-x86_64/krun-windows-x64.tar.xz";
const WINDOWS_RUNTIME_ARCHIVE_SHA256: &str =
    "c8d14bd0ceb86190effac9c9af12892f1dbb5b82f22123e8524dd375014d5493";
const WINDOWS_RUNTIME_FILES: &[(&str, &str)] = &[
    (
        "krun.dll",
        "e5debc685ae171e3f60a6e3b9c1c4e12a7c3eb943a68ceb1169e153f0cc6c255",
    ),
    (
        "krun.lib",
        "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d",
    ),
    (
        "libkrunfw.dll",
        "44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077",
    ),
];

const MACOS_RUNTIME_ARCHIVE: &str = "runtime/macos-aarch64/krun-macos-arm64.tar.xz";
const MACOS_RUNTIME_ARCHIVE_SHA256: &str =
    "5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56";
const MACOS_RUNTIME_FILES: &[(&str, &str)] = &[
    (
        "libkrun.1.17.0.dylib",
        "c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d",
    ),
    (
        "libkrunfw.5.dylib",
        "841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4",
    ),
];

struct RuntimeBundle {
    platform: &'static str,
    archive: &'static str,
    archive_sha256: &'static str,
    files: &'static [(&'static str, &'static str)],
}

const WINDOWS_RUNTIME: RuntimeBundle = RuntimeBundle {
    platform: "windows-x86_64",
    archive: WINDOWS_RUNTIME_ARCHIVE,
    archive_sha256: WINDOWS_RUNTIME_ARCHIVE_SHA256,
    files: WINDOWS_RUNTIME_FILES,
};

const MACOS_RUNTIME: RuntimeBundle = RuntimeBundle {
    platform: "macos-aarch64",
    archive: MACOS_RUNTIME_ARCHIVE,
    archive_sha256: MACOS_RUNTIME_ARCHIVE_SHA256,
    files: MACOS_RUNTIME_FILES,
};

fn main() {
    println!("cargo:rerun-if-changed={WINDOWS_RUNTIME_ARCHIVE}");
    println!("cargo:rerun-if-changed={MACOS_RUNTIME_ARCHIVE}");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let bundle = match (target_os.as_str(), target_arch.as_str()) {
        ("windows", "x86_64") => &WINDOWS_RUNTIME,
        ("macos", "aarch64") => &MACOS_RUNTIME,
        _ => return,
    };

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not set manifest dir"),
    );
    let archive = manifest_dir.join(bundle.archive);
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let runtime_dir = out_dir.join(format!(
        "{}-runtime-{}",
        bundle.platform,
        &bundle.archive_sha256[..12]
    ));
    install_runtime(&archive, &runtime_dir, bundle)
        .unwrap_or_else(|error| panic!("failed to install {}: {error}", archive.display()));

    let profile_dir = profile_dir(&out_dir).expect("failed to derive Cargo profile directory");
    if target_os == "windows" {
        stage_windows_runtime(&runtime_dir, &profile_dir);
        println!("cargo:rustc-link-search=native={}", runtime_dir.display());
        println!(
            "cargo:rustc-env=A3S_OCI_KRUN_RUNTIME_DIR={}",
            runtime_dir.display()
        );
    } else {
        let staged_runtime = profile_dir.join("a3s-oci-krun-runtime");
        stage_runtime_files(&runtime_dir, &staged_runtime, bundle.files).unwrap_or_else(|error| {
            panic!("failed to stage {} runtime files: {error}", bundle.platform)
        });
        println!(
            "cargo:rustc-env=A3S_OCI_KRUN_RUNTIME_DIR={}",
            staged_runtime.display()
        );
    }
}

fn stage_windows_runtime(runtime_dir: &Path, profile_dir: &Path) {
    for name in ["krun.dll", "libkrunfw.dll"] {
        let source = runtime_dir.join(name);
        copy_runtime_file(&source, &profile_dir.join(name))
            .unwrap_or_else(|error| panic!("failed to stage {}: {error}", source.display()));
        copy_runtime_file(&source, &profile_dir.join("deps").join(name)).unwrap_or_else(|error| {
            panic!("failed to stage {} for tests: {error}", source.display())
        });
    }
}

fn stage_runtime_files(
    runtime_dir: &Path,
    destination_dir: &Path,
    files: &[(&str, &str)],
) -> io::Result<()> {
    for (name, expected) in files {
        let source = runtime_dir.join(name);
        let destination = destination_dir.join(name);
        copy_runtime_file(&source, &destination)?;
        verify_sha256(&destination, expected)?;
    }
    Ok(())
}

fn install_runtime(
    archive_path: &Path,
    runtime_dir: &Path,
    bundle: &RuntimeBundle,
) -> io::Result<()> {
    verify_sha256(archive_path, bundle.archive_sha256)?;
    if runtime_files_match(runtime_dir, bundle.files) {
        return Ok(());
    }

    fs::create_dir_all(runtime_dir)?;
    for (name, _) in bundle.files {
        let path = runtime_dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let decoder = XzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = vec![false; bundle.files.len()];

    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            return Err(invalid_archive(
                bundle,
                "contains a non-file entry".to_string(),
            ));
        }

        let path = entry.path()?;
        let name = path
            .to_str()
            .ok_or_else(|| invalid_archive(bundle, "contains a non-UTF-8 path".to_string()))?;
        if path.components().count() != 1 {
            return Err(invalid_archive(
                bundle,
                format!("contains an unsafe path: {name}"),
            ));
        }
        let Some(index) = bundle
            .files
            .iter()
            .position(|(expected, _)| *expected == name)
        else {
            return Err(invalid_archive(
                bundle,
                format!("contains an unexpected file: {name}"),
            ));
        };
        if seen[index] {
            return Err(invalid_archive(
                bundle,
                format!("contains a duplicate file: {name}"),
            ));
        }

        entry.unpack(runtime_dir.join(name))?;
        seen[index] = true;
    }

    if seen.iter().any(|present| !present) {
        return Err(invalid_archive(bundle, "is incomplete".to_string()));
    }
    if !runtime_files_match(runtime_dir, bundle.files) {
        return Err(invalid_archive(
            bundle,
            "files do not match their pinned checksums".to_string(),
        ));
    }
    Ok(())
}

fn invalid_archive(bundle: &RuntimeBundle, message: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{} runtime archive {message}", bundle.platform),
    )
}

fn runtime_files_match(runtime_dir: &Path, files: &[(&str, &str)]) -> bool {
    files
        .iter()
        .all(|(name, expected)| verify_sha256(&runtime_dir.join(name), expected).is_ok())
}

fn verify_sha256(path: &Path, expected: &str) -> io::Result<()> {
    let actual = file_sha256(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SHA-256 mismatch for {}: expected {expected}, found {actual}",
                path.display()
            ),
        ))
    }
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn profile_dir(out_dir: &Path) -> Option<PathBuf> {
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

fn copy_runtime_file(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::other("runtime destination has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::copy(source, destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{profile_dir, MACOS_RUNTIME_FILES, WINDOWS_RUNTIME_FILES};
    use std::path::Path;

    #[test]
    fn profile_directory_is_derived_from_cargo_out_dir() {
        let out = Path::new(r"C:\target\debug\build\crate-hash\out");
        assert_eq!(profile_dir(out), Some(Path::new(r"C:\target\debug").into()));
    }

    #[test]
    fn runtime_manifest_has_exactly_one_entry_per_required_file() {
        for (files, required) in [
            (
                WINDOWS_RUNTIME_FILES,
                &["krun.dll", "krun.lib", "libkrunfw.dll"][..],
            ),
            (
                MACOS_RUNTIME_FILES,
                &["libkrun.1.17.0.dylib", "libkrunfw.5.dylib"][..],
            ),
        ] {
            assert_eq!(files.len(), required.len());
            for required_name in required {
                assert_eq!(
                    files
                        .iter()
                        .filter(|(name, _)| name == required_name)
                        .count(),
                    1
                );
            }
        }
    }
}
