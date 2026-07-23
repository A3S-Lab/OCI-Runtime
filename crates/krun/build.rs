use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

const RUNTIME_ARCHIVE: &str = "runtime/windows-x86_64/krun-windows-x64.tar.xz";
const RUNTIME_ARCHIVE_SHA256: &str =
    "c8d14bd0ceb86190effac9c9af12892f1dbb5b82f22123e8524dd375014d5493";
const RUNTIME_FILES: &[(&str, &str)] = &[
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

fn main() {
    println!("cargo:rerun-if-changed={RUNTIME_ARCHIVE}");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not set manifest dir"),
    );
    let archive = manifest_dir.join(RUNTIME_ARCHIVE);
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let runtime_dir = out_dir.join(format!("windows-runtime-{}", &RUNTIME_ARCHIVE_SHA256[..12]));
    install_runtime(&archive, &runtime_dir)
        .unwrap_or_else(|error| panic!("failed to install {}: {error}", archive.display()));

    let profile_dir = profile_dir(&out_dir).expect("failed to derive Cargo profile directory");
    for name in ["krun.dll", "libkrunfw.dll"] {
        let source = runtime_dir.join(name);
        copy_runtime_file(&source, &profile_dir.join(name))
            .unwrap_or_else(|error| panic!("failed to stage {}: {error}", source.display()));
        copy_runtime_file(&source, &profile_dir.join("deps").join(name)).unwrap_or_else(|error| {
            panic!("failed to stage {} for tests: {error}", source.display())
        });
    }

    println!("cargo:rustc-link-search=native={}", runtime_dir.display());
    println!(
        "cargo:rustc-env=A3S_OCI_KRUN_RUNTIME_DIR={}",
        runtime_dir.display()
    );
}

fn install_runtime(archive_path: &Path, runtime_dir: &Path) -> io::Result<()> {
    verify_sha256(archive_path, RUNTIME_ARCHIVE_SHA256)?;
    if runtime_files_match(runtime_dir) {
        return Ok(());
    }

    fs::create_dir_all(runtime_dir)?;
    for (name, _) in RUNTIME_FILES {
        let path = runtime_dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let decoder = XzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut seen = vec![false; RUNTIME_FILES.len()];

    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows runtime archive contains a non-file entry",
            ));
        }

        let path = entry.path()?;
        let name = path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows runtime archive contains a non-UTF-8 path",
            )
        })?;
        if path.components().count() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Windows runtime archive contains an unsafe path: {name}"),
            ));
        }
        let Some(index) = RUNTIME_FILES
            .iter()
            .position(|(expected, _)| *expected == name)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Windows runtime archive contains an unexpected file: {name}"),
            ));
        };
        if seen[index] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Windows runtime archive contains a duplicate file: {name}"),
            ));
        }

        entry.unpack(runtime_dir.join(name))?;
        seen[index] = true;
    }

    if seen.iter().any(|present| !present) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows runtime archive is incomplete",
        ));
    }
    if !runtime_files_match(runtime_dir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows runtime files do not match their pinned checksums",
        ));
    }
    Ok(())
}

fn runtime_files_match(runtime_dir: &Path) -> bool {
    RUNTIME_FILES
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
    use super::{profile_dir, RUNTIME_FILES};
    use std::path::Path;

    #[test]
    fn profile_directory_is_derived_from_cargo_out_dir() {
        let out = Path::new(r"C:\target\debug\build\crate-hash\out");
        assert_eq!(profile_dir(out), Some(Path::new(r"C:\target\debug").into()));
    }

    #[test]
    fn runtime_manifest_has_exactly_one_entry_per_required_file() {
        assert_eq!(
            RUNTIME_FILES
                .iter()
                .filter(|(name, _)| *name == "krun.dll")
                .count(),
            1
        );
        assert_eq!(
            RUNTIME_FILES
                .iter()
                .filter(|(name, _)| *name == "krun.lib")
                .count(),
            1
        );
        assert_eq!(
            RUNTIME_FILES
                .iter()
                .filter(|(name, _)| *name == "libkrunfw.dll")
                .count(),
            1
        );
    }
}
