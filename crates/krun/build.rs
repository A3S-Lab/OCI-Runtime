use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use xz2::read::XzDecoder;

#[path = "src/runtime_assets.rs"]
mod runtime_assets;

use runtime_assets::{
    runtime_bundle, runtime_bundles, RuntimeBundle, RuntimeFile, RuntimeFileRole,
};

fn main() {
    println!("cargo:rerun-if-changed=src/runtime_assets.rs");
    println!("cargo:rerun-if-changed=runtime/runtime-assets.json");
    let bundles = runtime_bundles()
        .unwrap_or_else(|error| panic!("checked-in runtime asset manifest is invalid: {error}"));
    for bundle in bundles {
        println!("cargo:rerun-if-changed={}", bundle.archive);
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let Some(bundle) = runtime_bundle(&target_os, &target_arch)
        .unwrap_or_else(|error| panic!("checked-in runtime asset manifest is invalid: {error}"))
    else {
        return;
    };

    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo did not set manifest dir"),
    );
    let archive = manifest_dir.join(&bundle.archive);
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
        stage_windows_runtime(&runtime_dir, &profile_dir, bundle);
        println!("cargo:rustc-link-search=native={}", runtime_dir.display());
        println!(
            "cargo:rustc-env=A3S_OCI_KRUN_RUNTIME_DIR={}",
            runtime_dir.display()
        );
    } else {
        let staged_runtime = profile_dir.join("a3s-oci-krun-runtime");
        stage_runtime_files(&runtime_dir, &staged_runtime, &bundle.files).unwrap_or_else(|error| {
            panic!("failed to stage {} runtime files: {error}", bundle.platform)
        });
        println!(
            "cargo:rustc-env=A3S_OCI_KRUN_RUNTIME_DIR={}",
            staged_runtime.display()
        );
    }
}

fn stage_windows_runtime(runtime_dir: &Path, profile_dir: &Path, bundle: &RuntimeBundle) {
    for role in [RuntimeFileRole::Library, RuntimeFileRole::Firmware] {
        let file = bundle.file(role).unwrap_or_else(|| {
            panic!(
                "validated {} bundle is missing the {} role",
                bundle.platform,
                role.as_str()
            )
        });
        let source = runtime_dir.join(&file.name);
        copy_runtime_file(&source, &profile_dir.join(&file.name))
            .unwrap_or_else(|error| panic!("failed to stage {}: {error}", source.display()));
        copy_runtime_file(&source, &profile_dir.join("deps").join(&file.name)).unwrap_or_else(
            |error| panic!("failed to stage {} for tests: {error}", source.display()),
        );
    }
}

fn stage_runtime_files(
    runtime_dir: &Path,
    destination_dir: &Path,
    files: &[RuntimeFile],
) -> io::Result<()> {
    for file in files {
        let source = runtime_dir.join(&file.name);
        let destination = destination_dir.join(&file.name);
        copy_runtime_file(&source, &destination)?;
        verify_runtime_file(&destination, file)?;
    }
    Ok(())
}

fn install_runtime(
    archive_path: &Path,
    runtime_dir: &Path,
    bundle: &RuntimeBundle,
) -> io::Result<()> {
    verify_size(archive_path, bundle.archive_size)?;
    verify_sha256(archive_path, &bundle.archive_sha256)?;
    if runtime_files_match(runtime_dir, &bundle.files) {
        return Ok(());
    }

    fs::create_dir_all(runtime_dir)?;
    for file in &bundle.files {
        let path = runtime_dir.join(&file.name);
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
            .position(|expected| expected.name == name)
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
    if !runtime_files_match(runtime_dir, &bundle.files) {
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

fn runtime_files_match(runtime_dir: &Path, files: &[RuntimeFile]) -> bool {
    files
        .iter()
        .all(|file| verify_runtime_file(&runtime_dir.join(&file.name), file).is_ok())
}

fn verify_runtime_file(path: &Path, file: &RuntimeFile) -> io::Result<()> {
    verify_size(path, file.size)?;
    verify_sha256(path, &file.sha256)
}

fn verify_size(path: &Path, expected: u64) -> io::Result<()> {
    let actual = fs::metadata(path)?.len();
    if actual == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "size mismatch for {}: expected {expected}, found {actual}",
                path.display()
            ),
        ))
    }
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
