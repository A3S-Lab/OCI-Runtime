use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_A3S_KRUN_LIBKRUN_A3S_DEP");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let runtime_dir = PathBuf::from(
        env::var_os("DEP_A3S_KRUN_LIBKRUN_A3S_DEP")
            .expect("a3s-libkrun-sys did not publish its Windows runtime directory"),
    );
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not set OUT_DIR"));
    let profile_dir = profile_dir(&out_dir).expect("failed to derive Cargo profile directory");

    for name in ["krun.dll", "libkrunfw.dll"] {
        let source = runtime_dir.join(name);
        assert!(
            source.is_file(),
            "a3s-libkrun-sys runtime is missing {}",
            source.display()
        );
        println!("cargo:rerun-if-changed={}", source.display());
        copy_runtime_file(&source, &profile_dir.join(name))
            .unwrap_or_else(|error| panic!("failed to stage {}: {error}", source.display()));
        copy_runtime_file(&source, &profile_dir.join("deps").join(name)).unwrap_or_else(|error| {
            panic!("failed to stage {} for tests: {error}", source.display())
        });
    }

    println!(
        "cargo:rustc-env=A3S_OCI_KRUN_RUNTIME_DIR={}",
        runtime_dir.display()
    );
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
