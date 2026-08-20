use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{
    LinuxSystemImage, ALPINE_ARCHIVE_SHA256, ALPINE_ARCHIVE_SIZE, ALPINE_URL, ALPINE_VERSION,
    ARCHITECTURE, COMPATIBILITY_LEVEL, DIRECTORY_HASH_SEED, FILESYSTEM, FILESYSTEM_LABEL,
    FILESYSTEM_UUID, IMAGE_NAME, IMAGE_SIZE, SCHEMA_VERSION, SOURCE_DATE_EPOCH,
};
use crate::runtime_assets::{runtime_bundle, RuntimeBundle};

#[test]
fn exact_compatibility_set_loads_and_reverifies() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    let image = LinuxSystemImage::load(&fixture.manifest, runtime)
        .expect("exact Linux compatibility set must load");

    assert!(image.evidence().is_success());
    assert_eq!(image.evidence().target_arch, ARCHITECTURE);
    assert!(fs::metadata(image.pinned_image_path())
        .expect("pinned procfs image path must resolve")
        .is_file());
    image
        .reverify(runtime)
        .expect("unchanged compatibility set must reverify");
}

#[test]
fn manifest_and_image_symbolic_links_fail_closed() {
    let fixture = Fixture::new();
    let manifest_link = fixture.directory.path().join("manifest-link.json");
    symlink(&fixture.manifest, &manifest_link).expect("create manifest symbolic link");
    let error = LinuxSystemImage::load(&manifest_link, fixture.runtime())
        .expect_err("manifest symbolic link must fail");
    assert!(error.to_string().contains("symbolic link"));

    let image_target = fixture.directory.path().join("image-target.ext4");
    fs::rename(&fixture.image, &image_target).expect("move image fixture");
    symlink(&image_target, &fixture.image).expect("create image symbolic link");
    let error = LinuxSystemImage::load(&fixture.manifest, fixture.runtime())
        .expect_err("image symbolic link must fail");
    assert!(error.to_string().contains("symbolic link"));
}

#[test]
fn runtime_drift_and_unknown_manifest_fields_fail_closed() {
    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["runtime"]["archive_sha256"] = Value::String("0".repeat(64));
    });
    let error = LinuxSystemImage::load(&fixture.manifest, fixture.runtime())
        .expect_err("runtime drift must fail");
    assert!(error.to_string().contains("checked-in target bundle"));

    let fixture = Fixture::new();
    fixture.mutate_manifest(|manifest| {
        manifest["unexpected"] = Value::Bool(true);
    });
    let error = LinuxSystemImage::load(&fixture.manifest, fixture.runtime())
        .expect_err("unknown manifest field must fail");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn same_size_mutation_and_path_replacement_fail_reverification() {
    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    let image = LinuxSystemImage::load(&fixture.manifest, runtime)
        .expect("exact Linux compatibility set must load");
    let mut file = OpenOptions::new()
        .write(true)
        .open(&fixture.image)
        .expect("open image for tamper");
    file.seek(SeekFrom::Start(IMAGE_SIZE - 1))
        .expect("seek image fixture");
    file.write_all(&[1]).expect("tamper image fixture");
    file.sync_all().expect("flush image fixture");
    let error = image
        .reverify(runtime)
        .expect_err("same-size content drift must fail");
    assert!(error.to_string().contains("SHA-256 changed"));

    let fixture = Fixture::new();
    let runtime = fixture.runtime();
    let image = LinuxSystemImage::load(&fixture.manifest, runtime)
        .expect("exact Linux compatibility set must load");
    let displaced = fixture.directory.path().join("displaced.ext4");
    fs::rename(&fixture.image, &displaced).expect("replace image path");
    let replacement = File::create(&fixture.image).expect("create replacement image");
    replacement
        .set_len(IMAGE_SIZE)
        .expect("size replacement image");
    let error = image
        .reverify(runtime)
        .expect_err("path replacement must fail");
    assert!(error.to_string().contains("identity changed"));
}

struct Fixture {
    directory: tempfile::TempDir,
    manifest: PathBuf,
    image: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create system-image fixture directory");
        let image = directory.path().join(IMAGE_NAME);
        let image_file = File::create(&image).expect("create sparse system image");
        image_file
            .set_len(IMAGE_SIZE)
            .expect("size sparse system image");
        let image_sha256 = sha256_path(&image);
        let runtime = runtime_bundle("linux", ARCHITECTURE)
            .expect("checked-in runtime manifest must be valid")
            .expect("current Linux architecture must have a runtime bundle");
        let manifest = directory.path().join("system-image.json");
        let contents = json!({
            "schema_version": SCHEMA_VERSION,
            "compatibility_level": COMPATIBILITY_LEVEL,
            "architecture": ARCHITECTURE,
            "image": {
                "name": IMAGE_NAME,
                "size": IMAGE_SIZE,
                "sha256": image_sha256,
                "archive_name": "a3s-oci-system.ext4.xz",
                "archive_size": 1,
                "archive_sha256": "1".repeat(64),
                "filesystem": FILESYSTEM,
                "filesystem_uuid": FILESYSTEM_UUID,
                "filesystem_label": FILESYSTEM_LABEL,
                "directory_hash_seed": DIRECTORY_HASH_SEED
            },
            "sources": {
                "alpine": {
                    "version": ALPINE_VERSION,
                    "url": ALPINE_URL,
                    "archive_size": ALPINE_ARCHIVE_SIZE,
                    "archive_sha256": ALPINE_ARCHIVE_SHA256
                },
                "agent": {
                    "version": env!("CARGO_PKG_VERSION"),
                    "size": 1,
                    "sha256": "2".repeat(64)
                },
                "builder": {
                    "source_date_epoch": SOURCE_DATE_EPOCH,
                    "e2fsprogs_version": "1.47.0"
                }
            },
            "runtime": runtime
        });
        fs::write(
            &manifest,
            serde_json::to_vec(&contents).expect("serialize system-image fixture"),
        )
        .expect("write system-image fixture");
        Self {
            directory,
            manifest,
            image,
        }
    }

    fn runtime(&self) -> &'static RuntimeBundle {
        runtime_bundle("linux", ARCHITECTURE)
            .expect("checked-in runtime manifest must be valid")
            .expect("current Linux architecture must have a runtime bundle")
    }

    fn mutate_manifest(&self, mutate: impl FnOnce(&mut Value)) {
        let mut manifest: Value = serde_json::from_slice(
            &fs::read(&self.manifest).expect("read system-image fixture manifest"),
        )
        .expect("parse system-image fixture manifest");
        mutate(&mut manifest);
        fs::write(
            &self.manifest,
            serde_json::to_vec(&manifest).expect("serialize mutated system-image manifest"),
        )
        .expect("write mutated system-image manifest");
    }
}

fn sha256_path(path: &Path) -> String {
    let mut file = File::open(path).expect("open hashed fixture");
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("read hashed fixture");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    format!("{:x}", hasher.finalize())
}
