use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use a3s_oci_sdk::{
    canonical_json_bytes, CheckpointCompatibility, CheckpointDigest, ContainerTarget, ErrorCode,
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::tool::CriuIdentity;
use super::{checkpoint_error, io_error};

// Framing version 1 remains stable. Manifest schema v2 adds the exact
// external-device mount contract needed by restore without changing how the
// length-delimited manifest and image bodies are encoded.
const ARTIFACT_MAGIC: [u8; 16] = *b"A3SOCI-CRIU-V1\0\0";
const ARTIFACT_SCHEMA_V2: &str = "a3s.oci.native-criu-checkpoint.v2";
const INVENTORY_IMAGE: &str = "inventory.img";
const MAX_IMAGE_FILES: usize = 4_096;
const MAX_IMAGE_NAME_BYTES: usize = 255;
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub(super) struct ArtifactMetadata {
    pub(super) source: ContainerTarget,
    pub(super) source_config_digest: CheckpointDigest,
    pub(super) source_attachments_digest: CheckpointDigest,
    pub(super) compatibility: CheckpointCompatibility,
    pub(super) launcher_pid: i32,
    pub(super) checkpoint_root_pid: i32,
    pub(super) init_pid: i32,
    pub(super) cgroup_path: String,
    pub(super) criu: CriuIdentity,
    pub(super) dump_options: Vec<String>,
    pub(super) external_mounts: Vec<ExternalMountManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BuiltArtifact {
    pub(super) manifest: CheckpointArtifactManifest,
    pub(super) digest: CheckpointDigest,
    pub(super) size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CheckpointArtifactManifest {
    schema_version: String,
    publication_token: String,
    source: ContainerTarget,
    source_config_digest: CheckpointDigest,
    source_attachments_digest: CheckpointDigest,
    compatibility: CheckpointCompatibility,
    quiesce: String,
    launcher_pid: i32,
    checkpoint_root_pid: i32,
    init_pid: i32,
    cgroup_path: String,
    criu: CriuIdentity,
    dump_options: Vec<String>,
    external_mounts: Vec<ExternalMountManifestEntry>,
    images: Vec<ImageManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExternalMountManifestEntry {
    name: String,
    mountpoint: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImageManifestEntry {
    name: String,
    size_bytes: u64,
    digest: CheckpointDigest,
}

struct ImageSource {
    manifest: ImageManifestEntry,
    file: File,
}

impl CheckpointArtifactManifest {
    pub(super) const fn compatibility(&self) -> &CheckpointCompatibility {
        &self.compatibility
    }

    pub(super) const fn source(&self) -> &ContainerTarget {
        &self.source
    }

    pub(super) const fn source_config_digest(&self) -> &CheckpointDigest {
        &self.source_config_digest
    }

    pub(super) const fn source_attachments_digest(&self) -> &CheckpointDigest {
        &self.source_attachments_digest
    }

    pub(super) fn cgroup_path(&self) -> &str {
        &self.cgroup_path
    }

    pub(super) const fn criu(&self) -> &CriuIdentity {
        &self.criu
    }

    pub(super) fn dump_options(&self) -> &[String] {
        &self.dump_options
    }

    pub(super) fn external_mounts(&self) -> &[ExternalMountManifestEntry] {
        &self.external_mounts
    }

    fn validate(&self, expected_token: &[u8; 32]) -> Result<()> {
        if self.schema_version != ARTIFACT_SCHEMA_V2
            || self.publication_token != encode_token(expected_token)
            || self.quiesce != "paused"
            || self.launcher_pid <= 0
            || self.checkpoint_root_pid <= 0
            || self.init_pid <= 0
            || self.checkpoint_root_pid != self.init_pid
            || !Path::new(&self.cgroup_path).is_absolute()
            || self.dump_options.is_empty()
            || self.external_mounts.is_empty()
            || self.external_mounts.len() > 256
            || self.images.is_empty()
            || self.images.len() > MAX_IMAGE_FILES
        {
            return Err(invalid_artifact(
                "native checkpoint manifest has invalid identity, quiescence, process, cgroup, or image metadata",
            ));
        }
        for mount in &self.external_mounts {
            mount.validate()?;
        }
        let mountpoints = self
            .external_mounts
            .iter()
            .map(|mount| &mount.mountpoint)
            .collect::<BTreeSet<_>>();
        if self
            .external_mounts
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
            || mountpoints.len() != self.external_mounts.len()
        {
            return Err(invalid_artifact(
                "native checkpoint external mounts are not unique and sorted",
            ));
        }
        if !self
            .images
            .iter()
            .any(|entry| entry.name == INVENTORY_IMAGE)
        {
            return Err(invalid_artifact(
                "native checkpoint manifest omits CRIU inventory.img",
            ));
        }
        for entry in &self.images {
            validate_image_name(&entry.name)?;
        }
        if self
            .images
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(invalid_artifact(
                "native checkpoint image entries are not unique and sorted",
            ));
        }
        Ok(())
    }
}

impl ExternalMountManifestEntry {
    pub(super) fn new(name: &str, mountpoint: &Path) -> Result<Self> {
        let entry = Self {
            name: name.to_string(),
            mountpoint: mountpoint.to_path_buf(),
        };
        entry.validate()?;
        Ok(entry)
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    fn validate(&self) -> Result<()> {
        let Some(index) = self.name.strip_prefix("a3s-oci-device-") else {
            return Err(invalid_artifact(
                "native checkpoint external mount has an invalid cookie",
            ));
        };
        if index.len() != 4
            || !index.bytes().all(|byte| byte.is_ascii_digit())
            || index.parse::<usize>().ok().is_none_or(|index| index >= 256)
        {
            return Err(invalid_artifact(
                "native checkpoint external mount has an invalid cookie index",
            ));
        }
        let Some(mountpoint) = self.mountpoint.to_str() else {
            return Err(invalid_artifact(
                "native checkpoint external mountpoint is not valid UTF-8",
            ));
        };
        let components = mountpoint
            .strip_prefix('/')
            .filter(|relative| !relative.is_empty())
            .map(|relative| relative.split('/').collect::<Vec<_>>());
        if mountpoint.len() > 4_096
            || mountpoint.as_bytes().contains(&0)
            || components.as_ref().is_none_or(|components| {
                components.iter().any(|component| {
                    component.is_empty() || *component == "." || *component == ".."
                })
            })
        {
            return Err(invalid_artifact(
                "native checkpoint external mountpoint is not normalized and absolute",
            ));
        }
        Ok(())
    }
}

pub(super) async fn build(
    mut destination: File,
    images_directory: PathBuf,
    metadata: ArtifactMetadata,
    publication_token: [u8; 32],
) -> Result<BuiltArtifact> {
    tokio::task::spawn_blocking(move || {
        build_blocking(
            &mut destination,
            &images_directory,
            metadata,
            &publication_token,
        )
    })
    .await
    .map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("checkpoint artifact builder task failed: {error}"),
        )
    })?
}

pub(super) async fn validate(
    mut artifact: File,
    expected_digest: CheckpointDigest,
    expected_size: u64,
    publication_token: [u8; 32],
) -> Result<BuiltArtifact> {
    tokio::task::spawn_blocking(move || {
        validate_blocking(
            &mut artifact,
            &expected_digest,
            expected_size,
            &publication_token,
            None,
        )
    })
    .await
    .map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("checkpoint artifact validation task failed: {error}"),
        )
    })?
}

pub(super) async fn validate_external(
    mut artifact: File,
    expected_digest: CheckpointDigest,
    expected_size: u64,
) -> Result<BuiltArtifact> {
    tokio::task::spawn_blocking(move || {
        let publication_token = read_publication_token(&mut artifact)?;
        validate_blocking(
            &mut artifact,
            &expected_digest,
            expected_size,
            &publication_token,
            None,
        )
    })
    .await
    .map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("external checkpoint validation task failed: {error}"),
        )
    })?
}

pub(super) async fn extract_external(
    mut artifact: File,
    expected_digest: CheckpointDigest,
    expected_size: u64,
    images_directory: PathBuf,
) -> Result<BuiltArtifact> {
    tokio::task::spawn_blocking(move || {
        validate_empty_image_destination(&images_directory)?;
        let publication_token = read_publication_token(&mut artifact)?;
        validate_blocking(
            &mut artifact,
            &expected_digest,
            expected_size,
            &publication_token,
            Some(&images_directory),
        )
    })
    .await
    .map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("checkpoint extraction task failed: {error}"),
        )
    })?
}

pub(super) fn initialize_pending(artifact: &mut File, publication_token: &[u8; 32]) -> Result<()> {
    artifact.seek(SeekFrom::Start(0)).map_err(|error| {
        io_error(
            "rewind pending checkpoint artifact",
            Path::new("<pending>"),
            error,
        )
    })?;
    artifact.set_len(0).map_err(|error| {
        io_error(
            "truncate pending checkpoint artifact",
            Path::new("<pending>"),
            error,
        )
    })?;
    artifact
        .write_all(&ARTIFACT_MAGIC)
        .and_then(|()| artifact.write_all(publication_token))
        .and_then(|()| artifact.sync_all())
        .map_err(|error| {
            io_error(
                "initialize pending checkpoint ownership",
                Path::new("<pending>"),
                error,
            )
        })
}

pub(super) fn owns_pending(artifact: &mut File, publication_token: &[u8; 32]) -> Result<bool> {
    artifact.seek(SeekFrom::Start(0)).map_err(|error| {
        io_error(
            "rewind pending checkpoint artifact",
            Path::new("<pending>"),
            error,
        )
    })?;
    let mut header = [0_u8; 48];
    match artifact.read_exact(&mut header) {
        Ok(()) => Ok(header[..16] == ARTIFACT_MAGIC && header[16..] == publication_token[..]),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(io_error(
            "read pending checkpoint ownership header",
            Path::new("<pending>"),
            error,
        )),
    }
}

fn build_blocking(
    destination: &mut File,
    images_directory: &Path,
    metadata: ArtifactMetadata,
    publication_token: &[u8; 32],
) -> Result<BuiltArtifact> {
    if metadata.launcher_pid <= 0
        || metadata.checkpoint_root_pid <= 0
        || metadata.init_pid <= 0
        || metadata.checkpoint_root_pid != metadata.init_pid
        || !Path::new(&metadata.cgroup_path).is_absolute()
    {
        return Err(checkpoint_error(
            ErrorCode::InvalidArgument,
            "checkpoint artifact metadata requires positive PIDs and an absolute cgroup path",
        ));
    }
    let mut sources = inspect_images(images_directory)?;
    let manifest = CheckpointArtifactManifest {
        schema_version: ARTIFACT_SCHEMA_V2.to_string(),
        publication_token: encode_token(publication_token),
        source: metadata.source,
        source_config_digest: metadata.source_config_digest,
        source_attachments_digest: metadata.source_attachments_digest,
        compatibility: metadata.compatibility,
        quiesce: "paused".to_string(),
        launcher_pid: metadata.launcher_pid,
        checkpoint_root_pid: metadata.checkpoint_root_pid,
        init_pid: metadata.init_pid,
        cgroup_path: metadata.cgroup_path,
        criu: metadata.criu,
        dump_options: metadata.dump_options,
        external_mounts: metadata.external_mounts,
        images: sources
            .iter()
            .map(|source| source.manifest.clone())
            .collect(),
    };
    manifest.validate(publication_token)?;
    let encoded = canonical_json_bytes(&manifest).map_err(|error| {
        checkpoint_error(
            ErrorCode::Internal,
            format!("failed to encode native checkpoint manifest: {error}"),
        )
    })?;
    if encoded.is_empty() || encoded.len() > MAX_MANIFEST_BYTES {
        return Err(checkpoint_error(
            ErrorCode::ResourceExhausted,
            format!(
                "native checkpoint manifest is {} bytes; maximum is {MAX_MANIFEST_BYTES}",
                encoded.len()
            ),
        ));
    }

    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind checkpoint artifact", Path::new("<pending>"), error))?;
    destination.set_len(0).map_err(|error| {
        io_error(
            "truncate checkpoint artifact",
            Path::new("<pending>"),
            error,
        )
    })?;
    let mut artifact_digest = Sha256::new();
    let mut size_bytes = 0_u64;
    write_hashed(
        destination,
        &mut artifact_digest,
        &mut size_bytes,
        &ARTIFACT_MAGIC,
    )?;
    write_hashed(
        destination,
        &mut artifact_digest,
        &mut size_bytes,
        publication_token,
    )?;
    write_hashed(
        destination,
        &mut artifact_digest,
        &mut size_bytes,
        &u64::try_from(encoded.len())
            .map_err(|_| invalid_artifact("checkpoint manifest length does not fit u64"))?
            .to_le_bytes(),
    )?;
    write_hashed(destination, &mut artifact_digest, &mut size_bytes, &encoded)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    for source in &mut sources {
        source.file.seek(SeekFrom::Start(0)).map_err(|error| {
            image_io(
                "rewind CRIU image",
                images_directory,
                &source.manifest.name,
                error,
            )
        })?;
        let mut remaining = source.manifest.size_bytes;
        while remaining > 0 {
            let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = source.file.read(&mut buffer[..limit]).map_err(|error| {
                image_io(
                    "read CRIU image",
                    images_directory,
                    &source.manifest.name,
                    error,
                )
            })?;
            if read == 0 {
                return Err(invalid_artifact(format!(
                    "CRIU image {} became shorter while packaging",
                    source.manifest.name
                )));
            }
            write_hashed(
                destination,
                &mut artifact_digest,
                &mut size_bytes,
                &buffer[..read],
            )?;
            remaining -= read as u64;
        }
    }
    destination
        .sync_all()
        .map_err(|error| io_error("sync checkpoint artifact", Path::new("<pending>"), error))?;
    let digest = CheckpointDigest::new(format!("sha256:{:x}", artifact_digest.finalize()))?;
    let verified = validate_blocking(destination, &digest, size_bytes, publication_token, None)?;
    if verified.manifest != manifest {
        return Err(invalid_artifact(
            "checkpoint artifact manifest changed during verification",
        ));
    }
    Ok(verified)
}

fn inspect_images(directory: &Path) -> Result<Vec<ImageSource>> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| io_error("inspect CRIU image directory", directory, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_artifact(format!(
            "CRIU image path is not a real directory: {}",
            directory.display()
        )));
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(directory)
        .map_err(|error| io_error("list CRIU image directory", directory, error))?
    {
        let entry = entry.map_err(|error| io_error("read CRIU image entry", directory, error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_artifact("CRIU image directory contains a non-UTF-8 file name"))?;
        validate_image_name(&name)?;
        names.push(name);
    }
    names.sort();
    if names.is_empty() || names.len() > MAX_IMAGE_FILES {
        return Err(invalid_artifact(format!(
            "CRIU emitted {} image files; expected 1 through {MAX_IMAGE_FILES}",
            names.len()
        )));
    }
    if !names.iter().any(|name| name == INVENTORY_IMAGE) {
        return Err(invalid_artifact("CRIU image directory omits inventory.img"));
    }

    let mut sources = Vec::with_capacity(names.len());
    for name in names {
        let path = directory.join(&name);
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options
            .open(&path)
            .map_err(|error| image_io("open CRIU image", directory, &name, error))?;
        let metadata = file
            .metadata()
            .map_err(|error| image_io("inspect CRIU image", directory, &name, error))?;
        if !metadata.is_file() {
            return Err(invalid_artifact(format!(
                "CRIU image {name} is not a regular file"
            )));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| image_io("hash CRIU image", directory, &name, error))?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        sources.push(ImageSource {
            manifest: ImageManifestEntry {
                name,
                size_bytes: metadata.len(),
                digest: CheckpointDigest::new(format!("sha256:{:x}", digest.finalize()))?,
            },
            file,
        });
    }
    Ok(sources)
}

fn validate_blocking(
    artifact: &mut File,
    expected_digest: &CheckpointDigest,
    expected_size: u64,
    publication_token: &[u8; 32],
    images_directory: Option<&Path>,
) -> Result<BuiltArtifact> {
    let metadata = artifact
        .metadata()
        .map_err(|error| io_error("inspect checkpoint artifact", Path::new("<pending>"), error))?;
    if !metadata.is_file() || metadata.len() != expected_size || expected_size == 0 {
        return Err(invalid_artifact(
            "checkpoint artifact is not a regular file with the expected positive size",
        ));
    }
    artifact
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind checkpoint artifact", Path::new("<pending>"), error))?;
    let mut digest = Sha256::new();
    let mut header = [0_u8; 56];
    read_exact_hashed(artifact, &mut digest, &mut header)?;
    if header[..16] != ARTIFACT_MAGIC || header[16..48] != publication_token[..] {
        return Err(invalid_artifact(
            "checkpoint artifact magic or publication token does not match",
        ));
    }
    let manifest_length =
        usize::try_from(u64::from_le_bytes(header[48..56].try_into().map_err(
            |_| invalid_artifact("checkpoint manifest length header is malformed"),
        )?))
        .map_err(|_| invalid_artifact("checkpoint manifest length does not fit this platform"))?;
    if manifest_length == 0 || manifest_length > MAX_MANIFEST_BYTES {
        return Err(invalid_artifact(
            "checkpoint manifest length is zero or exceeds its bound",
        ));
    }
    let mut encoded = vec![0_u8; manifest_length];
    read_exact_hashed(artifact, &mut digest, &mut encoded)?;
    let manifest: CheckpointArtifactManifest =
        serde_json::from_slice(&encoded).map_err(|error| {
            invalid_artifact(format!(
                "failed to decode checkpoint artifact manifest: {error}"
            ))
        })?;
    manifest.validate(publication_token)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    for image in &manifest.images {
        let mut extracted = match images_directory {
            Some(directory) => {
                let path = directory.join(&image.name);
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
                Some(options.open(&path).map_err(|error| {
                    image_io("create extracted CRIU image", directory, &image.name, error)
                })?)
            }
            None => None,
        };
        let mut image_digest = Sha256::new();
        let mut remaining = image.size_bytes;
        while remaining > 0 {
            let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
            let read = artifact.read(&mut buffer[..limit]).map_err(|error| {
                io_error(
                    "read checkpoint artifact image",
                    Path::new("<pending>"),
                    error,
                )
            })?;
            if read == 0 {
                return Err(invalid_artifact(format!(
                    "checkpoint artifact truncates CRIU image {}",
                    image.name
                )));
            }
            digest.update(&buffer[..read]);
            image_digest.update(&buffer[..read]);
            if let (Some(extracted), Some(directory)) = (extracted.as_mut(), images_directory) {
                extracted.write_all(&buffer[..read]).map_err(|error| {
                    image_io("write extracted CRIU image", directory, &image.name, error)
                })?;
            }
            remaining -= read as u64;
        }
        let actual = format!("sha256:{:x}", image_digest.finalize());
        if actual != image.digest.as_str() {
            return Err(invalid_artifact(format!(
                "checkpoint artifact CRIU image {} has the wrong digest",
                image.name
            )));
        }
        if let (Some(extracted), Some(directory)) = (extracted, images_directory) {
            extracted.sync_all().map_err(|error| {
                image_io("sync extracted CRIU image", directory, &image.name, error)
            })?;
        }
    }
    let mut trailing = [0_u8; 1];
    if artifact.read(&mut trailing).map_err(|error| {
        io_error(
            "read checkpoint artifact trailer",
            Path::new("<pending>"),
            error,
        )
    })? != 0
    {
        return Err(invalid_artifact(
            "checkpoint artifact contains unmanifested trailing bytes",
        ));
    }
    let actual_digest = CheckpointDigest::new(format!("sha256:{:x}", digest.finalize()))?;
    if &actual_digest != expected_digest {
        return Err(invalid_artifact(
            "checkpoint artifact digest differs from retained evidence",
        ));
    }
    if let Some(directory) = images_directory {
        File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error("sync extracted CRIU image directory", directory, error))?;
    }
    Ok(BuiltArtifact {
        manifest,
        digest: actual_digest,
        size_bytes: expected_size,
    })
}

fn read_publication_token(artifact: &mut File) -> Result<[u8; 32]> {
    artifact
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind checkpoint artifact", Path::new("<external>"), error))?;
    let mut header = [0_u8; 48];
    artifact.read_exact(&mut header).map_err(|error| {
        io_error(
            "read checkpoint artifact ownership header",
            Path::new("<external>"),
            error,
        )
    })?;
    if header[..16] != ARTIFACT_MAGIC {
        return Err(invalid_artifact("checkpoint artifact magic does not match"));
    }
    header[16..48]
        .try_into()
        .map_err(|_| invalid_artifact("checkpoint publication token has an invalid width"))
}

fn validate_empty_image_destination(directory: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| io_error("inspect restore image directory", directory, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_artifact(format!(
            "restore image destination is not a real directory: {}",
            directory.display()
        )));
    }
    if std::fs::read_dir(directory)
        .map_err(|error| io_error("list restore image directory", directory, error))?
        .next()
        .transpose()
        .map_err(|error| io_error("read restore image directory", directory, error))?
        .is_some()
    {
        return Err(invalid_artifact(format!(
            "restore image destination is not empty: {}",
            directory.display()
        )));
    }
    Ok(())
}

fn write_hashed(
    writer: &mut File,
    digest: &mut Sha256,
    size: &mut u64,
    bytes: &[u8],
) -> Result<()> {
    writer
        .write_all(bytes)
        .map_err(|error| io_error("write checkpoint artifact", Path::new("<pending>"), error))?;
    digest.update(bytes);
    *size = size.checked_add(bytes.len() as u64).ok_or_else(|| {
        checkpoint_error(
            ErrorCode::ResourceExhausted,
            "checkpoint artifact size overflowed",
        )
    })?;
    Ok(())
}

fn read_exact_hashed(reader: &mut File, digest: &mut Sha256, bytes: &mut [u8]) -> Result<()> {
    reader
        .read_exact(bytes)
        .map_err(|error| io_error("read checkpoint artifact", Path::new("<pending>"), error))?;
    digest.update(bytes);
    Ok(())
}

fn validate_image_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || name.len() > MAX_IMAGE_NAME_BYTES
        || path.file_name().and_then(|value| value.to_str()) != Some(name)
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_artifact(format!(
            "CRIU image name is unsafe or oversized: {name:?}"
        )));
    }
    Ok(())
}

pub(super) fn encode_token(token: &[u8; 32]) -> String {
    token.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn image_io(
    action: &str,
    directory: &Path,
    name: &str,
    error: std::io::Error,
) -> a3s_oci_sdk::Error {
    io_error(action, &directory.join(name), error)
}

fn invalid_artifact(message: impl Into<String>) -> a3s_oci_sdk::Error {
    checkpoint_error(ErrorCode::FailedPrecondition, message)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::OpenOptionsExt;

    use a3s_oci_core::{DriverKind, HostPlatform, IsolationClass};
    use a3s_oci_sdk::{CheckpointFormat, ContainerId, Generation, RuntimeArtifact};
    use tempfile::tempdir;

    use super::*;

    fn metadata() -> ArtifactMetadata {
        let digest = CheckpointDigest::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        let runtime = RuntimeArtifact::new(
            "a3s-oci-runtime",
            "0.2.0",
            format!("sha256:{}", "2".repeat(64)),
            None,
        )
        .unwrap();
        ArtifactMetadata {
            source: ContainerTarget::exact(
                ContainerId::new("artifact-source").unwrap(),
                Generation(7),
            ),
            source_config_digest: digest.clone(),
            source_attachments_digest: digest.clone(),
            compatibility: CheckpointCompatibility::new(
                DriverKind::NativeLinux,
                IsolationClass::SharedHostKernel,
                HostPlatform::Linux,
                std::env::consts::ARCH,
                runtime,
                digest.clone(),
                CheckpointFormat::new("native-linux-criu", 1).unwrap(),
            )
            .unwrap(),
            launcher_pid: 41,
            checkpoint_root_pid: 43,
            init_pid: 43,
            cgroup_path: "/sys/fs/cgroup/a3s-test".to_string(),
            criu: CriuIdentity {
                executable_digest: digest,
                version: "4.2.1".to_string(),
                git_id: Some("v4.2.1".to_string()),
            },
            dump_options: vec!["--leave-running".to_string()],
            external_mounts: vec![ExternalMountManifestEntry::new(
                "a3s-oci-device-0000",
                Path::new("/dev/null"),
            )
            .expect("external mount")],
        }
    }

    fn pending_file(path: &Path) -> File {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        options.open(path).unwrap()
    }

    #[tokio::test]
    async fn packages_sorted_images_and_detects_content_drift() {
        let temporary = tempdir().unwrap();
        let images = temporary.path().join("images");
        std::fs::create_dir(&images).unwrap();
        std::fs::write(images.join("pages-1.img"), b"pages").unwrap();
        std::fs::write(images.join(INVENTORY_IMAGE), b"inventory").unwrap();
        let artifact_path = temporary.path().join("artifact.bin");
        let token = [7_u8; 32];
        let built = build(pending_file(&artifact_path), images, metadata(), token)
            .await
            .unwrap();
        assert!(built.size_bytes > 0);
        assert_eq!(
            built
                .manifest
                .images
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec![INVENTORY_IMAGE, "pages-1.img"]
        );
        validate(
            File::open(&artifact_path).unwrap(),
            built.digest.clone(),
            built.size_bytes,
            token,
        )
        .await
        .unwrap();
        assert_eq!(
            validate_external(
                File::open(&artifact_path).unwrap(),
                built.digest.clone(),
                built.size_bytes,
            )
            .await
            .unwrap(),
            built
        );

        let extracted = temporary.path().join("extracted");
        std::fs::create_dir(&extracted).unwrap();
        assert_eq!(
            extract_external(
                File::open(&artifact_path).unwrap(),
                built.digest.clone(),
                built.size_bytes,
                extracted.clone(),
            )
            .await
            .unwrap(),
            built
        );
        assert_eq!(
            std::fs::read(extracted.join(INVENTORY_IMAGE)).unwrap(),
            b"inventory"
        );
        assert_eq!(
            std::fs::read(extracted.join("pages-1.img")).unwrap(),
            b"pages"
        );

        let mut bytes = std::fs::read(&artifact_path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&artifact_path, bytes).unwrap();
        assert!(validate(
            File::open(&artifact_path).unwrap(),
            built.digest.clone(),
            built.size_bytes,
            token,
        )
        .await
        .is_err());
        assert!(validate_external(
            File::open(&artifact_path).unwrap(),
            built.digest,
            built.size_bytes,
        )
        .await
        .is_err());
    }

    #[test]
    fn validates_exact_external_mount_cookie_and_path_contract() {
        let mount = ExternalMountManifestEntry::new(
            "a3s-oci-device-0255",
            Path::new("/dev/qualified-device"),
        )
        .expect("bounded external device mount");
        assert_eq!(mount.name(), "a3s-oci-device-0255");
        assert_eq!(mount.mountpoint(), Path::new("/dev/qualified-device"));

        for cookie in [
            "device-0000",
            "a3s-oci-device-000",
            "a3s-oci-device-00000",
            "a3s-oci-device-0256",
            "a3s-oci-device-abcd",
        ] {
            assert!(ExternalMountManifestEntry::new(cookie, Path::new("/dev/null")).is_err());
        }
        for mountpoint in [
            "dev/null",
            "/",
            "/dev//null",
            "/dev/./null",
            "/dev/../null",
            "/dev/null/",
        ] {
            assert!(
                ExternalMountManifestEntry::new("a3s-oci-device-0000", Path::new(mountpoint),)
                    .is_err()
            );
        }
    }

    #[test]
    fn pending_ownership_requires_magic_and_full_token() {
        let temporary = tempdir().unwrap();
        let path = temporary.path().join("pending");
        let token = [9_u8; 32];
        let mut file = pending_file(&path);
        file.write_all(&ARTIFACT_MAGIC).unwrap();
        file.write_all(&token).unwrap();
        assert!(owns_pending(&mut file, &token).unwrap());
        assert!(!owns_pending(&mut file, &[8_u8; 32]).unwrap());
    }
}
