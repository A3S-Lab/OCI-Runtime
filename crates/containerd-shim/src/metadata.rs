use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::oci_spec::runtime::Process;
use a3s_oci_sdk::{
    ContainerId, DriverKind, Error, ErrorCode, ExitStatus, Generation, IsolationClass,
    ProcessRecord, Result,
};
use serde::{Deserialize, Serialize};

use crate::adapter::TaskIdentity;
use crate::identity::IncarnationId;

mod create_intent;

pub(crate) use create_intent::{NewShimCreateIntent, ShimCreateIntent};

const METADATA_FILE_NAME: &str = "a3s-oci-shim-v1.json";
const INCARNATION_FILE_NAME: &str = "a3s-oci-shim-incarnation-v1";
const METADATA_SCHEMA_VERSION: u32 = 2;
const MIN_METADATA_SCHEMA_VERSION: u32 = 1;
const MAX_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_INCARNATION_BYTES: u64 = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShimMetadata {
    schema_version: u32,
    namespace: String,
    task_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    incarnation: Option<String>,
    container_id: ContainerId,
    generation: Generation,
    driver: DriverKind,
    isolation: IsolationClass,
    bundle: PathBuf,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    output_cursor: u64,
    rootfs_mounted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit: Option<ExitStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exited_at_unix_nanos: Option<u128>,
    execs: Vec<ExecMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecMetadata {
    pub(crate) exec_id: String,
    pub(crate) stage: ExecStage,
    pub(crate) process: Process,
    pub(crate) stdin: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) terminal: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) output_cursor: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) record: Option<ProcessRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exit: Option<ExitStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) exited_at_unix_nanos: Option<u128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExecStage {
    Added,
    Starting,
    Started,
    Exited,
}

impl ExecMetadata {
    pub(crate) fn new(
        exec_id: String,
        process: Process,
        stdin: String,
        stdout: String,
        stderr: String,
        terminal: bool,
    ) -> Self {
        Self {
            exec_id,
            stage: ExecStage::Added,
            process,
            stdin,
            stdout,
            stderr,
            terminal,
            output_cursor: 0,
            record: None,
            exit: None,
            exited_at_unix_nanos: None,
        }
    }
}

pub(crate) struct NewShimMetadata {
    pub(crate) identity: TaskIdentity,
    pub(crate) generation: Generation,
    pub(crate) driver: DriverKind,
    pub(crate) isolation: IsolationClass,
    pub(crate) bundle: PathBuf,
    pub(crate) stdin: String,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) terminal: bool,
    pub(crate) output_cursor: u64,
    pub(crate) rootfs_mounted: bool,
}

impl ShimMetadata {
    pub(crate) fn new(value: NewShimMetadata) -> Self {
        let TaskIdentity {
            namespace,
            task_id,
            incarnation,
            container_id,
        } = value.identity;
        Self {
            schema_version: METADATA_SCHEMA_VERSION,
            namespace,
            task_id,
            incarnation: incarnation.as_ref().map(|value| value.as_str().to_string()),
            container_id,
            generation: value.generation,
            driver: value.driver,
            isolation: value.isolation,
            bundle: value.bundle,
            stdin: value.stdin,
            stdout: value.stdout,
            stderr: value.stderr,
            terminal: value.terminal,
            output_cursor: value.output_cursor,
            rootfs_mounted: value.rootfs_mounted,
            exit: None,
            exited_at_unix_nanos: None,
            execs: Vec::new(),
        }
    }

    pub(crate) fn path(bundle: &Path) -> PathBuf {
        bundle.join(METADATA_FILE_NAME)
    }

    pub(crate) fn incarnation_path(bundle: &Path) -> PathBuf {
        bundle.join(INCARNATION_FILE_NAME)
    }

    pub(crate) fn load_or_create_incarnation(bundle: &Path) -> Result<IncarnationId> {
        let path = Self::incarnation_path(bundle);
        match open_private_read(&path) {
            Ok(file) => read_incarnation(file, &path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let incarnation = IncarnationId::generate()?;
                let temporary = bundle.join(format!(
                    ".{INCARNATION_FILE_NAME}.{}.tmp",
                    incarnation.as_str()
                ));
                let mut create = OpenOptions::new();
                create.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    create
                        .mode(0o600)
                        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
                }
                match create.open(&temporary) {
                    Ok(mut file) => {
                        if let Err(error) = file
                            .write_all(incarnation.as_str().as_bytes())
                            .and_then(|()| file.sync_all())
                        {
                            let _ = fs::remove_file(&temporary);
                            return Err(metadata_io(
                                "commit incarnation temporary",
                                &temporary,
                                error,
                            ));
                        }
                        match fs::hard_link(&temporary, &path) {
                            Ok(()) => {
                                let _ = fs::remove_file(&temporary);
                                sync_parent(&path)?;
                                Ok(incarnation)
                            }
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                                let _ = fs::remove_file(&temporary);
                                let file = open_private_read(&path).map_err(|error| {
                                    metadata_io("open raced incarnation", &path, error)
                                })?;
                                read_incarnation(file, &path)
                            }
                            Err(error) => {
                                let _ = fs::remove_file(&temporary);
                                Err(metadata_io("publish incarnation", &path, error))
                            }
                        }
                    }
                    Err(error) => Err(metadata_io(
                        "create incarnation temporary",
                        &temporary,
                        error,
                    )),
                }
            }
            Err(error) => Err(metadata_io("open incarnation", &path, error)),
        }
    }

    pub(crate) fn load(path: &Path) -> Result<Option<Self>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(metadata_io("open", path, error)),
        };
        validate_metadata_file(&file, path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_METADATA_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| metadata_io("read", path, error))?;
        if bytes.len() as u64 > MAX_METADATA_BYTES {
            return Err(metadata_error(format!(
                "shim metadata {} exceeds the {MAX_METADATA_BYTES}-byte limit",
                path.display()
            )));
        }
        let metadata: Self = serde_json::from_slice(&bytes).map_err(|error| {
            metadata_error(format!(
                "failed to decode shim metadata {}: {error}",
                path.display()
            ))
        })?;
        metadata.validate(path)?;
        Ok(Some(metadata))
    }

    pub(crate) fn store(&self) -> Result<()> {
        self.validate(&Self::path(&self.bundle))?;
        let encoded = serde_json::to_vec_pretty(self).map_err(|error| {
            metadata_error(format!(
                "failed to encode containerd shim metadata: {error}"
            ))
        })?;
        atomic_write(&Self::path(&self.bundle), &encoded)
    }

    pub(crate) fn remove(bundle: &Path) -> Result<()> {
        let path = Self::path(bundle);
        match fs::remove_file(&path) {
            Ok(()) => sync_parent(&path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(metadata_io("remove", &path, error)),
        }
    }

    pub(crate) fn identity(&self) -> Result<TaskIdentity> {
        let incarnation = self
            .incarnation
            .as_deref()
            .map(IncarnationId::new)
            .transpose()?;
        let identity = TaskIdentity::with_optional_incarnation(
            self.namespace.clone(),
            self.task_id.clone(),
            incarnation,
        )?;
        if identity.container_id != self.container_id {
            return Err(metadata_error(format!(
                "shim metadata identity resolves to {}, but records {}",
                identity.container_id.as_str(),
                self.container_id.as_str()
            )));
        }
        Ok(identity)
    }

    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }

    pub(crate) fn driver(&self) -> DriverKind {
        self.driver
    }

    pub(crate) fn isolation(&self) -> IsolationClass {
        self.isolation
    }

    pub(crate) fn bundle(&self) -> &Path {
        &self.bundle
    }

    pub(crate) fn stdin(&self) -> &str {
        &self.stdin
    }

    pub(crate) fn stdout(&self) -> &str {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &str {
        &self.stderr
    }

    pub(crate) fn terminal(&self) -> bool {
        self.terminal
    }

    pub(crate) fn output_cursor(&self) -> u64 {
        self.output_cursor
    }

    pub(crate) fn rootfs_mounted(&self) -> bool {
        self.rootfs_mounted
    }

    pub(crate) fn exit(&self) -> Option<&ExitStatus> {
        self.exit.as_ref()
    }

    pub(crate) fn exited_at_unix_nanos(&self) -> Option<u128> {
        self.exited_at_unix_nanos
    }

    pub(crate) fn execs(&self) -> &[ExecMetadata] {
        &self.execs
    }

    pub(crate) fn set_exit(&mut self, exit: Option<ExitStatus>, exited_at: Option<u128>) {
        self.exit = exit;
        self.exited_at_unix_nanos = exited_at;
    }

    pub(crate) fn set_execs(&mut self, execs: Vec<ExecMetadata>) {
        self.execs = execs;
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if !(MIN_METADATA_SCHEMA_VERSION..=METADATA_SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(metadata_error(format!(
                "unsupported shim metadata schema {} in {}; expected {MIN_METADATA_SCHEMA_VERSION} through {METADATA_SCHEMA_VERSION}",
                self.schema_version,
                path.display()
            )));
        }
        if self.generation.0 == 0 {
            return Err(metadata_error(format!(
                "shim metadata {} records generation zero",
                path.display()
            )));
        }
        if !self.bundle.is_absolute() {
            return Err(metadata_error(format!(
                "shim metadata {} records a non-absolute bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        if self.bundle != path.parent().unwrap_or_else(|| Path::new("")) {
            return Err(metadata_error(format!(
                "shim metadata {} records a different bundle {}",
                path.display(),
                self.bundle.display()
            )));
        }
        self.identity()?;
        let mut previous = None;
        for exec in &self.execs {
            if exec.exec_id.is_empty() {
                return Err(metadata_error("shim metadata contains an empty exec ID"));
            }
            if previous
                .as_deref()
                .is_some_and(|value| value >= exec.exec_id.as_str())
            {
                return Err(metadata_error(
                    "shim metadata exec entries must be unique and sorted by exec ID",
                ));
            }
            previous = Some(exec.exec_id.clone());
        }
        Ok(())
    }
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn read_incarnation(mut file: File, path: &Path) -> Result<IncarnationId> {
    validate_private_file(&file, path, MAX_INCARNATION_BYTES)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_INCARNATION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| metadata_io("read incarnation", path, error))?;
    if bytes.len() as u64 > MAX_INCARNATION_BYTES {
        return Err(metadata_error(format!(
            "containerd task incarnation {} exceeds the {MAX_INCARNATION_BYTES}-byte limit",
            path.display()
        )));
    }
    let value = String::from_utf8(bytes).map_err(|error| {
        metadata_error(format!(
            "containerd task incarnation {} is not UTF-8: {error}",
            path.display()
        ))
    })?;
    IncarnationId::new(value)
}

fn open_private_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn validate_metadata_file(file: &File, path: &Path) -> Result<()> {
    validate_private_file(file, path, MAX_METADATA_BYTES)
}

fn validate_private_file(file: &File, path: &Path, maximum_bytes: u64) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| metadata_io("inspect", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(metadata_error(format!(
            "shim metadata {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum_bytes {
        return Err(metadata_error(format!(
            "shim metadata {} exceeds the {maximum_bytes}-byte limit",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(metadata_error(format!(
                "shim metadata {} is owned by UID {}, expected effective UID {effective_uid}",
                path.display(),
                metadata.uid()
            )));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(metadata_error(format!(
                "shim metadata {} has unsafe mode {:04o}; group and other permissions must be zero",
                path.display(),
                metadata.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

fn atomic_write(destination: &Path, encoded: &[u8]) -> Result<()> {
    let file_name = destination.file_name().ok_or_else(|| {
        metadata_error(format!(
            "shim metadata destination has no file name: {}",
            destination.display()
        ))
    })?;
    let temporary = destination.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = match options.open(&temporary) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(&temporary).map_err(|remove_error| {
                metadata_io("remove stale temporary", &temporary, remove_error)
            })?;
            options
                .open(&temporary)
                .map_err(|open_error| metadata_io("create temporary", &temporary, open_error))?
        }
        Err(error) => return Err(metadata_io("create temporary", &temporary, error)),
    };
    let result = file.write_all(encoded).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(metadata_io("write temporary", &temporary, error));
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(metadata_io("commit", destination, error));
    }
    sync_parent(destination)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        metadata_error(format!(
            "shim metadata path has no parent: {}",
            path.display()
        ))
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| metadata_io("sync parent of", path, error))
}

fn metadata_io(operation: &str, path: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorCode::Unavailable,
        format!(
            "failed to {operation} containerd shim metadata {}: {error}",
            path.display()
        ),
    )
    .for_operation("containerd-shim-metadata")
}

fn metadata_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("containerd-shim-metadata")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(bundle: &Path) -> ShimMetadata {
        ShimMetadata::new(NewShimMetadata {
            identity: TaskIdentity::new("k8s.io", "task-a").expect("identity"),
            generation: Generation(7),
            driver: DriverKind::NativeLinux,
            isolation: IsolationClass::SharedHostKernel,
            bundle: bundle.to_path_buf(),
            stdin: "stdin".to_string(),
            stdout: "stdout".to_string(),
            stderr: "stderr".to_string(),
            terminal: false,
            output_cursor: 0,
            rootfs_mounted: true,
        })
    }

    #[test]
    fn metadata_round_trip_is_atomic_and_identity_bound() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expected = metadata(directory.path());
        expected.store().expect("store metadata");
        assert_eq!(
            ShimMetadata::load(&ShimMetadata::path(directory.path())).expect("load metadata"),
            Some(expected.clone())
        );
        assert_eq!(
            expected
                .identity()
                .expect("validated identity")
                .container_id,
            expected.container_id
        );
        assert!(directory
            .path()
            .read_dir()
            .expect("read directory")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }

    #[test]
    fn schema_v1_metadata_defaults_task_and_exec_output_cursors_to_zero() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": true,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh"],
            "cwd": "/"
        }))
        .expect("OCI process");
        expected.set_execs(vec![ExecMetadata::new(
            "exec-a".to_string(),
            process,
            String::new(),
            "exec-out".to_string(),
            String::new(),
            true,
        )]);
        expected.store().expect("store schema-v2 metadata");

        let path = ShimMetadata::path(directory.path());
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read metadata"))
                .expect("decode metadata document");
        document["schema_version"] = serde_json::json!(1);
        document
            .as_object_mut()
            .expect("metadata object")
            .remove("output_cursor");
        document["execs"][0]
            .as_object_mut()
            .expect("exec metadata object")
            .remove("output_cursor");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("encode schema-v1 metadata"),
        )
        .expect("replace metadata with schema-v1 document");

        let loaded = ShimMetadata::load(&path)
            .expect("load schema-v1 metadata")
            .expect("metadata exists");
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.output_cursor(), 0);
        assert_eq!(loaded.execs()[0].output_cursor, 0);
    }

    #[test]
    fn schema_v2_metadata_round_trip_preserves_task_and_exec_output_cursors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut expected = metadata(directory.path());
        expected.output_cursor = 41;
        let process: Process = serde_json::from_value(serde_json::json!({
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }))
        .expect("OCI process");
        let mut exec = ExecMetadata::new(
            "exec-a".to_string(),
            process,
            String::new(),
            "exec-out".to_string(),
            "exec-err".to_string(),
            false,
        );
        exec.output_cursor = 73;
        expected.set_execs(vec![exec]);

        expected.store().expect("store schema-v2 metadata");
        let loaded = ShimMetadata::load(&ShimMetadata::path(directory.path()))
            .expect("load schema-v2 metadata")
            .expect("metadata exists");

        assert_eq!(loaded.schema_version, METADATA_SCHEMA_VERSION);
        assert_eq!(loaded.output_cursor(), 41);
        assert_eq!(loaded.execs()[0].output_cursor, 73);
    }

    #[test]
    fn task_incarnation_is_stable_within_one_bundle_and_distinct_across_bundles() {
        let first_bundle = tempfile::tempdir().expect("first bundle");
        let second_bundle = tempfile::tempdir().expect("second bundle");

        let first = ShimMetadata::load_or_create_incarnation(first_bundle.path())
            .expect("create first incarnation");
        let replay = ShimMetadata::load_or_create_incarnation(first_bundle.path())
            .expect("reload first incarnation");
        let second = ShimMetadata::load_or_create_incarnation(second_bundle.path())
            .expect("create second incarnation");

        assert_eq!(first, replay);
        assert_ne!(first, second);
        let path = ShimMetadata::incarnation_path(first_bundle.path());
        assert_eq!(
            fs::read_to_string(&path).expect("read incarnation"),
            first.as_str()
        );
        assert!(first_bundle
            .path()
            .read_dir()
            .expect("read bundle")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }

    #[test]
    fn task_incarnation_rejects_corruption_symlinks_and_wide_permissions() {
        let directory = tempfile::tempdir().expect("bundle");
        let path = ShimMetadata::incarnation_path(directory.path());

        fs::write(&path, "not-an-incarnation").expect("write invalid incarnation");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("set private invalid incarnation permissions");
        }
        let error = ShimMetadata::load_or_create_incarnation(directory.path())
            .expect_err("invalid incarnation must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        fs::remove_file(&path).expect("remove invalid incarnation");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let target = directory.path().join("incarnation-target");
            fs::write(&target, "01".repeat(32)).expect("write symlink target");
            symlink(&target, &path).expect("create incarnation symlink");
            let error = ShimMetadata::load_or_create_incarnation(directory.path())
                .expect_err("incarnation symlink must fail closed");
            assert_eq!(error.code, ErrorCode::Unavailable);
            fs::remove_file(&path).expect("remove incarnation symlink");

            fs::write(&path, "02".repeat(32)).expect("write wide incarnation");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("set wide incarnation permissions");
            let error = ShimMetadata::load_or_create_incarnation(directory.path())
                .expect_err("wide incarnation permissions must fail closed");
            assert_eq!(error.code, ErrorCode::FailedPrecondition);
        }
    }

    #[test]
    fn metadata_rejects_generation_and_identity_drift() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut value = metadata(directory.path());
        value.generation = Generation(0);
        assert_eq!(
            value.store().expect_err("generation zero must fail").code,
            ErrorCode::FailedPrecondition
        );

        let mut value = metadata(directory.path());
        value.container_id = ContainerId::new("changed").expect("container ID");
        assert_eq!(
            value.store().expect_err("identity drift must fail").code,
            ErrorCode::FailedPrecondition
        );
    }

    #[cfg(unix)]
    #[test]
    fn metadata_load_rejects_symlinks_oversized_files_and_wide_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = ShimMetadata::path(directory.path());
        let target = directory.path().join("target.json");
        fs::write(&target, b"{}").expect("write symlink target");
        symlink(&target, &path).expect("create metadata symlink");
        let error = ShimMetadata::load(&path).expect_err("metadata symlink must fail closed");
        assert!(matches!(
            error.code,
            ErrorCode::Unavailable | ErrorCode::FailedPrecondition
        ));

        fs::remove_file(&path).expect("remove metadata symlink");
        fs::write(&path, vec![b'x'; (MAX_METADATA_BYTES + 1) as usize])
            .expect("write oversized metadata");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("set private metadata mode");
        let error = ShimMetadata::load(&path).expect_err("oversized metadata must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains("exceeds"));

        fs::write(
            &path,
            serde_json::to_vec(&metadata(directory.path())).expect("encode metadata"),
        )
        .expect("write metadata with wide permissions");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set wide metadata mode");
        let error = ShimMetadata::load(&path).expect_err("wide metadata mode must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);
        assert!(error.message.contains("unsafe mode"));
    }
}
