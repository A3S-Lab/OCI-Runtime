use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{ErrorCode, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

#[cfg(unix)]
use cap_fs_ext::DirExt;
#[cfg(any(unix, windows))]
use cap_std::fs::OpenOptionsExt;

use crate::fault::{
    DirectoryCommitStage, DurableMutation, FaultInjector, FaultPoint, FileCommitStage,
};

#[cfg(any(unix, windows))]
use super::platform::verify_moved_directory;
use super::platform::{atomic_replace_relative, rename_directory_noreplace, sync_directory};
use super::{io_error, run_blocking, state_error, StateFilesystem, MAX_STATE_FILE_BYTES};

struct PreparedWrite {
    parent: Dir,
    destination_name: OsString,
    temporary_name: OsString,
    temporary_display: PathBuf,
    destination_display: PathBuf,
    file: cap_std::fs::File,
}

struct PreparedDirectoryMove {
    source_parent: Dir,
    destination_parent: Dir,
    source_name: OsString,
    destination_name: OsString,
    source_display: PathBuf,
    destination_display: PathBuf,
    same_parent: bool,
    #[cfg(unix)]
    source: Dir,
    #[cfg(windows)]
    source: cap_std::fs::File,
}

impl StateFilesystem {
    pub(in crate::state) async fn atomic_write_json(
        &self,
        faults: &dyn FaultInjector,
        mutation: DurableMutation,
        path: &Path,
        value: &impl Serialize,
    ) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
            state_error(
                ErrorCode::Internal,
                "encode-state-file",
                format!("failed to encode durable state {}: {error}", path.display()),
            )
        })?;
        bytes.push(b'\n');
        self.atomic_write(faults, mutation, path, &bytes).await
    }

    pub(in crate::state) async fn atomic_write(
        &self,
        faults: &dyn FaultInjector,
        mutation: DurableMutation,
        path: &Path,
        bytes: &[u8],
    ) -> Result<()> {
        if mutation.is_directory_move() {
            return Err(state_error(
                ErrorCode::Internal,
                "write-state-file",
                format!("directory mutation {mutation:?} cannot replace a state file"),
            ));
        }
        if bytes.len() as u64 > MAX_STATE_FILE_BYTES {
            return Err(state_error(
                ErrorCode::ResourceExhausted,
                "write-state-file",
                format!(
                    "durable state exceeds {MAX_STATE_FILE_BYTES} bytes: {}",
                    path.display()
                ),
            ));
        }

        let filesystem = self.clone();
        let destination = path.to_path_buf();
        let prepared = run_blocking("create-state-file", move || {
            filesystem.prepare_atomic_write(destination)
        })
        .await?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::TemporaryFileCreated,
        })?;

        let filesystem = self.clone();
        let temporary_display = prepared.temporary_display.clone();
        let prepared_file = prepared.file;
        let prepared_file = run_blocking("protect-state-file", move || {
            filesystem.protect_file(&prepared_file, &temporary_display)?;
            Ok(prepared_file)
        })
        .await?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::TemporaryFileProtected,
        })?;

        let temporary_display = prepared.temporary_display.clone();
        let mut file = tokio::fs::File::from_std(prepared_file.into_std());
        file.write_all(bytes)
            .await
            .map_err(|error| io_error("write-state-file", &temporary_display, error))?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::DataWritten,
        })?;
        file.flush()
            .await
            .map_err(|error| io_error("flush-state-file", &temporary_display, error))?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::DataFlushed,
        })?;
        file.sync_all()
            .await
            .map_err(|error| io_error("sync-state-file", &temporary_display, error))?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::FileSynced,
        })?;
        let file = file.into_std().await;

        let destination_display = prepared.destination_display.clone();
        let temporary_display = prepared.temporary_display.clone();
        let parent = prepared.parent;
        let parent = run_blocking("commit-state-file", move || {
            atomic_replace_relative(
                &parent,
                &file,
                &prepared.temporary_name,
                &prepared.destination_name,
                &temporary_display,
                &destination_display,
            )?;
            Ok(parent)
        })
        .await?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::FileReplaced,
        })?;
        sync_directory(parent, path).await?;
        faults.check(FaultPoint::DurableFile {
            mutation,
            stage: FileCommitStage::ParentDirectorySynced,
        })
    }

    pub(in crate::state) async fn atomic_move_directory(
        &self,
        faults: &dyn FaultInjector,
        mutation: DurableMutation,
        source: &Path,
        destination: &Path,
    ) -> Result<()> {
        if !mutation.is_directory_move() {
            return Err(state_error(
                ErrorCode::Internal,
                "commit-state-directory",
                format!("file mutation {mutation:?} cannot move a state directory"),
            ));
        }
        let filesystem = self.clone();
        let source = source.to_path_buf();
        let destination = destination.to_path_buf();
        let prepared = run_blocking("prepare-state-directory-move", move || {
            filesystem.prepare_directory_move(source, destination)
        })
        .await?;

        let source_display = prepared.source_display.clone();
        let destination_display = prepared.destination_display.clone();
        let source_sync_display = prepared.source_display.clone();
        let destination_sync_display = prepared.destination_display.clone();
        let same_parent = prepared.same_parent;
        let (source_parent, destination_parent) =
            run_blocking("commit-state-directory", move || {
                rename_directory_noreplace(
                    &prepared.source,
                    &prepared.source_parent,
                    &prepared.source_name,
                    &prepared.destination_parent,
                    &prepared.destination_name,
                    &source_display,
                    &destination_display,
                )?;
                verify_moved_directory(
                    &prepared.source,
                    &prepared.destination_parent,
                    &prepared.destination_name,
                    &destination_display,
                )?;
                Ok((prepared.source_parent, prepared.destination_parent))
            })
            .await?;
        faults.check(FaultPoint::DurableDirectory {
            mutation,
            stage: DirectoryCommitStage::DirectoryMoved,
        })?;
        sync_directory(source_parent, &source_sync_display).await?;
        faults.check(FaultPoint::DurableDirectory {
            mutation,
            stage: DirectoryCommitStage::SourceParentSynced,
        })?;
        if !same_parent {
            sync_directory(destination_parent, &destination_sync_display).await?;
        }
        faults.check(FaultPoint::DurableDirectory {
            mutation,
            stage: DirectoryCommitStage::DestinationParentSynced,
        })
    }

    fn prepare_atomic_write(&self, destination: PathBuf) -> Result<PreparedWrite> {
        let (parent, destination_name) =
            self.resolve_parent(&destination, "durable state parent")?;
        match parent.symlink_metadata(&destination_name) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || super::metadata_is_reparse_point(&metadata)
                {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "write-state-file",
                        format!(
                            "durable state destination is not a plain file: {}",
                            destination.display()
                        ),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect-state-file-destination",
                    &destination,
                    error,
                ));
            }
        }

        let destination_name_utf8 = destination_name.to_str().ok_or_else(|| {
            state_error(
                ErrorCode::Internal,
                "write-state-file",
                format!(
                    "durable state filename is not valid UTF-8: {}",
                    destination.display()
                ),
            )
        })?;
        let temporary_name = OsString::from(format!(".{destination_name_utf8}.next"));
        let temporary_display = destination.with_file_name(&temporary_name);
        match parent.symlink_metadata(&temporary_name) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || super::metadata_is_reparse_point(&metadata)
                {
                    return Err(state_error(
                        ErrorCode::FailedPrecondition,
                        "remove-stale-state-transaction",
                        format!(
                            "state transaction path is not a plain file: {}",
                            temporary_display.display()
                        ),
                    ));
                }
                let stale = self.open_plain_file_in_parent(
                    &parent,
                    &temporary_name,
                    &temporary_display,
                    "state transaction file",
                )?;
                self.protect_file(&stale, &temporary_display)?;
                drop(stale);
                parent.remove_file(&temporary_name).map_err(|error| {
                    io_error("remove-stale-state-transaction", &temporary_display, error)
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect-state-transaction",
                    &temporary_display,
                    error,
                ));
            }
        }

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options.follow(FollowSymlinks::No);
        #[cfg(unix)]
        options.mode(0o600);
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC, WRITE_OWNER,
            };

            options.access_mode(
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
            );
        }
        let file = parent
            .open_with(&temporary_name, &options)
            .map_err(|error| io_error("create-state-file", &temporary_display, error))?;
        self.verify_file_location(&file, &temporary_display)?;
        Ok(PreparedWrite {
            parent,
            destination_name,
            temporary_name,
            temporary_display,
            destination_display: destination,
            file,
        })
    }

    fn prepare_directory_move(
        &self,
        source: PathBuf,
        destination: PathBuf,
    ) -> Result<PreparedDirectoryMove> {
        let (source_parent, source_name) =
            self.resolve_parent(&source, "state transaction source parent")?;
        #[cfg(unix)]
        let source_handle = {
            let directory = source_parent
                .open_dir_nofollow(&source_name)
                .map_err(|error| {
                    state_error(
                        ErrorCode::FailedPrecondition,
                        "commit-state-directory",
                        format!(
                            "state transaction source is not a plain directory: {}: {error}",
                            source.display()
                        ),
                    )
                })?;
            self.verify_directory_location(&directory, &source)?;
            directory
        };
        #[cfg(windows)]
        let source_handle = self.open_directory_for_move(&source_parent, &source_name, &source)?;

        let (destination_parent, destination_name) =
            self.resolve_parent(&destination, "state transaction destination parent")?;
        match destination_parent.symlink_metadata(&destination_name) {
            Ok(_) => {
                return Err(state_error(
                    ErrorCode::Conflict,
                    "commit-state-directory",
                    format!(
                        "state transaction destination already exists: {}",
                        destination.display()
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect-state-directory-destination",
                    &destination,
                    error,
                ));
            }
        }
        let source_parent_path = source.parent().ok_or_else(|| {
            state_error(
                ErrorCode::Internal,
                "commit-state-directory",
                format!("state source has no parent: {}", source.display()),
            )
        })?;
        let destination_parent_path = destination.parent().ok_or_else(|| {
            state_error(
                ErrorCode::Internal,
                "commit-state-directory",
                format!("state destination has no parent: {}", destination.display()),
            )
        })?;
        let same_parent = source_parent_path == destination_parent_path;
        Ok(PreparedDirectoryMove {
            source_parent,
            destination_parent,
            source_name,
            destination_name,
            source_display: source,
            destination_display: destination,
            same_parent,
            source: source_handle,
        })
    }

    #[cfg(windows)]
    fn open_directory_for_move(
        &self,
        parent: &Dir,
        name: &std::ffi::OsStr,
        display: &Path,
    ) -> Result<cap_std::fs::File> {
        use cap_fs_ext::OsMetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        let mut options = OpenOptions::new();
        options.access_mode(FILE_GENERIC_READ | DELETE);
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        options.follow(FollowSymlinks::No);
        let directory = parent.open_with(name, &options).map_err(|error| {
            state_error(
                ErrorCode::FailedPrecondition,
                "commit-state-directory",
                format!(
                    "state transaction source is not a plain directory: {}: {error}",
                    display.display()
                ),
            )
        })?;
        let metadata = directory
            .metadata()
            .map_err(|error| io_error("inspect-state-directory-source", display, error))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(state_error(
                ErrorCode::FailedPrecondition,
                "commit-state-directory",
                format!(
                    "state transaction source is not a plain directory: {}",
                    display.display()
                ),
            ));
        }
        self.verify_file_location(&directory, display)?;
        Ok(directory)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::os::windows::fs::symlink_dir;

    use super::super::platform::{rename_directory_noreplace, verify_moved_directory};
    use crate::state::DurableStateStore;

    #[tokio::test]
    async fn moves_the_prepared_directory_object_when_its_name_is_replaced() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let requested_root = temporary.path().join("state");
        let external = temporary.path().join("external-directory");
        let external_sentinel = external.join("sentinel.txt");
        let store = DurableStateStore::open(&requested_root)
            .await
            .expect("initialize state root");
        let root = store.root();
        let source = root.join("containers/source");
        let displaced = root.join("containers/source.displaced");
        let destination = root.join("quarantine/destination");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::write(source.join("original.txt"), b"original-directory\n")
            .expect("original source sentinel");
        std::fs::create_dir(&external).expect("external directory");
        std::fs::write(&external_sentinel, b"external-directory\n").expect("external sentinel");

        let prepared = store
            .filesystem
            .prepare_directory_move(source.clone(), destination.clone())
            .expect("prepare exact source object");
        std::fs::rename(&source, &displaced).expect("displace prepared source name");
        symlink_dir(&external, &source).expect("replace source name with directory symlink");

        rename_directory_noreplace(
            &prepared.source,
            &prepared.source_parent,
            &prepared.source_name,
            &prepared.destination_parent,
            &prepared.destination_name,
            &prepared.source_display,
            &prepared.destination_display,
        )
        .expect("rename exact prepared directory object");
        verify_moved_directory(
            &prepared.source,
            &prepared.destination_parent,
            &prepared.destination_name,
            &prepared.destination_display,
        )
        .expect("verify moved directory identity");

        assert_eq!(
            std::fs::read(destination.join("original.txt")).expect("moved original sentinel"),
            b"original-directory\n"
        );
        assert!(!displaced.exists());
        assert_eq!(
            std::fs::read(&external_sentinel).expect("external sentinel remains readable"),
            b"external-directory\n"
        );
        assert_eq!(
            std::fs::read_dir(&external)
                .expect("external directory")
                .count(),
            1
        );
    }
}
