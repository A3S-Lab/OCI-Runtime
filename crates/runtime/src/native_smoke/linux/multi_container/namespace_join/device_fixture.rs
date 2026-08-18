use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_agent::{OciLinuxDefaultDeviceNode, OCI_LINUX_DEFAULT_DEVICE_NODES};
use a3s_oci_sdk::OciBundle;

pub(super) struct JoinedMountDeviceFixture {
    created: Vec<PathBuf>,
}

impl JoinedMountDeviceFixture {
    pub(super) fn prepare(bundle: &OciBundle) -> Result<Self, String> {
        let root = bundle
            .spec()
            .root()
            .as_ref()
            .ok_or_else(|| "joined mount device fixture requires config.root".to_string())?;
        let configured = root.path();
        let rootfs = if configured.is_absolute() {
            configured.to_path_buf()
        } else {
            bundle.directory().join(configured)
        }
        .canonicalize()
        .map_err(|error| {
            format!(
                "failed to resolve joined mount device fixture rootfs {}: {error}",
                configured.display()
            )
        })?;
        let device_directory = rootfs.join("dev");
        let metadata = fs::symlink_metadata(&device_directory).map_err(|error| {
            format!(
                "failed to inspect joined mount device directory {}: {error}",
                device_directory.display()
            )
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "joined mount device directory must be a real directory: {}",
                device_directory.display()
            ));
        }

        let mut fixture = Self {
            created: Vec::with_capacity(OCI_LINUX_DEFAULT_DEVICE_NODES.len() + 1),
        };
        for device in OCI_LINUX_DEFAULT_DEVICE_NODES {
            fixture.prepare_device(&rootfs, device)?;
        }
        fixture.prepare_ptmx_link(&device_directory)?;
        Ok(fixture)
    }

    fn prepare_device(
        &mut self,
        rootfs: &Path,
        device: OciLinuxDefaultDeviceNode,
    ) -> Result<(), String> {
        let relative = Path::new(device.path)
            .strip_prefix("/")
            .map_err(|error| format!("fixed OCI device path is not absolute: {error}"))?;
        let target = rootfs.join(relative);
        match fs::symlink_metadata(&target) {
            Ok(metadata) => return verify_joined_mount_device(&target, &metadata, device),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect joined mount device {}: {error}",
                    target.display()
                ));
            }
        }

        let target_c = CString::new(target.as_os_str().as_bytes()).map_err(|error| {
            format!(
                "joined mount device path {} contains NUL: {error}",
                target.display()
            )
        })?;
        // SAFETY: the target is a NUL-terminated path beneath the private
        // qualification rootfs and the fixed type and device numbers are valid.
        if unsafe {
            libc::mknod(
                target_c.as_ptr(),
                libc::S_IFCHR | device.mode,
                libc::makedev(device.major, device.minor),
            )
        } != 0
        {
            return Err(format!(
                "failed to create joined mount device {}: {}",
                target.display(),
                io::Error::last_os_error()
            ));
        }
        self.created.push(target.clone());
        // SAFETY: the path remains live and names the node created above.
        if unsafe { libc::chown(target_c.as_ptr(), 0, 0) } != 0 {
            return Err(format!(
                "failed to set joined mount device ownership {}: {}",
                target.display(),
                io::Error::last_os_error()
            ));
        }
        fs::set_permissions(&target, fs::Permissions::from_mode(device.mode)).map_err(|error| {
            format!(
                "failed to set joined mount device mode {}: {error}",
                target.display()
            )
        })?;
        let metadata = fs::symlink_metadata(&target).map_err(|error| {
            format!(
                "failed to verify joined mount device {}: {error}",
                target.display()
            )
        })?;
        verify_joined_mount_device(&target, &metadata, device)
    }

    fn prepare_ptmx_link(&mut self, device_directory: &Path) -> Result<(), String> {
        let target = device_directory.join("ptmx");
        match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let link = fs::read_link(&target).map_err(|error| {
                    format!(
                        "failed to read joined mount /dev/ptmx link {}: {error}",
                        target.display()
                    )
                })?;
                if link == Path::new("pts/ptmx") {
                    return Ok(());
                }
                return Err(format!(
                    "joined mount /dev/ptmx must link to pts/ptmx, found {}",
                    link.display()
                ));
            }
            Ok(_) => {
                return Err(format!(
                    "joined mount /dev/ptmx is not the required symlink: {}",
                    target.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to inspect joined mount /dev/ptmx {}: {error}",
                    target.display()
                ));
            }
        }
        std::os::unix::fs::symlink("pts/ptmx", &target).map_err(|error| {
            format!(
                "failed to create joined mount /dev/ptmx {}: {error}",
                target.display()
            )
        })?;
        self.created.push(target);
        Ok(())
    }

    pub(super) fn cleanup(mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        let created = std::mem::take(&mut self.created);
        for target in created.into_iter().rev() {
            if let Err(error) = fs::remove_file(&target) {
                failures.push(format!("{}: {error}", target.display()));
                self.created.push(target);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "failed to remove joined mount device fixtures: {}",
                failures.join("; ")
            ))
        }
    }
}

impl Drop for JoinedMountDeviceFixture {
    fn drop(&mut self) {
        for target in self.created.drain(..).rev() {
            let _ = fs::remove_file(target);
        }
    }
}

fn verify_joined_mount_device(
    path: &Path,
    metadata: &fs::Metadata,
    device: OciLinuxDefaultDeviceNode,
) -> Result<(), String> {
    if metadata.file_type().is_char_device()
        && libc::major(metadata.rdev()) == device.major
        && libc::minor(metadata.rdev()) == device.minor
        && metadata.mode() & 0o7777 == device.mode
        && metadata.uid() == 0
        && metadata.gid() == 0
    {
        Ok(())
    } else {
        Err(format!(
            "joined mount device differs from {} {}:{} mode {:04o} owner 0:0: {}",
            device.path,
            device.major,
            device.minor,
            device.mode,
            path.display()
        ))
    }
}
