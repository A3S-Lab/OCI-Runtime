use std::fs::{self, File, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use a3s_oci_sdk::{Error, ErrorCode, Result};

const KVM_DEVICE: &str = "/dev/kvm";
const KVM_API_VERSION: i32 = 12;
const KVM_GET_API_VERSION: libc::Ioctl = 0xAE00;

/// Descriptor-pinned KVM device prerequisite for one real Linux VM entry.
#[derive(Debug)]
pub(crate) struct LinuxKvmDevice {
    path: PathBuf,
    device: File,
    identity: DeviceIdentity,
}

impl LinuxKvmDevice {
    pub(crate) fn open() -> Result<Self> {
        Self::open_path(Path::new(KVM_DEVICE))
    }

    fn open_path(path: &Path) -> Result<Self> {
        let path_metadata = fs::symlink_metadata(path).map_err(|error| {
            device_error(format!(
                "failed to inspect Linux KVM device {}: {error}",
                path.display()
            ))
        })?;
        ensure_character_device(&path_metadata, path)?;
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                device_error(format!(
                    "failed to open Linux KVM device {} for read/write: {error}",
                    path.display()
                ))
            })?;
        let descriptor_metadata = device.metadata().map_err(|error| {
            device_error(format!(
                "failed to inspect pinned Linux KVM device {}: {error}",
                path.display()
            ))
        })?;
        ensure_character_device(&descriptor_metadata, path)?;
        let identity = DeviceIdentity::from_metadata(&descriptor_metadata);
        if DeviceIdentity::from_metadata(&path_metadata) != identity {
            return Err(device_error(format!(
                "Linux KVM device changed while it was being pinned: {}",
                path.display()
            )));
        }
        Ok(Self {
            path: path.to_path_buf(),
            device,
            identity,
        })
    }

    pub(crate) fn verify_api(&self) -> Result<()> {
        // SAFETY: device is a live KVM character-device descriptor and
        // KVM_GET_API_VERSION takes no pointer argument.
        let version = unsafe { libc::ioctl(self.device.as_raw_fd(), KVM_GET_API_VERSION) };
        if version < 0 {
            return Err(device_error(format!(
                "KVM_GET_API_VERSION failed for {}: {}",
                self.path.display(),
                std::io::Error::last_os_error()
            )));
        }
        if version != KVM_API_VERSION {
            return Err(device_error(format!(
                "Linux KVM API version {version} is unsupported; expected {KVM_API_VERSION}"
            )));
        }
        Ok(())
    }

    pub(crate) fn reverify(&self) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            device_error(format!(
                "failed to re-inspect Linux KVM device {}: {error}",
                self.path.display()
            ))
        })?;
        ensure_character_device(&path_metadata, &self.path)?;
        let descriptor_metadata = self.device.metadata().map_err(|error| {
            device_error(format!(
                "failed to re-inspect pinned Linux KVM device {}: {error}",
                self.path.display()
            ))
        })?;
        ensure_character_device(&descriptor_metadata, &self.path)?;
        if DeviceIdentity::from_metadata(&path_metadata) != self.identity
            || DeviceIdentity::from_metadata(&descriptor_metadata) != self.identity
        {
            return Err(device_error(format!(
                "Linux KVM device identity changed before VM entry: {}",
                self.path.display()
            )));
        }
        self.verify_api()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeviceIdentity {
    device: u64,
    inode: u64,
    raw_device: u64,
}

impl DeviceIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            raw_device: metadata.rdev(),
        }
    }
}

fn ensure_character_device(metadata: &Metadata, path: &Path) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_char_device() {
        return Err(device_error(format!(
            "Linux KVM path must be a real character device, not a symbolic link: {}",
            path.display()
        )));
    }
    Ok(())
}

fn device_error(message: String) -> Error {
    Error::new(ErrorCode::FailedPrecondition, message).for_operation("verify-linux-kvm-device")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use super::LinuxKvmDevice;

    #[test]
    fn rejects_missing_regular_and_symbolic_paths() {
        let temporary = tempfile::tempdir().expect("temporary KVM fixture");
        let missing = temporary.path().join("missing");
        assert!(LinuxKvmDevice::open_path(&missing).is_err());

        let regular = temporary.path().join("regular");
        fs::write(&regular, b"not a KVM device").expect("write regular fixture");
        assert!(LinuxKvmDevice::open_path(&regular).is_err());

        let alias = temporary.path().join("alias");
        symlink(&regular, &alias).expect("create symbolic fixture");
        assert!(LinuxKvmDevice::open_path(&alias).is_err());
    }
}
