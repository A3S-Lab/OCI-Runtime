use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use a3s_oci_agent_protocol::AgentVsockEndpoint;
use zeroize::Zeroizing;

use crate::macos_runtime_share::MacosRuntimeShare;

const MARKER_PREFIX: &str = ".a3s-oci-hvf-vm-smoke-";
const MARKER_NONCE_PREFIX: &str = "a3s-oci-agent-";
const MARKER_NONCE_HEX_BYTES: usize = 32;
const MARKER_TOKEN_HEX_BYTES: usize = 64;
pub(crate) const MAX_MARKER_BYTES: usize = MARKER_TOKEN_HEX_BYTES + 1;
const PRIVATE_MARKER_MODE: u32 = 0o600;

#[derive(Debug)]
pub(crate) struct PinnedMarkerDirectory {
    directory: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MarkerConsumption {
    pub(crate) verified: bool,
    pub(crate) removed: bool,
    pub(crate) content_len: usize,
}

impl PinnedMarkerDirectory {
    pub(crate) fn open(runtime_share: &MacosRuntimeShare) -> io::Result<Self> {
        // Duplicate the retained descriptor directly. All marker operations
        // below are then relative to that duplicate and cannot be redirected
        // by replacing the public runtime-share pathname.
        let directory = runtime_share.duplicate_directory()?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "descriptor-backed runtime share is not a directory",
            ));
        }
        let identity = (metadata.dev(), metadata.ino());
        if identity != runtime_share.identity() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "descriptor-backed runtime share identity changed",
            ));
        }
        Ok(Self { directory })
    }

    pub(crate) fn require_absent(&self, marker_name: &str) -> io::Result<()> {
        let name = marker_component(marker_name)?;
        match fstatat(&self.directory, &name) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "marker entry already exists",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn consume(
        &self,
        marker_name: &str,
        expected: &[u8],
    ) -> io::Result<MarkerConsumption> {
        let name = marker_component(marker_name)?;
        let before = fstatat(&self.directory, &name)?;
        validate_marker_stat(&before)?;
        let expected_identity = identity_from_stat(&before);

        let mut file = open_marker(&self.directory, &name)?;
        let opened = fstat(&file)?;
        validate_marker_stat(&opened)?;
        if identity_from_stat(&opened) != expected_identity {
            return Err(marker_changed("marker identity changed while opening"));
        }

        let mut contents = Vec::with_capacity(MAX_MARKER_BYTES + 1);
        (&mut file)
            .take(u64::try_from(MAX_MARKER_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut contents)?;
        let after_read = fstat(&file)?;
        let bytes_read = u64::try_from(contents.len()).map_err(|error| {
            marker_changed(format!("marker length is not representable: {error}"))
        })?;
        if bytes_read > u64::try_from(MAX_MARKER_BYTES).unwrap_or(u64::MAX)
            || stat_len(&after_read)? != bytes_read
            || identity_from_stat(&after_read) != expected_identity
        {
            return Err(marker_changed("marker changed while it was read"));
        }

        let after_path = fstatat(&self.directory, &name)?;
        validate_marker_stat(&after_path)?;
        if stat_len(&after_path)? != bytes_read
            || identity_from_stat(&after_path) != expected_identity
        {
            return Err(marker_changed("marker pathname changed after it was read"));
        }

        if contents != expected {
            // A pathname controlled by the guest (or another same-UID
            // process) is not ours to delete merely because it has the
            // expected shape. Leave an unexpected marker in place so the
            // caller can fail closed without destroying unrelated state.
            return Ok(MarkerConsumption {
                verified: false,
                removed: false,
                content_len: contents.len(),
            });
        }
        self.remove_if_identity(&name, expected_identity)?;
        Ok(MarkerConsumption {
            verified: true,
            removed: true,
            content_len: contents.len(),
        })
    }

    fn remove_if_identity(&self, name: &CStr, expected: (u64, u64)) -> io::Result<()> {
        let current = fstatat(&self.directory, name)?;
        validate_marker_stat(&current)?;
        if identity_from_stat(&current) != expected {
            return Err(marker_changed("marker identity changed before cleanup"));
        }
        // SAFETY: `directory` is a live directory descriptor and `name` is a
        // validated single component. The identity was checked immediately
        // before this unlink, and a later replacement is never followed.
        let result = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        match fstatat(&self.directory, name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(marker_changed("marker remained after cleanup")),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn generate_marker_name() -> Result<String, String> {
    let endpoint = AgentVsockEndpoint::generate()
        .map_err(|error| format!("failed to generate the macOS VM smoke marker name: {error}"))?;
    let suffix = endpoint
        .pipe_name()
        .strip_prefix(MARKER_NONCE_PREFIX)
        .ok_or_else(|| "generated marker nonce used an unexpected endpoint prefix".to_string())?;
    let marker_name = format!("{MARKER_PREFIX}{suffix}");
    validate_marker_name(&marker_name)?;
    Ok(marker_name)
}

pub(crate) fn validate_marker_name(marker_name: &str) -> Result<(), String> {
    let suffix = marker_name
        .strip_prefix(MARKER_PREFIX)
        .ok_or_else(|| "macOS VM smoke marker has an invalid prefix".to_string())?;
    if suffix.len() != MARKER_NONCE_HEX_BYTES
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "macOS VM smoke marker must contain a 128-bit lowercase hexadecimal nonce".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_marker_token(marker_token: &str) -> Result<(), String> {
    if marker_token.len() != MARKER_TOKEN_HEX_BYTES
        || !marker_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || marker_token.bytes().all(|byte| byte == b'0')
    {
        return Err(
            "macOS VM smoke marker nonce must be a non-zero 256-bit lowercase hexadecimal value"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn read_marker_token_from_stdin() -> Result<Zeroizing<String>, String> {
    let mut encoded = Vec::with_capacity(MARKER_TOKEN_HEX_BYTES + 1);
    io::stdin()
        .take(u64::try_from(MARKER_TOKEN_HEX_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut encoded)
        .map_err(|error| format!("failed to read the macOS VM smoke marker nonce: {error}"))?;
    let marker_token = String::from_utf8(encoded)
        .map_err(|error| format!("macOS VM smoke marker nonce was not UTF-8: {error}"))?;
    validate_marker_token(&marker_token)?;
    Ok(Zeroizing::new(marker_token))
}

fn marker_component(marker_name: &str) -> io::Result<CString> {
    if marker_name.is_empty()
        || marker_name == "."
        || marker_name == ".."
        || marker_name.contains('/')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "marker name must be one directory component",
        ));
    }
    CString::new(marker_name.as_bytes()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("marker name contains NUL: {error}"),
        )
    })
}

fn open_marker(parent: &File, name: &CStr) -> io::Result<File> {
    // SAFETY: `parent` is a live directory descriptor and `name` is a
    // validated single component. O_NOFOLLOW prevents a symlink from being
    // interpreted as the guest marker.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was returned by openat and ownership is transferred here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn fstat(file: &File) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `file` owns a live descriptor and `stat` points to writable
    // storage for a complete libc structure.
    let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

fn fstatat(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `parent` is a live directory descriptor, `name` is a bounded
    // component, and `stat` points to writable storage.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat returned success and initialized the structure.
    Ok(unsafe { stat.assume_init() })
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn identity_from_stat(stat: &libc::stat) -> (u64, u64) {
    (stat.st_dev as u64, stat.st_ino as u64)
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn stat_len(stat: &libc::stat) -> io::Result<u64> {
    if stat.st_size < 0 {
        return Err(marker_changed("marker reported a negative size"));
    }
    u64::try_from(stat.st_size)
        .map_err(|error| marker_changed(format!("marker size is not representable: {error}")))
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn validate_marker_stat(stat: &libc::stat) -> io::Result<()> {
    let mode = stat.st_mode as u32;
    let effective_uid = unsafe { libc::geteuid() } as u64;
    if mode & libc::S_IFMT as u32 != libc::S_IFREG as u32 {
        return Err(marker_changed("marker is not a regular file"));
    }
    if stat.st_uid as u64 != effective_uid || mode & 0o777 != PRIVATE_MARKER_MODE {
        return Err(marker_changed(
            "marker is not owned by the runtime with private permissions",
        ));
    }
    if stat.st_nlink != 1 {
        return Err(marker_changed("marker has an unexpected hard-link count"));
    }
    if stat_len(stat)? > u64::try_from(MAX_MARKER_BYTES).unwrap_or(u64::MAX) {
        return Err(marker_changed("marker exceeds the bounded size"));
    }
    Ok(())
}

fn marker_changed(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::{
        marker_component, validate_marker_name, validate_marker_token, MacosRuntimeShare,
        PinnedMarkerDirectory, MAX_MARKER_BYTES,
    };

    fn private_share() -> tempfile::TempDir {
        let temporary = tempfile::tempdir().expect("create marker fixture");
        let share = temporary.path().join("runtime-share");
        fs::create_dir(&share).expect("create runtime share");
        fs::set_permissions(&share, fs::Permissions::from_mode(0o700))
            .expect("protect runtime share");
        temporary
    }

    fn marker_name() -> &'static str {
        ".a3s-oci-hvf-vm-smoke-0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn marker_name_requires_a_fresh_hex_nonce() {
        validate_marker_name(marker_name()).expect("generated marker must pass");
        assert!(validate_marker_name(".a3s-oci-hvf-vm-smoke-123").is_err());
        assert!(validate_marker_name("../marker").is_err());
        assert!(validate_marker_name(".a3s-oci-hvf-vm-smoke-1';reboot").is_err());
        assert!(
            validate_marker_name(".a3s-oci-hvf-vm-smoke-0123456789ABCDEF0123456789abcdef").is_err()
        );
    }

    #[test]
    fn marker_token_requires_a_nonzero_lowercase_256_bit_value() {
        validate_marker_token(&"a".repeat(64)).expect("generated token must pass");
        assert!(validate_marker_token(&"0".repeat(64)).is_err());
        assert!(validate_marker_token(&"a".repeat(63)).is_err());
        assert!(validate_marker_token(&format!("{}'", "a".repeat(63))).is_err());
    }

    #[test]
    fn marker_consumption_is_descriptor_relative_and_bounded() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let expected = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        fs::write(&marker, expected).expect("write marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("protect marker");

        let consumed = directory
            .consume(marker_name(), expected)
            .expect("consume marker");
        assert!(consumed.verified);
        assert!(consumed.removed);
        assert_eq!(consumed.content_len, MAX_MARKER_BYTES);
        assert!(!marker.exists());
    }

    #[test]
    fn marker_symlinks_are_rejected_without_touching_the_target() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let target = share_path.join("target");
        let marker = share_path.join(marker_name());
        fs::write(
            &target,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("protect target");
        symlink(&target, &marker).expect("create marker symlink");

        assert!(directory.consume(marker_name(), b"ignored").is_err());
        assert!(marker.is_symlink());
        assert!(target.is_file());
    }

    #[test]
    fn marker_cleanup_preserves_a_replacement_inode() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let expected = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        fs::write(&marker, expected).expect("write marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("protect marker");
        let component = marker_component(marker_name()).expect("marker component");
        let original = fs::File::open(&marker).expect("open original marker");
        let original_stat = super::fstat(&original).expect("stat original marker");
        let original_identity = super::identity_from_stat(&original_stat);
        drop(original);
        fs::remove_file(&marker).expect("remove original marker");
        fs::write(&marker, b"replacement").expect("publish replacement marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("protect replacement marker");

        assert!(directory
            .remove_if_identity(&component, original_identity)
            .is_err());
        assert_eq!(fs::read(&marker).expect("read replacement"), b"replacement");
    }

    #[test]
    fn marker_with_wrong_nonce_is_left_untouched() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let wrong = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
        fs::write(&marker, wrong).expect("write wrong-nonce marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("protect wrong-nonce marker");

        let consumed = directory
            .consume(
                marker_name(),
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            )
            .expect("wrong-nonce marker should be inspectable");
        assert!(!consumed.verified);
        assert!(!consumed.removed);
        assert_eq!(fs::read(&marker).expect("read wrong-nonce marker"), wrong);
    }

    #[test]
    fn marker_with_non_private_mode_is_rejected_and_left_untouched() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let expected = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        fs::write(&marker, expected).expect("write marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o640))
            .expect("make marker group-readable");

        assert!(directory.consume(marker_name(), expected).is_err());
        assert_eq!(fs::read(&marker).expect("read marker"), expected);
    }

    #[test]
    fn hard_linked_marker_is_rejected_without_deleting_either_link() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let alias = share_path.join("marker-alias");
        let expected = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        fs::write(&marker, expected).expect("write marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).expect("protect marker");
        fs::hard_link(&marker, &alias).expect("create marker hard link");

        assert!(directory.consume(marker_name(), expected).is_err());
        assert_eq!(fs::read(&marker).expect("read marker"), expected);
        assert_eq!(fs::read(&alias).expect("read marker alias"), expected);
    }

    #[test]
    fn oversized_marker_is_rejected_without_deleting_the_entry() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let oversized = vec![b'a'; MAX_MARKER_BYTES + 1];
        fs::write(&marker, &oversized).expect("write oversized marker");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))
            .expect("protect oversized marker");

        assert!(directory.consume(marker_name(), b"ignored").is_err());
        assert_eq!(fs::read(&marker).expect("read oversized marker"), oversized);
    }

    #[test]
    fn fifo_marker_is_rejected_without_opening_or_removing_it() {
        let temporary = private_share();
        let share_path = temporary.path().join("runtime-share");
        let share = MacosRuntimeShare::open(&share_path).expect("pin runtime share");
        let directory = PinnedMarkerDirectory::open(&share).expect("pin marker directory");
        let marker = share_path.join(marker_name());
        let marker_c =
            CString::new(marker.as_os_str().as_bytes()).expect("marker path must be NUL-free");
        // SAFETY: `marker_c` is a valid path and the parent directory is a
        // private test fixture. `mkfifo` does not expose a borrowed pointer
        // after this call returns.
        let result = unsafe { libc::mkfifo(marker_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create marker FIFO: {}",
            std::io::Error::last_os_error()
        );

        assert!(directory.consume(marker_name(), b"ignored").is_err());
        assert!(marker.exists());
    }
}
