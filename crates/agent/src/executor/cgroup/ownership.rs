use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

use a3s_oci_sdk::{ErrorCode, Result};

use super::super::mount::MountPlan;
use super::super::namespace::NamespacePlan;
use super::cgroup_error;

const CGROUP_DELEGATE_FILE: &str = "/sys/kernel/cgroup/delegate";
const FALLBACK_DELEGATE_FILES: [&str; 3] =
    ["cgroup.procs", "cgroup.subtree_control", "cgroup.threads"];
const MAX_DELEGATE_BYTES: usize = 64 * 1024;
const MAX_DELEGATE_FILES: usize = 256;
const MAX_DELEGATE_NAME_BYTES: usize = 255;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum CgroupOwnershipState {
    #[default]
    Preserve,
    Requested,
    Resolved(u32),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::executor) struct CgroupOwnershipPlan {
    state: CgroupOwnershipState,
}

impl CgroupOwnershipPlan {
    pub(in crate::executor) fn from_mounts(
        mounts: &[MountPlan],
        namespaces: &NamespacePlan,
    ) -> Self {
        let requested =
            namespaces.new_cgroup() && mounts.iter().any(MountPlan::requests_cgroup_ownership);
        Self {
            state: if requested {
                CgroupOwnershipState::Requested
            } else {
                CgroupOwnershipState::Preserve
            },
        }
    }

    pub(in crate::executor) const fn requested(self) -> bool {
        !matches!(self.state, CgroupOwnershipState::Preserve)
    }

    pub(in crate::executor) fn resolve(
        &mut self,
        process_uid: u32,
        namespaces: &NamespacePlan,
        rootless_effective_uid: Option<u32>,
    ) -> Result<()> {
        if matches!(
            self.state,
            CgroupOwnershipState::Preserve | CgroupOwnershipState::Resolved(_)
        ) {
            return Ok(());
        }
        let host_uid = if namespaces.has_user() {
            namespaces.host_uid(process_uid).ok_or_else(|| {
                cgroup_error(
                    ErrorCode::FailedPrecondition,
                    "process.user.uid has no resolved host mapping for cgroup delegation",
                )
            })?
        } else {
            process_uid
        };
        if host_uid == u32::MAX {
            return Err(cgroup_error(
                ErrorCode::Unsupported,
                "cgroup delegation cannot use the Linux chown no-change UID sentinel",
            ));
        }
        if let Some(effective_uid) = rootless_effective_uid {
            if host_uid != effective_uid {
                return Err(cgroup_error(
                    ErrorCode::Unsupported,
                    format!(
                        "rootless writable cgroup delegation requires process.user.uid to map to the executor UID {effective_uid}, not {host_uid}"
                    ),
                ));
            }
        }
        self.state = CgroupOwnershipState::Resolved(host_uid);
        Ok(())
    }

    pub(super) fn apply(self, cgroup: &Path) -> Result<()> {
        self.apply_with_delegate_source(cgroup, Path::new(CGROUP_DELEGATE_FILE))
    }

    fn apply_with_delegate_source(self, cgroup: &Path, delegate_source: &Path) -> Result<()> {
        let Some(uid) = self.resolved_uid()? else {
            return Ok(());
        };
        let directory = open_cgroup_directory(cgroup)?;
        let delegated_files = delegated_files(delegate_source)?;
        apply_delegated_targets(uid, &delegated_files, |target, uid| {
            chown_and_verify(directory.as_raw_fd(), target, uid)
        })
    }

    fn resolved_uid(self) -> Result<Option<u32>> {
        match self.state {
            CgroupOwnershipState::Preserve => Ok(None),
            CgroupOwnershipState::Resolved(uid) => Ok(Some(uid)),
            CgroupOwnershipState::Requested => Err(cgroup_error(
                ErrorCode::Internal,
                "cgroup ownership was not resolved before executor mutation",
            )),
        }
    }
}

fn open_cgroup_directory(path: &Path) -> Result<OwnedFd> {
    let path_string = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
        cgroup_error(
            ErrorCode::InvalidArgument,
            format!("container cgroup path contains NUL: {error}"),
        )
    })?;
    // SAFETY: the path is NUL-terminated. O_NOFOLLOW rejects replacement of
    // the final runtime-created cgroup with a symlink, and open returns a new
    // descriptor on success.
    let descriptor = unsafe {
        libc::open(
            path_string.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "failed to retain container cgroup {} for ownership delegation: {}",
                path.display(),
                io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: open returned a fresh descriptor whose ownership transfers here.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn delegated_files(source: &Path) -> Result<Vec<String>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(FALLBACK_DELEGATE_FILES
                .into_iter()
                .map(str::to_string)
                .collect());
        }
        Err(error) => {
            return Err(cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to open cgroup delegation inventory {}: {error}",
                    source.display()
                ),
            ));
        }
    };
    let mut contents = Vec::new();
    file.by_ref()
        .take((MAX_DELEGATE_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|error| {
            cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "failed to read cgroup delegation inventory {}: {error}",
                    source.display()
                ),
            )
        })?;
    if contents.len() > MAX_DELEGATE_BYTES {
        return Err(cgroup_error(
            ErrorCode::ResourceExhausted,
            format!(
                "cgroup delegation inventory {} exceeds {MAX_DELEGATE_BYTES} bytes",
                source.display()
            ),
        ));
    }
    let contents = String::from_utf8(contents).map_err(|error| {
        cgroup_error(
            ErrorCode::FailedPrecondition,
            format!(
                "cgroup delegation inventory {} is not UTF-8: {error}",
                source.display()
            ),
        )
    })?;
    parse_delegated_files(&contents, source)
}

fn parse_delegated_files(contents: &str, source: &Path) -> Result<Vec<String>> {
    let mut unique = BTreeSet::new();
    let mut files = Vec::new();
    for name in contents.lines().filter(|line| !line.is_empty()) {
        let path = Path::new(name);
        let mut components = path.components();
        let valid_component =
            matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
        let valid_bytes = !name.as_bytes().contains(&0)
            && name.len() <= MAX_DELEGATE_NAME_BYTES
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if !valid_component || !valid_bytes || matches!(name, "." | "..") {
            return Err(cgroup_error(
                ErrorCode::FailedPrecondition,
                format!(
                    "cgroup delegation inventory {} contains invalid file name {name:?}",
                    source.display()
                ),
            ));
        }
        if unique.insert(name.to_string()) {
            files.push(name.to_string());
            if files.len() > MAX_DELEGATE_FILES {
                return Err(cgroup_error(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "cgroup delegation inventory {} contains more than {MAX_DELEGATE_FILES} files",
                        source.display()
                    ),
                ));
            }
        }
    }
    Ok(files)
}

fn apply_delegated_targets<F>(uid: u32, files: &[String], mut apply: F) -> Result<()>
where
    F: FnMut(Option<&str>, u32) -> io::Result<()>,
{
    apply(None, uid).map_err(|error| {
        cgroup_error(
            ErrorCode::PermissionDenied,
            format!("failed to delegate container cgroup directory to UID {uid}: {error}"),
        )
    })?;
    for name in files {
        match apply(Some(name), uid) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(cgroup_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "failed to delegate container cgroup file {name:?} to UID {uid}: {error}"
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn chown_and_verify(directory: RawFd, target: Option<&str>, uid: u32) -> io::Result<()> {
    let name = CString::new(target.unwrap_or_default())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let flags = if target.is_some() {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW
    };
    // SAFETY: directory is a retained O_PATH directory descriptor and name is
    // NUL-terminated. A gid_t of all ones asks Linux to preserve the group.
    if unsafe {
        libc::fchownat(
            directory,
            name.as_ptr(),
            uid as libc::uid_t,
            libc::gid_t::MAX,
            flags,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata points to writable storage for one stat result, and the
    // same retained descriptor-relative target is used for verification.
    if unsafe { libc::fstatat(directory, name.as_ptr(), metadata.as_mut_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat succeeded and initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_uid != uid as libc::uid_t {
        return Err(io::Error::other(format!(
            "ownership read-back returned UID {}, expected {uid}",
            metadata.st_uid
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::MetadataExt;

    use a3s_oci_sdk::oci_spec::runtime::{Linux, Mount};

    use super::*;
    use crate::executor::{mount, namespace::NamespacePlan};

    fn namespace_plan(value: serde_json::Value, process_uid: u32) -> NamespacePlan {
        let linux: Linux = serde_json::from_value(value).expect("decode Linux namespace fixture");
        NamespacePlan::from_linux(Some(&linux), process_uid, 0, &[])
            .expect("plan Linux namespace fixture")
    }

    fn mount_plans(value: serde_json::Value, namespaces: &NamespacePlan) -> Vec<MountPlan> {
        let mounts: Vec<Mount> = serde_json::from_value(value).expect("decode mount fixtures");
        mount::plan_all(Some(&mounts), namespaces).expect("plan mount fixtures")
    }

    fn cgroup_mount(options: &[&str], source: &str, filesystem: &str) -> serde_json::Value {
        serde_json::json!([{
            "destination": "/sys/fs/cgroup",
            "source": source,
            "type": filesystem,
            "options": options
        }])
    }

    #[test]
    fn requests_ownership_only_for_the_exact_writable_new_namespace_mount() {
        let created = namespace_plan(serde_json::json!({"namespaces": [{"type": "cgroup"}]}), 0);
        let inherited = namespace_plan(serde_json::json!({}), 0);
        let joined = namespace_plan(
            serde_json::json!({
                "namespaces": [{"type": "cgroup", "path": "/proc/1/ns/cgroup"}]
            }),
            0,
        );

        let writable = mount_plans(cgroup_mount(&["rw", "nodev"], "cgroup", "cgroup"), &created);
        assert!(CgroupOwnershipPlan::from_mounts(&writable, &created).requested());
        let default_writable = mount_plans(
            serde_json::json!([{
                "destination": "/sys/fs/cgroup",
                "source": "cgroup",
                "type": "cgroup"
            }]),
            &created,
        );
        assert!(CgroupOwnershipPlan::from_mounts(&default_writable, &created).requested());

        for (mounts, namespaces) in [
            (
                mount_plans(cgroup_mount(&["ro", "rw"], "cgroup", "cgroup"), &created),
                &created,
            ),
            (
                mount_plans(cgroup_mount(&["rw"], "cgroup2", "cgroup2"), &created),
                &created,
            ),
            (
                mount_plans(cgroup_mount(&["rw"], "cgroup/", "cgroup"), &created),
                &created,
            ),
            (
                mount_plans(cgroup_mount(&["rw"], "cgroup", "cgroup"), &inherited),
                &inherited,
            ),
            (
                mount_plans(cgroup_mount(&["rw"], "cgroup", "cgroup"), &joined),
                &joined,
            ),
            (
                mount_plans(
                    serde_json::json!([{
                        "destination": "/sys/fs/./cgroup",
                        "source": "cgroup",
                        "type": "cgroup",
                        "options": ["rw"]
                    }]),
                    &created,
                ),
                &created,
            ),
        ] {
            assert!(!CgroupOwnershipPlan::from_mounts(&mounts, namespaces).requested());
        }
    }

    #[test]
    fn resolves_process_uid_through_the_container_user_mapping() {
        let namespaces = namespace_plan(
            serde_json::json!({
                "namespaces": [{"type": "cgroup"}, {"type": "user"}],
                "uidMappings": [
                    {"containerID": 0, "hostID": 100000, "size": 1},
                    {"containerID": 7, "hostID": 200007, "size": 1}
                ],
                "gidMappings": [{"containerID": 0, "hostID": 100000, "size": 1}]
            }),
            7,
        );
        let mounts = mount_plans(cgroup_mount(&["rw"], "cgroup", "cgroup"), &namespaces);
        let mut plan = CgroupOwnershipPlan::from_mounts(&mounts, &namespaces);
        plan.resolve(7, &namespaces, None)
            .expect("resolve mapped process owner");
        assert_eq!(plan.resolved_uid().expect("resolved owner"), Some(200007));
    }

    #[test]
    fn rootless_delegation_cannot_transfer_ownership_to_a_subordinate_uid() {
        let namespaces = namespace_plan(
            serde_json::json!({
                "namespaces": [{"type": "cgroup"}, {"type": "user"}],
                "uidMappings": [
                    {"containerID": 0, "hostID": 20000, "size": 1},
                    {"containerID": 1, "hostID": 300000, "size": 1}
                ],
                "gidMappings": [{"containerID": 0, "hostID": 20000, "size": 1}]
            }),
            1,
        );
        let mounts = mount_plans(cgroup_mount(&["rw"], "cgroup", "cgroup"), &namespaces);
        let mut plan = CgroupOwnershipPlan::from_mounts(&mounts, &namespaces);
        let error = plan
            .resolve(1, &namespaces, Some(20000))
            .expect_err("rootless runtime cannot chown to a subordinate UID");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("executor UID 20000, not 300000"));
    }

    #[test]
    fn rejects_the_linux_chown_no_change_uid_sentinel() {
        let namespaces = namespace_plan(
            serde_json::json!({"namespaces": [{"type": "cgroup"}]}),
            u32::MAX,
        );
        let mounts = mount_plans(cgroup_mount(&["rw"], "cgroup", "cgroup"), &namespaces);
        let mut plan = CgroupOwnershipPlan::from_mounts(&mounts, &namespaces);
        let error = plan
            .resolve(u32::MAX, &namespaces, None)
            .expect_err("the chown no-change sentinel cannot name a delegated owner");
        assert_eq!(error.code, ErrorCode::Unsupported);
        assert!(error.message.contains("chown no-change UID sentinel"));
    }

    #[test]
    fn missing_kernel_inventory_uses_the_normative_fallback() {
        let directory = tempfile::tempdir().expect("temporary delegate source");
        assert_eq!(
            delegated_files(&directory.path().join("missing")).expect("fallback files"),
            FALLBACK_DELEGATE_FILES.map(str::to_string)
        );
    }

    #[test]
    fn delegate_inventory_is_bounded_deduplicated_and_single_component() {
        let source = Path::new("test-delegate");
        assert_eq!(
            parse_delegated_files(
                "cgroup.procs\ncgroup.threads\ncgroup.procs\nmemory.oom.group\n",
                source,
            )
            .expect("valid inventory"),
            ["cgroup.procs", "cgroup.threads", "memory.oom.group"]
        );
        for invalid in [
            "../tasks\n",
            "/absolute\n",
            "nested/file\n",
            "white space\n",
        ] {
            let error = parse_delegated_files(invalid, source)
                .expect_err("invalid delegate file names must fail closed");
            assert_eq!(error.code, ErrorCode::FailedPrecondition);
        }
        let long_name = format!("{}\n", "a".repeat(MAX_DELEGATE_NAME_BYTES + 1));
        let error = parse_delegated_files(&long_name, source)
            .expect_err("overlong delegate file names must fail closed");
        assert_eq!(error.code, ErrorCode::FailedPrecondition);

        let too_many = (0..=MAX_DELEGATE_FILES)
            .map(|index| format!("file-{index}\n"))
            .collect::<String>();
        let error = parse_delegated_files(&too_many, source)
            .expect_err("overwide delegate inventories must fail closed");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);

        let directory = tempfile::tempdir().expect("temporary delegate inventory");
        let oversized = directory.path().join("delegate");
        std::fs::write(&oversized, vec![b'a'; MAX_DELEGATE_BYTES + 1])
            .expect("oversized delegate inventory");
        let error = delegated_files(&oversized)
            .expect_err("oversized delegate inventory bytes must fail closed");
        assert_eq!(error.code, ErrorCode::ResourceExhausted);
    }

    #[test]
    fn ownership_targets_only_the_directory_and_listed_existing_files() {
        let calls = RefCell::new(Vec::new());
        apply_delegated_targets(
            1234,
            &["cgroup.procs".to_string(), "missing".to_string()],
            |target, uid| {
                calls.borrow_mut().push((target.map(str::to_string), uid));
                if target == Some("missing") {
                    Err(io::Error::from(io::ErrorKind::NotFound))
                } else {
                    Ok(())
                }
            },
        )
        .expect("missing listed files are not fatal");
        assert_eq!(
            calls.into_inner(),
            [
                (None, 1234),
                (Some("cgroup.procs".to_string()), 1234),
                (Some("missing".to_string()), 1234),
            ]
        );
    }

    #[test]
    fn descriptor_relative_chown_preserves_the_group() {
        let directory = tempfile::tempdir().expect("temporary cgroup fixture");
        let delegated = directory.path().join("cgroup.procs");
        let unlisted = directory.path().join("memory.max");
        std::fs::write(&delegated, "").expect("delegated fixture");
        std::fs::write(&unlisted, "").expect("unlisted fixture");
        let inventory = directory.path().join("delegate");
        std::fs::write(&inventory, "cgroup.procs\nmissing\n").expect("delegate inventory");
        let before = std::fs::metadata(directory.path()).expect("directory metadata");
        let delegated_before = std::fs::metadata(&delegated).expect("delegated metadata");
        let unlisted_before = std::fs::metadata(&unlisted).expect("unlisted metadata");
        let plan = CgroupOwnershipPlan {
            state: CgroupOwnershipState::Resolved(before.uid()),
        };

        plan.apply_with_delegate_source(directory.path(), &inventory)
            .expect("descriptor-relative ownership application");

        let after = std::fs::metadata(directory.path()).expect("delegated directory metadata");
        let delegated_after = std::fs::metadata(&delegated).expect("delegated file metadata");
        let unlisted_after = std::fs::metadata(&unlisted).expect("unlisted file metadata");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(
            (delegated_after.uid(), delegated_after.gid()),
            (before.uid(), delegated_before.gid())
        );
        assert_eq!(unlisted_after.uid(), unlisted_before.uid());
        assert_eq!(unlisted_after.gid(), unlisted_before.gid());
    }
}
