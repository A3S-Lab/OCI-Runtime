use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;

use a3s_oci_sdk::{ErrorCode, Result};

use super::{IdMapping, NamespaceAction, NamespacePlan};
use crate::executor::executor_error;

#[derive(Debug, Clone, Copy)]
struct NamespaceKind {
    name: &'static str,
    clone_flag: libc::c_int,
}

const NAMESPACE_KINDS: [NamespaceKind; 8] = [
    NamespaceKind {
        name: "user",
        clone_flag: libc::CLONE_NEWUSER,
    },
    NamespaceKind {
        name: "cgroup",
        clone_flag: libc::CLONE_NEWCGROUP,
    },
    NamespaceKind {
        name: "ipc",
        clone_flag: libc::CLONE_NEWIPC,
    },
    NamespaceKind {
        name: "uts",
        clone_flag: libc::CLONE_NEWUTS,
    },
    NamespaceKind {
        name: "net",
        clone_flag: libc::CLONE_NEWNET,
    },
    NamespaceKind {
        name: "mnt",
        clone_flag: libc::CLONE_NEWNS,
    },
    NamespaceKind {
        name: "pid",
        clone_flag: libc::CLONE_NEWPID,
    },
    NamespaceKind {
        name: "time",
        clone_flag: libc::CLONE_NEWTIME,
    },
];

#[derive(Debug)]
struct RetainedNamespace {
    kind: NamespaceKind,
    descriptor: File,
    identity: FileIdentity,
    enter: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_file(file: &File, description: &str) -> Result<Self> {
        let metadata = file.metadata().map_err(|error| {
            retained_error(
                ErrorCode::Internal,
                format!("failed to inspect {description}: {error}"),
            )
        })?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    async fn from_path(path: &str, description: &str) -> Result<Self> {
        let metadata = tokio::fs::metadata(path).await.map_err(|error| {
            retained_error(
                ErrorCode::PermissionDenied,
                format!("failed to inspect {description} at {path}: {error}"),
            )
        })?;
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

/// One validated namespace descriptor supplied to the single-threaded exec helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetainedNamespaceArgument {
    pub(crate) name: &'static str,
    pub(crate) clone_flag: libc::c_int,
    pub(crate) descriptor: RawFd,
}

/// Root and namespace descriptors pinned while the configured process is alive.
#[derive(Debug)]
pub(crate) struct RetainedExecutionContext {
    rootfs: File,
    root_identity: FileIdentity,
    namespaces: Vec<RetainedNamespace>,
    uid_mappings: Vec<IdMapping>,
    gid_mappings: Vec<IdMapping>,
    new_user_namespace: bool,
}

impl RetainedExecutionContext {
    pub(crate) async fn capture(
        plan: &NamespacePlan,
        runtime_pid: i32,
        original_rootfs: File,
    ) -> Result<Self> {
        if runtime_pid <= 0 {
            return Err(retained_error(
                ErrorCode::InvalidArgument,
                format!("cannot retain execution context for PID {runtime_pid}"),
            ));
        }
        let rootfs = if plan.new_mount() {
            open_proc_file(runtime_pid, "root", "container root").await?
        } else {
            original_rootfs
        };
        let root_identity = FileIdentity::from_file(&rootfs, "retained container root")?;

        let mut namespaces = Vec::new();
        for (kind, action) in namespace_actions(plan) {
            if !action.is_configured() {
                continue;
            }
            let descriptor =
                open_proc_file(runtime_pid, &format!("ns/{}", kind.name), kind.name).await?;
            let identity =
                FileIdentity::from_file(&descriptor, &format!("retained {} namespace", kind.name))?;
            let current = FileIdentity::from_path(
                &format!("/proc/self/ns/{}", kind.name),
                &format!("current {} namespace", kind.name),
            )
            .await?;
            namespaces.push(RetainedNamespace {
                kind,
                descriptor,
                identity,
                enter: identity != current,
            });
        }

        Ok(Self {
            rootfs,
            root_identity,
            namespaces,
            uid_mappings: plan.uid_mappings().to_vec(),
            gid_mappings: plan.gid_mappings().to_vec(),
            new_user_namespace: plan.new_user(),
        })
    }

    pub(crate) fn root_descriptor(&self) -> RawFd {
        self.rootfs.as_raw_fd()
    }

    pub(crate) fn namespace_arguments(&self) -> Vec<RetainedNamespaceArgument> {
        self.namespaces
            .iter()
            .filter(|namespace| namespace.enter)
            .map(|namespace| RetainedNamespaceArgument {
                name: namespace.kind.name,
                clone_flag: namespace.kind.clone_flag,
                descriptor: namespace.descriptor.as_raw_fd(),
            })
            .collect()
    }

    pub(crate) fn inherited_descriptors(&self, init_pidfd: RawFd) -> Result<Vec<RawFd>> {
        let mut descriptors = vec![self.root_descriptor(), init_pidfd];
        descriptors.extend(
            self.namespaces
                .iter()
                .filter(|namespace| namespace.enter)
                .map(|namespace| namespace.descriptor.as_raw_fd()),
        );
        let mut unique = BTreeSet::new();
        for descriptor in &descriptors {
            if *descriptor <= libc::STDERR_FILENO || !unique.insert(*descriptor) {
                return Err(retained_error(
                    ErrorCode::Internal,
                    format!(
                        "exec helper received invalid or duplicate inherited descriptor \
                         {descriptor}"
                    ),
                ));
            }
        }
        Ok(descriptors)
    }

    pub(crate) async fn validate_process(&self, runtime_pid: i32) -> Result<()> {
        let actual_root = FileIdentity::from_path(
            &format!("/proc/{runtime_pid}/root"),
            "reported exec process root",
        )
        .await?;
        if actual_root != self.root_identity {
            return Err(retained_error(
                ErrorCode::PermissionDenied,
                format!(
                    "reported exec process {runtime_pid} did not enter the retained container root"
                ),
            ));
        }
        for namespace in &self.namespaces {
            let actual = FileIdentity::from_path(
                &format!("/proc/{runtime_pid}/ns/{}", namespace.kind.name),
                &format!("reported exec process {} namespace", namespace.kind.name),
            )
            .await?;
            if actual != namespace.identity {
                return Err(retained_error(
                    ErrorCode::PermissionDenied,
                    format!(
                        "reported exec process {runtime_pid} did not enter the retained {} \
                         namespace",
                        namespace.kind.name
                    ),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_process_ids(
        &self,
        uid: u32,
        gid: u32,
        additional_gids: &[u32],
    ) -> Result<()> {
        if !self.new_user_namespace {
            return Ok(());
        }
        ensure_mapped("exec process UID", uid, &self.uid_mappings)?;
        ensure_mapped("exec process GID", gid, &self.gid_mappings)?;
        for (index, gid) in additional_gids.iter().copied().enumerate() {
            ensure_mapped(
                &format!("exec process supplementary GID {index}"),
                gid,
                &self.gid_mappings,
            )?;
        }
        Ok(())
    }
}

async fn open_proc_file(runtime_pid: i32, relative: &str, description: &str) -> Result<File> {
    let path = format!("/proc/{runtime_pid}/{relative}");
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|error| {
            retained_error(
                ErrorCode::PermissionDenied,
                format!("failed to retain {description} from {path}: {error}"),
            )
        })?
        .into_std()
        .await;
    Ok(file)
}

fn namespace_actions(
    plan: &NamespacePlan,
) -> [(NamespaceKind, &NamespaceAction); NAMESPACE_KINDS.len()] {
    [
        (NAMESPACE_KINDS[0], &plan.user),
        (NAMESPACE_KINDS[1], &plan.cgroup),
        (NAMESPACE_KINDS[2], &plan.ipc),
        (NAMESPACE_KINDS[3], &plan.uts),
        (NAMESPACE_KINDS[4], &plan.network),
        (NAMESPACE_KINDS[5], &plan.mount),
        (NAMESPACE_KINDS[6], &plan.pid),
        (NAMESPACE_KINDS[7], &plan.time),
    ]
}

fn retained_error(code: ErrorCode, message: impl Into<String>) -> a3s_oci_sdk::Error {
    executor_error(code, message)
}

fn ensure_mapped(field: &str, id: u32, mappings: &[IdMapping]) -> Result<()> {
    if mappings
        .iter()
        .any(|mapping| id >= mapping.container_id && id - mapping.container_id < mapping.size)
    {
        Ok(())
    } else {
        Err(retained_error(
            ErrorCode::InvalidArgument,
            format!("{field} value {id} is not covered by the container ID mappings"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;

    use a3s_oci_sdk::ErrorCode;
    use tempfile::tempdir;

    use super::{FileIdentity, RetainedExecutionContext};
    use crate::executor::namespace::{IdMapping, NamespacePlan};

    #[tokio::test(flavor = "current_thread")]
    async fn retained_root_identity_validates_the_exact_running_process_root() {
        let context = RetainedExecutionContext::capture(
            &NamespacePlan::default(),
            i32::try_from(std::process::id()).expect("test PID fits the runtime model"),
            File::open("/").expect("open current root"),
        )
        .await
        .expect("capture current execution context");

        context
            .validate_process(
                i32::try_from(std::process::id()).expect("test PID fits the runtime model"),
            )
            .await
            .expect("current process retains the captured root identity");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_file_identity_does_not_follow_path_replacement() {
        let directory = tempdir().expect("temporary identity directory");
        let path = directory.path().join("namespace");
        std::fs::write(&path, b"retained").expect("create retained file");
        let retained = File::open(&path).expect("open retained file");
        let identity = FileIdentity::from_file(&retained, "retained test file")
            .expect("read retained identity");
        assert_eq!(
            FileIdentity::from_path(
                path.to_str().expect("temporary path is UTF-8"),
                "retained test path",
            )
            .await
            .expect("read path identity"),
            identity
        );

        std::fs::remove_file(&path).expect("unlink retained path");
        std::fs::write(&path, b"replacement").expect("replace retained path");
        assert_ne!(
            FileIdentity::from_path(
                path.to_str().expect("temporary path is UTF-8"),
                "replacement test path",
            )
            .await
            .expect("read replacement identity"),
            identity
        );
        assert_eq!(
            FileIdentity::from_file(&retained, "still-retained test file")
                .expect("re-read retained identity"),
            identity
        );
    }

    #[test]
    fn exec_ids_and_inherited_descriptors_are_checked_against_retained_context() {
        let rootfs = File::open("/").expect("open root");
        let root_identity =
            FileIdentity::from_file(&rootfs, "test root").expect("inspect test root");
        let context = RetainedExecutionContext {
            rootfs,
            root_identity,
            namespaces: Vec::new(),
            uid_mappings: vec![IdMapping {
                container_id: 0,
                host_id: 1_000,
                size: 2,
            }],
            gid_mappings: vec![IdMapping {
                container_id: 0,
                host_id: 2_000,
                size: 2,
            }],
            new_user_namespace: true,
        };

        context
            .validate_process_ids(1, 1, &[0, 1])
            .expect("mapped exec identities");
        for (uid, gid, additional_gids) in [(2, 1, &[][..]), (1, 2, &[][..]), (1, 1, &[2][..])] {
            let error = context
                .validate_process_ids(uid, gid, additional_gids)
                .expect_err("unmapped exec identity must fail closed");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
        }

        let error = context
            .inherited_descriptors(context.rootfs.as_raw_fd())
            .expect_err("root and init descriptors must be distinct");
        assert_eq!(error.code, ErrorCode::Internal);
    }
}
