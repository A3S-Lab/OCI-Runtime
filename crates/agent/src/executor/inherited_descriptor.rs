use std::collections::BTreeSet;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use a3s_oci_agent_protocol::{
    AgentInheritedDescriptorRole, AgentInheritedDescriptorSchema, AgentInheritedDescriptorSlot,
    AgentInheritedDescriptorType,
};
use a3s_oci_sdk::{ErrorCode, Result};

use super::executor_error;

const MIN_DUPLICATED_DESCRIPTOR: RawFd = 10;
const MAX_INHERITED_DESCRIPTORS: usize = 16;
const MAX_TARGET_DESCRIPTOR: RawFd = 1_023;

#[derive(Debug)]
struct PreparedDescriptor {
    target: RawFd,
    source: OwnedFd,
}

/// Validated, collision-safe descriptors installed by the native create path.
///
/// Every source is duplicated close-on-exec above every target before the
/// process is spawned. The child-side installation uses `dup2`, so targets
/// survive exec while the protected source copies close automatically.
#[derive(Debug, Default)]
pub struct InheritedDescriptorPlan {
    schema: Option<AgentInheritedDescriptorSchema>,
    descriptors: Vec<PreparedDescriptor>,
}

#[derive(Clone, Copy)]
struct DescriptorSource<'a> {
    slot: AgentInheritedDescriptorSlot,
    source: BorrowedFd<'a>,
}

impl InheritedDescriptorPlan {
    /// No inherited workload descriptors, as used by the wire protocol path.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schema: None,
            descriptors: Vec::new(),
        }
    }

    /// Build the A3S Box exec/PTY/init-log descriptor contract.
    pub fn a3s_box_control(
        exec_listener: BorrowedFd<'_>,
        pty_listener: BorrowedFd<'_>,
        init_log: BorrowedFd<'_>,
    ) -> Result<Self> {
        let schema = AgentInheritedDescriptorSchema::a3s_box_control_v1();
        let sources = [
            DescriptorSource {
                slot: schema.slots[0],
                source: exec_listener,
            },
            DescriptorSource {
                slot: schema.slots[1],
                source: pty_listener,
            },
            DescriptorSource {
                slot: schema.slots[2],
                source: init_log,
            },
        ];
        Self::prepare(schema, &sources)
    }

    /// Stable schema used by create idempotency fingerprints.
    #[must_use]
    pub fn schema(&self) -> Option<&AgentInheritedDescriptorSchema> {
        self.schema.as_ref()
    }

    pub(super) fn install_in_child(&self) -> io::Result<()> {
        for descriptor in &self.descriptors {
            if unsafe { libc::dup2(descriptor.source.as_raw_fd(), descriptor.target) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn prepare(
        schema: AgentInheritedDescriptorSchema,
        sources: &[DescriptorSource<'_>],
    ) -> Result<Self> {
        validate_schema(&schema, sources)?;
        let highest_target = schema
            .slots
            .iter()
            .map(|slot| slot.target)
            .max()
            .ok_or_else(|| descriptor_error("inherited descriptor schema is empty"))?;
        let duplicate_minimum = MIN_DUPLICATED_DESCRIPTOR.max(highest_target + 1);
        let mut descriptors = Vec::with_capacity(sources.len());
        for source in sources {
            validate_source(*source)?;
            // SAFETY: the source is live for this call. F_DUPFD_CLOEXEC returns
            // a distinct owned descriptor at or above `duplicate_minimum`.
            let duplicated = unsafe {
                libc::fcntl(
                    source.source.as_raw_fd(),
                    libc::F_DUPFD_CLOEXEC,
                    duplicate_minimum,
                )
            };
            if duplicated < 0 {
                return Err(last_os_error(format!(
                    "duplicate {:?} inherited descriptor",
                    source.slot.role
                )));
            }
            // SAFETY: successful F_DUPFD_CLOEXEC returned a new owned fd.
            let duplicated = unsafe { OwnedFd::from_raw_fd(duplicated) };
            descriptors.push(PreparedDescriptor {
                target: source.slot.target,
                source: duplicated,
            });
        }
        debug_assert!(descriptors.iter().all(|descriptor| {
            descriptor.source.as_raw_fd() > highest_target
                && descriptor.source.as_raw_fd() >= MIN_DUPLICATED_DESCRIPTOR
        }));
        Ok(Self {
            schema: Some(schema),
            descriptors,
        })
    }

    #[cfg(test)]
    fn protected_sources(&self) -> Vec<(AgentInheritedDescriptorRole, RawFd, RawFd)> {
        self.schema
            .as_ref()
            .into_iter()
            .flat_map(|schema| schema.slots.iter().zip(&self.descriptors))
            .map(|(slot, descriptor)| (slot.role, descriptor.source.as_raw_fd(), descriptor.target))
            .collect()
    }
}

fn validate_schema(
    schema: &AgentInheritedDescriptorSchema,
    sources: &[DescriptorSource<'_>],
) -> Result<()> {
    if schema.profile.is_empty()
        || schema.profile.len() > 128
        || !schema
            .profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(descriptor_error(
            "inherited descriptor profile must be a bounded ASCII identifier",
        ));
    }
    if schema.slots.is_empty()
        || schema.slots.len() > MAX_INHERITED_DESCRIPTORS
        || schema.slots.len() != sources.len()
    {
        return Err(descriptor_error(format!(
            "inherited descriptor count must be 1..={MAX_INHERITED_DESCRIPTORS} and match its sources"
        )));
    }

    let mut roles = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut source_descriptors = BTreeSet::new();
    for (slot, source) in schema.slots.iter().zip(sources) {
        if *slot != source.slot {
            return Err(descriptor_error(
                "inherited descriptor sources do not match their logical schema",
            ));
        }
        if !roles.insert(slot.role) {
            return Err(descriptor_error(format!(
                "inherited descriptor role {:?} is duplicated",
                slot.role
            )));
        }
        if !(libc::STDERR_FILENO + 1..=MAX_TARGET_DESCRIPTOR).contains(&slot.target) {
            return Err(descriptor_error(format!(
                "inherited descriptor target {} is outside 3..={MAX_TARGET_DESCRIPTOR}",
                slot.target
            )));
        }
        if !targets.insert(slot.target) {
            return Err(descriptor_error(format!(
                "inherited descriptor target {} is duplicated",
                slot.target
            )));
        }
        if !source_descriptors.insert(source.source.as_raw_fd()) {
            return Err(descriptor_error(format!(
                "inherited descriptor source {} is reused across roles",
                source.source.as_raw_fd()
            )));
        }
    }
    Ok(())
}

fn validate_source(source: DescriptorSource<'_>) -> Result<()> {
    let descriptor = source.source.as_raw_fd();
    // SAFETY: F_GETFD only inspects the borrowed descriptor.
    if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return Err(last_os_error(format!(
            "inspect {:?} inherited descriptor",
            source.slot.role
        )));
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata points to writable storage for one stat structure.
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(last_os_error(format!(
            "stat {:?} inherited descriptor",
            source.slot.role
        )));
    }
    // SAFETY: successful fstat initialized the complete structure.
    let metadata = unsafe { metadata.assume_init() };
    let file_type = metadata.st_mode & libc::S_IFMT;
    match source.slot.descriptor_type {
        AgentInheritedDescriptorType::UnixStreamListener => {
            if file_type != libc::S_IFSOCK {
                return Err(descriptor_error(format!(
                    "{:?} inherited descriptor must be a Unix stream listener",
                    source.slot.role
                )));
            }
            validate_stream_listener(descriptor, source.slot.role)
        }
        AgentInheritedDescriptorType::WritableRegularFile => {
            if file_type != libc::S_IFREG {
                return Err(descriptor_error(format!(
                    "{:?} inherited descriptor must be a writable regular file",
                    source.slot.role
                )));
            }
            // SAFETY: F_GETFL only inspects the borrowed descriptor.
            let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
            if flags < 0 {
                return Err(last_os_error(format!(
                    "inspect {:?} inherited file access mode",
                    source.slot.role
                )));
            }
            if flags & libc::O_ACCMODE == libc::O_RDONLY {
                return Err(descriptor_error(format!(
                    "{:?} inherited descriptor must be writable",
                    source.slot.role
                )));
            }
            Ok(())
        }
    }
}

fn validate_stream_listener(descriptor: RawFd, role: AgentInheritedDescriptorRole) -> Result<()> {
    let socket_type = socket_option(descriptor, libc::SO_TYPE, role)?;
    if socket_type != libc::SOCK_STREAM {
        return Err(descriptor_error(format!(
            "{role:?} inherited descriptor must be a Unix stream socket"
        )));
    }
    if socket_option(descriptor, libc::SO_ACCEPTCONN, role)? != 1 {
        return Err(descriptor_error(format!(
            "{role:?} inherited descriptor must already be listening"
        )));
    }
    let mut address = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut address_length = libc::socklen_t::try_from(size_of::<libc::sockaddr_storage>())
        .map_err(|error| {
            descriptor_error(format!("socket address size is not representable: {error}"))
        })?;
    // SAFETY: address and length are writable buffers sized for every socket
    // address family and the descriptor was already verified as a socket.
    if unsafe { libc::getsockname(descriptor, address.as_mut_ptr().cast(), &mut address_length) }
        != 0
    {
        return Err(last_os_error(format!(
            "inspect {role:?} inherited socket address"
        )));
    }
    if usize::try_from(address_length).unwrap_or_default() < size_of::<libc::sa_family_t>() {
        return Err(descriptor_error(format!(
            "{role:?} inherited socket returned a truncated address"
        )));
    }
    // SAFETY: successful getsockname initialized at least the family field.
    if i32::from(unsafe { address.assume_init() }.ss_family) != libc::AF_UNIX {
        return Err(descriptor_error(format!(
            "{role:?} inherited descriptor must use the Unix socket family"
        )));
    }
    Ok(())
}

fn socket_option(
    descriptor: RawFd,
    option: libc::c_int,
    role: AgentInheritedDescriptorRole,
) -> Result<libc::c_int> {
    let mut value = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::c_int>()).map_err(|error| {
        descriptor_error(format!("socket option size is not representable: {error}"))
    })?;
    // SAFETY: value and length are writable, correctly sized buffers and the
    // borrowed descriptor was already verified as a socket.
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(last_os_error(format!(
            "inspect {role:?} inherited socket option {option}"
        )));
    }
    if usize::try_from(length).ok() != Some(size_of::<libc::c_int>()) {
        return Err(descriptor_error(format!(
            "{role:?} inherited socket returned an invalid option size"
        )));
    }
    Ok(value)
}

fn last_os_error(action: impl Into<String>) -> a3s_oci_sdk::Error {
    let action = action.into();
    descriptor_error(format!(
        "failed to {action}: {}",
        io::Error::last_os_error()
    ))
}

fn descriptor_error(message: impl Into<String>) -> a3s_oci_sdk::Error {
    executor_error(ErrorCode::InvalidArgument, message)
        .for_operation("prepare-inherited-descriptors")
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use a3s_oci_agent_protocol::{
        AgentInheritedDescriptorRole, AgentInheritedDescriptorSchema, AgentInheritedDescriptorSlot,
        AgentInheritedDescriptorType,
    };
    use a3s_oci_sdk::ErrorCode;

    use super::{DescriptorSource, InheritedDescriptorPlan, MAX_INHERITED_DESCRIPTORS};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn descriptor_plan_is_send_sync() {
        assert_send_sync::<InheritedDescriptorPlan>();
    }

    #[test]
    fn native_control_sources_are_type_checked_and_duplicated_above_targets() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let exec = UnixListener::bind(temporary.path().join("exec.sock")).expect("exec listener");
        let pty = UnixListener::bind(temporary.path().join("pty.sock")).expect("PTY listener");
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temporary.path().join("init.log"))
            .expect("init log");

        let plan = InheritedDescriptorPlan::a3s_box_control(exec.as_fd(), pty.as_fd(), log.as_fd())
            .expect("descriptor plan");
        assert_eq!(
            plan.schema(),
            Some(&AgentInheritedDescriptorSchema::a3s_box_control_v1())
        );
        let protected = plan.protected_sources();
        assert_eq!(protected.len(), 3);
        assert!(protected
            .iter()
            .all(|(_, source, target)| *source >= 10 && *source > *target));
        assert_eq!(
            protected
                .iter()
                .map(|(role, _, target)| (*role, *target))
                .collect::<Vec<_>>(),
            vec![
                (AgentInheritedDescriptorRole::ExecListener, 3),
                (AgentInheritedDescriptorRole::PtyListener, 4),
                (AgentInheritedDescriptorRole::InitLog, 5),
            ]
        );
    }

    #[test]
    fn descriptor_plan_rejects_wrong_types_duplicate_roles_targets_and_bounds() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let exec = UnixListener::bind(temporary.path().join("exec.sock")).expect("exec listener");
        let pty = UnixListener::bind(temporary.path().join("pty.sock")).expect("PTY listener");
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(temporary.path().join("init.log"))
            .expect("init log");
        let schema = AgentInheritedDescriptorSchema::a3s_box_control_v1();

        let wrong_type = [
            DescriptorSource {
                slot: schema.slots[0],
                source: log.as_fd(),
            },
            DescriptorSource {
                slot: schema.slots[1],
                source: pty.as_fd(),
            },
            DescriptorSource {
                slot: schema.slots[2],
                source: exec.as_fd(),
            },
        ];
        let error = InheritedDescriptorPlan::prepare(schema.clone(), &wrong_type)
            .expect_err("wrong source types must fail");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("Unix stream listener"));

        let sources = [
            DescriptorSource {
                slot: schema.slots[0],
                source: exec.as_fd(),
            },
            DescriptorSource {
                slot: schema.slots[1],
                source: pty.as_fd(),
            },
            DescriptorSource {
                slot: schema.slots[2],
                source: log.as_fd(),
            },
        ];
        let mut duplicate_role = schema.clone();
        duplicate_role.slots[1].role = duplicate_role.slots[0].role;
        let duplicate_role_sources = [
            DescriptorSource {
                slot: duplicate_role.slots[0],
                source: exec.as_fd(),
            },
            DescriptorSource {
                slot: duplicate_role.slots[1],
                source: pty.as_fd(),
            },
            DescriptorSource {
                slot: duplicate_role.slots[2],
                source: log.as_fd(),
            },
        ];
        assert!(
            InheritedDescriptorPlan::prepare(duplicate_role, &duplicate_role_sources)
                .expect_err("duplicate roles must fail")
                .message
                .contains("role")
        );

        let mut duplicate_target = schema.clone();
        duplicate_target.slots[1].target = duplicate_target.slots[0].target;
        let duplicate_target_sources = [
            DescriptorSource {
                slot: duplicate_target.slots[0],
                source: exec.as_fd(),
            },
            DescriptorSource {
                slot: duplicate_target.slots[1],
                source: pty.as_fd(),
            },
            DescriptorSource {
                slot: duplicate_target.slots[2],
                source: log.as_fd(),
            },
        ];
        assert!(
            InheritedDescriptorPlan::prepare(duplicate_target, &duplicate_target_sources)
                .expect_err("duplicate targets must fail")
                .message
                .contains("target")
        );

        let mut low_target = schema.clone();
        low_target.slots[0].target = 2;
        let low_target_sources = [
            DescriptorSource {
                slot: low_target.slots[0],
                source: exec.as_fd(),
            },
            sources[1],
            sources[2],
        ];
        assert!(
            InheritedDescriptorPlan::prepare(low_target, &low_target_sources)
                .expect_err("stdio targets must fail")
                .message
                .contains("outside")
        );

        let oversized_schema = AgentInheritedDescriptorSchema {
            profile: "oversized".to_string(),
            slots: (0..=MAX_INHERITED_DESCRIPTORS)
                .map(|index| AgentInheritedDescriptorSlot {
                    role: AgentInheritedDescriptorRole::ExecListener,
                    target: i32::try_from(index + 3).expect("target"),
                    descriptor_type: AgentInheritedDescriptorType::UnixStreamListener,
                })
                .collect(),
        };
        assert!(InheritedDescriptorPlan::prepare(oversized_schema, &sources)
            .expect_err("oversized descriptor plans must fail")
            .message
            .contains("count"));
    }

    #[test]
    fn child_dup2_overwrites_occupied_targets_and_preserves_exact_roles() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let exec = UnixListener::bind(temporary.path().join("exec.sock")).expect("exec listener");
        let pty = UnixListener::bind(temporary.path().join("pty.sock")).expect("PTY listener");
        let log_path = temporary.path().join("init.log");
        let log = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log_path)
            .expect("init log");
        let plan = InheritedDescriptorPlan::a3s_box_control(exec.as_fd(), pty.as_fd(), log.as_fd())
            .expect("descriptor plan");
        let occupied = OpenOptions::new()
            .read(true)
            .open("/dev/null")
            .expect("occupied target source");
        let occupied_fd = occupied.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(
                "test -S /proc/self/fd/3 && test -S /proc/self/fd/4 && \
                 test -f /proc/self/fd/5 && printf 'native-control-dup2-v1\\n' >&5",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the child callback performs only async-signal-safe dup2
        // operations over descriptors captured before fork.
        unsafe {
            command.pre_exec(move || {
                for target in 3..=5 {
                    if libc::dup2(occupied_fd, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                plan.install_in_child()
            });
        }
        let status = command.status().expect("run descriptor child");
        assert!(status.success(), "descriptor child failed with {status}");
        assert_eq!(
            std::fs::read(&log_path).expect("read init log"),
            b"native-control-dup2-v1\n"
        );
    }
}
