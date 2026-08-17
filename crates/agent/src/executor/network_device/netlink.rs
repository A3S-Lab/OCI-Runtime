use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;

use a3s_oci_sdk::{Error, ErrorCode, Result};

use super::{network_error, NetworkDevicePlan};

mod protocol;

use protocol::{
    dump_request, move_request, parse_acknowledgement, parse_address, parse_link,
    parse_netlink_messages,
};

const NETLINK_ROUTE: libc::c_int = 0;
const NETLINK_HEADER_BYTES: usize = 16;
const INTERFACE_INFO_BYTES: usize = 16;
const INTERFACE_ADDRESS_BYTES: usize = 8;
const ROUTE_ATTRIBUTE_BYTES: usize = 4;
#[cfg(test)]
const NETLINK_ERROR_BYTES: usize = NETLINK_HEADER_BYTES + 4;
const NETLINK_RECEIVE_BYTES: usize = 1024 * 1024;
const MAX_NETLINK_DUMP_BYTES: usize = 4 * 1024 * 1024;
const MAX_NETLINK_MESSAGES: usize = 8 * 1024;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_DUMP_INTR: u16 = 0x0010;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_DONE: u16 = 0x0003;

const IFLA_ADDRESS: u16 = 1;
const IFLA_BROADCAST: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_QDISC: u16 = 6;
const IFLA_MASTER: u16 = 10;
const IFLA_TXQLEN: u16 = 13;
const IFLA_LINKMODE: u16 = 17;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_GROUP: u16 = 27;
const IFLA_PROTO_DOWN: u16 = 39;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_MIN_MTU: u16 = 50;
const IFLA_MAX_MTU: u16 = 51;
const IFLA_PERM_ADDRESS: u16 = 54;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
#[cfg(test)]
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_ANYCAST: u16 = 5;
const IFA_FLAGS: u16 = 8;
const IFA_F_OPTIMISTIC: u32 = 0x04;
const IFA_F_DADFAILED: u32 = 0x08;
const IFA_F_DEPRECATED: u32 = 0x20;
const IFA_F_TENTATIVE: u32 = 0x40;
const IFA_F_PERMANENT: u32 = 0x80;
const VOLATILE_ADDRESS_FLAGS: u32 =
    IFA_F_OPTIMISTIC | IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TENTATIVE;
const RT_SCOPE_UNIVERSE: u8 = 0;

const IFF_LOWER_UP: u32 = 1 << 16;
const IFF_DORMANT: u32 = 1 << 17;
const VOLATILE_LINK_FLAGS: u32 = libc::IFF_RUNNING as u32 | IFF_LOWER_UP | IFF_DORMANT;

const STABLE_LINK_ATTRIBUTES: [u16; 13] = [
    IFLA_ADDRESS,
    IFLA_BROADCAST,
    IFLA_MTU,
    IFLA_QDISC,
    IFLA_TXQLEN,
    IFLA_LINKMODE,
    IFLA_GROUP,
    IFLA_PROTO_DOWN,
    IFLA_GSO_MAX_SEGS,
    IFLA_GSO_MAX_SIZE,
    IFLA_MIN_MTU,
    IFLA_MAX_MTU,
    IFLA_PERM_ADDRESS,
];

// IFA_LABEL is name-derived for a primary address and legitimately changes
// when the interface is renamed. IFA_FLAGS also carries transient IPv6 DAD
// state. Address identity remains covered by normalized flags and the
// address/local/broadcast/anycast attributes.
const STABLE_ADDRESS_ATTRIBUTES: [u16; 4] = [IFA_ADDRESS, IFA_LOCAL, IFA_BROADCAST, IFA_ANYCAST];

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NetlinkAddress {
    family: libc::sa_family_t,
    padding: u16,
    port_id: u32,
    groups: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinkSnapshot {
    index: i32,
    name: String,
    link_type: u16,
    flags: u32,
    attributes: BTreeMap<u16, Vec<u8>>,
    addresses: Vec<AddressSnapshot>,
}

impl LinkSnapshot {
    fn is_up(&self) -> bool {
        self.flags & libc::IFF_UP as u32 != 0
    }

    fn master(&self) -> Option<u32> {
        self.attributes
            .get(&IFLA_MASTER)
            .and_then(|value| value.get(..4))
            .map(|value| u32::from_ne_bytes(value.try_into().expect("four-byte slice")))
            .filter(|master| *master != 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AddressSnapshot {
    family: u8,
    prefix_length: u8,
    flags: u32,
    attributes: BTreeMap<u16, Vec<u8>>,
}

#[derive(Debug, Clone)]
struct MovedDevice {
    before: LinkSnapshot,
    requested_name: String,
    template: bool,
}

#[derive(Debug)]
struct RollbackState {
    source_namespace: File,
    target_namespace: File,
    devices: Vec<MovedDevice>,
}

/// A successful network-device move that remains reversible until guest Create
/// commits. Normal container deletion intentionally does not use this lease:
/// network-device lifecycle belongs to the configured network namespace.
#[derive(Debug)]
pub(in crate::executor) struct NetworkDeviceLease {
    rollback: Option<RollbackState>,
}

impl NetworkDeviceLease {
    pub(in crate::executor) async fn apply(
        plan: &NetworkDevicePlan,
        target_namespace: File,
    ) -> Result<Option<Self>> {
        if plan.is_empty() {
            return Ok(None);
        }
        let plan = plan.clone();
        run_disposable_thread("a3s-oci-net-device-apply", move || {
            apply_sync(&plan, target_namespace)
        })
        .await
        .map(Some)
    }

    pub(in crate::executor) async fn rollback(mut self) -> Result<()> {
        let Some(state) = self.rollback.take() else {
            return Ok(());
        };
        run_disposable_thread("a3s-oci-net-device-rollback", move || rollback_sync(&state)).await
    }

    pub(in crate::executor) fn commit(mut self) {
        self.rollback.take();
    }
}

impl Drop for NetworkDeviceLease {
    fn drop(&mut self) {
        let Some(state) = self.rollback.take() else {
            return;
        };
        let result = std::thread::Builder::new()
            .name("a3s-oci-net-device-drop".to_string())
            .spawn(move || rollback_sync(&state))
            .and_then(|thread| {
                thread
                    .join()
                    .map_err(|_| io::Error::other("network-device rollback thread panicked"))?
                    .map_err(|error| io::Error::other(error.to_string()))
            });
        if let Err(error) = result {
            eprintln!("a3s-oci-agent: network-device drop rollback warning: {error}");
        }
    }
}

async fn run_disposable_thread<T, F>(name: &'static str, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _ = sender.send(operation());
        })
        .map_err(|error| {
            network_error(
                ErrorCode::ResourceExhausted,
                format!("failed to spawn bounded network-device worker: {error}"),
            )
        })?;
    receiver.await.map_err(|_| {
        network_error(
            ErrorCode::Internal,
            "network-device worker exited without returning an outcome",
        )
    })?
}

fn apply_sync(plan: &NetworkDevicePlan, target_namespace: File) -> Result<NetworkDeviceLease> {
    validate_network_namespace(&target_namespace, "container target")?;
    let source_namespace = File::open("/proc/self/ns/net").map_err(|error| {
        netlink_error(
            ErrorCode::Internal,
            format!("failed to retain the runtime network namespace: {error}"),
        )
    })?;
    validate_network_namespace(&source_namespace, "runtime source")?;
    if same_file(&source_namespace, &target_namespace)? {
        return Err(netlink_error(
            ErrorCode::PermissionDenied,
            "linux.netDevices target must differ from the runtime network namespace",
        ));
    }

    enter_network_namespace(&source_namespace, "runtime source")?;
    let mut source_socket = RouteSocket::open()?;
    let source_links = source_socket.snapshots()?;
    let mut source_indices = BTreeSet::new();
    let prepared = plan
        .entries()
        .iter()
        .map(|entry| {
            let before = source_links.get(entry.host_name()).cloned().ok_or_else(|| {
                netlink_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "linux.netDevices source `{}` does not exist in the runtime network namespace",
                        entry.host_name()
                    ),
                )
            })?;
            if before.link_type == libc::ARPHRD_LOOPBACK {
                return Err(netlink_error(
                    ErrorCode::Unsupported,
                    format!(
                        "linux.netDevices source `{}` is a non-migratable loopback device",
                        entry.host_name()
                    ),
                ));
            }
            if let Some(master) = before.master() {
                return Err(netlink_error(
                    ErrorCode::Unsupported,
                    format!(
                        "linux.netDevices source `{}` is attached to master interface index {master}",
                        entry.host_name()
                    ),
                ));
            }
            if !source_indices.insert(before.index) {
                return Err(netlink_error(
                    ErrorCode::Conflict,
                    format!(
                        "linux.netDevices resolved more than one source name to interface index {}",
                        before.index
                    ),
                ));
            }
            Ok((entry.clone(), before))
        })
        .collect::<Result<Vec<_>>>()?;

    enter_network_namespace(&target_namespace, "container target")?;
    let mut target_socket = RouteSocket::open()?;
    let target_links = target_socket.snapshots()?;
    for (entry, _) in &prepared {
        if !entry.uses_template() && target_links.contains_key(entry.container_name()) {
            return Err(netlink_error(
                ErrorCode::Conflict,
                format!(
                    "linux.netDevices target `{}` already exists in the container network namespace",
                    entry.container_name()
                ),
            ));
        }
    }
    drop(target_socket);

    enter_network_namespace(&source_namespace, "runtime source")?;
    let mut moved = Vec::with_capacity(prepared.len());
    for (entry, before) in prepared {
        if let Err(error) = source_socket.move_link(
            before.index,
            target_namespace.as_raw_fd(),
            entry.container_name(),
            true,
        ) {
            let state = RollbackState {
                source_namespace,
                target_namespace,
                devices: moved,
            };
            return Err(rollback_after(error, &state));
        }
        moved.push(MovedDevice {
            before,
            requested_name: entry.container_name().to_string(),
            template: entry.uses_template(),
        });
    }
    let state = RollbackState {
        source_namespace,
        target_namespace,
        devices: moved,
    };
    if let Err(error) = verify_applied(&state) {
        return Err(rollback_after(error, &state));
    }
    Ok(NetworkDeviceLease {
        rollback: Some(state),
    })
}

fn verify_applied(state: &RollbackState) -> Result<()> {
    enter_network_namespace(&state.target_namespace, "container target")?;
    let mut socket = RouteSocket::open()?;
    let links = socket.snapshots()?;
    for moved in &state.devices {
        let actual = links
            .values()
            .find(|link| link.index == moved.before.index)
            .ok_or_else(|| {
                netlink_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "moved network interface index {} disappeared from the container namespace",
                        moved.before.index
                    ),
                )
            })?;
        verify_target_name(moved, actual)?;
        verify_snapshot(
            &moved.before,
            actual,
            true,
            "after moving into the container",
        )?;
    }
    Ok(())
}

fn verify_target_name(moved: &MovedDevice, actual: &LinkSnapshot) -> Result<()> {
    let matches = if moved.template {
        let prefix = moved
            .requested_name
            .strip_suffix("%d")
            .expect("validated template suffix");
        actual.name.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    } else {
        actual.name == moved.requested_name
    };
    if matches {
        Ok(())
    } else {
        Err(netlink_error(
            ErrorCode::FailedPrecondition,
            format!(
                "network interface index {} was named `{}` after requesting `{}`",
                moved.before.index, actual.name, moved.requested_name
            ),
        ))
    }
}

fn rollback_after(primary: Error, state: &RollbackState) -> Error {
    match rollback_sync(state) {
        Ok(()) => primary,
        Err(rollback) => {
            let mut combined = primary;
            combined.message = format!(
                "{}; network-device rollback also failed: {}",
                combined.message, rollback.message
            );
            combined
        }
    }
}

fn rollback_sync(state: &RollbackState) -> Result<()> {
    if state.devices.is_empty() {
        return Ok(());
    }
    enter_network_namespace(&state.target_namespace, "container target during rollback")?;
    let mut target_socket = RouteSocket::open()?;
    let target_links = target_socket.snapshots()?;
    let mut first_error = None;
    for moved in state.devices.iter().rev() {
        let Some(actual) = target_links
            .values()
            .find(|link| link.index == moved.before.index)
        else {
            first_error.get_or_insert_with(|| {
                netlink_error(
                    ErrorCode::FailedPrecondition,
                    format!(
                        "cannot roll back missing network interface index {}",
                        moved.before.index
                    ),
                )
            });
            continue;
        };
        if let Err(error) = target_socket.move_link(
            actual.index,
            state.source_namespace.as_raw_fd(),
            &moved.before.name,
            moved.before.is_up(),
        ) {
            first_error.get_or_insert(error);
        }
    }
    drop(target_socket);

    enter_network_namespace(&state.source_namespace, "runtime source during rollback")?;
    let mut source_socket = RouteSocket::open()?;
    let restored = source_socket.snapshots()?;
    for moved in &state.devices {
        match restored.get(&moved.before.name) {
            Some(actual) => {
                if let Err(error) = verify_snapshot(
                    &moved.before,
                    actual,
                    moved.before.is_up(),
                    "after failed-Create rollback",
                ) {
                    first_error.get_or_insert(error);
                }
            }
            None => {
                first_error.get_or_insert_with(|| {
                    netlink_error(
                        ErrorCode::FailedPrecondition,
                        format!(
                            "network interface `{}` was not restored to the runtime namespace",
                            moved.before.name
                        ),
                    )
                });
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn verify_snapshot(
    before: &LinkSnapshot,
    actual: &LinkSnapshot,
    expected_up: bool,
    phase: &str,
) -> Result<()> {
    let stable_mask = !(VOLATILE_LINK_FLAGS | libc::IFF_UP as u32);
    if before.index != actual.index
        || before.link_type != actual.link_type
        || before.flags & stable_mask != actual.flags & stable_mask
        || actual.is_up() != expected_up
        || before.attributes != actual.attributes
        || before.addresses != actual.addresses
    {
        return Err(netlink_error(
            ErrorCode::FailedPrecondition,
            format!(
                "network interface `{}` did not preserve its identity, link attributes, and permanent global addresses {phase}",
                before.name
            ),
        ));
    }
    Ok(())
}

fn validate_network_namespace(namespace: &File, description: &str) -> Result<()> {
    // SAFETY: NS_GET_NSTYPE reads metadata from a live namespace descriptor.
    let namespace_type = unsafe { libc::ioctl(namespace.as_raw_fd(), libc::NS_GET_NSTYPE) };
    if namespace_type == libc::CLONE_NEWNET {
        Ok(())
    } else if namespace_type < 0 {
        Err(io_error(
            &format!("inspect {description} network namespace"),
            io::Error::last_os_error(),
        ))
    } else {
        Err(netlink_error(
            ErrorCode::PermissionDenied,
            format!(
                "{description} namespace has type {namespace_type:#x}, expected Linux network namespace type {:#x}",
                libc::CLONE_NEWNET
            ),
        ))
    }
}

fn same_file(left: &File, right: &File) -> Result<bool> {
    let left = left
        .metadata()
        .map_err(|error| io_error("inspect runtime source network namespace", error))?;
    let right = right
        .metadata()
        .map_err(|error| io_error("inspect container target network namespace", error))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn enter_network_namespace(namespace: &File, description: &str) -> Result<()> {
    // SAFETY: the descriptor was type-checked as a network namespace and this
    // operation runs only in a dedicated disposable OS thread.
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0 {
        Ok(())
    } else {
        Err(io_error(
            &format!("enter {description} network namespace"),
            io::Error::last_os_error(),
        ))
    }
}

struct RouteSocket {
    descriptor: OwnedFd,
    sequence: u32,
}

impl RouteSocket {
    fn open() -> Result<Self> {
        // SAFETY: socket has no pointer arguments. A successful descriptor is
        // transferred immediately to OwnedFd.
        let descriptor = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if descriptor < 0 {
            return Err(io_error(
                "open route netlink socket",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: descriptor is a unique successful socket result.
        let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
        bind_route_socket(&descriptor)?;
        connect_route_socket(&descriptor)?;
        set_receive_timeout(&descriptor)?;
        Ok(Self {
            descriptor,
            sequence: 0,
        })
    }

    fn snapshots(&mut self) -> Result<BTreeMap<String, LinkSnapshot>> {
        let links = self.dump_links()?;
        let addresses = self.dump_addresses()?;
        let mut by_name = BTreeMap::new();
        let mut indices = BTreeSet::new();
        for mut link in links {
            if !indices.insert(link.index) || by_name.contains_key(&link.name) {
                return Err(netlink_error(
                    ErrorCode::Conflict,
                    "route netlink returned duplicate network interface identity",
                ));
            }
            link.addresses = addresses.get(&link.index).cloned().unwrap_or_default();
            by_name.insert(link.name.clone(), link);
        }
        Ok(by_name)
    }

    fn dump_links(&mut self) -> Result<Vec<LinkSnapshot>> {
        let sequence = self.next_sequence()?;
        let request = dump_request(libc::RTM_GETLINK, INTERFACE_INFO_BYTES, sequence)?;
        self.send(&request, "request network-interface inventory")?;
        self.receive_dump(sequence, libc::RTM_NEWLINK)?
            .into_iter()
            .map(|payload| {
                parse_link(&payload)
                    .map_err(|error| io_error("parse network-interface inventory", error))
            })
            .collect()
    }

    fn dump_addresses(&mut self) -> Result<BTreeMap<i32, Vec<AddressSnapshot>>> {
        let sequence = self.next_sequence()?;
        let request = dump_request(libc::RTM_GETADDR, INTERFACE_ADDRESS_BYTES, sequence)?;
        self.send(&request, "request network-address inventory")?;
        let mut addresses: BTreeMap<i32, Vec<AddressSnapshot>> = BTreeMap::new();
        for payload in self.receive_dump(sequence, libc::RTM_NEWADDR)? {
            if let Some((index, address)) = parse_address(&payload)
                .map_err(|error| io_error("parse network-address inventory", error))?
            {
                addresses.entry(index).or_default().push(address);
            }
        }
        for values in addresses.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        Ok(addresses)
    }

    fn move_link(
        &mut self,
        index: i32,
        target_namespace: RawFd,
        target_name: &str,
        up: bool,
    ) -> Result<()> {
        let sequence = self.next_sequence()?;
        let request = move_request(index, target_namespace, target_name, up, sequence)?;
        self.send(&request, "move Linux network interface")?;
        self.receive_acknowledgement(sequence)
    }

    fn next_sequence(&mut self) -> Result<u32> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            netlink_error(
                ErrorCode::ResourceExhausted,
                "route netlink sequence space is exhausted",
            )
        })?;
        Ok(self.sequence)
    }

    fn send(&self, request: &[u8], operation: &str) -> Result<()> {
        // SAFETY: request remains readable for its exact length and send does
        // not retain the buffer.
        let sent = unsafe {
            libc::send(
                self.descriptor.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io_error(operation, io::Error::last_os_error()));
        }
        if usize::try_from(sent).ok() != Some(request.len()) {
            return Err(netlink_error(
                ErrorCode::Internal,
                format!("{operation} sent {sent} of {} bytes", request.len()),
            ));
        }
        Ok(())
    }

    fn receive_acknowledgement(&self, sequence: u32) -> Result<()> {
        loop {
            let response = receive_datagram(&self.descriptor)?;
            for message in parse_netlink_messages(&response)? {
                if message.sequence != sequence {
                    return Err(netlink_error(
                        ErrorCode::PermissionDenied,
                        format!(
                            "route netlink acknowledgement sequence {} does not match {sequence}",
                            message.sequence
                        ),
                    ));
                }
                if message.message_type == NLMSG_ERROR {
                    return parse_acknowledgement(message.payload);
                }
            }
        }
    }

    fn receive_dump(&self, sequence: u32, expected_type: u16) -> Result<Vec<Vec<u8>>> {
        let mut total_bytes = 0_usize;
        let mut messages = Vec::new();
        loop {
            let response = receive_datagram(&self.descriptor)?;
            total_bytes = total_bytes.checked_add(response.len()).ok_or_else(|| {
                netlink_error(
                    ErrorCode::ResourceExhausted,
                    "route netlink dump size overflow",
                )
            })?;
            if total_bytes > MAX_NETLINK_DUMP_BYTES {
                return Err(netlink_error(
                    ErrorCode::ResourceExhausted,
                    format!("route netlink dump exceeds {MAX_NETLINK_DUMP_BYTES} bytes"),
                ));
            }
            for message in parse_netlink_messages(&response)? {
                if message.sequence != sequence {
                    return Err(netlink_error(
                        ErrorCode::PermissionDenied,
                        format!(
                            "route netlink dump sequence {} does not match {sequence}",
                            message.sequence
                        ),
                    ));
                }
                match message.message_type {
                    NLMSG_DONE => {
                        if message.flags & NLM_F_DUMP_INTR != 0 {
                            return Err(netlink_error(
                                ErrorCode::Unavailable,
                                "route netlink dump was interrupted by a concurrent interface change",
                            ));
                        }
                        return Ok(messages);
                    }
                    NLMSG_ERROR => parse_acknowledgement(message.payload)?,
                    message_type if message_type == expected_type => {
                        if messages.len() == MAX_NETLINK_MESSAGES {
                            return Err(netlink_error(
                                ErrorCode::ResourceExhausted,
                                format!(
                                    "route netlink dump exceeds {MAX_NETLINK_MESSAGES} messages"
                                ),
                            ));
                        }
                        messages.push(message.payload.to_vec());
                    }
                    other => {
                        return Err(netlink_error(
                            ErrorCode::FailedPrecondition,
                            format!(
                                "route netlink dump returned message type {other}, expected {expected_type}"
                            ),
                        ));
                    }
                }
            }
        }
    }
}

fn bind_route_socket(socket: &OwnedFd) -> Result<()> {
    let local = NetlinkAddress {
        family: libc::AF_NETLINK as libc::sa_family_t,
        padding: 0,
        port_id: 0,
        groups: 0,
    };
    let length =
        libc::socklen_t::try_from(std::mem::size_of::<NetlinkAddress>()).map_err(|error| {
            netlink_error(
                ErrorCode::Internal,
                format!("route netlink address length does not fit socklen_t: {error}"),
            )
        })?;
    // SAFETY: NetlinkAddress matches sockaddr_nl and remains live for length.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&raw const local).cast::<libc::sockaddr>(),
            length,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io_error(
            "bind route netlink socket",
            io::Error::last_os_error(),
        ))
    }
}

fn connect_route_socket(socket: &OwnedFd) -> Result<()> {
    let kernel = NetlinkAddress {
        family: libc::AF_NETLINK as libc::sa_family_t,
        padding: 0,
        port_id: 0,
        groups: 0,
    };
    let length =
        libc::socklen_t::try_from(std::mem::size_of::<NetlinkAddress>()).map_err(|error| {
            netlink_error(
                ErrorCode::Internal,
                format!("route netlink address length does not fit socklen_t: {error}"),
            )
        })?;
    // SAFETY: NetlinkAddress matches sockaddr_nl and remains live for length.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const kernel).cast::<libc::sockaddr>(),
            length,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io_error(
            "connect route netlink socket",
            io::Error::last_os_error(),
        ))
    }
}

fn set_receive_timeout(socket: &OwnedFd) -> Result<()> {
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    let length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::timeval>()).map_err(|error| {
            netlink_error(
                ErrorCode::Internal,
                format!("route netlink timeout length does not fit socklen_t: {error}"),
            )
        })?;
    // SAFETY: timeout is readable for its exact length and sets one socket option.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast(),
            length,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io_error(
            "set route netlink receive timeout",
            io::Error::last_os_error(),
        ))
    }
}

fn receive_datagram(socket: &OwnedFd) -> Result<Vec<u8>> {
    let mut response = vec![0_u8; NETLINK_RECEIVE_BYTES];
    // SAFETY: response is writable for its complete length. MSG_TRUNC reports
    // the full datagram size, allowing an explicit truncation check.
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            libc::MSG_TRUNC,
        )
    };
    if received < 0 {
        return Err(io_error(
            "receive route netlink response",
            io::Error::last_os_error(),
        ));
    }
    let received = usize::try_from(received).map_err(|error| {
        netlink_error(
            ErrorCode::Internal,
            format!("route netlink returned an invalid response length: {error}"),
        )
    })?;
    if received > response.len() {
        return Err(netlink_error(
            ErrorCode::ResourceExhausted,
            format!(
                "route netlink datagram contains {received} bytes; maximum is {}",
                response.len()
            ),
        ));
    }
    if received == 0 {
        return Err(netlink_error(
            ErrorCode::Unavailable,
            "route netlink socket closed before returning a response",
        ));
    }
    response.truncate(received);
    Ok(response)
}

fn io_error(operation: &str, error: io::Error) -> Error {
    let code = match error.raw_os_error() {
        Some(libc::EACCES | libc::EPERM) => ErrorCode::PermissionDenied,
        Some(libc::EEXIST) => ErrorCode::Conflict,
        Some(libc::ENOENT | libc::ENODEV | libc::ENXIO) => ErrorCode::FailedPrecondition,
        Some(libc::EOPNOTSUPP) => ErrorCode::Unsupported,
        Some(libc::ENOBUFS | libc::ENOMEM) => ErrorCode::ResourceExhausted,
        Some(libc::EAGAIN | libc::EINTR | libc::ETIMEDOUT) => ErrorCode::Unavailable,
        _ if error.kind() == io::ErrorKind::InvalidData => ErrorCode::FailedPrecondition,
        _ => ErrorCode::Internal,
    };
    netlink_error(code, format!("failed to {operation}: {error}"))
}

fn netlink_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("move-linux-network-devices")
}
