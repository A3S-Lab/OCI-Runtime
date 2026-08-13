use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use a3s_oci_sdk::{ErrorCode, Result};

use super::namespace_error;

const NETLINK_SEQUENCE: u32 = 1;
const NETLINK_HEADER_BYTES: usize = 16;
const NETLINK_ERROR_BYTES: usize = NETLINK_HEADER_BYTES + size_of::<i32>();
const NETLINK_ROUTE: libc::c_int = 0;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NetlinkAddress {
    family: libc::sa_family_t,
    padding: u16,
    port_id: u32,
    groups: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NetlinkHeader {
    length: u32,
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct InterfaceInfo {
    family: u8,
    padding: u8,
    link_type: u16,
    index: i32,
    flags: u32,
    change: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct LinkRequest {
    header: NetlinkHeader,
    interface: InterfaceInfo,
}

pub(super) fn bring_loopback_up() -> Result<()> {
    let index = loopback_index()?;
    let socket = route_socket()?;
    connect_to_kernel(&socket)?;
    let request = link_up_request(index)?;
    send_request(&socket, &request)?;
    receive_acknowledgement(&socket, NETLINK_SEQUENCE)
}

fn loopback_index() -> Result<u32> {
    // SAFETY: the C string remains live for the duration of the libc call.
    let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    if index == 0 {
        Err(network_error(
            ErrorCode::FailedPrecondition,
            "resolve the loopback interface",
            io::Error::last_os_error(),
        ))
    } else {
        Ok(index)
    }
}

fn route_socket() -> Result<OwnedFd> {
    // SAFETY: socket has no pointer arguments. Ownership of a successful
    // descriptor is transferred immediately into OwnedFd.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if descriptor < 0 {
        return Err(network_error(
            ErrorCode::Internal,
            "open the route netlink socket",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: descriptor is a unique, successful socket result that has not
    // been transferred or closed.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn connect_to_kernel(socket: &OwnedFd) -> Result<()> {
    let kernel = NetlinkAddress {
        family: libc::AF_NETLINK as libc::sa_family_t,
        padding: 0,
        port_id: 0,
        groups: 0,
    };
    let length = libc::socklen_t::try_from(size_of::<NetlinkAddress>()).map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!("run-container-init could not encode the netlink address length: {error}"),
        )
    })?;
    // SAFETY: NetlinkAddress is the Linux sockaddr_nl UAPI layout and remains
    // live for exactly length bytes. The zero port/groups select the kernel.
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const kernel).cast::<libc::sockaddr>(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(network_error(
            ErrorCode::Internal,
            "connect the route netlink socket to the kernel",
            io::Error::last_os_error(),
        ))
    }
}

fn link_up_request(index: u32) -> Result<LinkRequest> {
    let index = i32::try_from(index).map_err(|error| {
        namespace_error(
            ErrorCode::FailedPrecondition,
            format!("loopback interface index {index} exceeds the Linux link identifier: {error}"),
        )
    })?;
    let length = u32::try_from(size_of::<LinkRequest>()).map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!("run-container-init could not encode the link request length: {error}"),
        )
    })?;
    Ok(LinkRequest {
        header: NetlinkHeader {
            length,
            message_type: RTM_NEWLINK,
            flags: NLM_F_REQUEST | NLM_F_ACK,
            sequence: NETLINK_SEQUENCE,
            port_id: 0,
        },
        interface: InterfaceInfo {
            family: libc::AF_UNSPEC as u8,
            padding: 0,
            link_type: 0,
            index,
            flags: libc::IFF_UP as u32,
            change: libc::IFF_UP as u32,
        },
    })
}

fn send_request(socket: &OwnedFd, request: &LinkRequest) -> Result<()> {
    let length = size_of::<LinkRequest>();
    // SAFETY: request is a repr(C) value live for length bytes, and send reads
    // but does not retain that memory.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            (request as *const LinkRequest).cast(),
            length,
            0,
        )
    };
    if sent < 0 {
        return Err(network_error(
            ErrorCode::Internal,
            "request loopback activation",
            io::Error::last_os_error(),
        ));
    }
    if usize::try_from(sent).ok() != Some(length) {
        return Err(namespace_error(
            ErrorCode::Internal,
            format!("run-container-init sent {sent} of {length} bytes while activating loopback"),
        ));
    }
    Ok(())
}

fn receive_acknowledgement(socket: &OwnedFd, sequence: u32) -> Result<()> {
    let mut response = [0_u8; 4096];
    // SAFETY: response is writable for its complete length, and recv does not
    // retain the pointer after returning.
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            0,
        )
    };
    if received < 0 {
        return Err(network_error(
            ErrorCode::Internal,
            "receive loopback activation acknowledgement",
            io::Error::last_os_error(),
        ));
    }
    let received = usize::try_from(received).map_err(|error| {
        namespace_error(
            ErrorCode::Internal,
            format!("run-container-init received an invalid netlink length: {error}"),
        )
    })?;
    validate_acknowledgement(&response[..received], sequence).map_err(|error| {
        let code = if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
            ErrorCode::PermissionDenied
        } else {
            ErrorCode::FailedPrecondition
        };
        network_error(code, "activate the loopback interface", error)
    })
}

fn validate_acknowledgement(response: &[u8], sequence: u32) -> io::Result<()> {
    if response.len() < NETLINK_ERROR_BYTES {
        return Err(invalid_acknowledgement(format!(
            "netlink acknowledgement contains {} bytes, expected at least {NETLINK_ERROR_BYTES}",
            response.len()
        )));
    }
    let declared = u32::from_ne_bytes(response[0..4].try_into().expect("four-byte slice"));
    let declared = usize::try_from(declared).map_err(|error| {
        invalid_acknowledgement(format!(
            "netlink acknowledgement length is invalid: {error}"
        ))
    })?;
    if !(NETLINK_ERROR_BYTES..=response.len()).contains(&declared) {
        return Err(invalid_acknowledgement(format!(
            "netlink acknowledgement declares {declared} bytes but received {}",
            response.len()
        )));
    }
    let message_type = u16::from_ne_bytes(response[4..6].try_into().expect("two-byte slice"));
    if message_type != NLMSG_ERROR {
        return Err(invalid_acknowledgement(format!(
            "netlink acknowledgement has message type {message_type}, expected {NLMSG_ERROR}"
        )));
    }
    let actual_sequence = u32::from_ne_bytes(response[8..12].try_into().expect("four-byte slice"));
    if actual_sequence != sequence {
        return Err(invalid_acknowledgement(format!(
            "netlink acknowledgement sequence {actual_sequence} does not match {sequence}"
        )));
    }
    let status = i32::from_ne_bytes(
        response[NETLINK_HEADER_BYTES..NETLINK_ERROR_BYTES]
            .try_into()
            .expect("four-byte slice"),
    );
    match status {
        0 => Ok(()),
        value if value < 0 => {
            let errno = value.checked_neg().ok_or_else(|| {
                invalid_acknowledgement("netlink acknowledgement status underflowed".to_string())
            })?;
            Err(io::Error::from_raw_os_error(errno))
        }
        value => Err(invalid_acknowledgement(format!(
            "netlink acknowledgement returned invalid positive status {value}"
        ))),
    }
}

fn invalid_acknowledgement(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn network_error(code: ErrorCode, operation: &str, error: io::Error) -> a3s_oci_sdk::Error {
    namespace_error(
        code,
        format!("failed to {operation} in the new Linux network namespace: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_request_matches_linux_netlink_layout_and_changes_only_up() {
        assert_eq!(size_of::<NetlinkAddress>(), 12);
        assert_eq!(size_of::<NetlinkHeader>(), NETLINK_HEADER_BYTES);
        assert_eq!(size_of::<InterfaceInfo>(), 16);
        let request = link_up_request(7).expect("link request");
        assert_eq!(request.header.length as usize, size_of::<LinkRequest>());
        assert_eq!(request.header.message_type, RTM_NEWLINK);
        assert_eq!(request.header.flags, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(request.interface.index, 7);
        assert_eq!(request.interface.flags, libc::IFF_UP as u32);
        assert_eq!(request.interface.change, libc::IFF_UP as u32);
    }

    #[test]
    fn acknowledgement_is_sequence_fenced_and_preserves_kernel_errno() {
        let mut response = [0_u8; NETLINK_ERROR_BYTES];
        response[0..4].copy_from_slice(&(NETLINK_ERROR_BYTES as u32).to_ne_bytes());
        response[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        response[8..12].copy_from_slice(&NETLINK_SEQUENCE.to_ne_bytes());
        assert!(validate_acknowledgement(&response, NETLINK_SEQUENCE).is_ok());

        assert_eq!(
            validate_acknowledgement(&response, NETLINK_SEQUENCE + 1)
                .expect_err("wrong sequence")
                .kind(),
            io::ErrorKind::InvalidData
        );
        response[NETLINK_HEADER_BYTES..NETLINK_ERROR_BYTES]
            .copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        assert_eq!(
            validate_acknowledgement(&response, NETLINK_SEQUENCE)
                .expect_err("kernel permission failure")
                .raw_os_error(),
            Some(libc::EPERM)
        );
    }
}
