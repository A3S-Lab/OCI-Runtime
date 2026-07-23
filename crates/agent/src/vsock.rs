use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use a3s_oci_agent_protocol::AGENT_VSOCK_PORT;
use a3s_oci_sdk::{Error, ErrorCode, Result};

const CONNECT_ATTEMPTS: usize = 100;
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(50);
const CONNECT_TIMEOUT_MILLIS: i32 = 100;

pub(super) fn connect_host_with_retry() -> Result<UnixStream> {
    let mut last_error = None;
    for attempt in 0..CONNECT_ATTEMPTS {
        match connect_host() {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < CONNECT_ATTEMPTS {
            thread::sleep(CONNECT_RETRY_DELAY);
        }
    }
    let error = last_error.unwrap_or_else(|| io::Error::other("no connection attempt ran"));
    Err(Error::new(
        ErrorCode::Unavailable,
        format!(
            "failed to connect guest AF_VSOCK CID {} port {} after {CONNECT_ATTEMPTS} attempts: \
             {error}",
            libc::VMADDR_CID_HOST,
            AGENT_VSOCK_PORT
        ),
    )
    .for_operation("connect-guest-agent")
    .retryable(true))
}

fn connect_host() -> io::Result<UnixStream> {
    // SAFETY: `socket` has no pointer arguments. The returned descriptor is
    // either negative or uniquely owned by the guard constructed below.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_fd` was just returned as a new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let address = host_address()?;
    let address_length = libc::socklen_t::try_from(size_of::<libc::sockaddr_vm>())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    // SAFETY: `address` has the AF_VSOCK layout and remains live for the call.
    let status = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_vm).cast(),
            address_length,
        )
    };
    if status != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        wait_for_connection(&fd)?;
    }

    let stream = UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    Ok(stream)
}

fn wait_for_connection(fd: &OwnedFd) -> io::Result<()> {
    let mut poll_fd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        // SAFETY: `poll_fd` is a valid single-entry array for this call.
        let status = unsafe { libc::poll(&mut poll_fd, 1, CONNECT_TIMEOUT_MILLIS) };
        if status > 0 {
            break;
        }
        if status == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "guest AF_VSOCK connect timed out",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }

    let mut socket_error = 0;
    let mut error_length = libc::socklen_t::try_from(size_of::<libc::c_int>())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: both output pointers are valid and `fd` remains live.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut socket_error as *mut libc::c_int).cast(),
            &mut error_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if socket_error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(socket_error))
    }
}

fn host_address() -> io::Result<libc::sockaddr_vm> {
    // SAFETY: zero is a valid initialization for the reserved sockaddr bytes.
    let mut address: libc::sockaddr_vm = unsafe { zeroed() };
    address.svm_family = libc::sa_family_t::try_from(libc::AF_VSOCK)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    address.svm_port = AGENT_VSOCK_PORT;
    address.svm_cid = libc::VMADDR_CID_HOST;
    Ok(address)
}

#[cfg(test)]
mod tests {
    use a3s_oci_agent_protocol::AGENT_VSOCK_PORT;

    use super::host_address;

    #[test]
    fn targets_the_host_control_port() {
        let address = host_address().expect("AF_VSOCK address must be representable");
        assert_eq!(i32::from(address.svm_family), libc::AF_VSOCK);
        assert_eq!(address.svm_cid, libc::VMADDR_CID_HOST);
        assert_eq!(address.svm_port, AGENT_VSOCK_PORT);
    }
}
