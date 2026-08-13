use std::io::{self, ErrorKind};
use std::mem::{size_of, zeroed};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use super::device::ROOTLESS_DEVICE_MOUNT_COUNT;

const DEVICE_MOUNT_DESCRIPTOR_BYTES: usize = ROOTLESS_DEVICE_MOUNT_COUNT * size_of::<RawFd>();
const DEVICE_MOUNT_CONTROL_BYTES: usize =
    unsafe { libc::CMSG_SPACE(DEVICE_MOUNT_DESCRIPTOR_BYTES as libc::c_uint) as usize };

#[repr(C)]
union DeviceMountControlBuffer {
    alignment: libc::cmsghdr,
    bytes: [u8; DEVICE_MOUNT_CONTROL_BYTES],
}

pub(super) fn send_descriptor_frame(
    socket: RawFd,
    marker: u8,
    descriptors: &[RawFd],
) -> io::Result<()> {
    if descriptors.len() > ROOTLESS_DEVICE_MOUNT_COUNT {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "device mount descriptor count {} exceeds {ROOTLESS_DEVICE_MOUNT_COUNT}",
                descriptors.len()
            ),
        ));
    }
    if descriptors.iter().any(|descriptor| *descriptor < 0) {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "device mount descriptor frame contains an invalid descriptor",
        ));
    }
    let descriptor_bytes = descriptors
        .len()
        .checked_mul(size_of::<RawFd>())
        .ok_or_else(|| io::Error::other("device mount descriptor frame size overflow"))?;
    let control_bytes = if descriptor_bytes == 0 {
        0
    } else {
        unsafe { libc::CMSG_SPACE(descriptor_bytes as libc::c_uint) as usize }
    };

    let mut payload = [marker];
    let mut payload_vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = DeviceMountControlBuffer {
        bytes: [0_u8; DEVICE_MOUNT_CONTROL_BYTES],
    };
    // SAFETY: zero is a valid initialization for msghdr. Every pointer is
    // replaced with live payload or control storage before sendmsg observes it.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut payload_vector;
    message.msg_iovlen = 1;
    if control_bytes != 0 {
        // SAFETY: DeviceMountControlBuffer is aligned for cmsghdr and its byte
        // member spans the complete fixed control buffer.
        message.msg_control = std::ptr::addr_of_mut!(control.bytes).cast();
    }
    message.msg_controllen = control_bytes;

    if descriptor_bytes != 0 {
        // SAFETY: the aligned control buffer contains CMSG_SPACE bytes for
        // every descriptor, so CMSG_FIRSTHDR and CMSG_DATA point into live
        // initialized storage for the duration of sendmsg.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(io::Error::other(
                    "device mount descriptor control buffer has no header",
                ));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes as libc::c_uint) as usize;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                descriptor_bytes,
            );
        }
    }

    loop {
        // SAFETY: message references live payload and control storage and
        // contains one bounded SCM_RIGHTS item.
        let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
        if sent == payload.len() as isize {
            return Ok(());
        }
        if sent < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        return Err(io::Error::new(
            ErrorKind::WriteZero,
            format!(
                "device mount descriptor frame wrote {sent} of {} bytes",
                payload.len()
            ),
        ));
    }
}

pub(super) fn receive_descriptor_frame(
    socket: RawFd,
    expected_marker: u8,
    expected_count: usize,
) -> io::Result<Vec<OwnedFd>> {
    if expected_count > ROOTLESS_DEVICE_MOUNT_COUNT {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "expected device mount descriptor count {expected_count} exceeds {ROOTLESS_DEVICE_MOUNT_COUNT}"
            ),
        ));
    }

    let mut payload = [0_u8; 1];
    let mut payload_vector = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut control = DeviceMountControlBuffer {
        bytes: [0_u8; DEVICE_MOUNT_CONTROL_BYTES],
    };
    // SAFETY: zero is valid for msghdr and every pointer is populated before
    // recvmsg writes through it.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut payload_vector;
    message.msg_iovlen = 1;
    // SAFETY: DeviceMountControlBuffer is aligned for cmsghdr and its byte
    // member spans the complete fixed control buffer.
    message.msg_control = std::ptr::addr_of_mut!(control.bytes).cast();
    message.msg_controllen = DEVICE_MOUNT_CONTROL_BYTES;

    let received = loop {
        // SAFETY: message references writable payload and control storage.
        // Linux applies close-on-exec atomically to every installed descriptor.
        let received = unsafe { libc::recvmsg(socket, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 {
            break received;
        }
        let error = io::Error::last_os_error();
        if error.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    };

    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        discard_received_descriptors(&message);
        return Err(invalid_data("device mount descriptor frame was truncated"));
    }
    if received != payload.len() as isize {
        discard_received_descriptors(&message);
        return Err(invalid_data(format!(
            "device mount descriptor frame contained {received} payload bytes; expected {}",
            payload.len()
        )));
    }
    if payload[0] != expected_marker {
        discard_received_descriptors(&message);
        return Err(invalid_data(
            "device mount descriptor frame marker is invalid",
        ));
    }
    let descriptors = collect_received_descriptors(&message)?;
    if descriptors.len() != expected_count {
        let actual_count = descriptors.len();
        return Err(invalid_data(format!(
            "device mount descriptor frame contained {} descriptors; expected {expected_count}",
            actual_count
        )));
    }
    Ok(descriptors)
}

fn collect_received_descriptors(message: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let mut descriptors = Vec::<RawFd>::new();
    let mut header_count = 0_usize;
    // SAFETY: recvmsg initialized the bounded control buffer described by
    // message. libc's traversal helpers keep each header within that buffer.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        header_count += 1;
        // SAFETY: header lies within the recvmsg-populated control buffer.
        let (level, kind, length) = unsafe {
            (
                (*header).cmsg_level,
                (*header).cmsg_type,
                (*header).cmsg_len,
            )
        };
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        if length < minimum {
            discard_received_descriptors(message);
            return Err(invalid_data(
                "device mount ancillary header is shorter than cmsghdr",
            ));
        }
        let data_bytes = length - minimum;
        if level != libc::SOL_SOCKET
            || kind != libc::SCM_RIGHTS
            || data_bytes == 0
            || data_bytes % size_of::<RawFd>() != 0
        {
            discard_received_descriptors(message);
            return Err(invalid_data(
                "device mount ancillary data is not a non-empty SCM_RIGHTS array",
            ));
        }
        let count = data_bytes / size_of::<RawFd>();
        if descriptors.len().saturating_add(count) > ROOTLESS_DEVICE_MOUNT_COUNT {
            discard_received_descriptors(message);
            return Err(invalid_data(
                "device mount ancillary data exceeds the descriptor bound",
            ));
        }
        for index in 0..count {
            // SAFETY: cmsg_len proves this RawFd lies within the SCM_RIGHTS
            // payload. read_unaligned handles the payload's byte alignment.
            let descriptor = unsafe {
                libc::CMSG_DATA(header)
                    .cast::<RawFd>()
                    .add(index)
                    .read_unaligned()
            };
            if descriptor < 0 {
                discard_received_descriptors(message);
                return Err(invalid_data(
                    "device mount ancillary data contained an invalid descriptor",
                ));
            }
            descriptors.push(descriptor);
        }
        // SAFETY: libc checks that the next aligned header remains within the
        // exact msg_controllen populated by recvmsg.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    if header_count > 1 {
        discard_received_descriptors(message);
        return Err(invalid_data(format!(
            "device mount descriptor frame contained {header_count} ancillary headers; maximum is 1"
        )));
    }
    for descriptor in &descriptors {
        let flags = unsafe { libc::fcntl(*descriptor, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            for descriptor in descriptors {
                // SAFETY: recvmsg installed each parsed descriptor, and this
                // validation failure discards every one exactly once.
                unsafe { libc::close(descriptor) };
            }
            return Err(invalid_data(
                "device mount descriptor was not received close-on-exec",
            ));
        }
    }
    Ok(descriptors
        .into_iter()
        .map(|descriptor| {
            // SAFETY: recvmsg installed a fresh descriptor for this SCM_RIGHTS
            // slot, and ownership is transferred exactly once after validation.
            unsafe { OwnedFd::from_raw_fd(descriptor) }
        })
        .collect())
}

fn discard_received_descriptors(message: &libc::msghdr) {
    // A truncated control buffer can still contain a complete leading
    // SCM_RIGHTS header. Close every descriptor that can be parsed safely;
    // descriptors omitted by the kernel are closed by the kernel.
    // SAFETY: recvmsg initialized the bounded control buffer.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        // SAFETY: header is bounded by msg_controllen as populated by recvmsg.
        let (level, kind, length) = unsafe {
            (
                (*header).cmsg_level,
                (*header).cmsg_type,
                (*header).cmsg_len,
            )
        };
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS && length >= minimum {
            let count = (length - minimum) / size_of::<RawFd>();
            for index in 0..count.min(ROOTLESS_DEVICE_MOUNT_COUNT) {
                // SAFETY: the complete prefix described by cmsg_len is within
                // the recvmsg-populated ancillary buffer.
                let descriptor = unsafe {
                    libc::CMSG_DATA(header)
                        .cast::<RawFd>()
                        .add(index)
                        .read_unaligned()
                };
                if descriptor >= 0 {
                    // SAFETY: this descriptor was installed by recvmsg and is
                    // deliberately discarded exactly once.
                    unsafe { libc::close(descriptor) };
                }
            }
        }
        // SAFETY: libc bounds the next header by msg_controllen.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    use super::{receive_descriptor_frame, send_descriptor_frame};

    const MARKER: u8 = 0xD1;

    #[test]
    fn descriptor_frames_round_trip_six_close_on_exec_descriptors() {
        let (sender, receiver) = UnixStream::pair().expect("descriptor channel");
        let files = open_devices();
        let descriptors = raw_descriptors(&files);

        send_descriptor_frame(sender.as_raw_fd(), MARKER, &descriptors).expect("send frame");
        let received = receive_descriptor_frame(receiver.as_raw_fd(), MARKER, descriptors.len())
            .expect("receive frame");

        assert_eq!(received.len(), descriptors.len());
        for descriptor in received {
            // SAFETY: the received descriptor is live and F_GETFD only reads
            // descriptor flags.
            let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn empty_descriptor_frame_completes_the_no_device_handshake() {
        let (sender, receiver) = UnixStream::pair().expect("descriptor channel");

        send_descriptor_frame(sender.as_raw_fd(), MARKER, &[]).expect("send empty frame");
        let received =
            receive_descriptor_frame(receiver.as_raw_fd(), MARKER, 0).expect("receive empty frame");

        assert!(received.is_empty());
    }

    #[test]
    fn descriptor_frame_rejects_wrong_marker_and_count() {
        let files = open_devices();
        let descriptors = raw_descriptors(&files);

        let (sender, receiver) = UnixStream::pair().expect("marker channel");
        send_descriptor_frame(sender.as_raw_fd(), MARKER ^ 0xff, &descriptors)
            .expect("send wrong marker");
        let marker_error =
            receive_descriptor_frame(receiver.as_raw_fd(), MARKER, descriptors.len())
                .expect_err("wrong marker must fail");
        assert_eq!(marker_error.kind(), std::io::ErrorKind::InvalidData);
        assert!(marker_error.to_string().contains("marker"));

        let (sender, receiver) = UnixStream::pair().expect("count channel");
        send_descriptor_frame(sender.as_raw_fd(), MARKER, &descriptors).expect("send frame");
        let count_error = receive_descriptor_frame(receiver.as_raw_fd(), MARKER, 1)
            .expect_err("wrong count must fail");
        assert_eq!(count_error.kind(), std::io::ErrorKind::InvalidData);
        assert!(count_error.to_string().contains("descriptors"));
    }

    #[test]
    fn descriptor_frame_rejects_missing_ancillary_data() {
        let (mut sender, receiver) = UnixStream::pair().expect("descriptor channel");
        sender.write_all(&[MARKER]).expect("send bare marker");

        let error = receive_descriptor_frame(receiver.as_raw_fd(), MARKER, 1)
            .expect_err("missing descriptors must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("contained 0 descriptors"));
    }

    #[test]
    fn descriptor_frame_rejects_truncated_ancillary_data() {
        let (sender, receiver) = UnixStream::pair().expect("descriptor channel");
        let files = open_devices();
        let descriptors = raw_descriptors(&files);
        send_raw_descriptor_frame(sender.as_raw_fd(), MARKER, &descriptors, 32)
            .expect("send oversized frame");

        let error = receive_descriptor_frame(receiver.as_raw_fd(), MARKER, descriptors.len())
            .expect_err("truncated ancillary data must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("truncated"));
    }

    fn open_devices() -> Vec<std::fs::File> {
        ["/dev/null"; 6]
            .into_iter()
            .map(|path| std::fs::File::open(path).expect("open descriptor fixture"))
            .collect()
    }

    fn raw_descriptors(files: &[std::fs::File]) -> Vec<RawFd> {
        files.iter().map(AsRawFd::as_raw_fd).collect()
    }

    fn send_raw_descriptor_frame(
        socket: RawFd,
        marker: u8,
        descriptors: &[RawFd],
        repeated: usize,
    ) -> std::io::Result<()> {
        let expanded = descriptors
            .iter()
            .copied()
            .cycle()
            .take(repeated)
            .collect::<Vec<_>>();
        let descriptor_bytes = expanded.len() * std::mem::size_of::<RawFd>();
        let control_bytes = unsafe { libc::CMSG_SPACE(descriptor_bytes as libc::c_uint) as usize };
        let mut payload = [marker];
        let mut payload_vector = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        let mut control = vec![0_u8; control_bytes + std::mem::align_of::<libc::cmsghdr>()];
        let offset = control
            .as_ptr()
            .align_offset(std::mem::align_of::<libc::cmsghdr>());
        let aligned = unsafe { control.as_mut_ptr().add(offset) };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut payload_vector;
        message.msg_iovlen = 1;
        message.msg_control = aligned.cast();
        message.msg_controllen = control_bytes;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(descriptor_bytes as libc::c_uint) as usize;
            std::ptr::copy_nonoverlapping(
                expanded.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                descriptor_bytes,
            );
        }
        let sent = unsafe { libc::sendmsg(socket, &message, libc::MSG_NOSIGNAL) };
        if sent == 1 {
            Ok(())
        } else if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Err(std::io::Error::other("short raw descriptor frame"))
        }
    }
}
