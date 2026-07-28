use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use a3s_oci_sdk::ErrorCode;

use super::pid_supervisor::{
    establish_process_group, signal_process_group, terminate_process_group, wait_for_child,
};

static SIGNAL_DESCRIPTOR: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_MARKER: AtomicU8 = AtomicU8::new(0);

extern "C" fn record_test_signal(_signal: libc::c_int) {
    let descriptor = SIGNAL_DESCRIPTOR.load(Ordering::Relaxed);
    let marker = [SIGNAL_MARKER.load(Ordering::Relaxed)];
    if descriptor >= 0 && marker[0] != 0 {
        // SAFETY: the fork child owns this live pipe descriptor and the
        // handler performs one bounded async-signal-safe write.
        unsafe {
            libc::write(
                descriptor,
                marker.as_ptr().cast::<libc::c_void>(),
                marker.len(),
            );
        }
    }
}

struct ProcessGroupGuard(libc::pid_t);

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        terminate_process_group(self.0);
        let _ = wait_for_child(self.0);
    }
}

#[test]
fn signals_an_owned_process_group_without_missing_its_descendant() {
    let mut descriptors = [-1; 2];
    // SAFETY: `descriptors` has storage for the two descriptors returned by
    // pipe2, and CLOEXEC prevents accidental workload inheritance.
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "create process-group test pipe: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: pipe2 returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: pipe2 returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };

    // SAFETY: the child performs only libc calls and atomics before parking;
    // the parent retains and reaps the exact returned PID.
    let leader = unsafe { libc::fork() };
    assert!(
        leader >= 0,
        "fork process-group leader: {}",
        std::io::Error::last_os_error()
    );
    if leader == 0 {
        drop(reader);
        SIGNAL_DESCRIPTOR.store(writer.as_raw_fd(), Ordering::Relaxed);
        SIGNAL_MARKER.store(b'L', Ordering::Relaxed);
        if establish_process_group().is_err()
            || establish_process_group().is_err()
            || install_test_signal_handler().is_err()
        {
            // SAFETY: the isolated fork child must not unwind into the
            // multithreaded Rust test harness.
            unsafe { libc::_exit(101) }
        }
        // SAFETY: this child remains single-threaded and both branches use
        // only libc calls before parking.
        let descendant = unsafe { libc::fork() };
        if descendant < 0 {
            // SAFETY: see the fork-child invariant above.
            unsafe { libc::_exit(102) }
        }
        if descendant == 0 {
            SIGNAL_MARKER.store(b'D', Ordering::Relaxed);
            write_test_byte(writer.as_raw_fd(), b'R');
            loop {
                // SAFETY: pause blocks until the installed test signal.
                unsafe { libc::pause() };
            }
        }
        write_test_byte(writer.as_raw_fd(), b'R');
        loop {
            // SAFETY: pause blocks until the installed test signal.
            unsafe { libc::pause() };
        }
    }

    drop(writer);
    let _guard = ProcessGroupGuard(leader);
    assert_eq!(
        read_test_bytes(reader.as_raw_fd(), 2),
        vec![b'R', b'R'],
        "leader and descendant must become ready before signaling"
    );
    signal_process_group(leader, libc::SIGUSR1).expect("signal owned process group");
    let mut markers = read_test_bytes(reader.as_raw_fd(), 2);
    markers.sort_unstable();
    assert_eq!(markers, vec![b'D', b'L']);
}

#[test]
fn rejects_invalid_process_group_targets_and_signals() {
    for (leader, signal) in [
        (0, libc::SIGTERM),
        (-1, libc::SIGTERM),
        (1, 0),
        (1, -1),
        (1, libc::SIGRTMAX() + 1),
    ] {
        let error = signal_process_group(leader, signal)
            .expect_err("invalid process-group signal must fail before kill(2)");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }
}

fn install_test_signal_handler() -> std::io::Result<()> {
    // SAFETY: SIGUSR1 is valid and the handler performs only a bounded write
    // to a pipe owned by the fork child.
    let previous = unsafe {
        libc::signal(
            libc::SIGUSR1,
            record_test_signal as *const () as libc::sighandler_t,
        )
    };
    if previous == libc::SIG_ERR {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_test_byte(descriptor: RawFd, byte: u8) {
    // SAFETY: the fork child owns the live pipe descriptor and writes one
    // initialized byte.
    let written =
        unsafe { libc::write(descriptor, (&byte as *const u8).cast::<libc::c_void>(), 1) };
    if written != 1 {
        // SAFETY: the isolated fork child must not unwind into the test harness
        // when readiness cannot be reported.
        unsafe { libc::_exit(103) }
    }
}

fn read_test_bytes(descriptor: RawFd, count: usize) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::with_capacity(count);
    while bytes.len() < count && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = i32::try_from(remaining.as_millis().min(i32::MAX as u128))
            .expect("bounded poll timeout");
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll references one initialized descriptor record.
        let ready = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        if ready <= 0 {
            break;
        }
        let mut byte = 0_u8;
        // SAFETY: byte is writable and the requested length is one.
        let read =
            unsafe { libc::read(descriptor, (&mut byte as *mut u8).cast::<libc::c_void>(), 1) };
        if read == 1 {
            bytes.push(byte);
        } else {
            break;
        }
    }
    bytes
}
