use std::io;

/// First descriptor that is private to the executor rather than standard I/O.
pub(super) const FIRST_PRIVATE_DESCRIPTOR: u32 = 3;

/// Mark every executor-private descriptor close-on-exec in the forked child.
///
/// Descriptor flags are changed only in the child-side table, so concurrent
/// operations in the long-lived Agent cannot race with this boundary. Callers
/// must clear the bit again (or install a descriptor with `dup2`) for each
/// explicitly authenticated descriptor that is part of the child contract.
pub(super) fn mark_private_descriptors_close_on_exec() -> io::Result<()> {
    // SAFETY: `close_range` receives a bounded descriptor interval and the
    // kernel-defined close-on-exec flag; it does not dereference pointers.
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_PRIVATE_DESCRIPTOR,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    use super::mark_private_descriptors_close_on_exec;

    #[test]
    fn non_cloexec_private_descriptors_do_not_cross_the_exec_boundary() {
        let probe = File::open("/dev/null").expect("open descriptor inheritance probe");
        let descriptor = probe.as_raw_fd();
        assert!(descriptor >= 3, "probe must be a private descriptor");

        // Rust opens files close-on-exec. Deliberately clear the bit to model
        // a descriptor supplied by a PTY broker or an older caller.
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(flags >= 0, "read descriptor flags");
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0,
            "clear descriptor close-on-exec"
        );

        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!("test ! -e /proc/self/fd/{descriptor}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the callback performs one async-signal-safe Linux syscall in
        // the freshly forked child before `/bin/sh` is executed.
        unsafe {
            command.pre_exec(mark_private_descriptors_close_on_exec);
        }
        let status = command.status().expect("run descriptor boundary probe");
        assert!(
            status.success(),
            "private descriptor crossed exec boundary: {status}"
        );
    }
}
