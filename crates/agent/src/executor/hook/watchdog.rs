use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

const FIRST_PRIVATE_DESCRIPTOR: u32 = 3;
const WATCHDOG_READY: u8 = 1;

/// Install the pre-exec descriptor boundary and a detached owner-death
/// watchdog for one Hook process group.
pub(super) fn configure(command: &mut Command) -> io::Result<()> {
    let owner_pid = unsafe { libc::getpid() };
    let owner_pidfd = open_pidfd(owner_pid)?;
    // SAFETY: the closure runs after fork and before exec. Every operation in
    // `configure_child` is a direct Linux/libc syscall over stack-owned data.
    // The captured pidfd is close-on-exec in both the parent and Hook child.
    unsafe {
        command.pre_exec(move || configure_child(owner_pid, owner_pidfd.as_raw_fd()));
    }
    Ok(())
}

fn configure_child(owner_pid: libc::pid_t, owner_pidfd: RawFd) -> io::Result<()> {
    mark_private_descriptors_close_on_exec()?;
    if unsafe { libc::getppid() } != owner_pid {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }

    let hook_pid = unsafe { libc::getpid() };
    if unsafe { libc::getpgrp() } != hook_pid {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let hook_pidfd = open_pidfd(hook_pid)?;
    let (ready_reader, ready_writer) = pipe_close_on_exec()?;
    let intermediate = unsafe { libc::fork() };
    if intermediate < 0 {
        return Err(io::Error::last_os_error());
    }
    if intermediate == 0 {
        // SAFETY: this branch never returns into Rust. It performs a second
        // fork so the watchdog cannot become a child visible to Hook code.
        unsafe {
            watchdog_intermediate(
                owner_pidfd,
                hook_pidfd.as_raw_fd(),
                hook_pid,
                ready_reader.as_raw_fd(),
                ready_writer.as_raw_fd(),
            )
        }
    }

    drop(ready_writer);
    wait_for_intermediate(intermediate)?;
    let ready = read_byte(ready_reader.as_raw_fd())?;
    drop(ready_reader);
    drop(hook_pidfd);
    if ready != WATCHDOG_READY || unsafe { libc::getppid() } != owner_pid {
        return Err(io::Error::from_raw_os_error(libc::ECHILD));
    }
    Ok(())
}

fn mark_private_descriptors_close_on_exec() -> io::Result<()> {
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

fn open_pidfd(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor =
        RawFd::try_from(descriptor).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    // SAFETY: pidfd_open returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn pipe_close_on_exec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn wait_for_intermediate(pid: libc::pid_t) -> io::Result<()> {
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::ECHILD))
            };
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::last_os_error());
    }
}

fn read_byte(descriptor: RawFd) -> io::Result<u8> {
    let mut value = 0_u8;
    loop {
        let result = unsafe { libc::read(descriptor, (&mut value as *mut u8).cast(), 1) };
        if result == 1 {
            return Ok(value);
        }
        if result == 0 {
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

unsafe fn watchdog_intermediate(
    owner_pidfd: RawFd,
    hook_pidfd: RawFd,
    hook_pid: libc::pid_t,
    ready_reader: RawFd,
    ready_writer: RawFd,
) -> ! {
    unsafe {
        libc::close(ready_reader);
    }
    let watchdog = unsafe { libc::fork() };
    if watchdog < 0 {
        let _ = write_byte(ready_writer, 0);
        unsafe { libc::_exit(1) }
    }
    if watchdog > 0 {
        unsafe { libc::_exit(0) }
    }
    unsafe { watchdog_main(owner_pidfd, hook_pidfd, hook_pid, ready_writer) }
}

unsafe fn watchdog_main(
    owner_pidfd: RawFd,
    hook_pidfd: RawFd,
    hook_pid: libc::pid_t,
    ready_writer: RawFd,
) -> ! {
    let ready = close_except([owner_pidfd, hook_pidfd, ready_writer])
        && unsafe { libc::getpgrp() } == hook_pid
        && write_byte(ready_writer, WATCHDOG_READY);
    unsafe {
        libc::close(ready_writer);
        libc::close(libc::STDIN_FILENO);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
    if !ready {
        unsafe { libc::_exit(1) }
    }

    let mut descriptors = [
        libc::pollfd {
            fd: owner_pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: hook_pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, -1) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            kill_hook_group(hook_pid);
        }
        if descriptors[0].revents != 0 {
            kill_hook_group(hook_pid);
        }
        if descriptors[1].revents != 0 {
            unsafe { libc::_exit(0) }
        }
    }
}

fn write_byte(descriptor: RawFd, value: u8) -> bool {
    loop {
        let result = unsafe { libc::write(descriptor, (&value as *const u8).cast(), 1) };
        if result == 1 {
            return true;
        }
        if result >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return false;
        }
    }
}

fn close_except(mut descriptors: [RawFd; 3]) -> bool {
    if descriptors.iter().any(|descriptor| *descriptor < 3) {
        return false;
    }
    if descriptors[0] > descriptors[1] {
        descriptors.swap(0, 1);
    }
    if descriptors[1] > descriptors[2] {
        descriptors.swap(1, 2);
    }
    if descriptors[0] > descriptors[1] {
        descriptors.swap(0, 1);
    }
    if descriptors[0] == descriptors[1] || descriptors[1] == descriptors[2] {
        return false;
    }

    let mut first = FIRST_PRIVATE_DESCRIPTOR;
    for descriptor in descriptors {
        let descriptor = descriptor as u32;
        if first < descriptor && !close_range(first, descriptor - 1) {
            return false;
        }
        first = descriptor.saturating_add(1);
    }
    first == u32::MAX || close_range(first, u32::MAX)
}

fn close_range(first: u32, last: u32) -> bool {
    unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) == 0 }
}

fn kill_hook_group(hook_pid: libc::pid_t) -> ! {
    unsafe {
        libc::kill(-hook_pid, libc::SIGKILL);
        libc::kill(hook_pid, libc::SIGKILL);
        libc::_exit(1)
    }
}
