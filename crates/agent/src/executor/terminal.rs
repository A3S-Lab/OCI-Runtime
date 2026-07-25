use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::process::Stdio;
use std::sync::Arc;

use a3s_oci_sdk::{Error, ErrorCode, Result, TerminalSize};
use nix::pty::openpty;
use tokio::io::unix::AsyncFd;
use tokio::process::Command;

/// One PTY allocated before process launch.
///
/// This follows the same mechanism used by A3S Box: one master remains with
/// the runtime and three duplicates of the slave become child stdin, stdout,
/// and stderr. The child creates a session and acquires the slave as its
/// controlling terminal immediately before exec.
#[derive(Debug)]
pub(super) struct TerminalSetup {
    master: OwnedFd,
}

impl TerminalSetup {
    pub(super) fn configure(command: &mut Command, size: TerminalSize) -> Result<Self> {
        validate_size(size)?;
        let pty = openpty(None, None).map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to allocate process terminal: {error}"),
            )
        })?;
        set_close_on_exec(pty.master.as_raw_fd()).map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to protect process terminal master descriptor: {error}"),
            )
        })?;
        set_window_size(pty.master.as_raw_fd(), size).map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to set initial process terminal size: {error}"),
            )
        })?;

        let stdin = pty.slave.try_clone().map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to duplicate terminal stdin descriptor: {error}"),
            )
        })?;
        let stdout = pty.slave.try_clone().map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to duplicate terminal stdout descriptor: {error}"),
            )
        })?;
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(pty.slave));
        Ok(Self { master: pty.master })
    }

    pub(super) fn attach(self) -> Result<TerminalHandle> {
        set_nonblocking(self.master.as_raw_fd()).map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to make process terminal master nonblocking: {error}"),
            )
        })?;
        let descriptor = AsyncFd::new(self.master).map_err(|error| {
            terminal_error(
                ErrorCode::Internal,
                format!("failed to register process terminal with Tokio: {error}"),
            )
        })?;
        Ok(TerminalHandle {
            descriptor: Arc::new(descriptor),
        })
    }
}

/// Cloneable runtime ownership of one terminal master.
#[derive(Debug, Clone)]
pub(super) struct TerminalHandle {
    descriptor: Arc<AsyncFd<OwnedFd>>,
}

impl TerminalHandle {
    pub(super) async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.descriptor.readable().await?;
            match ready
                .try_io(|descriptor| read_descriptor(descriptor.get_ref().as_raw_fd(), bytes))
            {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }

    pub(super) async fn write_all(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut ready = self.descriptor.writable().await?;
            match ready
                .try_io(|descriptor| write_descriptor(descriptor.get_ref().as_raw_fd(), bytes))
            {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "terminal master accepted zero bytes",
                    ));
                }
                Ok(Ok(written)) => bytes = &bytes[written..],
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => {}
            }
        }
        Ok(())
    }

    /// Deliver the terminal's configured EOF character.
    ///
    /// A PTY is one bidirectional file description and cannot be half-closed
    /// like a pipe. Delivering the active VEOF byte preserves terminal input
    /// semantics while the output side remains readable.
    pub(super) async fn close_input(&self) -> io::Result<()> {
        let eof = terminal_eof(self.descriptor.get_ref().as_raw_fd())?;
        self.write_all(&[eof]).await
    }

    pub(super) fn resize(&self, size: TerminalSize) -> Result<()> {
        validate_size(size)?;
        set_window_size(self.descriptor.get_ref().as_raw_fd(), size).map_err(|error| {
            terminal_error(
                terminal_error_code(&error),
                format!("failed to resize process terminal: {error}"),
            )
        })
    }

    #[cfg(test)]
    fn current_size(&self) -> io::Result<TerminalSize> {
        get_window_size(self.descriptor.get_ref().as_raw_fd())
    }
}

/// Establish a fresh controlling-terminal session in a `Command::pre_exec`
/// callback after Rust has installed the configured slave as descriptors 0-2.
pub(super) fn prepare_child_terminal(enabled: bool) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    // SAFETY: this runs in a fresh command child before untrusted code and
    // `setsid` has no pointer arguments.
    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: stdin is the live PTY slave installed by `Command`; the ioctl has
    // no user pointer for TIOCSCTTY.
    if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Move an exec payload's dedicated process group into the foreground of the
/// controlling terminal inherited from its authenticated helper.
pub(super) fn make_foreground_process_group(enabled: bool) -> io::Result<()> {
    if !enabled {
        return Ok(());
    }
    // SAFETY: these signal and process-group calls operate on the current
    // single-threaded helper child. SIGTTOU is ignored only across TIOCSPGRP
    // and restored before the workload is executed.
    let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `getpgrp` has no preconditions.
    let process_group = unsafe { libc::getpgrp() };
    // SAFETY: stdin is the controlling PTY slave and the pointer references a
    // live process-group value for the duration of the ioctl.
    let result = unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSPGRP, &process_group) };
    // SAFETY: restore the exact prior disposition before exec.
    unsafe {
        libc::signal(libc::SIGTTOU, previous);
    }
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_size(size: TerminalSize) -> Result<()> {
    if size.width == 0 || size.height == 0 {
        return Err(terminal_error(
            ErrorCode::InvalidArgument,
            "terminal width and height must both be positive",
        ));
    }
    Ok(())
}

fn set_window_size(descriptor: RawFd, size: TerminalSize) -> io::Result<()> {
    let size = libc::winsize {
        ws_row: size.height,
        ws_col: size.width,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: descriptor is a live PTY master and `size` points to initialized
    // storage for the duration of the ioctl.
    if unsafe { libc::ioctl(descriptor, libc::TIOCSWINSZ, &size) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn get_window_size(descriptor: RawFd) -> io::Result<TerminalSize> {
    // SAFETY: all-zero winsize is valid output storage for TIOCGWINSZ.
    let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
    // SAFETY: descriptor is a live PTY master and `size` is writable.
    if unsafe { libc::ioctl(descriptor, libc::TIOCGWINSZ, &mut size) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(TerminalSize {
            width: size.ws_col,
            height: size.ws_row,
        })
    }
}

fn terminal_eof(descriptor: RawFd) -> io::Result<u8> {
    // SAFETY: all-zero termios is valid output storage for tcgetattr.
    let mut attributes = unsafe { std::mem::zeroed::<libc::termios>() };
    // SAFETY: descriptor is a live PTY master and `attributes` is writable.
    if unsafe { libc::tcgetattr(descriptor, &mut attributes) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(attributes.c_cc[libc::VEOF])
}

fn read_descriptor(descriptor: RawFd, bytes: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `bytes` is writable for its full length and descriptor is owned
    // by the surrounding AsyncFd.
    let read = unsafe { libc::read(descriptor, bytes.as_mut_ptr().cast(), bytes.len()) };
    if read < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(read as usize)
    }
}

fn write_descriptor(descriptor: RawFd, bytes: &[u8]) -> io::Result<usize> {
    // SAFETY: `bytes` is readable for its full length and descriptor is owned
    // by the surrounding AsyncFd.
    let written = unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(written as usize)
    }
}

fn set_close_on_exec(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFD and F_SETFD operate only on this live descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_nonblocking(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL operate only on this live descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn terminal_error_code(error: &io::Error) -> ErrorCode {
    if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) {
        ErrorCode::PermissionDenied
    } else {
        ErrorCode::Internal
    }
}

fn terminal_error(code: ErrorCode, message: impl Into<String>) -> Error {
    Error::new(code, message).for_operation("process-terminal")
}

#[cfg(test)]
mod tests {
    use a3s_oci_sdk::TerminalSize;
    use tokio::process::Command;

    use super::TerminalSetup;

    #[tokio::test]
    async fn terminal_setup_applies_initial_and_resized_dimensions() {
        let mut command = Command::new("/bin/true");
        let setup = TerminalSetup::configure(
            &mut command,
            TerminalSize {
                width: 80,
                height: 24,
            },
        )
        .expect("configure terminal");
        let terminal = setup.attach().expect("attach terminal");
        assert_eq!(
            terminal.current_size().expect("initial terminal size"),
            TerminalSize {
                width: 80,
                height: 24,
            }
        );

        terminal
            .resize(TerminalSize {
                width: 120,
                height: 40,
            })
            .expect("resize terminal");
        assert_eq!(
            terminal.current_size().expect("resized terminal size"),
            TerminalSize {
                width: 120,
                height: 40,
            }
        );
    }
}
