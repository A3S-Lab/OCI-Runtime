use super::*;
use std::fs::OpenOptions;
use std::path::Path;

pub(super) fn open_fifo(
    path: &str,
    read: bool,
    write: bool,
) -> Result<AsyncFd<File>, RuntimeError> {
    let path = Path::new(path);
    let file = OpenOptions::new()
        .read(read)
        .write(write)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| io_error(format!("open containerd FIFO {}", path.display()), error))?;
    AsyncFd::new(file).map_err(|error| {
        io_error(
            format!("register containerd FIFO {}", path.display()),
            error,
        )
    })
}

pub(super) fn open_output_fifo(path: &str) -> Result<AsyncFd<File>, RuntimeError> {
    // Keep one local read end so a restarted shim can reopen the writer before
    // containerd reconnects its reader. The shim never consumes this handle;
    // bytes remain available for containerd's external read end.
    open_fifo(path, true, true)
}

pub(super) fn io_error(context: impl AsRef<str>, error: io::Error) -> RuntimeError {
    RuntimeError::new(
        if matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
        ) {
            ErrorCode::InvalidArgument
        } else {
            ErrorCode::Unavailable
        },
        format!("{}: {error}", context.as_ref()),
    )
    .for_operation("containerd-stdio")
}

trait OpenOptionsExt {
    fn custom_flags(&mut self, flags: i32) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    fn custom_flags(&mut self, flags: i32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::custom_flags(self, flags)
    }
}
