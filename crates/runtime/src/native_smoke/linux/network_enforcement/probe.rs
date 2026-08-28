use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

const REDIRECT_BODY: &str = "a3s-oar01-redirect-v1";
const BLOCK_CONTROL_BODY: &str = "a3s-oar01-block-control-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NamespaceIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn probe_mechanism(
    namespace_path: &Path,
    redirect_port: u16,
    rejected_port: u16,
) -> Result<(), String> {
    let namespace_path = namespace_path.to_path_buf();
    std::thread::Builder::new()
        .name("a3s-oci-oar01-probe".into())
        .spawn(move || {
            enter_network_namespace(&namespace_path)?;
            require_http_body(
                Ipv4Addr::LOCALHOST,
                redirect_port,
                REDIRECT_BODY,
                "redirected endpoint",
            )?;
            require_http_body(
                Ipv4Addr::new(127, 0, 0, 2),
                rejected_port,
                BLOCK_CONTROL_BODY,
                "rejection control endpoint",
            )?;
            let blocked = SocketAddrV4::new(Ipv4Addr::LOCALHOST, rejected_port);
            if TcpStream::connect_timeout(&blocked.into(), Duration::from_secs(2)).is_ok() {
                return Err(
                    "caller-owned rejection mechanism accepted the blocked endpoint".into(),
                );
            }
            Ok(())
        })
        .map_err(|error| format!("failed to start network-enforcement probe: {error}"))?
        .join()
        .map_err(|_| "network-enforcement probe panicked".to_string())?
}

pub(super) fn interface_exists(namespace_path: &Path, interface: &str) -> Result<bool, String> {
    let namespace_path = namespace_path.to_path_buf();
    let interface = interface.to_string();
    std::thread::Builder::new()
        .name("a3s-oci-oar01-interface".into())
        .spawn(move || {
            enter_network_namespace(&namespace_path)?;
            let interface = CString::new(interface)
                .map_err(|_| "target network interface contains a NUL byte".to_string())?;
            // SAFETY: the name is a bounded C string and this dedicated thread
            // exits immediately after the namespace-local lookup.
            Ok(unsafe { libc::if_nametoindex(interface.as_ptr()) } != 0)
        })
        .map_err(|error| format!("failed to start network-interface probe: {error}"))?
        .join()
        .map_err(|_| "network-interface probe panicked".to_string())?
}

pub(super) async fn namespace_identity(path: &Path) -> Result<NamespaceIdentity, String> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        format!(
            "failed to inspect caller-owned network namespace {}: {error}",
            path.display()
        )
    })?;
    Ok(NamespaceIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
    })
}

pub(super) async fn same_namespace(first: &Path, second: &Path) -> Result<bool, String> {
    Ok(namespace_identity(first).await? == namespace_identity(second).await?)
}

fn require_http_body(
    address: Ipv4Addr,
    port: u16,
    expected: &str,
    description: &str,
) -> Result<(), String> {
    let address = SocketAddrV4::new(address, port);
    let mut stream = TcpStream::connect_timeout(&address.into(), Duration::from_secs(2))
        .map_err(|error| format!("failed to connect to {description}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to bound {description} read: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("failed to bound {description} write: {error}"))?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .map_err(|error| format!("failed to request {description}: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("failed to read {description}: {error}"))?;
    let response = String::from_utf8(response)
        .map_err(|error| format!("{description} returned non-UTF-8 bytes: {error}"))?;
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    if body.trim_end() == expected {
        Ok(())
    } else {
        Err(format!("{description} returned unexpected body {body:?}"))
    }
}

fn enter_network_namespace(namespace_path: &Path) -> Result<(), String> {
    let namespace = std::fs::File::open(namespace_path).map_err(|error| {
        format!(
            "failed to open caller-owned network namespace {}: {error}",
            namespace_path.display()
        )
    })?;
    // SAFETY: the descriptor pins the exact caller-owned network namespace and
    // each caller runs inside a dedicated thread that exits after inspection.
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(format!(
            "failed to enter caller-owned network namespace {}: {}",
            namespace_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
