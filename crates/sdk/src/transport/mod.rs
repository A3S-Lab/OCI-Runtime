//! Versioned, length-delimited SDK transport shared by local IPC connectors.

mod client;
mod local;
mod server;
mod wire;

use crate::{Error, ErrorCode};

pub use client::RuntimeTransportClient;
pub use local::LocalIpcEndpoint;
pub use server::serve_transport_connection;

/// Oldest SDK wire protocol implemented by this release.
pub const SDK_PROTOCOL_VERSION_MIN: u16 = 3;
/// Newest SDK wire protocol implemented by this release.
pub const SDK_PROTOCOL_VERSION_MAX: u16 = 9;

pub(super) fn transport_error(operation: &'static str, message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unavailable, message)
        .for_operation(operation)
        .retryable(true)
}

/// Map a local-IPC connect failure.
///
/// Mode-0600 host/runtime sockets reject wrong identities with EACCES/EPERM.
/// That is permanent for this caller ([`ErrorCode::PermissionDenied`]); Box
/// retries [`ErrorCode::Unavailable`] by code, so misclassifying access denial
/// as transport `Unavailable` burns watchdog attempts. Missing/refused
/// endpoints stay retryable `Unavailable`.
pub(super) fn connect_io_error(
    operation: &'static str,
    message: impl Into<String>,
    error: &std::io::Error,
) -> Error {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        return Error::new(ErrorCode::PermissionDenied, message)
            .for_operation(operation)
            .retryable(false);
    }
    transport_error(operation, message)
}

pub(super) fn protocol_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, message).for_operation("sdk-transport")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod connect_honesty_tests {
    use std::io;

    use crate::ErrorCode;

    use super::connect_io_error;

    #[test]
    fn permission_denied_connect_is_not_unavailable() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "EACCES");
        let mapped = connect_io_error(
            "sdk-connect",
            format!("failed to connect SDK Unix socket /tmp/runtime.sock: {error}"),
            &error,
        );
        assert_eq!(mapped.code, ErrorCode::PermissionDenied);
        assert!(!mapped.retryable);
        assert_eq!(mapped.operation.as_deref(), Some("sdk-connect"));
    }

    #[test]
    fn missing_or_refused_connect_stays_retryable_unavailable() {
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::ConnectionRefused] {
            let error = io::Error::new(kind, "transient");
            let mapped = connect_io_error(
                "sdk-connect",
                format!("failed to connect SDK Unix socket /tmp/runtime.sock: {error}"),
                &error,
            );
            assert_eq!(mapped.code, ErrorCode::Unavailable);
            assert!(mapped.retryable);
        }
    }
}
