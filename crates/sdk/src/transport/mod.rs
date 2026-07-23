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
pub const SDK_PROTOCOL_VERSION_MIN: u16 = 1;
/// Newest SDK wire protocol implemented by this release.
pub const SDK_PROTOCOL_VERSION_MAX: u16 = 1;

pub(super) fn transport_error(operation: &'static str, message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unavailable, message)
        .for_operation(operation)
        .retryable(true)
}

pub(super) fn protocol_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Internal, message).for_operation("sdk-transport")
}

#[cfg(test)]
mod tests;
