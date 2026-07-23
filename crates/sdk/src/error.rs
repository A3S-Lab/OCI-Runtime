use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable error classes shared by in-process and transported SDK clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// A request is malformed or contains an invalid value.
    InvalidArgument,
    /// The requested container, process, or operation does not exist.
    NotFound,
    /// The requested identifier already exists.
    AlreadyExists,
    /// The request conflicts with the current lifecycle state or generation.
    FailedPrecondition,
    /// The operation or configuration is not implemented by the selected driver.
    Unsupported,
    /// The caller is not authorized to perform the operation.
    PermissionDenied,
    /// A resource limit prevented the operation.
    ResourceExhausted,
    /// The operation exceeded its deadline.
    DeadlineExceeded,
    /// A concurrent operation changed the target.
    Conflict,
    /// The runtime service is temporarily unavailable.
    Unavailable,
    /// The runtime failed internally.
    Internal,
}

/// Contextual runtime error suitable for crossing a process boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{message}")]
pub struct Error {
    /// Stable machine-readable error class.
    pub code: ErrorCode,
    /// Operation that failed, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// Human-readable diagnostic context.
    pub message: String,
    /// Whether retrying the same operation may succeed without caller changes.
    pub retryable: bool,
}

impl Error {
    /// Construct a non-retryable error.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            operation: None,
            message: message.into(),
            retryable: false,
        }
    }

    /// Attach the operation that failed.
    #[must_use]
    pub fn for_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Mark whether retrying may succeed without changing the request.
    #[must_use]
    pub const fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Construct an unsupported-operation error.
    #[must_use]
    pub fn unsupported(operation: &'static str) -> Self {
        Self::new(
            ErrorCode::Unsupported,
            format!("runtime operation `{operation}` is not supported by the selected driver"),
        )
        .for_operation(operation)
    }
}

/// SDK result type.
pub type Result<T> = std::result::Result<T, Error>;
