use a3s_oci_sdk::{Error, ErrorCode};

#[derive(Debug)]
pub(super) struct OperationJournal<Request, Response> {
    pub(super) entry: Option<(Request, Response)>,
    pub(super) requests: usize,
    pub(super) effects: usize,
}

impl<Request, Response> Default for OperationJournal<Request, Response> {
    fn default() -> Self {
        Self {
            entry: None,
            requests: 0,
            effects: 0,
        }
    }
}

pub(super) fn changed_request(operation: &'static str) -> Error {
    Error::new(
        ErrorCode::Conflict,
        format!("{operation} operation ID was reused with a different guest request"),
    )
    .for_operation(format!("agent-{operation}"))
}

pub(super) fn already_exists(operation: &'static str) -> Error {
    Error::new(
        ErrorCode::AlreadyExists,
        format!("the exact guest container generation already has a {operation} journal"),
    )
    .for_operation(format!("agent-{operation}"))
}
