use std::path::Path;

use crate::{
    CheckpointRequest, CloseStdinRequest, ContainerOperationRequest, CreateRequest, DeleteRequest,
    Error, ErrorCode, EventsRequest, ExecRequest, IoMode, KillRequest, ListRequest, ProcessIo,
    ProcessesRequest, ReadOutputRequest, ResizeRequest, RestoreRequest, Result, RunRequest,
    SignalProcessRequest, StartRequest, StateRequest, StatsRequest, UpdateRequest,
    WaitProcessRequest, WaitRequest, WriteStdinRequest,
};
use crate::{OciSemanticPhase, OciSemanticValidator};

/// Maximum number of events returned by one SDK poll.
pub const MAX_EVENT_BATCH_ITEMS: u32 = 4_096;
/// Maximum captured output requested by one SDK poll.
pub const MAX_OUTPUT_READ_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum stdin payload carried by one SDK request.
pub const MAX_STDIN_WRITE_BYTES: usize = 16 * 1024 * 1024;

/// Fail-closed validation performed before a request reaches runtime state.
pub trait ValidateRequest {
    fn validate(&self) -> Result<()>;
}

impl ValidateRequest for CreateRequest {
    fn validate(&self) -> Result<()> {
        self.bundle.validate_for_phase(OciSemanticPhase::Create)?;
        validate_process_io(&self.io, initial_process_uses_terminal(self))
    }
}

impl ValidateRequest for RunRequest {
    fn validate(&self) -> Result<()> {
        self.create.validate()?;
        self.create
            .bundle
            .validate_for_phase(OciSemanticPhase::Start)?;
        let create = &self.create.context.operation_id;
        let start = &self.start_context.operation_id;
        let delete = &self.delete_context.operation_id;
        if create == start || create == delete || start == delete {
            return Err(invalid_request(
                "run requires distinct create, start, and delete operation IDs",
            ));
        }
        Ok(())
    }
}

impl ValidateRequest for ExecRequest {
    fn validate(&self) -> Result<()> {
        if self.process_id.is_init() {
            return Err(invalid_request(
                "exec.process_id `init` is reserved for the container's configured process",
            ));
        }
        OciSemanticValidator::new()?.validate_process(&self.process)?;
        validate_process_io(&self.io, self.process.terminal().unwrap_or(false))
    }
}

impl ValidateRequest for UpdateRequest {
    fn validate(&self) -> Result<()> {
        OciSemanticValidator::new()?.validate_linux_resources(&self.resources)
    }
}

impl ValidateRequest for EventsRequest {
    fn validate(&self) -> Result<()> {
        validate_positive_bounded(self.limit, MAX_EVENT_BATCH_ITEMS, "events.limit")
    }
}

impl ValidateRequest for ReadOutputRequest {
    fn validate(&self) -> Result<()> {
        validate_positive_bounded(
            self.max_bytes,
            MAX_OUTPUT_READ_BYTES,
            "read_output.max_bytes",
        )
    }
}

impl ValidateRequest for WriteStdinRequest {
    fn validate(&self) -> Result<()> {
        if self.data.len() > MAX_STDIN_WRITE_BYTES {
            return Err(invalid_request(format!(
                "write_stdin.data is {} bytes; maximum is {MAX_STDIN_WRITE_BYTES}",
                self.data.len()
            )));
        }
        Ok(())
    }
}

impl ValidateRequest for ResizeRequest {
    fn validate(&self) -> Result<()> {
        validate_terminal_size(self.size.width, self.size.height, "resize.size")
    }
}

impl ValidateRequest for CheckpointRequest {
    fn validate(&self) -> Result<()> {
        validate_absolute_path(&self.directory, "checkpoint.directory")
    }
}

impl ValidateRequest for RestoreRequest {
    fn validate(&self) -> Result<()> {
        self.bundle.validate_for_phase(OciSemanticPhase::Create)?;
        validate_absolute_path(&self.checkpoint_directory, "restore.checkpoint_directory")?;
        validate_process_io(
            &self.io,
            self.bundle
                .spec()
                .process()
                .as_ref()
                .and_then(|process| process.terminal())
                .unwrap_or(false),
        )
    }
}

macro_rules! valid_by_construction {
    ($($request:ty),+ $(,)?) => {
        $(
            impl ValidateRequest for $request {
                fn validate(&self) -> Result<()> {
                    Ok(())
                }
            }
        )+
    };
}

valid_by_construction!(
    StateRequest,
    StartRequest,
    KillRequest,
    DeleteRequest,
    WaitRequest,
    ListRequest,
    ContainerOperationRequest,
    ProcessesRequest,
    StatsRequest,
    CloseStdinRequest,
    SignalProcessRequest,
    WaitProcessRequest,
);

fn initial_process_uses_terminal(request: &CreateRequest) -> bool {
    request
        .bundle
        .spec()
        .process()
        .as_ref()
        .and_then(|process| process.terminal())
        .unwrap_or(false)
}

fn validate_process_io(io: &ProcessIo, process_uses_terminal: bool) -> Result<()> {
    let terminal_modes = [
        matches!(io.stdin, IoMode::Terminal),
        matches!(io.stdout, IoMode::Terminal),
        matches!(io.stderr, IoMode::Terminal),
    ];
    if process_uses_terminal && terminal_modes != [true, true, true] {
        return Err(invalid_request(
            "process.terminal requires terminal stdin, stdout, and stderr",
        ));
    }
    if !process_uses_terminal && terminal_modes.iter().any(|terminal| *terminal) {
        return Err(invalid_request(
            "terminal I/O requires process.terminal to be true",
        ));
    }
    match (process_uses_terminal, io.terminal_size) {
        (true, Some(size)) => {
            validate_terminal_size(size.width, size.height, "process_io.terminal_size")?
        }
        (true, None) => {
            return Err(invalid_request(
                "process.terminal requires an initial terminal_size",
            ));
        }
        (false, Some(_)) => {
            return Err(invalid_request(
                "terminal_size requires process.terminal to be true",
            ));
        }
        (false, None) => {}
    }
    Ok(())
}

fn validate_terminal_size(width: u16, height: u16, field: &str) -> Result<()> {
    if width == 0 || height == 0 {
        return Err(invalid_request(format!(
            "{field} width and height must both be positive"
        )));
    }
    Ok(())
}

fn validate_positive_bounded(value: u32, maximum: u32, field: &str) -> Result<()> {
    if value == 0 || value > maximum {
        return Err(invalid_request(format!(
            "{field} must be between 1 and {maximum}; received {value}"
        )));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, field: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(invalid_request(format!(
            "{field} must be absolute: {}",
            path.display()
        )));
    }
    let Some(path_text) = path.to_str() else {
        return Err(invalid_request(format!(
            "{field} must be valid UTF-8 for SDK transport"
        )));
    };
    if path_text.as_bytes().contains(&0) {
        return Err(invalid_request(format!(
            "{field} must not contain a NUL byte"
        )));
    }
    Ok(())
}

fn invalid_request(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-sdk-request")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use oci_spec::runtime::{LinuxResources, Process};
    use serde_json::json;

    use super::{
        ValidateRequest, MAX_EVENT_BATCH_ITEMS, MAX_OUTPUT_READ_BYTES, MAX_STDIN_WRITE_BYTES,
    };
    use crate::{
        CheckpointRequest, ContainerId, ContainerTarget, EventsRequest, ExecRequest, Generation,
        IoMode, OperationContext, OperationId, ProcessId, ProcessIo, ReadOutputRequest,
        ResizeRequest, TerminalSize, UpdateRequest, WriteStdinRequest,
    };

    fn target() -> ContainerTarget {
        ContainerTarget::exact(
            ContainerId::new("validation-container").expect("container ID"),
            Generation(1),
        )
    }

    fn context() -> OperationContext {
        OperationContext::new(OperationId::new("validation-operation").expect("operation ID"))
    }

    #[test]
    fn validates_bounded_poll_and_write_requests() {
        let events = EventsRequest {
            container: None,
            after_sequence: 0,
            limit: MAX_EVENT_BATCH_ITEMS + 1,
            wait_timeout_ms: None,
        };
        assert!(events.validate().is_err());

        let read = ReadOutputRequest {
            process: crate::ProcessTarget {
                container: target(),
                process_id: ProcessId::new("init").expect("process ID"),
            },
            after_sequence: 0,
            max_bytes: MAX_OUTPUT_READ_BYTES + 1,
            wait_timeout_ms: None,
        };
        assert!(read.validate().is_err());

        let write = WriteStdinRequest {
            context: context(),
            process: read.process,
            data: vec![0; MAX_STDIN_WRITE_BYTES + 1],
        };
        assert!(write.validate().is_err());
    }

    #[test]
    fn validates_exec_process_semantics_and_terminal_contract() {
        let process: Process = serde_json::from_value(json!({
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0},
            "terminal": false
        }))
        .expect("decode process");
        let request = ExecRequest {
            context: context(),
            container: target(),
            process_id: ProcessId::new("exec").expect("process ID"),
            process,
            io: ProcessIo {
                stdin: IoMode::Terminal,
                stdout: IoMode::Terminal,
                stderr: IoMode::Terminal,
                terminal_size: None,
            },
        };
        assert!(request.validate().is_err());

        let terminal_process: Process = serde_json::from_value(json!({
            "cwd": "/",
            "args": ["/bin/sh"],
            "user": {"uid": 0, "gid": 0},
            "terminal": true
        }))
        .expect("decode terminal process");
        let terminal_io = ProcessIo {
            stdin: IoMode::Terminal,
            stdout: IoMode::Terminal,
            stderr: IoMode::Terminal,
            terminal_size: Some(TerminalSize {
                width: 80,
                height: 24,
            }),
        };
        let terminal_request = ExecRequest {
            context: context(),
            container: target(),
            process_id: ProcessId::new("terminal").expect("process ID"),
            process: terminal_process.clone(),
            io: terminal_io.clone(),
        };
        terminal_request
            .validate()
            .expect("exact terminal contract must validate");

        let mut partial = terminal_request.clone();
        partial.io.stderr = IoMode::Capture;
        assert!(partial.validate().is_err());

        let mut missing_size = terminal_request.clone();
        missing_size.io.terminal_size = None;
        assert!(missing_size.validate().is_err());

        let mut zero_size = terminal_request;
        zero_size.io.terminal_size = Some(TerminalSize {
            width: 0,
            height: 24,
        });
        assert!(zero_size.validate().is_err());

        ResizeRequest {
            context: context(),
            process: crate::ProcessTarget {
                container: target(),
                process_id: ProcessId::new("terminal").expect("process ID"),
            },
            size: TerminalSize {
                width: 120,
                height: 40,
            },
        }
        .validate()
        .expect("positive terminal resize");
        assert!(ResizeRequest {
            context: context(),
            process: crate::ProcessTarget {
                container: target(),
                process_id: ProcessId::new("terminal").expect("process ID"),
            },
            size: TerminalSize {
                width: 120,
                height: 0,
            },
        }
        .validate()
        .is_err());
    }

    #[test]
    fn reserves_the_init_process_id_for_the_container_process() {
        let process: Process = serde_json::from_value(json!({
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0},
            "terminal": false
        }))
        .expect("decode process");
        let request = ExecRequest {
            context: context(),
            container: target(),
            process_id: ProcessId::init(),
            process,
            io: ProcessIo::default(),
        };

        let error = request
            .validate()
            .expect_err("exec must not replace the reserved init process");
        assert_eq!(error.code, crate::ErrorCode::InvalidArgument);
    }

    #[test]
    fn validates_resource_updates_and_checkpoint_paths() {
        let resources: LinuxResources = serde_json::from_value(json!({
            "cpu": {"quota": 10, "burst": 20}
        }))
        .expect("decode resources");
        let update = UpdateRequest {
            context: context(),
            target: target(),
            resources,
        };
        assert!(update.validate().is_err());

        let checkpoint = CheckpointRequest {
            context: context(),
            target: target(),
            directory: PathBuf::from("relative-checkpoint"),
            leave_running: false,
        };
        assert!(checkpoint.validate().is_err());
    }
}
