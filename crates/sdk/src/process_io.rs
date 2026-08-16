use crate::{Error, ErrorCode, IoMode, ProcessIo, Result, TerminalSize};

impl ProcessIo {
    /// Resolve the effective process I/O contract against one OCI process.
    ///
    /// A terminal `consoleSize` is the normative initial PTY size. Callers may
    /// omit the transport copy, or provide the same value for compatibility;
    /// a conflicting copy fails before runtime mutation. A non-terminal
    /// `consoleSize` is ignored as required by the OCI specification.
    pub fn resolve_for_process(&self, process: &oci_spec::runtime::Process) -> Result<Self> {
        let terminal = process.terminal().unwrap_or(false);
        let console_size = if terminal {
            process
                .console_size()
                .map(|size| terminal_size_from_oci(size.width(), size.height()))
                .transpose()?
        } else {
            None
        };
        resolve(self, terminal, console_size)
    }
}

pub(crate) fn validate_without_process(io: &ProcessIo) -> Result<()> {
    resolve(io, false, None).map(|_| ())
}

pub(crate) fn validate_terminal_size(width: u16, height: u16, field: &str) -> Result<()> {
    if width == 0 || height == 0 {
        return Err(invalid(format!(
            "{field} width and height must both be positive"
        )));
    }
    Ok(())
}

fn resolve(
    io: &ProcessIo,
    process_uses_terminal: bool,
    console_size: Option<TerminalSize>,
) -> Result<ProcessIo> {
    let terminal_modes = [
        matches!(io.stdin, IoMode::Terminal),
        matches!(io.stdout, IoMode::Terminal),
        matches!(io.stderr, IoMode::Terminal),
    ];
    if process_uses_terminal && terminal_modes != [true, true, true] {
        return Err(invalid(
            "process.terminal requires terminal stdin, stdout, and stderr",
        ));
    }
    if !process_uses_terminal && terminal_modes.iter().any(|terminal| *terminal) {
        return Err(invalid("terminal I/O requires process.terminal to be true"));
    }

    let mut resolved = io.clone();
    if process_uses_terminal {
        if let Some(configured) = console_size {
            if io
                .terminal_size
                .is_some_and(|transport| transport != configured)
            {
                return Err(invalid(format!(
                    "process.consoleSize {}x{} conflicts with process_io.terminal_size",
                    configured.width, configured.height
                )));
            }
            resolved.terminal_size = Some(configured);
        }
        let size = resolved.terminal_size.ok_or_else(|| {
            invalid("process.terminal requires process.consoleSize or an initial terminal_size")
        })?;
        validate_terminal_size(size.width, size.height, "initial terminal size")?;
    } else if io.terminal_size.is_some() {
        return Err(invalid(
            "terminal_size requires process.terminal to be true",
        ));
    }
    Ok(resolved)
}

fn terminal_size_from_oci(width: u64, height: u64) -> Result<TerminalSize> {
    let width = u16::try_from(width).map_err(|_| {
        unsupported(format!(
            "process.consoleSize.width must not exceed {} on this runtime",
            u16::MAX
        ))
    })?;
    let height = u16::try_from(height).map_err(|_| {
        unsupported(format!(
            "process.consoleSize.height must not exceed {} on this runtime",
            u16::MAX
        ))
    })?;
    Ok(TerminalSize { width, height })
}

fn invalid(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("validate-sdk-request")
}

fn unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::Unsupported, message).for_operation("validate-sdk-request")
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::Process;
    use serde_json::json;

    use crate::{ErrorCode, IoMode, ProcessIo, TerminalSize};

    fn terminal_process(console_size: serde_json::Value) -> Process {
        serde_json::from_value(json!({
            "cwd": "/",
            "args": ["/bin/sh"],
            "user": {"uid": 0, "gid": 0},
            "terminal": true,
            "consoleSize": console_size
        }))
        .expect("decode terminal process")
    }

    fn terminal_io(size: Option<TerminalSize>) -> ProcessIo {
        ProcessIo {
            stdin: IoMode::Terminal,
            stdout: IoMode::Terminal,
            stderr: IoMode::Terminal,
            terminal_size: size,
        }
    }

    #[test]
    fn terminal_console_size_supplies_and_fences_initial_dimensions() {
        let process = terminal_process(json!({"width": 120, "height": 40}));
        let io = terminal_io(None);
        let resolved = io
            .resolve_for_process(&process)
            .expect("OCI console size must supply the transport copy");
        assert_eq!(
            resolved.terminal_size,
            Some(TerminalSize {
                width: 120,
                height: 40,
            })
        );
        terminal_io(resolved.terminal_size)
            .resolve_for_process(&process)
            .expect("matching transport dimensions remain compatible");

        let error = terminal_io(Some(TerminalSize {
            width: 80,
            height: 24,
        }))
        .resolve_for_process(&process)
        .expect_err("conflicting initial dimensions must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("process.consoleSize"));

        let oversized = terminal_process(json!({"width": 65536, "height": 40}));
        let error = io
            .resolve_for_process(&oversized)
            .expect_err("unrepresentable PTY dimensions must be rejected");
        assert_eq!(error.code, ErrorCode::Unsupported);

        let ignored: Process = serde_json::from_value(json!({
            "cwd": "/",
            "args": ["/bin/true"],
            "user": {"uid": 0, "gid": 0},
            "terminal": false,
            "consoleSize": {"width": 18446744073709551615u64, "height": 0}
        }))
        .expect("decode ignored non-terminal console size");
        assert_eq!(
            ProcessIo::default()
                .resolve_for_process(&ignored)
                .expect("non-terminal console size must be ignored"),
            ProcessIo::default()
        );
    }
}
