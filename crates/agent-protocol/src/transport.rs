use a3s_oci_sdk::{Error, ErrorCode, Result};

/// Guest control port reserved by every libkrun host bridge.
pub const AGENT_VSOCK_PORT: u32 = 4_093;

/// Exact endpoint basename mapped to the guest-agent vsock port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentVsockEndpoint {
    pipe_name: String,
}

impl AgentVsockEndpoint {
    /// Generate an unguessable runtime-owned endpoint name.
    pub fn generate() -> Result<Self> {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| {
            Error::new(
                ErrorCode::Internal,
                format!("operating-system random source failed: {error}"),
            )
            .for_operation("generate-agent-endpoint")
        })?;
        let mut pipe_name = String::from("a3s-oci-agent-");
        for byte in nonce {
            use std::fmt::Write;
            write!(&mut pipe_name, "{byte:02x}").map_err(|error| {
                Error::new(
                    ErrorCode::Internal,
                    format!("failed to encode guest-agent endpoint nonce: {error}"),
                )
                .for_operation("generate-agent-endpoint")
            })?;
        }
        Self::new(pipe_name)
    }

    /// Validate a portable basename from which the host endpoint is derived.
    pub fn new(pipe_name: impl Into<String>) -> Result<Self> {
        let pipe_name = pipe_name.into();
        if pipe_name.is_empty()
            || pipe_name.len() > 128
            || !pipe_name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            || !pipe_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "agent pipe name must be a 1..=128 byte ASCII basename starting with an \
                 alphanumeric character and containing only alphanumerics, `_`, or `-`",
            )
            .for_operation("configure-agent-transport"));
        }
        Ok(Self { pipe_name })
    }

    /// Bare name passed to `krun_add_vsock_port_windows`.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Full local Windows named-pipe path used by the host server.
    #[must_use]
    pub fn windows_pipe_path(&self) -> String {
        format!(r"\\.\pipe\{}", self.pipe_name)
    }

    /// Fixed guest vsock port.
    #[must_use]
    pub const fn port(&self) -> u32 {
        AGENT_VSOCK_PORT
    }
}

#[cfg(test)]
mod tests {
    use crate::AgentCapabilities;

    use super::{AgentVsockEndpoint, AGENT_VSOCK_PORT};

    #[test]
    fn validates_an_exact_windows_agent_pipe_basename() {
        let endpoint = AgentVsockEndpoint::new("a3s-oci-agent-123").expect("valid agent endpoint");
        assert_eq!(endpoint.pipe_name(), "a3s-oci-agent-123");
        assert_eq!(endpoint.port(), AGENT_VSOCK_PORT);
        assert_eq!(endpoint.windows_pipe_path(), r"\\.\pipe\a3s-oci-agent-123");

        for name in [
            "",
            "-a3s",
            "a3s.agent",
            r"a3s\agent",
            r"\\.\pipe\a3s-agent",
            "a3s agent",
        ] {
            assert!(
                AgentVsockEndpoint::new(name).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn generates_a_valid_unguessable_endpoint_name() {
        let endpoint =
            AgentVsockEndpoint::generate().expect("operating-system random source must work");
        assert!(endpoint.pipe_name().starts_with("a3s-oci-agent-"));
        assert_eq!(endpoint.pipe_name().len(), "a3s-oci-agent-".len() + 32);
        AgentVsockEndpoint::new(endpoint.pipe_name()).expect("generated endpoint must validate");
    }

    #[test]
    fn negotiation_only_capabilities_do_not_overclaim_an_executor() {
        let capabilities =
            AgentCapabilities::handshake_only("0.1.0-test", "x86_64").expect("valid handshake");
        assert!(capabilities.operations().is_empty());
    }

    #[test]
    fn generates_nonzero_redacted_session_tokens() {
        let token = crate::SessionToken::generate().expect("operating-system random source");
        assert!(token.as_bytes().iter().any(|byte| *byte != 0));
        assert_eq!(format!("{token:?}"), "SessionToken([REDACTED])");
        let encoded = token.expose_hex();
        assert_eq!(encoded.len(), 64);
        assert_eq!(
            crate::SessionToken::from_hex(encoded.as_str()).expect("decode bootstrap token"),
            token
        );
        assert!(crate::SessionToken::from_hex("00").is_err());
        assert!(crate::SessionToken::from_hex(&"0".repeat(64)).is_err());
    }
}
