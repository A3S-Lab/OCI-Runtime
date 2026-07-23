//! Cross-field OCI semantics that JSON Schema cannot express.

mod common;
mod linux;
mod vm;

use std::fmt;

use oci_spec::runtime::{LinuxResources, Process, Spec};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, ErrorCode, OciSchemaDocument, OciSchemaValidator, Result};

const MAX_REPORTED_VIOLATIONS: usize = 64;

/// Lifecycle point whose configuration requirements are being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSemanticPhase {
    /// Validate a Linux OCI configuration before it is accepted as a bundle.
    Configuration,
    /// Validate all requirements that must hold before OCI `create` mutates state.
    Create,
    /// Validate all requirements that must hold before OCI `start` executes the process.
    Start,
}

impl fmt::Display for OciSemanticPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "configuration",
            Self::Create => "create",
            Self::Start => "start",
        })
    }
}

/// Classification of one semantic violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSemanticViolationKind {
    /// A field value or cross-field combination violates OCI semantics.
    Invalid,
    /// The configuration selects a native workload platform A3S does not run.
    UnsupportedPlatform,
}

/// One deterministic violation of an OCI cross-field or platform rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciSemanticViolation {
    pub instance_path: String,
    pub rule: String,
    pub kind: OciSemanticViolationKind,
    pub message: String,
}

/// Bounded semantic-validation evidence suitable for SDK transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciSemanticValidationReport {
    pub phase: OciSemanticPhase,
    pub valid: bool,
    pub violations: Vec<OciSemanticViolation>,
    pub truncated: bool,
}

/// Semantic validator for the Linux workload contract used by A3S.
///
/// Windows, macOS, and Linux utility-VM hosts still execute a Linux OCI
/// workload. Native Windows, Solaris, FreeBSD, and z/OS workload sections are
/// rejected explicitly. The optional OCI `vm` section remains represented and
/// receives its own platform-independent checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct OciSemanticValidator;

impl OciSemanticValidator {
    /// Construct a validator and verify the pinned schema set.
    pub fn new() -> Result<Self> {
        OciSchemaValidator::new()?;
        Ok(Self)
    }

    /// Validate schema first, then return bounded semantic evidence.
    pub fn inspect(
        self,
        phase: OciSemanticPhase,
        value: &Value,
    ) -> Result<OciSemanticValidationReport> {
        OciSchemaValidator::new()?.validate(OciSchemaDocument::Configuration, value)?;
        Ok(self.inspect_schema_valid(phase, value))
    }

    fn inspect_schema_valid(
        self,
        phase: OciSemanticPhase,
        value: &Value,
    ) -> OciSemanticValidationReport {
        let mut collector = ViolationCollector::default();
        common::inspect(value, phase, &mut collector);
        linux::inspect(value, &mut collector);
        vm::inspect(value, &mut collector);
        collector.finish(phase)
    }

    /// Validate a raw OCI configuration or return a stable SDK error.
    pub fn validate(self, phase: OciSemanticPhase, value: &Value) -> Result<()> {
        OciSchemaValidator::new()?.validate(OciSchemaDocument::Configuration, value)?;
        self.validate_schema_valid(phase, value)
    }

    pub(crate) fn validate_schema_valid(
        self,
        phase: OciSemanticPhase,
        value: &Value,
    ) -> Result<()> {
        let report = self.inspect_schema_valid(phase, value);
        if report.valid {
            return Ok(());
        }

        let Some(first) = report.violations.first() else {
            return Err(Error::new(
                ErrorCode::Internal,
                "invalid semantic validation report contains no violation",
            )
            .for_operation("validate-oci-semantics"));
        };
        let count = if report.truncated {
            format!("at least {}", report.violations.len() + 1)
        } else {
            report.violations.len().to_string()
        };
        let code = if first.kind == OciSemanticViolationKind::UnsupportedPlatform {
            ErrorCode::Unsupported
        } else {
            ErrorCode::InvalidArgument
        };
        Err(Error::new(
            code,
            format!(
                "OCI {phase} failed semantic validation ({count} violation(s)): {} at {} [{}]",
                first.message,
                display_instance_path(&first.instance_path),
                first.rule
            ),
        )
        .for_operation("validate-oci-semantics"))
    }

    /// Validate a complete typed OCI configuration.
    pub fn validate_spec(self, phase: OciSemanticPhase, spec: &Spec) -> Result<()> {
        let value = serde_json::to_value(spec).map_err(|error| {
            Error::new(
                ErrorCode::InvalidArgument,
                format!("failed to encode OCI configuration for semantic validation: {error}"),
            )
            .for_operation("validate-oci-semantics")
        })?;
        self.validate(phase, &value)
    }

    /// Validate one Linux OCI process using the same runnable-process rules.
    pub fn validate_process(self, process: &Process) -> Result<()> {
        let value = serde_json::json!({
            "ociVersion": crate::OCI_RUNTIME_SPEC_VERSION_MAX,
            "root": {"path": "rootfs"},
            "process": process,
        });
        self.validate(OciSemanticPhase::Start, &value)
    }

    /// Validate one OCI Linux resource update using the configuration rules.
    pub fn validate_linux_resources(self, resources: &LinuxResources) -> Result<()> {
        let value = serde_json::json!({
            "ociVersion": crate::OCI_RUNTIME_SPEC_VERSION_MAX,
            "root": {"path": "rootfs"},
            "linux": {"resources": resources},
        });
        self.validate(OciSemanticPhase::Configuration, &value)
    }
}

#[derive(Default)]
struct ViolationCollector {
    violations: Vec<OciSemanticViolation>,
    truncated: bool,
}

impl ViolationCollector {
    fn invalid(
        &mut self,
        instance_path: impl Into<String>,
        rule: &'static str,
        message: impl Into<String>,
    ) {
        self.push(
            instance_path,
            rule,
            OciSemanticViolationKind::Invalid,
            message,
        );
    }

    fn unsupported(
        &mut self,
        instance_path: impl Into<String>,
        rule: &'static str,
        message: impl Into<String>,
    ) {
        self.push(
            instance_path,
            rule,
            OciSemanticViolationKind::UnsupportedPlatform,
            message,
        );
    }

    fn push(
        &mut self,
        instance_path: impl Into<String>,
        rule: &'static str,
        kind: OciSemanticViolationKind,
        message: impl Into<String>,
    ) {
        if self.violations.len() == MAX_REPORTED_VIOLATIONS {
            self.truncated = true;
            return;
        }
        if self.truncated {
            return;
        }
        self.violations.push(OciSemanticViolation {
            instance_path: instance_path.into(),
            rule: rule.to_string(),
            kind,
            message: message.into(),
        });
    }

    fn finish(self, phase: OciSemanticPhase) -> OciSemanticValidationReport {
        OciSemanticValidationReport {
            phase,
            valid: self.violations.is_empty() && !self.truncated,
            violations: self.violations,
            truncated: self.truncated,
        }
    }
}

fn display_instance_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

fn is_posix_absolute(value: &str) -> bool {
    value.starts_with('/')
}

fn is_runtime_absolute(value: &str) -> bool {
    if is_posix_absolute(value) || value.starts_with(r"\\") || value.starts_with("//") {
        return true;
    }
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

fn contains_nul(value: &str) -> bool {
    value.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests;
