//! OCI Runtime annotation values derived from the pinned OCI Image Specification.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, OnceLock};

use jsonschema::{Draft, PatternOptions, Retrieve, Uri, Validator};
use serde_json::{json, Value};

use crate::{Error, ErrorCode, Result};

/// OCI Image Specification tag referenced by OCI Runtime Specification 1.3.0.
pub const OCI_IMAGE_SPEC_VERSION: &str = "v1.1.0-rc2";
/// Commit resolved from the annotated OCI Image Specification tag.
pub const OCI_IMAGE_SPEC_COMMIT: &str = "19a74bcb54ba211005a68d85c6b359c2947721ce";
/// Runtime annotation carrying the image-configured default stop signal.
pub const OCI_IMAGE_STOP_SIGNAL_ANNOTATION: &str = "org.opencontainers.image.stopSignal";

const OCI_IMAGE_OS_ANNOTATION: &str = "org.opencontainers.image.os";
const OCI_IMAGE_OS_VERSION_ANNOTATION: &str = "org.opencontainers.image.os.version";
const OCI_IMAGE_OS_FEATURES_ANNOTATION: &str = "org.opencontainers.image.os.features";
const OCI_IMAGE_ARCHITECTURE_ANNOTATION: &str = "org.opencontainers.image.architecture";
const OCI_IMAGE_VARIANT_ANNOTATION: &str = "org.opencontainers.image.variant";
const OCI_IMAGE_AUTHOR_ANNOTATION: &str = "org.opencontainers.image.author";
const OCI_IMAGE_CREATED_ANNOTATION: &str = "org.opencontainers.image.created";

const IMAGE_SCHEMA_BASE_URI: &str = "https://opencontainers.org/schema/image/";
const IMAGE_CONFIG_SCHEMA: &str =
    include_str!("../vendor/image-spec/v1.1.0-rc2/schema/config-schema.json");
const IMAGE_DEFINITIONS_SCHEMA: &str =
    include_str!("../vendor/image-spec/v1.1.0-rc2/schema/defs.json");

const LINUX_NAMED_SIGNALS: &[(&str, i32)] = &[
    ("SIGHUP", 1),
    ("SIGINT", 2),
    ("SIGQUIT", 3),
    ("SIGILL", 4),
    ("SIGTRAP", 5),
    ("SIGABRT", 6),
    ("SIGIOT", 6),
    ("SIGBUS", 7),
    ("SIGFPE", 8),
    ("SIGKILL", 9),
    ("SIGUSR1", 10),
    ("SIGSEGV", 11),
    ("SIGUSR2", 12),
    ("SIGPIPE", 13),
    ("SIGALRM", 14),
    ("SIGTERM", 15),
    ("SIGSTKFLT", 16),
    ("SIGCHLD", 17),
    ("SIGCLD", 17),
    ("SIGCONT", 18),
    ("SIGSTOP", 19),
    ("SIGTSTP", 20),
    ("SIGTTIN", 21),
    ("SIGTTOU", 22),
    ("SIGURG", 23),
    ("SIGXCPU", 24),
    ("SIGXFSZ", 25),
    ("SIGVTALRM", 26),
    ("SIGPROF", 27),
    ("SIGWINCH", 28),
    ("SIGIO", 29),
    ("SIGPOLL", 29),
    ("SIGPWR", 30),
    ("SIGSYS", 31),
    ("SIGUNUSED", 31),
    ("SIGRTMIN", 34),
    ("SIGRTMAX", 64),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OciImageAnnotationValueKind {
    String,
    Created,
    OsFeatures,
    StopSignal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OciImageAnnotationViolation {
    pub kind: OciImageAnnotationValueKind,
    pub message: String,
}

pub(crate) fn initialize() -> Result<()> {
    compiled_image_schema().map(|_| ())
}

pub(crate) fn validate_value(
    key: &str,
    value: &str,
) -> Result<Option<OciImageAnnotationViolation>> {
    let (property, kind) = match key {
        OCI_IMAGE_OS_ANNOTATION => ("os", OciImageAnnotationValueKind::String),
        OCI_IMAGE_OS_VERSION_ANNOTATION => ("os.version", OciImageAnnotationValueKind::String),
        OCI_IMAGE_ARCHITECTURE_ANNOTATION => ("architecture", OciImageAnnotationValueKind::String),
        OCI_IMAGE_VARIANT_ANNOTATION => ("variant", OciImageAnnotationValueKind::String),
        OCI_IMAGE_AUTHOR_ANNOTATION => ("author", OciImageAnnotationValueKind::String),
        OCI_IMAGE_CREATED_ANNOTATION => ("created", OciImageAnnotationValueKind::Created),
        OCI_IMAGE_OS_FEATURES_ANNOTATION => {
            ("os.features", OciImageAnnotationValueKind::OsFeatures)
        }
        OCI_IMAGE_STOP_SIGNAL_ANNOTATION => {
            ("config.StopSignal", OciImageAnnotationValueKind::StopSignal)
        }
        _ => return Ok(None),
    };

    let mut image = json!({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": []}
    });
    match key {
        OCI_IMAGE_OS_FEATURES_ANNOTATION => {
            let features = match serde_json::from_str::<Value>(value) {
                Ok(features) => features,
                Err(error) => {
                    return Ok(Some(OciImageAnnotationViolation {
                        kind,
                        message: format!(
                            "annotation {key} must contain the JSON serialization of the OCI Image Specification os.features array: {error}"
                        ),
                    }));
                }
            };
            image[property] = features;
        }
        OCI_IMAGE_STOP_SIGNAL_ANNOTATION => {
            image["config"] = json!({"StopSignal": value});
        }
        _ => image[property] = Value::String(value.to_string()),
    }

    let schema_error = compiled_image_schema()?
        .iter_errors(&image)
        .next()
        .map(|error| error.to_string());
    if let Some(schema_error) = schema_error {
        return Ok(Some(OciImageAnnotationViolation {
            kind,
            message: format!(
                "annotation {key} is not a valid OCI Image Specification {property} value: {schema_error}"
            ),
        }));
    }

    if kind == OciImageAnnotationValueKind::StopSignal && parse_stop_signal(value).is_none() {
        return Ok(Some(OciImageAnnotationViolation {
            kind,
            message: format!(
                "annotation {key} must name a supported Linux signal such as SIGTERM, SIGRTMIN+3, or 15"
            ),
        }));
    }

    Ok(None)
}

pub(crate) fn parse_stop_signal(value: &str) -> Option<i32> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value
            .parse::<i32>()
            .ok()
            .filter(|number| (1..=64).contains(number));
    }
    if let Some((_, number)) = LINUX_NAMED_SIGNALS.iter().find(|(name, _)| *name == value) {
        return Some(*number);
    }
    if let Some(offset) = decimal_suffix(value, "SIGRTMIN+") {
        return (offset <= 30).then_some(34 + offset);
    }
    if let Some(offset) = decimal_suffix(value, "SIGRTMAX-") {
        return (offset <= 30).then_some(64 - offset);
    }
    None
}

fn decimal_suffix(value: &str, prefix: &str) -> Option<i32> {
    let suffix = value.strip_prefix(prefix)?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

fn compiled_image_schema() -> Result<&'static Validator> {
    static SCHEMA: OnceLock<std::result::Result<Validator, String>> = OnceLock::new();
    SCHEMA
        .get_or_init(compile_image_schema)
        .as_ref()
        .map_err(|message| {
            Error::new(
                ErrorCode::Internal,
                format!(
                    "failed to compile pinned OCI Image Specification {OCI_IMAGE_SPEC_VERSION} schema: {message}"
                ),
            )
            .for_operation("compile-oci-image-schema")
        })
}

fn compile_image_schema() -> std::result::Result<Validator, String> {
    let root: Value = serde_json::from_str(IMAGE_CONFIG_SCHEMA)
        .map_err(|error| format!("invalid embedded config-schema.json: {error}"))?;
    let definitions: Value = serde_json::from_str(IMAGE_DEFINITIONS_SCHEMA)
        .map_err(|error| format!("invalid embedded defs.json: {error}"))?;
    jsonschema::options()
        .with_draft(Draft::Draft4)
        .with_base_uri(IMAGE_SCHEMA_BASE_URI)
        .with_retriever(EmbeddedImageSchemaRetriever::new(definitions))
        .with_pattern_options(PatternOptions::regex())
        .should_validate_formats(true)
        .build(&root)
        .map_err(|error| error.to_string())
}

#[derive(Clone)]
struct EmbeddedImageSchemaRetriever {
    documents: Arc<HashMap<String, Value>>,
}

impl EmbeddedImageSchemaRetriever {
    fn new(definitions: Value) -> Self {
        Self {
            documents: Arc::new(HashMap::from([(
                format!("{IMAGE_SCHEMA_BASE_URI}defs.json"),
                definitions,
            )])),
        }
    }
}

impl Retrieve for EmbeddedImageSchemaRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.documents.get(uri.as_str()).cloned().ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!("embedded OCI Image Specification schema not found: {uri}"),
            )) as Box<dyn std::error::Error + Send + Sync>
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        initialize, parse_stop_signal, IMAGE_CONFIG_SCHEMA, IMAGE_DEFINITIONS_SCHEMA,
        OCI_IMAGE_SPEC_COMMIT, OCI_IMAGE_SPEC_VERSION,
    };
    use crate::conformance::canonical_text_sha256;

    const CONFIG_SOURCE: &str = include_str!("../vendor/image-spec/v1.1.0-rc2/config.md");
    const CONVERSION_SOURCE: &str = include_str!("../vendor/image-spec/v1.1.0-rc2/conversion.md");
    const RUNTIME_CONFIG_SOURCE: &str = include_str!("../vendor/runtime-spec/v1.3.0/config.md");

    #[test]
    fn pins_runtime_referenced_image_spec_sources() {
        assert_eq!(OCI_IMAGE_SPEC_VERSION, "v1.1.0-rc2");
        assert_eq!(
            OCI_IMAGE_SPEC_COMMIT,
            "19a74bcb54ba211005a68d85c6b359c2947721ce"
        );
        assert_eq!(
            canonical_text_sha256(CONFIG_SOURCE),
            "sha256:fac2d89de4130d18d393d4539c4db4827f16cba6d1f893fb743351b4595bc740"
        );
        assert_eq!(
            canonical_text_sha256(CONVERSION_SOURCE),
            "sha256:e3dc948043dc9ec16d4ca818d3af954377e48c9eb353ac554200480a953148ed"
        );
        assert_eq!(
            canonical_text_sha256(IMAGE_CONFIG_SCHEMA),
            "sha256:ddf035e2512daed6d501add9e69caeb187a2203a4595e994b03ff7cc203ee7bd"
        );
        assert_eq!(
            canonical_text_sha256(IMAGE_DEFINITIONS_SCHEMA),
            "sha256:35246f51344bcb4e2cf30f968e234a4ae8dbd916ff1a3c490fe53c0b2518b82c"
        );
        assert!(RUNTIME_CONFIG_SOURCE.contains(
            "https://github.com/opencontainers/image-spec/blob/v1.1.0-rc2/config.md#properties"
        ));
        assert!(RUNTIME_CONFIG_SOURCE.contains(
            "https://github.com/opencontainers/image-spec/blob/v1.1.0-rc2/conversion.md"
        ));
        initialize().expect("compile pinned OCI Image Specification schema offline");
    }

    #[test]
    fn parses_portable_linux_stop_signal_forms() {
        for (source, expected) in [
            ("SIGTERM", 15),
            ("15", 15),
            ("SIGRTMIN", 34),
            ("SIGRTMIN+3", 37),
            ("SIGRTMAX-3", 61),
            ("SIGRTMAX", 64),
        ] {
            assert_eq!(parse_stop_signal(source), Some(expected), "{source}");
        }
        for invalid in [
            "",
            "0",
            "65",
            "TERM",
            "sigterm",
            "SIGUNKNOWN",
            "SIGRTMIN+31",
            "SIGRTMAX-31",
        ] {
            assert_eq!(parse_stop_signal(invalid), None, "{invalid}");
        }
    }
}
