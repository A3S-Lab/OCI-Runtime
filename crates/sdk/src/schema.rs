use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock};

use jsonschema::{Draft, PatternOptions, Retrieve, Uri, Validator};
use oci_spec::runtime::{Features, Spec, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, ErrorCode, Result};

mod coverage;
mod embedded;
#[cfg(test)]
mod suite_tests;

use embedded::EMBEDDED_SCHEMAS;

pub use coverage::{
    OciSchemaCoverageItem, OciSchemaCoverageManifest, OciSchemaDisposition,
    OciSchemaEvidenceBinding, OciSchemaEvidenceManifest,
};

const SCHEMA_BASE_URI: &str = "https://schema.a3s.dev/oci/runtime-spec/v1.3.0/";
const MAX_REPORTED_VIOLATIONS: usize = 64;

/// Official OCI JSON document validated by the SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSchemaDocument {
    Configuration,
    State,
    Features,
}

impl OciSchemaDocument {
    const fn root_schema(self) -> &'static str {
        match self {
            Self::Configuration => "config-schema.json",
            Self::State => "state-schema.json",
            Self::Features => "features-schema.json",
        }
    }

    const fn operation(self) -> &'static str {
        match self {
            Self::Configuration => "validate-oci-configuration",
            Self::State => "validate-oci-state",
            Self::Features => "validate-oci-features",
        }
    }
}

impl fmt::Display for OciSchemaDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.root_schema())
    }
}

/// One deterministic violation of a pinned OCI 1.3.0 JSON Schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciSchemaViolation {
    pub instance_path: String,
    pub schema_path: String,
    pub message: String,
}

/// Bounded validation evidence suitable for SDK and transport responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciSchemaValidationReport {
    pub document: OciSchemaDocument,
    pub valid: bool,
    pub violations: Vec<OciSchemaViolation>,
    pub truncated: bool,
}

/// Kind of entry in the pinned schema inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSchemaInventoryKind {
    Property,
    EnumValue,
}

/// One named property or enum value declared by an official OCI schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OciSchemaInventoryItem {
    pub schema: String,
    pub pointer: String,
    pub kind: OciSchemaInventoryKind,
    pub value: String,
}

/// Offline validator for the pinned OCI Runtime Specification 1.3.0 schemas.
///
/// Construction compiles all three public root schemas and resolves every
/// reference from embedded, checksum-reviewable repository files. Validation
/// never performs filesystem or network retrieval.
#[derive(Debug, Clone, Copy, Default)]
pub struct OciSchemaValidator;

impl OciSchemaValidator {
    /// Compile and verify the embedded schema set.
    pub fn new() -> Result<Self> {
        compiled_schemas()?;
        Ok(Self)
    }

    /// Validate a raw JSON document and return bounded structured evidence.
    pub fn inspect(
        self,
        document: OciSchemaDocument,
        value: &Value,
    ) -> Result<OciSchemaValidationReport> {
        let compiled = compiled_schemas()?;
        let validator = compiled.validator(document);
        let mut errors = validator.iter_errors(value);
        let mut violations = Vec::new();

        for error in errors.by_ref().take(MAX_REPORTED_VIOLATIONS) {
            violations.push(OciSchemaViolation {
                instance_path: error.instance_path().to_string(),
                schema_path: error
                    .absolute_keyword_location()
                    .map_or_else(|| error.schema_path().to_string(), ToString::to_string),
                message: error.to_string(),
            });
        }
        let truncated = errors.next().is_some();

        Ok(OciSchemaValidationReport {
            document,
            valid: violations.is_empty() && !truncated,
            violations,
            truncated,
        })
    }

    /// Validate a raw JSON document or return a stable SDK error.
    pub fn validate(self, document: OciSchemaDocument, value: &Value) -> Result<()> {
        let report = self.inspect(document, value)?;
        if report.valid {
            return Ok(());
        }

        let first = report
            .violations
            .first()
            .map(|violation| {
                format!(
                    "{} at {}",
                    violation.message,
                    display_instance_path(&violation.instance_path)
                )
            })
            .unwrap_or_else(|| "violation limit exceeded".to_string());
        let suffix = if report.truncated {
            format!("at least {}", report.violations.len() + 1)
        } else {
            report.violations.len().to_string()
        };
        Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "OCI {} failed pinned 1.3.0 schema validation ({suffix} violation(s)): {first}",
                document
            ),
        )
        .for_operation(document.operation()))
    }

    /// Validate a complete typed OCI runtime configuration.
    pub fn validate_spec(self, spec: &Spec) -> Result<()> {
        let value = encode_typed_document(OciSchemaDocument::Configuration, spec)?;
        self.validate(OciSchemaDocument::Configuration, &value)
    }

    /// Validate a complete typed OCI runtime state document.
    pub fn validate_state(self, state: &State) -> Result<()> {
        let value = encode_typed_document(OciSchemaDocument::State, state)?;
        self.validate(OciSchemaDocument::State, &value)
    }

    /// Validate a complete typed OCI runtime feature document.
    pub fn validate_features(self, features: &Features) -> Result<()> {
        let value = encode_typed_document(OciSchemaDocument::Features, features)?;
        self.validate(OciSchemaDocument::Features, &value)
    }

    /// Inventory every named property and enum value in the pinned schema set.
    pub fn inventory(self) -> Result<Vec<OciSchemaInventoryItem>> {
        let compiled = compiled_schemas()?;
        let mut inventory = Vec::new();
        for (schema, value) in &compiled.documents {
            collect_inventory(schema, value, "", &mut inventory);
        }
        inventory.sort();
        inventory.dedup();
        Ok(inventory)
    }
}

fn encode_typed_document(document: OciSchemaDocument, value: &impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|error| {
        Error::new(
            ErrorCode::InvalidArgument,
            format!("failed to encode OCI {document}: {error}"),
        )
        .for_operation(document.operation())
    })
}

fn display_instance_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

struct CompiledSchemas {
    documents: BTreeMap<&'static str, Value>,
    configuration: Validator,
    state: Validator,
    features: Validator,
}

impl CompiledSchemas {
    fn compile() -> std::result::Result<Self, String> {
        let mut documents = EMBEDDED_SCHEMAS
            .iter()
            .map(|(name, source)| {
                serde_json::from_str(source)
                    .map(|value| (*name, value))
                    .map_err(|error| format!("invalid embedded OCI schema {name}: {error}"))
            })
            .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
        let normalized_refs = documents
            .values_mut()
            .map(normalize_legacy_definition_refs)
            .sum::<usize>();
        if normalized_refs != 1 {
            return Err(format!(
                "expected exactly one legacy #definitions reference in the pinned schema set, \
                 found {normalized_refs}"
            ));
        }
        let retriever = EmbeddedSchemaRetriever::new(&documents);

        Ok(Self {
            configuration: compile_validator(
                OciSchemaDocument::Configuration,
                &documents,
                retriever.clone(),
            )?,
            state: compile_validator(OciSchemaDocument::State, &documents, retriever.clone())?,
            features: compile_validator(OciSchemaDocument::Features, &documents, retriever)?,
            documents,
        })
    }

    const fn validator(&self, document: OciSchemaDocument) -> &Validator {
        match document {
            OciSchemaDocument::Configuration => &self.configuration,
            OciSchemaDocument::State => &self.state,
            OciSchemaDocument::Features => &self.features,
        }
    }
}

fn normalize_legacy_definition_refs(value: &mut Value) -> usize {
    match value {
        Value::Object(object) => {
            let mut normalized = 0;
            let replacement = object
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|reference| reference.strip_prefix("#definitions/"))
                .map(|definition| format!("#/definitions/{definition}"));
            if let Some(reference) = replacement {
                object.insert("$ref".to_string(), Value::String(reference));
                normalized += 1;
            }
            normalized
                + object
                    .values_mut()
                    .map(normalize_legacy_definition_refs)
                    .sum::<usize>()
        }
        Value::Array(array) => array.iter_mut().map(normalize_legacy_definition_refs).sum(),
        _ => 0,
    }
}

fn compiled_schemas() -> Result<&'static CompiledSchemas> {
    static SCHEMAS: OnceLock<std::result::Result<CompiledSchemas, String>> = OnceLock::new();
    SCHEMAS
        .get_or_init(CompiledSchemas::compile)
        .as_ref()
        .map_err(|message| {
            Error::new(
                ErrorCode::Internal,
                format!("failed to compile pinned OCI 1.3.0 schemas: {message}"),
            )
            .for_operation("compile-oci-schemas")
        })
}

fn compile_validator(
    document: OciSchemaDocument,
    documents: &BTreeMap<&'static str, Value>,
    retriever: EmbeddedSchemaRetriever,
) -> std::result::Result<Validator, String> {
    let root = documents
        .get(document.root_schema())
        .ok_or_else(|| format!("missing embedded root schema {document}"))?;
    jsonschema::options()
        .with_draft(Draft::Draft4)
        .with_base_uri(SCHEMA_BASE_URI)
        .with_retriever(retriever)
        .with_pattern_options(PatternOptions::regex())
        .build(root)
        .map_err(|error| format!("failed to compile {document}: {error}"))
}

#[derive(Clone)]
struct EmbeddedSchemaRetriever {
    documents: Arc<HashMap<String, Value>>,
}

impl EmbeddedSchemaRetriever {
    fn new(documents: &BTreeMap<&'static str, Value>) -> Self {
        Self {
            documents: Arc::new(
                documents
                    .iter()
                    .map(|(name, value)| (format!("{SCHEMA_BASE_URI}{name}"), value.clone()))
                    .collect(),
            ),
        }
    }
}

impl Retrieve for EmbeddedSchemaRetriever {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.documents.get(uri.as_str()).cloned().ok_or_else(|| {
            Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!("embedded OCI schema not found: {uri}"),
            )) as Box<dyn std::error::Error + Send + Sync>
        })
    }
}

fn collect_inventory(
    schema: &str,
    value: &Value,
    pointer: &str,
    inventory: &mut Vec<OciSchemaInventoryItem>,
) {
    match value {
        Value::Object(object) => {
            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                for name in properties.keys() {
                    inventory.push(OciSchemaInventoryItem {
                        schema: schema.to_string(),
                        pointer: format!("{pointer}/properties/{}", escape_pointer(name)),
                        kind: OciSchemaInventoryKind::Property,
                        value: name.clone(),
                    });
                }
            }
            if let Some(values) = object.get("enum").and_then(Value::as_array) {
                for (index, item) in values.iter().enumerate() {
                    inventory.push(OciSchemaInventoryItem {
                        schema: schema.to_string(),
                        pointer: format!("{pointer}/enum/{index}"),
                        kind: OciSchemaInventoryKind::EnumValue,
                        value: serde_json::to_string(item)
                            .unwrap_or_else(|_| "<unserializable>".to_string()),
                    });
                }
            }
            for (name, child) in object {
                collect_inventory(
                    schema,
                    child,
                    &format!("{pointer}/{}", escape_pointer(name)),
                    inventory,
                );
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                collect_inventory(schema, child, &format!("{pointer}/{index}"), inventory);
            }
        }
        _ => {}
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use oci_spec::runtime::{Features, State};
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::{
        OciSchemaCoverageManifest, OciSchemaDocument, OciSchemaEvidenceManifest,
        OciSchemaInventoryKind, OciSchemaValidator,
    };
    use crate::ErrorCode;

    #[test]
    fn validator_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OciSchemaValidator>();
    }

    #[test]
    fn validates_official_minimal_documents() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &json!({"ociVersion": "1.3.0"}),
            )
            .expect("minimal config must pass");
        validator
            .validate(
                OciSchemaDocument::State,
                &json!({
                    "ociVersion": "1.3.0",
                    "id": "example",
                    "status": "created",
                    "bundle": "/bundle"
                }),
            )
            .expect("minimal state must pass");
        validator
            .validate(
                OciSchemaDocument::Features,
                &json!({
                    "ociVersionMin": "1.0.0",
                    "ociVersionMax": "1.3.0"
                }),
            )
            .expect("minimal features must pass");
    }

    #[test]
    fn validates_annotation_contracts_for_configuration_and_features() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");

        for annotations in [
            json!({}),
            json!({
                "com.example.empty": "",
                "com.example.structured": r#"{"nested":true}"#,
                "com.example.unstructured": "plain text"
            }),
        ] {
            validator
                .validate(
                    OciSchemaDocument::Configuration,
                    &json!({"ociVersion": "1.3.0", "annotations": annotations}),
                )
                .expect("configuration annotations must accept string metadata");
        }
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &json!({"ociVersion": "1.3.0"}),
            )
            .expect("configuration annotations may be absent");

        for invalid in [
            json!({"ociVersion": "1.3.0", "annotations": []}),
            json!({"ociVersion": "1.3.0", "annotations": {"com.example.count": 2}}),
        ] {
            validator
                .validate(OciSchemaDocument::Configuration, &invalid)
                .expect_err("configuration annotations must be a string map");
        }

        let feature_base = || {
            json!({
                "ociVersionMin": "1.0.0",
                "ociVersionMax": "1.3.0"
            })
        };
        validator
            .validate(OciSchemaDocument::Features, &feature_base())
            .expect("feature annotations may be absent");
        for annotations in [
            json!({}),
            json!({
                "dev.a3s.runtime.empty": "",
                "dev.a3s.runtime.structured": r#"{"lifecycle":"durable"}"#,
                "dev.a3s.runtime.unstructured": "probe-only"
            }),
        ] {
            let mut features = feature_base();
            features["annotations"] = annotations;
            validator
                .validate(OciSchemaDocument::Features, &features)
                .expect("feature annotations must accept string metadata");
        }
        for annotations in [json!([]), json!({"dev.a3s.runtime.level": 2})] {
            let mut features = feature_base();
            features["annotations"] = annotations;
            validator
                .validate(OciSchemaDocument::Features, &features)
                .expect_err("feature annotations must be a string map");
        }
    }

    #[test]
    fn requires_block_io_device_identity() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        for field in [
            "weightDevice",
            "throttleReadBpsDevice",
            "throttleWriteBpsDevice",
            "throttleReadIOPSDevice",
            "throttleWriteIOPSDevice",
        ] {
            for missing in ["major", "minor"] {
                let mut entry = json!({"major": 8, "minor": 0});
                if field == "weightDevice" {
                    entry["weight"] = json!(100);
                } else {
                    entry["rate"] = json!(1);
                }
                entry.as_object_mut().expect("device entry").remove(missing);
                validator
                    .validate(
                        OciSchemaDocument::Configuration,
                        &json!({
                            "ociVersion": "1.3.0",
                            "linux": {
                                "resources": {
                                    "blockIO": {(field): [entry]}
                                }
                            }
                        }),
                    )
                    .expect_err("block I/O device entries require major and minor numbers");
            }
        }
    }

    #[test]
    fn validates_linux_device_schema_shapes() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &json!({
                    "ociVersion": "1.3.0",
                    "linux": {
                        "devices": [
                            {"type": "c", "path": "/dev/null", "major": 1, "minor": 3},
                            {"type": "u", "path": "/run/a3s/char", "major": 10, "minor": 229},
                            {"type": "b", "path": "/storage/block", "major": 8, "minor": 0},
                            {
                                "type": "p",
                                "path": "/run/a3s/fifo",
                                "fileMode": 416,
                                "uid": 1,
                                "gid": 2
                            }
                        ],
                        "resources": {
                            "devices": [
                                {"allow": false},
                                {"allow": true, "type": "a", "access": ""},
                                {
                                    "allow": true,
                                    "type": "c",
                                    "major": 1,
                                    "minor": 3,
                                    "access": "rwm"
                                },
                                {"allow": false, "type": "b", "major": 8}
                            ]
                        }
                    }
                }),
            )
            .expect("all OCI Linux device types and optional fields are schema-valid");
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &json!({
                    "ociVersion": "1.3.0",
                    "linux": {"devices": [], "resources": {"devices": []}}
                }),
            )
            .expect("both Linux device arrays are optional and may be empty");

        for invalid_linux in [
            json!({"devices": [{"path": "/dev/null", "major": 1, "minor": 3}]}),
            json!({"devices": [{"type": "c", "major": 1, "minor": 3}]}),
            json!({"devices": [{"type": "a", "path": "/dev/wildcard"}]}),
            json!({"resources": {"devices": [{"type": "c", "access": "r"}]}}),
        ] {
            validator
                .validate(
                    OciSchemaDocument::Configuration,
                    &json!({"ociVersion": "1.3.0", "linux": invalid_linux}),
                )
                .expect_err("required device fields and node types must follow the OCI schema");
        }
    }

    #[test]
    fn validates_complete_vm_schema_shapes() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &json!({
                    "ociVersion": "1.3.0",
                    "vm": {
                        "hypervisor": {
                            "path": "/runtime/a3s-vmm",
                            "parameters": ["--machine", "a3s"]
                        },
                        "kernel": {
                            "path": "/runtime/vmlinux",
                            "parameters": ["console=hvc0"],
                            "initrd": "/runtime/initrd.img"
                        },
                        "image": {
                            "path": "/runtime/root.vmdk",
                            "format": "vmdk"
                        },
                        "hwConfig": {
                            "deviceTree": "/runtime/a3s.dtb",
                            "vcpus": 2,
                            "memory": 536870912,
                            "dtdevs": ["/soc/virtio@1000"],
                            "iomems": [
                                {"firstMFN": 12288, "nrMFNs": 1},
                                {"firstGFN": 12544, "firstMFN": 33024, "nrMFNs": 2}
                            ],
                            "irqs": [11, 22]
                        }
                    }
                }),
            )
            .expect("all OCI VM fields and optional forms are schema-valid");
        validator
            .validate(
                OciSchemaDocument::Configuration,
                &json!({
                    "ociVersion": "1.3.0",
                    "vm": {"kernel": {"path": "/runtime/vmlinux"}}
                }),
            )
            .expect("optional OCI VM fields may be absent");

        for format in ["raw", "qcow2", "vdi", "vmdk", "vhd"] {
            validator
                .validate(
                    OciSchemaDocument::Configuration,
                    &json!({
                        "ociVersion": "1.3.0",
                        "vm": {
                            "kernel": {"path": "/runtime/vmlinux"},
                            "image": {"path": "/runtime/root.img", "format": format}
                        }
                    }),
                )
                .unwrap_or_else(|error| panic!("OCI VM image format {format} is valid: {error}"));
        }

        for invalid_vm in [
            json!({}),
            json!({"kernel": {}}),
            json!({"kernel": {"path": "/runtime/vmlinux"}, "hypervisor": {}}),
            json!({
                "kernel": {"path": "/runtime/vmlinux"},
                "image": {"path": "/runtime/root.img"}
            }),
            json!({
                "kernel": {"path": "/runtime/vmlinux"},
                "image": {"path": "/runtime/root.img", "format": "iso"}
            }),
            json!({
                "kernel": {"path": "/runtime/vmlinux"},
                "hwConfig": {"iomems": [{"nrMFNs": 1}]}
            }),
            json!({
                "kernel": {"path": "/runtime/vmlinux"},
                "hwConfig": {"iomems": [{"firstMFN": 12288}]}
            }),
            json!({
                "kernel": {"path": "/runtime/vmlinux"},
                "hwConfig": {"vcpus": -1}
            }),
            json!({
                "kernel": {"path": "/runtime/vmlinux"},
                "hwConfig": {"memory": "512MiB", "dtdevs": [1], "irqs": ["11"]}
            }),
        ] {
            validator
                .validate(
                    OciSchemaDocument::Configuration,
                    &json!({"ociVersion": "1.3.0", "vm": invalid_vm}),
                )
                .expect_err("required OCI VM fields and types must follow the pinned schema");
        }
    }

    #[test]
    fn accepts_runtime_spec_image_annotation_keys() {
        OciSchemaValidator::new()
            .expect("compile pinned schemas")
            .validate(
                OciSchemaDocument::Configuration,
                &json!({
                    "ociVersion": "1.3.0",
                    "annotations": {
                        "org.opencontainers.image.os": "linux",
                        "org.opencontainers.image.os.version": "6.8.0",
                        "org.opencontainers.image.os.features": "win32k",
                        "org.opencontainers.image.architecture": "arm64",
                        "org.opencontainers.image.variant": "v8",
                        "org.opencontainers.image.author": "A3S Lab <dev@a3s.dev>",
                        "org.opencontainers.image.created": "2026-08-17T10:11:12Z",
                        "org.opencontainers.image.stopSignal": "SIGTERM"
                    }
                }),
            )
            .expect("Runtime Specification image annotation keys may be used");
    }

    #[test]
    fn reports_schema_paths_without_network_resolution() {
        let report = OciSchemaValidator::new()
            .expect("compile pinned schemas")
            .inspect(OciSchemaDocument::Configuration, &json!({"ociVersion": 13}))
            .expect("inspect invalid config");

        assert!(!report.valid);
        assert!(!report.truncated);
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].instance_path, "/ociVersion");
        assert!(report.violations[0].schema_path.contains("defs.json"));
    }

    #[test]
    fn invalid_state_returns_stable_sdk_error() {
        let error = OciSchemaValidator::new()
            .expect("compile pinned schemas")
            .validate(
                OciSchemaDocument::State,
                &json!({
                    "ociVersion": "1.3.0",
                    "id": "example",
                    "status": "invalid",
                    "bundle": "/bundle"
                }),
            )
            .expect_err("unknown state must fail");

        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.operation.as_deref(), Some("validate-oci-state"));
        assert!(error.message.contains("/status"));
    }

    #[test]
    fn inventory_contains_v1_3_properties_and_enum_values() {
        let inventory = OciSchemaValidator::new()
            .expect("compile pinned schemas")
            .inventory()
            .expect("inventory embedded schemas");

        assert!(inventory.iter().any(|item| {
            item.kind == OciSchemaInventoryKind::Property
                && item.value == "enableMonitoring"
                && item.schema == "config-linux.json"
        }));
        assert!(inventory.iter().any(|item| {
            item.kind == OciSchemaInventoryKind::EnumValue
                && item.value == "\"running\""
                && item.schema == "state-schema.json"
        }));
    }

    #[test]
    fn checked_in_coverage_manifest_matches_reviewed_evidence() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        let evidence: OciSchemaEvidenceManifest = serde_json::from_str(include_str!(
            "../../../conformance/oci-1.3.0-schema-evidence.json"
        ))
        .expect("decode checked-in schema evidence");
        let expected = validator
            .coverage_with_evidence(&evidence)
            .expect("generate coverage from reviewed evidence");
        let actual: OciSchemaCoverageManifest = serde_json::from_str(include_str!(
            "../../../conformance/oci-1.3.0-schema-coverage.json"
        ))
        .expect("decode checked-in coverage manifest");

        assert_eq!(actual.schema_version, "a3s.oci.schema-coverage.v2");
        assert_eq!(actual.oci_runtime_spec, "1.3.0");
        assert_eq!(
            actual.upstream_commit,
            "92249139eea7161e13745abd4cb6d0ea02a3227a"
        );
        assert_eq!(actual, expected, "coverage lock is stale");
        validator
            .verify_coverage(&actual)
            .expect("checked-in coverage must pass strict verification");
    }

    #[test]
    fn typed_sdk_models_preserve_upstream_state_and_features_fixtures() {
        assert_strict_typed_round_trip::<State>(include_str!(
            "../../../vendor/runtime-spec/v1.3.0/schema/test/state/good/spec-example.json"
        ));
        assert_strict_typed_round_trip::<Features>(include_str!(
            "../../../vendor/runtime-spec/v1.3.0/schema/test/features/good/runc.json"
        ));
    }

    fn assert_strict_typed_round_trip<T>(source: &str)
    where
        T: DeserializeOwned + serde::Serialize,
    {
        let original: serde_json::Value =
            serde_json::from_str(source).expect("upstream fixture must be JSON");
        let mut deserializer = serde_json::Deserializer::from_str(source);
        let mut unknown = Vec::new();
        let decoded: T = serde_ignored::deserialize(&mut deserializer, |path| {
            unknown.push(path.to_string());
        })
        .expect("upstream fixture must decode");
        assert!(unknown.is_empty(), "typed model missed fields: {unknown:?}");
        let encoded = serde_json::to_value(decoded).expect("encode typed OCI document");
        assert_explicit_fields_preserved(&original, &encoded, "");
    }

    fn assert_explicit_fields_preserved(
        original: &serde_json::Value,
        encoded: &serde_json::Value,
        path: &str,
    ) {
        match original {
            serde_json::Value::Object(object) => {
                let encoded = encoded
                    .as_object()
                    .unwrap_or_else(|| panic!("{path} changed from an object"));
                for (key, value) in object {
                    let child_path = format!("{path}/{key}");
                    let encoded_value = encoded
                        .get(key)
                        .unwrap_or_else(|| panic!("{child_path} disappeared during round trip"));
                    assert_explicit_fields_preserved(value, encoded_value, &child_path);
                }
            }
            serde_json::Value::Array(array) => {
                let encoded = encoded
                    .as_array()
                    .unwrap_or_else(|| panic!("{path} changed from an array"));
                assert_eq!(encoded.len(), array.len(), "{path} changed array length");
                for (index, value) in array.iter().enumerate() {
                    assert_explicit_fields_preserved(
                        value,
                        &encoded[index],
                        &format!("{path}/{index}"),
                    );
                }
            }
            value => assert_eq!(encoded, value, "{path} changed value"),
        }
    }
}
