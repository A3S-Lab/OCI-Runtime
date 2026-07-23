use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock};

use jsonschema::{Draft, PatternOptions, Retrieve, Uri, Validator};
use oci_spec::runtime::{Features, Spec, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, ErrorCode, Result};

const SCHEMA_BASE_URI: &str = "https://schema.a3s.dev/oci/runtime-spec/v1.3.0/";
const MAX_REPORTED_VIOLATIONS: usize = 64;

const EMBEDDED_SCHEMAS: &[(&str, &str)] = &[
    (
        "config-freebsd.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-freebsd.json"),
    ),
    (
        "config-linux.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-linux.json"),
    ),
    (
        "config-schema.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-schema.json"),
    ),
    (
        "config-solaris.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-solaris.json"),
    ),
    (
        "config-vm.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-vm.json"),
    ),
    (
        "config-windows.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-windows.json"),
    ),
    (
        "config-zos.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/config-zos.json"),
    ),
    (
        "defs-freebsd.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/defs-freebsd.json"),
    ),
    (
        "defs-linux.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/defs-linux.json"),
    ),
    (
        "defs-vm.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/defs-vm.json"),
    ),
    (
        "defs-windows.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/defs-windows.json"),
    ),
    (
        "defs-zos.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/defs-zos.json"),
    ),
    (
        "defs.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/defs.json"),
    ),
    (
        "features-linux.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/features-linux.json"),
    ),
    (
        "features-schema.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/features-schema.json"),
    ),
    (
        "state-schema.json",
        include_str!("../../../vendor/runtime-spec/v1.3.0/schema/state-schema.json"),
    ),
];

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

/// Current implementation disposition for one pinned schema inventory item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSchemaDisposition {
    SchemaValidatedPendingEnforcement,
    SchemaValidatedRejectedInapplicablePlatform,
}

/// Classified property or enum value in the checked-in OCI coverage manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciSchemaCoverageItem {
    #[serde(flatten)]
    pub inventory: OciSchemaInventoryItem,
    pub disposition: OciSchemaDisposition,
}

/// Machine-readable coverage lock for the pinned OCI schema release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSchemaCoverageManifest {
    pub schema_version: String,
    pub oci_runtime_spec: String,
    pub upstream_commit: String,
    pub items: Vec<OciSchemaCoverageItem>,
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

    /// Build the review baseline used to update the checked-in coverage lock.
    ///
    /// Unsupported native workload-platform schemas are classified as
    /// rejected. Every other item remains pending enforcement until a later
    /// reviewed manifest update promotes it.
    pub fn coverage_baseline(self) -> Result<OciSchemaCoverageManifest> {
        let items = self
            .inventory()?
            .into_iter()
            .map(|inventory| OciSchemaCoverageItem {
                disposition: disposition_for(&inventory),
                inventory,
            })
            .collect();
        Ok(OciSchemaCoverageManifest {
            schema_version: "a3s.oci.schema-coverage.v1".to_string(),
            oci_runtime_spec: "1.3.0".to_string(),
            upstream_commit: "92249139eea7161e13745abd4cb6d0ea02a3227a".to_string(),
            items,
        })
    }
}

fn disposition_for(item: &OciSchemaInventoryItem) -> OciSchemaDisposition {
    const INAPPLICABLE_SCHEMAS: &[&str] = &[
        "config-freebsd.json",
        "config-solaris.json",
        "config-windows.json",
        "config-zos.json",
        "defs-freebsd.json",
        "defs-windows.json",
        "defs-zos.json",
    ];
    const INAPPLICABLE_ROOT_PROPERTIES: &[&str] = &["freebsd", "solaris", "windows", "zos"];

    if INAPPLICABLE_SCHEMAS.contains(&item.schema.as_str())
        || (item.schema == "config-schema.json"
            && item.kind == OciSchemaInventoryKind::Property
            && item.pointer.starts_with("/properties/")
            && !item.pointer["/properties/".len()..].contains('/')
            && INAPPLICABLE_ROOT_PROPERTIES.contains(&item.value.as_str()))
    {
        OciSchemaDisposition::SchemaValidatedRejectedInapplicablePlatform
    } else {
        OciSchemaDisposition::SchemaValidatedPendingEnforcement
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
    use std::collections::BTreeSet;

    use oci_spec::runtime::{Features, State};
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::{
        OciSchemaCoverageManifest, OciSchemaDocument, OciSchemaInventoryKind, OciSchemaValidator,
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
    fn matches_upstream_v1_3_fixture_expectations() {
        const GOOD_CONFIGS: &[&str] = &[
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/freebsd-example.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/freebsd-minimal.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/linux-netdevice.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/linux-rdma.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/minimal-for-start.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/minimal.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/spec-example.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/zos-example.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/good/zos-minimal.json"
            ),
        ];
        const BAD_CONFIGS: &[&str] = &[
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/bad/freebsd-vnet-disable.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/bad/linux-hugepage.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/bad/linux-netdevice.json"
            ),
            include_str!(
                "../../../vendor/runtime-spec/v1.3.0/schema/test/config/bad/linux-rdma.json"
            ),
        ];

        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        for source in GOOD_CONFIGS {
            let value: serde_json::Value =
                serde_json::from_str(source).expect("upstream good fixture must be JSON");
            validator
                .validate(OciSchemaDocument::Configuration, &value)
                .expect("upstream good fixture must pass");
        }
        for source in BAD_CONFIGS {
            let value: serde_json::Value =
                serde_json::from_str(source).expect("upstream bad fixture must be JSON");
            assert!(
                validator
                    .validate(OciSchemaDocument::Configuration, &value)
                    .is_err(),
                "upstream bad fixture unexpectedly passed: {value}"
            );
        }

        let good_state: serde_json::Value = serde_json::from_str(include_str!(
            "../../../vendor/runtime-spec/v1.3.0/schema/test/state/good/spec-example.json"
        ))
        .expect("upstream state fixture must be JSON");
        validator
            .validate(OciSchemaDocument::State, &good_state)
            .expect("upstream state fixture must pass");

        let good_features: serde_json::Value = serde_json::from_str(include_str!(
            "../../../vendor/runtime-spec/v1.3.0/schema/test/features/good/runc.json"
        ))
        .expect("upstream features fixture must be JSON");
        validator
            .validate(OciSchemaDocument::Features, &good_features)
            .expect("upstream features fixture must pass");
    }

    #[test]
    fn checked_in_coverage_manifest_classifies_every_inventory_item() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        let expected = validator.inventory().expect("inventory pinned schemas");
        let manifest: OciSchemaCoverageManifest = serde_json::from_str(include_str!(
            "../../../conformance/oci-1.3.0-schema-coverage.json"
        ))
        .expect("decode checked-in coverage manifest");

        assert_eq!(manifest.schema_version, "a3s.oci.schema-coverage.v1");
        assert_eq!(manifest.oci_runtime_spec, "1.3.0");
        assert_eq!(
            manifest.upstream_commit,
            "92249139eea7161e13745abd4cb6d0ea02a3227a"
        );

        let actual = manifest
            .items
            .iter()
            .map(|item| item.inventory.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "coverage lock is stale");
        assert_eq!(
            actual.iter().collect::<BTreeSet<_>>().len(),
            actual.len(),
            "coverage lock contains duplicate entries"
        );
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
