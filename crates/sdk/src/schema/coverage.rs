use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{OciSchemaInventoryItem, OciSchemaInventoryKind, OciSchemaValidator};
use crate::{Error, ErrorCode, Result};

const OCI_RUNTIME_SPEC_VERSION: &str = "1.3.0";
const OCI_RUNTIME_SPEC_COMMIT: &str = "92249139eea7161e13745abd4cb6d0ea02a3227a";
const SCHEMA_COVERAGE_VERSION: &str = "a3s.oci.schema-coverage.v2";
const SCHEMA_EVIDENCE_VERSION: &str = "a3s.oci.schema-evidence.v1";

/// Current implementation disposition for one pinned schema inventory item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSchemaDisposition {
    /// The schema shape is known, but its runtime behavior still needs review.
    PendingReview,
    /// The native workload platform is rejected before runtime mutation.
    RejectedInapplicablePlatform,
    /// The field or value is known and rejected before runtime mutation.
    RejectedUnsupported,
    /// Static schema or semantic validation owns the complete behavior.
    Validated,
    /// Runtime or driver behavior is implemented and has direct evidence.
    Enforced,
    /// All release-level conformance gates have retained evidence.
    Conformant,
}

/// Classified property or enum value in the checked-in OCI support manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSchemaCoverageItem {
    /// Stable identity derived from the complete inventory tuple.
    pub id: String,
    #[serde(flatten)]
    pub inventory: OciSchemaInventoryItem,
    pub disposition: OciSchemaDisposition,
    pub owner: String,
    pub rule_ids: Vec<String>,
    pub test_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Machine-readable support lock for the pinned OCI schema release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSchemaCoverageManifest {
    pub schema_version: String,
    pub oci_runtime_spec: String,
    pub upstream_commit: String,
    pub items: Vec<OciSchemaCoverageItem>,
}

/// Reviewed evidence used to generate the exact schema support manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSchemaEvidenceManifest {
    pub schema_version: String,
    pub oci_runtime_spec: String,
    pub upstream_commit: String,
    pub bindings: Vec<OciSchemaEvidenceBinding>,
}

/// One evidence mapping shared by equivalent schema inventory items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSchemaEvidenceBinding {
    pub description: String,
    pub item_ids: Vec<String>,
    pub disposition: OciSchemaDisposition,
    pub owner: String,
    pub rule_ids: Vec<String>,
    pub test_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

impl OciSchemaValidator {
    /// Build the review baseline for the pinned schema inventory.
    ///
    /// Unsupported native workload platforms have a generated fail-closed
    /// disposition. Every applicable item stays pending until reviewed
    /// evidence binds it to validation, enforcement, or explicit rejection.
    pub fn coverage_baseline(self) -> Result<OciSchemaCoverageManifest> {
        let items = self.inventory()?.into_iter().map(baseline_item).collect();
        Ok(OciSchemaCoverageManifest {
            schema_version: SCHEMA_COVERAGE_VERSION.to_string(),
            oci_runtime_spec: OCI_RUNTIME_SPEC_VERSION.to_string(),
            upstream_commit: OCI_RUNTIME_SPEC_COMMIT.to_string(),
            items,
        })
    }

    /// Apply reviewed evidence to a fresh inventory and require full coverage.
    pub fn coverage_with_evidence(
        self,
        evidence: &OciSchemaEvidenceManifest,
    ) -> Result<OciSchemaCoverageManifest> {
        verify_evidence_metadata(evidence)?;

        let mut manifest = self.coverage_baseline()?;
        let indexes = manifest
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| (item.id.clone(), index))
            .collect::<BTreeMap<_, _>>();
        let mut promoted = BTreeSet::new();

        for binding in &evidence.bindings {
            verify_evidence_binding(binding)?;
            for item_id in &binding.item_ids {
                if !promoted.insert(item_id.as_str()) {
                    return Err(coverage_error(format!(
                        "schema item {item_id} has more than one evidence binding"
                    )));
                }
                let Some(index) = indexes.get(item_id).copied() else {
                    return Err(coverage_error(format!(
                        "schema evidence references unknown item {item_id}"
                    )));
                };
                let item = &mut manifest.items[index];
                if item.disposition != OciSchemaDisposition::PendingReview {
                    return Err(coverage_error(format!(
                        "schema evidence cannot replace generated {:?} disposition for {item_id}",
                        item.disposition
                    )));
                }
                item.disposition = binding.disposition;
                item.owner.clone_from(&binding.owner);
                item.rule_ids.clone_from(&binding.rule_ids);
                item.test_ids.clone_from(&binding.test_ids);
                item.rationale.clone_from(&binding.rationale);
            }
        }

        self.verify_coverage(&manifest)?;
        Ok(manifest)
    }

    /// Verify that the support manifest exactly covers the pinned inventory.
    pub fn verify_coverage(self, manifest: &OciSchemaCoverageManifest) -> Result<()> {
        if manifest.schema_version != SCHEMA_COVERAGE_VERSION
            || manifest.oci_runtime_spec != OCI_RUNTIME_SPEC_VERSION
            || manifest.upstream_commit != OCI_RUNTIME_SPEC_COMMIT
        {
            return Err(coverage_error(
                "schema coverage metadata does not match the pinned OCI release",
            ));
        }

        let expected = self
            .inventory()?
            .into_iter()
            .map(|inventory| (inventory_id(&inventory), inventory))
            .collect::<BTreeMap<_, _>>();
        let mut actual = BTreeMap::new();
        for item in &manifest.items {
            if actual.insert(item.id.as_str(), item).is_some() {
                return Err(coverage_error(format!(
                    "duplicate schema coverage ID {}",
                    item.id
                )));
            }
        }
        if actual.len() != expected.len() {
            return Err(coverage_error(format!(
                "schema coverage has {} entries; pinned schemas require {}",
                actual.len(),
                expected.len()
            )));
        }
        for (id, inventory) in expected {
            let Some(item) = actual.get(id.as_str()) else {
                return Err(coverage_error(format!("schema coverage is missing {id}")));
            };
            if item.inventory != inventory {
                return Err(coverage_error(format!(
                    "schema coverage metadata is stale for {id}"
                )));
            }
            verify_coverage_item(item)?;
        }
        crate::conformance::verify_conformance_rule_references(
            manifest
                .items
                .iter()
                .map(|item| (item.owner.as_str(), item.rule_ids.as_slice())),
        )
        .map_err(coverage_error)?;
        Ok(())
    }
}

fn baseline_item(inventory: OciSchemaInventoryItem) -> OciSchemaCoverageItem {
    let id = inventory_id(&inventory);
    if is_inapplicable_platform_item(&inventory) {
        return OciSchemaCoverageItem {
            id,
            inventory,
            disposition: OciSchemaDisposition::RejectedInapplicablePlatform,
            owner: "sdk-semantic-validation".to_string(),
            rule_ids: vec!["oci.platform.linux-only".to_string()],
            test_ids: vec![
                "semantic::tests::rejects_native_non_linux_workload_sections_as_unsupported"
                    .to_string(),
            ],
            rationale: Some(
                "A3S executes Linux workloads and rejects native non-Linux platform sections before mutation."
                    .to_string(),
            ),
        };
    }

    let owner = match inventory.schema.as_str() {
        "state-schema.json" => "runtime-lifecycle",
        "features-schema.json" | "features-linux.json" => "runtime-feature-report",
        "config-linux.json" | "defs-linux.json" => "linux-executor",
        "config-vm.json" | "defs-vm.json" => "vm-driver",
        _ => "sdk-semantic-and-runtime",
    };
    OciSchemaCoverageItem {
        id,
        inventory,
        disposition: OciSchemaDisposition::PendingReview,
        owner: owner.to_string(),
        rule_ids: Vec::new(),
        test_ids: Vec::new(),
        rationale: None,
    }
}

fn is_inapplicable_platform_item(item: &OciSchemaInventoryItem) -> bool {
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

    INAPPLICABLE_SCHEMAS.contains(&item.schema.as_str())
        || (item.schema == "config-schema.json"
            && item.kind == OciSchemaInventoryKind::Property
            && item.pointer.starts_with("/properties/")
            && !item.pointer["/properties/".len()..].contains('/')
            && INAPPLICABLE_ROOT_PROPERTIES.contains(&item.value.as_str()))
}

fn inventory_id(item: &OciSchemaInventoryItem) -> String {
    let kind = match item.kind {
        OciSchemaInventoryKind::Property => "property",
        OciSchemaInventoryKind::EnumValue => "enum-value",
    };
    let identity = format!(
        "{OCI_RUNTIME_SPEC_VERSION}\0{}\0{}\0{kind}\0{}",
        item.schema, item.pointer, item.value
    );
    let digest = Sha256::digest(identity.as_bytes());
    format!("sha256:{digest:x}")
}

fn verify_evidence_metadata(evidence: &OciSchemaEvidenceManifest) -> Result<()> {
    if evidence.schema_version != SCHEMA_EVIDENCE_VERSION
        || evidence.oci_runtime_spec != OCI_RUNTIME_SPEC_VERSION
        || evidence.upstream_commit != OCI_RUNTIME_SPEC_COMMIT
    {
        return Err(coverage_error(
            "schema evidence metadata does not match the pinned OCI release",
        ));
    }
    Ok(())
}

fn verify_evidence_binding(binding: &OciSchemaEvidenceBinding) -> Result<()> {
    if binding.description.trim().is_empty() || binding.item_ids.is_empty() {
        return Err(coverage_error(
            "schema evidence requires a description and at least one item ID",
        ));
    }
    if !matches!(
        binding.disposition,
        OciSchemaDisposition::RejectedUnsupported
            | OciSchemaDisposition::Validated
            | OciSchemaDisposition::Enforced
            | OciSchemaDisposition::Conformant
    ) {
        return Err(coverage_error(
            "reviewed schema evidence has an invalid promoted disposition",
        ));
    }
    if binding.owner.trim().is_empty() || binding.rule_ids.is_empty() || binding.test_ids.is_empty()
    {
        return Err(coverage_error(
            "schema evidence requires an owner, rule IDs, and test IDs",
        ));
    }
    if binding.disposition == OciSchemaDisposition::RejectedUnsupported
        && binding
            .rationale
            .as_deref()
            .is_none_or(|rationale| rationale.trim().is_empty())
    {
        return Err(coverage_error(
            "rejected schema evidence requires a rationale",
        ));
    }
    let mut unique = BTreeSet::new();
    if binding
        .item_ids
        .iter()
        .any(|item_id| item_id.trim().is_empty() || !unique.insert(item_id))
    {
        return Err(coverage_error(
            "schema evidence contains an empty or duplicate item ID",
        ));
    }
    Ok(())
}

fn verify_coverage_item(item: &OciSchemaCoverageItem) -> Result<()> {
    if item.id != inventory_id(&item.inventory) {
        return Err(coverage_error(format!(
            "schema coverage ID does not match its inventory tuple: {}",
            item.id
        )));
    }
    if item.disposition == OciSchemaDisposition::PendingReview {
        return Err(coverage_error(format!(
            "schema coverage {} remains pending review",
            item.id
        )));
    }
    if item.owner.trim().is_empty() || item.rule_ids.is_empty() || item.test_ids.is_empty() {
        return Err(coverage_error(format!(
            "schema coverage {} has no complete owner, rule, and test evidence",
            item.id
        )));
    }
    if matches!(
        item.disposition,
        OciSchemaDisposition::RejectedInapplicablePlatform
            | OciSchemaDisposition::RejectedUnsupported
    ) && item
        .rationale
        .as_deref()
        .is_none_or(|rationale| rationale.trim().is_empty())
    {
        return Err(coverage_error(format!(
            "rejected schema coverage {} has no rationale",
            item.id
        )));
    }
    let mut unique_rules = BTreeSet::new();
    if item
        .rule_ids
        .iter()
        .any(|rule| rule.trim().is_empty() || !unique_rules.insert(rule))
    {
        return Err(coverage_error(format!(
            "schema coverage {} has an empty or duplicate rule ID",
            item.id
        )));
    }
    let mut unique_tests = BTreeSet::new();
    if item
        .test_ids
        .iter()
        .any(|test| test.trim().is_empty() || !unique_tests.insert(test))
    {
        return Err(coverage_error(format!(
            "schema coverage {} has an empty or duplicate test ID",
            item.id
        )));
    }
    Ok(())
}

fn coverage_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("verify-oci-schema-coverage")
}

#[cfg(test)]
mod tests {
    use super::{
        OciSchemaDisposition, OciSchemaEvidenceBinding, OciSchemaEvidenceManifest,
        OciSchemaValidator, OCI_RUNTIME_SPEC_COMMIT, OCI_RUNTIME_SPEC_VERSION,
        SCHEMA_EVIDENCE_VERSION,
    };
    use crate::ErrorCode;

    fn evidence(bindings: Vec<OciSchemaEvidenceBinding>) -> OciSchemaEvidenceManifest {
        OciSchemaEvidenceManifest {
            schema_version: SCHEMA_EVIDENCE_VERSION.to_string(),
            oci_runtime_spec: OCI_RUNTIME_SPEC_VERSION.to_string(),
            upstream_commit: OCI_RUNTIME_SPEC_COMMIT.to_string(),
            bindings,
        }
    }

    fn binding(item_ids: Vec<String>) -> OciSchemaEvidenceBinding {
        OciSchemaEvidenceBinding {
            description: "reviewed schema behavior".to_string(),
            item_ids,
            disposition: OciSchemaDisposition::Validated,
            owner: "sdk-semantic-validation".to_string(),
            rule_ids: vec!["oci.common.root.path.non-empty".to_string()],
            test_ids: vec!["semantic::tests::requires_a_root_for_linux_workloads".to_string()],
            rationale: None,
        }
    }

    fn applicable_item_id() -> String {
        OciSchemaValidator::new()
            .expect("compile pinned schemas")
            .coverage_baseline()
            .expect("build coverage baseline")
            .items
            .into_iter()
            .find(|item| item.disposition == OciSchemaDisposition::PendingReview)
            .expect("applicable schema inventory item")
            .id
    }

    fn checked_in_manifest() -> super::OciSchemaCoverageManifest {
        serde_json::from_str(include_str!(
            "../../../../conformance/oci-1.3.0-schema-coverage.json"
        ))
        .expect("decode checked-in schema coverage")
    }

    fn assert_invalid(result: crate::Result<impl std::fmt::Debug>, message: &str) {
        let error = result.expect_err("invalid schema coverage must fail closed");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(
            error.operation.as_deref(),
            Some("verify-oci-schema-coverage")
        );
        assert!(error.message.contains(message), "{error}");
    }

    #[test]
    fn evidence_metadata_is_pinned_to_the_schema_release() {
        let mut manifest = evidence(Vec::new());
        manifest.upstream_commit = "stale".to_string();

        assert_invalid(
            OciSchemaValidator::new()
                .expect("compile pinned schemas")
                .coverage_with_evidence(&manifest),
            "metadata does not match",
        );
    }

    #[test]
    fn evidence_rejects_unknown_duplicate_and_generated_item_bindings() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![binding(vec![
                "sha256:unknown".to_string()
            ])])),
            "unknown item",
        );

        let item_id = applicable_item_id();
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![
                binding(vec![item_id.clone()]),
                binding(vec![item_id]),
            ])),
            "more than one evidence binding",
        );

        let generated = validator
            .coverage_baseline()
            .expect("build coverage baseline")
            .items
            .into_iter()
            .find(|item| item.disposition == OciSchemaDisposition::RejectedInapplicablePlatform)
            .expect("generated platform rejection");
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![binding(vec![generated.id])])),
            "cannot replace generated",
        );
    }

    #[test]
    fn evidence_bindings_require_complete_reviewed_support_data() {
        let item_id = applicable_item_id();
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");

        let mut incomplete = binding(vec![item_id.clone()]);
        incomplete.owner.clear();
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![incomplete])),
            "requires an owner, rule IDs, and test IDs",
        );

        let mut pending = binding(vec![item_id.clone()]);
        pending.disposition = OciSchemaDisposition::PendingReview;
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![pending])),
            "invalid promoted disposition",
        );

        let mut rejected = binding(vec![item_id.clone()]);
        rejected.disposition = OciSchemaDisposition::RejectedUnsupported;
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![rejected])),
            "requires a rationale",
        );

        let mut duplicated = binding(vec![item_id.clone(), item_id]);
        duplicated.disposition = OciSchemaDisposition::Enforced;
        assert_invalid(
            validator.coverage_with_evidence(&evidence(vec![duplicated])),
            "empty or duplicate item ID",
        );
    }

    #[test]
    fn coverage_verification_rejects_pending_stale_and_incomplete_items() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");

        let mut pending = checked_in_manifest();
        pending.items[0].disposition = OciSchemaDisposition::PendingReview;
        assert_invalid(
            validator.verify_coverage(&pending),
            "remains pending review",
        );

        let mut stale = checked_in_manifest();
        stale.items[0].inventory.value.push_str("-stale");
        assert_invalid(validator.verify_coverage(&stale), "metadata is stale");

        let mut incomplete = checked_in_manifest();
        incomplete.items[0].test_ids.clear();
        assert_invalid(
            validator.verify_coverage(&incomplete),
            "has no complete owner, rule, and test evidence",
        );
    }

    #[test]
    fn coverage_verification_rejects_duplicate_ids_and_unknown_rules() {
        let validator = OciSchemaValidator::new().expect("compile pinned schemas");

        let mut duplicate = checked_in_manifest();
        let duplicate_id = duplicate.items[0].id.clone();
        duplicate.items[1].id = duplicate_id;
        assert_invalid(
            validator.verify_coverage(&duplicate),
            "duplicate schema coverage ID",
        );

        let mut unknown_rule = checked_in_manifest();
        unknown_rule.items[0].rule_ids = vec!["oci.unknown.rule".to_string()];
        assert_invalid(validator.verify_coverage(&unknown_rule), "unknown rule");
    }

    #[test]
    fn common_configuration_schema_items_have_the_exact_owner_profile() {
        let manifest = checked_in_manifest();
        let items = manifest
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.inventory.schema.as_str(),
                    "config-schema.json" | "defs.json"
                ) && !(item.inventory.schema == "config-schema.json"
                    && item.inventory.pointer == "/properties/vm")
            })
            .collect::<Vec<_>>();

        assert_eq!(items.len(), 79);
        for (disposition, owner, expected) in [
            (OciSchemaDisposition::Enforced, "linux-executor", 68),
            (OciSchemaDisposition::Enforced, "runtime-bundle", 1),
            (
                OciSchemaDisposition::RejectedInapplicablePlatform,
                "sdk-semantic-validation",
                4,
            ),
            (
                OciSchemaDisposition::RejectedUnsupported,
                "sdk-semantic-and-runtime",
                4,
            ),
            (OciSchemaDisposition::Validated, "runtime-bundle", 1),
            (
                OciSchemaDisposition::Validated,
                "sdk-semantic-validation",
                1,
            ),
        ] {
            assert_eq!(
                items
                    .iter()
                    .filter(|item| item.disposition == disposition && item.owner == owner)
                    .count(),
                expected,
                "unexpected {disposition:?} schema-item count for {owner}"
            );
        }
        assert!(items.iter().all(|item| {
            item.disposition != OciSchemaDisposition::PendingReview
                && !item.rule_ids.is_empty()
                && !item.test_ids.is_empty()
                && (!matches!(
                    item.disposition,
                    OciSchemaDisposition::RejectedInapplicablePlatform
                        | OciSchemaDisposition::RejectedUnsupported
                ) || item
                    .rationale
                    .as_deref()
                    .is_some_and(|rationale| !rationale.trim().is_empty()))
        }));
        let annotations = items
            .iter()
            .find(|item| {
                item.inventory.schema == "config-schema.json"
                    && item.inventory.pointer == "/properties/annotations"
            })
            .expect("configuration annotations schema item");
        assert_eq!(
            annotations.test_ids,
            [
                "bundle::tests::loads_v1_3_fields_without_losing_them",
                "executor::plan_tests::preserves_arbitrary_annotation_strings_without_c_string_restrictions",
                "schema::tests::validates_annotation_contracts_for_configuration_and_features",
            ]
        );
    }

    #[test]
    fn linux_configuration_schema_items_have_the_exact_support_profile() {
        let manifest = checked_in_manifest();
        let items = manifest
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.inventory.schema.as_str(),
                    "config-linux.json" | "defs-linux.json"
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(items.len(), 190);
        assert_eq!(
            items
                .iter()
                .filter(|item| {
                    item.disposition == OciSchemaDisposition::Enforced
                        && item.owner == "linux-executor"
                })
                .count(),
            145
        );
        assert_eq!(
            items
                .iter()
                .filter(|item| {
                    item.disposition == OciSchemaDisposition::RejectedUnsupported
                        && item.owner == "linux-executor"
                })
                .count(),
            45
        );
        assert!(items.iter().all(|item| {
            item.disposition != OciSchemaDisposition::PendingReview
                && !item.rule_ids.is_empty()
                && !item.test_ids.is_empty()
                && (item.disposition != OciSchemaDisposition::RejectedUnsupported
                    || item
                        .rationale
                        .as_deref()
                        .is_some_and(|rationale| !rationale.trim().is_empty()))
        }));
    }

    #[test]
    fn vm_schema_items_have_the_exact_fail_closed_profile() {
        const VM_PATH_POINTERS: &[&str] = &[
            "/vm/properties/hypervisor/properties/path",
            "/vm/properties/image/properties/path",
            "/vm/properties/kernel/properties/initrd",
            "/vm/properties/kernel/properties/path",
        ];
        const VM_PARAMETER_POINTERS: &[&str] = &[
            "/vm/properties/hypervisor/properties/parameters",
            "/vm/properties/kernel/properties/parameters",
        ];
        const RATIONALE: &str = "Current A3S drivers use runtime-owned, digest-pinned VM assets and reject every caller-provided vm section before durable reservation or platform mutation.";

        let manifest = checked_in_manifest();
        let vm_items = manifest
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.inventory.schema.as_str(),
                    "config-vm.json" | "defs-vm.json"
                ) || (item.inventory.schema == "config-schema.json"
                    && item.inventory.pointer == "/properties/vm")
            })
            .collect::<Vec<_>>();

        assert_eq!(vm_items.len(), 26);
        assert!(vm_items.iter().all(|item| {
            item.disposition == OciSchemaDisposition::RejectedUnsupported
                && item.owner == "vm-driver"
                && item
                    .rule_ids
                    .iter()
                    .any(|rule| rule == "oci.vm.configuration.runtime-owned")
                && item
                    .test_ids
                    .iter()
                    .any(|test| test == "schema::tests::validates_complete_vm_schema_shapes")
                && item.test_ids.iter().any(|test| {
                    test == "service::tests::rejects_caller_vm_configuration_before_durable_reservation_and_create_dispatch"
                })
                && item.rationale.as_deref() == Some(RATIONALE)
        }));

        let paths = vm_items
            .iter()
            .filter(|item| VM_PATH_POINTERS.contains(&item.inventory.pointer.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(paths.len(), 4);
        assert!(paths.iter().all(|item| {
            item.rule_ids
                == [
                    "oci.vm.configuration.runtime-owned",
                    "oci.common.path.no-nul",
                    "oci.vm.path.absolute",
                ]
                && item.test_ids
                    == [
                        "schema::tests::validates_complete_vm_schema_shapes",
                        "semantic::tests::rejects_nul_in_vm_runtime_paths_and_parameters",
                        "semantic::tests::validates_vm_paths_without_inventing_hardware_minima",
                        "service::tests::rejects_caller_vm_configuration_before_durable_reservation_and_create_dispatch",
                    ]
        }));

        let parameters = vm_items
            .iter()
            .filter(|item| VM_PARAMETER_POINTERS.contains(&item.inventory.pointer.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(parameters.len(), 2);
        assert!(parameters.iter().all(|item| {
            item.rule_ids
                == [
                    "oci.vm.configuration.runtime-owned",
                    "oci.vm.parameter.no-nul",
                ]
                && item.test_ids
                    == [
                        "schema::tests::validates_complete_vm_schema_shapes",
                        "semantic::tests::rejects_nul_in_vm_runtime_paths_and_parameters",
                        "service::tests::rejects_caller_vm_configuration_before_durable_reservation_and_create_dispatch",
                    ]
        }));

        let remaining = vm_items
            .iter()
            .filter(|item| {
                !VM_PATH_POINTERS.contains(&item.inventory.pointer.as_str())
                    && !VM_PARAMETER_POINTERS.contains(&item.inventory.pointer.as_str())
            })
            .collect::<Vec<_>>();
        assert_eq!(remaining.len(), 20);
        assert!(remaining.iter().all(|item| {
            item.rule_ids == ["oci.vm.configuration.runtime-owned"]
                && item.test_ids
                    == [
                        "schema::tests::validates_complete_vm_schema_shapes",
                        "service::tests::rejects_caller_vm_configuration_before_durable_reservation_and_create_dispatch",
                    ]
        }));
    }
}
