use std::collections::BTreeSet;

use super::{
    canonical_text_sha256, keyword_occurrences, OciNormativeCoverageManifest,
    OciNormativeDisposition, OciNormativeEvidenceManifest, OciNormativeInventory,
    OciNormativeKeyword, SPECIFICATION_DOCUMENTS,
};

#[test]
fn inventory_covers_every_pinned_rfc_2119_occurrence() {
    let requirements = OciNormativeInventory::new().requirements();
    assert_eq!(SPECIFICATION_DOCUMENTS.len(), 15);
    assert_eq!(requirements.len(), 764);
    assert_eq!(
        requirements
            .iter()
            .map(|requirement| requirement.id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        requirements.len()
    );
    assert!(requirements.iter().all(|requirement| {
        requirement
            .source
            .contains(requirement.keyword.source_text())
    }));
    assert!(requirements
        .iter()
        .any(|requirement| requirement.keyword == OciNormativeKeyword::MustNot));
    assert!(requirements
        .iter()
        .any(|requirement| requirement.keyword == OciNormativeKeyword::Optional));
}

#[test]
fn checked_in_normative_manifest_matches_the_pinned_corpus() {
    let manifest = checked_in_manifest();
    let evidence = checked_in_evidence();
    let generated = OciNormativeInventory::new()
        .coverage_with_evidence(&evidence)
        .expect("checked-in normative evidence must be complete and current");
    assert_eq!(manifest, generated);
}

#[test]
fn reviewed_external_evidence_requires_a_nonempty_rationale() {
    let mut evidence = checked_in_evidence();
    let binding = evidence
        .bindings
        .iter_mut()
        .find(|binding| binding.disposition == OciNormativeDisposition::ReviewedExternal)
        .expect("reviewed external evidence binding");
    binding.rationale = Some("  ".to_string());

    let error = OciNormativeInventory::new()
        .coverage_with_evidence(&evidence)
        .expect_err("external responsibility cannot be asserted without a rationale");
    assert!(error.message.contains("requires a rationale"));
}

#[test]
fn common_external_requirements_retain_reviewed_boundaries() {
    let manifest = checked_in_manifest();
    let external = manifest
        .items
        .iter()
        .filter(|item| item.disposition == OciNormativeDisposition::ReviewedExternal)
        .collect::<Vec<_>>();

    assert_eq!(external.len(), 14);
    assert!(external.iter().all(|item| {
        item.rationale
            .as_deref()
            .is_some_and(|rationale| !rationale.trim().is_empty())
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
    }));
}

#[test]
fn normative_manifest_has_no_pending_review() {
    let manifest = checked_in_manifest();
    assert_eq!(manifest.items.len(), 764);
    assert_eq!(
        manifest
            .items
            .iter()
            .filter(|item| item.disposition == OciNormativeDisposition::Enforced)
            .count(),
        578
    );
    assert_eq!(
        manifest
            .items
            .iter()
            .filter(|item| item.disposition == OciNormativeDisposition::Conformant)
            .count(),
        12
    );
    assert!(manifest
        .items
        .iter()
        .all(|item| item.disposition != OciNormativeDisposition::PendingReview));
}

#[test]
fn common_configuration_requirements_have_the_exact_owner_profile() {
    let manifest = checked_in_manifest();
    let requirements = manifest
        .items
        .iter()
        .filter(|item| item.requirement.document == "config.md")
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 278);
    for (disposition, owner, expected) in [
        (OciNormativeDisposition::Conformant, "linux-executor", 2),
        (
            OciNormativeDisposition::Conformant,
            "sdk-semantic-and-runtime",
            1,
        ),
        (OciNormativeDisposition::Enforced, "linux-executor", 200),
        (OciNormativeDisposition::Enforced, "runtime-bundle", 3),
        (
            OciNormativeDisposition::Enforced,
            "runtime-feature-report",
            2,
        ),
        (
            OciNormativeDisposition::Enforced,
            "sdk-semantic-and-runtime",
            1,
        ),
        (
            OciNormativeDisposition::Enforced,
            "sdk-semantic-validation",
            21,
        ),
        (
            OciNormativeDisposition::ReviewedExternal,
            "bundle-author",
            1,
        ),
        (
            OciNormativeDisposition::ReviewedExternal,
            "oci-configuration-author",
            2,
        ),
        (
            OciNormativeDisposition::ReviewedExternal,
            "oci-image-converter",
            8,
        ),
        (
            OciNormativeDisposition::ReviewedExternal,
            "oci-specification-author",
            1,
        ),
        (
            OciNormativeDisposition::ReviewedExternal,
            "runtime-caller",
            1,
        ),
        (OciNormativeDisposition::Validated, "runtime-bundle", 2),
        (
            OciNormativeDisposition::Validated,
            "sdk-image-annotation-validation",
            8,
        ),
        (
            OciNormativeDisposition::Validated,
            "sdk-schema-validation",
            8,
        ),
        (
            OciNormativeDisposition::Validated,
            "sdk-semantic-validation",
            17,
        ),
    ] {
        assert_eq!(
            requirements
                .iter()
                .filter(|item| item.disposition == disposition && item.owner == owner)
                .count(),
            expected,
            "unexpected {disposition:?} requirement count for {owner}"
        );
    }
    assert!(requirements.iter().all(|item| {
        item.disposition != OciNormativeDisposition::PendingReview
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
            && (item.disposition != OciNormativeDisposition::ReviewedExternal
                || item
                    .rationale
                    .as_deref()
                    .is_some_and(|rationale| !rationale.trim().is_empty()))
    }));
    let annotation_extensibility = requirements
        .iter()
        .find(|item| {
            item.rule_ids
                .iter()
                .any(|rule| rule == "oci.common.annotations.unknown-preserved")
        })
        .expect("unknown-annotation extensibility requirement");
    assert_eq!(
        annotation_extensibility.test_ids,
        [
            "bundle::tests::loads_v1_3_fields_without_losing_them",
            "executor::plan_tests::preserves_arbitrary_annotation_strings_without_c_string_restrictions",
        ]
    );
}

#[test]
fn namespace_mapping_and_time_requirements_are_all_owner_bound() {
    let manifest = checked_in_manifest();
    let headings = [
        "Namespaces",
        "User namespace mappings",
        "Offset for Time Namespace",
    ];
    let requirements = manifest
        .items
        .iter()
        .filter(|item| {
            item.requirement.document == "config-linux.md"
                && headings.contains(&item.requirement.heading.as_str())
        })
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 19);
    assert!(requirements.iter().all(|item| {
        item.disposition != OciNormativeDisposition::PendingReview
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
    }));
}

#[test]
fn seccomp_requirements_are_all_owner_bound() {
    let manifest = checked_in_manifest();
    let headings = ["Seccomp", "The Container Process State"];
    let requirements = manifest
        .items
        .iter()
        .filter(|item| {
            item.requirement.document == "config-linux.md"
                && headings.contains(&item.requirement.heading.as_str())
        })
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 36);
    assert!(requirements.iter().all(|item| {
        item.disposition != OciNormativeDisposition::PendingReview
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
    }));
}

#[test]
fn linux_configuration_requirements_have_the_exact_support_profile() {
    let manifest = checked_in_manifest();
    let requirements = manifest
        .items
        .iter()
        .filter(|item| item.requirement.document == "config-linux.md")
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 218);
    for (disposition, owner, expected) in [
        (OciNormativeDisposition::Conformant, "linux-executor", 3),
        (OciNormativeDisposition::Enforced, "linux-executor", 206),
        (
            OciNormativeDisposition::Validated,
            "sdk-semantic-validation",
            9,
        ),
    ] {
        assert_eq!(
            requirements
                .iter()
                .filter(|item| item.disposition == disposition && item.owner == owner)
                .count(),
            expected,
            "unexpected {disposition:?} Linux requirement count for {owner}"
        );
    }
    assert!(requirements.iter().all(|item| {
        item.disposition != OciNormativeDisposition::PendingReview
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
    }));
}

#[test]
fn linux_features_requirements_are_all_enforced_by_the_feature_report() {
    let manifest = checked_in_manifest();
    let requirements = manifest
        .items
        .iter()
        .filter(|item| item.requirement.document == "features-linux.md")
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 41);
    assert!(requirements.iter().all(|item| {
        item.disposition == OciNormativeDisposition::Enforced
            && item.owner == "runtime-feature-report"
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
    }));
}

#[test]
fn vm_requirements_have_the_exact_fail_closed_profile() {
    let manifest = checked_in_manifest();
    let requirements = manifest
        .items
        .iter()
        .filter(|item| item.requirement.document == "config-vm.md")
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 24);
    let validated_paths = requirements
        .iter()
        .filter(|item| item.disposition == OciNormativeDisposition::Validated)
        .collect::<Vec<_>>();
    assert_eq!(validated_paths.len(), 4);
    assert!(validated_paths.iter().all(|item| {
        item.owner == "sdk-semantic-validation"
            && item.rule_ids == ["oci.vm.path.absolute"]
            && item.test_ids
                == [
                    "semantic::tests::accepts_validated_normative_cross_field_boundaries",
                    "semantic::tests::validates_vm_paths_without_inventing_hardware_minima",
                ]
    }));

    let runtime_owned = requirements
        .iter()
        .filter(|item| item.disposition == OciNormativeDisposition::Enforced)
        .collect::<Vec<_>>();
    assert_eq!(runtime_owned.len(), 20);
    assert!(runtime_owned.iter().all(|item| {
        item.owner == "vm-driver"
            && item.rule_ids == ["oci.vm.configuration.runtime-owned"]
            && item.test_ids
                == [
                    "schema::tests::validates_complete_vm_schema_shapes",
                    "service::tests::rejects_caller_vm_configuration_before_durable_reservation_and_create_dispatch",
                ]
    }));
}

#[test]
fn runtime_lifecycle_requirements_are_all_owner_bound() {
    let manifest = checked_in_manifest();
    let requirements = manifest
        .items
        .iter()
        .filter(|item| item.requirement.document == "runtime.md")
        .collect::<Vec<_>>();

    assert_eq!(requirements.len(), 66);
    assert!(requirements.iter().all(|item| {
        item.disposition != OciNormativeDisposition::PendingReview
            && !item.rule_ids.is_empty()
            && !item.test_ids.is_empty()
    }));
}

#[test]
fn coverage_verifier_rejects_unknown_rule_ids() {
    let inventory = OciNormativeInventory::new();
    let mut manifest = checked_in_manifest();
    let item = manifest
        .items
        .iter_mut()
        .find(|item| {
            item.rule_ids
                .iter()
                .any(|rule| rule == "oci.bundle.config.root-file")
        })
        .expect("root config evidence item");
    item.rule_ids = vec!["oci.bundle.config.unknown".to_string()];

    let error = inventory
        .verify_coverage(&manifest)
        .expect_err("unknown evidence rules must fail closed");
    assert!(error.message.contains("references unknown rule"));
}

#[test]
fn coverage_verifier_rejects_non_semantic_rule_owner_drift() {
    let inventory = OciNormativeInventory::new();
    let mut manifest = checked_in_manifest();
    let item = manifest
        .items
        .iter_mut()
        .find(|item| {
            item.rule_ids
                .iter()
                .any(|rule| rule == "oci.bundle.config.root-file")
        })
        .expect("root config evidence item");
    item.owner = "runtime-lifecycle".to_string();

    let error = inventory
        .verify_coverage(&manifest)
        .expect_err("non-semantic rule owner drift must fail closed");
    assert!(error.message.contains("belongs to runtime-bundle"));
}

#[test]
fn coverage_verifier_rejects_missing_inventory_entries() {
    let inventory = OciNormativeInventory::new();
    let mut manifest = inventory.coverage_baseline();
    manifest.items.pop();
    assert!(inventory.verify_coverage(&manifest).is_err());
}

#[test]
fn keyword_scanner_prefers_complete_rfc_2119_terms() {
    let keywords = keyword_occurrences("the runtime MUST NOT weaken and MUST report")
        .into_iter()
        .map(|(_, keyword)| keyword)
        .collect::<Vec<_>>();
    assert_eq!(
        keywords,
        vec![OciNormativeKeyword::MustNot, OciNormativeKeyword::Must]
    );
}

#[test]
fn document_digests_are_independent_of_checkout_line_endings() {
    assert_eq!(
        canonical_text_sha256("first\r\nsecond\r\n"),
        canonical_text_sha256("first\nsecond\n")
    );
}

fn checked_in_manifest() -> OciNormativeCoverageManifest {
    serde_json::from_str(include_str!(
        "../../../../conformance/oci-1.3.0-normative-coverage.json"
    ))
    .expect("decode checked-in normative coverage")
}

fn checked_in_evidence() -> OciNormativeEvidenceManifest {
    serde_json::from_str(include_str!(
        "../../../../conformance/oci-1.3.0-normative-evidence.json"
    ))
    .expect("decode checked-in normative evidence")
}
