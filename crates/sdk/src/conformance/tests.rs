use std::collections::BTreeSet;

use super::{
    canonical_text_sha256, keyword_occurrences, OciNormativeCoverageManifest,
    OciNormativeEvidenceManifest, OciNormativeInventory, OciNormativeKeyword,
    SPECIFICATION_DOCUMENTS,
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
    let evidence: OciNormativeEvidenceManifest = serde_json::from_str(include_str!(
        "../../../../conformance/oci-1.3.0-normative-evidence.json"
    ))
    .expect("decode checked-in normative evidence");
    let generated = OciNormativeInventory::new()
        .coverage_with_evidence(&evidence)
        .expect("checked-in normative evidence must be complete and current");
    assert_eq!(manifest, generated);
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
