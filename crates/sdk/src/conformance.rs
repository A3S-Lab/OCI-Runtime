//! Offline inventory of normative OCI Runtime Specification requirements.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, ErrorCode, Result};

const OCI_RUNTIME_SPEC_VERSION: &str = "1.3.0";
const OCI_RUNTIME_SPEC_COMMIT: &str = "92249139eea7161e13745abd4cb6d0ea02a3227a";
const NORMATIVE_COVERAGE_SCHEMA_VERSION: &str = "a3s.oci.normative-coverage.v1";

const SPECIFICATION_DOCUMENTS: &[EmbeddedSpecificationDocument] = &[
    EmbeddedSpecificationDocument::new(
        "spec.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/spec.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "principles.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/principles.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "bundle.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/bundle.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "runtime.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/runtime.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "runtime-linux.md",
        OciSpecificationScope::Linux,
        include_str!("../../../vendor/runtime-spec/v1.3.0/runtime-linux.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config-freebsd.md",
        OciSpecificationScope::FreeBsd,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config-freebsd.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config-linux.md",
        OciSpecificationScope::Linux,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config-linux.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config-solaris.md",
        OciSpecificationScope::Solaris,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config-solaris.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config-windows.md",
        OciSpecificationScope::Windows,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config-windows.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config-vm.md",
        OciSpecificationScope::Vm,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config-vm.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "config-zos.md",
        OciSpecificationScope::Zos,
        include_str!("../../../vendor/runtime-spec/v1.3.0/config-zos.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "features.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/features.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "features-linux.md",
        OciSpecificationScope::Linux,
        include_str!("../../../vendor/runtime-spec/v1.3.0/features-linux.md"),
    ),
    EmbeddedSpecificationDocument::new(
        "glossary.md",
        OciSpecificationScope::Common,
        include_str!("../../../vendor/runtime-spec/v1.3.0/glossary.md"),
    ),
];

const KEYWORDS: &[(&str, OciNormativeKeyword)] = &[
    ("NOT RECOMMENDED", OciNormativeKeyword::NotRecommended),
    ("SHOULD NOT", OciNormativeKeyword::ShouldNot),
    ("SHALL NOT", OciNormativeKeyword::ShallNot),
    ("MUST NOT", OciNormativeKeyword::MustNot),
    ("RECOMMENDED", OciNormativeKeyword::Recommended),
    ("REQUIRED", OciNormativeKeyword::Required),
    ("OPTIONAL", OciNormativeKeyword::Optional),
    ("SHOULD", OciNormativeKeyword::Should),
    ("SHALL", OciNormativeKeyword::Shall),
    ("MUST", OciNormativeKeyword::Must),
    ("MAY", OciNormativeKeyword::May),
];

#[derive(Clone, Copy)]
struct EmbeddedSpecificationDocument {
    name: &'static str,
    scope: OciSpecificationScope,
    source: &'static str,
}

impl EmbeddedSpecificationDocument {
    const fn new(name: &'static str, scope: OciSpecificationScope, source: &'static str) -> Self {
        Self {
            name,
            scope,
            source,
        }
    }
}

/// Platform scope assigned by the pinned specification table of contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciSpecificationScope {
    Common,
    Linux,
    Vm,
    FreeBsd,
    Solaris,
    Windows,
    Zos,
}

impl OciSpecificationScope {
    const fn is_inapplicable_native_platform(self) -> bool {
        matches!(
            self,
            Self::FreeBsd | Self::Solaris | Self::Windows | Self::Zos
        )
    }
}

/// RFC 2119 term found in one pinned specification source line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciNormativeKeyword {
    Must,
    MustNot,
    Required,
    Shall,
    ShallNot,
    Should,
    ShouldNot,
    Recommended,
    NotRecommended,
    May,
    Optional,
}

impl OciNormativeKeyword {
    const fn source_text(self) -> &'static str {
        match self {
            Self::Must => "MUST",
            Self::MustNot => "MUST NOT",
            Self::Required => "REQUIRED",
            Self::Shall => "SHALL",
            Self::ShallNot => "SHALL NOT",
            Self::Should => "SHOULD",
            Self::ShouldNot => "SHOULD NOT",
            Self::Recommended => "RECOMMENDED",
            Self::NotRecommended => "NOT RECOMMENDED",
            Self::May => "MAY",
            Self::Optional => "OPTIONAL",
        }
    }
}

impl fmt::Display for OciNormativeKeyword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.source_text())
    }
}

/// Digest of one unmodified source document in the normative corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciNormativeDocument {
    pub name: String,
    pub scope: OciSpecificationScope,
    pub sha256: String,
}

/// One occurrence of an RFC 2119 term in the pinned specification corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciNormativeRequirement {
    pub id: String,
    pub document: String,
    pub scope: OciSpecificationScope,
    pub line: u32,
    pub heading: String,
    pub keyword: OciNormativeKeyword,
    pub occurrence: u32,
    pub source: String,
}

/// Review and implementation state for one normative inventory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OciNormativeDisposition {
    /// The entry is inventoried but still needs an exact rule and evidence map.
    PendingReview,
    /// The entry defines specification vocabulary rather than runtime behavior.
    SpecificationDefinition,
    /// The entire native workload platform is rejected before state mutation.
    RejectedInapplicablePlatform,
    /// Static validation is implemented and has positive and negative evidence.
    Validated,
    /// Runtime or driver enforcement is implemented and tested.
    Enforced,
    /// All applicable conformance gates have retained evidence.
    Conformant,
}

/// Coverage metadata attached to one normative inventory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciNormativeCoverageItem {
    #[serde(flatten)]
    pub requirement: OciNormativeRequirement,
    pub disposition: OciNormativeDisposition,
    pub owner: String,
    pub rule_ids: Vec<String>,
    pub test_ids: Vec<String>,
}

/// Machine-readable lock for the pinned normative specification corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciNormativeCoverageManifest {
    pub schema_version: String,
    pub oci_runtime_spec: String,
    pub upstream_commit: String,
    pub documents: Vec<OciNormativeDocument>,
    pub items: Vec<OciNormativeCoverageItem>,
}

/// Offline inventory for the normative OCI Runtime Specification 1.3.0 text.
///
/// The corpus is the exact document list linked by the pinned `spec.md` table
/// of contents. Fenced examples and HTML comments are excluded. Each remaining
/// RFC 2119 keyword occurrence receives a stable content fingerprint.
#[derive(Debug, Clone, Copy, Default)]
pub struct OciNormativeInventory;

impl OciNormativeInventory {
    /// Construct an inventory over the embedded, pinned specification corpus.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Return digests for every source document in specification order.
    #[must_use]
    pub fn documents(self) -> Vec<OciNormativeDocument> {
        SPECIFICATION_DOCUMENTS
            .iter()
            .map(|document| OciNormativeDocument {
                name: document.name.to_string(),
                scope: document.scope,
                sha256: canonical_text_sha256(document.source),
            })
            .collect()
    }

    /// Extract every RFC 2119 keyword occurrence outside examples and comments.
    #[must_use]
    pub fn requirements(self) -> Vec<OciNormativeRequirement> {
        SPECIFICATION_DOCUMENTS
            .iter()
            .flat_map(extract_requirements)
            .collect()
    }

    /// Build the initial review baseline for the checked-in coverage lock.
    ///
    /// Common, Linux, and VM entries remain pending until they are manually
    /// bound to exact validation or enforcement evidence. Unsupported native
    /// workload-platform documents are bound to the fail-closed platform rule.
    #[must_use]
    pub fn coverage_baseline(self) -> OciNormativeCoverageManifest {
        let items = self
            .requirements()
            .into_iter()
            .map(baseline_coverage)
            .collect();
        OciNormativeCoverageManifest {
            schema_version: NORMATIVE_COVERAGE_SCHEMA_VERSION.to_string(),
            oci_runtime_spec: OCI_RUNTIME_SPEC_VERSION.to_string(),
            upstream_commit: OCI_RUNTIME_SPEC_COMMIT.to_string(),
            documents: self.documents(),
            items,
        }
    }

    /// Verify that a coverage manifest has no missing, stale, or invalid entry.
    pub fn verify_coverage(self, manifest: &OciNormativeCoverageManifest) -> Result<()> {
        if manifest.schema_version != NORMATIVE_COVERAGE_SCHEMA_VERSION
            || manifest.oci_runtime_spec != OCI_RUNTIME_SPEC_VERSION
            || manifest.upstream_commit != OCI_RUNTIME_SPEC_COMMIT
        {
            return Err(coverage_error(
                "normative coverage metadata does not match the pinned OCI release",
            ));
        }

        let documents = self.documents();
        if manifest.documents != documents {
            return Err(coverage_error(
                "normative source document names, scopes, or digests changed",
            ));
        }

        let requirements = self.requirements();
        let expected = requirements
            .iter()
            .map(|requirement| (requirement.id.as_str(), requirement))
            .collect::<BTreeMap<_, _>>();
        let mut actual = BTreeMap::new();
        for item in &manifest.items {
            if actual.insert(item.requirement.id.as_str(), item).is_some() {
                return Err(coverage_error(format!(
                    "duplicate normative coverage ID {}",
                    item.requirement.id
                )));
            }
        }
        if expected.len() != actual.len() {
            return Err(coverage_error(format!(
                "normative coverage has {} entries; pinned corpus requires {}",
                actual.len(),
                expected.len()
            )));
        }
        for (id, requirement) in expected {
            let Some(item) = actual.get(id) else {
                return Err(coverage_error(format!(
                    "normative coverage is missing {id}"
                )));
            };
            if &item.requirement != requirement {
                return Err(coverage_error(format!(
                    "normative coverage metadata is stale for {id}"
                )));
            }
            verify_coverage_item(item)?;
        }
        Ok(())
    }
}

fn extract_requirements(document: &EmbeddedSpecificationDocument) -> Vec<OciNormativeRequirement> {
    let mut requirements = Vec::new();
    let mut heading = String::new();
    let mut fence = None;
    let mut inside_comment = false;

    for (line_index, raw_line) in document.source.lines().enumerate() {
        let trimmed = raw_line.trim_start();
        if let Some(marker) = fence_marker(trimmed) {
            if fence == Some(marker) {
                fence = None;
            } else if fence.is_none() {
                fence = Some(marker);
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }

        let visible = strip_html_comments(raw_line, &mut inside_comment);
        if let Some(current_heading) = markdown_heading(&visible) {
            heading = current_heading;
        }
        let source = normalize_whitespace(&visible);
        if source.is_empty() {
            continue;
        }

        for (ordinal, (_, keyword)) in keyword_occurrences(&source).into_iter().enumerate() {
            let line = u32::try_from(line_index + 1).unwrap_or(u32::MAX);
            let occurrence = u32::try_from(ordinal + 1).unwrap_or(u32::MAX);
            requirements.push(OciNormativeRequirement {
                id: requirement_id(document.name, line, &heading, keyword, occurrence, &source),
                document: document.name.to_string(),
                scope: document.scope,
                line,
                heading: heading.clone(),
                keyword,
                occurrence,
                source: source.clone(),
            });
        }
    }
    requirements
}

fn fence_marker(line: &str) -> Option<char> {
    if line.starts_with("```") {
        Some('`')
    } else if line.starts_with("~~~") {
        Some('~')
    } else {
        None
    }
}

fn strip_html_comments(line: &str, inside_comment: &mut bool) -> String {
    let mut visible = String::new();
    let mut remaining = line;
    loop {
        if *inside_comment {
            let Some(end) = remaining.find("-->") else {
                return visible;
            };
            *inside_comment = false;
            remaining = &remaining[end + 3..];
        } else {
            let Some(start) = remaining.find("<!--") else {
                visible.push_str(remaining);
                return visible;
            };
            visible.push_str(&remaining[..start]);
            *inside_comment = true;
            remaining = &remaining[start + 4..];
        }
    }
}

fn markdown_heading(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let hashes = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    if hashes == 0 || hashes > 6 || trimmed.as_bytes().get(hashes) != Some(&b' ') {
        return None;
    }
    let mut heading = trimmed[hashes..].trim();
    while heading.starts_with("<a ") {
        let Some(end) = heading.find("/>") else {
            break;
        };
        heading = heading[end + 2..].trim_start();
    }
    Some(heading.trim_end_matches('#').trim().to_string())
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn keyword_occurrences(source: &str) -> Vec<(usize, OciNormativeKeyword)> {
    let mut candidates = Vec::new();
    for (text, keyword) in KEYWORDS {
        for (start, _) in source.match_indices(text) {
            let end = start + text.len();
            if keyword_boundary(source.as_bytes(), start, end) {
                candidates.push((start, end, *keyword));
            }
        }
    }
    candidates.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| (right.1 - right.0).cmp(&(left.1 - left.0)))
    });

    let mut accepted = Vec::new();
    let mut previous_end = 0;
    for (start, end, keyword) in candidates {
        if start < previous_end {
            continue;
        }
        accepted.push((start, keyword));
        previous_end = end;
    }
    accepted
}

fn keyword_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let left = start == 0 || !bytes[start - 1].is_ascii_alphabetic();
    let right = end == bytes.len() || !bytes[end].is_ascii_alphabetic();
    left && right
}

fn requirement_id(
    document: &str,
    line: u32,
    heading: &str,
    keyword: OciNormativeKeyword,
    occurrence: u32,
    source: &str,
) -> String {
    let identity = format!(
        "{OCI_RUNTIME_SPEC_VERSION}\0{document}\0{line}\0{heading}\0{}\0{occurrence}\0{source}",
        keyword.source_text()
    );
    sha256(identity.as_bytes())
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn canonical_text_sha256(source: &str) -> String {
    sha256(source.replace("\r\n", "\n").as_bytes())
}

fn baseline_coverage(requirement: OciNormativeRequirement) -> OciNormativeCoverageItem {
    if requirement.document == "glossary.md"
        || (requirement.document == "spec.md" && requirement.heading == "Notational Conventions")
    {
        return OciNormativeCoverageItem {
            requirement,
            disposition: OciNormativeDisposition::SpecificationDefinition,
            owner: "specification-corpus".to_string(),
            rule_ids: Vec::new(),
            test_ids: Vec::new(),
        };
    }

    if requirement.scope.is_inapplicable_native_platform() {
        return OciNormativeCoverageItem {
            requirement,
            disposition: OciNormativeDisposition::RejectedInapplicablePlatform,
            owner: "sdk-semantic-validation".to_string(),
            rule_ids: vec!["oci.platform.linux-only".to_string()],
            test_ids: vec![
                "semantic::tests::rejects_native_non_linux_workload_sections_as_unsupported"
                    .to_string(),
            ],
        };
    }

    let owner = match requirement.document.as_str() {
        "bundle.md" => "runtime-bundle",
        "runtime.md" => "runtime-lifecycle",
        "runtime-linux.md" | "config-linux.md" => "linux-executor",
        "config-vm.md" => "vm-driver",
        "features.md" | "features-linux.md" => "feature-report",
        "config.md" => "sdk-semantic-and-runtime",
        _ => "runtime-contract",
    };
    OciNormativeCoverageItem {
        requirement,
        disposition: OciNormativeDisposition::PendingReview,
        owner: owner.to_string(),
        rule_ids: Vec::new(),
        test_ids: Vec::new(),
    }
}

fn verify_coverage_item(item: &OciNormativeCoverageItem) -> Result<()> {
    if item.owner.trim().is_empty() {
        return Err(coverage_error(format!(
            "normative coverage {} has no owner",
            item.requirement.id
        )));
    }

    let mut unique_rules = BTreeSet::new();
    if item
        .rule_ids
        .iter()
        .any(|rule| rule.trim().is_empty() || !unique_rules.insert(rule))
    {
        return Err(coverage_error(format!(
            "normative coverage {} has an empty or duplicate rule ID",
            item.requirement.id
        )));
    }
    let mut unique_tests = BTreeSet::new();
    if item
        .test_ids
        .iter()
        .any(|test| test.trim().is_empty() || !unique_tests.insert(test))
    {
        return Err(coverage_error(format!(
            "normative coverage {} has an empty or duplicate test ID",
            item.requirement.id
        )));
    }

    let evidence_required = matches!(
        item.disposition,
        OciNormativeDisposition::RejectedInapplicablePlatform
            | OciNormativeDisposition::Validated
            | OciNormativeDisposition::Enforced
            | OciNormativeDisposition::Conformant
    );
    if evidence_required && (item.rule_ids.is_empty() || item.test_ids.is_empty()) {
        return Err(coverage_error(format!(
            "normative coverage {} claims implementation without rule and test evidence",
            item.requirement.id
        )));
    }
    Ok(())
}

fn coverage_error(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::InvalidArgument, message).for_operation("verify-oci-normative-coverage")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        canonical_text_sha256, keyword_occurrences, OciNormativeCoverageManifest,
        OciNormativeInventory, OciNormativeKeyword, SPECIFICATION_DOCUMENTS,
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
        let manifest: OciNormativeCoverageManifest = serde_json::from_str(include_str!(
            "../../../conformance/oci-1.3.0-normative-coverage.json"
        ))
        .expect("decode checked-in normative coverage");
        OciNormativeInventory::new()
            .verify_coverage(&manifest)
            .expect("checked-in normative coverage must be complete and current");
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
}
