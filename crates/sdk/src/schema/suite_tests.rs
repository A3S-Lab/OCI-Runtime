use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{OciSchemaDocument, OciSchemaValidator};

const UPSTREAM_FIXTURE_ROOT: &str = "../../vendor/runtime-spec/v1.3.0/schema/test";
const UPSTREAM_FIXTURE_SET_SHA256: &str =
    "sha256:d03beb426942605b7fe387237da7ab2db9ce76e351b26902b49be18325c6f398";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedResult {
    Valid,
    InvalidJson,
    InvalidSchema,
}

#[derive(Debug, Clone, Copy)]
struct SchemaCase {
    relative_path: &'static str,
    document: OciSchemaDocument,
    expected: ExpectedResult,
    source: &'static [u8],
}

macro_rules! schema_case {
    ($path:literal, $document:expr, $expected:expr) => {
        SchemaCase {
            relative_path: $path,
            document: $document,
            expected: $expected,
            source: include_bytes!(concat!(
                "../../../../vendor/runtime-spec/v1.3.0/schema/test/",
                $path
            )),
        }
    };
}

const UPSTREAM_CASES: &[SchemaCase] = &[
    schema_case!(
        "config/bad/freebsd-vnet-disable.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::InvalidSchema
    ),
    schema_case!(
        "config/bad/invalid-json.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::InvalidJson
    ),
    schema_case!(
        "config/bad/linux-hugepage.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::InvalidSchema
    ),
    schema_case!(
        "config/bad/linux-netdevice.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::InvalidSchema
    ),
    schema_case!(
        "config/bad/linux-rdma.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::InvalidSchema
    ),
    schema_case!(
        "config/good/freebsd-example.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/freebsd-minimal.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/linux-netdevice.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/linux-rdma.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/minimal-for-start.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/minimal.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/spec-example.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/zos-example.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "config/good/zos-minimal.json",
        OciSchemaDocument::Configuration,
        ExpectedResult::Valid
    ),
    schema_case!(
        "features/bad/missing-ociVersionMax.json",
        OciSchemaDocument::Features,
        ExpectedResult::InvalidSchema
    ),
    schema_case!(
        "features/good/minimal.json",
        OciSchemaDocument::Features,
        ExpectedResult::Valid
    ),
    schema_case!(
        "features/good/runc.json",
        OciSchemaDocument::Features,
        ExpectedResult::Valid
    ),
    schema_case!(
        "state/bad/invalid-json.json",
        OciSchemaDocument::State,
        ExpectedResult::InvalidJson
    ),
    schema_case!(
        "state/good/spec-example.json",
        OciSchemaDocument::State,
        ExpectedResult::Valid
    ),
];

#[test]
fn passes_every_pinned_upstream_schema_fixture() {
    assert_fixture_inventory_is_exhaustive();
    assert_fixture_set_is_digest_bound();

    let validator = OciSchemaValidator::new().expect("compile pinned schemas");
    for case in UPSTREAM_CASES {
        let decoded = serde_json::from_slice::<Value>(case.source);
        match case.expected {
            ExpectedResult::Valid => {
                let value = decoded.unwrap_or_else(|error| {
                    panic!("{} must contain valid JSON: {error}", case.relative_path)
                });
                validator
                    .validate(case.document, &value)
                    .unwrap_or_else(|error| {
                        panic!(
                            "{} must pass the pinned {}: {error}",
                            case.relative_path, case.document
                        )
                    });
            }
            ExpectedResult::InvalidJson => {
                assert!(
                    decoded.is_err(),
                    "{} must remain a malformed JSON fixture",
                    case.relative_path
                );
            }
            ExpectedResult::InvalidSchema => {
                let value = decoded.unwrap_or_else(|error| {
                    panic!(
                        "{} must be JSON so the schema performs the rejection: {error}",
                        case.relative_path
                    )
                });
                assert!(
                    validator.validate(case.document, &value).is_err(),
                    "{} unexpectedly passed the pinned {}",
                    case.relative_path,
                    case.document
                );
            }
        }
    }
}

fn assert_fixture_set_is_digest_bound() {
    let mut cases = UPSTREAM_CASES.iter().collect::<Vec<_>>();
    cases.sort_by(|left, right| left.relative_path.cmp(right.relative_path));

    let mut digest = Sha256::new();
    for case in cases {
        let source = canonical_fixture_source(case.source);
        let path_length = u64::try_from(case.relative_path.len()).expect("fixture path length");
        let source_length = u64::try_from(source.len()).expect("fixture source length");
        digest.update(path_length.to_be_bytes());
        digest.update(case.relative_path.as_bytes());
        digest.update(source_length.to_be_bytes());
        digest.update(source);
    }
    let actual = format!("sha256:{:x}", digest.finalize());
    assert_eq!(
        actual, UPSTREAM_FIXTURE_SET_SHA256,
        "pinned upstream fixture content changed"
    );
}

fn canonical_fixture_source(source: &[u8]) -> Vec<u8> {
    let source = std::str::from_utf8(source).expect("OCI schema fixture must be UTF-8");
    source.replace("\r\n", "\n").into_bytes()
}

#[test]
fn fixture_digest_is_independent_of_checkout_line_endings() {
    assert_eq!(
        canonical_fixture_source(b"first\r\nsecond\r\n"),
        b"first\nsecond\n"
    );
    assert_eq!(
        canonical_fixture_source(b"first\rsecond\n"),
        b"first\rsecond\n"
    );
}

fn assert_fixture_inventory_is_exhaustive() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(UPSTREAM_FIXTURE_ROOT);
    let mut actual = Vec::new();
    collect_fixture_files(&root, &root, &mut actual);
    actual.sort();

    let mut expected = UPSTREAM_CASES
        .iter()
        .map(|case| case.relative_path.to_string())
        .collect::<Vec<_>>();
    let case_count = expected.len();
    expected.sort();
    expected.dedup();
    assert_eq!(
        expected.len(),
        case_count,
        "pinned upstream expectation table contains duplicate fixtures"
    );

    assert_eq!(
        actual, expected,
        "pinned upstream fixture inventory changed"
    );
}

fn collect_fixture_files(root: &Path, directory: &Path, paths: &mut Vec<String>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "failed to read an entry in {}: {error}",
                directory.display()
            )
        });
        let path = entry.path();
        let file_type = entry
            .file_type()
            .unwrap_or_else(|error| panic!("failed to inspect {}: {error}", path.display()));
        if file_type.is_dir() {
            collect_fixture_files(root, &path, paths);
        } else if file_type.is_file() {
            paths.push(portable_relative_path(root, path));
        } else {
            panic!(
                "pinned upstream fixture must be a regular file or directory: {}",
                path.display()
            );
        }
    }
}

fn portable_relative_path(root: &Path, path: PathBuf) -> String {
    path.strip_prefix(root)
        .unwrap_or_else(|_| panic!("{} is outside {}", path.display(), root.display()))
        .to_string_lossy()
        .replace('\\', "/")
}
