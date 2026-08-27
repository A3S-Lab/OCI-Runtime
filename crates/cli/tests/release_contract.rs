const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const RELEASE_GUIDE: &str = include_str!("../../../docs/release-verification.md");
const README: &str = include_str!("../../../README.md");
const CONTAINERD_GUIDE: &str = include_str!("../../../docs/containerd-runtime-v2.md");

const ATTEST_ACTION: &str = "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1";
const RELEASE_ACTION: &str =
    "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65 # v2.6.2";
const SIGNER_WORKFLOW: &str = "--signer-workflow A3S-Lab/OCI-Runtime/.github/workflows/release.yml";
const PINNED_RELEASE_ACTIONS: [(&str, usize); 7] = [
    (
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0",
        3,
    ),
    (
        "dtolnay/rust-toolchain@4360b52568e2003a75bf9bc1d59f33a8e3fc893c # stable",
        3,
    ),
    (
        "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2",
        3,
    ),
    (
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2",
        2,
    ),
    (
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0",
        1,
    ),
    (ATTEST_ACTION, 1),
    (RELEASE_ACTION, 1),
];

#[test]
fn every_external_release_action_is_pinned_to_an_immutable_commit() {
    let action_lines = RELEASE_WORKFLOW
        .lines()
        .filter(|line| line.contains("uses: "))
        .collect::<Vec<_>>();
    assert_eq!(action_lines.len(), 14);

    for line in &action_lines {
        let action = line
            .split_once("uses: ")
            .expect("action line must contain a uses value")
            .1;
        let revision = action
            .split_once('@')
            .expect("external action must contain a revision")
            .1
            .split_whitespace()
            .next()
            .expect("external action must contain a revision value");
        assert_eq!(revision.len(), 40, "action is not pinned: {action}");
        assert!(
            revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "action is not pinned: {action}"
        );
    }

    for (action, expected_count) in PINNED_RELEASE_ACTIONS {
        assert_eq!(
            RELEASE_WORKFLOW.matches(action).count(),
            expected_count,
            "unexpected release action revision for {action}"
        );
    }
}

#[test]
fn release_attests_every_checksum_bound_archive_before_publishing() {
    let (workflow_header, publish_job) = RELEASE_WORKFLOW
        .split_once("\n  publish:\n")
        .expect("release workflow must retain one publish job");

    assert!(workflow_header.contains("permissions:\n  contents: read"));
    assert!(publish_job.contains(
        "permissions:\n      contents: write\n      id-token: write\n      attestations: write\n      artifact-metadata: write"
    ));
    assert_eq!(RELEASE_WORKFLOW.matches("id-token: write").count(), 1);
    assert_eq!(RELEASE_WORKFLOW.matches("attestations: write").count(), 1);
    assert_eq!(
        RELEASE_WORKFLOW.matches("artifact-metadata: write").count(),
        1
    );

    assert!(publish_job.contains("test \"$(find dist -type f -name '*.tar.gz' | wc -l)\" -eq 5"));
    assert!(publish_job.contains("sha256sum *.tar.gz > SHA256SUMS"));
    assert!(publish_job.contains(ATTEST_ACTION));
    assert!(publish_job
        .contains("subject-path: |\n            dist/*.tar.gz\n            dist/SHA256SUMS"));
    assert!(publish_job.contains("${{ steps.provenance.outputs.bundle-path }}"));
    assert!(
        publish_job.contains("dist/a3s-oci-runtime-${GITHUB_REF_NAME}-provenance.sigstore.json")
    );
    assert!(publish_job.contains("files: dist/*"));

    let attest_position = publish_job
        .find(ATTEST_ACTION)
        .expect("attestation action must be present");
    let release_position = publish_job
        .find(RELEASE_ACTION)
        .expect("release action must be present");
    let bundle_position = publish_job
        .find("Retain portable Sigstore bundle")
        .expect("portable bundle step must be present");
    assert!(attest_position < release_position);
    assert!(bundle_position < release_position);

    assert_eq!(
        RELEASE_WORKFLOW
            .matches("cp docs/release-verification.md \"$package/docs/\"")
            .count(),
        2
    );
}

#[test]
fn packaged_verification_guide_enforces_identity_without_promoting_capability() {
    assert!(RELEASE_GUIDE.contains("gh attestation verify \"$archive\""));
    assert_eq!(RELEASE_GUIDE.matches(SIGNER_WORKFLOW).count(), 2);
    assert_eq!(
        RELEASE_GUIDE
            .matches("--source-ref \"refs/tags/$tag\"")
            .count(),
        2
    );
    assert!(RELEASE_GUIDE.contains("--bundle \"$bundle\""));
    assert!(RELEASE_GUIDE.contains("--custom-trusted-root trusted_root.jsonl"));
    assert!(RELEASE_GUIDE.contains("gh attestation trusted-root > trusted_root.jsonl"));
    assert!(RELEASE_GUIDE.contains("does not establish that an experimental or probe-only"));
    assert!(README.contains("docs/release-verification.md"));
    assert!(CONTAINERD_GUIDE.contains("release-verification.md"));
}
