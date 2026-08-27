const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const RELEASE_GUIDE: &str = include_str!("../../../docs/release-verification.md");
const README: &str = include_str!("../../../README.md");
const CONTAINERD_GUIDE: &str = include_str!("../../../docs/containerd-runtime-v2.md");

const ATTEST_ACTION: &str = "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1";
const SIGNER_WORKFLOW: &str = "--signer-workflow A3S-Lab/OCI-Runtime/.github/workflows/release.yml";

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
        .find("softprops/action-gh-release@v2")
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
