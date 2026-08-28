const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const RELEASE_GUIDE: &str = include_str!("../../../docs/release-verification.md");
const README: &str = include_str!("../../../README.md");
const CONTAINERD_GUIDE: &str = include_str!("../../../docs/containerd-runtime-v2.md");
const NATIVE_LINUX_PACKAGE_SMOKE: &str =
    include_str!("../../../.github/scripts/native-linux-package-smoke.sh");
const NATIVE_LINUX_SMOKE: &str = include_str!("../../../.github/scripts/native-linux-smoke.sh");
const NATIVE_LINUX_CHECKPOINT: &str =
    include_str!("../../../.github/scripts/native-linux-checkpoint.sh");
const BUILD_PINNED_CRIU: &str = include_str!("../../../.github/scripts/build-pinned-criu.sh");

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
    assert_eq!(
        RELEASE_WORKFLOW
            .matches("cp docs/checkpoint-contract.md \"$package/docs/\"")
            .count(),
        1
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

#[test]
fn linux_release_archives_retain_exact_package_qualification() {
    let qualification = "bash .github/scripts/native-linux-package-smoke.sh \"$package\"";
    assert_eq!(RELEASE_WORKFLOW.matches(qualification).count(), 1);
    let qualification_position = RELEASE_WORKFLOW
        .find(qualification)
        .expect("Linux package qualification must be present");
    let archive_position = RELEASE_WORKFLOW
        .find("tar -czf \"${package}.tar.gz\" \"$package\"")
        .expect("host package archive must be created");
    assert!(qualification_position < archive_position);

    for required in [
        "a3s.oci.native-linux-package-qualification.v4",
        "full-sdk-oar01-oar02-oar03-without-kvm-v4",
        "A3S_OCI_NATIVE_RUNTIME_BINARY",
        "A3S_OCI_NATIVE_AGENT_BINARY",
        "A3S_OCI_NATIVE_NETWORK_ENFORCEMENT_REPORT",
        "a3s.oci.native-linux-network-enforcement-smoke.v1",
        "A3S_OCI_NATIVE_KVM_ABSENCE_EVIDENCE",
        "checkpoint_driver_build_digest",
        "checkpoint_source_revision",
        "verify-static-elf.sh",
        "containerd-shim-a3s-oci-v2",
    ] {
        assert!(
            NATIVE_LINUX_PACKAGE_SMOKE.contains(required),
            "Native package qualification lost {required}"
        );
    }
    assert!(RELEASE_WORKFLOW.contains(
        "bash .github/scripts/build-pinned-criu.sh \\\n            /usr/local/lib/a3s-oci-tools/criu-4.2.1"
    ));
    assert!(
        RELEASE_WORKFLOW.contains("A3S_OCI_CRIU_BINARY=/usr/local/lib/a3s-oci-tools/criu-4.2.1")
    );
    assert!(RELEASE_WORKFLOW.contains("A3S_OCI_GIT_REVISION=\"$GITHUB_SHA\""));
}

#[test]
fn native_package_qualification_retains_oar01_real_host_evidence() {
    for required in [
        "native-linux-network-enforcement-smoke",
        "dev.a3s.network.enforcement",
        "network_enforcement_table_digest",
        "namespace_preserved_after_delete",
        "mechanism_preserved_after_delete",
        "A3S_OCI_NATIVE_NETWORK_ENFORCEMENT_REPORT",
    ] {
        assert!(
            NATIVE_LINUX_SMOKE.contains(required),
            "Native OAR-01 qualification lost {required}"
        );
    }
    assert!(NATIVE_LINUX_PACKAGE_SMOKE.contains("and (.evidence | length == 11)"));
}

#[test]
fn native_package_qualification_retains_oar02_real_host_evidence() {
    for required in [
        "a3s.oci.native-linux-soak.v2",
        "pause_resume_evidence",
        "progress_after_pause_reopen",
        "progress_after_resume_reopen",
        "pause_response_replayed_after_reopen",
        "resume_response_replayed_after_reopen",
        "oar02_pause_resume_verified",
    ] {
        assert!(
            NATIVE_LINUX_PACKAGE_SMOKE.contains(required) || NATIVE_LINUX_SMOKE.contains(required),
            "Native OAR-02 qualification lost {required}"
        );
    }
}

#[test]
fn native_package_qualification_retains_oar03_real_host_evidence() {
    for required in [
        "A3S_OCI_CRIU_BINARY",
        "A3S_OCI_NATIVE_CHECKPOINT_REPORT",
        "A3S_OCI_NATIVE_CHECKPOINT_PIDNS_REPORT",
        "A3S_OCI_NATIVE_CHECKPOINT_NETNS_REPORT",
        "native-linux-checkpoint.json",
        "native-linux-checkpoint-pidns.json",
        "native-linux-checkpoint-netns.json",
        "a3s.oci.native-linux-checkpoint-smoke.v3",
        "checkpoint_driver_build_digest",
        "checkpoint_criu_digest",
        "oar03_checkpoint_restore_verified",
        "external_tools",
    ] {
        assert!(
            NATIVE_LINUX_PACKAGE_SMOKE.contains(required),
            "Native OAR-03 package qualification lost {required}"
        );
    }

    for required in [
        "restoreAfterCallOwnerReplaced",
        "restoreAfterCommitOwnerReplaced",
        "crossProcessRestoredPidsLive",
        "crossProcessRestoreCleanupExact",
    ] {
        assert!(
            NATIVE_LINUX_CHECKPOINT.contains(required),
            "Native checkpoint qualification lost {required}"
        );
    }

    for required in [
        "https://github.com/checkpoint-restore/criu.git",
        "v4.2.1",
        "9539417f3e3cfa4eb84c319cd71f4d52f1f08645",
        "refs/tags/${criu_tag}:refs/tags/${criu_tag}",
        "install -m 0755 -o root -g root",
    ] {
        assert!(
            BUILD_PINNED_CRIU.contains(required),
            "Pinned CRIU builder lost {required}"
        );
    }
}

#[test]
fn pinned_criu_install_validates_the_destination_before_publication() {
    let destination_guard = BUILD_PINNED_CRIU
        .find("if [[ -e \"$destination\" || -L \"$destination\" ]]; then")
        .expect("Pinned CRIU builder lost the pre-canonical destination guard");
    let canonicalization = BUILD_PINNED_CRIU
        .find("destination=\"$(realpath -m -- \"$destination\")\"")
        .expect("Pinned CRIU builder lost destination canonicalization");
    let parent_identity = BUILD_PINNED_CRIU
        .find("destination_parent_mode=\"$(stat --format '%a' -- \"$destination_parent\")\"")
        .expect("Pinned CRIU builder lost install-parent identity validation");
    let publication = BUILD_PINNED_CRIU
        .find("install -m 0755 -o root -g root --")
        .expect("Pinned CRIU builder lost root-owned publication");

    assert!(destination_guard < canonicalization);
    assert!(canonicalization < parent_identity);
    assert!(parent_identity < publication);
    assert_eq!(
        BUILD_PINNED_CRIU
            .matches("if [[ -e \"$destination\" || -L \"$destination\" ]]; then")
            .count(),
        3,
        "Destination identity must be rechecked after each path-changing step"
    );
}

#[test]
fn packaged_native_binaries_are_validated_before_host_setup() {
    let host_setup_position = NATIVE_LINUX_SMOKE
        .find("sudo apt-get update")
        .expect("Native host dependency setup must be present");
    let pre_setup = &NATIVE_LINUX_SMOKE[..host_setup_position];

    for required in [
        "must be supplied together",
        "! -f \"$candidate\" || -L \"$candidate\" || ! -x \"$candidate\"",
        "realpath -e -- \"$native_runtime_binary\"",
        "Native runtime and Agent qualification binaries must be distinct",
        "use_development_binaries=false",
    ] {
        assert!(
            pre_setup.contains(required),
            "Native package binary validation must precede host setup: {required}"
        );
    }
    assert!(pre_setup.matches("validate_native_binaries").count() >= 2);
}

#[test]
fn packaged_native_service_waits_for_the_protected_socket_publication() {
    for required in [
        "os.path.lexists(socket_path)",
        "stat.S_ISSOCK(socket_metadata.st_mode)",
        "socket_mode == 0o600",
        "timed out waiting for protected native service socket",
    ] {
        assert!(
            NATIVE_LINUX_SMOKE.contains(required),
            "Native package gate lost protected socket readiness check: {required}"
        );
    }
}
