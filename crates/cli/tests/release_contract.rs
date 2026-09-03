const RELEASE_WORKFLOW: &str = include_str!("../../../.github/workflows/release.yml");
const CI_WORKFLOW: &str = include_str!("../../../.github/workflows/ci.yml");
const RELEASE_GUIDE: &str = include_str!("../../../docs/release-verification.md");
const README: &str = include_str!("../../../README.md");
const CONTAINERD_GUIDE: &str = include_str!("../../../docs/containerd-runtime-v2.md");
const NATIVE_LINUX_PACKAGE_SMOKE: &str =
    include_str!("../../../.github/scripts/native-linux-package-smoke.sh");
const NATIVE_LINUX_SMOKE: &str = include_str!("../../../.github/scripts/native-linux-smoke.sh");
const NATIVE_LINUX_CHECKPOINT: &str =
    include_str!("../../../.github/scripts/native-linux-checkpoint.sh");
const BUILD_PINNED_CRIU: &str = include_str!("../../../.github/scripts/build-pinned-criu.sh");
const BUILD_PINNED_RUNTIME_TOOLS: &str =
    include_str!("../../../.github/scripts/build-pinned-runtime-tools.sh");
const UPSTREAM_BUNDLE_VALIDATION: &str =
    include_str!("../../../.github/scripts/upstream-oci-bundle-validation.sh");
const UPSTREAM_LIFECYCLE_VALIDATION: &str =
    include_str!("../../../.github/scripts/upstream-oci-lifecycle-validation.sh");
const CREATE_RELEASE_PACKAGE_MANIFEST: &str =
    include_str!("../../../.github/scripts/create-release-package-manifest.sh");
const VERIFY_RELEASE_PACKAGE_MANIFEST: &str =
    include_str!("../../../.github/scripts/verify-release-package-manifest.sh");
const UPSTREAM_RUNTIME_TOOLS_LOCK: &str =
    include_str!("../../../compat/upstream-runtime-tools.json");

const ATTEST_ACTION: &str = "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1";
const RELEASE_ACTION: &str =
    "softprops/action-gh-release@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65 # v2.6.2";
const SIGNER_WORKFLOW: &str = "--signer-workflow A3S-Lab/OCI-Runtime/.github/workflows/release.yml";
const PINNED_RELEASE_ACTIONS: [(&str, usize); 8] = [
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
        "actions/setup-go@4dc6199c7b1a012772edbd06daecab0f50c9053c # v6.1.0",
        1,
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

fn normalize_newlines(document: &str) -> String {
    document.lines().collect::<Vec<_>>().join("\n")
}

fn normalized_release_workflow() -> String {
    normalize_newlines(RELEASE_WORKFLOW)
}

#[test]
fn release_contract_documents_are_newline_independent() {
    assert_eq!(
        normalize_newlines("jobs:\r\n  publish:\r\n"),
        "jobs:\n  publish:"
    );
}

#[test]
fn every_external_release_action_is_pinned_to_an_immutable_commit() {
    let release_workflow = normalized_release_workflow();
    let action_lines = release_workflow
        .lines()
        .filter(|line| line.contains("uses: "))
        .collect::<Vec<_>>();
    assert_eq!(action_lines.len(), 15);

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
            release_workflow.matches(action).count(),
            expected_count,
            "unexpected release action revision for {action}"
        );
    }
}

#[test]
fn release_attests_every_checksum_bound_archive_before_publishing() {
    let release_workflow = normalized_release_workflow();
    let (workflow_header, publish_job) = release_workflow
        .split_once("\n  publish:\n")
        .expect("release workflow must retain one publish job");

    assert!(workflow_header.contains("permissions:\n  contents: read"));
    assert!(publish_job.contains(
        "permissions:\n      contents: write\n      id-token: write\n      attestations: write\n      artifact-metadata: write"
    ));
    assert_eq!(release_workflow.matches("id-token: write").count(), 1);
    assert_eq!(release_workflow.matches("attestations: write").count(), 1);
    assert_eq!(
        release_workflow.matches("artifact-metadata: write").count(),
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
        release_workflow
            .matches("cp docs/release-verification.md \"$package/docs/\"")
            .count(),
        2
    );
    assert_eq!(
        release_workflow
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
    let release_workflow = normalized_release_workflow();
    let qualification = "bash .github/scripts/native-linux-package-smoke.sh \"$package\"";
    assert_eq!(release_workflow.matches(qualification).count(), 1);
    let qualification_position = release_workflow
        .find(qualification)
        .expect("Linux package qualification must be present");
    let archive_position = release_workflow
        .find("tar -czf \"${package}.tar.gz\" \"$package\"")
        .expect("host package archive must be created");
    assert!(qualification_position < archive_position);

    for required in [
        "a3s.oci.native-linux-package-qualification.v7",
        "full-sdk-oar01-oar02-oar03-upstream-lifecycle-qualified-without-kvm-v7",
        "A3S_OCI_NATIVE_RUNTIME_BINARY",
        "A3S_OCI_NATIVE_AGENT_BINARY",
        "A3S_OCI_NATIVE_NETWORK_ENFORCEMENT_REPORT",
        "a3s.oci.native-linux-network-enforcement-smoke.v1",
        "A3S_OCI_NATIVE_KVM_ABSENCE_EVIDENCE",
        "checkpoint_driver_build_digest",
        "checkpoint_source_revision",
        "verify-static-elf.sh",
        "containerd-shim-a3s-oci-v2",
        "upstream_bundle_validation_verified",
        "a3s.oci.upstream-bundle-validation.v1",
        "upstream_core_lifecycle_verified",
        "a3s.oci.upstream-lifecycle-validation.v1",
    ] {
        assert!(
            NATIVE_LINUX_PACKAGE_SMOKE.contains(required),
            "Native package qualification lost {required}"
        );
    }
    assert!(release_workflow.contains(
        "bash .github/scripts/build-pinned-criu.sh \\\n            /usr/local/lib/a3s-oci-tools/criu-4.2.1"
    ));
    assert!(release_workflow.contains(
        "bash .github/scripts/build-pinned-runtime-tools.sh \\\n            /usr/local/lib/a3s-oci-tools/runtime-tools-8a4db579f5c88af5a0d036fad34bddc9c1f703f3"
    ));
    assert!(release_workflow.contains(
        "A3S_OCI_UPSTREAM_RUNTIME_TOOL=/usr/local/lib/a3s-oci-tools/runtime-tools-8a4db579f5c88af5a0d036fad34bddc9c1f703f3/oci-runtime-tool"
    ));
    assert!(release_workflow.contains(
        "A3S_OCI_UPSTREAM_RUNTIME_TOOL_MANIFEST=/usr/local/lib/a3s-oci-tools/runtime-tools-8a4db579f5c88af5a0d036fad34bddc9c1f703f3/build.json"
    ));
    assert!(
        release_workflow.contains("A3S_OCI_CRIU_BINARY=/usr/local/lib/a3s-oci-tools/criu-4.2.1")
    );
    assert!(release_workflow.contains("A3S_OCI_GIT_REVISION=\"$GITHUB_SHA\""));
}

#[test]
fn linux_release_archives_bind_and_verify_their_complete_package_manifest() {
    let release_workflow = normalized_release_workflow();
    let qualification = release_workflow
        .find("bash .github/scripts/native-linux-package-smoke.sh \"$package\"")
        .expect("Linux package qualification must be present");
    let manifest_creation = release_workflow
        .find("bash .github/scripts/create-release-package-manifest.sh \"$package\"")
        .expect("Linux package manifest creation must be present");
    let manifest_verification = release_workflow
        .find("bash .github/scripts/verify-release-package-manifest.sh \"$package\"")
        .expect("Linux package manifest verification must be present");
    let archive = release_workflow
        .find("tar -czf \"${package}.tar.gz\" \"$package\"")
        .expect("host package archive must be created");
    assert!(qualification < manifest_creation);
    assert!(manifest_creation < manifest_verification);
    assert!(manifest_verification < archive);
    assert!(release_workflow
        .contains("cp .github/scripts/verify-release-package-manifest.sh \"$package/docs/\""));

    for required in [
        "a3s.oci.release-package-manifest.v1",
        "export LC_ALL=C",
        "qualification/native-linux-package.json",
        "compat/containerd-runtime-v2.json",
        "qualified_protocols",
        "sort_by(.path)",
        "mode: $mode",
        "manifest_size=$(jq -r --arg path \"$path\"",
        "ln -- \"$temporary\" \"$manifest_path\"",
    ] {
        assert!(
            CREATE_RELEASE_PACKAGE_MANIFEST.contains(required),
            "package manifest creation lost {required}"
        );
    }
    for required in [
        "a3s.oci.release-package-manifest.v1",
        "export LC_ALL=C",
        "Release package file inventory differs from its manifest",
        "Release package qualification record does not match its manifest",
        "Release package compatibility record does not match its manifest",
        "select(([.qualification_runs[].protocols] | unique) == $expected_protocols)",
        "find -P \"$package_directory\" -type l",
        "Manifest file is not a regular nonsymlink file",
        "actual_mode=$(stat --format '%a' -- \"$path\")",
        "report_size=$(jq -r \"$report_size_pointer\" \"$qualification_report\")",
    ] {
        assert!(
            VERIFY_RELEASE_PACKAGE_MANIFEST.contains(required),
            "package manifest verification lost {required}"
        );
    }
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
    assert!(NATIVE_LINUX_PACKAGE_SMOKE.contains("and (.evidence | length == 13)"));
}

#[test]
fn native_package_qualification_pins_upstream_oci_bundle_validation() {
    for required in [
        "a3s.oci.upstream-runtime-tools-lock.v2",
        "https://github.com/opencontainers/runtime-tools.git",
        "8a4db579f5c88af5a0d036fad34bddc9c1f703f3",
        "\"version\": \"0.9.0\"",
        "\"version\": \"1.3.0\"",
        "\"go_version\": \"go1.24.0\"",
        "\"buildvcs\": false",
        "\"static_elf\": true",
        "\"lifecycle_validation\": \"native-linux-core-qualified-v1\"",
        "\"validated_architectures\":",
        "\"preflight_architectures\":",
        "\"rootfs_sources\":",
        "alpine-minirootfs-3.22.5-aarch64.tar.gz",
        "3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70",
        "alpine-minirootfs-3.22.5-x86_64.tar.gz",
        "4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282",
        "\"runtime-tools-start-process-unset-inverted-assertion\"",
        "\"runtime-tools-pidfile-true-kill-race\"",
        "\"stdio-descriptor-transport\"",
        "\"terminal-console-socket\"",
        "\"listen-fds\"",
    ] {
        assert!(
            UPSTREAM_RUNTIME_TOOLS_LOCK.contains(required),
            "Upstream Runtime Tools lock lost {required}"
        );
    }
    for required in [
        "CGO_ENABLED=0 GOFLAGS=-mod=readonly",
        "-trimpath -buildvcs=false",
        "git -C \"$source_directory\" diff --exit-code",
        "a3s.oci.upstream-runtime-tools-build.v3",
        "tool runtimetest \"${validation_targets[@]}\"",
        "rootfs-$go_architecture.tar.gz",
        "curl --fail --location --retry 3",
        "rootfs.source == $rootfs_source",
        "expected_destination=\"/usr/local/lib/a3s-oci-tools/runtime-tools-$upstream_commit\"",
        "install -m 0755 -o root -g root",
    ] {
        assert!(
            BUILD_PINNED_RUNTIME_TOOLS.contains(required),
            "Pinned Runtime Tools builder lost {required}"
        );
    }
    for required in [
        "lock_file=\"$repository_root/compat/upstream-runtime-tools.json\"",
        "--host-specific=false",
        "--compliance-level MUST",
        "native-linux=fixtures/native-linux/config.json",
        "utility-vm=fixtures/utility-vm/config.json",
        "negative_escape_rejected",
        "lifecycle_cli_adapter_integrated: true",
        "lifecycle_cli_adapter_qualified: false",
    ] {
        assert!(
            UPSTREAM_BUNDLE_VALIDATION.contains(required)
                || NATIVE_LINUX_PACKAGE_SMOKE.contains(required),
            "Upstream OCI bundle gate lost {required}"
        );
    }
    assert_eq!(
        UPSTREAM_BUNDLE_VALIDATION
            .matches("Refusing to replace an upstream OCI bundle temporary report")
            .count(),
        2,
        "Temporary report identity must be checked before and after canonicalization"
    );
    assert!(NATIVE_LINUX_PACKAGE_SMOKE
        .contains("Packaged Runtime Tools lock differs from the qualification source lock"));
    assert!(!UPSTREAM_BUNDLE_VALIDATION.contains("8a4db579f5c88af5a0d036fad34bddc9c1f703f3"));
    assert!(!NATIVE_LINUX_PACKAGE_SMOKE.contains("8a4db579f5c88af5a0d036fad34bddc9c1f703f3"));
}

#[test]
fn native_package_qualification_retains_the_pinned_upstream_lifecycle_qualification() {
    for required in [
        "a3s.oci.upstream-lifecycle-validation.v1",
        "native-linux-core-v1",
        "RUNTIME=\"$runtime_binary\"",
        "A3S_OCI_RUNTIME_ENDPOINT=\"$socket_path\"",
        "A3S_OCI_CLI_STATE_ROOT=\"$adapter_root\"",
        "A3S_OCI_CLI_ISOLATION=shared-host-kernel",
        "TAP version 13",
        "runtime-tools-start-process-unset-inverted-assertion",
        "runtime-tools-pidfile-true-kill-race",
        "result: \"conformant-with-upstream-harness-defect\"",
        "and .validation.all_selected_passed == false",
        "all_selected_conformant: true",
        "all_lifecycles_retired: true",
        "service_shutdown_clean: true",
        "core_lifecycle_qualified: true",
        "full_lifecycle_qualified: false",
        "expected_rootfs_path=\"lifecycle/rootfs-$go_architecture.tar.gz\"",
        "rootfs_source: $rootfs_source",
        "print_upstream_failure_diagnostics",
        "$state_root/events/records",
        "durable lifecycle events (last 48 records)",
        "initExitStatus: .initExitStatus",
    ] {
        assert!(
            UPSTREAM_LIFECYCLE_VALIDATION.contains(required),
            "Upstream lifecycle gate lost {required}"
        );
    }
    for test in [
        "create",
        "state",
        "start",
        "kill",
        "killsig",
        "kill_no_effect",
        "delete",
        "pidfile",
        "config_updates_without_affect",
    ] {
        assert!(
            UPSTREAM_RUNTIME_TOOLS_LOCK.contains(&format!("\"{test}\"")),
            "Upstream core lifecycle lock lost {test}"
        );
    }
    assert!(NATIVE_LINUX_PACKAGE_SMOKE
        .contains("bash .github/scripts/upstream-oci-lifecycle-validation.sh"));
    assert!(NATIVE_LINUX_PACKAGE_SMOKE.contains("upstream_lifecycle_status=available"));
    assert!(NATIVE_LINUX_PACKAGE_SMOKE.contains("upstream_core_lifecycle_verified=true"));
    assert!(!NATIVE_LINUX_PACKAGE_SMOKE.contains("upstream_lifecycle_status=unavailable"));
    assert!(!NATIVE_LINUX_PACKAGE_SMOKE.contains("upstream_core_lifecycle_verified=false"));
    assert!(!UPSTREAM_RUNTIME_TOOLS_LOCK.contains("missing-upstream-aarch64-rootfs"));
    assert!(!UPSTREAM_RUNTIME_TOOLS_LOCK.contains("aarch64-upstream-rootfs"));
    assert!(!UPSTREAM_LIFECYCLE_VALIDATION.contains("8a4db579f5c88af5a0d036fad34bddc9c1f703f3"));
    assert_eq!(
        UPSTREAM_LIFECYCLE_VALIDATION
            .matches("print_upstream_failure_diagnostics")
            .count(),
        3,
        "Both lifecycle failure paths must emit bounded durable-state diagnostics"
    );
}

#[test]
fn upstream_lifecycle_lock_pins_qualified_rootfs_inputs_for_both_linux_architectures() {
    let lock: serde_json::Value =
        serde_json::from_str(UPSTREAM_RUNTIME_TOOLS_LOCK).expect("Runtime Tools lock must be JSON");

    assert_eq!(
        lock.pointer("/lifecycle/validated_architectures"),
        Some(&serde_json::json!(["aarch64", "x86_64"]))
    );
    assert_eq!(
        lock.pointer("/lifecycle/preflight_architectures"),
        Some(&serde_json::json!([]))
    );
    assert_eq!(
        lock.pointer("/lifecycle/blockers"),
        Some(&serde_json::json!({}))
    );
    assert_eq!(
        lock.pointer("/lifecycle/rootfs_sources/aarch64"),
        Some(&serde_json::json!({
            "distribution": "alpine",
            "version": "3.22.5",
            "url": "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz",
            "sha256": "3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70",
            "size": 3_966_256
        }))
    );
    assert_eq!(
        lock.pointer("/lifecycle/rootfs_sources/x86_64"),
        Some(&serde_json::json!({
            "distribution": "alpine",
            "version": "3.22.5",
            "url": "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.5-x86_64.tar.gz",
            "sha256": "4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282",
            "size": 3_638_276
        }))
    );
}

#[test]
fn ci_runs_the_pinned_upstream_core_lifecycle_on_both_linux_architectures() {
    let ci_workflow = normalize_newlines(CI_WORKFLOW);

    for required in [
        "upstream-runtime-tools:",
        "name: upstream OCI core lifecycle (${{ matrix.architecture }})",
        "architecture: x86_64",
        "os: ubuntu-latest",
        "rust_target: x86_64-unknown-linux-musl",
        "architecture: aarch64",
        "os: ubuntu-24.04-arm",
        "rust_target: aarch64-unknown-linux-musl",
        "go-version: '1.24.0'",
        "bash .github/scripts/build-pinned-runtime-tools.sh",
        "bash .github/scripts/upstream-oci-lifecycle-validation.sh",
        "upstream-oci-lifecycle-${{ matrix.architecture }}",
        "and .status == \"available\"",
        "and .core_lifecycle_qualified",
    ] {
        assert!(
            ci_workflow.contains(required),
            "Dual-architecture upstream lifecycle CI lost {required}"
        );
    }
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
fn native_package_qualification_normalizes_retained_evidence_permissions() {
    let permission_normalization = NATIVE_LINUX_PACKAGE_SMOKE
        .find("chmod 0644 -- \"$evidence\"")
        .expect("Native package qualification must make retained evidence readable");
    let evidence_hash = NATIVE_LINUX_PACKAGE_SMOKE
        .find("--arg sha256 \"$(sha256sum \"$evidence\" | cut -d ' ' -f 1)\"")
        .expect("Native package qualification lost evidence hashing");

    assert!(
        permission_normalization < evidence_hash,
        "Evidence permissions must be normalized before the package report binds its digest"
    );
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
fn pinned_runtime_tools_install_validates_the_locked_destination_before_publication() {
    let destination_guard = BUILD_PINNED_RUNTIME_TOOLS
        .find("if [[ -e \"$destination\" || -L \"$destination\" ]]; then")
        .expect("Pinned Runtime Tools builder lost the pre-canonical destination guard");
    let canonicalization = BUILD_PINNED_RUNTIME_TOOLS
        .find("destination=\"$(realpath -m -- \"$destination\")\"")
        .expect("Pinned Runtime Tools builder lost destination canonicalization");
    let exact_destination = BUILD_PINNED_RUNTIME_TOOLS
        .find(
            "expected_destination=\"/usr/local/lib/a3s-oci-tools/runtime-tools-$upstream_commit\"",
        )
        .expect("Pinned Runtime Tools builder lost its exact locked destination");
    let parent_identity = BUILD_PINNED_RUNTIME_TOOLS
        .find("destination_parent_mode=\"$(stat --format '%a' -- \"$destination_parent\")\"")
        .expect("Pinned Runtime Tools builder lost install-parent identity validation");
    let publication = BUILD_PINNED_RUNTIME_TOOLS
        .find("install -m 0755 -o root -g root --")
        .expect("Pinned Runtime Tools builder lost root-owned publication");

    assert!(destination_guard < canonicalization);
    assert!(canonicalization < exact_destination);
    assert!(exact_destination < parent_identity);
    assert!(parent_identity < publication);
    assert_eq!(
        BUILD_PINNED_RUNTIME_TOOLS
            .matches("if [[ -e \"$destination\" || -L \"$destination\" ]]; then")
            .count(),
        3,
        "Runtime Tools destination identity must be rechecked after path changes"
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
