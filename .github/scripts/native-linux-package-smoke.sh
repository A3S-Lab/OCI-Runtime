#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <staged-package-directory>\n' "$0" >&2
  exit 2
fi

package_directory=$1
source_commit="${A3S_QUALIFICATION_SOURCE_COMMIT:-}"
criu_binary="${A3S_OCI_CRIU_BINARY:-}"
runtime_tools_binary="${A3S_OCI_UPSTREAM_RUNTIME_TOOL:-}"
runtime_tools_manifest="${A3S_OCI_UPSTREAM_RUNTIME_TOOL_MANIFEST:-}"
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' \
    'A3S_QUALIFICATION_SOURCE_COMMIT must be one lowercase 40-character Git commit' >&2
  exit 2
fi
if [[ -z "$criu_binary" || "$criu_binary" != /* ]] ||
  [[ ! -f "$criu_binary" || -L "$criu_binary" || ! -x "$criu_binary" ]]; then
  printf '%s\n' \
    'A3S_OCI_CRIU_BINARY must name one absolute regular nonsymlink executable' >&2
  exit 2
fi
for runtime_tools_input in "$runtime_tools_binary" "$runtime_tools_manifest"; do
  if [[ -z "$runtime_tools_input" || "$runtime_tools_input" != /* ]] ||
    [[ ! -f "$runtime_tools_input" || -L "$runtime_tools_input" ]]; then
    printf '%s\n' \
      'A3S_OCI_UPSTREAM_RUNTIME_TOOL and its MANIFEST must name absolute regular nonsymlink files' >&2
    exit 2
  fi
done
if [[ ! -x "$runtime_tools_binary" ]]; then
  printf '%s\n' 'A3S_OCI_UPSTREAM_RUNTIME_TOOL must be executable' >&2
  exit 2
fi
runtime_tools_binary="$(realpath -e -- "$runtime_tools_binary")"
runtime_tools_manifest="$(realpath -e -- "$runtime_tools_manifest")"
for runtime_tools_input in "$runtime_tools_binary" "$runtime_tools_manifest"; do
  runtime_tools_mode="$(stat --format '%a' -- "$runtime_tools_input")"
  if [[ "$(stat --format '%u:%g' -- "$runtime_tools_input")" != '0:0' ]] ||
    (((8#$runtime_tools_mode & 8#022) != 0)); then
    printf '%s\n' \
      'OCI Runtime Tools inputs must be root-owned without group/world write access' >&2
    exit 2
  fi
done
criu_binary="$(realpath -e -- "$criu_binary")"
criu_mode="$(stat --format '%a' -- "$criu_binary")"
if [[ "$(stat --format '%u:%g' -- "$criu_binary")" != '0:0' ]] ||
  (((8#$criu_mode & 8#022) != 0)); then
  printf '%s\n' \
    'CRIU must be root-owned without group/world write access' >&2
  exit 2
fi
criu_version_output="$("$criu_binary" --version)"
grep --fixed-strings --line-regexp 'Version: 4.2.1' \
  <<<"$criu_version_output" >/dev/null
grep --fixed-strings --line-regexp 'GitID: v4.2.1' \
  <<<"$criu_version_output" >/dev/null
criu_version='4.2.1'
criu_git_id='v4.2.1'
if [[ ! -d "$package_directory" || -L "$package_directory" ]]; then
  printf 'Staged Native Linux package must be a nonsymlink directory: %s\n' \
    "$package_directory" >&2
  exit 2
fi
package_directory="$(realpath -e -- "$package_directory")"
package_name="$(basename "$package_directory")"
runtime_binary="$package_directory/a3s-oci"
agent_binary="$package_directory/a3s-oci-agent"
shim_binary="$package_directory/containerd-shim-a3s-oci-v2"
runtime_tools_lock="$package_directory/compat/upstream-runtime-tools.json"

required_files=(
  "$runtime_binary"
  "$agent_binary"
  "$shim_binary"
  "$package_directory/README.md"
  "$package_directory/CHANGELOG.md"
  "$package_directory/LICENSE"
  "$package_directory/docs/release-verification.md"
  "$package_directory/docs/checkpoint-contract.md"
  "$package_directory/docs/containerd-runtime-v2.md"
  "$package_directory/compat/containerd-runtime-v2.json"
  "$runtime_tools_lock"
)
for candidate in "${required_files[@]}"; do
  if [[ ! -f "$candidate" || -L "$candidate" ]]; then
    printf 'Native Linux package entry must be a regular nonsymlink file: %s\n' \
      "$candidate" >&2
    exit 1
  fi
done
repository_runtime_tools_lock="$(realpath -e -- compat/upstream-runtime-tools.json)"
if [[ "$(sha256sum "$runtime_tools_lock" | cut -d ' ' -f 1)" != \
  "$(sha256sum "$repository_runtime_tools_lock" | cut -d ' ' -f 1)" ]]; then
  printf '%s\n' \
    'Packaged Runtime Tools lock differs from the qualification source lock' >&2
  exit 1
fi
expected_runtime_tools_commit="$(jq --raw-output '.commit' "$runtime_tools_lock")"
expected_runtime_tools_version="$(jq --raw-output '.version' "$runtime_tools_lock")"
expected_runtime_tools_spec_version="$(
  jq --raw-output '.runtime_spec.version' "$runtime_tools_lock"
)"
expected_runtime_tools_go_version="$(
  jq --raw-output '.build.go_version' "$runtime_tools_lock"
)"
expected_runtime_tools_lifecycle_profile="$(
  jq --raw-output '.lifecycle.profile' "$runtime_tools_lock"
)"
expected_lifecycle_preflight_architectures="$(
  jq --compact-output '.lifecycle.preflight_architectures' "$runtime_tools_lock"
)"
expected_lifecycle_validated_architectures="$(
  jq --compact-output '.lifecycle.validated_architectures' "$runtime_tools_lock"
)"
expected_lifecycle_upstream_harness_defects="$(
  jq --compact-output '.lifecycle.upstream_harness_defects' "$runtime_tools_lock"
)"
expected_aarch64_lifecycle_blocker="$(
  jq --raw-output '.lifecycle.blockers.aarch64' "$runtime_tools_lock"
)"
for executable in "$runtime_binary" "$agent_binary" "$shim_binary"; do
  if [[ ! -x "$executable" ]]; then
    printf 'Native Linux package executable is not executable: %s\n' \
      "$executable" >&2
    exit 1
  fi
done

.github/scripts/verify-static-elf.sh \
  "$runtime_binary" \
  "$agent_binary" \
  "$shim_binary"

runtime_version_output="$("$runtime_binary" --version)"
runtime_version="${runtime_version_output##* }"
if [[ ! "$runtime_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'Packaged runtime returned an invalid version: %s\n' \
    "$runtime_version_output" >&2
  exit 1
fi
runtime_sha256="$(sha256sum "$runtime_binary" | cut -d ' ' -f 1)"
agent_sha256="$(sha256sum "$agent_binary" | cut -d ' ' -f 1)"
shim_sha256="$(sha256sum "$shim_binary" | cut -d ' ' -f 1)"
criu_sha256="$(sha256sum "$criu_binary" | cut -d ' ' -f 1)"
criu_size="$(stat --format '%s' "$criu_binary")"

architecture="$(uname -m)"
case "$architecture" in
  x86_64)
    package_architecture=x86_64
    ;;
  aarch64 | arm64)
    package_architecture=aarch64
    ;;
  *)
    printf 'Unsupported Native Linux package architecture: %s\n' \
      "$architecture" >&2
    exit 2
    ;;
esac
expected_package_name="a3s-oci-runtime-v${runtime_version}-linux-${package_architecture}"
if [[ "$package_name" != "$expected_package_name" ]]; then
  printf 'Native Linux package name mismatch: expected %s, found %s\n' \
    "$expected_package_name" "$package_name" >&2
  exit 1
fi

qualification_directory="$package_directory/qualification"
if [[ -e "$qualification_directory" || -L "$qualification_directory" ]]; then
  printf 'Refusing to reuse Native Linux qualification directory: %s\n' \
    "$qualification_directory" >&2
  exit 2
fi
mkdir -m 0755 "$qualification_directory"

features_report="$qualification_directory/features.json"
soak_report="$qualification_directory/native-linux-soak.json"
recovery_report="$qualification_directory/native-linux-recovery.json"
hook_recovery_report="$qualification_directory/native-linux-hook-recovery.json"
rootless_recovery_report="$qualification_directory/native-linux-rootless-recovery.json"
rootless_device_report="$qualification_directory/native-linux-rootless-device-policy.json"
network_enforcement_report="$qualification_directory/native-linux-network-enforcement.json"
kvm_absence_report="$qualification_directory/native-linux-kvm-absence.json"
checkpoint_report="$qualification_directory/native-linux-checkpoint.json"
checkpoint_pidns_report="$qualification_directory/native-linux-checkpoint-pidns.json"
checkpoint_netns_report="$qualification_directory/native-linux-checkpoint-netns.json"
upstream_bundle_report="$qualification_directory/upstream-oci-bundles.json"
upstream_lifecycle_report="$qualification_directory/upstream-oci-lifecycle.json"
package_report="$qualification_directory/native-linux-package.json"

"$runtime_binary" features >"$features_report"
jq --exit-status \
  '.schema_version == "a3s.oci.features.v1"
   and .platform == "linux"
   and any(
     .drivers[];
     .driver == "native-linux"
     and .status == "available"
     and .readiness == "probe-only"
     and (.isolation_classes | index("shared-host-kernel")) != null
   )' \
  "$features_report" >/dev/null

bash .github/scripts/upstream-oci-bundle-validation.sh \
  "$runtime_tools_binary" \
  "$runtime_tools_manifest" \
  "$runtime_binary" \
  "$agent_binary" \
  "$shim_binary" \
  "$source_commit" \
  "$upstream_bundle_report" \
  native-linux=fixtures/native-linux/config.json \
  utility-vm=fixtures/utility-vm/config.json
jq --exit-status \
  --arg source_commit "$source_commit" \
  --arg runtime_sha256 "$runtime_sha256" \
  --arg agent_sha256 "$agent_sha256" \
  --arg shim_sha256 "$shim_sha256" \
  --arg upstream_commit "$expected_runtime_tools_commit" \
  --arg runtime_spec_version "$expected_runtime_tools_spec_version" \
  '.schema_version == "a3s.oci.upstream-bundle-validation.v1"
   and .status == "available"
   and .source_commit == $source_commit
   and .upstream.commit == $upstream_commit
   and .upstream.runtime_spec_version == $runtime_spec_version
   and .package_executables.runtime.sha256 == $runtime_sha256
   and .package_executables.agent.sha256 == $agent_sha256
   and .package_executables.containerd_shim.sha256 == $shim_sha256
   and (.validation.bundles | length) == 2
   and all(.validation.bundles[]; .result == "passed")
   and .validation.negative_escape_rejected
   and .lifecycle_cli_adapter_integrated
   and .lifecycle_cli_adapter_qualified == false' \
  "$upstream_bundle_report" >/dev/null

bash .github/scripts/upstream-oci-lifecycle-validation.sh \
  "$runtime_tools_binary" \
  "$runtime_tools_manifest" \
  "$runtime_binary" \
  "$agent_binary" \
  "$source_commit" \
  "$upstream_lifecycle_report"
if [[ "$package_architecture" == x86_64 ]]; then
  upstream_lifecycle_status=available
  upstream_lifecycle_blocker_json=null
  upstream_core_lifecycle_verified=true
  jq --exit-status \
    --arg source_commit "$source_commit" \
    --arg runtime_sha256 "$runtime_sha256" \
    --arg agent_sha256 "$agent_sha256" \
    --arg upstream_commit "$expected_runtime_tools_commit" \
    --arg runtime_spec_version "$expected_runtime_tools_spec_version" \
    --argjson upstream_harness_defects "$expected_lifecycle_upstream_harness_defects" \
    '.schema_version == "a3s.oci.upstream-lifecycle-validation.v1"
     and .status == "available"
     and .reason == null
     and .blocker == null
     and .source_commit == $source_commit
     and .architecture == "x86_64"
     and .upstream.commit == $upstream_commit
     and .upstream.runtime_spec_version == $runtime_spec_version
     and .package_executables.runtime.sha256 == $runtime_sha256
     and .package_executables.agent.sha256 == $agent_sha256
     and (.validation.selected_tests | length) == 9
     and [.validation.results[].name] == .validation.selected_tests
     and ([.validation.results[] | select(.result == "passed")] | length) == 7
     and ([
       .validation.results[]
       | select(.result == "conformant-with-upstream-harness-defect")
     ] | length) == 2
     and all(
       .validation.results[];
       .result == "passed"
       or (
         .result == "conformant-with-upstream-harness-defect"
         and (
           (
             .name == "start"
             and .upstream_harness_defect ==
               "runtime-tools-start-process-unset-inverted-assertion"
           )
           or (
             .name == "pidfile"
             and .upstream_harness_defect ==
               "runtime-tools-pidfile-true-kill-race"
           )
         )
         and .tap_failures == 1
       )
     )
     and .validation.upstream_harness_defects == $upstream_harness_defects
     and .validation.all_selected_passed == false
     and .validation.all_selected_conformant
     and .validation.all_lifecycles_retired
     and .validation.service_shutdown_clean
     and .core_lifecycle_qualified
     and .full_lifecycle_qualified == false' \
    "$upstream_lifecycle_report" >/dev/null
else
  upstream_lifecycle_status=unavailable
  upstream_lifecycle_blocker="$expected_aarch64_lifecycle_blocker"
  upstream_lifecycle_blocker_json="$(
    jq --compact-output --null-input \
      --arg blocker "$upstream_lifecycle_blocker" '$blocker'
  )"
  upstream_core_lifecycle_verified=false
  jq --exit-status \
    --arg source_commit "$source_commit" \
    --arg runtime_sha256 "$runtime_sha256" \
    --arg agent_sha256 "$agent_sha256" \
    --arg upstream_commit "$expected_runtime_tools_commit" \
    --arg blocker "$upstream_lifecycle_blocker" \
    '.schema_version == "a3s.oci.upstream-lifecycle-validation.v1"
     and .status == "unavailable"
     and (.reason | type == "string" and length > 0)
     and .blocker == $blocker
     and .source_commit == $source_commit
     and .architecture == "aarch64"
     and .upstream.commit == $upstream_commit
     and .package_executables.runtime.sha256 == $runtime_sha256
     and .package_executables.agent.sha256 == $agent_sha256
     and (.validation.selected_tests | length) == 9
     and (.validation.results | length) == 0
     and .validation.all_selected_passed == false
     and .validation.all_lifecycles_retired == false
     and .validation.service_shutdown_clean == false
     and .core_lifecycle_qualified == false
     and .full_lifecycle_qualified == false
     and (.limitations | index("aarch64-upstream-rootfs")) != null' \
    "$upstream_lifecycle_report" >/dev/null
fi

A3S_OCI_NATIVE_RUNTIME_BINARY="$runtime_binary" \
A3S_OCI_NATIVE_AGENT_BINARY="$agent_binary" \
A3S_OCI_NATIVE_SOAK_ITERATIONS=25 \
A3S_OCI_NATIVE_SOAK_REPORT="$soak_report" \
A3S_OCI_NATIVE_RECOVERY_REPORT="$recovery_report" \
A3S_OCI_NATIVE_HOOK_RECOVERY_REPORT="$hook_recovery_report" \
A3S_OCI_NATIVE_ROOTLESS_RECOVERY_REPORT="$rootless_recovery_report" \
A3S_OCI_NATIVE_ROOTLESS_DEVICE_POLICY_REPORT="$rootless_device_report" \
A3S_OCI_NATIVE_NETWORK_ENFORCEMENT_REPORT="$network_enforcement_report" \
A3S_OCI_NATIVE_KVM_ABSENCE_EVIDENCE="$kvm_absence_report" \
  bash <(tr -d '\015' < .github/scripts/native-linux-smoke.sh)

jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-soak.v2"
   and .status == "available"
   and .configuration.iterations == 25
   and .configuration.concurrent_containers == 4
   and .completed_iterations == 25
   and .completed_container_lifecycles == 100
   and .durable_reopens == 50
   and (.pause_resume_evidence | length) == 100
   and all(
     .pause_resume_evidence[];
     .progress_after_pause_reopen == .progress_at_pause
     and .progress_after_resume > .progress_after_pause_reopen
     and .progress_after_resume_reopen > .progress_after_resume
     and .pause_response_replayed_after_reopen
     and .resume_response_replayed_after_reopen
   )' \
  "$soak_report" >/dev/null
jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-recovery-smoke.v2"
   and .status == "available"' \
  "$recovery_report" >/dev/null
jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-hook-owner-death-smoke.v1"
   and .status == "available"' \
  "$hook_recovery_report" >/dev/null
jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-recovery-smoke.v2"
   and .status == "available"
   and .cgroup_delegation_requested
   and .cgroup_delegation_verified' \
  "$rootless_recovery_report" >/dev/null
jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-rootless-smoke.v4"
   and .status == "available"' \
  "$rootless_device_report" >/dev/null
jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-network-enforcement-smoke.v1"
   and .status == "available"
   and .extension_advertised
   and .mechanism_verified_before_create
   and .host_service_reopened
   and .attachment_replayed_after_reopen
   and .namespace_preserved_after_delete
   and .interface_preserved_after_delete
   and .mechanism_preserved_after_delete' \
  "$network_enforcement_report" >/dev/null
jq --exit-status --arg architecture "$architecture" \
  '.schema_version == "a3s.oci.native-linux-kvm-absence.v1"
   and .platform == "linux"
   and .architecture == $architecture
   and .device_absent_before_lifecycle' \
  "$kvm_absence_report" >/dev/null

A3S_OCI_NATIVE_RUNTIME_BINARY="$runtime_binary" \
A3S_OCI_NATIVE_AGENT_BINARY="$agent_binary" \
A3S_OCI_CRIU_BINARY="$criu_binary" \
A3S_QUALIFICATION_SOURCE_COMMIT="$source_commit" \
A3S_OCI_NATIVE_CHECKPOINT_REPORT="$checkpoint_report" \
A3S_OCI_NATIVE_CHECKPOINT_PIDNS_REPORT="$checkpoint_pidns_report" \
A3S_OCI_NATIVE_CHECKPOINT_NETNS_REPORT="$checkpoint_netns_report" \
  bash <(tr -d '\015' < .github/scripts/native-linux-checkpoint.sh)

criu_digest="sha256:$criu_sha256"
checkpoint_driver_build_digest="$(
  jq --raw-output --exit-status \
    '.driverEvidence.checkpoint_driver_build_digest
     | select(type == "string" and test("^sha256:[0-9a-f]{64}$"))' \
    "$checkpoint_report"
)"
jq --exit-status \
  --arg source_commit "$source_commit" \
  --arg checkpoint_driver_build_digest "$checkpoint_driver_build_digest" \
  --arg criu_digest "$criu_digest" \
  --arg criu_version "$criu_version" \
  '
    .schemaVersion == "a3s.oci.native-linux-checkpoint-smoke.v3"
    and .status == "available"
    and .sourceRevision == $source_commit
    and .checkpointAdvertised and .restoreAdvertised
    and .restoreAfterCallOwnerReplaced
    and .restoreAfterCallServiceReopened
    and .restoreAfterCallReplayExact
    and .restoreAfterCommitOwnerReplaced
    and .restoreAfterCommitServiceReopened
    and .restoreAfterCommitReplayExact
    and .crossProcessRestoredPidsLive
    and .crossProcessArtifactUnchanged
    and .crossProcessRestoreCleanupExact
    and .driverJournalAcknowledged
    and .unpublishedPartialsAbsent
    and .executorRuntimeClean
    and .sessionRootClean
    and .driverEvidence.checkpoint_driver_build_digest == $checkpoint_driver_build_digest
    and .driverEvidence.checkpoint_source_revision == $source_commit
    and .driverEvidence.checkpoint_criu_digest == $criu_digest
    and .driverEvidence.checkpoint_criu_version == $criu_version
  ' \
  "$checkpoint_report" >/dev/null
for checkpoint_negative_report in \
  "$checkpoint_pidns_report" \
  "$checkpoint_netns_report"; do
  jq --exit-status \
    --arg source_commit "$source_commit" \
    --arg checkpoint_driver_build_digest "$checkpoint_driver_build_digest" \
    --arg criu_digest "$criu_digest" \
    --arg criu_version "$criu_version" \
    '
      .schemaVersion == "a3s.oci.native-linux-checkpoint-smoke.v3"
      and .status == "unavailable"
      and .sourceRevision == $source_commit
      and .checkpointAdvertised and .restoreAdvertised
      and .pausedSourceObserved
      and .preexistingDestinationRejected
      and .preexistingDestinationPreserved
      and .driverJournalAcknowledged
      and .unpublishedPartialsAbsent
      and .executorRuntimeClean
      and .sessionRootClean
      and .driverEvidence.checkpoint_driver_build_digest == $checkpoint_driver_build_digest
      and .driverEvidence.checkpoint_source_revision == $source_commit
      and .driverEvidence.checkpoint_criu_digest == $criu_digest
      and .driverEvidence.checkpoint_criu_version == $criu_version
      and (.reason | type == "string" and length > 0)
    ' \
    "$checkpoint_negative_report" >/dev/null
done

evidence_manifest="$qualification_directory/.evidence.jsonl"
for evidence in \
  "$features_report" \
  "$soak_report" \
  "$recovery_report" \
  "$hook_recovery_report" \
  "$rootless_recovery_report" \
  "$rootless_device_report" \
  "$network_enforcement_report" \
  "$kvm_absence_report" \
  "$checkpoint_report" \
  "$checkpoint_pidns_report" \
  "$checkpoint_netns_report" \
  "$upstream_bundle_report" \
  "$upstream_lifecycle_report"; do
  if [[ ! -f "$evidence" || -L "$evidence" ]]; then
    printf 'Native Linux package evidence must be a regular nonsymlink file: %s\n' \
      "$evidence" >&2
    exit 1
  fi
  chmod 0644 -- "$evidence"
  if [[ "$(stat --format '%a' -- "$evidence")" != 644 ]]; then
    printf 'Native Linux package evidence mode normalization failed: %s\n' \
      "$evidence" >&2
    exit 1
  fi
  evidence_schema="$(
    jq --raw-output --exit-status \
      '(.schema_version // .schemaVersion)
       | select(type == "string" and length > 0)' \
      "$evidence"
  )"
  jq --compact-output --null-input \
    --arg name "$(basename "$evidence")" \
    --arg schema_version "$evidence_schema" \
    --arg sha256 "$(sha256sum "$evidence" | cut -d ' ' -f 1)" \
    --argjson size "$(stat --format '%s' "$evidence")" \
    '{
      name: $name,
      schema_version: $schema_version,
      sha256: $sha256,
      size: $size
    }' >>"$evidence_manifest"
done

workflow_run_id="${GITHUB_RUN_ID:-}"
runtime_tools_commit="$(jq --raw-output '.upstream.commit' "$upstream_bundle_report")"
runtime_tools_version="$(jq --raw-output '.upstream.version' "$upstream_bundle_report")"
runtime_tools_spec_version="$(jq --raw-output '.upstream.runtime_spec_version' "$upstream_bundle_report")"
runtime_tools_go_version="$(jq --raw-output '.upstream.go_version' "$upstream_bundle_report")"
runtime_tools_sha256="$(jq --raw-output '.upstream.tool_sha256' "$upstream_bundle_report")"
runtime_tools_size="$(jq --raw-output '.upstream.tool_size' "$upstream_bundle_report")"
runtime_tools_manifest_sha256="$(jq --raw-output '.upstream.build_manifest_sha256' "$upstream_bundle_report")"
jq --null-input \
  --arg schema_version 'a3s.oci.native-linux-package-qualification.v6' \
  --arg status 'available' \
  --arg source_commit "$source_commit" \
  --arg workflow_run_id "$workflow_run_id" \
  --arg platform 'linux' \
  --arg architecture "$package_architecture" \
  --arg kernel_release "$(uname -r)" \
  --arg driver 'native-linux' \
  --arg isolation_class 'shared-host-kernel' \
  --arg profile 'full-sdk-oar01-oar02-oar03-upstream-lifecycle-qualified-without-kvm-v6' \
  --arg package_name "$package_name" \
  --arg runtime_version "$runtime_version" \
  --arg runtime_sha256 "$runtime_sha256" \
  --argjson runtime_size "$(stat --format '%s' "$runtime_binary")" \
  --arg agent_sha256 "$agent_sha256" \
  --argjson agent_size "$(stat --format '%s' "$agent_binary")" \
  --arg shim_sha256 "$shim_sha256" \
  --argjson shim_size "$(stat --format '%s' "$shim_binary")" \
  --arg criu_version "$criu_version" \
  --arg criu_git_id "$criu_git_id" \
  --arg criu_sha256 "$criu_sha256" \
  --argjson criu_size "$criu_size" \
  --arg runtime_tools_commit "$runtime_tools_commit" \
  --arg runtime_tools_version "$runtime_tools_version" \
  --arg runtime_tools_spec_version "$runtime_tools_spec_version" \
  --arg runtime_tools_go_version "$runtime_tools_go_version" \
  --arg runtime_tools_sha256 "$runtime_tools_sha256" \
  --argjson runtime_tools_size "$runtime_tools_size" \
  --arg runtime_tools_manifest_sha256 "$runtime_tools_manifest_sha256" \
  --arg runtime_tools_lifecycle_profile "$expected_runtime_tools_lifecycle_profile" \
  --argjson lifecycle_preflight_architectures "$expected_lifecycle_preflight_architectures" \
  --argjson lifecycle_validated_architectures "$expected_lifecycle_validated_architectures" \
  --argjson lifecycle_upstream_harness_defects "$expected_lifecycle_upstream_harness_defects" \
  --arg upstream_lifecycle_status "$upstream_lifecycle_status" \
  --argjson upstream_lifecycle_blocker "$upstream_lifecycle_blocker_json" \
  --argjson upstream_core_lifecycle_verified "$upstream_core_lifecycle_verified" \
  --arg checkpoint_driver_build_digest "$checkpoint_driver_build_digest" \
  --slurpfile evidence "$evidence_manifest" \
  '{
    schema_version: $schema_version,
    status: $status,
    source_commit: $source_commit,
    workflow_run_id: (if $workflow_run_id == "" then null else $workflow_run_id end),
    platform: $platform,
    architecture: $architecture,
    kernel_release: $kernel_release,
    driver: $driver,
    isolation_class: $isolation_class,
    profile: $profile,
    package_name: $package_name,
    runtime_version: $runtime_version,
    executables: {
      runtime: {sha256: $runtime_sha256, size: $runtime_size},
      agent: {sha256: $agent_sha256, size: $agent_size},
      containerd_shim: {sha256: $shim_sha256, size: $shim_size}
    },
    external_tools: {
      criu: {
        packaged: false,
        version: $criu_version,
        git_id: $criu_git_id,
        sha256: $criu_sha256,
        size: $criu_size
      },
      oci_runtime_tools: {
        packaged: false,
        commit: $runtime_tools_commit,
        version: $runtime_tools_version,
        runtime_spec_version: $runtime_tools_spec_version,
        go_version: $runtime_tools_go_version,
        sha256: $runtime_tools_sha256,
        size: $runtime_tools_size,
        build_manifest_sha256: $runtime_tools_manifest_sha256,
        lifecycle_profile: $runtime_tools_lifecycle_profile,
        lifecycle_preflight_architectures: $lifecycle_preflight_architectures,
        lifecycle_validated_architectures: $lifecycle_validated_architectures,
        lifecycle_upstream_harness_defects: $lifecycle_upstream_harness_defects
      }
    },
    checkpoint_driver_build_digest: $checkpoint_driver_build_digest,
    package_layout_verified: true,
    static_elf_verified: true,
    features_verified: true,
    kvm_absent_before_lifecycle: true,
    full_sdk_matrix_completed: true,
    oar02_pause_resume_verified: true,
    oar03_checkpoint_restore_verified: true,
    upstream_bundle_validation_verified: true,
    upstream_lifecycle_validation_status: $upstream_lifecycle_status,
    upstream_lifecycle_blocker: $upstream_lifecycle_blocker,
    upstream_core_lifecycle_verified: $upstream_core_lifecycle_verified,
    upstream_full_lifecycle_verified: false,
    evidence: $evidence
  }' >"$package_report.tmp"
chmod 0644 "$package_report.tmp"
mv "$package_report.tmp" "$package_report"
rm "$evidence_manifest"

jq --exit-status \
  --arg runtime_tools_commit "$expected_runtime_tools_commit" \
  --arg runtime_tools_version "$expected_runtime_tools_version" \
  --arg runtime_tools_spec_version "$expected_runtime_tools_spec_version" \
  --arg runtime_tools_go_version "$expected_runtime_tools_go_version" \
  --arg runtime_tools_lifecycle_profile "$expected_runtime_tools_lifecycle_profile" \
  --argjson lifecycle_preflight_architectures "$expected_lifecycle_preflight_architectures" \
  --argjson lifecycle_validated_architectures "$expected_lifecycle_validated_architectures" \
  --argjson lifecycle_upstream_harness_defects "$expected_lifecycle_upstream_harness_defects" \
  --arg upstream_lifecycle_status "$upstream_lifecycle_status" \
  --argjson upstream_lifecycle_blocker "$upstream_lifecycle_blocker_json" \
  --argjson upstream_core_lifecycle_verified "$upstream_core_lifecycle_verified" \
  'select(
     .schema_version == "a3s.oci.native-linux-package-qualification.v6"
     and .status == "available"
     and .package_layout_verified
     and .static_elf_verified
     and .features_verified
     and .kvm_absent_before_lifecycle
     and .full_sdk_matrix_completed
     and .oar02_pause_resume_verified
     and .oar03_checkpoint_restore_verified
     and .upstream_bundle_validation_verified
     and .upstream_lifecycle_validation_status == $upstream_lifecycle_status
     and .upstream_lifecycle_blocker == $upstream_lifecycle_blocker
     and .upstream_core_lifecycle_verified == $upstream_core_lifecycle_verified
     and .upstream_full_lifecycle_verified == false
     and .external_tools.criu.packaged == false
     and .external_tools.criu.version == "4.2.1"
     and .external_tools.criu.git_id == "v4.2.1"
     and (.external_tools.criu.sha256 | test("^[0-9a-f]{64}$"))
     and (.external_tools.criu.size > 0)
     and .external_tools.oci_runtime_tools.packaged == false
     and .external_tools.oci_runtime_tools.commit == $runtime_tools_commit
     and .external_tools.oci_runtime_tools.version == $runtime_tools_version
     and .external_tools.oci_runtime_tools.runtime_spec_version == $runtime_tools_spec_version
     and .external_tools.oci_runtime_tools.go_version == $runtime_tools_go_version
     and (.external_tools.oci_runtime_tools.sha256 | test("^[0-9a-f]{64}$"))
     and (.external_tools.oci_runtime_tools.size > 0)
     and (.external_tools.oci_runtime_tools.build_manifest_sha256 | test("^[0-9a-f]{64}$"))
     and .external_tools.oci_runtime_tools.lifecycle_profile == $runtime_tools_lifecycle_profile
     and .external_tools.oci_runtime_tools.lifecycle_preflight_architectures == $lifecycle_preflight_architectures
     and .external_tools.oci_runtime_tools.lifecycle_validated_architectures == $lifecycle_validated_architectures
     and .external_tools.oci_runtime_tools.lifecycle_upstream_harness_defects == $lifecycle_upstream_harness_defects
     and (.checkpoint_driver_build_digest | test("^sha256:[0-9a-f]{64}$"))
     and (.evidence | length == 13)
   )' \
  "$package_report"
