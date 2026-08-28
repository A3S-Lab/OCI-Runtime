#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <staged-package-directory>\n' "$0" >&2
  exit 2
fi

package_directory=$1
source_commit="${A3S_QUALIFICATION_SOURCE_COMMIT:-}"
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' \
    'A3S_QUALIFICATION_SOURCE_COMMIT must be one lowercase 40-character Git commit' >&2
  exit 2
fi
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

required_files=(
  "$runtime_binary"
  "$agent_binary"
  "$shim_binary"
  "$package_directory/README.md"
  "$package_directory/CHANGELOG.md"
  "$package_directory/LICENSE"
  "$package_directory/docs/release-verification.md"
  "$package_directory/docs/containerd-runtime-v2.md"
  "$package_directory/compat/containerd-runtime-v2.json"
)
for candidate in "${required_files[@]}"; do
  if [[ ! -f "$candidate" || -L "$candidate" ]]; then
    printf 'Native Linux package entry must be a regular nonsymlink file: %s\n' \
      "$candidate" >&2
    exit 1
  fi
done
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
  '.schema_version == "a3s.oci.native-linux-soak.v1"
   and .status == "available"
   and .configuration.iterations == 25
   and .configuration.concurrent_containers == 4
   and .completed_iterations == 25
   and .completed_container_lifecycles == 100' \
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

evidence_manifest="$qualification_directory/.evidence.jsonl"
for evidence in \
  "$features_report" \
  "$soak_report" \
  "$recovery_report" \
  "$hook_recovery_report" \
  "$rootless_recovery_report" \
  "$rootless_device_report" \
  "$network_enforcement_report" \
  "$kvm_absence_report"; do
  jq --compact-output --null-input \
    --arg name "$(basename "$evidence")" \
    --arg schema_version "$(jq --raw-output '.schema_version' "$evidence")" \
    --arg sha256 "$(sha256sum "$evidence" | cut -d ' ' -f 1)" \
    --argjson size "$(stat --format '%s' "$evidence")" \
    '{
      name: $name,
      schema_version: $schema_version,
      sha256: $sha256,
      size: $size
    }' >>"$evidence_manifest"
done

runtime_sha256="$(sha256sum "$runtime_binary" | cut -d ' ' -f 1)"
agent_sha256="$(sha256sum "$agent_binary" | cut -d ' ' -f 1)"
shim_sha256="$(sha256sum "$shim_binary" | cut -d ' ' -f 1)"
workflow_run_id="${GITHUB_RUN_ID:-}"
jq --null-input \
  --arg schema_version 'a3s.oci.native-linux-package-qualification.v2' \
  --arg status 'available' \
  --arg source_commit "$source_commit" \
  --arg workflow_run_id "$workflow_run_id" \
  --arg platform 'linux' \
  --arg architecture "$package_architecture" \
  --arg kernel_release "$(uname -r)" \
  --arg driver 'native-linux' \
  --arg isolation_class 'shared-host-kernel' \
  --arg profile 'full-sdk-oar01-without-kvm-v2' \
  --arg package_name "$package_name" \
  --arg runtime_version "$runtime_version" \
  --arg runtime_sha256 "$runtime_sha256" \
  --argjson runtime_size "$(stat --format '%s' "$runtime_binary")" \
  --arg agent_sha256 "$agent_sha256" \
  --argjson agent_size "$(stat --format '%s' "$agent_binary")" \
  --arg shim_sha256 "$shim_sha256" \
  --argjson shim_size "$(stat --format '%s' "$shim_binary")" \
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
    package_layout_verified: true,
    static_elf_verified: true,
    features_verified: true,
    kvm_absent_before_lifecycle: true,
    full_sdk_matrix_completed: true,
    evidence: $evidence
  }' >"$package_report.tmp"
chmod 0644 "$package_report.tmp"
mv "$package_report.tmp" "$package_report"
rm "$evidence_manifest"

jq --exit-status \
  'select(
     .schema_version == "a3s.oci.native-linux-package-qualification.v2"
     and .status == "available"
     and .package_layout_verified
     and .static_elf_verified
     and .features_verified
     and .kvm_absent_before_lifecycle
     and .full_sdk_matrix_completed
     and (.evidence | length == 8)
   )' \
  "$package_report"
