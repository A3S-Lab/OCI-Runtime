#!/usr/bin/env bash

set -euo pipefail

validation_root=''

cleanup() {
  local command_status=$?
  local cleanup_status=0

  trap - EXIT
  if [[ -n "$validation_root" ]]; then
    case "$validation_root" in
      /var/tmp/a3s-oci-upstream-bundles.????????)
        rm -rf --one-file-system -- "$validation_root" || cleanup_status=1
        ;;
      *)
        printf 'Refusing to remove unexpected upstream validation root: %s\n' \
          "$validation_root" >&2
        cleanup_status=1
        ;;
    esac
  fi
  if ((command_status != 0)); then
    exit "$command_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

if [[ "$#" -lt 9 ]]; then
  printf '%s\n' \
    "usage: $0 <tool> <tool-build.json> <runtime> <agent> <shim> <source-commit> <report> <name=config.json>..." >&2
  exit 2
fi

tool=$1
tool_manifest=$2
runtime_binary=$3
agent_binary=$4
shim_binary=$5
source_commit=$6
report=$7
shift 7

if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'Source commit must be one lowercase 40-character Git commit' >&2
  exit 2
fi
for command in basename chmod cp cut dirname file grep jq mkdir mktemp mv \
  readelf realpath rm sed sha256sum stat; do
  command -v "$command" >/dev/null || {
    printf 'Upstream OCI bundle validation requires %s\n' "$command" >&2
    exit 2
  }
done

script_directory="$(dirname -- "$(realpath -e -- "$0")")"
repository_root="$(realpath -e -- "$script_directory/../..")"
lock_file="$repository_root/compat/upstream-runtime-tools.json"
if [[ ! -f "$lock_file" || -L "$lock_file" ]]; then
  printf 'Runtime Tools lock must be a regular nonsymlink file: %s\n' \
    "$lock_file" >&2
  exit 2
fi
jq --exit-status \
  '.schema_version == "a3s.oci.upstream-runtime-tools-lock.v1"
   and (.repository | type == "string" and length > 0)
   and (.commit | test("^[0-9a-f]{40}$"))
   and (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
   and (.runtime_spec.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
   and (.runtime_spec.module_sum | startswith("h1:"))
   and (.build.go_version | test("^go[0-9]+\\.[0-9]+\\.[0-9]+$"))
   and .build.cgo_enabled == false
   and .build.trimpath == true
   and .build.buildvcs == false
   and .build.static_elf == true
   and .upstream_interface == "oci-runtime-command-line-interface"
   and .integration.bundle_validation == "native-linux-package"
   and .integration.lifecycle_validation == "native-linux-core-qualified-v1"
   and .lifecycle.profile == "native-linux-core-v1"
   and .lifecycle.validated_architectures == ["x86_64"]
   and .lifecycle.preflight_architectures == []
   and (.lifecycle.blockers | keys) == ["aarch64"]
   and .lifecycle.blockers.aarch64 == "missing-upstream-aarch64-rootfs"
   and .lifecycle.upstream_harness_defects == [
     "runtime-tools-start-process-unset-inverted-assertion",
     "runtime-tools-pidfile-true-kill-race"
   ]
   and (.lifecycle.tests | length) > 0' \
  "$lock_file" >/dev/null

upstream_repository="$(jq --raw-output '.repository' "$lock_file")"
upstream_commit="$(jq --raw-output '.commit' "$lock_file")"
upstream_version="$(jq --raw-output '.version' "$lock_file")"
runtime_spec_version="$(jq --raw-output '.runtime_spec.version' "$lock_file")"
runtime_spec_sum="$(jq --raw-output '.runtime_spec.module_sum' "$lock_file")"
required_go_version="$(jq --raw-output '.build.go_version' "$lock_file")"
lifecycle_profile="$(jq --raw-output '.lifecycle.profile' "$lock_file")"
lifecycle_test_count="$(jq --raw-output '.lifecycle.tests | length' "$lock_file")"

for executable in "$tool" "$runtime_binary" "$agent_binary" "$shim_binary"; do
  if [[ "$executable" != /* ]] ||
    [[ ! -f "$executable" || -L "$executable" || ! -x "$executable" ]]; then
    printf 'Upstream validation executable must be absolute, regular, nonsymlink, and executable: %s\n' \
      "$executable" >&2
    exit 2
  fi
done
tool="$(realpath -e -- "$tool")"
runtime_binary="$(realpath -e -- "$runtime_binary")"
agent_binary="$(realpath -e -- "$agent_binary")"
shim_binary="$(realpath -e -- "$shim_binary")"
if [[ "$tool_manifest" != /* ]] ||
  [[ ! -f "$tool_manifest" || -L "$tool_manifest" ]]; then
  printf 'Runtime Tools build manifest must be an absolute regular nonsymlink file: %s\n' \
    "$tool_manifest" >&2
  exit 2
fi
tool_manifest="$(realpath -e -- "$tool_manifest")"
for protected in "$tool" "$tool_manifest"; do
  protected_mode="$(stat --format '%a' -- "$protected")"
  if [[ "$(stat --format '%u:%g' -- "$protected")" != '0:0' ]] ||
    (((8#$protected_mode & 8#022) != 0)); then
    printf 'Runtime Tools input must be root-owned without group/world write access: %s\n' \
      "$protected" >&2
    exit 2
  fi
done

if [[ "$report" != /* ]]; then
  printf 'Upstream OCI bundle report path must be absolute: %s\n' "$report" >&2
  exit 2
fi
if [[ -e "$report" || -L "$report" ]]; then
  printf 'Refusing to replace an upstream OCI bundle report: %s\n' "$report" >&2
  exit 2
fi
if [[ -e "$report.tmp" || -L "$report.tmp" ]]; then
  printf 'Refusing to replace an upstream OCI bundle temporary report: %s\n' \
    "$report.tmp" >&2
  exit 2
fi
report_parent="$(dirname -- "$report")"
if [[ ! -d "$report_parent" || -L "$report_parent" ]]; then
  printf 'Upstream OCI bundle report parent must be a nonsymlink directory: %s\n' \
    "$report_parent" >&2
  exit 2
fi
report_parent="$(realpath -e -- "$report_parent")"
report="$report_parent/$(basename -- "$report")"
if [[ -e "$report" || -L "$report" ]]; then
  printf 'Refusing to replace an upstream OCI bundle report: %s\n' "$report" >&2
  exit 2
fi
if [[ -e "$report.tmp" || -L "$report.tmp" ]]; then
  printf 'Refusing to replace an upstream OCI bundle temporary report: %s\n' \
    "$report.tmp" >&2
  exit 2
fi

tool_sha256="$(sha256sum "$tool" | cut -d ' ' -f 1)"
tool_size="$(stat --format '%s' "$tool")"
tool_manifest_sha256="$(sha256sum "$tool_manifest" | cut -d ' ' -f 1)"
jq --exit-status \
  --arg sha256 "$tool_sha256" \
  --argjson size "$tool_size" \
  --arg repository "$upstream_repository" \
  --arg commit "$upstream_commit" \
  --arg version "$upstream_version" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg runtime_spec_sum "$runtime_spec_sum" \
  --arg go_version "$required_go_version" \
  --arg lifecycle_profile "$lifecycle_profile" \
  --argjson validated_architectures "$(jq --compact-output '.lifecycle.validated_architectures' "$lock_file")" \
  --argjson preflight_architectures "$(jq --compact-output '.lifecycle.preflight_architectures' "$lock_file")" \
  --argjson lifecycle_blockers "$(jq --compact-output '.lifecycle.blockers' "$lock_file")" \
  --argjson upstream_harness_defects "$(jq --compact-output '.lifecycle.upstream_harness_defects' "$lock_file")" \
  --argjson lifecycle_test_count "$lifecycle_test_count" \
  '.schema_version == "a3s.oci.upstream-runtime-tools-build.v2"
   and .repository == $repository
   and .commit == $commit
   and .version == $version
   and .runtime_spec.version == $runtime_spec_version
   and .runtime_spec.module_sum == $runtime_spec_sum
   and .build.go_version == $go_version
   and .build.cgo_enabled == false
   and .build.trimpath == true
   and .build.buildvcs == false
   and .binary.sha256 == $sha256
   and .binary.size == $size
   and .binary.static_elf == true
   and .lifecycle.profile == $lifecycle_profile
   and .lifecycle.validated_architectures == $validated_architectures
   and .lifecycle.preflight_architectures == $preflight_architectures
   and .lifecycle.blockers == $lifecycle_blockers
   and .lifecycle.upstream_harness_defects == $upstream_harness_defects
   and (.lifecycle.tests | length) == $lifecycle_test_count
   and all(.lifecycle.tests[]; .static_elf == true)' \
  "$tool_manifest" >/dev/null
expected_version_output="oci-runtime-tool version ${upstream_version}, commit: ${upstream_commit}"
if [[ "$("$tool" --version)" != "$expected_version_output" ]]; then
  printf '%s\n' 'OCI Runtime Tools version output does not match its build manifest' >&2
  exit 1
fi
if readelf --program-headers "$tool" | grep --quiet 'INTERP'; then
  printf '%s\n' 'OCI Runtime Tools qualification binary has an ELF interpreter' >&2
  exit 1
fi
file "$tool" | grep --fixed-strings 'statically linked' >/dev/null

validation_root="$(mktemp -d /var/tmp/a3s-oci-upstream-bundles.XXXXXXXX)"
entries="$validation_root/entries.jsonl"
declare -A profile_names=()
first_bundle=''
for bundle_spec in "$@"; do
  if [[ "$bundle_spec" != *=* ]]; then
    printf 'Bundle input must use name=config.json syntax: %s\n' "$bundle_spec" >&2
    exit 2
  fi
  profile_name="${bundle_spec%%=*}"
  config_file="${bundle_spec#*=}"
  if [[ ! "$profile_name" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] ||
    [[ -n "${profile_names[$profile_name]:-}" ]]; then
    printf 'Bundle profile name must be unique and path-safe: %s\n' \
      "$profile_name" >&2
    exit 2
  fi
  profile_names[$profile_name]=1
  if [[ ! -f "$config_file" || -L "$config_file" ]]; then
    printf 'Bundle configuration must be a regular nonsymlink file: %s\n' \
      "$config_file" >&2
    exit 2
  fi
  config_file="$(realpath -e -- "$config_file")"
  if [[ "$(jq --raw-output '.ociVersion // empty' "$config_file")" != '1.3.0' ]]; then
    printf 'Upstream bundle profile must target OCI 1.3.0: %s\n' \
      "$config_file" >&2
    exit 2
  fi

  bundle_directory="$validation_root/$profile_name"
  mkdir -m 0755 "$bundle_directory" "$bundle_directory/rootfs"
  cp --no-preserve=mode,ownership -- "$config_file" \
    "$bundle_directory/config.json"
  chmod 0644 "$bundle_directory/config.json"
  output="$validation_root/$profile_name.output"
  if ! "$tool" \
    --host-specific=false \
    --compliance-level MUST \
    validate \
    --path "$bundle_directory" \
    --platform linux >"$output" 2>&1; then
    printf 'Upstream OCI validation failed for %s:\n' "$profile_name" >&2
    sed -n '1,120p' "$output" >&2
    exit 1
  fi
  grep --fixed-strings --line-regexp 'Bundle validation succeeded.' \
    "$output" >/dev/null
  if [[ -z "$first_bundle" ]]; then
    first_bundle="$bundle_directory"
  fi
  jq --compact-output --null-input \
    --arg name "$profile_name" \
    --arg oci_version '1.3.0' \
    --arg config_sha256 "$(sha256sum "$config_file" | cut -d ' ' -f 1)" \
    --argjson config_size "$(stat --format '%s' "$config_file")" \
    --arg output_sha256 "$(sha256sum "$output" | cut -d ' ' -f 1)" \
    --argjson output_size "$(stat --format '%s' "$output")" \
    '{
      name: $name,
      oci_version: $oci_version,
      config_sha256: $config_sha256,
      config_size: $config_size,
      result: "passed",
      output_sha256: $output_sha256,
      output_size: $output_size
    }' >>"$entries"
done
if [[ -z "$first_bundle" ]]; then
  printf '%s\n' 'At least one upstream bundle profile is required' >&2
  exit 2
fi

negative_bundle="$validation_root/negative-escape"
mkdir -m 0755 "$negative_bundle" "$negative_bundle/rootfs"
jq '.root.path = "../outside-rootfs"' \
  "$first_bundle/config.json" >"$negative_bundle/config.json"
negative_output="$validation_root/negative-escape.output"
set +e
"$tool" \
  --host-specific=false \
  --compliance-level MUST \
  validate \
  --path "$negative_bundle" \
  --platform linux >"$negative_output" 2>&1
negative_status=$?
set -e
if ((negative_status == 0)); then
  printf '%s\n' 'Upstream OCI validator accepted an escaping rootfs path' >&2
  exit 1
fi
grep --fixed-strings 'but it MUST be a child of' "$negative_output" >/dev/null

runtime_sha256="$(sha256sum "$runtime_binary" | cut -d ' ' -f 1)"
agent_sha256="$(sha256sum "$agent_binary" | cut -d ' ' -f 1)"
shim_sha256="$(sha256sum "$shim_binary" | cut -d ' ' -f 1)"
jq --null-input \
  --arg schema_version 'a3s.oci.upstream-bundle-validation.v1' \
  --arg status 'available' \
  --arg source_commit "$source_commit" \
  --arg repository "$upstream_repository" \
  --arg upstream_commit "$upstream_commit" \
  --arg upstream_version "$upstream_version" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg go_version "$required_go_version" \
  --arg tool_sha256 "$tool_sha256" \
  --argjson tool_size "$tool_size" \
  --arg tool_manifest_sha256 "$tool_manifest_sha256" \
  --arg runtime_sha256 "$runtime_sha256" \
  --argjson runtime_size "$(stat --format '%s' "$runtime_binary")" \
  --arg agent_sha256 "$agent_sha256" \
  --argjson agent_size "$(stat --format '%s' "$agent_binary")" \
  --arg shim_sha256 "$shim_sha256" \
  --argjson shim_size "$(stat --format '%s' "$shim_binary")" \
  --argjson negative_exit_code "$negative_status" \
  --arg negative_output_sha256 "$(sha256sum "$negative_output" | cut -d ' ' -f 1)" \
  --slurpfile bundles "$entries" \
  '{
    schema_version: $schema_version,
    status: $status,
    source_commit: $source_commit,
    upstream: {
      repository: $repository,
      commit: $upstream_commit,
      version: $upstream_version,
      runtime_spec_version: $runtime_spec_version,
      go_version: $go_version,
      tool_sha256: $tool_sha256,
      tool_size: $tool_size,
      build_manifest_sha256: $tool_manifest_sha256,
      static_elf: true
    },
    package_executables: {
      runtime: {sha256: $runtime_sha256, size: $runtime_size},
      agent: {sha256: $agent_sha256, size: $agent_size},
      containerd_shim: {sha256: $shim_sha256, size: $shim_size}
    },
    validation: {
      interface: "bundle-validation",
      platform: "linux",
      compliance_level: "MUST",
      host_specific: false,
      bundles: $bundles,
      negative_escape_rejected: true,
      negative_exit_code: $negative_exit_code,
      negative_output_sha256: $negative_output_sha256
    },
    lifecycle_cli_adapter_integrated: true,
    lifecycle_cli_adapter_qualified: false
  }' >"$report.tmp"
chmod 0644 "$report.tmp"
mv "$report.tmp" "$report"

jq --exit-status \
  --arg source_commit "$source_commit" \
  --arg runtime_sha256 "$runtime_sha256" \
  --arg agent_sha256 "$agent_sha256" \
  --arg shim_sha256 "$shim_sha256" \
  --arg upstream_commit "$upstream_commit" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg go_version "$required_go_version" \
  'select(
     .schema_version == "a3s.oci.upstream-bundle-validation.v1"
     and .status == "available"
     and .source_commit == $source_commit
     and .upstream.commit == $upstream_commit
     and .upstream.runtime_spec_version == $runtime_spec_version
     and .upstream.go_version == $go_version
     and .upstream.static_elf
     and .package_executables.runtime.sha256 == $runtime_sha256
     and .package_executables.agent.sha256 == $agent_sha256
     and .package_executables.containerd_shim.sha256 == $shim_sha256
     and (.validation.bundles | length) >= 2
     and all(.validation.bundles[]; .result == "passed")
     and .validation.negative_escape_rejected
     and .validation.negative_exit_code > 0
     and .lifecycle_cli_adapter_integrated
     and .lifecycle_cli_adapter_qualified == false
   )' "$report" >/dev/null
