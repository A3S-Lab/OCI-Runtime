#!/usr/bin/env bash
set -Eeuo pipefail

# Aggregate Linux KVM release gates into one digest-bound matrix.
# host_class=existing is observation-only (promotes_readiness=false).
# host_class=fresh requires a single-use operator attestation and may set
# promotes_readiness=true only when every bound gate reports available.

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-fresh-host-attestation.sh
source .github/scripts/lib/linux-kvm-release-matrix-promotion.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM release matrix requires a Linux host\n' >&2
  exit 2
fi

for command in cargo cp cut date jq mkdir mktemp rm sha256sum uname; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Linux KVM release-matrix command is unavailable: %s\n' \
      "$command" >&2
    exit 1
  fi
done

host_class="${A3S_OCI_LINUX_KVM_HOST_CLASS:-existing}"
attestation_path="${A3S_OCI_LINUX_KVM_FRESH_HOST_ATTESTATION:-}"
skip_soak="${A3S_OCI_LINUX_KVM_SKIP_SOAK:-0}"
linux_kvm_assert_fresh_host_skip_policy "$host_class" "$skip_soak"
fresh_host_attestation="$(
  linux_kvm_resolve_fresh_host_attestation "$host_class" "$attestation_path"
)"

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-release-matrix.XXXXXX")"
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && "${A3S_OCI_KEEP_FAILED_WORK:-0}" == "1" ]]; then
    printf 'preserving failed Linux KVM release-matrix work directory: %s\n' \
      "$work" >&2
    return 0
  fi
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-release-matrix.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected Linux KVM release-matrix path: %s\n' \
        "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

report_path="${A3S_OCI_LINUX_KVM_RELEASE_MATRIX_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite Linux KVM release-matrix report: %s\n' \
    "$report_path" >&2
  exit 1
fi
test -d "$(dirname "$report_path")"
gates_dir="$work/gates"
mkdir -p "$gates_dir"
chmod 0700 "$work" "$gates_dir"

if [[ "$fresh_host_attestation" != "null" ]]; then
  cp -p "$attestation_path" "$work/fresh-host-attestation.json"
fi

manifest_sha256="$(
  sha256sum "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" | cut -d ' ' -f 1
)"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
gates_ndjson="$work/gates.ndjson"
: > "$gates_ndjson"

run_gate() {
  local name="$1"
  local script="$2"
  local env_name="$3"
  local expected_schema="$4"
  local gate_report="$gates_dir/$name.json"
  local started completed duration_ms status schema
  local -a env_args

  printf 'BEGIN Linux KVM release gate: %s\n' "$name" >&2
  started="$(date +%s%3N)"
  env_args=(
    "A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
    "$env_name=$gate_report"
  )
  case "$name" in
    agent-entry)
      env_args+=(
        "A3S_OCI_LINUX_KVM_POST_PROBE_FAILURE_REPORT=$gates_dir/post-probe-failure.json"
      )
      ;;
  esac

  env "${env_args[@]}" bash "$script"
  completed="$(date +%s%3N)"
  duration_ms=$((completed - started))

  schema="$(jq --raw-output '.schema_version // empty' "$gate_report")"
  status="$(jq --raw-output '.status // empty' "$gate_report")"
  if [[ "$schema" != "$expected_schema" ]]; then
    printf 'gate %s schema mismatch: expected %s found %s\n' \
      "$name" "$expected_schema" "$schema" >&2
    return 1
  fi
  if [[ "$status" != "available" ]]; then
    printf 'gate %s status is %s, expected available\n' "$name" "$status" >&2
    return 1
  fi

  jq --compact-output --null-input \
    --arg name "$name" \
    --arg schema "$expected_schema" \
    --arg status "$status" \
    --argjson duration_ms "$duration_ms" \
    --arg summary_path "$gate_report" \
    --arg summary_sha256 "$(sha256sum "$gate_report" | cut -d ' ' -f 1)" \
    '{
      name: $name,
      schema_version: $schema,
      status: $status,
      duration_ms: $duration_ms,
      summary_path: $summary_path,
      summary_sha256: $summary_sha256
    }' >> "$gates_ndjson"
  printf 'PASS Linux KVM release gate: %s (%s ms)\n' "$name" "$duration_ms" >&2
}

run_gate agent-entry \
  .github/scripts/linux-kvm-agent-entry.sh \
  A3S_OCI_LINUX_KVM_AGENT_REPORT \
  a3s.oci.linux-kvm-agent-entry.v1

run_gate compatibility-drift \
  .github/scripts/linux-kvm-compatibility-drift.sh \
  A3S_OCI_LINUX_KVM_COMPATIBILITY_DRIFT_REPORT \
  a3s.oci.linux-kvm-compatibility-drift.v2

run_gate lifecycle \
  .github/scripts/linux-kvm-lifecycle.sh \
  A3S_OCI_LINUX_KVM_LIFECYCLE_REPORT \
  a3s.oci.linux-kvm-lifecycle-matrix.v2

run_gate recovery \
  .github/scripts/linux-kvm-recovery.sh \
  A3S_OCI_LINUX_KVM_RECOVERY_REPORT \
  a3s.oci.linux-kvm-recovery-matrix.v2

run_gate create-reopen \
  .github/scripts/linux-kvm-create-reopen.sh \
  A3S_OCI_LINUX_KVM_CREATE_REOPEN_REPORT \
  a3s.oci.linux-kvm-create-reopen-matrix.v2

soak_ran=0
if [[ "$skip_soak" != "1" ]]; then
  run_gate soak \
    .github/scripts/linux-kvm-soak.sh \
    A3S_OCI_LINUX_KVM_SOAK_REPORT \
    a3s.oci.linux-kvm-soak-matrix.v2
  soak_ran=1
fi

completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
promotes="$(
  linux_kvm_compute_promotes_readiness \
    "$host_class" \
    "$fresh_host_attestation" \
    "$skip_soak" \
    "$soak_ran"
)"

gates_json="$(jq --slurp --compact-output '.' "$gates_ndjson")"

jq --null-input \
  --arg architecture "$(uname -m)" \
  --arg host_class "$host_class" \
  --argjson promotes_readiness "$promotes" \
  --argjson fresh_host_attestation "$fresh_host_attestation" \
  --argjson included_soak "$([[ "$soak_ran" == "1" ]] && printf true || printf false)" \
  --arg started_at_utc "$started_at" \
  --arg completed_at_utc "$completed_at" \
  --arg commit "$(git rev-parse HEAD)" \
  --arg manifest_sha256 "$manifest_sha256" \
  --argjson gates "$gates_json" \
  '{
    schema_version: "a3s.oci.linux-kvm-release-matrix.v1",
    platform: "linux",
    architecture: $architecture,
    status: "available",
    host_class: $host_class,
    promotes_readiness: $promotes_readiness,
    fresh_host_attestation: $fresh_host_attestation,
    included_soak: $included_soak,
    started_at_utc: $started_at_utc,
    completed_at_utc: $completed_at_utc,
    commit: $commit,
    system_image_manifest_sha256: $manifest_sha256,
    gate_count: ($gates | length),
    gates: $gates,
    reason: (if $promotes_readiness then null
             else "host_class=existing does not close the fresh-host promotion gate"
             end)
  }' | tee "$report_path"

jq --exit-status \
  --arg host_class "$host_class" \
  '
  .schema_version == "a3s.oci.linux-kvm-release-matrix.v1"
  and .platform == "linux"
  and .status == "available"
  and .host_class == $host_class
  and (.gate_count | type) == "number"
  and (.gates | length) == .gate_count
  and all(.gates[]; .status == "available")
  and (
    if .host_class == "fresh" then
      .promotes_readiness
      and .included_soak
      and .gate_count == 6
      and any(.gates[]; .name == "soak")
      and (.fresh_host_attestation.schema_version
           == "a3s.oci.linux-kvm-fresh-host-attestation.v1")
    else
      (.promotes_readiness | not)
      and .fresh_host_attestation == null
      and .gate_count >= 5
    end
  )
  ' \
  "$report_path" >/dev/null

if [[ "$promotes" != "true" ]]; then
  printf '%s\n' \
    'host_class=existing does not close the fresh-host promotion gate.' >&2
fi
