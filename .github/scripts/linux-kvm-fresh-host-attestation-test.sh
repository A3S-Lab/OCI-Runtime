#!/usr/bin/env bash
set -Eeuo pipefail

# Fail-closed unit checks for Linux KVM fresh-host attestation resolution.
source .github/scripts/lib/linux-kvm-fresh-host-attestation.sh

work="$(mktemp -d /tmp/a3s-oci-kvm-attestation-test.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT

# existing rejects attestation path
if linux_kvm_resolve_fresh_host_attestation existing "$work/x.json" >/dev/null 2>&1; then
  printf 'existing host_class unexpectedly accepted an attestation path\n' >&2
  exit 1
fi

# existing without path yields null
[[ "$(linux_kvm_resolve_fresh_host_attestation existing '')" == "null" ]]

# fresh without path fails
if linux_kvm_resolve_fresh_host_attestation fresh '' >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly accepted a missing attestation\n' >&2
  exit 1
fi

# fresh with wrong schema fails
printf '%s\n' '{"schema_version":"wrong","operator_attests_fresh_provisioning":true,"provisioned_at_utc":"2026-09-07T00:00:00Z"}' \
  > "$work/bad.json"
if linux_kvm_resolve_fresh_host_attestation fresh "$work/bad.json" >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly accepted a wrong schema\n' >&2
  exit 1
fi

# fresh with valid attestation succeeds
printf '%s\n' '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1","operator_attests_fresh_provisioning":true,"provisioned_at_utc":"2026-09-07T00:00:00Z","hostname":"kvm-release-01"}' \
  > "$work/good.json"
resolved="$(linux_kvm_resolve_fresh_host_attestation fresh "$work/good.json")"
jq --exit-status \
  --arg path "$work/good.json" \
  '
  .schema_version == "a3s.oci.linux-kvm-fresh-host-attestation.v1"
  and .operator_attests_fresh_provisioning
  and .path == $path
  and (.sha256 | length) == 64
  and .hostname == "kvm-release-01"
  ' <<<"$resolved" >/dev/null

printf 'linux-kvm-fresh-host-attestation checks passed\n'
