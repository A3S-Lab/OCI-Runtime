#!/usr/bin/env bash
set -Eeuo pipefail

# Fail-closed unit checks for Linux KVM release-matrix promotion policy.
source .github/scripts/lib/linux-kvm-release-matrix-promotion.sh

work="$(mktemp -d /tmp/a3s-oci-kvm-promotion-test.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/gates"

# existing may skip soak
linux_kvm_assert_fresh_host_skip_policy existing 1

# fresh refuses skip soak
if linux_kvm_assert_fresh_host_skip_policy fresh 1 >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly allowed SKIP_SOAK=1\n' >&2
  exit 1
fi
linux_kvm_assert_fresh_host_skip_policy fresh 0

# existing may use a reduced soak profile
linux_kvm_assert_fresh_host_soak_profile existing 1

# fresh refuses reduced soak depth
if linux_kvm_assert_fresh_host_soak_profile fresh 1 >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly allowed SOAK_ITERATIONS=1\n' >&2
  exit 1
fi
linux_kvm_assert_fresh_host_soak_profile fresh 25

# existing skips bound-depth checks
linux_kvm_assert_fresh_host_bound_gate_depths existing "$work/gates"

# fresh refuses missing gate summaries
if linux_kvm_assert_fresh_host_bound_gate_depths fresh "$work/gates" >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly accepted missing bound gate summaries\n' >&2
  exit 1
fi

for entry in "${LINUX_KVM_PROMOTION_BOUND_GATE_CASES[@]}"; do
  name="${entry%%:*}"
  expected="${entry##*:}"
  jq --null-input --argjson case_count "$expected" \
    '{case_count: $case_count}' > "$work/gates/$name.json"
done
linux_kvm_assert_fresh_host_bound_gate_depths fresh "$work/gates"

# fresh refuses thinned lifecycle depth
jq --null-input '{case_count: 1}' > "$work/gates/lifecycle.json"
if linux_kvm_assert_fresh_host_bound_gate_depths fresh "$work/gates" >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly accepted thinned lifecycle case_count\n' >&2
  exit 1
fi
jq --null-input '{case_count: 17}' > "$work/gates/lifecycle.json"

# promotes_readiness stays false for existing
[[ "$(linux_kvm_compute_promotes_readiness existing '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 1 25 25 1)" == "false" ]]

# fresh + attestation + full soak + bound depths promotes
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 1 25 25 1)" == "true" ]]

# fresh without bound depths does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 1 25 25 0)" == "false" ]]

# fresh + attestation but soak skipped does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 1 0 0 0 1)" == "false" ]]

# fresh + attestation but reduced soak depth does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 1 1 1 1)" == "false" ]]

# fresh without attestation does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh 'null' 0 1 25 25 1)" == "false" ]]

printf 'linux-kvm-release-matrix-promotion checks passed\n'
