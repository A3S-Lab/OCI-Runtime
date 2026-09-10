#!/usr/bin/env bash
set -Eeuo pipefail

# Fail-closed unit checks for Linux KVM release-matrix promotion policy.
source .github/scripts/lib/linux-kvm-release-matrix-promotion.sh

# existing may skip soak
linux_kvm_assert_fresh_host_skip_policy existing 1

# fresh refuses skip soak
if linux_kvm_assert_fresh_host_skip_policy fresh 1 >/dev/null 2>&1; then
  printf 'fresh host_class unexpectedly allowed SKIP_SOAK=1\n' >&2
  exit 1
fi

# fresh without skip is allowed by the skip policy
linux_kvm_assert_fresh_host_skip_policy fresh 0

# promotes_readiness stays false for existing even with attestation-shaped payload
[[ "$(linux_kvm_compute_promotes_readiness existing '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 1)" == "false" ]]

# fresh + attestation + soak promotes
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 1)" == "true" ]]

# fresh + attestation but soak skipped does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 1 0)" == "false" ]]

# fresh + attestation but soak did not run does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh '{"schema_version":"a3s.oci.linux-kvm-fresh-host-attestation.v1"}' 0 0)" == "false" ]]

# fresh without attestation does not promote
[[ "$(linux_kvm_compute_promotes_readiness fresh 'null' 0 1)" == "false" ]]

printf 'linux-kvm-release-matrix-promotion checks passed\n'
