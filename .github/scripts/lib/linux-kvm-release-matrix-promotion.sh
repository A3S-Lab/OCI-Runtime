#!/usr/bin/env bash

# Fail-closed promotion policy for the Linux KVM release matrix.
# Fresh hosts may promote only with a full bound gate set (including soak).

linux_kvm_assert_fresh_host_skip_policy() {
  local host_class="${1:-}"
  local skip_soak="${2:-0}"

  case "$host_class" in
    existing|fresh) ;;
    *)
      printf 'invalid Linux KVM host_class: %s\n' "$host_class" >&2
      return 2
      ;;
  esac

  if [[ "$host_class" == "fresh" && "$skip_soak" == "1" ]]; then
    printf '%s\n' \
      'host_class=fresh refuses A3S_OCI_LINUX_KVM_SKIP_SOAK=1 (soak is required to promote readiness)' >&2
    return 2
  fi
  return 0
}

# Emit true/false. Callers pass host_class, attestation JSON-or-null, skip_soak (0|1),
# and whether the soak gate ran (0|1).
linux_kvm_compute_promotes_readiness() {
  local host_class="${1:-}"
  local fresh_host_attestation="${2:-null}"
  local skip_soak="${3:-0}"
  local soak_ran="${4:-0}"

  if [[ "$host_class" != "fresh" ]]; then
    printf '%s\n' 'false'
    return 0
  fi
  if [[ "$fresh_host_attestation" == "null" || -z "$fresh_host_attestation" ]]; then
    printf '%s\n' 'false'
    return 0
  fi
  if [[ "$skip_soak" == "1" || "$soak_ran" != "1" ]]; then
    printf '%s\n' 'false'
    return 0
  fi
  printf '%s\n' 'true'
}
