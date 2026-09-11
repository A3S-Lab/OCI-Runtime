#!/usr/bin/env bash

# Fail-closed promotion policy for the Linux KVM release matrix.
# Fresh hosts may promote only with a full bound gate set and full soak depth.

LINUX_KVM_PROMOTION_SOAK_ITERATIONS=25

# Bound gate depths re-asserted by the release matrix for fresh promotion.
# Format: gate_name:expected_case_count
LINUX_KVM_PROMOTION_BOUND_GATE_CASES=(
  'agent-entry:1'
  'compatibility-drift:14'
  'lifecycle:17'
  'recovery:1'
  'create-reopen:11'
)

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

# Refuse reduced soak depth for fresh hosts. Pass the effective iteration count
# (default 25 when the env var is unset).
linux_kvm_assert_fresh_host_soak_profile() {
  local host_class="${1:-}"
  local soak_iterations="${2:-$LINUX_KVM_PROMOTION_SOAK_ITERATIONS}"

  case "$host_class" in
    existing|fresh) ;;
    *)
      printf 'invalid Linux KVM host_class: %s\n' "$host_class" >&2
      return 2
      ;;
  esac

  if [[ "$host_class" == "fresh" &&
        "$soak_iterations" != "$LINUX_KVM_PROMOTION_SOAK_ITERATIONS" ]]; then
    printf '%s\n' \
      "host_class=fresh requires A3S_OCI_LINUX_KVM_SOAK_ITERATIONS=$LINUX_KVM_PROMOTION_SOAK_ITERATIONS (refusing reduced soak depth)" >&2
    return 2
  fi
  return 0
}

# Re-assert bound gate case_count values from gate summary JSON files.
# Args: host_class, gates_directory
linux_kvm_assert_fresh_host_bound_gate_depths() {
  local host_class="${1:-}"
  local gates_dir="${2:-}"
  local entry name expected actual path

  case "$host_class" in
    existing)
      return 0
      ;;
    fresh) ;;
    *)
      printf 'invalid Linux KVM host_class: %s\n' "$host_class" >&2
      return 2
      ;;
  esac

  if [[ -z "$gates_dir" || ! -d "$gates_dir" ]]; then
    printf 'fresh host_class requires a gates directory for bound-depth checks\n' >&2
    return 2
  fi

  for entry in "${LINUX_KVM_PROMOTION_BOUND_GATE_CASES[@]}"; do
    name="${entry%%:*}"
    expected="${entry##*:}"
    path="$gates_dir/$name.json"
    if [[ ! -f "$path" ]]; then
      printf 'fresh host_class missing bound gate summary: %s\n' "$path" >&2
      return 2
    fi
    actual="$(jq --raw-output '.case_count // empty' "$path")"
    if [[ "$actual" != "$expected" ]]; then
      printf '%s\n' \
        "fresh host_class requires gate $name case_count=$expected (found ${actual:-missing})" >&2
      return 2
    fi
  done
  return 0
}

# Emit true/false.
# Args: host_class, attestation JSON-or-null, skip_soak (0|1), soak_ran (0|1),
#       soak_requested_iterations, soak_completed_iterations,
#       bound_depths_ok (0|1).
linux_kvm_compute_promotes_readiness() {
  local host_class="${1:-}"
  local fresh_host_attestation="${2:-null}"
  local skip_soak="${3:-0}"
  local soak_ran="${4:-0}"
  local soak_requested="${5:-0}"
  local soak_completed="${6:-0}"
  local bound_depths_ok="${7:-0}"

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
  if [[ "$soak_requested" != "$LINUX_KVM_PROMOTION_SOAK_ITERATIONS" ||
        "$soak_completed" != "$LINUX_KVM_PROMOTION_SOAK_ITERATIONS" ]]; then
    printf '%s\n' 'false'
    return 0
  fi
  if [[ "$bound_depths_ok" != "1" ]]; then
    printf '%s\n' 'false'
    return 0
  fi
  printf '%s\n' 'true'
}
