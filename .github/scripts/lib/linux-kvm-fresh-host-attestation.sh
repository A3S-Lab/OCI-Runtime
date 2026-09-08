#!/usr/bin/env bash

# Validate and emit one fail-closed fresh-host attestation object for Linux KVM.
# Callers pass host_class and optional attestation path.
linux_kvm_resolve_fresh_host_attestation() {
  local host_class="${1:-}"
  local attestation_path="${2:-}"

  case "$host_class" in
    existing)
      if [[ -n "$attestation_path" ]]; then
        printf '%s\n' \
          'Fresh-host attestation is only valid with host_class=fresh' >&2
        return 2
      fi
      printf '%s\n' 'null'
      return 0
      ;;
    fresh) ;;
    *)
      printf 'invalid Linux KVM host_class: %s\n' "$host_class" >&2
      return 2
      ;;
  esac

  if [[ -z "$attestation_path" ]]; then
    printf '%s\n' \
      'host_class=fresh requires A3S_OCI_LINUX_KVM_FRESH_HOST_ATTESTATION' >&2
    return 2
  fi
  if [[ ! -f "$attestation_path" || -L "$attestation_path" ]]; then
    printf 'fresh-host attestation must be a real regular file: %s\n' \
      "$attestation_path" >&2
    return 1
  fi

  local sha256
  if ! sha256="$(sha256sum "$attestation_path" | cut -d ' ' -f 1)"; then
    printf '%s\n' 'failed to digest the fresh-host attestation' >&2
    return 1
  fi

  jq --exit-status \
    --arg path "$attestation_path" \
    --arg sha256 "$sha256" \
    '
    if .schema_version != "a3s.oci.linux-kvm-fresh-host-attestation.v1" then
      error("unexpected fresh-host attestation schema")
    elif .operator_attests_fresh_provisioning != true then
      error("operator_attests_fresh_provisioning must be true")
    elif ((.provisioned_at_utc | type) != "string")
      or (.provisioned_at_utc | length) < 10 then
      error("provisioned_at_utc is required")
    else
      {
        path: $path,
        sha256: $sha256,
        schema_version: .schema_version,
        operator_attests_fresh_provisioning: true,
        provisioned_at_utc: .provisioned_at_utc,
        hostname: (if (.hostname | type) == "string" then .hostname else null end)
      }
    end
    ' \
    "$attestation_path"
}
