#!/usr/bin/env bash
set -Eeuo pipefail

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-provenance.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM compatibility-drift qualification requires a Linux host\n' >&2
  exit 2
fi

for command in cp dd find grep jq od ps sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required compatibility-drift command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

umask 077
target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$PWD/$target_dir"
fi
profile="${A3S_OCI_BUILD_PROFILE:-debug}"
build_arguments=(build -p a3s-oci-cli -p a3s-oci-krun)
case "$profile" in
  debug) ;;
  release) build_arguments+=(--release) ;;
  *) build_arguments+=(--profile "$profile") ;;
esac
binary_dir="$target_dir/$profile"
cli="$binary_dir/a3s-oci"
shim="$binary_dir/a3s-oci-krun-shim"
runtime_dir="$binary_dir/a3s-oci-krun-runtime"
runtime_assets_manifest="crates/krun/runtime/runtime-assets.json"

cargo "${build_arguments[@]}"
test -x "$cli"
test -x "$shim"
test -d "$runtime_dir"
test -f "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
test ! -L "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"

system_image_directory="$(dirname "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST")"
system_image_name="$(
  jq --raw-output '.image.name' "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
)"
source_system_image="$system_image_directory/$system_image_name"
test -f "$source_system_image"
test ! -L "$source_system_image"
test "$(jq --raw-output '.image.sha256' "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST")" = \
  "$(sha256sum "$source_system_image" | cut -d ' ' -f 1)"

architecture="$(uname -m)"
case "$architecture" in
  x86_64) opposite_architecture="aarch64" ;;
  aarch64) opposite_architecture="x86_64" ;;
  *)
    printf 'unsupported Linux KVM qualification architecture: %s\n' "$architecture" >&2
    exit 2
    ;;
esac

provenance="$(
  linux_kvm_provenance \
    linux-kvm-compatibility-drift-14-case-v1 "$profile" \
    "$cli" "$shim" "$runtime_dir" "$runtime_assets_manifest" \
    "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
)"

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-compatibility-drift.XXXXXX")"
active_pid=""
current_case="setup"
cleanup() {
  if [[ -n "$active_pid" ]] && kill -0 "$active_pid" 2>/dev/null; then
    kill "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
  fi
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-compatibility-drift.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected compatibility-drift path: %s\n' "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

on_error() {
  local status=$?
  trap - ERR
  printf 'Linux KVM compatibility-drift case %s failed near line %s\n' \
    "$current_case" "${BASH_LINENO[0]}" >&2
  if [[ -n "${case_report:-}" && -f "$case_report" ]]; then
    jq --raw-output '.shim_report.reason // .reason // empty' \
      "$case_report" 2>/dev/null >&2 || true
  fi
  if [[ -n "${case_stderr:-}" && -s "$case_stderr" ]]; then
    tail -n 20 "$case_stderr" >&2 || true
  fi
  exit "$status"
}
trap on_error ERR

report_path="${A3S_OCI_LINUX_KVM_COMPATIBILITY_DRIFT_REPORT:-$work/report.json}"
cases_path="$work/cases.ndjson"
: > "$cases_path"

endpoint_inventory() {
  find /tmp -maxdepth 1 -type d -uid "$(id -u)" \
    -name 'a3s-oci-agent-*' -print 2>/dev/null | sort
}

shim_process_inventory() {
  ps -eo pid=,comm= | awk 'index($2, "a3s-oci-krun") == 1 {print $1 " " $2}' | sort
}

runtime_share_inventory() {
  find "$1" -mindepth 1 -maxdepth 2 -printf '%P %y\n' | sort
}

prepare_case() {
  local name="$1"
  current_case="$name"
  printf 'Qualifying Linux KVM compatibility drift: %s\n' "$name" >&2
  case_root="$work/$name"
  case_system_image_directory="$case_root/system-image"
  case_binary_directory="$case_root/bin"
  case_bootstrap="$case_root/bootstrap"
  case_runtime_share="$case_root/runtime-share"
  case_console="$case_root/console.log"
  case_report="$case_root/report.json"
  case_stderr="$case_root/stderr.log"
  case_manifest="$case_system_image_directory/system-image.json"
  case_system_image="$case_system_image_directory/$system_image_name"
  case_shim="$case_binary_directory/a3s-oci-krun-shim"

  mkdir -p \
    "$case_system_image_directory" \
    "$case_binary_directory" \
    "$case_bootstrap" \
    "$case_runtime_share/run"
  chmod 0700 \
    "$case_root" \
    "$case_system_image_directory" \
    "$case_binary_directory" \
    "$case_bootstrap" \
    "$case_runtime_share" \
    "$case_runtime_share/run"
  cp --reflink=auto --sparse=always \
    "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" "$case_manifest"
  cp --reflink=auto --sparse=always "$source_system_image" "$case_system_image"
  cp -p "$shim" "$case_shim"
  cp -a "$runtime_dir" "$case_binary_directory/a3s-oci-krun-runtime"
  chmod 0600 "$case_manifest" "$case_system_image"
  chmod -R u+w "$case_binary_directory/a3s-oci-krun-runtime"
}

rewrite_manifest() {
  local filter="$1"
  shift
  local replacement="$case_system_image_directory/system-image.rewritten.json"
  jq "$@" "$filter" "$case_manifest" > "$replacement"
  chmod 0600 "$replacement"
  mv -f -- "$replacement" "$case_manifest"
}

replace_same_size_in_place() {
  local path="$1"
  local original="$2"
  local replacement="$3"
  local matches offset size
  test "${#original}" -eq "${#replacement}"
  matches="$(grep --byte-offset --only-matching --fixed-strings -- "$original" "$path")"
  test "$(wc -l <<< "$matches")" -eq 1
  offset="${matches%%:*}"
  size="$(stat --format '%s' "$path")"
  printf '%s' "$replacement" | dd of="$path" bs=1 seek="$offset" \
    count="${#replacement}" conv=notrunc status=none
  test "$(stat --format '%s' "$path")" -eq "$size"
}

mutate_before_load() {
  local name="$1"
  case "$name" in
    architecture-mismatch)
      # jq, rather than the shell, expands this named JSON argument.
      # shellcheck disable=SC2016
      rewrite_manifest '.architecture = $architecture' \
        --arg architecture "$opposite_architecture"
      ;;
    runtime-target-mismatch)
      rewrite_manifest '.runtime.target_os = "freebsd"'
      ;;
    guest-agent-identity-drift)
      rewrite_manifest '.sources.agent.version = "0.2.1"'
      ;;
    runtime-archive-provenance-drift)
      rewrite_manifest '.runtime.archive_sha256 = ("0" * 64)'
      ;;
    libkrun-provenance-drift)
      rewrite_manifest \
        '(.runtime.files[] | select(.role == "library") | .sha256) = ("0" * 64)'
      ;;
    firmware-provenance-drift)
      rewrite_manifest \
        '(.runtime.files[] | select(.role == "firmware") | .sha256) = ("0" * 64)'
      ;;
    kernel-provenance-drift)
      rewrite_manifest '.runtime.kernel.sha256 = ("0" * 64)'
      ;;
    *)
      printf 'unknown pre-load compatibility-drift case: %s\n' "$name" >&2
      return 1
      ;;
  esac
}

mutate_after_configuration() {
  local name="$1"
  local original replacement size final_byte
  case "$name" in
    manifest-replacement)
      replacement="$case_system_image_directory/system-image.replacement.json"
      cp --reflink=auto --sparse=always "$case_manifest" "$replacement"
      chmod 0600 "$replacement"
      mv -f -- "$replacement" "$case_manifest"
      ;;
    manifest-content-drift)
      replace_same_size_in_place \
        "$case_manifest" 'agent-protocol-v10' 'agent-protocol-v11'
      ;;
    manifest-symlink)
      replacement="$case_system_image_directory/system-image.displaced.json"
      mv -- "$case_manifest" "$replacement"
      ln -s "$(basename "$replacement")" "$case_manifest"
      ;;
    system-image-replacement)
      replacement="$case_system_image_directory/system-image.replacement.ext4"
      cp --reflink=auto --sparse=always "$case_system_image" "$replacement"
      chmod 0600 "$replacement"
      mv -f -- "$replacement" "$case_system_image"
      ;;
    system-image-content-drift)
      size="$(stat --format '%s' "$case_system_image")"
      final_byte="$(
        od -An -tu1 -j "$((size - 1))" -N 1 "$case_system_image" | tr -d ' '
      )"
      if [[ "$final_byte" == "0" ]]; then
        printf '\001'
      else
        printf '\000'
      fi | dd of="$case_system_image" bs=1 seek="$((size - 1))" \
        count=1 conv=notrunc status=none
      test "$(stat --format '%s' "$case_system_image")" -eq "$size"
      ;;
    system-image-symlink)
      replacement="$case_system_image_directory/system-image.displaced.ext4"
      mv -- "$case_system_image" "$replacement"
      ln -s "$(basename "$replacement")" "$case_system_image"
      ;;
    guest-agent-digest-drift)
      original="$(jq --raw-output '.sources.agent.sha256' "$case_manifest")"
      if [[ "${original:0:1}" == "0" ]]; then
        replacement="1${original:1}"
      else
        replacement="0${original:1}"
      fi
      replace_same_size_in_place "$case_manifest" "$original" "$replacement"
      ;;
    *)
      printf 'unknown post-configuration compatibility-drift case: %s\n' "$name" >&2
      return 1
      ;;
  esac
}

assert_common_report() {
  local report="$1"
  local reason_fragment="$2"
  jq --exit-status --arg reason_fragment "$reason_fragment" \
    '.schema_version == "a3s.oci.agent-vm-smoke.v10"
     and .platform == "linux" and .status == "unavailable"
     and .endpoint_bound and .shim_spawned
     and (.shim_process_id > 0) and (.bridge_process_id == null)
     and (.shim_client_verified | not) and (.protocol_negotiated | not)
     and (.shim_report_verified | not) and .shim_exit_code == 2
     and .shim_report.schema_version == "a3s.oci.krun-agent-vm-smoke.v7"
     and .shim_report.platform == "linux"
     and .shim_report.status == "unavailable"
     and (.shim_report.kvm_device_opened | not)
     and (.shim_report.kvm_api_verified | not)
     and (.shim_report.kvm_post_probe_failure_injected | not)
     and (.shim_report.vm_entered | not)
     and .shim_report.guest_exit_code == null
     and (.shim_report.reason | contains($reason_fragment))
     and (.reason | contains("exited before connecting the authenticated agent bridge"))' \
    "$report" >/dev/null
}

assert_cleanup() {
  local endpoint_before="$1"
  local process_before="$2"
  local runtime_before="$3"
  local endpoint_after process_after runtime_after
  endpoint_after="$(endpoint_inventory)"
  process_after="$(shim_process_inventory)"
  runtime_after="$(runtime_share_inventory "$case_runtime_share")"
  test "$endpoint_after" = "$endpoint_before"
  test "$process_after" = "$process_before"
  test "$runtime_after" = "$runtime_before"
  test -z "$(
    find "$case_runtime_share" -maxdepth 2 \
      \( -name '.a3s-oci-bootstrap-*' \
         -o -name '.a3s-oci-recovery-*' \
         -o -name '.a3s-oci-kvm-compatibility-drift-*' \) \
      -print -quit
  )"
}

record_case() {
  local name="$1"
  local boundary="$2"
  jq --null-input --compact-output \
    --arg name "$name" \
    --arg boundary "$boundary" \
    --arg reason "$(jq --raw-output '.shim_report.reason' "$case_report")" \
    '{
      name: $name,
      boundary: $boundary,
      status: "rejected",
      vm_entered: false,
      kvm_device_opened: false,
      endpoint_restored: true,
      shim_process_inventory_restored: true,
      token_handoff_removed: true,
      runtime_share_restored: true,
      reason: $reason
    }' >> "$cases_path"
}

run_pre_load_case() {
  local name="$1"
  local reason_fragment="$2"
  local endpoint_before process_before runtime_before status
  prepare_case "$name"
  mutate_before_load "$name"
  endpoint_before="$(endpoint_inventory)"
  process_before="$(shim_process_inventory)"
  runtime_before="$(runtime_share_inventory "$case_runtime_share")"

  if "$cli" agent-vm-smoke \
    --shim "$case_shim" \
    --rootfs "$case_bootstrap" \
    --system-image-manifest "$case_manifest" \
    --runtime-share "$case_runtime_share" \
    --console "$case_console" \
    > "$case_report" 2> "$case_stderr"; then
    status=0
  else
    status=$?
  fi
  test "$status" -eq 2
  assert_common_report "$case_report" "$reason_fragment"
  jq --exit-status \
    '.shim_report.runtime_bundle_loaded
     and (.shim_report.context_created | not)
     and (.shim_report.vm_configured | not)
     and (.shim_report.rootfs_configured | not)
     and (.shim_report.runtime_share_configured | not)
     and (.shim_report.agent_binary_present | not)' \
    "$case_report" >/dev/null
  assert_cleanup "$endpoint_before" "$process_before" "$runtime_before"
  record_case "$name" "worker-load"
  printf 'Qualified Linux KVM compatibility drift: %s\n' "$name" >&2
}

run_post_configuration_case() {
  local name="$1"
  local drift_fragment="$2"
  local endpoint_before process_before runtime_before status ready proceed continue_staging
  prepare_case "$name"
  endpoint_before="$(endpoint_inventory)"
  process_before="$(shim_process_inventory)"
  runtime_before="$(runtime_share_inventory "$case_runtime_share")"
  ready="$case_runtime_share/run/.a3s-oci-kvm-compatibility-drift-ready"
  proceed="$case_runtime_share/run/.a3s-oci-kvm-compatibility-drift-continue"
  continue_staging="$case_runtime_share/run/compatibility-drift-continue.staging"

  "$cli" agent-vm-smoke \
    --shim "$case_shim" \
    --rootfs "$case_bootstrap" \
    --system-image-manifest "$case_manifest" \
    --runtime-share "$case_runtime_share" \
    --console "$case_console" \
    --qualify-kvm-compatibility-drift "$name" \
    > "$case_report" 2> "$case_stderr" &
  active_pid=$!

  for _ in $(seq 1 3000); do
    if [[ -f "$ready" ]]; then
      break
    fi
    if ! kill -0 "$active_pid" 2>/dev/null; then
      break
    fi
    sleep 0.02
  done
  test -f "$ready"
  test "$(cat "$ready")" = "$name"
  mutate_after_configuration "$name"
  printf '%s\n' "$name" > "$continue_staging"
  chmod 0600 "$continue_staging"
  mv -- "$continue_staging" "$proceed"

  if wait "$active_pid"; then
    status=0
  else
    status=$?
  fi
  active_pid=""
  test "$status" -eq 2
  assert_common_report \
    "$case_report" \
    "compatibility-drift qualification $name failed closed before KVM device access"
  jq --exit-status --arg drift_fragment "$drift_fragment" \
    '.shim_report.reason | contains($drift_fragment)' \
    "$case_report" >/dev/null
  jq --exit-status \
    '.shim_report.runtime_bundle_loaded
     and .shim_report.context_created and .shim_report.vm_configured
     and .shim_report.rootfs_configured
     and .shim_report.runtime_share_configured
     and .shim_report.agent_binary_present
     and .shim_report.agent_vsock_configured
     and .shim_report.workload_configured
     and .shim_report.console_configured
     and (.shim_report.linux_boot_assets != null)' \
    "$case_report" >/dev/null
  assert_cleanup "$endpoint_before" "$process_before" "$runtime_before"
  record_case "$name" "configured-pre-kvm"
  printf 'Qualified Linux KVM compatibility drift: %s\n' "$name" >&2
}

run_post_configuration_case \
  manifest-replacement 'Linux system-image manifest identity changed'
run_post_configuration_case \
  manifest-content-drift 'Linux system-image manifest SHA-256 changed'
run_post_configuration_case \
  manifest-symlink 'Linux system-image manifest must be a real regular file'
run_post_configuration_case \
  system-image-replacement 'raw Linux system image identity changed'
run_post_configuration_case \
  system-image-content-drift 'raw Linux system image SHA-256 changed'
run_post_configuration_case \
  system-image-symlink 'raw Linux system image must be a real regular file'
run_post_configuration_case \
  guest-agent-digest-drift 'Linux system-image manifest SHA-256 changed'

run_pre_load_case architecture-mismatch 'manifest architecture mismatch'
run_pre_load_case runtime-target-mismatch \
  'manifest runtime bundle does not match the checked-in target bundle'
run_pre_load_case guest-agent-identity-drift \
  'manifest sources.agent.version mismatch'
run_pre_load_case runtime-archive-provenance-drift \
  'manifest runtime bundle does not match the checked-in target bundle'
run_pre_load_case libkrun-provenance-drift \
  'manifest runtime bundle does not match the checked-in target bundle'
run_pre_load_case firmware-provenance-drift \
  'manifest runtime bundle does not match the checked-in target bundle'
run_pre_load_case kernel-provenance-drift \
  'manifest runtime bundle does not match the checked-in target bundle'

jq --slurp --arg architecture "$architecture" \
  --argjson provenance "$provenance" \
  '{
    schema_version: "a3s.oci.linux-kvm-compatibility-drift.v2",
    platform: "linux",
    architecture: $architecture,
    status: "available",
    kvm_required: false,
    provenance: $provenance,
    case_count: length,
    cases: .
  }' "$cases_path" | tee "$report_path"

jq --exit-status \
  '.schema_version == "a3s.oci.linux-kvm-compatibility-drift.v2"
   and .status == "available" and (.kvm_required | not)
   and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
   and .provenance.platform == .platform
   and .provenance.architecture == .architecture
   and .provenance.qualification_profile
     == "linux-kvm-compatibility-drift-14-case-v1"
   and .provenance.driver == "libkrun-kvm"
   and .provenance.isolation == "dedicated-vm"
   and .provenance.source_tree_clean
   and .case_count == 14
   and ([.cases[] | select(
     .status == "rejected"
     and (.vm_entered | not)
     and (.kvm_device_opened | not)
     and .endpoint_restored
     and .shim_process_inventory_restored
     and .token_handoff_removed
     and .runtime_share_restored
   )] | length) == 14' "$report_path" >/dev/null
