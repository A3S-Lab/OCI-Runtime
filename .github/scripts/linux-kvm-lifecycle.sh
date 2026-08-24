#!/usr/bin/env bash
set -Eeuo pipefail

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-provenance.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM lifecycle qualification requires a Linux host\n' >&2
  exit 2
fi

for command in \
  awk cargo chmod cp curl cut dirname find id jq mkdir mktemp ps rm sha256sum sort \
  tail tee uname
do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Linux KVM lifecycle command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

architecture="$(uname -m)"
case "$architecture" in
  x86_64)
    alpine_name="alpine-minirootfs-3.22.5-x86_64.tar.gz"
    alpine_url="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/$alpine_name"
    ;;
  aarch64)
    alpine_name="alpine-minirootfs-3.22.5-aarch64.tar.gz"
    alpine_url="https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/$alpine_name"
    ;;
  *)
    printf 'unsupported Linux KVM lifecycle architecture: %s\n' "$architecture" >&2
    exit 2
    ;;
esac

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
source_cli="$binary_dir/a3s-oci"
source_shim="$binary_dir/a3s-oci-krun-shim"
source_runtime_dir="$binary_dir/a3s-oci-krun-runtime"
runtime_assets_manifest="crates/krun/runtime/runtime-assets.json"

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-lifecycle.XXXXXX")"
current_case="setup"
case_report=""
case_stderr=""
cleanup() {
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-lifecycle.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected Linux KVM lifecycle path: %s\n' "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

on_error() {
  local status=$?
  trap - ERR
  printf 'Linux KVM lifecycle case %s failed near line %s\n' \
    "$current_case" "${BASH_LINENO[0]}" >&2
  if [[ -n "$case_report" && -f "$case_report" ]]; then
    jq --raw-output '.reason // .bridge.reason // empty' "$case_report" \
      2>/dev/null >&2 || true
  fi
  if [[ -n "$case_stderr" && -s "$case_stderr" ]]; then
    tail -n 30 "$case_stderr" >&2 || true
  fi
  exit "$status"
}
trap on_error ERR

report_path="${A3S_OCI_LINUX_KVM_LIFECYCLE_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite Linux KVM lifecycle report: %s\n' "$report_path" >&2
  exit 1
fi
test -d "$(dirname "$report_path")"
test -f "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
test ! -L "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"

cargo "${build_arguments[@]}"
test -x "$source_cli"
test -x "$source_shim"
test -d "$source_runtime_dir"

binary_stage="$work/bin"
mkdir "$binary_stage"
chmod 0700 "$work" "$binary_stage"
cp -p "$source_cli" "$binary_stage/a3s-oci"
cp -p "$source_shim" "$binary_stage/a3s-oci-krun-shim"
cp -a "$source_runtime_dir" "$binary_stage/a3s-oci-krun-runtime"
cli="$binary_stage/a3s-oci"
shim="$binary_stage/a3s-oci-krun-shim"
runtime_dir="$binary_stage/a3s-oci-krun-runtime"

provenance="$(
  linux_kvm_provenance \
    linux-kvm-lifecycle-17-case-v1 "$profile" \
    "$cli" "$shim" "$runtime_dir" \
    "$runtime_assets_manifest" \
    "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
)"

features="$($cli features)"
kvm_driver="$(
  jq --compact-output \
    '.drivers[] | select(.driver == "libkrun-kvm")' \
    <<<"$features"
)"
test -n "$kvm_driver"
kvm_status="$(jq --raw-output '.status' <<<"$kvm_driver")"
manifest_sha256="$(
  sha256sum "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" | cut -d ' ' -f 1
)"

if [[ "$kvm_status" == "unavailable" ]]; then
  reason="$(jq --raw-output '.reason // "Linux KVM is unavailable"' <<<"$kvm_driver")"
  jq --null-input \
    --arg architecture "$architecture" \
    --arg manifest_sha256 "$manifest_sha256" \
    --arg reason "$reason" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$provenance" \
    '{
      schema_version: "a3s.oci.linux-kvm-lifecycle-matrix.v2",
      platform: "linux",
      architecture: $architecture,
      status: "unavailable",
      kvm_required: true,
      expected_case_count: 17,
      case_count: 0,
      system_image_manifest_sha256: $manifest_sha256,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      cases: [],
      reason: $reason
    }' | tee "$report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-lifecycle-matrix.v2"
     and .platform == "linux" and .status == "unavailable"
     and .kvm_required and .expected_case_count == 17 and .case_count == 0
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == "linux-kvm-lifecycle-17-case-v1"
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .provenance.system_image_manifest_sha256
       == .system_image_manifest_sha256
     and .kvm_driver.status == "unavailable"
     and .cases == [] and (.reason | length > 0)' \
    "$report_path" >/dev/null
  exit 0
fi
if [[ "$kvm_status" != "available" ]]; then
  printf 'unexpected Linux KVM probe status: %s\n' "$kvm_status" >&2
  exit 1
fi

bootstrap="$work/bootstrap"
runtime_share="$work/runtime-share"
console_directory="$work/consoles"
case_report_directory="$work/case-reports"
mkdir \
  "$bootstrap" "$runtime_share" "$console_directory" \
  "$case_report_directory"
mkdir "$runtime_share/run"
chmod 0700 \
  "$work" "$bootstrap" "$runtime_share" "$runtime_share/run" \
  "$console_directory" "$case_report_directory" "$binary_stage"

alpine_archive="$work/$alpine_name"
curl --fail --location --retry 3 --silent --show-error \
  --output "$alpine_archive" "$alpine_url"
rootfs_archive_sha256="$(sha256sum "$alpine_archive" | cut -d ' ' -f 1)"

bundle_a="$runtime_share/var/lib/a3s-oci-lifecycle/bundle-a"
bundle_b="$runtime_share/var/lib/a3s-oci-lifecycle/bundle-b"
scripts/prepare-utility-vm-bundle.sh \
  --alpine-archive "$alpine_archive" \
  --config fixtures/utility-vm/config.json \
  --bundle "$bundle_a" \
  --cgroups-path a3s-oci-kvm-lifecycle-a
scripts/prepare-utility-vm-bundle.sh \
  --alpine-archive "$alpine_archive" \
  --config fixtures/utility-vm/config.json \
  --bundle "$bundle_b" \
  --cgroups-path a3s-oci-kvm-lifecycle-b

marker_a="$bundle_a/rootfs/.a3s-oci-create-start-smoke"
marker_b="$bundle_b/rootfs/.a3s-oci-create-start-smoke"
cases_path="$work/cases.ndjson"
: > "$cases_path"

endpoint_inventory() {
  find /tmp -maxdepth 1 -type d -uid "$(id -u)" \
    -name 'a3s-oci-agent-*' -print 2>/dev/null | sort
}

shim_process_inventory() {
  ps -eo pid=,comm= | awk \
    'index($2, "a3s-oci-krun") == 1 {print $1 " " $2}' | sort
}

runtime_state_inventory() {
  find "$runtime_share/run" -mindepth 1 -printf '%P %y\n' | sort
}

assert_no_residue() {
  local endpoint_before="$1"
  local process_before="$2"
  local runtime_before="$3"
  local endpoint_after process_after runtime_after
  endpoint_after="$(endpoint_inventory)"
  process_after="$(shim_process_inventory)"
  runtime_after="$(runtime_state_inventory)"
  test "$endpoint_after" = "$endpoint_before"
  test "$process_after" = "$process_before"
  test "$runtime_after" = "$runtime_before"
  test -z "$(find "$bootstrap" -mindepth 1 -print -quit)"
  test -z "$(
    find "$runtime_share" -xdev \
      -name '.a3s-oci-guest-isolation-*' -print -quit
  )"
  test -z "$(
    find "$runtime_share" -xdev \
      \( -name '.a3s-oci-bootstrap-*' \
         -o -name '.a3s-oci-recovery-*' \
         -o -name '*.pending' \) \
      -print -quit
  )"
  test ! -e "$marker_a"
  test ! -e "$marker_b"
}

record_case() {
  local name="$1"
  local kind="$2"
  local boundary="$3"
  jq --compact-output \
    --arg name "$name" \
    --arg kind "$kind" \
    --arg boundary "$boundary" \
    '{
      name: $name,
      kind: $kind,
      boundary: (if $boundary == "" then null else $boundary end),
      status: "available",
      cleanup: {
        endpoint_restored: true,
        shim_process_inventory_restored: true,
        runtime_state_restored: true,
        bootstrap_empty: true,
        token_recovery_residue_absent: true,
        markers_absent: true
      },
      report: .
    }' "$case_report" >> "$cases_path"
}

run_case() {
  local name="$1"
  local kind="$2"
  local schema="$3"
  local boundary="$4"
  shift 4
  local endpoint_before process_before runtime_before status
  current_case="$name"
  case_report="$case_report_directory/$name.json"
  case_stderr="$case_report_directory/$name.stderr.log"
  endpoint_before="$(endpoint_inventory)"
  process_before="$(shim_process_inventory)"
  runtime_before="$(runtime_state_inventory)"
  printf 'Qualifying Linux KVM lifecycle case: %s\n' "$name" >&2

  if "$cli" "$@" > "$case_report" 2> "$case_stderr"; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" -ne 0 ]]; then
    return "$status"
  fi

  jq --exit-status \
    --arg schema "$schema" \
    --arg architecture "$architecture" \
    --arg manifest_sha256 "$manifest_sha256" \
    '.schema_version == $schema
     and .platform == "linux" and .status == "available"
     and .bridge.platform == "linux" and .bridge.status == "available"
     and .bridge.protocol_negotiated and .bridge.selected_protocol == 10
     and .bridge.guest_architecture == $architecture
     and .bridge.shim_report_verified and .bridge.shim_exit_code == 0
     and .bridge.shim_report.platform == "linux"
     and .bridge.shim_report.status == "available"
     and .bridge.shim_report.kvm_device_opened
     and .bridge.shim_report.kvm_api_verified
     and .bridge.shim_report.vm_entered
     and .bridge.shim_report.linux_boot_assets.manifest_sha256 == $manifest_sha256
     and .bridge.shim_report.linux_boot_assets.root_disk_read_only
     and (.reason == null)' "$case_report" >/dev/null

  case "$kind" in
    lifecycle)
      jq --exit-status \
        '.bundle_loaded and .create_returned_created and .wait_timeout_enforced
         and .delete_succeeded and .guest_runtime_clean' \
        "$case_report" >/dev/null
      ;;
    multi-container)
      jq --exit-status \
        '.bundles_loaded and .lifecycle.distinct_created_pids
         and .namespace_join.joined_non_mount_namespaces
         and .rootfs_mount.exact_evidence
         and .pid_supervision.orphan_reaping_enforced
         and .guest_runtime_clean' "$case_report" >/dev/null
      ;;
    guest-isolation)
      jq --exit-status \
        '.bundle_loaded and .separate_runtime_share
         and .expected_case_count == 10 and (.cases | length) == 10
         and [.cases[].name] == [
           "bundle-system-directory",
           "bundle-runtime-share-root",
           "bundle-agent-state-root",
           "absolute-rootfs",
           "rootfs-symlink-escape",
           "absolute-bind-source",
           "relative-bind-traversal",
           "bind-source-symlink-escape",
           "file-intermediate-magic-link-escape",
           "filesystem-intermediate-magic-link-escape"
         ]
         and all(.cases[];
           .expected_error_code == "permission-denied"
           and .request_rejected
           and .observed_error_code == .expected_error_code
           and .observed_error_operation == .expected_error_operation
           and (.observed_error_retryable | not)
           and .container_state_absent_after_case
           and .canary_unchanged)
         and .fixture_removed and .canary_removed
         and .guest_runtime_clean' "$case_report" >/dev/null
      ;;
    lifecycle-fault)
      jq --exit-status --arg boundary "$boundary" \
        '.bundle_loaded
         and .lifecycle.requested_fault == $boundary
         and .lifecycle.injected_fault == $boundary
         and (.lifecycle.normal_delete_attempted | not)
         and .marker_removed and .guest_runtime_clean' \
        "$case_report" >/dev/null
      ;;
    transport-fault)
      jq --exit-status --arg boundary "$boundary" \
        '.bundle_loaded and .requested_stage == $boundary
         and .fault_crossings == 1 and .observed_error_code == "unavailable"
         and .observed_error_retryable
         and (.normal_delete_attempted | not)
         and .marker_absent_after_cleanup and .guest_runtime_clean' \
        "$case_report" >/dev/null
      ;;
    *)
      printf 'unknown Linux KVM lifecycle case kind: %s\n' "$kind" >&2
      return 1
      ;;
  esac

  assert_no_residue "$endpoint_before" "$process_before" "$runtime_before"
  record_case "$name" "$kind" "$boundary"
  printf 'Qualified Linux KVM lifecycle case: %s\n' "$name" >&2
}

run_case \
  oci-vm-smoke lifecycle a3s.oci.oci-vm-smoke.v9 "" \
  oci-vm-smoke \
  --shim "$shim" \
  --vm-rootfs "$bootstrap" \
  --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
  --runtime-share "$runtime_share" \
  --bundle "$bundle_a" \
  --console "$console_directory/oci-vm-smoke.log"

run_case \
  oci-vm-multi-container-smoke multi-container \
  a3s.oci.oci-vm-multi-container-smoke.v11 "" \
  oci-vm-multi-container-smoke \
  --shim "$shim" \
  --vm-rootfs "$bootstrap" \
  --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
  --runtime-share "$runtime_share" \
  --bundle-a "$bundle_a" \
  --bundle-b "$bundle_b" \
  --console "$console_directory/oci-vm-multi-container-smoke.log"

run_case \
  oci-vm-guest-isolation-smoke guest-isolation \
  a3s.oci.oci-vm-guest-isolation.v1 "" \
  oci-vm-guest-isolation-smoke \
  --shim "$shim" \
  --vm-rootfs "$bootstrap" \
  --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
  --runtime-share "$runtime_share" \
  --bundle "$bundle_a" \
  --console "$console_directory/oci-vm-guest-isolation-smoke.log"

for phase in after-create after-start after-kill; do
  run_case \
    "lifecycle-fault-$phase" lifecycle-fault \
    a3s.oci.oci-vm-fault-cleanup.v4 "$phase" \
    oci-vm-fault-cleanup \
    --shim "$shim" \
    --vm-rootfs "$bootstrap" \
    --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
    --runtime-share "$runtime_share" \
    --bundle "$bundle_a" \
    --console "$console_directory/lifecycle-fault-$phase.log" \
    --fault-after "$phase"
done

for transport_stage in \
  host-before-request-write \
  host-after-request-write \
  host-before-response-read \
  host-after-response-read \
  guest-after-request-read \
  guest-before-dispatch \
  guest-after-dispatch \
  guest-before-response-write \
  guest-after-response-write \
  host-before-shutdown \
  host-after-shutdown
do
  run_case \
    "transport-fault-$transport_stage" transport-fault \
    a3s.oci.oci-vm-transport-fault-cleanup.v3 "$transport_stage" \
    oci-vm-transport-fault-cleanup \
    --shim "$shim" \
    --vm-rootfs "$bootstrap" \
    --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
    --runtime-share "$runtime_share" \
    --bundle "$bundle_a" \
    --console "$console_directory/transport-fault-$transport_stage.log" \
    --fault-at "$transport_stage"
done

current_case="aggregate-report"
case_report=""
case_stderr=""
jq --slurp \
  --arg architecture "$architecture" \
  --arg manifest_sha256 "$manifest_sha256" \
  --arg rootfs_archive_sha256 "$rootfs_archive_sha256" \
  --argjson kvm_driver "$kvm_driver" \
  --argjson provenance "$provenance" \
  '{
    schema_version: "a3s.oci.linux-kvm-lifecycle-matrix.v2",
    platform: "linux",
    architecture: $architecture,
    status: "available",
    kvm_required: true,
    expected_case_count: 17,
    case_count: length,
    system_image_manifest_sha256: $manifest_sha256,
    rootfs_archive_sha256: $rootfs_archive_sha256,
    provenance: $provenance,
    kvm_driver: $kvm_driver,
    cases: .
  }' "$cases_path" | tee "$report_path"

jq --exit-status \
  '.schema_version == "a3s.oci.linux-kvm-lifecycle-matrix.v2"
   and .platform == "linux" and .status == "available"
   and .kvm_required and .expected_case_count == 17 and .case_count == 17
   and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
   and .provenance.platform == .platform
   and .provenance.architecture == .architecture
   and .provenance.qualification_profile == "linux-kvm-lifecycle-17-case-v1"
   and .provenance.driver == "libkrun-kvm"
   and .provenance.isolation == "dedicated-vm"
   and .provenance.source_tree_clean
   and .provenance.system_image_manifest_sha256
     == .system_image_manifest_sha256
   and .kvm_driver.status == "available"
   and ([.cases[] | select(.kind == "lifecycle")] | length) == 1
   and ([.cases[] | select(.kind == "multi-container")] | length) == 1
   and ([.cases[] | select(.kind == "guest-isolation")] | length) == 1
   and ([.cases[] | select(.kind == "lifecycle-fault")] | length) == 3
   and ([.cases[] | select(.kind == "transport-fault")] | length) == 11
   and ([.cases[] | select(
     .status == "available"
     and .cleanup.endpoint_restored
     and .cleanup.shim_process_inventory_restored
     and .cleanup.runtime_state_restored
     and .cleanup.bootstrap_empty
     and .cleanup.token_recovery_residue_absent
     and .cleanup.markers_absent
     and .report.platform == "linux"
     and .report.status == "available"
   )] | length) == 17' "$report_path" >/dev/null
