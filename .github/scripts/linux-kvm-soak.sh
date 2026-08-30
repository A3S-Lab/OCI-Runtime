#!/usr/bin/env bash
set -Eeuo pipefail

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-provenance.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM soak qualification requires a Linux host\n' >&2
  exit 2
fi

for command in cargo chmod curl cut dirname jq mkdir mktemp rm sha256sum tail tee uname
do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Linux KVM soak command is unavailable: %s\n' "$command" >&2
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
    printf 'unsupported Linux KVM soak architecture: %s\n' "$architecture" >&2
    exit 2
    ;;
esac

iterations="${A3S_OCI_LINUX_KVM_SOAK_ITERATIONS:-25}"
if [[ ! "$iterations" =~ ^[0-9]+$ ]] ||
  ((iterations < 1 || iterations > 1000)); then
  printf 'Linux KVM soak iterations must be between 1 and 1000: %s\n' \
    "$iterations" >&2
  exit 2
fi

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

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-soak.XXXXXX")"
runtime_report="$work/runtime-report.json"
runtime_stderr="$work/runtime.stderr.log"
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && "${A3S_OCI_KEEP_FAILED_WORK:-0}" == "1" ]]; then
    printf 'preserving failed Linux KVM soak work directory: %s\n' \
      "$work" >&2
    return 0
  fi
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-soak.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected Linux KVM soak path: %s\n' "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

on_error() {
  local status=$?
  trap - ERR
  printf 'Linux KVM soak qualification failed with status %s near line %s\n' \
    "$status" "${BASH_LINENO[0]}" >&2
  if [[ -s "$runtime_report" ]]; then
    jq --compact-output \
      '{schema_version, status, reason, completed_iterations,
        requested_iterations, cleanup}' \
      "$runtime_report" >&2 2>/dev/null || true
  fi
  if [[ -s "$runtime_stderr" ]]; then
    tail -n 40 "$runtime_stderr" >&2 || true
  fi
  exit "$status"
}
trap on_error ERR

report_path="${A3S_OCI_LINUX_KVM_SOAK_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite Linux KVM soak report: %s\n' "$report_path" >&2
  exit 1
fi
test -d "$(dirname "$report_path")"
test -f "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
test ! -L "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"

cargo "${build_arguments[@]}"
test -x "$cli"
test -x "$shim"
test -d "$runtime_dir"

provenance="$(
  linux_kvm_provenance \
    linux-kvm-bounded-soak-only-v1 "$profile" \
    "$cli" "$shim" "$runtime_dir" "$runtime_assets_manifest" \
    "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
)"
source_revision="$(jq --raw-output '.source_revision' <<<"$provenance")"

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
    --arg reason "$reason" \
    --argjson iterations "$iterations" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$provenance" \
    '{
      schema_version: "a3s.oci.linux-kvm-soak-matrix.v2",
      platform: "linux",
      architecture: $architecture,
      status: "unavailable",
      kvm_required: true,
      requested_iterations: $iterations,
      completed_iterations: 0,
      fixture_downloaded: false,
      rootfs_archive_sha256: null,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      report: null,
      reason: $reason
    }' | tee "$report_path"
  jq --exit-status --argjson iterations "$iterations" \
    '.schema_version == "a3s.oci.linux-kvm-soak-matrix.v2"
     and .platform == "linux" and .status == "unavailable"
     and .kvm_required and .requested_iterations == $iterations
     and .completed_iterations == 0 and (.fixture_downloaded | not)
     and .rootfs_archive_sha256 == null
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == "linux-kvm-bounded-soak-only-v1"
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .kvm_driver.status == "unavailable" and .report == null
     and (.reason | length > 0)' "$report_path" >/dev/null
  exit 0
fi
if [[ "$kvm_status" != "available" ]]; then
  printf 'unexpected Linux KVM probe status: %s\n' "$kvm_status" >&2
  exit 1
fi

alpine_archive="$work/$alpine_name"
curl --fail --location --retry 3 --silent --show-error \
  --output "$alpine_archive" "$alpine_url"
rootfs_archive_sha256="$(sha256sum "$alpine_archive" | cut -d ' ' -f 1)"
bundle="$work/bundle"
scripts/prepare-utility-vm-bundle.sh \
  --alpine-archive "$alpine_archive" \
  --config fixtures/utility-vm/config.linux-kvm.json \
  --bundle "$bundle" \
  --cgroups-path a3s-oci-kvm-soak
evidence_parent="$work/evidence"
mkdir "$evidence_parent"
chmod 0700 "$work" "$bundle" "$evidence_parent"

if "$cli" linux-kvm-soak \
  --shim "$shim" \
  --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
  --bundle "$bundle" \
  --work-parent "$evidence_parent" \
  --source-revision "$source_revision" \
  --iterations "$iterations" \
  > "$runtime_report" 2> "$runtime_stderr"
then
  runtime_status=0
else
  runtime_status=$?
fi
test "$runtime_status" -eq 0

jq --exit-status \
  --arg architecture "$architecture" \
  --arg manifest_sha256 "$manifest_sha256" \
  --arg source_revision "$source_revision" \
  --arg cgroups_path 'a3s-oci-kvm-soak' \
  --argjson iterations "$iterations" \
  '.schema_version == "a3s.oci.linux-kvm-soak.v1"
   and .platform == "linux" and .architecture == $architecture
   and .status == "available" and .kvm_required
   and .requested_iterations == $iterations
   and .artifacts.system_image_manifest_sha256 == $manifest_sha256
   and .artifacts.source_revision == $source_revision
   and .qualification_scope_verified
   and .source_cgroups_path == $cgroups_path
   and (.host_service != null) and .socket_peer == .host_service
   and (.waves | length) == $iterations
   and all(.waves[];
     .target.generation == .iteration
     and .configured_cgroups_path == $cgroups_path
     and .create_replayed and .generation_monotonic
     and .stale_generation_rejected and .start_returned_running
     and .init_marker_verified and (.live_vm_processes | length) >= 2
     and .kill_replayed
     and .wait_status == {"signal": 9, "oom_killed": false}
     and .wait_replayed and .delete_replayed and .state_removed
     and .source_marker_absent and .vm_processes_reaped
     and .endpoint_inventory_restored and .descriptor_inventory_restored
     and .bundle_handoffs_clean and .runtime_shares_clean
     and .recovery_reports_clean and .guest_cgroup_lifetime_bounded
     and .console_files_retained >= .iteration)
   and (.steady_open_descriptors > 0)
   and .final_open_descriptors == .steady_open_descriptors
   and .console_files_created >= $iterations
   and .service_socket_removed and .service_exit_success
   and .failure_iteration == null and .reason == null' \
  "$runtime_report" >/dev/null

jq --null-input \
  --arg architecture "$architecture" \
  --arg rootfs_archive_sha256 "$rootfs_archive_sha256" \
  --argjson iterations "$iterations" \
  --argjson kvm_driver "$kvm_driver" \
  --argjson provenance "$provenance" \
  --slurpfile report "$runtime_report" \
  '{
    schema_version: "a3s.oci.linux-kvm-soak-matrix.v2",
    platform: "linux",
    architecture: $architecture,
    status: "available",
    kvm_required: true,
    requested_iterations: $iterations,
    completed_iterations: ($report[0].waves | length),
    fixture_downloaded: true,
    rootfs_archive_sha256: $rootfs_archive_sha256,
    provenance: $provenance,
    kvm_driver: $kvm_driver,
    report: $report[0],
    reason: null
  }' | tee "$report_path"

jq --exit-status --argjson iterations "$iterations" \
  '.schema_version == "a3s.oci.linux-kvm-soak-matrix.v2"
   and .platform == "linux" and .status == "available"
   and .kvm_required and .requested_iterations == $iterations
   and .completed_iterations == $iterations and .fixture_downloaded
   and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
   and .provenance.platform == .platform
   and .provenance.architecture == .architecture
   and .provenance.qualification_profile == "linux-kvm-bounded-soak-only-v1"
   and .provenance.driver == "libkrun-kvm"
   and .provenance.isolation == "dedicated-vm"
   and .provenance.source_tree_clean
   and .report.artifacts.host_service_executable_sha256
     == .provenance.host_executable_sha256
   and .report.artifacts.shim_sha256 == .provenance.shim_executable_sha256
   and .report.artifacts.system_image_manifest_sha256
     == .provenance.system_image_manifest_sha256
   and .report.artifacts.source_revision == .provenance.source_revision
   and .kvm_driver.status == "available"
   and .report.status == "available"
   and (.report.waves | length) == $iterations
   and (.reason == null)' "$report_path" >/dev/null
