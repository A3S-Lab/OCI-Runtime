#!/usr/bin/env bash
set -Eeuo pipefail

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-provenance.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM recovery qualification requires a Linux host\n' >&2
  exit 2
fi

for command in cargo chmod cp curl cut dirname jq mkdir mktemp rm sha256sum tail tee uname
do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Linux KVM recovery command is unavailable: %s\n' "$command" >&2
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
    printf 'unsupported Linux KVM recovery architecture: %s\n' "$architecture" >&2
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
cli="$binary_dir/a3s-oci"
shim="$binary_dir/a3s-oci-krun-shim"
runtime_dir="$binary_dir/a3s-oci-krun-runtime"
runtime_assets_manifest="crates/krun/runtime/runtime-assets.json"

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-recovery.XXXXXX")"
runtime_report="$work/runtime-report.json"
runtime_stderr="$work/runtime.stderr.log"
cleanup() {
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-recovery.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected Linux KVM recovery path: %s\n' "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

on_error() {
  local status=$?
  trap - ERR
  printf 'Linux KVM recovery qualification failed near line %s\n' \
    "${BASH_LINENO[0]}" >&2
  if [[ -s "$runtime_report" ]]; then
    jq --raw-output '.reason // .recovery.reason // empty' "$runtime_report" \
      2>/dev/null >&2 || true
  fi
  if [[ -s "$runtime_stderr" ]]; then
    tail -n 40 "$runtime_stderr" >&2 || true
  fi
  exit "$status"
}
trap on_error ERR

report_path="${A3S_OCI_LINUX_KVM_RECOVERY_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite Linux KVM recovery report: %s\n' "$report_path" >&2
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
    linux-kvm-owner-death-restart-only-v1 "$profile" \
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
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$provenance" \
    '{
      schema_version: "a3s.oci.linux-kvm-recovery-matrix.v2",
      platform: "linux",
      architecture: $architecture,
      status: "unavailable",
      kvm_required: true,
      expected_case_count: 1,
      case_count: 0,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      report: null,
      reason: $reason
    }' | tee "$report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-recovery-matrix.v2"
     and .platform == "linux" and .status == "unavailable"
     and .kvm_required and .expected_case_count == 1 and .case_count == 0
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile
       == "linux-kvm-owner-death-restart-only-v1"
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
  --config fixtures/utility-vm/config.json \
  --bundle "$bundle" \
  --cgroups-path a3s-oci-kvm-recovery
evidence_parent="$work/evidence"
mkdir "$evidence_parent"
chmod 0700 "$work" "$bundle" "$evidence_parent"

if "$cli" linux-kvm-recovery-smoke \
  --shim "$shim" \
  --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
  --bundle "$bundle" \
  --work-parent "$evidence_parent" \
  --source-revision "$source_revision" \
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
  '.schema_version == "a3s.oci.linux-kvm-recovery-smoke.v1"
   and .platform == "linux" and .architecture == $architecture
   and .status == "available" and .kvm_required
   and .expected_case_count == 1 and .case_count == 1
   and .artifacts.system_image_manifest_sha256 == $manifest_sha256
   and .artifacts.source_revision == $source_revision
   and .recovery.qualification_scope_verified
   and .recovery.host_service_sigkill_delivered
   and .recovery.first_host_service_reaped
   and .recovery.live_vm_processes_reaped
   and .recovery.authenticated_recovery_report_retained
   and .recovery.replacement_socket_new_owner
   and .recovery.exact_stopped_state_recovered
   and .recovery.recovered_wait_status == {"signal": 9, "oom_killed": false}
   and .recovery.recovered_wait_replayed
   and .recovery.stopped_delete_succeeded
   and .recovery.replacement_descriptor_inventory_restored
   and .recovery.bundle_handoffs_clean
   and .recovery.runtime_shares_clean
   and .recovery.recovery_reports_clean
   and .recovery.replacement_socket_removed
   and .recovery.replacement_exit_success
   and .recovery.service_restart_recovered
   and (.reason == null)' "$runtime_report" >/dev/null

jq --null-input \
  --arg architecture "$architecture" \
  --arg rootfs_archive_sha256 "$rootfs_archive_sha256" \
  --argjson kvm_driver "$kvm_driver" \
  --argjson provenance "$provenance" \
  --slurpfile report "$runtime_report" \
  '{
    schema_version: "a3s.oci.linux-kvm-recovery-matrix.v2",
    platform: "linux",
    architecture: $architecture,
    status: "available",
    kvm_required: true,
    expected_case_count: 1,
    case_count: 1,
    rootfs_archive_sha256: $rootfs_archive_sha256,
    provenance: $provenance,
    kvm_driver: $kvm_driver,
    report: $report[0],
    reason: null
  }' | tee "$report_path"

jq --exit-status \
  '.schema_version == "a3s.oci.linux-kvm-recovery-matrix.v2"
   and .platform == "linux" and .status == "available"
   and .kvm_required and .expected_case_count == 1 and .case_count == 1
   and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
   and .provenance.platform == .platform
   and .provenance.architecture == .architecture
   and .provenance.qualification_profile
     == "linux-kvm-owner-death-restart-only-v1"
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
   and .report.recovery.service_restart_recovered
   and (.reason == null)' "$report_path" >/dev/null
