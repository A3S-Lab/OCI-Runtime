#!/usr/bin/env bash
set -Eeuo pipefail

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-provenance.sh

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

entry_provenance="$(
  linux_kvm_provenance \
    linux-kvm-agent-entry-v1 "$profile" \
    "$cli" "$shim" "$runtime_dir" "$runtime_assets_manifest" \
    "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
)"
post_probe_provenance="$(
  linux_kvm_provenance \
    linux-kvm-post-probe-failure-v1 "$profile" \
    "$cli" "$shim" "$runtime_dir" "$runtime_assets_manifest" \
    "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST"
)"

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-agent-entry.XXXXXX")"
cleanup() {
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-agent-entry.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected KVM smoke path: %s\n' "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

bootstrap="$work/bootstrap"
runtime_share="$work/runtime-share"
console="$work/console.log"
qualification_bootstrap="$work/qualification-bootstrap"
qualification_runtime_share="$work/qualification-runtime-share"
qualification_console="$work/qualification-console.log"
mkdir "$bootstrap" "$runtime_share" \
  "$qualification_bootstrap" "$qualification_runtime_share"
mkdir "$runtime_share/run"
mkdir "$qualification_runtime_share/run"
chmod 0700 \
  "$bootstrap" "$runtime_share" "$runtime_share/run" \
  "$qualification_bootstrap" "$qualification_runtime_share" \
  "$qualification_runtime_share/run"

report_path="${A3S_OCI_LINUX_KVM_AGENT_REPORT:-$work/report.json}"
qualification_report_path="${A3S_OCI_LINUX_KVM_POST_PROBE_FAILURE_REPORT:-$work/post-probe-failure-report.json}"
if [[ "$report_path" == "$qualification_report_path" ]]; then
  printf '%s\n' 'Linux KVM entry reports must use distinct output paths' >&2
  exit 1
fi
for output_path in "$report_path" "$qualification_report_path"; do
  if [[ -e "$output_path" || -L "$output_path" ]]; then
    printf 'refusing to overwrite Linux KVM evidence report: %s\n' \
      "$output_path" >&2
    exit 1
  fi
  test -d "$(dirname "$output_path")"
done
raw_report="$work/agent-vm-smoke.json"
qualification_raw_report="$work/post-probe-failure.json"
manifest_sha256="$(sha256sum "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" | cut -d ' ' -f 1)"
architecture="$(uname -m)"

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

endpoint_before="$(endpoint_inventory)"
process_before="$(shim_process_inventory)"
runtime_share_before="$(runtime_share_inventory "$runtime_share")"
features="$($cli features)"
kvm_driver="$(
  jq --compact-output \
    '.drivers[] | select(.driver == "libkrun-kvm")' \
    <<<"$features"
)"
test -n "$kvm_driver"
kvm_status="$(jq --raw-output '.status' <<<"$kvm_driver")"
kvm_device_opened="$(
  jq --raw-output '.evidence.device_opened' <<<"$kvm_driver"
)"
case "$kvm_device_opened" in
  true | false) ;;
  *)
    printf 'unexpected Linux KVM device-opened evidence: %s\n' "$kvm_device_opened" >&2
    exit 1
    ;;
esac

set +e
output="$(
  "$cli" agent-vm-smoke \
    --shim "$shim" \
    --rootfs "$bootstrap" \
    --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
    --runtime-share "$runtime_share" \
    --console "$console"
)"
status=$?
set -e
printf '%s\n' "$output" > "$raw_report"

if [[ "$kvm_status" == "available" ]]; then
  test "$status" -eq 0
  jq --exit-status \
    --arg architecture "$architecture" \
    --arg manifest_sha256 "$manifest_sha256" \
    '.schema_version == "a3s.oci.agent-vm-smoke.v10"
     and .platform == "linux" and .status == "available"
     and .endpoint_bound and .shim_spawned
     and (.shim_process_id > 0) and (.bridge_process_id > 0)
     and (.shim_process_id != .bridge_process_id)
     and .shim_client_verified and .protocol_negotiated
     and .selected_protocol == 10
     and .guest_architecture == $architecture
     and .advertised_operations
       == ["create", "state", "start", "kill", "delete", "wait",
           "exec", "signal-process", "wait-process", "pause", "resume",
           "processes", "update", "stats", "read-output", "write-stdin",
           "close-stdin", "resize", "file", "filesystem",
           "acknowledge-operations"]
     and .shim_report_verified and .shim_exit_code == 0
     and .console_created
     and .shim_report.schema_version == "a3s.oci.krun-agent-vm-smoke.v7"
     and .shim_report.platform == "linux"
     and .shim_report.status == "available"
     and .shim_report.runtime_bundle_loaded
     and .shim_report.context_created and .shim_report.vm_configured
     and .shim_report.rootfs_configured
     and .shim_report.runtime_share_configured
     and .shim_report.kvm_device_opened
     and .shim_report.kvm_api_verified
     and (.shim_report.kvm_post_probe_failure_injected | not)
     and .shim_report.agent_binary_present
     and .shim_report.agent_vsock_configured
     and .shim_report.workload_configured
     and .shim_report.console_configured
     and .shim_report.vm_entered
     and .shim_report.guest_exit_code == 0
     and .shim_report.linux_boot_assets.target_arch == $architecture
     and .shim_report.linux_boot_assets.manifest_sha256 == $manifest_sha256
     and .shim_report.linux_boot_assets.root_disk_read_only
     and (.reason == null)' \
    "$raw_report" >/dev/null

  qualification_endpoint_before="$(endpoint_inventory)"
  qualification_process_before="$(shim_process_inventory)"
  qualification_runtime_share_before="$(
    runtime_share_inventory "$qualification_runtime_share"
  )"
  set +e
  qualification_output="$(
    "$cli" agent-vm-smoke \
      --shim "$shim" \
      --rootfs "$qualification_bootstrap" \
      --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
      --runtime-share "$qualification_runtime_share" \
      --console "$qualification_console" \
      --qualify-kvm-post-probe-failure
  )"
  qualification_status=$?
  set -e
  printf '%s\n' "$qualification_output" > "$qualification_raw_report"

  test "$qualification_status" -eq 2
  jq --exit-status \
    --arg architecture "$architecture" \
    --arg manifest_sha256 "$manifest_sha256" \
    '.schema_version == "a3s.oci.agent-vm-smoke.v10"
     and .platform == "linux" and .status == "unavailable"
     and .endpoint_bound and .shim_spawned
     and (.shim_process_id > 0)
     and (.bridge_process_id == null)
     and (.shim_client_verified | not)
     and (.protocol_negotiated | not)
     and (.shim_report_verified | not)
     and .shim_exit_code == 2
     and (.console_created | not)
     and .shim_report.schema_version == "a3s.oci.krun-agent-vm-smoke.v7"
     and .shim_report.platform == "linux"
     and .shim_report.status == "unavailable"
     and .shim_report.runtime_bundle_loaded
     and .shim_report.context_created and .shim_report.vm_configured
     and .shim_report.rootfs_configured
     and .shim_report.runtime_share_configured
     and .shim_report.kvm_device_opened
     and .shim_report.kvm_api_verified
     and .shim_report.kvm_post_probe_failure_injected
     and .shim_report.agent_binary_present
     and .shim_report.agent_vsock_configured
     and .shim_report.workload_configured
     and .shim_report.console_configured
     and (.shim_report.vm_entered | not)
     and .shim_report.guest_exit_code == null
     and .shim_report.console_created
     and .shim_report.linux_boot_assets.target_arch == $architecture
     and .shim_report.linux_boot_assets.manifest_sha256 == $manifest_sha256
     and .shim_report.linux_boot_assets.root_disk_read_only
     and (.shim_report.reason
       == "injected Linux KVM failure after device verification and before native VM entry")
     and (.reason | contains("exited before connecting the authenticated agent bridge"))' \
    "$qualification_raw_report" >/dev/null
  test ! -e "$qualification_console"

  qualification_endpoint_after="$(endpoint_inventory)"
  qualification_process_after="$(shim_process_inventory)"
  qualification_runtime_share_after="$(
    runtime_share_inventory "$qualification_runtime_share"
  )"
  test "$qualification_endpoint_after" = "$qualification_endpoint_before"
  test "$qualification_process_after" = "$qualification_process_before"
  test "$qualification_runtime_share_after" = "$qualification_runtime_share_before"
elif [[ "$kvm_status" == "unavailable" ]]; then
  test "$status" -eq 2
  jq --exit-status \
    --arg architecture "$architecture" \
    --arg manifest_sha256 "$manifest_sha256" \
    --argjson kvm_device_opened "$kvm_device_opened" \
    '.schema_version == "a3s.oci.agent-vm-smoke.v10"
     and .platform == "linux" and .status == "unavailable"
     and .endpoint_bound and .shim_spawned
     and (.shim_process_id > 0)
     and (.shim_client_verified | not)
     and (.protocol_negotiated | not)
     and (.shim_report_verified | not)
     and .shim_exit_code == 2
     and .shim_report.schema_version == "a3s.oci.krun-agent-vm-smoke.v7"
     and .shim_report.platform == "linux"
     and .shim_report.status == "unavailable"
     and .shim_report.runtime_bundle_loaded
     and .shim_report.context_created and .shim_report.vm_configured
     and .shim_report.rootfs_configured
     and .shim_report.runtime_share_configured
     and .shim_report.kvm_device_opened == $kvm_device_opened
     and (.shim_report.kvm_api_verified | not)
     and (.shim_report.kvm_post_probe_failure_injected | not)
     and .shim_report.agent_binary_present
     and .shim_report.agent_vsock_configured
     and .shim_report.workload_configured
     and .shim_report.console_configured
     and (.shim_report.vm_entered | not)
     and .shim_report.linux_boot_assets.target_arch == $architecture
     and .shim_report.linux_boot_assets.manifest_sha256 == $manifest_sha256
     and .shim_report.linux_boot_assets.root_disk_read_only
     and (.shim_report.reason | contains("KVM"))
     and (.reason | length > 0)' \
    "$raw_report" >/dev/null
else
  printf 'unexpected Linux KVM probe status: %s\n' "$kvm_status" >&2
  exit 1
fi

endpoint_after="$(endpoint_inventory)"
process_after="$(shim_process_inventory)"
runtime_share_after="$(runtime_share_inventory "$runtime_share")"
test "$endpoint_after" = "$endpoint_before"
test "$process_after" = "$process_before"
test "$runtime_share_after" = "$runtime_share_before"
test -z "$(
  find "$runtime_share" "$qualification_runtime_share" -maxdepth 1 \
    \( -name '.a3s-oci-bootstrap-*' -o -name '.a3s-oci-recovery-*' \) \
    -print -quit
)"

if [[ "$kvm_status" == "available" ]]; then
  jq --null-input \
    --arg architecture "$architecture" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$entry_provenance" \
    --slurpfile report "$raw_report" \
    '{
      schema_version: "a3s.oci.linux-kvm-agent-entry.v1",
      platform: "linux",
      architecture: $architecture,
      status: "available",
      kvm_required: true,
      expected_case_count: 1,
      case_count: 1,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      report: $report[0],
      reason: null
    }' | tee "$report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-agent-entry.v1"
     and .platform == "linux" and .status == "available"
     and .kvm_required and .expected_case_count == 1 and .case_count == 1
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == "linux-kvm-agent-entry-v1"
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .kvm_driver.status == "available"
     and .report.status == "available"
     and .report.shim_report.linux_boot_assets.manifest_sha256
       == .provenance.system_image_manifest_sha256
     and (.reason == null)' "$report_path" >/dev/null

  jq --null-input \
    --arg architecture "$architecture" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$post_probe_provenance" \
    --slurpfile report "$qualification_raw_report" \
    '{
      schema_version: "a3s.oci.linux-kvm-post-probe-failure.v1",
      platform: "linux",
      architecture: $architecture,
      status: "available",
      expected_outcome: "fail-closed-before-vm-entry",
      kvm_required: true,
      expected_case_count: 1,
      case_count: 1,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      report: $report[0],
      reason: null
    }' | tee "$qualification_report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-post-probe-failure.v1"
     and .platform == "linux" and .status == "available"
     and .expected_outcome == "fail-closed-before-vm-entry"
     and .kvm_required and .expected_case_count == 1 and .case_count == 1
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == "linux-kvm-post-probe-failure-v1"
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .kvm_driver.status == "available"
     and .report.status == "unavailable"
     and .report.shim_report.kvm_post_probe_failure_injected
     and (.report.shim_report.vm_entered | not)
     and .report.shim_report.linux_boot_assets.manifest_sha256
       == .provenance.system_image_manifest_sha256
     and (.reason == null)' "$qualification_report_path" >/dev/null
else
  reason="$(jq --raw-output '.reason' "$raw_report")"
  jq --null-input \
    --arg architecture "$architecture" \
    --arg reason "$reason" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$entry_provenance" \
    --slurpfile report "$raw_report" \
    '{
      schema_version: "a3s.oci.linux-kvm-agent-entry.v1",
      platform: "linux",
      architecture: $architecture,
      status: "unavailable",
      kvm_required: true,
      expected_case_count: 1,
      case_count: 0,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      report: $report[0],
      reason: $reason
    }' | tee "$report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-agent-entry.v1"
     and .platform == "linux" and .status == "unavailable"
     and .kvm_required and .expected_case_count == 1 and .case_count == 0
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == "linux-kvm-agent-entry-v1"
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .kvm_driver.status == "unavailable"
     and .report.status == "unavailable"
     and (.reason | length > 0)' "$report_path" >/dev/null

  jq --null-input \
    --arg architecture "$architecture" \
    --arg reason "$reason" \
    --argjson kvm_driver "$kvm_driver" \
    --argjson provenance "$post_probe_provenance" \
    '{
      schema_version: "a3s.oci.linux-kvm-post-probe-failure.v1",
      platform: "linux",
      architecture: $architecture,
      status: "unavailable",
      expected_outcome: "fail-closed-before-vm-entry",
      kvm_required: true,
      expected_case_count: 1,
      case_count: 0,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      report: null,
      reason: $reason
    }' | tee "$qualification_report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-post-probe-failure.v1"
     and .platform == "linux" and .status == "unavailable"
     and .expected_outcome == "fail-closed-before-vm-entry"
     and .kvm_required and .expected_case_count == 1 and .case_count == 0
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.platform == .platform
     and .provenance.architecture == .architecture
     and .provenance.qualification_profile == "linux-kvm-post-probe-failure-v1"
     and .provenance.driver == "libkrun-kvm"
     and .provenance.isolation == "dedicated-vm"
     and .provenance.source_tree_clean
     and .kvm_driver.status == "unavailable" and .report == null
     and (.reason | length > 0)' "$qualification_report_path" >/dev/null
fi
