#!/usr/bin/env bash
set -Eeuo pipefail

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

source .github/scripts/lib/linux-kvm-provenance.sh

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM Update reopen qualification requires a Linux host\n' >&2
  exit 2
fi

for command in \
  awk cargo chmod cp curl cut dirname find id jq mkdir mktemp ps rm sha256sum sort \
  tail tee uname wc
do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Linux KVM Update reopen command is unavailable: %s\n' \
      "$command" >&2
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
    printf 'unsupported Linux KVM Update reopen architecture: %s\n' \
      "$architecture" >&2
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
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-update-reopen.XXXXXX")"
current_stage="setup"
case_report=""
case_stderr=""
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && "${A3S_OCI_KEEP_FAILED_WORK:-0}" == "1" ]]; then
    printf 'preserving failed Linux KVM Update reopen work directory: %s\n' \
      "$work" >&2
    return 0
  fi
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-update-reopen.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected Linux KVM Update reopen path: %s\n' \
        "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

on_error() {
  local status=$?
  trap - ERR
  printf 'Linux KVM Update reopen stage %s failed with status %s near line %s\n' \
    "$current_stage" "$status" "${BASH_LINENO[0]}" >&2
  if [[ -n "$case_report" && -s "$case_report" ]]; then
    jq --compact-output \
      '{schema_version, status, requested_stage, reason,
        durable_running_retained, update_journal_prepared_before_reopen,
        update_journal_succeeded_before_reopen, first_operation_dispatches,
        host_service_reopened, replacement_recovery_calls,
        replacement_rehydrated_created_record,
        replacement_rehydrated_running_record, replacement_rehydrated_update,
        replacement_update_effect_verified, replacement_operation_dispatches,
        host_changed_request_rejected, host_stale_generation_rejected,
        guest_stale_generation_rejected, replacement_workload_verified,
        owners_distinct, state_root_removed}' \
      "$case_report" >&2 2>/dev/null || true
  fi
  if [[ -n "$case_stderr" && -s "$case_stderr" ]]; then
    tail -n 40 "$case_stderr" >&2 || true
  fi
  exit "$status"
}
trap on_error ERR

report_path="${A3S_OCI_LINUX_KVM_UPDATE_REOPEN_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite Linux KVM Update reopen report: %s\n' \
    "$report_path" >&2
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
    linux-kvm-update-reopen-9-stage-v1 "$profile" \
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
      schema_version: "a3s.oci.linux-kvm-update-reopen-matrix.v1",
      platform: "linux",
      architecture: $architecture,
      status: "unavailable",
      kvm_required: true,
      qualification_scope: "linux-kvm-operation-stage-reopen-only-v1",
      expected_case_count: 9,
      case_count: 0,
      system_image_manifest_sha256: $manifest_sha256,
      provenance: $provenance,
      kvm_driver: $kvm_driver,
      cases: [],
      reason: $reason
    }' | tee "$report_path"
  jq --exit-status \
    '.schema_version == "a3s.oci.linux-kvm-update-reopen-matrix.v1"
     and .platform == "linux" and .status == "unavailable"
     and .qualification_scope
       == "linux-kvm-operation-stage-reopen-only-v1"
     and .kvm_required and .expected_case_count == 9 and .case_count == 0
     and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
     and .provenance.qualification_profile
       == "linux-kvm-update-reopen-9-stage-v1"
     and .provenance.source_tree_clean
     and .kvm_driver.status == "unavailable"
     and .cases == [] and (.reason | length > 0)' \
    "$report_path" >/dev/null
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
  --cgroups-path a3s-oci-kvm-update-reopen
init_marker="$bundle/rootfs/.a3s-oci-create-start-smoke"
test ! -e "$init_marker"

case_report_directory="$work/cases"
mkdir "$case_report_directory"
chmod 0700 "$case_report_directory"
cases_path="$work/cases.ndjson"
: > "$cases_path"

endpoint_inventory() {
  find /tmp -maxdepth 1 -type d -uid "$(id -u)" \
    -name 'a3s-oci-agent-*' -print 2>/dev/null | sort
}

shim_process_inventory() {
  ps -eo pid=,comm= | \
    awk 'index($2, "a3s-oci-krun") == 1 {print $1 " " $2}' | sort
}

endpoint_baseline="$(endpoint_inventory)"
process_baseline="$(shim_process_inventory)"

stages=(
  host-before-request-write
  host-after-request-write
  host-before-response-read
  host-after-response-read
  guest-after-request-read
  guest-before-dispatch
  guest-after-dispatch
  guest-before-response-write
  guest-after-response-write
)

run_stage() {
  local stage="$1"
  local runtime_root="$work/runtime-$stage"
  local status
  current_stage="$stage"
  case_report="$case_report_directory/$stage.json"
  case_stderr="$case_report_directory/$stage.stderr.log"
  printf 'Qualifying Linux KVM Update reopen stage: %s\n' "$stage" >&2

  set +e
  "$cli" linux-kvm-update-reopen \
    --shim "$shim" \
    --runtime-root "$runtime_root" \
    --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
    --bundle "$bundle" \
    --fault-at "$stage" \
    > "$case_report" 2> "$case_stderr"
  status=$?
  set -e
  test "$status" -eq 0

  jq --exit-status \
    --arg stage "$stage" \
    --arg architecture "$architecture" \
    --arg manifest_sha256 "$manifest_sha256" \
    '.schema_version
       == "a3s.oci.oci-vm-operation-reopen-replacement.v12"
     and .platform == "linux" and .status == "available"
     and .bundle_loaded and .requested_operation == "update"
     and .requested_stage == $stage
     and (.qualification_operation_id | startswith("kvm-update-reopen-"))
     and (.setup_create_operation_id | startswith("kvm-update-reopen-"))
     and (.setup_start_operation_id | startswith("kvm-update-reopen-"))
     and ([.qualification_operation_id, .setup_create_operation_id,
           .setup_start_operation_id] | unique | length) == 3
     and (.setup_kill_operation_id == null)
     and (.setup_exec_operation_id == null)
     and (.setup_signal_process_operation_id == null)
     and (.setup_pause_operation_id == null)
     and (.container_id | startswith("kvm-update-reopen-"))
     and .update_resources.memory.limit == 536870912
     and .update_resources.memory.reservation == 67108864
     and (.update_resources.memory.swap == null)
     and .update_resources.cpu.shares == 512
     and .update_resources.cpu.quota == 50000
     and .update_resources.cpu.period == 100000
     and .update_resources.cpu.cpus == "0"
     and .update_resources.cpu.mems == "0"
     and .update_resources.pids.limit == 64
     and .negotiated_protocol == 10
     and .injected_point == ("agent-v10.update-" + $stage)
     and .fault_crossings == 1
     and .first_operation_error_code == "unavailable"
     and .first_operation_error_retryable
     and (if ($stage | startswith("guest-")) then
            (.first_operation_error_operation
             | IN("agent-protocol",
                  "read-agent-frame-header", "read-agent-frame-payload",
                  "write-agent-frame-header", "write-agent-frame-payload",
                  "flush-agent-frame"))
            and .guest_evidence_verified
            and .guest_evidence_operation_id == .qualification_operation_id
          else
            .first_operation_error_operation
              == "oci-vm-transport-qualification-fault"
            and (.guest_evidence_verified | not)
            and (.guest_evidence_operation_id == null)
          end)
     and (.first_operation_response_received | not)
     and (.disconnect_probe_attempted | not)
     and (if $stage == "guest-after-response-write" then
            .first_response_matches_durable_record
            and (.update_journal_prepared_before_reopen | not)
            and .update_journal_succeeded_before_reopen
            and .replacement_rehydrated_update
            and .operation_replayed_without_driver_dispatch
          else
            (.first_response_matches_durable_record | not)
            and .update_journal_prepared_before_reopen
            and (.update_journal_succeeded_before_reopen | not)
            and (.replacement_rehydrated_update | not)
            and (.operation_replayed_without_driver_dispatch | not)
          end)
     and (.durable_created_retained | not)
     and .durable_running_retained
     and (.durable_paused_retained | not)
     and (.durable_stopped_retained | not)
     and (.first_created_pid > 0) and (.first_exec_pid == null)
     and .generation_before_reopen == 1
     and .host_service_reopened and .replacement_recovery_calls == 1
     and .replacement_rehydrated_created_record
     and .replacement_rehydrated_running_record
     and (.replacement_rehydrated_stopped_record | not)
     and (.replacement_rehydrated_exec_record | not)
     and (.replacement_rehydrated_signal_process | not)
     and (.replacement_rehydrated_paused_record | not)
     and (.replacement_rehydrated_resumed_record | not)
     and .operation_completed_after_reopen
     and .generation_after_reopen == .generation_before_reopen
     and (.replacement_created_pid > 0) and (.replacement_exec_pid == null)
     and .replacement_response_matches_durable_record
     and .replacement_update_effect_verified
     and .replacement_update_stats.target.id == .container_id
     and .replacement_update_stats.target.generation == .generation_after_reopen
     and (.replacement_update_stats.timestamp_unix_ns > 0)
     and (.replacement_update_stats.cpu.usage_ns > 0)
     and .replacement_update_stats.memory.limit_bytes == 536870912
     and (.replacement_update_stats.memory.usage_bytes <= 536870912)
     and (.replacement_update_stats.process_count >= 2)
     and (.replacement_update_stats.metrics | has("memory.events.oom_kill"))
     and (.replacement_update_stats.metrics | has("pids.events.max"))
     and .same_generation_reused
     and .setup_create_identity_reused and .setup_start_identity_reused
     and .same_operation_id_reused
     and .setup_create_response_rebound and .setup_start_response_rebound
     and .update_response_rebound and .update_request_identity_reused
     and (.exec_response_rebound | not)
     and (.pause_response_rebound | not)
     and (.resume_response_rebound | not)
     and (.exec_request_identity_reused | not)
     and (.signal_process_request_identity_reused | not)
     and (.pause_request_identity_reused | not)
     and (.resume_request_identity_reused | not)
     and (.processes_request_target_reused | not)
     and (.wait_process_request_identity_reused | not)
     and .first_operation_dispatches == 1
     and .replacement_operation_dispatches == 1
     and .host_changed_request_rejected
     and .host_stale_generation_rejected
     and .guest_stale_generation_rejected
     and (.guest_changed_request_rejected | not)
     and .marker_reset_before_replacement
     and .replacement_workload_verified
     and (.first_exec_marker_verified | not)
     and (.exec_marker_reset_before_replacement | not)
     and (.replacement_exec_marker_verified | not)
     and .force_delete_completed and .durable_records_empty
     and .marker_absent_after_cleanup
     and (.exec_marker_absent_after_cleanup | not)
     and (.signal_marker_absent_after_cleanup | not)
     and .first_guest_runtime_clean and .replacement_guest_runtime_clean
     and .owners_distinct and .state_root_removed
     and all(.first_vm, .replacement_vm;
       .platform == "linux" and .status == "available"
       and .endpoint_bound and .shim_spawned
       and (.shim_process_id > 0) and (.bridge_process_id > 0)
       and .shim_client_verified and .protocol_negotiated
       and .selected_protocol == 10
       and .guest_architecture == $architecture
       and .shim_report_verified and .shim_exit_code == 0
       and .console_created
       and .shim_report.status == "available"
       and .shim_report.kvm_device_opened
       and .shim_report.kvm_api_verified
       and .shim_report.vm_entered
       and .shim_report.linux_boot_assets.target_arch == $architecture
       and .shim_report.linux_boot_assets.manifest_sha256 == $manifest_sha256)
     and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
     and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
     and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
     and (.reason == null)' \
    "$case_report" >/dev/null

  test ! -e "$init_marker"
  test ! -e "$runtime_root/operation-reopen-state"
  test -z "$(find "$runtime_root/bootstrap" -mindepth 1 -print -quit)"
  test -z "$(find "$runtime_root/bundle-handoffs" -mindepth 1 -print -quit)"
  test -z "$(find "$runtime_root/shares" -mindepth 1 -print -quit)"
  test -z "$(find "$runtime_root/recovery" -mindepth 1 -print -quit)"
  test "$(endpoint_inventory)" = "$endpoint_baseline"
  test "$(shim_process_inventory)" = "$process_baseline"

  jq --compact-output --arg stage "$stage" \
    '{
      stage: $stage,
      status: "available",
      cleanup: {
        endpoint_inventory_restored: true,
        shim_process_inventory_restored: true,
        bootstrap_empty: true,
        bundle_handoffs_clean: true,
        runtime_shares_clean: true,
        recovery_reports_clean: true,
        init_marker_absent: true
      },
      report: .
    }' "$case_report" >> "$cases_path"
}

for stage in "${stages[@]}"; do
  run_stage "$stage"
done

case_count="$(wc -l < "$cases_path")"
test "$case_count" -eq 9
jq --null-input \
  --arg architecture "$architecture" \
  --arg rootfs_archive_sha256 "$rootfs_archive_sha256" \
  --arg manifest_sha256 "$manifest_sha256" \
  --argjson kvm_driver "$kvm_driver" \
  --argjson provenance "$provenance" \
  --slurpfile cases "$cases_path" \
  '{
    schema_version: "a3s.oci.linux-kvm-update-reopen-matrix.v1",
    platform: "linux",
    architecture: $architecture,
    status: "available",
    kvm_required: true,
    qualification_scope: "linux-kvm-operation-stage-reopen-only-v1",
    expected_case_count: 9,
    case_count: ($cases | length),
    rootfs_archive_sha256: $rootfs_archive_sha256,
    system_image_manifest_sha256: $manifest_sha256,
    provenance: $provenance,
    kvm_driver: $kvm_driver,
    cases: $cases,
    reason: null
  }' | tee "$report_path"

jq --exit-status \
  '.schema_version == "a3s.oci.linux-kvm-update-reopen-matrix.v1"
   and .platform == "linux" and .status == "available"
   and .qualification_scope == "linux-kvm-operation-stage-reopen-only-v1"
   and .kvm_required and .expected_case_count == 9 and .case_count == 9
   and .provenance.schema_version == "a3s.oci.linux-kvm-provenance.v1"
   and .provenance.platform == .platform
   and .provenance.architecture == .architecture
   and .provenance.qualification_profile
     == "linux-kvm-update-reopen-9-stage-v1"
   and .provenance.driver == "libkrun-kvm"
   and .provenance.isolation == "dedicated-vm"
   and .provenance.source_tree_clean
   and .provenance.system_image_manifest_sha256
     == .system_image_manifest_sha256
   and .kvm_driver.status == "available"
   and ([.cases[].stage] | length) == 9
   and ([.cases[].stage] | unique | length) == 9
   and all(.cases[];
     .status == "available"
     and .report.status == "available"
     and .report.requested_stage == .stage
     and all(.cleanup[]; . == true))
   and (.reason == null)' \
  "$report_path" >/dev/null
