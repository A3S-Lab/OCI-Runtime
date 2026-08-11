#!/usr/bin/env bash
set -euo pipefail

rootfs_dir="$RUNNER_TEMP/a3s-oci-alpine-aarch64"
signed_dir="$RUNNER_TEMP/a3s-oci-agent-vm-signed"
bundle_dir="$rootfs_dir/var/lib/a3s-oci-smoke/bundle"
marker="$bundle_dir/rootfs/.a3s-oci-create-start-smoke"
exec_marker="$bundle_dir/rootfs/.a3s-oci-exec-reopen-smoke"
signal_process_marker="$bundle_dir/rootfs/.a3s-oci-signal-process-reopen-smoke"
read_output_marker="$bundle_dir/rootfs/.a3s-oci-read-output-reopen-smoke"
write_stdin_marker="$bundle_dir/rootfs/.a3s-oci-write-stdin-reopen-smoke"
close_stdin_marker="$bundle_dir/rootfs/.a3s-oci-close-stdin-reopen-smoke"
console_root="$RUNNER_TEMP/a3s-oci-reopen-replacement"
support="$(sysctl -n kern.hv_support 2>/dev/null || printf unavailable)"
mkdir -p \
  "$console_root/create" \
  "$console_root/delete" \
  "$console_root/exec" \
  "$console_root/pause" \
  "$console_root/processes" \
  "$console_root/read-output" \
  "$console_root/write-stdin" \
  "$console_root/close-stdin" \
  "$console_root/resume" \
  "$console_root/stats" \
  "$console_root/update" \
  "$console_root/signal-process" \
  "$console_root/wait-process" \
  "$console_root/state" \
  "$console_root/start" \
  "$console_root/kill" \
  "$console_root/wait"

endpoint_baseline="$({
  find /private/tmp -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
})"
runtime_baseline="$({
  find "$rootfs_dir/run" -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
})"

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

hardware_available() {
  [[ "$(uname -m)" == "arm64" && "$support" == "1" ]]
}

assert_cleanup_baseline() {
  local stage_console_dir="$1"
  local endpoint_after runtime_after
  endpoint_after="$({
    find /private/tmp -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
  })"
  runtime_after="$({
    find "$rootfs_dir/run" -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
  })"
  test "$endpoint_after" = "$endpoint_baseline"
  test "$runtime_after" = "$runtime_baseline"
  test ! -e "$marker"
  test ! -e "$exec_marker"
  test ! -e "$signal_process_marker"
  test ! -e "$read_output_marker"
  test ! -e "$write_stdin_marker"
  test ! -e "$close_stdin_marker"
  test -z "$(find "$stage_console_dir" -maxdepth 1 -name '*-state' -print)"
}

source "$(dirname "$0")/macos-reopen-replacement-exec.sh"
source "$(dirname "$0")/macos-reopen-replacement-pause.sh"
source "$(dirname "$0")/macos-reopen-replacement-processes.sh"
source "$(dirname "$0")/macos-reopen-replacement-read-output.sh"
source "$(dirname "$0")/macos-reopen-replacement-write-stdin.sh"
source "$(dirname "$0")/macos-reopen-replacement-close-stdin.sh"
source "$(dirname "$0")/macos-reopen-replacement-resume.sh"
source "$(dirname "$0")/macos-reopen-replacement-update.sh"
source "$(dirname "$0")/macos-reopen-replacement-stats.sh"
source "$(dirname "$0")/macos-reopen-replacement-signal-process.sh"
source "$(dirname "$0")/macos-reopen-replacement-wait-process.sh"

run_create_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/create/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation create \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console-dir "$stage_console_dir" \
      --fault-at "$fault_stage"
  )"
  gate_exit_code=$?
  set -e
  printf '%s\n' "$output"

  if hardware_available; then
    test "$gate_exit_code" -eq 0
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version == "a3s.oci.oci-vm-reopen-replacement.v2"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "create"
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("reopen-"))
       and (.container_id | startswith("smoke-reopen-"))
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.create-" + $stage)
       and .fault_crossings == 1
       and .first_create_error_code == "unavailable"
       and .first_create_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_create_error_operation
               | IN("agent-protocol",
                    "read-agent-frame-header",
                    "read-agent-frame-payload",
                    "write-agent-frame-header",
                    "write-agent-frame-payload",
                    "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
              and (if $stage == "guest-after-response-write" then
                     .first_create_response_received
                     and .disconnect_probe_attempted
                     and (.durable_creating_retained | not)
                     and .durable_created_retained
                     and (.first_created_pid > 0)
                     and .replacement_rehydrated_created_record
                   else
                     (.first_create_response_received | not)
                     and (.disconnect_probe_attempted | not)
                     and .durable_creating_retained
                     and (.durable_created_retained | not)
                     and (.first_created_pid == null)
                     and (.replacement_rehydrated_created_record | not)
                   end)
            else
              .first_create_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.first_create_response_received | not)
              and (.disconnect_probe_attempted | not)
              and .durable_creating_retained
              and (.durable_created_retained | not)
              and (.first_created_pid == null)
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
              and (.replacement_rehydrated_created_record | not)
            end)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .create_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and .same_generation_reused
       and .same_operation_id_reused
       and .force_delete_completed
       and .durable_records_empty
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and .first_vm.selected_protocol == 9
       and .replacement_vm.selected_protocol == 9
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and (.first_vm.macos_cleanup.open_descriptors_before
            == .first_vm.macos_cleanup.open_descriptors_after)
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.replacement_vm.macos_cleanup.open_descriptors_before
            == .replacement_vm.macos_cleanup.open_descriptors_after)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version == "a3s.oci.oci-vm-reopen-replacement.v2"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "create"
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}

run_state_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/state/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation state \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console-dir "$stage_console_dir" \
      --fault-at "$fault_stage"
  )"
  gate_exit_code=$?
  set -e
  printf '%s\n' "$output"

  if hardware_available; then
    test "$gate_exit_code" -eq 0
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v1"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "state"
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("state-reopen-"))
       and (.setup_create_operation_id | startswith("state-reopen-"))
       and (.qualification_operation_id != .setup_create_operation_id)
       and (.container_id | startswith("smoke-state-reopen-"))
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.state-" + $stage)
       and .fault_crossings == 1
       and .first_operation_error_code == "unavailable"
       and .first_operation_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_operation_error_operation
               | IN("agent-protocol",
                    "read-agent-frame-header",
                    "read-agent-frame-payload",
                    "write-agent-frame-header",
                    "write-agent-frame-payload",
                    "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
            else
              .first_operation_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            end)
       and (if $stage == "guest-after-response-write" then
              .first_operation_response_received
              and .disconnect_probe_attempted
              and .first_response_matches_durable_record
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.first_response_matches_durable_record | not)
            end)
       and .durable_created_retained
       and (.first_created_pid > 0)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and .replacement_response_matches_durable_record
       and .same_generation_reused
       and .setup_create_identity_reused
       and .force_delete_completed
       and .durable_records_empty
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and .first_vm.selected_protocol == 9
       and .replacement_vm.selected_protocol == 9
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and (.first_vm.macos_cleanup.open_descriptors_before
            == .first_vm.macos_cleanup.open_descriptors_after)
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.replacement_vm.macos_cleanup.open_descriptors_before
            == .replacement_vm.macos_cleanup.open_descriptors_after)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v1"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "state"
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}

run_start_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/start/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation start \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console-dir "$stage_console_dir" \
      --fault-at "$fault_stage"
  )"
  gate_exit_code=$?
  set -e
  printf '%s\n' "$output"

  if hardware_available; then
    test "$gate_exit_code" -eq 0
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v2"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "start"
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("start-reopen-"))
       and (.setup_create_operation_id | startswith("start-reopen-"))
       and (.qualification_operation_id != .setup_create_operation_id)
       and (.container_id | startswith("smoke-start-reopen-"))
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.start-" + $stage)
       and .fault_crossings == 1
       and .first_operation_error_code == "unavailable"
       and .first_operation_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_operation_error_operation
               | IN("agent-protocol",
                    "read-agent-frame-header",
                    "read-agent-frame-payload",
                    "write-agent-frame-header",
                    "write-agent-frame-payload",
                    "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
            else
              .first_operation_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            end)
       and (if $stage == "guest-after-response-write" then
              .first_operation_response_received
              and .disconnect_probe_attempted
              and .first_response_matches_durable_record
              and (.durable_created_retained | not)
              and .durable_running_retained
              and .replacement_rehydrated_running_record
              and .operation_replayed_without_driver_dispatch
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.first_response_matches_durable_record | not)
              and .durable_created_retained
              and (.durable_running_retained | not)
              and (.replacement_rehydrated_running_record | not)
              and (.operation_replayed_without_driver_dispatch | not)
            end)
       and (.first_created_pid > 0)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and .replacement_response_matches_durable_record
       and .same_generation_reused
       and .setup_create_identity_reused
       and .same_operation_id_reused
       and .setup_create_response_rebound
       and .first_operation_dispatches == 1
       and .replacement_operation_dispatches == 1
       and .marker_reset_before_replacement
       and .replacement_workload_verified
       and .force_delete_completed
       and .durable_records_empty
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and .first_vm.selected_protocol == 9
       and .replacement_vm.selected_protocol == 9
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and (.first_vm.macos_cleanup.open_descriptors_before
            == .first_vm.macos_cleanup.open_descriptors_after)
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.replacement_vm.macos_cleanup.open_descriptors_before
            == .replacement_vm.macos_cleanup.open_descriptors_after)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v2"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "start"
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}

run_kill_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/kill/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation kill \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console-dir "$stage_console_dir" \
      --fault-at "$fault_stage"
  )"
  gate_exit_code=$?
  set -e
  printf '%s\n' "$output"

  if hardware_available; then
    test "$gate_exit_code" -eq 0
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v3"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "kill"
       and .kill_signal == 9
       and .kill_all
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("kill-reopen-"))
       and (.setup_create_operation_id | startswith("kill-reopen-"))
       and (.qualification_operation_id != .setup_create_operation_id)
       and (.container_id | startswith("smoke-kill-reopen-"))
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.kill-" + $stage)
       and .fault_crossings == 1
       and .first_operation_error_code == "unavailable"
       and .first_operation_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_operation_error_operation
               | IN("agent-protocol",
                    "read-agent-frame-header",
                    "read-agent-frame-payload",
                    "write-agent-frame-header",
                    "write-agent-frame-payload",
                    "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
            else
              .first_operation_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            end)
       and (if $stage == "guest-after-response-write" then
              .first_operation_response_received
              and .disconnect_probe_attempted
              and .first_response_matches_durable_record
              and (.durable_running_retained | not)
              and .durable_stopped_retained
              and .replacement_rehydrated_stopped_record
              and (.setup_create_response_rebound | not)
              and (.setup_start_response_rebound | not)
              and .operation_replayed_without_driver_dispatch
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.first_response_matches_durable_record | not)
              and .durable_running_retained
              and (.durable_stopped_retained | not)
              and (.replacement_rehydrated_stopped_record | not)
              and .setup_create_response_rebound
              and .setup_start_response_rebound
              and (.operation_replayed_without_driver_dispatch | not)
            end)
       and (.durable_created_retained | not)
       and (.first_created_pid > 0)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .replacement_rehydrated_running_record
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and .replacement_response_matches_durable_record
       and .same_generation_reused
       and .setup_create_identity_reused
       and .setup_start_identity_reused
       and .same_operation_id_reused
       and .first_operation_dispatches == 1
       and .replacement_operation_dispatches == 1
       and .marker_reset_before_replacement
       and .replacement_workload_verified
       and (.force_delete_completed | not)
       and .stopped_only_delete_completed
       and .durable_records_empty
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and .first_vm.selected_protocol == 9
       and .replacement_vm.selected_protocol == 9
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and (.first_vm.macos_cleanup.open_descriptors_before
            == .first_vm.macos_cleanup.open_descriptors_after)
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.replacement_vm.macos_cleanup.open_descriptors_before
            == .replacement_vm.macos_cleanup.open_descriptors_after)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v3"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "kill"
       and .kill_signal == 9
       and .kill_all
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}

run_delete_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/delete/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation delete \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console-dir "$stage_console_dir" \
      --fault-at "$fault_stage"
  )"
  gate_exit_code=$?
  set -e
  printf '%s\n' "$output"

  if hardware_available; then
    test "$gate_exit_code" -eq 0
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v4"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "delete"
       and .kill_signal == 9
       and .kill_all
       and .delete_mode == "stopped-only"
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("delete-reopen-"))
       and (.setup_create_operation_id | startswith("delete-reopen-"))
       and (.qualification_operation_id != .setup_create_operation_id)
       and (.container_id | startswith("smoke-delete-reopen-"))
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.delete-" + $stage)
       and .fault_crossings == 1
       and .first_operation_error_code == "unavailable"
       and .first_operation_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_operation_error_operation
               | IN("agent-protocol",
                    "read-agent-frame-header",
                    "read-agent-frame-payload",
                    "write-agent-frame-header",
                    "write-agent-frame-payload",
                    "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
            else
              .first_operation_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            end)
       and (.first_response_matches_durable_record | not)
       and (.durable_created_retained | not)
       and (.durable_running_retained | not)
       and (if $stage == "guest-after-response-write" then
              .first_operation_response_received
              and .disconnect_probe_attempted
              and (.durable_stopped_retained | not)
              and .first_durable_records_empty
              and (.delete_journal_prepared_before_reopen | not)
              and .delete_journal_succeeded_empty_before_reopen
              and .replacement_recovery_calls == 0
              and (.replacement_rehydrated_created_record | not)
              and (.replacement_rehydrated_running_record | not)
              and (.replacement_rehydrated_stopped_record | not)
              and (.replacement_created_pid == null)
              and (.setup_create_identity_reused | not)
              and (.setup_start_identity_reused | not)
              and (.setup_kill_identity_reused | not)
              and .operation_replayed_without_driver_dispatch
              and .replacement_operation_dispatches == 0
              and (.replacement_workload_verified | not)
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and .durable_stopped_retained
              and (.first_durable_records_empty | not)
              and .delete_journal_prepared_before_reopen
              and (.delete_journal_succeeded_empty_before_reopen | not)
              and .replacement_recovery_calls == 1
              and .replacement_rehydrated_created_record
              and .replacement_rehydrated_running_record
              and .replacement_rehydrated_stopped_record
              and (.replacement_created_pid > 0)
              and .setup_create_identity_reused
              and .setup_start_identity_reused
              and .setup_kill_identity_reused
              and (.operation_replayed_without_driver_dispatch | not)
              and .replacement_operation_dispatches == 1
              and .replacement_workload_verified
            end)
       and (.first_created_pid > 0)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_response_matches_durable_record | not)
       and .same_generation_reused
       and .same_operation_id_reused
       and (.setup_create_response_rebound | not)
       and (.setup_start_response_rebound | not)
       and .first_operation_dispatches == 1
       and .marker_reset_before_replacement
       and (.force_delete_completed | not)
       and .stopped_only_delete_completed
       and .durable_records_empty
       and .delete_journal_succeeded_empty_after_reopen
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and .first_vm.selected_protocol == 9
       and .replacement_vm.selected_protocol == 9
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and (.first_vm.macos_cleanup.open_descriptors_before
            == .first_vm.macos_cleanup.open_descriptors_after)
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.replacement_vm.macos_cleanup.open_descriptors_before
            == .replacement_vm.macos_cleanup.open_descriptors_after)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v4"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "delete"
       and .kill_signal == 9
       and .kill_all
       and .delete_mode == "stopped-only"
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}

run_wait_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/wait/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation wait \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console-dir "$stage_console_dir" \
      --fault-at "$fault_stage"
  )"
  gate_exit_code=$?
  set -e
  printf '%s\n' "$output"

  if hardware_available; then
    test "$gate_exit_code" -eq 0
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v5"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "wait"
       and .kill_signal == 9
       and .kill_all
       and (.delete_mode == null)
       and .wait_timeout_ms == 15000
       and .expected_exit_status == {"signal": 9, "oom_killed": false}
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("wait-reopen-"))
       and (.setup_create_operation_id | startswith("wait-reopen-"))
       and (.setup_start_operation_id | startswith("wait-reopen-"))
       and (.setup_kill_operation_id | startswith("wait-reopen-"))
       and (.qualification_operation_id != .setup_create_operation_id)
       and (.qualification_operation_id != .setup_start_operation_id)
       and (.qualification_operation_id != .setup_kill_operation_id)
       and (.setup_create_operation_id != .setup_start_operation_id)
       and (.setup_create_operation_id != .setup_kill_operation_id)
       and (.setup_start_operation_id != .setup_kill_operation_id)
       and (.container_id | startswith("smoke-wait-reopen-"))
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.wait-" + $stage)
       and .fault_crossings == 1
       and .first_operation_error_code == "unavailable"
       and .first_operation_error_retryable
       and (if ($stage | startswith("guest-")) then
              (.first_operation_error_operation
               | IN("agent-protocol",
                    "read-agent-frame-header",
                    "read-agent-frame-payload",
                    "write-agent-frame-header",
                    "write-agent-frame-payload",
                    "flush-agent-frame"))
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
            else
              .first_operation_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            end)
       and (if $stage == "guest-after-response-write" then
              .first_operation_response_received
              and .disconnect_probe_attempted
              and .first_response_matches_expected_exit
              and .first_wait_exit_status
                    == {"signal": 9, "oom_killed": false}
              and .init_exit_cached_before_reopen
              and .operation_replayed_without_driver_dispatch
              and .replacement_operation_dispatches == 0
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.first_response_matches_expected_exit | not)
              and (.first_wait_exit_status == null)
              and (.init_exit_cached_before_reopen | not)
              and (.operation_replayed_without_driver_dispatch | not)
              and .replacement_operation_dispatches == 1
            end)
       and (.first_response_matches_durable_record | not)
       and (.durable_created_retained | not)
       and (.durable_running_retained | not)
       and .durable_stopped_retained
       and (.first_durable_records_empty | not)
       and (.first_created_pid > 0)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .replacement_rehydrated_running_record
       and .replacement_rehydrated_stopped_record
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and (.replacement_response_matches_durable_record | not)
       and .replacement_response_matches_expected_exit
       and .cached_response_matches_expected_exit
       and .replacement_wait_exit_status
             == {"signal": 9, "oom_killed": false}
       and .cached_wait_exit_status
             == {"signal": 9, "oom_killed": false}
       and .init_exit_cached_after_reopen
       and .same_generation_reused
       and .setup_create_identity_reused
       and .setup_start_identity_reused
       and .setup_kill_identity_reused
       and (.same_operation_id_reused | not)
       and (.setup_create_response_rebound | not)
       and (.setup_start_response_rebound | not)
       and .cached_wait_replayed_without_driver_dispatch
       and .first_operation_dispatches == 1
       and .host_stale_generation_rejected
       and .guest_stale_generation_rejected
       and .marker_reset_before_replacement
       and .replacement_workload_verified
       and (.force_delete_completed | not)
       and .stopped_only_delete_completed
       and .durable_records_empty
       and (.delete_journal_succeeded_empty_after_reopen | not)
       and .marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and .first_vm.selected_protocol == 9
       and .replacement_vm.selected_protocol == 9
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and (.first_vm.macos_cleanup.open_descriptors_before
            == .first_vm.macos_cleanup.open_descriptors_after)
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.replacement_vm.macos_cleanup.open_descriptors_before
            == .replacement_vm.macos_cleanup.open_descriptors_after)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v5"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "wait"
       and .kill_signal == 9
       and .kill_all
       and .wait_timeout_ms == 15000
       and .expected_exit_status == {"signal": 9, "oom_killed": false}
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}

for fault_stage in "${stages[@]}"; do
  run_create_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_state_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_start_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_kill_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_delete_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_wait_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_exec_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_signal_process_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_wait_process_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_pause_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_processes_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_resume_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_update_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_stats_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_read_output_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_write_stdin_stage "$fault_stage"
done
for fault_stage in "${stages[@]}"; do
  run_close_stdin_stage "$fault_stage"
done
