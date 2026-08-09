#!/usr/bin/env bash
set -euo pipefail

rootfs_dir="$RUNNER_TEMP/a3s-oci-alpine-aarch64"
signed_dir="$RUNNER_TEMP/a3s-oci-agent-vm-signed"
bundle_dir="$rootfs_dir/var/lib/a3s-oci-smoke/bundle"
marker="$bundle_dir/rootfs/.a3s-oci-create-start-smoke"
support="$(sysctl -n kern.hv_support 2>/dev/null || printf unavailable)"

endpoint_baseline="$(
  find /private/tmp -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
)"
runtime_baseline="$(
  find "$rootfs_dir/run" -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
)"

assert_cleanup_baseline() {
  local endpoint_after runtime_after
  endpoint_after="$(
    find /private/tmp -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
  )"
  runtime_after="$(
    find "$rootfs_dir/run" -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
  )"
  test "$endpoint_after" = "$endpoint_baseline"
  test "$runtime_after" = "$runtime_baseline"
  test ! -e "$marker"
}

run_lifecycle_fault() {
  local phase="$1"
  local console="$RUNNER_TEMP/a3s-oci-fault-$phase.log"
  local output status
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-fault-cleanup \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console "$console" \
      --fault-after "$phase"
  )"
  status=$?
  set -e
  printf '%s\n' "$output"

  if [[ "$support" == "1" ]]; then
    test "$status" -eq 0
    jq --exit-status --arg phase "$phase" \
      '.schema_version == "a3s.oci.oci-vm-fault-cleanup.v4"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .lifecycle.requested_fault == $phase
       and .lifecycle.injected_fault == $phase
       and .lifecycle.create_completed
       and (.lifecycle.created_pid > 0)
       and .lifecycle.marker_absent_after_create
       and (.lifecycle.normal_delete_attempted | not)
       and (if $phase == "after-create" then
              (.lifecycle.start_completed | not)
              and (.lifecycle.kill_completed | not)
              and (.lifecycle.marker_verified_after_start | not)
            elif $phase == "after-start" then
              .lifecycle.start_completed
              and (.lifecycle.kill_completed | not)
              and .lifecycle.marker_verified_after_start
            else
              .lifecycle.start_completed
              and .lifecycle.kill_completed
              and .lifecycle.marker_verified_after_start
            end)
       and .marker_removed and .guest_runtime_clean
       and .bridge.status == "available"
       and .bridge.protocol_negotiated
       and .bridge.selected_protocol == 9
       and .bridge.advertised_operations
           == ["create", "state", "start", "kill", "delete", "wait",
               "exec", "signal-process", "wait-process", "pause",
               "resume", "processes", "update", "stats",
               "read-output", "write-stdin", "close-stdin", "resize",
               "file", "filesystem"]
       and .bridge.shim_report_verified
       and .bridge.shim_exit_code == 0
       and .bridge.macos_cleanup.endpoint_removed
       and .bridge.macos_cleanup.shim_reaped
       and .bridge.macos_cleanup.bridge_reaped
       and (.bridge.macos_cleanup.open_descriptors_before > 0)
       and (.bridge.macos_cleanup.open_descriptors_before
            == .bridge.macos_cleanup.open_descriptors_after)
       and .bridge.macos_cleanup.descriptor_inventory_restored
       and (.bridge.macos_cleanup.reason == null)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$status" -eq 2
    jq --exit-status --arg phase "$phase" \
      '.schema_version == "a3s.oci.oci-vm-fault-cleanup.v4"
       and .platform == "macos" and .status == "unavailable"
       and .bundle_loaded
       and .lifecycle.requested_fault == $phase
       and (.lifecycle.injected_fault == null)
       and (.lifecycle.normal_delete_attempted | not)
       and .bridge.status == "unavailable"
       and .bridge.macos_cleanup.endpoint_removed
       and .bridge.macos_cleanup.shim_reaped
       and .bridge.macos_cleanup.bridge_reaped
       and (.bridge.macos_cleanup.open_descriptors_before > 0)
       and (.bridge.macos_cleanup.open_descriptors_before
            == .bridge.macos_cleanup.open_descriptors_after)
       and .bridge.macos_cleanup.descriptor_inventory_restored
       and (.bridge.macos_cleanup.reason == null)
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline
}

run_transport_fault() {
  local transport_stage="$1"
  local console="$RUNNER_TEMP/a3s-oci-transport-$transport_stage.log"
  local output status
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-transport-fault-cleanup \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --bundle "$bundle_dir" \
      --console "$console" \
      --fault-at "$transport_stage"
  )"
  status=$?
  set -e
  printf '%s\n' "$output"

  if [[ "$(uname -m)" == "arm64" && "$support" == "1" ]]; then
    test "$status" -eq 0
    jq --exit-status --arg stage "$transport_stage" \
      '.schema_version == "a3s.oci.oci-vm-transport-fault-cleanup.v3"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "create"
       and (.qualification_operation_id | startswith("transport-fault-"))
       and .requested_stage == $stage
       and .negotiated_protocol == 9
       and .injected_point
           == (if ($stage | endswith("-shutdown")) then
                 "agent-v9." + $stage
               else
                 "agent-v9.create-" + $stage
               end)
       and .fault_crossings == 1
       and .observed_error_code == "unavailable"
       and .observed_error_retryable
       and (if ($stage | endswith("-shutdown")) then
              .observed_error_operation
                == "oci-vm-transport-qualification-fault"
              and .primary_response_received
              and (.disconnect_probe_attempted | not)
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            elif ($stage | startswith("host-")) then
              .observed_error_operation
                == "oci-vm-transport-qualification-fault"
              and (.primary_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.guest_evidence_verified | not)
              and (.guest_evidence_operation_id == null)
            else
              (.observed_error_operation == "agent-protocol"
               or .observed_error_operation == "read-agent-frame-header"
               or .observed_error_operation == "read-agent-frame-payload"
               or .observed_error_operation == "write-agent-frame-header"
               or .observed_error_operation == "write-agent-frame-payload"
               or .observed_error_operation == "flush-agent-frame")
              and .guest_evidence_verified
              and (.guest_evidence_operation_id
                   == .qualification_operation_id)
              and (.primary_response_received
                   == ($stage == "guest-after-response-write"))
              and (.disconnect_probe_attempted
                   == ($stage == "guest-after-response-write"))
            end)
       and (.normal_delete_attempted | not)
       and .marker_absent_after_cleanup
       and .guest_runtime_clean
       and .bridge.status == "available"
       and .bridge.protocol_negotiated
       and .bridge.selected_protocol == 9
       and .bridge.shim_report_verified
       and .bridge.shim_exit_code == 0
       and .bridge.macos_cleanup.endpoint_removed
       and .bridge.macos_cleanup.shim_reaped
       and .bridge.macos_cleanup.bridge_reaped
       and (.bridge.macos_cleanup.open_descriptors_before > 0)
       and (.bridge.macos_cleanup.open_descriptors_before
            == .bridge.macos_cleanup.open_descriptors_after)
       and .bridge.macos_cleanup.descriptor_inventory_restored
       and (.bridge.macos_cleanup.reason == null)
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$status" -eq 2
    jq --exit-status --arg stage "$transport_stage" \
      '.schema_version == "a3s.oci.oci-vm-transport-fault-cleanup.v3"
       and .platform == "macos" and .status != "available"
       and .requested_operation == "create"
       and .requested_stage == $stage
       and .fault_crossings == 0
       and (.observed_error_code == null)
       and (.normal_delete_attempted | not)
       and .bridge.status != "available"
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline
}

for phase in after-create after-start after-kill; do
  run_lifecycle_fault "$phase"
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
  run_transport_fault "$transport_stage"
done
