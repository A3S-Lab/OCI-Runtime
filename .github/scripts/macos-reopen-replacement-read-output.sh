run_read_output_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/read-output/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation read-output \
      --shim "$signed_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs_dir" \
      --system-image-manifest "$system_image_manifest" \
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
           == "a3s.oci.oci-vm-operation-reopen-replacement.v14"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "read-output"
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("read-output-reopen-"))
       and (.setup_create_operation_id | startswith("read-output-reopen-"))
       and (.setup_start_operation_id | startswith("read-output-reopen-"))
       and (.setup_exec_operation_id | startswith("read-output-reopen-"))
       and ([.qualification_operation_id,
             .setup_create_operation_id,
             .setup_start_operation_id,
             .setup_exec_operation_id] | unique | length) == 4
       and (.setup_kill_operation_id == null)
       and (.setup_signal_process_operation_id == null)
       and (.setup_pause_operation_id == null)
       and (.setup_update_operation_id == null)
       and (.container_id | startswith("smoke-read-output-reopen-"))
       and (.exec_process_id | startswith("reader-"))
       and (.exec_terminal | not)
       and .read_output_after_sequence == 0
       and (.read_output_max_bytes > 0)
       and .read_output_wait_timeout_ms == 5000
       and (.expected_output_chunks | length) == 1
       and .expected_output_chunks[0].stream == "stdout"
       and (.expected_output_chunks[0].eof | not)
       and (.expected_output_chunks[0].data | length)
           == .read_output_max_bytes
       and .expected_output_chunks[0].sequence
           == .read_output_max_bytes
       and .negotiated_protocol == 10
       and .injected_point == ("agent-v10.read-output-" + $stage)
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
              and .first_output_verified
              and .first_output_chunks == .expected_output_chunks
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.first_output_verified | not)
              and (.first_output_chunks == null)
            end)
       and (.first_response_matches_durable_record | not)
       and (.first_response_matches_expected_exit | not)
       and (.durable_created_retained | not)
       and .durable_running_retained
       and (.durable_paused_retained | not)
       and (.durable_stopped_retained | not)
       and (.first_durable_records_empty | not)
       and (.delete_journal_prepared_before_reopen | not)
       and (.delete_journal_succeeded_empty_before_reopen | not)
       and (.init_exit_cached_before_reopen | not)
       and (.exec_journal_prepared_before_reopen | not)
       and .exec_journal_succeeded_before_reopen
       and (.signal_process_journal_prepared_before_reopen | not)
       and (.signal_process_journal_succeeded_before_reopen | not)
       and (.pause_journal_prepared_before_reopen | not)
       and (.pause_journal_succeeded_before_reopen | not)
       and (.resume_journal_prepared_before_reopen | not)
       and (.resume_journal_succeeded_before_reopen | not)
       and (.update_journal_prepared_before_reopen | not)
       and (.update_journal_succeeded_before_reopen | not)
       and (.process_exit_cached_before_reopen | not)
       and (.first_created_pid > 0)
       and (.first_exec_pid > 0)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .replacement_rehydrated_running_record
       and (.replacement_rehydrated_stopped_record | not)
       and .replacement_rehydrated_exec_record
       and (.replacement_rehydrated_signal_process | not)
       and (.replacement_rehydrated_paused_record | not)
       and (.replacement_rehydrated_resumed_record | not)
       and (.replacement_rehydrated_update | not)
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and (.replacement_exec_pid > 0)
       and .replacement_output_verified
       and .replacement_output_chunks == .expected_output_chunks
       and .output_response_rebound
       and (.replacement_response_matches_durable_record | not)
       and (.replacement_response_matches_expected_exit | not)
       and (.cached_response_matches_expected_exit | not)
       and .same_generation_reused
       and .setup_create_identity_reused
       and .setup_start_identity_reused
       and (.setup_kill_identity_reused | not)
       and (.same_operation_id_reused | not)
       and .setup_create_response_rebound
       and .setup_start_response_rebound
       and .exec_response_rebound
       and (.pause_response_rebound | not)
       and (.resume_response_rebound | not)
       and (.update_response_rebound | not)
       and .exec_request_identity_reused
       and (.signal_process_request_identity_reused | not)
       and (.pause_request_identity_reused | not)
       and (.resume_request_identity_reused | not)
       and (.update_request_identity_reused | not)
       and (.processes_request_target_reused | not)
       and (.stats_request_target_reused | not)
       and .read_output_request_identity_reused
       and (.wait_process_request_identity_reused | not)
       and (.operation_replayed_without_driver_dispatch | not)
       and (.cached_wait_replayed_without_driver_dispatch | not)
       and .first_operation_dispatches == 1
       and .replacement_operation_dispatches == 1
       and .host_stale_generation_rejected
       and .guest_stale_generation_rejected
       and (.host_changed_request_rejected | not)
       and (.guest_changed_request_rejected | not)
       and .marker_reset_before_replacement
       and .replacement_workload_verified
       and .first_exec_marker_verified
       and .exec_marker_reset_before_replacement
       and .replacement_exec_marker_verified
       and .force_delete_completed
       and .durable_records_empty
       and .marker_absent_after_cleanup
       and .exec_marker_absent_after_cleanup
       and .first_guest_runtime_clean
       and .replacement_guest_runtime_clean
       and .owners_distinct
       and .state_root_removed
       and .first_vm.status == "available"
       and .replacement_vm.status == "available"
       and (.first_vm.endpoint_name != .replacement_vm.endpoint_name)
       and (.first_vm.shim_process_id != .replacement_vm.shim_process_id)
       and (.first_vm.bridge_process_id != .replacement_vm.bridge_process_id)
       and .first_vm.macos_cleanup.endpoint_removed
       and .first_vm.macos_cleanup.shim_reaped
       and .first_vm.macos_cleanup.bridge_reaped
       and .first_vm.macos_cleanup.descriptor_inventory_restored
       and .replacement_vm.macos_cleanup.endpoint_removed
       and .replacement_vm.macos_cleanup.shim_reaped
       and .replacement_vm.macos_cleanup.bridge_reaped
       and .replacement_vm.macos_cleanup.descriptor_inventory_restored
       and (.reason == null)' <<<"$output" >/dev/null
  else
    test "$gate_exit_code" -eq 2
    jq --exit-status --arg stage "$fault_stage" \
      '.schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v14"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "read-output"
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}
