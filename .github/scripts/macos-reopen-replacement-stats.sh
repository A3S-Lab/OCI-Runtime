run_stats_stage() {
  local fault_stage="$1"
  local stage_console_dir="$console_root/stats/$fault_stage"
  local output gate_exit_code
  mkdir "$stage_console_dir"
  set +e
  output="$(
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation stats \
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
      '. as $report
       | .schema_version
           == "a3s.oci.oci-vm-operation-reopen-replacement.v13"
       and .platform == "macos" and .status == "available"
       and .bundle_loaded
       and .requested_operation == "stats"
       and .requested_stage == $stage
       and (.qualification_operation_id | startswith("stats-reopen-"))
       and (.setup_create_operation_id | startswith("stats-reopen-"))
       and (.setup_start_operation_id | startswith("stats-reopen-"))
       and (.setup_update_operation_id | startswith("stats-reopen-"))
       and ([.qualification_operation_id,
             .setup_create_operation_id,
             .setup_start_operation_id,
             .setup_update_operation_id] | unique | length) == 4
       and (.setup_kill_operation_id == null)
       and (.setup_exec_operation_id == null)
       and (.setup_signal_process_operation_id == null)
       and (.setup_pause_operation_id == null)
       and (.container_id | startswith("smoke-stats-reopen-"))
       and .update_resources.memory.limit == 536870912
       and .update_resources.memory.reservation == 67108864
       and .update_resources.memory.swap == 1073741824
       and .update_resources.cpu.shares == 512
       and .update_resources.cpu.quota == 50000
       and .update_resources.cpu.period == 100000
       and .update_resources.cpu.cpus == "0"
       and .update_resources.cpu.mems == "0"
       and .update_resources.pids.limit == 64
       and .negotiated_protocol == 9
       and .injected_point == ("agent-v9.stats-" + $stage)
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
              and .first_stats_verified
              and .first_stats_snapshot.target.id == .container_id
              and .first_stats_snapshot.target.generation
                  == .generation_before_reopen
              and (.first_stats_snapshot.timestamp_unix_ns > 0)
              and (.first_stats_snapshot.cpu.usage_ns > 0)
              and .first_stats_snapshot.memory.limit_bytes == 536870912
              and (.first_stats_snapshot.memory.usage_bytes <= 536870912)
              and (.first_stats_snapshot.process_count >= 2)
              and (.first_stats_snapshot.metrics
                   | has("memory.events.oom_kill"))
              and (.first_stats_snapshot.metrics | has("pids.events.max"))
              and (.replacement_stats_snapshot.timestamp_unix_ns
                   > .first_stats_snapshot.timestamp_unix_ns)
              and (.replacement_stats_snapshot != .first_stats_snapshot)
            else
              (.first_operation_response_received | not)
              and (.disconnect_probe_attempted | not)
              and (.first_stats_verified | not)
              and (.first_stats_snapshot == null)
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
       and (.exec_journal_succeeded_before_reopen | not)
       and (.signal_process_journal_prepared_before_reopen | not)
       and (.signal_process_journal_succeeded_before_reopen | not)
       and (.pause_journal_prepared_before_reopen | not)
       and (.pause_journal_succeeded_before_reopen | not)
       and (.resume_journal_prepared_before_reopen | not)
       and (.resume_journal_succeeded_before_reopen | not)
       and (.update_journal_prepared_before_reopen | not)
       and .update_journal_succeeded_before_reopen
       and (.process_exit_cached_before_reopen | not)
       and (.first_created_pid > 0)
       and (.first_exec_pid == null)
       and (.first_process_inventory == null)
       and .generation_before_reopen == 1
       and .host_service_reopened
       and .replacement_recovery_calls == 1
       and .replacement_rehydrated_created_record
       and .replacement_rehydrated_running_record
       and (.replacement_rehydrated_stopped_record | not)
       and (.replacement_rehydrated_exec_record | not)
       and (.replacement_rehydrated_signal_process | not)
       and (.replacement_rehydrated_paused_record | not)
       and (.replacement_rehydrated_resumed_record | not)
       and .replacement_rehydrated_update
       and .operation_completed_after_reopen
       and .generation_after_reopen == .generation_before_reopen
       and (.replacement_created_pid > 0)
       and (.replacement_exec_pid == null)
       and (.replacement_process_inventory == null)
       and (.replacement_update_stats == null)
       and .replacement_stats_verified
       and .replacement_stats_snapshot.target.id == .container_id
       and .replacement_stats_snapshot.target.generation
           == .generation_after_reopen
       and (.replacement_stats_snapshot.timestamp_unix_ns > 0)
       and (.replacement_stats_snapshot.cpu.usage_ns > 0)
       and .replacement_stats_snapshot.memory.limit_bytes == 536870912
       and (.replacement_stats_snapshot.memory.usage_bytes <= 536870912)
       and (.replacement_stats_snapshot.process_count >= 2)
       and (.replacement_stats_snapshot.metrics | has("memory.events.oom_kill"))
       and (.replacement_stats_snapshot.metrics | has("pids.events.max"))
       and .stats_snapshot_rebound
       and (.replacement_response_matches_durable_record | not)
       and (.replacement_response_matches_expected_exit | not)
       and (.cached_response_matches_expected_exit | not)
       and (.init_exit_cached_after_reopen | not)
       and (.process_exit_cached_after_reopen | not)
       and (.first_process_inventory_verified | not)
       and (.replacement_process_inventory_verified | not)
       and (.process_inventory_rebound | not)
       and (.replacement_update_effect_verified | not)
       and .same_generation_reused
       and .setup_create_identity_reused
       and .setup_start_identity_reused
       and (.setup_kill_identity_reused | not)
       and (.same_operation_id_reused | not)
       and .setup_create_response_rebound
       and .setup_start_response_rebound
       and (.exec_response_rebound | not)
       and (.pause_response_rebound | not)
       and (.resume_response_rebound | not)
       and .update_response_rebound
       and (.exec_request_identity_reused | not)
       and (.signal_process_request_identity_reused | not)
       and (.pause_request_identity_reused | not)
       and (.resume_request_identity_reused | not)
       and .update_request_identity_reused
       and (.processes_request_target_reused | not)
       and .stats_request_target_reused
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
       and (.first_exec_marker_verified | not)
       and (.exec_marker_reset_before_replacement | not)
       and (.replacement_exec_marker_verified | not)
       and (.first_signal_marker_verified | not)
       and (.signal_marker_reset_before_replacement | not)
       and (.replacement_signal_marker_verified | not)
       and .force_delete_completed
       and (.stopped_only_delete_completed | not)
       and .durable_records_empty
       and (.delete_journal_succeeded_empty_after_reopen | not)
       and .marker_absent_after_cleanup
       and (.exec_marker_absent_after_cleanup | not)
       and (.signal_marker_absent_after_cleanup | not)
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
           == "a3s.oci.oci-vm-operation-reopen-replacement.v13"
       and .platform == "macos"
       and .status != "available"
       and .requested_operation == "stats"
       and .requested_stage == $stage
       and (.reason | length > 0)' <<<"$output" >/dev/null
  fi
  assert_cleanup_baseline "$stage_console_dir"
}
