#!/usr/bin/env bash

set -euo pipefail

qualification_root=""
saved_kvm="/dev/a3s-oci-kvm-$$"
kvm_original_moved=false
kvm_test_directory_created=false

restore_host() {
  local command_status=$?
  local cleanup_status=0
  local status
  trap - EXIT
  set +e

  if [[ "$kvm_test_directory_created" == true && -d /dev/kvm ]]; then
    sudo rmdir /dev/kvm
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ -n "$qualification_root" && -d "$qualification_root" ]]; then
    sudo rm -rf --one-file-system "$qualification_root"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ "$kvm_original_moved" == true ]]; then
    sudo mv "$saved_kvm" /dev/kvm
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if ((command_status != 0)); then
    exit "$command_status"
  fi
  exit "$cleanup_status"
}
trap restore_host EXIT

sudo apt-get update
sudo apt-get install --yes busybox-static jq
cargo build -p a3s-oci-agent -p a3s-oci-cli

features="$("$PWD/target/debug/a3s-oci" features)"
printf '%s\n' "$features"
jq --exit-status \
  '.platform == "linux"
   and any(
     .drivers[];
     .driver == "native-linux"
     and .status == "available"
     and .readiness == "probe-only"
     and .evidence.pidfd_signaling == "true"
   )' \
  <<<"$features" >/dev/null

qualification_root="$(mktemp -d /var/tmp/a3s-oci-native.XXXXXXXX)"
bundle="$qualification_root/bundle"
bundle_b="$qualification_root/bundle-b"
work_parent="$qualification_root/work"
mkdir -p \
  "$bundle/rootfs/bin" "$bundle/rootfs/proc" \
  "$bundle_b/rootfs/bin" "$bundle_b/rootfs/proc" \
  "$work_parent"
for candidate in "$bundle" "$bundle_b"; do
  cp fixtures/native-linux/config.json "$candidate/config.json"
  cp "$(command -v busybox)" "$candidate/rootfs/bin/busybox"
  ln -s busybox "$candidate/rootfs/bin/sh"
done
jq '.linux.cgroupsPath = "a3s-oci-smoke-b"' \
  "$bundle_b/config.json" >"$bundle_b/config.json.tmp"
mv "$bundle_b/config.json.tmp" "$bundle_b/config.json"
for candidate in "$bundle" "$bundle_b"; do
  jq --exit-status \
    '.linux.uidMappings
         == [{"containerID": 0, "hostID": 100000, "size": 65536}]
     and .linux.gidMappings
         == [{"containerID": 0, "hostID": 200000, "size": 65536}]' \
    "$candidate/config.json" >/dev/null
done
sudo chown -R 100000:200000 "$bundle/rootfs" "$bundle_b/rootfs"
sudo chmod 0755 "$qualification_root"
test "$(stat --format '%u:%g' "$bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$bundle_b/rootfs")" = '100000:200000'

report_native_failure() {
  local rootfs="$1"
  local status

  printf '%s\n' 'Native Linux host diagnostics:'
  uname -a || true
  printf 'LSM stack: '
  cat /sys/kernel/security/lsm 2>/dev/null || printf '%s\n' unavailable
  printf 'Runner profile: '
  cat /proc/self/attr/current 2>/dev/null || printf '%s\n' unavailable
  findmnt --target / --output TARGET,SOURCE,FSTYPE,OPTIONS --noheadings || true
  findmnt --target "$rootfs" \
    --output TARGET,SOURCE,FSTYPE,OPTIONS --noheadings || true
  namei --long "$rootfs" || true
  sudo sh -c \
    'grep -E "^(NoNewPrivs|Seccomp|Cap(Inh|Prm|Eff|Bnd|Amb)):" /proc/self/status' ||
    true
  if sudo timeout 10s unshare \
      --user --map-root-user --mount --fork -- \
      sh -c \
        'mount --make-rprivate / && mount --rbind "$1" "$1"' \
        sh "$rootfs"; then
    printf '%s\n' 'Combined user/mount namespace rbind probe: succeeded'
  else
    status=$?
    printf 'Combined user/mount namespace rbind probe: failed (%s)\n' "$status"
  fi

  if sudo timeout 10s unshare \
      --user --map-root-user --fork -- \
      unshare --mount --fork -- \
      sh -c \
        'mount --make-rprivate / && mount --rbind "$1" "$1"' \
        sh "$rootfs"; then
    printf '%s\n' 'Sequential user-then-mount namespace rbind probe: succeeded'
  else
    status=$?
    printf 'Sequential user-then-mount namespace rbind probe: failed (%s)\n' \
      "$status"
  fi

  sudo dmesg --ctime 2>/dev/null | tail -n 120 || true
}

run_smoke() {
  local expected_kvm_present="$1"
  local output
  local status
  if output="$(sudo "$PWD/target/debug/a3s-oci" native-linux-smoke \
      --agent "$PWD/target/debug/a3s-oci-agent" \
      --bundle "$bundle" \
      --work-parent "$work_parent")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if ((status != 0)); then
    report_native_failure "$bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    '.schema_version == "a3s.oci.native-linux-smoke.v8"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundle_loaded
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process"]
     and .dedicated_vm_rejected_before_create
     and .create_returned_created
     and .create_replayed
     and .list_visible_after_create
     and (.created_pid > 0)
     and .marker_absent_after_create
     and .start_released
     and .running_observed
     and .processes_verified
     and .process_io_verified
     and .terminal_io_verified
     and .resources_updated
     and .stats_verified
     and .pause_froze_workload
     and .resume_advanced_workload
     and .kill_delivered
     and .kill_replayed
     and .wait_timeout_enforced
     and .wait_exit_status == {"signal": 9, "oom_killed": false}
     and .wait_replayed
     and .stopped_observed
     and .marker_verified
     and .delete_succeeded
     and .delete_replayed
     and .state_missing_after_delete
     and .list_empty_after_delete
     and .marker_removed
     and .executor_runtime_clean
     and .session_root_clean
     and (.reason == null)' \
    <<<"$output" >/dev/null
}

run_multi_container_smoke() {
  local expected_kvm_present="$1"
  local output
  local status
  if output="$(sudo "$PWD/target/debug/a3s-oci" \
      native-linux-multi-container-smoke \
      --agent "$PWD/target/debug/a3s-oci-agent" \
      --bundle-a "$bundle" \
      --bundle-b "$bundle_b" \
      --work-parent "$work_parent")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if ((status != 0)); then
    report_native_failure "$bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    '.schema_version == "a3s.oci.native-linux-multi-container-smoke.v12"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundles_loaded
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process"]
     and .lifecycle.distinct_bundle_directories
     and .lifecycle.distinct_rootfs_directories
     and .lifecycle.both_created_before_start
     and .lifecycle.initial_generation_a == 1
     and .lifecycle.initial_generation_b == 1
     and .lifecycle.recreated_generation_a == 2
     and (.lifecycle.created_pid_a > 0)
     and (.lifecycle.created_pid_b > 0)
     and .lifecycle.distinct_created_pids
     and .lifecycle.create_replays_exact
     and .lifecycle.both_markers_absent_before_start
     and .lifecycle.start_a_replayed
     and .lifecycle.marker_a_verified
     and .lifecycle.b_unchanged_after_a_start
     and .lifecycle.marker_b_absent_after_a_start
     and .lifecycle.wait_a_did_not_block_b
     and .lifecycle.kill_a_replayed
     and .lifecycle.a_stopped
     and .lifecycle.wait_status_a == {"signal": 9, "oom_killed": false}
     and .lifecycle.wait_a_replayed
     and .lifecycle.b_unchanged_after_a_kill
     and .lifecycle.marker_b_absent_after_a_kill
     and .lifecycle.delete_a_replayed
     and .lifecycle.a_missing_after_delete
     and .lifecycle.b_unchanged_after_a_delete
     and .lifecycle.stale_generation_rejected
     and .lifecycle.generation_a_monotonic
     and .lifecycle.recreate_a_replayed
     and .lifecycle.marker_a_absent_after_recreate
     and .lifecycle.cross_container_operation_rejected
     and .lifecycle.b_unchanged_after_replay_conflict
     and .lifecycle.recreated_a_deleted
     and .lifecycle.start_b_replayed
     and .lifecycle.marker_b_verified
     and .lifecycle.kill_b_replayed
     and .lifecycle.b_stopped
     and .lifecycle.wait_status_b == {"signal": 9, "oom_killed": false}
     and .lifecycle.wait_b_replayed
     and .lifecycle.delete_b_replayed
     and .lifecycle.b_missing_after_delete
     and (.namespace_join.donor_pid > 0)
     and .namespace_join.wrong_type_rejected_before_state
     and .namespace_join.joined_non_mount_namespaces
     and .namespace_join.joined_pid_time_workload_verified
     and .namespace_join.joined_mount_namespace
     and .namespace_join.retained_rootfs_verified
     and .namespace_join.donor_unchanged_after_joins
     and .namespace_join.all_state_removed
     and .rootfs_mount.created_before_start
     and .rootfs_mount.mount_targets_created_before_start
     and .rootfs_mount.evidence_absent_before_start
     and .rootfs_mount.start_released
     and .rootfs_mount.rootfs_propagation_shared
     and .rootfs_mount.readonly_path_enforced
     and .rootfs_mount.masked_path_enforced
     and .rootfs_mount.recursive_mount_attributes_enforced
     and .rootfs_mount.idmapped_mounts_enforced
     and .rootfs_mount.idmap_source_ownership_unchanged
     and .rootfs_mount.idmap_nonrecursive_enforced
     and .rootfs_mount.ridmap_recursive_enforced
     and .rootfs_mount.readonly_rootfs_enforced
     and .rootfs_mount.exact_evidence
     and .rootfs_mount.wait_status
         == {"exit_code": 0, "oom_killed": false}
     and .rootfs_mount.state_removed
     and .rootfs_mount.artifacts_removed
     and .pid_supervision.pid1_supervision_enforced
     and .pid_supervision.orphan_reaping_enforced
     and .markers_removed
     and .executor_runtime_clean
     and .session_root_clean
     and (.reason == null)' \
    <<<"$output" >/dev/null
  test ! -e "$bundle/rootfs/.a3s-oci-native-smoke"
  test ! -e "$bundle_b/rootfs/.a3s-oci-native-smoke"
  test -z "$(find "$work_parent" -mindepth 1 -print -quit)"
}

run_fault_cleanup() {
  local phase
  local output
  local status
  for phase in after-create after-start after-kill; do
    if output="$(sudo "$PWD/target/debug/a3s-oci" native-linux-fault-cleanup \
        --agent "$PWD/target/debug/a3s-oci-agent" \
        --bundle "$bundle" \
        --work-parent "$work_parent" \
        --fault-after "$phase")"; then
      status=0
    else
      status=$?
    fi
    printf '%s\n' "$output"
    if ((status != 0)); then
      report_native_failure "$bundle/rootfs"
      return "$status"
    fi
    jq --exit-status --arg phase "$phase" \
      '.schema_version == "a3s.oci.native-linux-fault-cleanup.v6"
       and .platform == "linux" and .status == "available"
       and .bundle_loaded
       and .service_operations
           == ["features", "create", "state", "start", "kill", "delete",
               "exec", "wait", "list", "pause", "resume", "update", "processes",
               "stats", "read-output", "write-stdin", "close-stdin", "resize",
               "signal-process", "wait-process"]
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
       and .executor_shutdown_succeeded
       and .process_reaped
       and .marker_removed
       and .executor_runtime_clean
       and .session_root_clean
       and (.reason == null)' \
      <<<"$output" >/dev/null
    test ! -e "$bundle/rootfs/.a3s-oci-native-smoke"
    test -z "$(find "$work_parent" -mindepth 1 -print -quit)"
  done
}

if [[ -e /dev/kvm || -L /dev/kvm ]]; then
  sudo mv /dev/kvm "$saved_kvm"
  kvm_original_moved=true
fi

run_smoke false
run_multi_container_smoke false
run_fault_cleanup
sudo mkdir /dev/kvm
kvm_test_directory_created=true
run_smoke true
run_multi_container_smoke true
