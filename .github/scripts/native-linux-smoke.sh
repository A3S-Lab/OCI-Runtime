#!/usr/bin/env bash

set -euo pipefail

runner_temp="${RUNNER_TEMP:?RUNNER_TEMP must identify the CI job temporary directory}"
run_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID must identify the CI run}"
run_attempt="${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT must identify the CI attempt}"
apparmor_userns_policy="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
apparmor_profile_name="a3s-oci-agent-ci"
apparmor_profile_file="$runner_temp/a3s-oci-agent-ci.apparmor"
apparmor_profile_loaded=false
saved_kvm="/dev/a3s-oci-kvm-${run_id}-${run_attempt}"
kvm_original_moved=false
kvm_test_directory_created=false

restore_host() {
  local command_status=$?
  local cleanup_status=0
  local status
  trap - EXIT
  set +e

  if [[ "$apparmor_profile_loaded" == true ]]; then
    sudo apparmor_parser -R "$apparmor_profile_file"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  rm -f "$apparmor_profile_file"
  status=$?
  if ((status != 0)); then
    cleanup_status=$status
  fi
  if [[ "$kvm_test_directory_created" == true && -d /dev/kvm ]]; then
    sudo rmdir /dev/kvm
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

prepare_github_user_namespace_profile() {
  local agent_path

  if [[ "${GITHUB_ACTIONS:-}" != "true" || ! -r "$apparmor_userns_policy" ]]; then
    return
  fi
  printf 'AppArmor unprivileged user namespace restriction: %s\n' \
    "$(<"$apparmor_userns_policy")"
  if [[ "$(<"$apparmor_userns_policy")" != "1" ]]; then
    return
  fi

  agent_path="$(realpath "$PWD/target/debug/a3s-oci-agent")"
  if [[ "$agent_path" == *\"* ||
    "$agent_path" == *$'\n'* ||
    "$agent_path" == *$'\r'* ]]; then
    printf 'The AppArmor attachment path cannot be represented safely: %s\n' \
      "$agent_path" >&2
    return 1
  fi

  {
    printf '%s\n' 'abi <abi/4.0>,'
    printf '%s\n\n' 'include <tunables/global>'
    printf 'profile %s "%s" flags=(unconfined) {\n' \
      "$apparmor_profile_name" "$agent_path"
    printf '%s\n' '  userns,'
    printf '%s\n' '}'
  } >"$apparmor_profile_file"
  sudo apparmor_parser -r -W "$apparmor_profile_file"
  apparmor_profile_loaded=true
  printf 'Loaded temporary AppArmor profile %s for %s\n' \
    "$apparmor_profile_name" "$agent_path"
}

sudo apt-get update
sudo apt-get install --yes busybox-static jq
cargo build -p a3s-oci-agent -p a3s-oci-cli
prepare_github_user_namespace_profile

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

bundle="$runner_temp/a3s-native-bundle"
bundle_b="$runner_temp/a3s-native-bundle-b"
work_parent="$runner_temp/a3s-native-work"
mkdir -p \
  "$bundle/rootfs/bin" "$bundle/rootfs/proc" \
  "$bundle_b/rootfs/bin" "$bundle_b/rootfs/proc" \
  "$work_parent"
for candidate in "$bundle" "$bundle_b"; do
  cp fixtures/native-linux/config.json "$candidate/config.json"
  cp "$(command -v busybox)" "$candidate/rootfs/bin/busybox"
  ln -s busybox "$candidate/rootfs/bin/sh"
done
sudo chown -R 0:0 "$bundle/rootfs" "$bundle_b/rootfs"

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
  sudo sh -c \
    'grep -E "^(NoNewPrivs|Seccomp|Cap(Inh|Prm|Eff|Bnd|Amb)):" /proc/self/status' ||
    true
  if command -v aa-status >/dev/null; then
    sudo aa-status || true
  fi

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
    '.schema_version == "a3s.oci.native-linux-smoke.v2"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundle_loaded
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete", "wait"]
     and .dedicated_vm_rejected_before_create
     and .create_returned_created
     and .create_replayed
     and (.created_pid > 0)
     and .marker_absent_after_create
     and .start_released
     and .running_observed
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
    '.schema_version == "a3s.oci.native-linux-multi-container-smoke.v2"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundles_loaded
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete", "wait"]
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
      '.schema_version == "a3s.oci.native-linux-fault-cleanup.v2"
       and .platform == "linux" and .status == "available"
       and .bundle_loaded
       and .service_operations
           == ["features", "create", "state", "start", "kill", "delete", "wait"]
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
