#!/usr/bin/env bash

set -euo pipefail

runner_temp="${RUNNER_TEMP:?RUNNER_TEMP must identify the CI job temporary directory}"
run_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID must identify the CI run}"
run_attempt="${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT must identify the CI attempt}"

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

bundle="$runner_temp/a3s-native-bundle"
bundle_b="$runner_temp/a3s-native-bundle-b"
work_parent="$runner_temp/a3s-native-work"
mkdir -p "$bundle/rootfs/bin" "$bundle_b/rootfs/bin" "$work_parent"
for candidate in "$bundle" "$bundle_b"; do
  cp fixtures/native-linux/config.json "$candidate/config.json"
  cp "$(command -v busybox)" "$candidate/rootfs/bin/busybox"
  ln -s busybox "$candidate/rootfs/bin/sh"
done

run_smoke() {
  local expected_kvm_present="$1"
  local output
  output="$(sudo "$PWD/target/debug/a3s-oci" native-linux-smoke \
    --agent "$PWD/target/debug/a3s-oci-agent" \
    --bundle "$bundle" \
    --work-parent "$work_parent")"
  printf '%s\n' "$output"
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    '.status == "available" and .kvm_device_present == $expected' \
    <<<"$output" >/dev/null
}

run_multi_container_smoke() {
  local expected_kvm_present="$1"
  local output
  output="$(sudo "$PWD/target/debug/a3s-oci" \
    native-linux-multi-container-smoke \
    --agent "$PWD/target/debug/a3s-oci-agent" \
    --bundle-a "$bundle" \
    --bundle-b "$bundle_b" \
    --work-parent "$work_parent")"
  printf '%s\n' "$output"
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    '.schema_version == "a3s.oci.native-linux-multi-container-smoke.v1"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundles_loaded
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete"]
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
     and .lifecycle.kill_a_replayed
     and .lifecycle.a_stopped
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
  for phase in after-create after-start after-kill; do
    output="$(sudo "$PWD/target/debug/a3s-oci" native-linux-fault-cleanup \
      --agent "$PWD/target/debug/a3s-oci-agent" \
      --bundle "$bundle" \
      --work-parent "$work_parent" \
      --fault-after "$phase")"
    printf '%s\n' "$output"
    jq --exit-status --arg phase "$phase" \
      '.schema_version == "a3s.oci.native-linux-fault-cleanup.v1"
       and .platform == "linux" and .status == "available"
       and .bundle_loaded
       and .service_operations
           == ["features", "create", "state", "start", "kill", "delete"]
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

saved_kvm="/dev/a3s-oci-kvm-${run_id}-${run_attempt}"
restore_kvm() {
  if [[ -d /dev/kvm ]]; then
    sudo rmdir /dev/kvm
  fi
  if [[ -e "$saved_kvm" || -L "$saved_kvm" ]]; then
    sudo mv "$saved_kvm" /dev/kvm
  fi
}
trap restore_kvm EXIT

if [[ -e /dev/kvm || -L /dev/kvm ]]; then
  sudo mv /dev/kvm "$saved_kvm"
fi

run_smoke false
run_multi_container_smoke false
run_fault_cleanup
sudo mkdir /dev/kvm
run_smoke true
run_multi_container_smoke true
