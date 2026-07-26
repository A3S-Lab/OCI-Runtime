#!/usr/bin/env bash

set -euo pipefail

qualification_root=""
saved_kvm="/dev/a3s-oci-kvm-$$"
kvm_original_moved=false
kvm_test_directory_created=false
rootless_user="a3soci$$"
rootless_uid=20000
rootless_gid=20000
rootless_user_created=false
rootless_group_created=false
unprivileged_userns_original=""
unprivileged_userns_changed=false
apparmor_userns_original=""
apparmor_userns_changed=false

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
  if [[ "$rootless_user_created" == true ]]; then
    sudo userdel "$rootless_user"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
    sudo sed -i "\|^${rootless_user}:|d" /etc/subuid /etc/subgid
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ "$rootless_group_created" == true ]] && getent group "$rootless_user" >/dev/null; then
    sudo groupdel "$rootless_user"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ "$apparmor_userns_changed" == true ]]; then
    sudo sysctl -w \
      "kernel.apparmor_restrict_unprivileged_userns=$apparmor_userns_original"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ "$unprivileged_userns_changed" == true ]]; then
    sudo sysctl -w \
      "kernel.unprivileged_userns_clone=$unprivileged_userns_original"
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
sudo apt-get install --yes busybox-static jq uidmap util-linux
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
rootless_bundle="$qualification_root/rootless-bundle"
rootless_bin="$qualification_root/rootless-bin"
work_parent="$qualification_root/work"
rootless_work_parent="$qualification_root/rootless-work"
mkdir -p \
  "$bundle/rootfs/bin" "$bundle/rootfs/proc" \
  "$bundle_b/rootfs/bin" "$bundle_b/rootfs/proc" \
  "$rootless_bundle/rootfs/bin" "$rootless_bundle/rootfs/proc" \
  "$rootless_bin" "$work_parent" "$rootless_work_parent"
for candidate in "$bundle" "$bundle_b"; do
  cp fixtures/native-linux/config.json "$candidate/config.json"
  cp "$(command -v busybox)" "$candidate/rootfs/bin/busybox"
  ln -s busybox "$candidate/rootfs/bin/sh"
done
cp fixtures/native-linux/config.json "$rootless_bundle/config.json"
cp "$(command -v busybox)" "$rootless_bundle/rootfs/bin/busybox"
ln -s busybox "$rootless_bundle/rootfs/bin/sh"
jq '.linux.cgroupsPath = "a3s-oci-smoke-b"' \
  "$bundle_b/config.json" >"$bundle_b/config.json.tmp"
mv "$bundle_b/config.json.tmp" "$bundle_b/config.json"
hook_trace="$bundle/rootfs/.a3s-oci-hook-trace"
# shellcheck disable=SC2016 # Expanded by the hook process, not this script.
hook_command='IFS= read -r A3S_HOOK_STATE || :; printf "%s %s\n" "$A3S_HOOK_PHASE" "$A3S_HOOK_STATE" >> "$A3S_HOOK_TRACE"'
jq \
  --arg command "$hook_command" \
  --arg host_trace "$hook_trace" \
  '
    def hook($phase; $trace): {
      path: "/bin/sh",
      args: ["sh", "-c", $command],
      env: ["A3S_HOOK_PHASE=" + $phase, "A3S_HOOK_TRACE=" + $trace],
      timeout: 5
    };
    .annotations["dev.a3s.oci.hook-smoke"] = "ordered-v1"
    | .hooks = {
        prestart: [hook("prestart"; $host_trace)],
        createRuntime: [hook("createRuntime"; $host_trace)],
        createContainer: [hook("createContainer"; $host_trace)],
        startContainer: [hook("startContainer"; "/.a3s-oci-hook-trace")],
        poststart: [hook("poststart"; $host_trace)],
        poststop: [hook("poststop"; $host_trace)]
      }
  ' \
  "$bundle/config.json" >"$bundle/config.json.tmp"
mv "$bundle/config.json.tmp" "$bundle/config.json"
for candidate in "$bundle" "$bundle_b"; do
  jq --exit-status \
    '.linux.uidMappings
         == [{"containerID": 0, "hostID": 100000, "size": 65536}]
     and .linux.gidMappings
         == [{"containerID": 0, "hostID": 200000, "size": 65536}]' \
    "$candidate/config.json" >/dev/null
done
sudo chown -R 100000:200000 "$bundle/rootfs" "$bundle_b/rootfs"
sudo touch "$hook_trace"
sudo chown 100000:200000 "$hook_trace"
sudo chmod 0666 "$hook_trace"
sudo chmod 0755 "$qualification_root"
test "$(stat --format '%u:%g' "$bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$bundle_b/rootfs")" = '100000:200000'

if getent passwd "$rootless_uid" >/dev/null; then
  printf 'Required rootless smoke UID %s is already allocated\n' "$rootless_uid" >&2
  exit 1
fi
if getent group "$rootless_gid" >/dev/null; then
  printf 'Required rootless smoke GID %s is already allocated\n' "$rootless_gid" >&2
  exit 1
fi
sudo groupadd --gid "$rootless_gid" "$rootless_user"
rootless_group_created=true
sudo useradd \
  --no-create-home \
  --uid "$rootless_uid" \
  --gid "$rootless_gid" \
  --shell /usr/sbin/nologin \
  "$rootless_user"
rootless_user_created=true
sudo sed -i "\|^${rootless_user}:|d" /etc/subuid /etc/subgid
printf '%s:300000:65536\n' "$rootless_user" | sudo tee -a /etc/subuid >/dev/null
printf '%s:400000:65536\n' "$rootless_user" | sudo tee -a /etc/subgid >/dev/null

if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
  unprivileged_userns_original="$(
    cat /proc/sys/kernel/unprivileged_userns_clone
  )"
  if [[ "$unprivileged_userns_original" == 0 ]]; then
    sudo sysctl -w kernel.unprivileged_userns_clone=1
    unprivileged_userns_changed=true
  fi
fi
if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
  apparmor_userns_original="$(
    cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
  )"
  if [[ "$apparmor_userns_original" == 1 ]]; then
    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
    apparmor_userns_changed=true
  fi
fi

# shellcheck disable=SC2016 # Expanded inside the rootless workload.
rootless_command='set -eu; test "$(/bin/busybox id -u)" = 0; test "$(/bin/busybox id -g)" = 0; test "$(/bin/busybox cat /proc/self/setgroups)" = deny; test "$(/bin/busybox stat -c "%u:%g" /.a3s-oci-rootless-subordinate)" = 1:1; printf "a3s-oci-rootless-mapping-v1\n" > /.a3s-oci-rootless-smoke; exec /bin/busybox sleep 300'
jq \
  --arg command "$rootless_command" \
  --argjson uid "$rootless_uid" \
  --argjson gid "$rootless_gid" \
  '
    del(.linux.cgroupsPath, .linux.timeOffsets, .hooks)
    | .linux.namespaces = [
        {"type": "uts"},
        {"type": "mount"},
        {"type": "pid"},
        {"type": "user"}
      ]
    | .linux.uidMappings = [
        {"containerID": 0, "hostID": $uid, "size": 1},
        {"containerID": 1, "hostID": 300000, "size": 65535}
      ]
    | .linux.gidMappings = [
        {"containerID": 0, "hostID": $gid, "size": 1},
        {"containerID": 1, "hostID": 400000, "size": 65535}
      ]
    | .process.args = ["/bin/sh", "-c", $command]
  ' \
  "$rootless_bundle/config.json" >"$rootless_bundle/config.json.tmp"
mv "$rootless_bundle/config.json.tmp" "$rootless_bundle/config.json"
sudo chown -R "$rootless_uid:$rootless_gid" \
  "$rootless_bin" "$rootless_bundle" "$rootless_work_parent"
sudo install \
  --owner="$rootless_uid" \
  --group="$rootless_gid" \
  --mode=0755 \
  "$PWD/target/debug/a3s-oci" \
  "$PWD/target/debug/a3s-oci-agent" \
  "$rootless_bin/"
sudo touch "$rootless_bundle/rootfs/.a3s-oci-rootless-subordinate"
sudo chown 300000:400000 \
  "$rootless_bundle/rootfs/.a3s-oci-rootless-subordinate"
sudo chmod 0644 "$rootless_bundle/rootfs/.a3s-oci-rootless-subordinate"
test "$(stat --format '%u:%g' "$rootless_bundle/rootfs")" \
  = "$rootless_uid:$rootless_gid"
test "$(stat --format '%u:%g' \
  "$rootless_bundle/rootfs/.a3s-oci-rootless-subordinate")" \
  = '300000:400000'

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

verify_single_container_report() {
  local expected_kvm_present="$1"
  local output="$2"
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    '.schema_version == "a3s.oci.native-linux-smoke.v11"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundle_loaded
     and .control_descriptors_prepared
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process"]
     and .dedicated_vm_rejected_before_create
     and .create_returned_created
     and .create_replayed
     and .create_without_control_descriptors_rejected
     and .list_visible_after_create
     and .events_verified
     and .hook_phases
         == ["prestart", "createRuntime", "createContainer", "startContainer",
             "poststart", "poststop"]
     and .hooks_verified
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
     and .control_listener_connectivity_verified
     and .control_init_log_verified
     and .delete_succeeded
     and .delete_replayed
     and .state_missing_after_delete
     and .list_empty_after_delete
     and .control_descriptors_closed_after_delete
     and .marker_removed
     and .executor_runtime_clean
     and .session_root_clean
     and (.reason == null)' \
    <<<"$output" >/dev/null
}

run_smoke() {
  local expected_kvm_present="$1"
  local output
  local status
  sudo truncate --size 0 "$hook_trace"
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
  verify_single_container_report "$expected_kvm_present" "$output"
}

run_service_smoke() {
  local expected_kvm_present="$1"
  local output
  local status
  sudo truncate --size 0 "$hook_trace"
  if output="$(sudo "$PWD/target/debug/a3s-oci" native-linux-service-smoke \
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
  verify_single_container_report "$expected_kvm_present" "$output"
  test ! -e "$bundle/rootfs/.a3s-oci-native-smoke"
  test -z "$(find "$work_parent" -mindepth 1 -print -quit)"
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
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
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
               "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
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

run_rootless_smoke() {
  local output
  local status
  if output="$(sudo setpriv \
      --reuid="$rootless_uid" \
      --regid="$rootless_gid" \
      --clear-groups \
      -- \
      "$rootless_bin/a3s-oci" native-linux-rootless-smoke \
      --agent "$rootless_bin/a3s-oci-agent" \
      --bundle "$rootless_bundle" \
      --work-parent "$rootless_work_parent")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if ((status != 0)); then
    printf '%s\n' 'Native Linux rootless diagnostics:'
    ls -l /usr/bin/newuidmap /usr/bin/newgidmap || true
    grep "^${rootless_user}:" /etc/subuid /etc/subgid || true
    cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || true
    cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || true
    report_native_failure "$rootless_bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson uid "$rootless_uid" \
    --argjson gid "$rootless_gid" \
    '.schema_version == "a3s.oci.native-linux-rootless-smoke.v1"
     and .platform == "linux" and .status == "available"
     and .effective_uid == $uid and .effective_gid == $gid
     and .bundle_loaded
     and .mapping_plan_verified
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process"]
     and .create_returned_created
     and .create_replayed
     and (.created_pid > 0)
     and .uid_map_verified
     and .gid_map_verified
     and .setgroups_denied
     and .workload_verified
     and .exec_replayed
     and .exec_signal_replayed
     and .exec_wait_status == {"signal": 9, "oom_killed": false}
     and .init_kill_replayed
     and .init_wait_status == {"signal": 9, "oom_killed": false}
     and .events_verified
     and .delete_replayed
     and .durable_state_removed
     and .executor_runtime_clean
     and .session_root_clean
     and .marker_removed
     and (.reason == null)' \
    <<<"$output" >/dev/null
  test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-smoke"
  test -z "$(sudo find "$rootless_work_parent" -mindepth 1 -print -quit)"
}

run_service_signal_cleanup() {
  python3 - \
    "$PWD/target/debug/a3s-oci" \
    "$PWD/target/debug/a3s-oci-agent" \
    "$qualification_root/native-service-owner" \
    "$qualification_root/native-service-control" <<'PY'
import atexit
import fcntl
import os
import signal
import socket
import stat
import subprocess
import sys
import time

runtime, agent, service_root, control_root = sys.argv[1:]
os.mkdir(control_root, mode=0o700)
exec_path = os.path.join(control_root, "exec.sock")
pty_path = os.path.join(control_root, "pty.sock")
log_path = os.path.join(control_root, "init.log")

exec_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
exec_listener.bind(exec_path)
exec_listener.listen()
pty_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
pty_listener.bind(pty_path)
pty_listener.listen()
init_log = open(log_path, "w+b", buffering=0)
sources = [exec_listener.fileno(), pty_listener.fileno(), init_log.fileno()]
copies = [fcntl.fcntl(fd, fcntl.F_DUPFD, 10) for fd in sources]
for source, target in zip(copies, (3, 4, 5)):
    os.dup2(source, target, inheritable=True)

process = subprocess.Popen(
    [
        runtime,
        "native-linux-service",
        "--root",
        service_root,
        "--agent",
        agent,
        "--container-id",
        "box-signal-cleanup",
        "--a3s-box-control-fds",
    ],
    pass_fds=(3, 4, 5),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

def cleanup_process():
    if process.poll() is None:
        process.kill()
        process.communicate()

atexit.register(cleanup_process)
originals = set(sources)
exec_listener.close()
pty_listener.close()
init_log.close()
for target in (3, 4, 5):
    if target not in originals:
        os.close(target)
for source in copies:
    os.close(source)

socket_path = os.path.join(service_root, "runtime.sock")
deadline = time.monotonic() + 15
while not os.path.exists(socket_path):
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        raise RuntimeError(
            f"native service exited before readiness ({process.returncode}): "
            f"stdout={stdout!r} stderr={stderr!r}"
        )
    if time.monotonic() >= deadline:
        process.kill()
        stdout, stderr = process.communicate()
        raise RuntimeError(
            f"timed out waiting for native service: stdout={stdout!r} stderr={stderr!r}"
        )
    time.sleep(0.025)

for path, expected_mode in [
    (service_root, 0o700),
    (os.path.join(service_root, "state"), 0o700),
    (os.path.join(service_root, "executor"), 0o700),
    (socket_path, 0o600),
]:
    actual_mode = stat.S_IMODE(os.lstat(path).st_mode)
    if actual_mode != expected_mode:
        raise RuntimeError(
            f"native service path {path} has mode {oct(actual_mode)}, "
            f"expected {oct(expected_mode)}"
        )

process.send_signal(signal.SIGTERM)
try:
    stdout, stderr = process.communicate(timeout=15)
except subprocess.TimeoutExpired as error:
    process.kill()
    stdout, stderr = process.communicate()
    raise RuntimeError(
        f"native service ignored SIGTERM: stdout={stdout!r} stderr={stderr!r}"
    ) from error
if process.returncode != 0:
    raise RuntimeError(
        f"native service SIGTERM exit was {process.returncode}: "
        f"stdout={stdout!r} stderr={stderr!r}"
    )
if os.path.exists(socket_path):
    raise RuntimeError("native service socket remained after SIGTERM")
executor_root = os.path.join(service_root, "executor")
if os.listdir(executor_root):
    raise RuntimeError("native service executor root remained populated after SIGTERM")
atexit.unregister(cleanup_process)
PY
}

if [[ -e /dev/kvm || -L /dev/kvm ]]; then
  sudo mv /dev/kvm "$saved_kvm"
  kvm_original_moved=true
fi

run_rootless_smoke
run_smoke false
run_service_smoke false
run_service_signal_cleanup
run_multi_container_smoke false
run_fault_cleanup
sudo mkdir /dev/kvm
kvm_test_directory_created=true
run_smoke true
run_multi_container_smoke true
