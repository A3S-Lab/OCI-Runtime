#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=.github/scripts/native-linux-hook-owner-death.sh
source .github/scripts/native-linux-hook-owner-death.sh

qualification_root=""
saved_kvm="/dev/a3s-oci-kvm-$$"
kvm_original_moved=false
kvm_test_directory_created=false
rootless_user="a3soci$$"
rootless_uid=20000
rootless_gid=20000
rootless_user_created=false
rootless_group_created=false
rootless_cgroup_parent="/sys/fs/cgroup/a3s-oci-rootless-$rootless_uid-$$"
rootless_cgroup_created=false
rootless_cgroup_host_control="$rootless_cgroup_parent/a3s-host-control"
rootless_cgroup_host_control_created=false
rootless_cgroup_replacement="$rootless_cgroup_parent-replacement"
rootless_cgroup_replacement_created=false
rootless_cgroup_bind_mounted=false
rootless_cgroup_process_pid=""
rootless_cgroup_process_launcher_pid=""
recovery_owner_pid=""
recovery_runtime_owner_pid=""
hook_recovery_group_pid=""
soak_bundles=()
soak_iterations="${A3S_OCI_NATIVE_SOAK_ITERATIONS:-25}"
native_focus="${A3S_OCI_NATIVE_FOCUS:-}"
native_runtime_binary="${A3S_OCI_NATIVE_RUNTIME_BINARY:-}"
native_agent_binary="${A3S_OCI_NATIVE_AGENT_BINARY:-}"
soak_concurrent_containers=4
soak_operation_timeout_ms=30000
unprivileged_userns_original=""
unprivileged_userns_changed=false
apparmor_userns_original=""
apparmor_userns_changed=false
absolute_cgroup_path="/a3s-oci-absolute-$$"
absolute_cgroup_host_path="/sys/fs/cgroup${absolute_cgroup_path}"
network_device_sources=()
network_device_success_source="a3snd$$"
network_device_conflict_source="a3snc$$"
network_device_rollback_first="a3snr0$$"
network_device_rollback_second="a3snr1$$"
network_device_rootless_source="a3snl$$"
hugetlb_page_size=""
hugetlb_reservation_control=false
rdma_device=""
unified_io_device=""
unified_io_rbps="1099511627776"
unified_io_wiops="1000000000"

detect_hugetlb_page_size() {
  local candidate
  local candidate_kbytes
  local candidate_page_size
  local selected_kbytes=""
  local selected_page_size=""

  if ! grep -qw hugetlb /sys/fs/cgroup/cgroup.controllers; then
    return 0
  fi

  for candidate in /sys/kernel/mm/hugepages/hugepages-*kB; do
    [[ -d "$candidate" ]] || continue
    if [[ "${candidate##*/}" =~ ^hugepages-([0-9]+)kB$ ]]; then
      candidate_kbytes="${BASH_REMATCH[1]}"
    else
      continue
    fi
    if ((candidate_kbytes % 1048576 == 0)); then
      candidate_page_size="$((candidate_kbytes / 1048576))GB"
    elif ((candidate_kbytes % 1024 == 0)); then
      candidate_page_size="$((candidate_kbytes / 1024))MB"
    else
      candidate_page_size="${candidate_kbytes}KB"
    fi
    if [[ ! -f "/sys/fs/cgroup/hugetlb.${candidate_page_size}.max" ]]; then
      continue
    fi
    if [[ -z "$selected_kbytes" ]] || ((candidate_kbytes < selected_kbytes)); then
      selected_kbytes="$candidate_kbytes"
      selected_page_size="$candidate_page_size"
    fi
  done

  printf '%s' "$selected_page_size"
}

detect_rdma_device() {
  local candidate
  local candidate_name

  if ! grep -qw rdma /sys/fs/cgroup/cgroup.controllers || \
    [[ ! -r /sys/fs/cgroup/rdma.max ]]; then
    return 0
  fi

  for candidate in /sys/class/infiniband/*; do
    [[ -e "$candidate" ]] || continue
    candidate_name="${candidate##*/}"
    if [[ ! "$candidate_name" =~ ^[[:alnum:]_.:-]+$ ]] || \
      ((${#candidate_name} > 63)); then
      continue
    fi
    if awk -v device="$candidate_name" \
      '$1 == device { found = 1 } END { exit !found }' \
      /sys/fs/cgroup/rdma.max; then
      printf '%s' "$candidate_name"
      return 0
    fi
  done
}

detect_unified_io_device() {
  local candidate
  local candidate_device
  local candidate_name
  local probe="/sys/fs/cgroup/a3s-oci-unified-io-probe-$$"
  local selected=""

  if ! grep -qw io /sys/fs/cgroup/cgroup.controllers; then
    return 0
  fi
  sudo mkdir "$probe"
  for candidate in /sys/class/block/*; do
    [[ -r "$candidate/dev" ]] || continue
    candidate_name="${candidate##*/}"
    case "$candidate_name" in
      loop* | nbd* | ram* | zram*) continue ;;
    esac
    candidate_device="$(cat "$candidate/dev")"
    if printf '%s rbps=max wbps=max riops=max wiops=max\n' \
      "$candidate_device" | sudo tee "$probe/io.max" >/dev/null 2>&1; then
      selected="$candidate_device"
      break
    fi
  done
  sudo rmdir "$probe"
  printf '%s' "$selected"
}

restore_host() {
  local command_status=$?
  local cleanup_status=0
  local network_device
  local status
  trap - EXIT
  set +e

  if [[ -n "$recovery_runtime_owner_pid" ]] && \
    sudo kill -0 "$recovery_runtime_owner_pid" 2>/dev/null; then
    sudo kill -KILL "$recovery_runtime_owner_pid"
  fi
  if [[ -n "$recovery_owner_pid" ]] && kill -0 "$recovery_owner_pid" 2>/dev/null; then
    sudo kill -KILL "$recovery_owner_pid"
    wait "$recovery_owner_pid" 2>/dev/null
  fi
  if [[ -n "$hook_recovery_group_pid" ]]; then
    sudo kill -KILL -- "-$hook_recovery_group_pid" 2>/dev/null || true
    hook_recovery_group_pid=""
  fi

  for network_device in "${network_device_sources[@]}"; do
    if sudo ip link show dev "$network_device" >/dev/null 2>&1; then
      sudo ip link delete dev "$network_device"
      status=$?
      if ((status != 0)); then
        cleanup_status=$status
      fi
    fi
  done

  if [[ "$rootless_cgroup_bind_mounted" == true ]]; then
    sudo umount "$rootless_cgroup_parent"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
    rootless_cgroup_bind_mounted=false
  fi
  if [[ -n "$rootless_cgroup_process_pid" ]]; then
    if sudo kill -0 "$rootless_cgroup_process_pid" 2>/dev/null; then
      sudo kill -KILL "$rootless_cgroup_process_pid"
    fi
    rootless_cgroup_process_pid=""
  fi
  if [[ -n "$rootless_cgroup_process_launcher_pid" ]]; then
    wait "$rootless_cgroup_process_launcher_pid" 2>/dev/null
    rootless_cgroup_process_launcher_pid=""
  fi
  if [[ "$rootless_cgroup_replacement_created" == true && \
      -d "$rootless_cgroup_replacement" ]]; then
    sudo rmdir "$rootless_cgroup_replacement"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
    rootless_cgroup_replacement_created=false
  fi

  if [[ "$rootless_cgroup_host_control_created" == true && \
      -d "$rootless_cgroup_host_control" ]]; then
    sudo rmdir "$rootless_cgroup_host_control"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
    rootless_cgroup_host_control_created=false
  fi

  if [[ "$kvm_test_directory_created" == true && -d /dev/kvm ]]; then
    sudo rmdir /dev/kvm
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ "$rootless_cgroup_created" == true && -d "$rootless_cgroup_parent" ]]; then
    sudo rmdir "$rootless_cgroup_parent"
    status=$?
    if ((status != 0)); then
      cleanup_status=$status
    fi
  fi
  if [[ -d "$absolute_cgroup_host_path" ]]; then
    sudo rmdir "$absolute_cgroup_host_path"
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

if [[ ! "$soak_iterations" =~ ^[0-9]+$ ]] ||
  ((soak_iterations < 1 || soak_iterations > 10000)); then
  printf 'A3S_OCI_NATIVE_SOAK_ITERATIONS must be an integer from 1 to 10000\n' >&2
  exit 2
fi

validate_native_binaries() {
  for candidate in "$native_runtime_binary" "$native_agent_binary"; do
    if [[ ! -f "$candidate" || -L "$candidate" || ! -x "$candidate" ]]; then
      printf 'Native qualification binary must be a regular nonsymlink executable: %s\n' \
        "$candidate" >&2
      exit 2
    fi
  done
  native_runtime_binary="$(realpath -e -- "$native_runtime_binary")"
  native_agent_binary="$(realpath -e -- "$native_agent_binary")"
  if [[ "$native_runtime_binary" == "$native_agent_binary" ]]; then
    printf '%s\n' 'Native runtime and Agent qualification binaries must be distinct' >&2
    exit 2
  fi
}

if [[ -z "$native_runtime_binary" && -z "$native_agent_binary" ]]; then
  use_development_binaries=true
elif [[ -z "$native_runtime_binary" || -z "$native_agent_binary" ]]; then
  printf '%s\n' \
    'A3S_OCI_NATIVE_RUNTIME_BINARY and A3S_OCI_NATIVE_AGENT_BINARY must be supplied together' >&2
  exit 2
else
  use_development_binaries=false
  validate_native_binaries
fi

sudo apt-get update
sudo apt-get install --yes busybox-static iproute2 jq uidmap util-linux
if [[ "$use_development_binaries" == true ]]; then
  cargo build -p a3s-oci-agent -p a3s-oci-cli
  native_runtime_binary="$PWD/target/debug/a3s-oci"
  native_agent_binary="$PWD/target/debug/a3s-oci-agent"
  validate_native_binaries
fi

hugetlb_page_size="$(detect_hugetlb_page_size)"
if [[ -n "$hugetlb_page_size" ]]; then
  if [[ -f "/sys/fs/cgroup/hugetlb.${hugetlb_page_size}.rsvd.max" ]]; then
    hugetlb_reservation_control=true
  fi
  printf 'Native HugeTLB evidence enabled for page size %s (reservation=%s)\n' \
    "$hugetlb_page_size" "$hugetlb_reservation_control"
else
  printf '%s\n' \
    'Native HugeTLB evidence skipped: no usable host cgroup-v2 HugeTLB page size'
fi

rdma_device="$(detect_rdma_device)"
if [[ -n "$rdma_device" ]]; then
  printf 'Native RDMA evidence enabled for device %s\n' "$rdma_device"
else
  printf '%s\n' \
    'Native RDMA evidence skipped: no usable host cgroup-v2 RDMA device'
fi

unified_io_device="$(detect_unified_io_device)"
if [[ -n "$unified_io_device" ]]; then
  printf 'Native Unified io.max evidence enabled for device %s\n' \
    "$unified_io_device"
else
  printf '%s\n' \
    'Native Unified io.max evidence skipped: no usable host block device'
fi

features="$("$native_runtime_binary" features)"
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
control_bundle="$qualification_root/control-bundle"
terminal_bundle="$qualification_root/terminal-bundle"
terminal_existing_bundle="$qualification_root/terminal-existing-bundle"
device_boundary_bundle="$qualification_root/device-boundary-bundle"
cgroup_ownership_bundle="$qualification_root/cgroup-ownership-bundle"
cgroup_ownership_readonly_bundle="$qualification_root/cgroup-ownership-readonly-bundle"
recovery_bundle="$qualification_root/recovery-bundle"
hook_recovery_bundle="$qualification_root/hook-recovery-bundle"
rootless_bundle="$qualification_root/rootless-bundle"
network_device_bundle="$qualification_root/network-device-bundle"
network_device_conflict_bundle="$qualification_root/network-device-conflict-bundle"
network_device_rollback_bundle="$qualification_root/network-device-rollback-bundle"
network_device_rootless_bundle="$qualification_root/network-device-rootless-bundle"
rootless_bin="$qualification_root/rootless-bin"
work_parent="$qualification_root/work"
rootless_work_parent="$qualification_root/rootless-work"
mkdir -p \
  "$bundle/rootfs/bin" "$bundle/rootfs/dev" "$bundle/rootfs/proc" \
  "$bundle_b/rootfs/bin" "$bundle_b/rootfs/dev" "$bundle_b/rootfs/proc" \
  "$control_bundle/rootfs/bin" "$control_bundle/rootfs/dev" "$control_bundle/rootfs/proc" \
  "$control_bundle/rootfs/sys/fs/cgroup" \
  "$terminal_bundle/rootfs/bin" "$terminal_bundle/rootfs/dev" \
  "$terminal_bundle/rootfs/proc" "$terminal_bundle/rootfs/run/a3s" \
  "$recovery_bundle/rootfs/bin" "$recovery_bundle/rootfs/dev" "$recovery_bundle/rootfs/proc" \
  "$hook_recovery_bundle/rootfs/bin" "$hook_recovery_bundle/rootfs/dev" \
  "$hook_recovery_bundle/rootfs/proc" \
  "$rootless_bundle/rootfs/bin" "$rootless_bundle/rootfs/dev" "$rootless_bundle/rootfs/proc" \
  "$rootless_bin" "$work_parent" "$rootless_work_parent"
for candidate in \
  "$bundle" \
  "$bundle_b" \
  "$control_bundle" \
  "$terminal_bundle" \
  "$recovery_bundle" \
  "$hook_recovery_bundle"; do
  cp fixtures/native-linux/config.json "$candidate/config.json"
  cp "$(command -v busybox)" "$candidate/rootfs/bin/busybox"
  ln -s busybox "$candidate/rootfs/bin/sh"
done
jq '.linux.cgroupsPath = "a3s-oci-owner-recovery" | del(.hooks)' \
  "$recovery_bundle/config.json" >"$recovery_bundle/config.json.tmp"
mv "$recovery_bundle/config.json.tmp" "$recovery_bundle/config.json"
prepare_hook_owner_death_bundle "$hook_recovery_bundle"
for slot in 0 1 2 3; do
  candidate="$qualification_root/soak-bundle-$slot"
  mkdir -p "$candidate/rootfs/bin" "$candidate/rootfs/dev" "$candidate/rootfs/proc"
  cp fixtures/native-linux/config.json "$candidate/config.json"
  cp "$(command -v busybox)" "$candidate/rootfs/bin/busybox"
  ln -s busybox "$candidate/rootfs/bin/sh"
  jq --arg cgroup "a3s-oci-soak-$slot" \
    '.linux.cgroupsPath = $cgroup' \
    "$candidate/config.json" >"$candidate/config.json.tmp"
  mv "$candidate/config.json.tmp" "$candidate/config.json"
  soak_bundles+=("$candidate")
done
cp fixtures/native-linux/config.json "$rootless_bundle/config.json"
cp "$(command -v busybox)" "$rootless_bundle/rootfs/bin/busybox"
ln -s busybox "$rootless_bundle/rootfs/bin/sh"
jq --arg cgroup "$absolute_cgroup_path" '.linux.cgroupsPath = $cgroup' \
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
control_hook_trace="$control_bundle/rootfs/.a3s-oci-hook-trace"
# shellcheck disable=SC2016 # Expanded by the trusted configured init.
control_command_prefix='test "$A3S_CONTROL_CGROUP_PROCS_FD" = 6; test "$A3S_WORKLOAD_CGROUP_PROCS_FD" = 7; test -d /sys/fs/cgroup/a3s-control; test -d /sys/fs/cgroup/a3s-workload; test -z "$(/bin/busybox cat /sys/fs/cgroup/cgroup.procs)"; test "$(/bin/busybox cat /proc/self/cgroup)" = "0::/a3s-control"; printf 0 >&7; test "$(/bin/busybox cat /proc/self/cgroup)" = "0::/a3s-workload"; '
control_command_prefix+='test "$(/bin/busybox cat /sys/fs/cgroup/a3s-control/memory.high)" = max; test "$(/bin/busybox cat /sys/fs/cgroup/a3s-workload/memory.high)" = 201326592; '
if [[ -n "$unified_io_device" ]]; then
  control_command_prefix+='test -z "$(/bin/busybox cat /sys/fs/cgroup/a3s-control/io.max)"; '
  control_command_prefix+="/bin/busybox grep -Fxq '${unified_io_device} rbps=${unified_io_rbps} wbps=max riops=max wiops=${unified_io_wiops}' /sys/fs/cgroup/a3s-workload/io.max; "
fi
if [[ -n "$hugetlb_page_size" ]]; then
  control_command_prefix+="test \"\$(/bin/busybox cat /sys/fs/cgroup/a3s-control/hugetlb.${hugetlb_page_size}.max)\" = max; "
  control_command_prefix+="test \"\$(/bin/busybox cat /sys/fs/cgroup/a3s-workload/hugetlb.${hugetlb_page_size}.max)\" = 0; "
  if [[ "$hugetlb_reservation_control" == true ]]; then
    control_command_prefix+="test \"\$(/bin/busybox cat /sys/fs/cgroup/a3s-control/hugetlb.${hugetlb_page_size}.rsvd.max)\" = max; "
    control_command_prefix+="test \"\$(/bin/busybox cat /sys/fs/cgroup/a3s-workload/hugetlb.${hugetlb_page_size}.rsvd.max)\" = 0; "
  fi
fi
if [[ -n "$rdma_device" ]]; then
  control_command_prefix+="/bin/busybox grep -Fxq '${rdma_device} hca_handle=max hca_object=max' /sys/fs/cgroup/a3s-control/rdma.max; "
  control_command_prefix+="/bin/busybox grep -Fxq '${rdma_device} hca_handle=0 hca_object=0' /sys/fs/cgroup/a3s-workload/rdma.max; "
fi
control_command_prefix+='exec 6>&- 7>&-; '
jq \
  --arg command_prefix "$control_command_prefix" \
  --arg hook_trace "$control_hook_trace" \
  --arg hugetlb_page_size "$hugetlb_page_size" \
  --arg rdma_device "$rdma_device" \
  --arg unified_io_device "$unified_io_device" \
  --arg unified_io_rbps "$unified_io_rbps" \
  --arg unified_io_wiops "$unified_io_wiops" \
  '
    .process.args[2] = ($command_prefix + .process.args[2])
    | .mounts += [{
        destination: "/sys/fs/cgroup",
        type: "cgroup2",
        source: "cgroup2",
        options: ["ro", "nosuid", "noexec", "nodev"]
      }]
    | .linux.cgroupsPath = "a3s-oci-control-workload-smoke"
    | .linux.resources = {
        memory: {
          limit: 268435456,
          reservation: 67108864,
          swap: 536870912
        },
        cpu: {shares: 512, quota: 50000, period: 100000},
        pids: {limit: 64},
        unified: {"memory.high": "201326592"}
      }
    | if $hugetlb_page_size == ""
      then .
      else .linux.resources.hugepageLimits = [{
        pageSize: $hugetlb_page_size,
        limit: 0
      }]
      end
    | if $rdma_device == ""
      then .
      else .linux.resources.rdma = {
        ($rdma_device): {hcaHandles: 0, hcaObjects: 0}
      }
      end
    | if $unified_io_device == ""
      then .
      else .linux.resources.unified["io.max"] =
        ($unified_io_device
          + " rbps=" + $unified_io_rbps
          + " wiops=" + $unified_io_wiops)
      end
    | .annotations["dev.a3s.oci.cgroup.layout"] = "control-workload-v1"
    | .annotations["dev.a3s.oci.cgroup.control-memory-headroom-bytes"] = "67108864"
    | .annotations["dev.a3s.oci.cgroup.control-cpu-headroom-micros"] = "25000"
    | .annotations["dev.a3s.oci.cgroup.control-pids-headroom"] = "32"
    | .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
            then "A3S_HOOK_TRACE=" + $hook_trace
            else .
            end
          )
        )
      )
    | .hooks.startContainer[].env |= map(
        if startswith("A3S_HOOK_TRACE=")
        then "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
        else .
        end
      )
  ' \
  "$bundle/config.json" >"$control_bundle/config.json.tmp"
mv "$control_bundle/config.json.tmp" "$control_bundle/config.json"
terminal_hook_trace="$terminal_bundle/rootfs/.a3s-oci-hook-trace"
# shellcheck disable=SC2016 # Expanded by the configured terminal init.
terminal_command_prefix='test -t 0; test -t 1; test -t 2; test -c /dev/console; test "$(/bin/busybox readlink /dev/ptmx)" = pts/ptmx; test "$(/bin/busybox stty size)" = "40 120"; console_identity=$(/bin/busybox stat -Lc "%d:%i:%t:%T" /dev/console); stdin_identity=$(/bin/busybox stat -Lc "%d:%i:%t:%T" /proc/self/fd/0); test "$console_identity" = "$stdin_identity"; test -p /run/a3s/device-fifo; test "$(/bin/busybox stat -c "%a:%u:%g" /run/a3s/device-fifo)" = "640:1:2"; '
jq \
  --arg command_prefix "$terminal_command_prefix" \
  --arg hook_trace "$terminal_hook_trace" \
  '
    .process.terminal = true
    | .process.consoleSize = {width: 120, height: 40}
    | .process.args[2] = ($command_prefix + .process.args[2])
    | .linux.devices += [{
        path: "/run/a3s/device-fifo",
        type: "p",
        fileMode: 416,
        uid: 1,
        gid: 2
      }]
    | .linux.cgroupsPath = "a3s-oci-terminal-init-smoke"
    | .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
               and . != "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
            then "A3S_HOOK_TRACE=" + $hook_trace
            else .
            end
          )
        )
      )
  ' \
  "$bundle/config.json" >"$terminal_bundle/config.json.tmp"
mv "$terminal_bundle/config.json.tmp" "$terminal_bundle/config.json"
mkdir "$terminal_existing_bundle"
cp -a --no-preserve=ownership "$terminal_bundle/." "$terminal_existing_bundle/"
terminal_existing_hook_trace="$terminal_existing_bundle/rootfs/.a3s-oci-hook-trace"
jq \
  --arg hook_trace "$terminal_existing_hook_trace" \
  '
    .linux.cgroupsPath = "a3s-oci-terminal-existing-init-smoke"
    | .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
               and . != "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
            then "A3S_HOOK_TRACE=" + $hook_trace
            else .
            end
          )
        )
      )
  ' \
  "$terminal_bundle/config.json" >"$terminal_existing_bundle/config.json.tmp"
mv "$terminal_existing_bundle/config.json.tmp" "$terminal_existing_bundle/config.json"
printf '%s\n' 'a3s-preexisting-console-v1' \
  >"$terminal_existing_bundle/rootfs/dev/console"
mkdir "$device_boundary_bundle"
cp -a --no-preserve=ownership "$bundle/." "$device_boundary_bundle/"
device_boundary_hook_trace="$device_boundary_bundle/rootfs/.a3s-oci-hook-trace"
mkdir "$device_boundary_bundle/late-device-source"
sudo mknod "$device_boundary_bundle/late-device-source/unknown" c 240 0
sudo chmod 0666 "$device_boundary_bundle/late-device-source/unknown"
# shellcheck disable=SC2016 # Expanded by the configured boundary workload.
device_boundary_command='export LC_ALL=C; rm -f /declared-null /undeclared-device /late-device-error; /bin/busybox mknod /declared-null c 1 3; test -c /declared-null; printf probe > /declared-null; rm /declared-null; if /bin/busybox mknod /undeclared-device c 240 0 2>/late-device-error; then exit 91; fi; test ! -e /undeclared-device; /bin/busybox grep -q "Operation not permitted" /late-device-error; /bin/busybox mount -o remount,bind,dev /late-dev; if /bin/busybox dd if=/late-dev/unknown of=/dev/null bs=1 count=1 2>/late-device-error; then exit 92; fi; /bin/busybox grep -q "Operation not permitted" /late-device-error; rm /late-device-error; '
jq \
  --arg command_prefix "$device_boundary_command" \
  --arg hook_trace "$device_boundary_hook_trace" \
  '
    del(.linux.cgroupsPath, .linux.personality, .linux.memoryPolicy)
    | .process.capabilities.bounding += ["CAP_MKNOD", "CAP_SYS_ADMIN"]
    | .process.capabilities.effective += ["CAP_MKNOD", "CAP_SYS_ADMIN"]
    | .process.capabilities.permitted += ["CAP_MKNOD", "CAP_SYS_ADMIN"]
    | .process.args[2] = (
        $command_prefix
        + (.process.args[2]
            | split("test \"$(/bin/busybox cat /proc/self/personality)\" = 00000008; ")
            | join("")
            | split("/bin/busybox awk '\''$2 == \"bind=static:0\" { ok = 1 } END { exit !ok }'\'' /proc/self/numa_maps; ")
            | join("")
            | gsub("0000000000000401"; "0000000008200401"))
      )
    | .mounts += [{
        destination: "/late-dev",
        type: "bind",
        source: "late-device-source",
        options: ["bind", "nodev", "nosuid", "noexec"]
      }]
    | .annotations["dev.a3s.oci.device-boundary"] =
        "inventory-cap-mknod-late-source-v1"
    | .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
               and . != "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
            then "A3S_HOOK_TRACE=" + $hook_trace
            else .
            end
          )
        )
      )
  ' \
  "$device_boundary_bundle/config.json" \
  >"$device_boundary_bundle/config.json.tmp"
mv \
  "$device_boundary_bundle/config.json.tmp" \
  "$device_boundary_bundle/config.json"
for candidate in \
  "$cgroup_ownership_bundle" \
  "$cgroup_ownership_readonly_bundle"; do
  mkdir "$candidate"
  cp -a --no-preserve=ownership "$bundle/." "$candidate/"
done
cgroup_ownership_hook_trace="$cgroup_ownership_bundle/rootfs/.a3s-oci-hook-trace"
cgroup_ownership_readonly_hook_trace="$cgroup_ownership_readonly_bundle/rootfs/.a3s-oci-hook-trace"
cgroup_delegate_inventory="$cgroup_ownership_bundle/rootfs/.a3s-oci-cgroup-delegate"
if [[ -r /sys/kernel/cgroup/delegate ]]; then
  sed '/^$/d' /sys/kernel/cgroup/delegate >"$cgroup_delegate_inventory"
else
  printf '%s\n' cgroup.procs cgroup.subtree_control cgroup.threads \
    >"$cgroup_delegate_inventory"
fi
while IFS= read -r delegate_file; do
  if [[ ! "$delegate_file" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'Invalid kernel cgroup delegate file: %s\n' "$delegate_file" >&2
    exit 1
  fi
done <"$cgroup_delegate_inventory"
cgroup_unlisted_file=""
for candidate in cgroup.events cgroup.type cgroup.stat; do
  if [[ -e "/sys/fs/cgroup/$candidate" ]] && \
      ! grep -Fxq "$candidate" "$cgroup_delegate_inventory"; then
    cgroup_unlisted_file="$candidate"
    break
  fi
done
if [[ -z "$cgroup_unlisted_file" ]]; then
  printf '%s\n' 'No stable unlisted cgroup v2 file is available for ownership evidence' >&2
  exit 1
fi
printf '%s\n' "$cgroup_unlisted_file" \
  >"$cgroup_ownership_bundle/rootfs/.a3s-oci-cgroup-unlisted"
# shellcheck disable=SC2016 # Expanded by the delegated cgroup workload.
cgroup_ownership_command='set -eu; overflow_uid=$(/bin/busybox cat /proc/sys/kernel/overflowuid); overflow_gid=$(/bin/busybox cat /proc/sys/kernel/overflowgid); test "$(/bin/busybox stat -c "%u:%g" /sys/fs/cgroup)" = "0:$overflow_gid"; delegated=0; while IFS= read -r name; do if [ -e "/sys/fs/cgroup/$name" ]; then test "$(/bin/busybox stat -c "%u:%g" "/sys/fs/cgroup/$name")" = "0:$overflow_gid"; delegated=$((delegated + 1)); fi; done < /.a3s-oci-cgroup-delegate; test "$delegated" -gt 0; unlisted=$(/bin/busybox cat /.a3s-oci-cgroup-unlisted); test "$(/bin/busybox stat -c "%u:%g" "/sys/fs/cgroup/$unlisted")" = "$overflow_uid:$overflow_gid"; /bin/busybox mkdir /sys/fs/cgroup/a3s-delegation-write-probe; /bin/busybox rmdir /sys/fs/cgroup/a3s-delegation-write-probe; '
jq \
  --arg command_prefix "$cgroup_ownership_command" \
  --arg hook_trace "$cgroup_ownership_hook_trace" \
  '
    del(.linux.personality, .linux.memoryPolicy)
    | .linux.cgroupsPath = "a3s-oci-cgroup-ownership-smoke"
    | .process.args[2] = (
        $command_prefix
        + (.process.args[2]
            | split("test \"$(/bin/busybox cat /proc/self/personality)\" = 00000008; ")
            | join("")
            | split("/bin/busybox awk '\''$2 == \"bind=static:0\" { ok = 1 } END { exit !ok }'\'' /proc/self/numa_maps; ")
            | join(""))
      )
    | .mounts += [{
        destination: "/sys/fs/cgroup",
        type: "cgroup",
        source: "cgroup",
        options: ["rw", "nosuid", "noexec", "nodev"]
      }]
    | .annotations["dev.a3s.oci.cgroup-ownership"] = "delegate-v1"
    | .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
               and . != "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
            then "A3S_HOOK_TRACE=" + $hook_trace
            else .
            end
          )
        )
      )
  ' \
  "$cgroup_ownership_bundle/config.json" \
  >"$cgroup_ownership_bundle/config.json.tmp"
mv \
  "$cgroup_ownership_bundle/config.json.tmp" \
  "$cgroup_ownership_bundle/config.json"
# shellcheck disable=SC2016 # Expanded by the read-only cgroup workload.
cgroup_ownership_readonly_command='set -eu; overflow_uid=$(/bin/busybox cat /proc/sys/kernel/overflowuid); overflow_gid=$(/bin/busybox cat /proc/sys/kernel/overflowgid); test "$(/bin/busybox stat -c "%u:%g" /sys/fs/cgroup)" = "$overflow_uid:$overflow_gid"; if /bin/busybox mkdir /sys/fs/cgroup/a3s-readonly-write-probe 2>/tmp/a3s-cgroup-readonly-error; then /bin/busybox rmdir /sys/fs/cgroup/a3s-readonly-write-probe; exit 91; fi; /bin/busybox rm -f /tmp/a3s-cgroup-readonly-error; '
jq \
  --arg command_prefix "$cgroup_ownership_readonly_command" \
  --arg hook_trace "$cgroup_ownership_readonly_hook_trace" \
  '
    del(.linux.personality, .linux.memoryPolicy)
    | .linux.cgroupsPath = "a3s-oci-cgroup-ownership-readonly-smoke"
    | .process.args[2] = (
        $command_prefix
        + (.process.args[2]
            | split("test \"$(/bin/busybox cat /proc/self/personality)\" = 00000008; ")
            | join("")
            | split("/bin/busybox awk '\''$2 == \"bind=static:0\" { ok = 1 } END { exit !ok }'\'' /proc/self/numa_maps; ")
            | join(""))
      )
    | .mounts += [{
        destination: "/sys/fs/cgroup",
        type: "cgroup",
        source: "cgroup",
        options: ["ro", "nosuid", "noexec", "nodev"]
      }]
    | .annotations["dev.a3s.oci.cgroup-ownership"] = "preserve-readonly-v1"
    | .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
               and . != "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
            then "A3S_HOOK_TRACE=" + $hook_trace
            else .
            end
          )
        )
      )
  ' \
  "$cgroup_ownership_readonly_bundle/config.json" \
  >"$cgroup_ownership_readonly_bundle/config.json.tmp"
mv \
  "$cgroup_ownership_readonly_bundle/config.json.tmp" \
  "$cgroup_ownership_readonly_bundle/config.json"
for candidate in \
  "$bundle" \
  "$bundle_b" \
  "$control_bundle" \
  "$terminal_bundle" \
  "$terminal_existing_bundle" \
  "$device_boundary_bundle" \
  "$cgroup_ownership_bundle" \
  "$cgroup_ownership_readonly_bundle"; do
  jq --exit-status \
    '.linux.uidMappings
         == [{"containerID": 0, "hostID": 100000, "size": 65536}]
     and .linux.gidMappings
         == [{"containerID": 0, "hostID": 200000, "size": 65536}]' \
    "$candidate/config.json" >/dev/null
done
sudo chown -R 100000:200000 "$bundle/rootfs" "$bundle_b/rootfs"
sudo chown -R 100000:200000 "$control_bundle/rootfs"
sudo chown -R 100000:200000 "$terminal_bundle/rootfs"
sudo chown -R 100000:200000 "$terminal_existing_bundle/rootfs"
sudo chown -R 100000:200000 "$device_boundary_bundle/rootfs"
sudo chown -R 100000:200000 "$cgroup_ownership_bundle/rootfs"
sudo chown -R 100000:200000 "$cgroup_ownership_readonly_bundle/rootfs"
sudo chown -R 100000:200000 "$recovery_bundle/rootfs"
sudo chown -R 100000:200000 "$hook_recovery_bundle/rootfs"
for candidate in "${soak_bundles[@]}"; do
  sudo chown -R 100000:200000 "$candidate/rootfs"
  test "$(stat --format '%u:%g' "$candidate/rootfs")" = '100000:200000'
done
sudo touch "$hook_trace"
sudo chown 100000:200000 "$hook_trace"
sudo chmod 0666 "$hook_trace"
sudo touch "$control_hook_trace"
sudo chown 100000:200000 "$control_hook_trace"
sudo chmod 0666 "$control_hook_trace"
sudo touch "$terminal_hook_trace"
sudo chown 100000:200000 "$terminal_hook_trace"
sudo chmod 0666 "$terminal_hook_trace"
sudo touch "$terminal_existing_hook_trace"
sudo chown 100000:200000 "$terminal_existing_hook_trace"
sudo chmod 0666 "$terminal_existing_hook_trace"
sudo touch "$device_boundary_hook_trace"
sudo chown 100000:200000 "$device_boundary_hook_trace"
sudo chmod 0666 "$device_boundary_hook_trace"
sudo touch "$cgroup_ownership_hook_trace"
sudo chown 100000:200000 "$cgroup_ownership_hook_trace"
sudo chmod 0666 "$cgroup_ownership_hook_trace"
sudo touch "$cgroup_ownership_readonly_hook_trace"
sudo chown 100000:200000 "$cgroup_ownership_readonly_hook_trace"
sudo chmod 0666 "$cgroup_ownership_readonly_hook_trace"
sudo chmod 0755 "$qualification_root"
test "$(stat --format '%u:%g' "$bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$bundle_b/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$control_bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$terminal_bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$terminal_existing_bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$device_boundary_bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$recovery_bundle/rootfs")" = '100000:200000'
test "$(stat --format '%u:%g' "$hook_recovery_bundle/rootfs")" = '100000:200000'

# shellcheck disable=SC2016 # Expanded inside the network-device workload.
network_device_command_prefix='test -e /sys/class/net/a3seth0; test "$(/bin/busybox cat /sys/class/net/a3seth0/mtu)" = 1450; network_flags=$(/bin/busybox cat /sys/class/net/a3seth0/flags); test "$((network_flags & 1))" = 1; test "$(/bin/busybox cat /sys/class/net/a3seth0/address)" = 02:00:00:00:00:10; /bin/busybox ip -4 address show dev a3seth0 | /bin/busybox grep -q "inet 192.0.2.10/24"; '
for candidate in \
  "$network_device_bundle" \
  "$network_device_conflict_bundle" \
  "$network_device_rollback_bundle"; do
  mkdir "$candidate"
  cp -a --no-preserve=ownership "$bundle/." "$candidate/"
  candidate_trace="$candidate/rootfs/.a3s-oci-hook-trace"
  jq --arg host_trace "$candidate_trace" '
      .hooks |= with_entries(
        .value |= map(
          .env |= map(
            if startswith("A3S_HOOK_TRACE=")
               and . != "A3S_HOOK_TRACE=/.a3s-oci-hook-trace"
            then "A3S_HOOK_TRACE=" + $host_trace
            else .
            end
          )
        )
      )
    ' "$candidate/config.json" >"$candidate/config.json.tmp"
  mv "$candidate/config.json.tmp" "$candidate/config.json"
  sudo chown -R 100000:200000 "$candidate/rootfs"
  sudo chmod 0666 "$candidate_trace"
done
jq \
  --arg source "$network_device_success_source" \
  --arg command_prefix "$network_device_command_prefix" \
  '
    .linux.netDevices = {($source): {name: "a3seth%d"}}
    | .process.args[2] = ($command_prefix + .process.args[2])
    | .annotations["dev.a3s.oci.net-devices"] = "move-rename-preserve-up-v1"
  ' \
  "$network_device_bundle/config.json" >"$network_device_bundle/config.json.tmp"
mv "$network_device_bundle/config.json.tmp" "$network_device_bundle/config.json"
jq \
  --arg source "$network_device_conflict_source" \
  '
    .linux.netDevices = {($source): {name: "lo"}}
    | .annotations["dev.a3s.oci.net-devices"] = "target-conflict-v1"
  ' \
  "$network_device_conflict_bundle/config.json" \
  >"$network_device_conflict_bundle/config.json.tmp"
mv \
  "$network_device_conflict_bundle/config.json.tmp" \
  "$network_device_conflict_bundle/config.json"
jq \
  --arg first "$network_device_rollback_first" \
  --arg second "$network_device_rollback_second" \
  '
    .linux.netDevices = {
      ($first): {name: "a3seth%d"},
      ($second): {name: "a3seth0"}
    }
    | .annotations["dev.a3s.oci.net-devices"] = "partial-failure-rollback-v1"
  ' \
  "$network_device_rollback_bundle/config.json" \
  >"$network_device_rollback_bundle/config.json.tmp"
mv \
  "$network_device_rollback_bundle/config.json.tmp" \
  "$network_device_rollback_bundle/config.json"

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
rootless_default_filesystem_command='test "$(/bin/busybox stat -f -c %T /proc)" = proc; test ! -e /sys; test "$(/bin/busybox stat -f -c %T /dev/pts)" = devpts; test "$(/bin/busybox stat -f -c %T /dev/shm)" = tmpfs; printf rootless-default-filesystem > /dev/shm/.a3s-oci-default-filesystem; test "$(/bin/busybox cat /dev/shm/.a3s-oci-default-filesystem)" = rootless-default-filesystem; /bin/busybox rm /dev/shm/.a3s-oci-default-filesystem; '
rootless_command='set -eu; test "$(/bin/busybox id -u)" = 0; test "$(/bin/busybox id -g)" = 0; test "$(/bin/busybox cat /proc/self/setgroups)" = deny; test "$(/bin/busybox stat -c "%u:%g" /.a3s-oci-rootless-subordinate)" = 1:1; for spec in null:1:3 zero:1:5 full:1:7 random:1:8 urandom:1:9 tty:5:0; do name=${spec%%:*}; rest=${spec#*:}; major=${rest%%:*}; minor=${rest#*:}; test "$(/bin/busybox stat -c %t:%T /dev/$name)" = "$(printf %x $major):$(printf %x $minor)"; test "$(/bin/busybox stat -c %a /dev/$name)" = 666; done; printf probe > /dev/null; /bin/busybox head -c 1 /dev/zero > /dev/null; test "$(/bin/busybox head -c 1 /dev/full | /bin/busybox wc -c)" = 1; /bin/busybox head -c 1 /dev/random > /dev/null; /bin/busybox head -c 1 /dev/urandom > /dev/null; printf "a3s-oci-rootless-mapping-v1\n" > /.a3s-oci-rootless-smoke; progress=0; while :; do progress=$((progress + 1)); printf "%s\n" "$progress" > /.a3s-oci-rootless-progress.next; /bin/busybox mv /.a3s-oci-rootless-progress.next /.a3s-oci-rootless-progress; /bin/busybox sleep 0.05; done'
jq \
  --arg command "${rootless_default_filesystem_command}${rootless_command}" \
  --arg native_focus "$native_focus" \
  --argjson uid "$rootless_uid" \
  --argjson gid "$rootless_gid" \
  '
    del(.linux.timeOffsets, .linux.sysctl, .hooks)
    | .linux.cgroupsPath = "a3s-oci-rootless-smoke"
    | .linux.resources = {
        memory: {limit: 268435456, reservation: 33554432, swap: 536870912},
        cpu: {shares: 512, quota: 50000, period: 100000},
        pids: {limit: 64}
      }
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
    | if $native_focus == "rootless-device-boundary"
      then del(
        .linux.cgroupsPath,
        .linux.personality,
        .linux.memoryPolicy
      )
      else .
      end
  ' \
  "$rootless_bundle/config.json" >"$rootless_bundle/config.json.tmp"
mv "$rootless_bundle/config.json.tmp" "$rootless_bundle/config.json"
jq --exit-status '(.linux | has("sysctl")) | not' \
  "$rootless_bundle/config.json" >/dev/null
for controller in cpu cpuset memory pids; do
  grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers
done
sudo sh -c \
  'printf "+cpu +cpuset +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control'
sudo mkdir "$rootless_cgroup_parent"
rootless_cgroup_created=true
sudo chown "$rootless_uid:$rootless_gid" "$rootless_cgroup_parent"
sudo sh -c \
  'printf "+cpu +cpuset +memory +pids" > "$1/cgroup.subtree_control"' \
  sh "$rootless_cgroup_parent"
sudo chown "$rootless_uid:$rootless_gid" \
  "$rootless_cgroup_parent/cgroup.procs" \
  "$rootless_cgroup_parent/cgroup.subtree_control"
sudo mkdir "$rootless_cgroup_host_control"
rootless_cgroup_host_control_created=true
test -z "$(sudo cat "$rootless_cgroup_parent/cgroup.procs")"
sudo chown -R "$rootless_uid:$rootless_gid" \
  "$rootless_bin" "$rootless_bundle" "$rootless_work_parent"
sudo install \
  --owner="$rootless_uid" \
  --group="$rootless_gid" \
  --mode=0755 \
  "$native_runtime_binary" \
  "$native_agent_binary" \
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

mkdir "$network_device_rootless_bundle"
cp -a --no-preserve=ownership \
  "$rootless_bundle/." "$network_device_rootless_bundle/"
jq \
  --arg source "$network_device_rootless_source" \
  '
    .linux.namespaces += [{"type": "network"}]
    | .linux.netDevices = {($source): {name: "a3sroot%d"}}
    | .annotations["dev.a3s.oci.net-devices"] = "rootless-rejection-v1"
  ' \
  "$network_device_rootless_bundle/config.json" \
  >"$network_device_rootless_bundle/config.json.tmp"
mv \
  "$network_device_rootless_bundle/config.json.tmp" \
  "$network_device_rootless_bundle/config.json"
sudo chown -R \
  "$rootless_uid:$rootless_gid" "$network_device_rootless_bundle"
sudo chown 300000:400000 \
  "$network_device_rootless_bundle/rootfs/.a3s-oci-rootless-subordinate"

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
    '.schema_version == "a3s.oci.native-linux-smoke.v20"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundle_loaded
     and .control_descriptors_prepared
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process", "file", "filesystem"]
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
     and .init_rlimits_verified
     and .init_oom_score_adj_verified
     and .init_io_priority_verified
     and .init_scheduler_verified
     and .init_personality_verified
     and .init_memory_policy_verified
     and .init_capabilities_verified
     and .init_no_new_privileges_verified
     and .processes_verified
     and .process_io_verified
     and .exec_rlimits_verified
     and .exec_oom_score_adj_verified
     and .exec_io_priority_verified
     and .exec_scheduler_verified
     and .exec_capabilities_verified
     and .exec_no_new_privileges_verified
     and .exec_cpu_affinity_verified
     and .terminal_io_verified
     and .file_transfer_verified
     and .filesystem_operations_verified
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
  local smoke_bundle="${2:-$bundle}"
  local smoke_hook_trace="${3:-$hook_trace}"
  local output
  local status
  sudo truncate --size 0 "$smoke_hook_trace"
  if output="$(sudo "$native_runtime_binary" native-linux-smoke \
      --agent "$native_agent_binary" \
      --bundle "$smoke_bundle" \
      --work-parent "$work_parent")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if ((status != 0)); then
    report_native_failure "$smoke_bundle/rootfs"
    return "$status"
  fi
  verify_single_container_report "$expected_kvm_present" "$output"
}

create_dummy_network_device() {
  local name="$1"
  local mtu="$2"
  local mac="$3"
  local address="${4:-}"

  sudo ip link add name "$name" type dummy
  network_device_sources+=("$name")
  sudo ip link set dev "$name" address "$mac"
  sudo ip link set dev "$name" mtu "$mtu"
  if [[ -n "$address" ]]; then
    sudo ip address add "$address" dev "$name"
  fi
  sudo ip link set dev "$name" down
}

verify_host_network_device() {
  local name="$1"
  local mtu="$2"
  local mac="$3"
  local address="${4:-}"
  local flags

  sudo ip link show dev "$name" >/dev/null
  test "$(cat "/sys/class/net/$name/mtu")" = "$mtu"
  test "$(cat "/sys/class/net/$name/address")" = "$mac"
  flags="$(cat "/sys/class/net/$name/flags")"
  test "$((flags & 1))" = 0
  if [[ -n "$address" ]]; then
    sudo ip -4 address show dev "$name" | grep -Fq "inet $address "
  fi
}

verify_host_network_device_absent() {
  local name="$1"

  if sudo ip link show dev "$name" >/dev/null 2>&1; then
    printf 'Network device %s unexpectedly remained in the host namespace\n' \
      "$name" >&2
    return 1
  fi
}

run_network_device_negative_smoke() {
  local case_name="$1"
  local smoke_bundle="$2"
  local expected_reason="$3"
  local output
  local status

  if output="$(sudo "$native_runtime_binary" native-linux-smoke \
      --agent "$native_agent_binary" \
      --bundle "$smoke_bundle" \
      --work-parent "$work_parent")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if ((status != 2)); then
    report_native_failure "$smoke_bundle/rootfs"
    return 1
  fi
  jq --exit-status \
    --arg reason "$expected_reason" \
    '.schema_version == "a3s.oci.native-linux-smoke.v20"
     and .status != "available"
     and (.reason | contains($reason))
     and ((.reason | contains("rollback also failed")) | not)
     and (.created_pid == null)
     and .executor_runtime_clean
     and .session_root_clean
     and .marker_removed' \
    <<<"$output" >/dev/null
  test ! -e "$smoke_bundle/rootfs/.a3s-oci-native-smoke"
  test -z "$(find "$work_parent" -mindepth 1 -print -quit)"
  printf 'Network-device negative case passed: %s\n' "$case_name"
}

run_service_smoke() {
  local expected_kvm_present="$1"
  local output
  local status
  sudo truncate --size 0 "$hook_trace"
  if output="$(sudo "$native_runtime_binary" native-linux-service-smoke \
      --agent "$native_agent_binary" \
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
  if output="$(sudo "$native_runtime_binary" \
      native-linux-multi-container-smoke \
      --agent "$native_agent_binary" \
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
    --arg absolute "$absolute_cgroup_path" \
    '.schema_version == "a3s.oci.native-linux-multi-container-smoke.v20"
     and .platform == "linux" and .status == "available"
     and .kvm_device_present == $expected
     and .bundles_loaded
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process", "file", "filesystem"]
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
     and .cgroup_paths.requested_relative == "a3s-oci-smoke-a"
     and .cgroup_paths.requested_absolute == $absolute
     and (.cgroup_paths.observed_relative_initial | endswith("/a3s-oci-smoke-a"))
     and .cgroup_paths.observed_relative_recreated
         == .cgroup_paths.observed_relative_initial
     and .cgroup_paths.observed_absolute == $absolute
     and .cgroup_paths.absolute_mountpoint_resolution_verified
     and .cgroup_paths.relative_recreate_resolution_verified
     and .cgroup_paths.distinct_locations
     and .cgroup_paths.paths_removed_after_delete
     and (.namespace_join.donor_pid > 0)
     and .namespace_join.wrong_type_rejected_before_state
     and .namespace_join.joined_non_mount_namespaces
     and .namespace_join.joined_pid_time_workload_verified
     and .namespace_join.joined_user_default_devices_verified
     and .namespace_join.joined_mount_namespace
     and .namespace_join.retained_rootfs_verified
     and .namespace_join.donor_unchanged_after_joins
     and .namespace_join.all_state_removed
     and .network_modes.private_namespace_verified
     and .network_modes.host_namespace_verified
     and .network_modes.shared_namespace_verified
     and .network_modes.all_profiles_removed
     and .rootfs_mount.created_before_start
     and .rootfs_mount.mount_targets_created_before_start
     and .rootfs_mount.evidence_absent_before_start
     and .rootfs_mount.start_released
     and .rootfs_mount.dev_symlinks_verified
     and .rootfs_mount.rootfs_propagation_shared
     and .rootfs_mount.readonly_path_enforced
     and .rootfs_mount.masked_path_enforced
     and .rootfs_mount.recursive_mount_attributes_enforced
     and .rootfs_mount.idmapped_mounts_enforced
     and .rootfs_mount.idmap_source_ownership_unchanged
     and .rootfs_mount.foreign_readonly_bind_enforced
     and .rootfs_mount.idmap_nonrecursive_enforced
     and .rootfs_mount.ridmap_recursive_enforced
     and .rootfs_mount.readonly_rootfs_enforced
     and .rootfs_mount.exact_evidence
     and .rootfs_mount.wait_status
         == {"exit_code": 0, "oom_killed": false}
     and .rootfs_mount.state_removed
     and .rootfs_mount.artifacts_removed
     and .storage_volumes.shared_bind_write_visible
     and .storage_volumes.readonly_bind_enforced
     and .storage_volumes.private_tmpfs_isolated
     and .storage_volumes.bind_data_persisted_after_recreate
     and .storage_volumes.all_profiles_removed
     and .initialization.inline_shell_verified
     and .initialization.executable_script_verified
     and .initialization.direct_argv_verified
     and .initialization.nonzero_exit_verified
     and .initialization.prestart_failure_rolled_back
     and .initialization.create_runtime_failure_rolled_back
     and .initialization.create_container_failure_rolled_back
     and .initialization.start_container_failure_rolled_back
     and .initialization.poststart_failure_rolled_back
     and .initialization.hook_timeout_rolled_back
     and .initialization.hook_timeout_process_group_terminated
     and .initialization.poststop_failure_warning_only
     and .initialization.all_profiles_removed
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

run_soak() {
  local expected_kvm_present="$1"
  local output
  local status
  local arguments=(
    native-linux-soak
    --agent "$native_agent_binary"
    --work-parent "$work_parent"
    --iterations "$soak_iterations"
    --concurrent-containers "$soak_concurrent_containers"
    --operation-timeout-ms "$soak_operation_timeout_ms"
  )
  for candidate in "${soak_bundles[@]}"; do
    arguments+=(--bundle "$candidate")
  done
  if output="$(sudo "$native_runtime_binary" "${arguments[@]}")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if [[ -n "${A3S_OCI_NATIVE_SOAK_REPORT:-}" ]]; then
    mkdir -p "$(dirname "$A3S_OCI_NATIVE_SOAK_REPORT")"
    printf '%s\n' "$output" >"$A3S_OCI_NATIVE_SOAK_REPORT"
  fi
  if ((status != 0)); then
    report_native_failure "${soak_bundles[0]}/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    --argjson iterations "$soak_iterations" \
    --argjson concurrent "$soak_concurrent_containers" \
    --argjson operation_timeout_ms "$soak_operation_timeout_ms" \
    '($iterations * $concurrent) as $lifecycles
     | (($iterations - 1) * $concurrent) as $stale
     | .schema_version == "a3s.oci.native-linux-soak.v1"
     and .platform == "linux" and .status == "available"
     and .configuration.iterations == $iterations
     and .configuration.concurrent_containers == $concurrent
     and .configuration.operation_timeout_ms == $operation_timeout_ms
     and .kvm_device_present == $expected
     and .bundles_loaded == $concurrent
     and .distinct_bundles_and_rootfs
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process", "file", "filesystem"]
     and .completed_iterations == $iterations
     and .completed_container_lifecycles == $lifecycles
     and .operation_counts.features == ($iterations + 1)
     and .operation_counts.create == $lifecycles
     and .operation_counts.state >= (($lifecycles * 3) + $stale)
     and .operation_counts.start == $lifecycles
     and .operation_counts.list == ($iterations * 3)
     and .operation_counts.exec == $lifecycles
     and .operation_counts.wait_process == $lifecycles
     and .operation_counts.processes == $lifecycles
     and .operation_counts.stats == $lifecycles
     and .operation_counts.pause == $lifecycles
     and .operation_counts.resume == $lifecycles
     and .operation_counts.kill == $lifecycles
     and .operation_counts.wait == $lifecycles
     and .operation_counts.delete == $lifecycles
     and .operation_counts.read_output >= $lifecycles
     and .max_live_containers == $concurrent
     and .unique_live_pids
     and .generation_sequence_verified
     and .stale_generation_rejections == $stale
     and .exec_output_verified
     and .pause_resume_verified
     and .durable_reopens == $iterations
     and .durable_recovery_verified
     and .runtime_empty_after_each_iteration
     and .executor_empty_after_each_iteration
     and .markers_removed_after_each_iteration
     and (.steady_open_descriptors > 0)
     and .final_open_descriptors == .steady_open_descriptors
     and .descriptor_inventory_stable
     and .final_child_processes == .baseline_child_processes
     and .child_process_inventory_stable
     and .executor_runtime_clean
     and .session_root_clean
     and (.reason == null)' \
    <<<"$output" >/dev/null
  for candidate in "${soak_bundles[@]}"; do
    test ! -e "$candidate/rootfs/.a3s-oci-native-smoke"
  done
  test -z "$(find "$work_parent" -mindepth 1 -print -quit)"
}

run_fault_cleanup() {
  local phase
  local output
  local status
  for phase in after-create after-start after-kill; do
    if output="$(sudo "$native_runtime_binary" native-linux-fault-cleanup \
        --agent "$native_agent_binary" \
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
               "signal-process", "wait-process", "file", "filesystem"]
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
  if output="$(sudo sh -c '
      control=$1
      uid=$2
      gid=$3
      shift 3
      printf 0 > "$control/cgroup.procs"
      exec setpriv \
        --ruid="$uid" --euid=0 \
        --rgid="$gid" --egid=0 \
        --clear-groups -- "$@"
    ' sh \
      "$rootless_cgroup_host_control" \
      "$rootless_uid" \
      "$rootless_gid" \
      "$rootless_bin/a3s-oci" native-linux-rootless-smoke \
      --agent "$rootless_bin/a3s-oci-agent" \
      --bundle "$rootless_bundle" \
      --work-parent "$rootless_work_parent" \
      --delegated-cgroup-root "$rootless_cgroup_parent" \
      --rootless-device-bootstrap)"; then
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
    '.schema_version == "a3s.oci.native-linux-rootless-smoke.v4"
     and .platform == "linux" and .status == "available"
     and .effective_uid == $uid and .effective_gid == $gid
     and .bundle_loaded
     and .mapping_plan_verified
     and .service_operations
         == ["features", "create", "state", "start", "kill", "delete",
             "exec", "wait", "list", "pause", "resume", "update", "processes",
             "stats", "events", "read-output", "write-stdin", "close-stdin", "resize",
             "signal-process", "wait-process", "file", "filesystem"]
     and .create_returned_created
     and .create_replayed
     and (.created_pid > 0)
     and .uid_map_verified
     and .gid_map_verified
     and .setgroups_denied
     and .device_policy_helper_verified
     and .device_nodes_verified
     and (.device_policy_updates_verified | not)
     and .cgroup_delegation_requested
     and .cgroup_delegation_verified
     and .resources_updated
     and .stats_verified
     and .freezer_verified
     and (.progress_before_pause > 0)
     and .progress_while_paused == .progress_before_pause
     and .progress_after_resume > .progress_while_paused
     and .cgroup_delegation_clean
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
  test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-progress"
  test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-progress.next"
  test -z "$(sudo find "$rootless_work_parent" -mindepth 1 -print -quit)"
  test -z "$(sudo cat "$rootless_cgroup_host_control/cgroup.procs")"
  test -z "$(sudo find "$rootless_cgroup_parent" -mindepth 1 -maxdepth 1 \
    -type d ! -name a3s-host-control -print -quit)"
}

run_rootless_device_policy_smoke() {
  local device_bundle="$qualification_root/rootless-device-bundle"
  local output
  local status
  mkdir -p "$device_bundle/rootfs/dev"
  cp -a --no-preserve=ownership \
    "$rootless_bundle/rootfs/." "$device_bundle/rootfs/"
  jq --slurpfile box fixtures/a3s-box/config.json '
      .linux.devices = $box[0].linux.devices
      | .linux.resources.devices = $box[0].linux.resources.devices
      | .process.args[2] =
          "set -eu; "
          + "for spec in null:1:3 zero:1:5 full:1:7 random:1:8 urandom:1:9 tty:5:0; do "
          + "name=${spec%%:*}; rest=${spec#*:}; major=${rest%%:*}; minor=${rest#*:}; "
          + "test \"$(/bin/busybox stat -c %t:%T /dev/$name)\" = \"$(printf %x $major):$(printf %x $minor)\"; "
          + "test \"$(/bin/busybox stat -c %a /dev/$name)\" = 666; done; "
          + "printf probe > /dev/null; /bin/busybox head -c 1 /dev/zero > /dev/null; "
          + "test \"$(/bin/busybox head -c 1 /dev/full | /bin/busybox wc -c)\" = 1; "
          + "/bin/busybox head -c 1 /dev/random > /dev/null; "
          + "/bin/busybox head -c 1 /dev/urandom > /dev/null; "
          + .process.args[2]
    ' "$rootless_bundle/config.json" > "$device_bundle/config.json"
  sudo chown -R "$rootless_uid:$rootless_gid" "$device_bundle"
  sudo chown 300000:400000 \
    "$device_bundle/rootfs/.a3s-oci-rootless-subordinate"

  if output="$(sudo sh -c '
      control=$1
      uid=$2
      gid=$3
      shift 3
      printf 0 > "$control/cgroup.procs"
      exec setpriv \
        --ruid="$uid" --euid=0 \
        --rgid="$gid" --egid=0 \
        --clear-groups -- "$@"
    ' sh \
      "$rootless_cgroup_host_control" \
      "$rootless_uid" \
      "$rootless_gid" \
      "$rootless_bin/a3s-oci" native-linux-rootless-device-policy-smoke \
      --agent "$rootless_bin/a3s-oci-agent" \
      --bundle "$device_bundle" \
      --work-parent "$rootless_work_parent" \
      --delegated-cgroup-root "$rootless_cgroup_parent")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if [[ -n "${A3S_OCI_NATIVE_ROOTLESS_DEVICE_POLICY_REPORT:-}" ]]; then
    mkdir -p "$(dirname "$A3S_OCI_NATIVE_ROOTLESS_DEVICE_POLICY_REPORT")"
    printf '%s\n' "$output" >"$A3S_OCI_NATIVE_ROOTLESS_DEVICE_POLICY_REPORT"
  fi
  if ((status != 0)); then
    report_native_failure "$device_bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson uid "$rootless_uid" \
    --argjson gid "$rootless_gid" \
    '.schema_version == "a3s.oci.native-linux-rootless-smoke.v4"
     and .platform == "linux" and .status == "available"
     and .effective_uid == $uid and .effective_gid == $gid
     and .device_policy_helper_verified
     and .device_nodes_verified
     and .device_policy_updates_verified
     and .cgroup_delegation_clean
     and .executor_runtime_clean
     and .session_root_clean
     and (.reason == null)' <<<"$output" >/dev/null
  test -z "$(sudo find "$rootless_work_parent" -mindepth 1 -print -quit)"
  test -z "$(sudo cat "$rootless_cgroup_host_control/cgroup.procs")"
  test -z "$(sudo find "$rootless_cgroup_parent" -mindepth 1 -maxdepth 1 \
    -type d ! -name a3s-host-control -print -quit)"
  sudo rm -rf --one-file-system -- "$device_bundle"
}

run_rootless_negative_smoke() {
  local case_name="$1"
  local delegated_root="$2"
  local expected_reason="$3"
  local smoke_bundle="${4:-$rootless_bundle}"
  local output
  local status
  local before_work
  local after_work
  local before_cgroup
  local after_cgroup
  local before_rootfs
  local after_rootfs
  local -a command=(
    "$rootless_bin/a3s-oci" native-linux-rootless-smoke
    --agent "$rootless_bin/a3s-oci-agent"
    --bundle "$smoke_bundle"
    --work-parent "$rootless_work_parent"
  )

  if [[ -n "$delegated_root" ]]; then
    command+=(--delegated-cgroup-root "$delegated_root")
  fi

  before_work="$(sudo find "$rootless_work_parent" -mindepth 1 -printf '%P\n' | sort)"
  before_cgroup="$(sudo find "$rootless_cgroup_parent" -mindepth 1 -printf '%P\n' | sort)"
  before_rootfs="$(
    sudo find "$smoke_bundle/rootfs" -xdev \
      -printf '%P|%y|%m|%U|%G|%s|%T@|%l\n' | sort
    sudo find "$smoke_bundle/rootfs" -xdev -type f \
      -exec sha256sum {} + | sort
  )"
  if output="$(sudo sh -c '
      control=$1
      uid=$2
      gid=$3
      shift 3
      printf 0 > "$control/cgroup.procs"
      exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$@"
    ' sh \
      "$rootless_cgroup_host_control" \
      "$rootless_uid" \
      "$rootless_gid" \
      "${command[@]}")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  test "$status" -eq 2
  jq --exit-status \
    --arg reason "$expected_reason" \
    '.schema_version == "a3s.oci.native-linux-rootless-smoke.v4"
     and .status != "available"
     and (.reason | contains($reason))
     and (.created_pid == null)' \
    <<<"$output" >/dev/null
  after_work="$(sudo find "$rootless_work_parent" -mindepth 1 -printf '%P\n' | sort)"
  after_cgroup="$(sudo find "$rootless_cgroup_parent" -mindepth 1 -printf '%P\n' | sort)"
  after_rootfs="$(
    sudo find "$smoke_bundle/rootfs" -xdev \
      -printf '%P|%y|%m|%U|%G|%s|%T@|%l\n' | sort
    sudo find "$smoke_bundle/rootfs" -xdev -type f \
      -exec sha256sum {} + | sort
  )"
  test "$after_work" = "$before_work"
  test "$after_cgroup" = "$before_cgroup"
  test "$after_rootfs" = "$before_rootfs"
  test ! -e "$smoke_bundle/rootfs/.a3s-oci-rootless-smoke"
  test ! -e "$smoke_bundle/rootfs/.a3s-oci-rootless-progress"
  test ! -e "$smoke_bundle/rootfs/.a3s-oci-rootless-progress.next"
  printf 'Rootless negative case passed: %s\n' "$case_name"
}

run_rootless_post_open_negative_smoke() {
  local case_name="$1"
  local mutation="$2"
  local expected_reason="$3"
  local barrier_root="$qualification_root/rootless-post-open-$case_name"
  local ready_file="$barrier_root/ready"
  local continue_file="$barrier_root/continue"
  local output_file="$barrier_root/output"
  local command_pid
  local output
  local status
  local ready_observed=false
  local before_work
  local after_work
  local before_cgroup
  local after_cgroup
  local before_rootfs
  local after_rootfs

  sudo mkdir "$barrier_root"
  sudo touch "$output_file"
  sudo chown "$(id -u):$(id -g)" "$output_file"
  sudo chown "$rootless_uid:$rootless_gid" "$barrier_root"
  before_work="$(sudo find "$rootless_work_parent" -mindepth 1 -printf '%P\n' | sort)"
  before_cgroup="$(sudo find "$rootless_cgroup_parent" -mindepth 1 -printf '%P\n' | sort)"
  before_rootfs="$(
    sudo find "$rootless_bundle/rootfs" -xdev \
      -printf '%P|%y|%m|%U|%G|%s|%T@|%l\n' | sort
    sudo find "$rootless_bundle/rootfs" -xdev -type f \
      -exec sha256sum {} + | sort
  )"

  sudo sh -c '
    control=$1
    uid=$2
    gid=$3
    shift 3
    printf 0 > "$control/cgroup.procs"
    exec setpriv \
      --ruid="$uid" --euid=0 \
      --rgid="$gid" --egid=0 \
      --clear-groups -- "$@"
  ' sh \
    "$rootless_cgroup_host_control" \
    "$rootless_uid" \
    "$rootless_gid" \
    "$rootless_bin/a3s-oci" native-linux-rootless-smoke \
    --agent "$rootless_bin/a3s-oci-agent" \
    --bundle "$rootless_bundle" \
    --work-parent "$rootless_work_parent" \
    --delegated-cgroup-root "$rootless_cgroup_parent" \
    --rootless-device-bootstrap \
    --post-open-ready-file "$ready_file" \
    --post-open-continue-file "$continue_file" \
    >"$output_file" 2>&1 &
  command_pid=$!

  for _ in $(seq 1 300); do
    if sudo test -f "$ready_file"; then
      ready_observed=true
      break
    fi
    if ! kill -0 "$command_pid" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if [[ "$ready_observed" != true ]]; then
    kill "$command_pid" 2>/dev/null || true
    wait "$command_pid" 2>/dev/null || true
    sudo cat "$output_file" || true
    sudo rm -rf --one-file-system "$barrier_root"
    printf 'Rootless post-open case did not reach readiness: %s\n' "$case_name" >&2
    return 1
  fi

  case "$mutation" in
    inode-drift)
      sudo mkdir "$rootless_cgroup_replacement"
      rootless_cgroup_replacement_created=true
      sudo chown "$rootless_uid:$rootless_gid" "$rootless_cgroup_replacement"
      sudo sh -c \
        'printf "+cpu +cpuset +memory +pids" > "$1/cgroup.subtree_control"' \
        sh "$rootless_cgroup_replacement"
      sudo chown "$rootless_uid:$rootless_gid" \
        "$rootless_cgroup_replacement/cgroup.procs" \
        "$rootless_cgroup_replacement/cgroup.subtree_control"
      sudo mount --bind "$rootless_cgroup_replacement" "$rootless_cgroup_parent"
      rootless_cgroup_bind_mounted=true
      ;;
    controller-drift)
      sudo sh -c \
        'printf -- "-pids" > "$1/cgroup.subtree_control"' \
        sh "$rootless_cgroup_parent"
      ;;
    *)
      printf 'Unknown rootless post-open mutation: %s\n' "$mutation" >&2
      return 2
      ;;
  esac
  sudo -u "$rootless_user" touch "$continue_file"
  if wait "$command_pid"; then
    status=0
  else
    status=$?
  fi
  output="$(sudo cat "$output_file")"
  printf '%s\n' "$output"

  if [[ "$rootless_cgroup_bind_mounted" == true ]]; then
    sudo umount "$rootless_cgroup_parent"
    rootless_cgroup_bind_mounted=false
  fi
  if [[ "$rootless_cgroup_replacement_created" == true ]]; then
    sudo rmdir "$rootless_cgroup_replacement"
    rootless_cgroup_replacement_created=false
  fi
  if [[ "$mutation" == controller-drift ]]; then
    sudo sh -c \
      'printf "+pids" > "$1/cgroup.subtree_control"' \
      sh "$rootless_cgroup_parent"
  fi
  sudo rm -rf --one-file-system "$barrier_root"

  test "$status" -eq 2
  jq --exit-status \
    --arg reason "$expected_reason" \
    '.schema_version == "a3s.oci.native-linux-rootless-smoke.v4"
     and .status != "available"
     and (.reason | contains($reason))
     and (.created_pid == null)' \
    <<<"$output" >/dev/null
  after_work="$(sudo find "$rootless_work_parent" -mindepth 1 -printf '%P\n' | sort)"
  after_cgroup="$(sudo find "$rootless_cgroup_parent" -mindepth 1 -printf '%P\n' | sort)"
  after_rootfs="$(
    sudo find "$rootless_bundle/rootfs" -xdev \
      -printf '%P|%y|%m|%U|%G|%s|%T@|%l\n' | sort
    sudo find "$rootless_bundle/rootfs" -xdev -type f \
      -exec sha256sum {} + | sort
  )"
  test "$after_work" = "$before_work"
  test "$after_cgroup" = "$before_cgroup"
  test "$after_rootfs" = "$before_rootfs"
  test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-smoke"
  test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-progress"
  test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-progress.next"
  printf 'Rootless post-open negative case passed: %s\n' "$case_name"
}

run_owner_death_recovery() {
  local recovery_root="$qualification_root/native-owner-recovery"
  local ready_file="$qualification_root/native-owner-recovery-ready.json"
  local owner_log="$qualification_root/native-owner-recovery-owner.log"
  local output
  local status
  local generation
  local ready_json
  local ready_owner_pid
  local init_pid
  local deadline

  sudo rm -f "$recovery_bundle/rootfs/.a3s-oci-native-smoke"
  sudo "$native_runtime_binary" native-linux-recovery-owner \
    --agent "$native_agent_binary" \
    --root "$recovery_root" \
    --bundle "$recovery_bundle" \
    --container-id native-owner-recovery \
    --ready-file "$ready_file" >"$owner_log" 2>&1 &
  recovery_owner_pid=$!

  deadline=$((SECONDS + 30))
  while [[ ! -f "$ready_file" ]]; do
    if ! kill -0 "$recovery_owner_pid" 2>/dev/null; then
      wait "$recovery_owner_pid" || true
      cat "$owner_log" >&2
      printf '%s\n' 'Native recovery owner exited before readiness' >&2
      return 1
    fi
    if ((SECONDS >= deadline)); then
      cat "$owner_log" >&2
      printf '%s\n' 'Timed out waiting for native recovery owner readiness' >&2
      return 1
    fi
    sleep 0.025
  done

  test "$(sudo stat --format '%u:%g:%a' "$ready_file")" = '0:0:600'
  ready_json="$(sudo cat -- "$ready_file")"
  jq --exit-status \
    '.schema_version == "a3s.oci.native-linux-recovery-owner-ready.v3"
     and .status == "available" and .platform == "linux"
     and .target.id == "native-owner-recovery"
     and .target.generation == 1
     and .recovery_point == "running"
     and (.owner_pid > 0) and (.owner_start_time_ticks > 0)
     and (.init_pid > 0)
     and .effective_uid == 0 and .effective_gid == 0
     and (.cgroup_delegation_requested | not)
     and (.cgroup_delegation_verified | not)
     and .running_observed' \
    <<<"$ready_json" >/dev/null
  ready_owner_pid="$(jq --raw-output '.owner_pid' <<<"$ready_json")"
  recovery_runtime_owner_pid="$ready_owner_pid"
  init_pid="$(jq --raw-output '.init_pid' <<<"$ready_json")"
  generation="$(jq --raw-output '.target.generation' <<<"$ready_json")"
  sudo test -e "/proc/$init_pid/stat"
  # sudo may either exec the command directly or retain a monitor process.
  # The authenticated readiness record identifies the actual runtime owner;
  # the shell PID remains useful only for reaping the background sudo job.
  sudo kill -KILL "$ready_owner_pid"
  set +e
  wait "$recovery_owner_pid"
  status=$?
  set -e
  recovery_owner_pid=""
  recovery_runtime_owner_pid=""
  if ((status == 0)); then
    cat "$owner_log" >&2
    printf '%s\n' 'Native recovery owner unexpectedly exited cleanly after SIGKILL' >&2
    return 1
  fi
  sudo grep --fixed-strings --line-regexp \
    'a3s-oci-native-box-mapping-v1' \
    "$recovery_bundle/rootfs/.a3s-oci-native-smoke" >/dev/null

  if output="$(sudo "$native_runtime_binary" \
      native-linux-recovery-resume \
      --agent "$native_agent_binary" \
      --root "$recovery_root" \
      --bundle "$recovery_bundle" \
      --container-id native-owner-recovery \
      --generation "$generation")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if [[ -n "${A3S_OCI_NATIVE_RECOVERY_REPORT:-}" ]]; then
    mkdir -p "$(dirname "$A3S_OCI_NATIVE_RECOVERY_REPORT")"
    printf '%s\n' "$output" >"$A3S_OCI_NATIVE_RECOVERY_REPORT"
  fi
  if ((status != 0)); then
    cat "$owner_log" >&2
    report_native_failure "$recovery_bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson killed_owner "$ready_owner_pid" \
    '.schema_version == "a3s.oci.native-linux-recovery-smoke.v2"
     and .status == "available" and .platform == "linux"
     and .target.id == "native-owner-recovery"
     and .target.generation == 1
     and .replacement_owner_pid != $killed_owner
     and .replacement_effective_uid == 0
     and .replacement_effective_gid == 0
     and (.cgroup_delegation_requested | not)
     and (.cgroup_delegation_verified | not)
     and .bundle_loaded
     and .host_service_reopened
     and .recorded_workload_terminated
     and .stopped_observed
     and .process_inventory_empty
     and .kill_idempotent
     and .exact_wait_evidence_refused
     and .stopped_delete_succeeded
     and .durable_record_removed
     and .current_driver_shutdown
     and .executor_transients_clean
     and .cgroup_delegation_clean
     and (.reason == null)' \
    <<<"$output" >/dev/null
  sudo test ! -e "/proc/$init_pid/stat"
  sudo rm -f "$recovery_bundle/rootfs/.a3s-oci-native-smoke"
  sudo test ! -e "$recovery_bundle/rootfs/.a3s-oci-native-smoke"
  test -z "$(sudo find "$recovery_root/executor" -mindepth 1 -print -quit)"
}

run_rootless_owner_death_recovery() {
  local recovery_root="$rootless_work_parent/native-owner-recovery"
  local ready_file="$rootless_work_parent/native-owner-recovery-ready.json"
  local owner_log="$qualification_root/rootless-owner-recovery-owner.log"
  local output
  local status
  local generation
  local ready_json
  local ready_owner_pid
  local init_pid
  local deadline

  sudo rm -f \
    "$rootless_bundle/rootfs/.a3s-oci-rootless-smoke" \
    "$rootless_bundle/rootfs/.a3s-oci-rootless-progress" \
    "$rootless_bundle/rootfs/.a3s-oci-rootless-progress.next"
  sudo sh -c '
      control=$1
      uid=$2
      gid=$3
      shift 3
      printf 0 > "$control/cgroup.procs"
      exec setpriv \
        --ruid="$uid" --euid=0 \
        --rgid="$gid" --egid=0 \
        --clear-groups -- "$@"
    ' sh \
      "$rootless_cgroup_host_control" \
      "$rootless_uid" \
      "$rootless_gid" \
      "$rootless_bin/a3s-oci" native-linux-recovery-owner \
      --agent "$rootless_bin/a3s-oci-agent" \
      --root "$recovery_root" \
      --bundle "$rootless_bundle" \
      --container-id native-rootless-owner-recovery \
      --ready-file "$ready_file" \
      --delegated-cgroup-root "$rootless_cgroup_parent" \
      --rootless-device-bootstrap \
      >"$owner_log" 2>&1 &
  recovery_owner_pid=$!

  deadline=$((SECONDS + 30))
  while ! sudo test -f "$ready_file"; do
    if ! kill -0 "$recovery_owner_pid" 2>/dev/null; then
      wait "$recovery_owner_pid" || true
      cat "$owner_log" >&2
      printf '%s\n' 'Rootless recovery owner exited before readiness' >&2
      return 1
    fi
    if ((SECONDS >= deadline)); then
      cat "$owner_log" >&2
      printf '%s\n' 'Timed out waiting for rootless recovery readiness' >&2
      return 1
    fi
    sleep 0.025
  done

  test "$(sudo stat --format '%u:%g:%a' "$ready_file")" \
    = "$rootless_uid:$rootless_gid:600"
  ready_json="$(sudo cat -- "$ready_file")"
  jq --exit-status \
    --argjson uid "$rootless_uid" \
    --argjson gid "$rootless_gid" \
    '.schema_version == "a3s.oci.native-linux-recovery-owner-ready.v3"
     and .status == "available" and .platform == "linux"
     and .target.id == "native-rootless-owner-recovery"
     and .target.generation == 1
     and .recovery_point == "running"
     and (.owner_pid > 0) and (.owner_start_time_ticks > 0)
     and (.init_pid > 0)
     and .effective_uid == $uid and .effective_gid == $gid
     and .cgroup_delegation_requested
     and .cgroup_delegation_verified
     and .running_observed' \
    <<<"$ready_json" >/dev/null
  ready_owner_pid="$(jq --raw-output '.owner_pid' <<<"$ready_json")"
  recovery_runtime_owner_pid="$ready_owner_pid"
  init_pid="$(jq --raw-output '.init_pid' <<<"$ready_json")"
  generation="$(jq --raw-output '.target.generation' <<<"$ready_json")"
  sudo test -e "/proc/$init_pid/stat"

  deadline=$((SECONDS + 10))
  while ! sudo grep --fixed-strings --line-regexp \
      'a3s-oci-rootless-mapping-v1' \
      "$rootless_bundle/rootfs/.a3s-oci-rootless-smoke" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      cat "$owner_log" >&2
      printf '%s\n' 'Rootless recovery workload did not publish its marker' >&2
      return 1
    fi
    sleep 0.025
  done

  sudo kill -KILL "$ready_owner_pid"
  set +e
  wait "$recovery_owner_pid"
  status=$?
  set -e
  recovery_owner_pid=""
  recovery_runtime_owner_pid=""
  if ((status == 0)); then
    cat "$owner_log" >&2
    printf '%s\n' \
      'Rootless recovery owner unexpectedly exited cleanly after SIGKILL' >&2
    return 1
  fi

  if output="$(sudo sh -c '
      control=$1
      uid=$2
      gid=$3
      shift 3
      printf 0 > "$control/cgroup.procs"
      exec setpriv \
        --ruid="$uid" --euid=0 \
        --rgid="$gid" --egid=0 \
        --clear-groups -- "$@"
    ' sh \
      "$rootless_cgroup_host_control" \
      "$rootless_uid" \
      "$rootless_gid" \
      "$rootless_bin/a3s-oci" native-linux-recovery-resume \
      --agent "$rootless_bin/a3s-oci-agent" \
      --root "$recovery_root" \
      --bundle "$rootless_bundle" \
      --container-id native-rootless-owner-recovery \
      --generation "$generation" \
      --delegated-cgroup-root "$rootless_cgroup_parent" \
      --rootless-device-bootstrap)"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if [[ -n "${A3S_OCI_NATIVE_ROOTLESS_RECOVERY_REPORT:-}" ]]; then
    mkdir -p "$(dirname "$A3S_OCI_NATIVE_ROOTLESS_RECOVERY_REPORT")"
    printf '%s\n' "$output" >"$A3S_OCI_NATIVE_ROOTLESS_RECOVERY_REPORT"
  fi
  if ((status != 0)); then
    cat "$owner_log" >&2
    report_native_failure "$rootless_bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson killed_owner "$ready_owner_pid" \
    --argjson uid "$rootless_uid" \
    --argjson gid "$rootless_gid" \
    '.schema_version == "a3s.oci.native-linux-recovery-smoke.v2"
     and .status == "available" and .platform == "linux"
     and .target.id == "native-rootless-owner-recovery"
     and .target.generation == 1
     and .replacement_owner_pid != $killed_owner
     and .replacement_effective_uid == $uid
     and .replacement_effective_gid == $gid
     and .cgroup_delegation_requested
     and .cgroup_delegation_verified
     and .bundle_loaded
     and .host_service_reopened
     and .recorded_workload_terminated
     and .stopped_observed
     and .process_inventory_empty
     and .kill_idempotent
     and .exact_wait_evidence_refused
     and .stopped_delete_succeeded
     and .durable_record_removed
     and .current_driver_shutdown
     and .executor_transients_clean
     and .cgroup_delegation_clean
     and (.reason == null)' \
    <<<"$output" >/dev/null
  sudo test ! -e "/proc/$init_pid/stat"
  sudo test -z "$(sudo cat "$rootless_cgroup_host_control/cgroup.procs")"
  test -z "$(sudo find "$rootless_cgroup_parent" -mindepth 1 -maxdepth 1 \
    -type d ! -name a3s-host-control -print -quit)"
  sudo test -z "$(sudo find "$recovery_root/executor" -mindepth 1 -print -quit)"
  sudo rm -f \
    "$rootless_bundle/rootfs/.a3s-oci-rootless-smoke" \
    "$rootless_bundle/rootfs/.a3s-oci-rootless-progress" \
    "$rootless_bundle/rootfs/.a3s-oci-rootless-progress.next"
  sudo test ! -e "$rootless_bundle/rootfs/.a3s-oci-rootless-smoke"
  sudo -u "$rootless_user" rm -f -- "$ready_file"
  sudo -u "$rootless_user" rm -rf --one-file-system -- "$recovery_root"
  sudo test ! -e "$ready_file"
  sudo test ! -e "$recovery_root"
  test -z "$(sudo find "$rootless_work_parent" -mindepth 1 -print -quit)"
}

run_service_signal_cleanup() {
  # Match the root-owned A3S Box profile qualified by the transported lifecycle.
  sudo python3 - \
    "$native_runtime_binary" \
    "$native_agent_binary" \
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
if [[ -n "${A3S_OCI_NATIVE_KVM_ABSENCE_EVIDENCE:-}" ]]; then
  if [[ -e /dev/kvm || -L /dev/kvm ]]; then
    printf '%s\n' 'Native lifecycle KVM-absence boundary was not established' >&2
    exit 1
  fi
  kvm_evidence="$A3S_OCI_NATIVE_KVM_ABSENCE_EVIDENCE"
  if [[ -e "$kvm_evidence" || -L "$kvm_evidence" ]]; then
    printf 'Refusing to replace Native KVM-absence evidence: %s\n' \
      "$kvm_evidence" >&2
    exit 2
  fi
  mkdir -p "$(dirname "$kvm_evidence")"
  jq --null-input \
    --arg schema_version 'a3s.oci.native-linux-kvm-absence.v1' \
    --arg platform 'linux' \
    --arg architecture "$(uname -m)" \
    --argjson device_was_hidden "$kvm_original_moved" \
    '{
      schema_version: $schema_version,
      platform: $platform,
      architecture: $architecture,
      device_was_hidden: $device_was_hidden,
      device_absent_before_lifecycle: true
    }' >"$kvm_evidence.tmp"
  chmod 0644 "$kvm_evidence.tmp"
  mv "$kvm_evidence.tmp" "$kvm_evidence"
fi

if [[ "$native_focus" == terminal-init ]]; then
  run_smoke false "$terminal_bundle" "$terminal_hook_trace"
  test ! -e "$terminal_bundle/rootfs/dev/console"
  test ! -e "$terminal_bundle/rootfs/run/a3s/device-fifo"
  run_smoke false "$terminal_existing_bundle" "$terminal_existing_hook_trace"
  test -f "$terminal_existing_bundle/rootfs/dev/console"
  test "$(cat "$terminal_existing_bundle/rootfs/dev/console")" = \
    'a3s-preexisting-console-v1'
  test ! -e "$terminal_existing_bundle/rootfs/run/a3s/device-fifo"
  exit 0
elif [[ "$native_focus" == device-boundary ]]; then
  run_smoke false "$device_boundary_bundle" "$device_boundary_hook_trace"
  test ! -e "$device_boundary_bundle/rootfs/declared-null"
  test ! -e "$device_boundary_bundle/rootfs/undeclared-device"
  test ! -e "$device_boundary_bundle/rootfs/late-device-error"
  exit 0
elif [[ "$native_focus" == cgroup-ownership ]]; then
  run_smoke false "$cgroup_ownership_bundle" "$cgroup_ownership_hook_trace"
  run_smoke \
    false \
    "$cgroup_ownership_readonly_bundle" \
    "$cgroup_ownership_readonly_hook_trace"
  exit 0
elif [[ "$native_focus" == control-workload ]]; then
  run_smoke false "$control_bundle" "$control_hook_trace"
  exit 0
elif [[ "$native_focus" == multi-container ]]; then
  run_multi_container_smoke false
  exit 0
elif [[ "$native_focus" == owner-death ]]; then
  run_owner_death_recovery
  exit 0
elif [[ "$native_focus" == hook-owner-death ]]; then
  run_hook_owner_death_recovery
  exit 0
elif [[ "$native_focus" == rootless-device-boundary ]]; then
  run_rootless_smoke
  run_rootless_device_policy_smoke
  exit 0
elif [[ -n "$native_focus" ]]; then
  printf 'unsupported A3S_OCI_NATIVE_FOCUS value: %s\n' "$native_focus" >&2
  exit 2
fi

create_dummy_network_device \
  "$network_device_rootless_source" 1500 02:00:00:00:00:30
run_rootless_negative_smoke \
  network-device-authority \
  "$rootless_cgroup_parent" \
  "rootless linux.netDevices requires network-device authority" \
  "$network_device_rootless_bundle"
verify_host_network_device \
  "$network_device_rootless_source" 1500 02:00:00:00:00:30
sudo ip link delete dev "$network_device_rootless_source"

run_rootless_negative_smoke \
  missing-delegation \
  "" \
  "requires --delegated-cgroup-root"

run_rootless_negative_smoke \
  noncanonical-delegation \
  "$rootless_cgroup_parent/." \
  "must already be canonical"

sudo chown root:root "$rootless_cgroup_parent"
run_rootless_negative_smoke \
  wrong-delegation-owner \
  "$rootless_cgroup_parent" \
  "must be a real directory owned by"
sudo chown "$rootless_uid:$rootless_gid" "$rootless_cgroup_parent"

sudo sh -c \
  'printf -- "-pids" > "$1/cgroup.subtree_control"' \
  sh "$rootless_cgroup_parent"
run_rootless_negative_smoke \
  disabled-delegated-controller \
  "$rootless_cgroup_parent" \
  "has not enabled required controller"
sudo sh -c \
  'printf "+pids" > "$1/cgroup.subtree_control"' \
  sh "$rootless_cgroup_parent"

sudo sh -c \
  'printf -- "-cpu -cpuset -memory -pids" > "$1/cgroup.subtree_control"' \
  sh "$rootless_cgroup_parent"
sudo sh -c \
  'printf 0 > "$1/cgroup.procs"; exec sleep 300' \
  sh "$rootless_cgroup_parent" &
rootless_cgroup_process_launcher_pid=$!
for _ in $(seq 1 100); do
  rootless_cgroup_process_pid="$(
    sudo sed -n '1p' "$rootless_cgroup_parent/cgroup.procs"
  )"
  if [[ -n "$rootless_cgroup_process_pid" ]]; then
    break
  fi
  sleep 0.01
done
test -n "$rootless_cgroup_process_pid"
run_rootless_negative_smoke \
  populated-delegation \
  "$rootless_cgroup_parent" \
  "must not contain processes"
if [[ -e "$rootless_cgroup_parent/cgroup.kill" ]]; then
  sudo sh -c 'printf 1 > "$1/cgroup.kill"' sh "$rootless_cgroup_parent"
else
  while IFS= read -r pid; do
    [[ -z "$pid" ]] || sudo kill -KILL "$pid" 2>/dev/null || true
  done < <(sudo cat "$rootless_cgroup_parent/cgroup.procs")
fi
wait "$rootless_cgroup_process_launcher_pid" 2>/dev/null || true
rootless_cgroup_process_pid=""
rootless_cgroup_process_launcher_pid=""
for _ in $(seq 1 100); do
  if [[ -z "$(sudo cat "$rootless_cgroup_parent/cgroup.procs")" ]]; then
    break
  fi
  sleep 0.01
done
test -z "$(sudo cat "$rootless_cgroup_parent/cgroup.procs")"
sudo sh -c \
  'printf "+cpu +cpuset +memory +pids" > "$1/cgroup.subtree_control"' \
  sh "$rootless_cgroup_parent"

run_rootless_post_open_negative_smoke \
  inode-drift \
  inode-drift \
  "changed after executor open"

run_rootless_post_open_negative_smoke \
  controller-drift \
  controller-drift \
  "has not enabled required controller"

run_rootless_owner_death_recovery
run_rootless_smoke
run_rootless_device_policy_smoke
create_dummy_network_device \
  "$network_device_conflict_source" 1500 02:00:00:00:00:20
run_network_device_negative_smoke \
  target-conflict \
  "$network_device_conflict_bundle" \
  "already exists in the container network namespace"
verify_host_network_device \
  "$network_device_conflict_source" 1500 02:00:00:00:00:20
sudo ip link delete dev "$network_device_conflict_source"

create_dummy_network_device \
  "$network_device_rollback_first" 1450 02:00:00:00:00:11 192.0.2.11/24
create_dummy_network_device \
  "$network_device_rollback_second" 1500 02:00:00:00:00:12
run_network_device_negative_smoke \
  partial-failure-rollback \
  "$network_device_rollback_bundle" \
  "apply route netlink network-device request"
verify_host_network_device \
  "$network_device_rollback_first" 1450 02:00:00:00:00:11 192.0.2.11/24
verify_host_network_device \
  "$network_device_rollback_second" 1500 02:00:00:00:00:12
sudo ip link delete dev "$network_device_rollback_first"
sudo ip link delete dev "$network_device_rollback_second"

create_dummy_network_device \
  "$network_device_success_source" 1450 02:00:00:00:00:10 192.0.2.10/24
run_smoke \
  false \
  "$network_device_bundle" \
  "$network_device_bundle/rootfs/.a3s-oci-hook-trace"
verify_host_network_device_absent "$network_device_success_source"

run_smoke false
run_smoke false "$device_boundary_bundle" "$device_boundary_hook_trace"
run_smoke false "$cgroup_ownership_bundle" "$cgroup_ownership_hook_trace"
run_smoke \
  false \
  "$cgroup_ownership_readonly_bundle" \
  "$cgroup_ownership_readonly_hook_trace"
run_smoke false "$terminal_bundle" "$terminal_hook_trace"
test ! -e "$terminal_bundle/rootfs/dev/console"
test ! -e "$terminal_bundle/rootfs/run/a3s/device-fifo"
run_smoke false "$terminal_existing_bundle" "$terminal_existing_hook_trace"
test -f "$terminal_existing_bundle/rootfs/dev/console"
test "$(cat "$terminal_existing_bundle/rootfs/dev/console")" = \
  'a3s-preexisting-console-v1'
test ! -e "$terminal_existing_bundle/rootfs/run/a3s/device-fifo"
run_smoke false "$control_bundle" "$control_hook_trace"
run_service_smoke false
run_service_signal_cleanup
run_owner_death_recovery
run_hook_owner_death_recovery
run_multi_container_smoke false
run_soak false
run_fault_cleanup
sudo mkdir /dev/kvm
kvm_test_directory_created=true
run_smoke true
run_multi_container_smoke true
