# Native Linux Hook owner-death qualification helpers.

read_linux_process_identity() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys

pid = int(sys.argv[1])
encoded = pathlib.Path(f"/proc/{pid}/stat").read_text()
closing = encoded.rfind(") ")
if closing < 0:
    raise RuntimeError(f"malformed process stat for PID {pid}")
reported_pid = int(encoded[:encoded.find(" (")])
fields = encoded[closing + 2:].split()
if reported_pid != pid or len(fields) <= 19 or fields[0] in {"Z", "X", "x"}:
    raise RuntimeError(f"process PID {pid} was not live at evidence capture")
print(json.dumps({
    "pid": pid,
    "process_group_id": int(fields[2]),
    "start_time_ticks": int(fields[19]),
}, separators=(",", ":")))
PY
}

read_hook_process_group() {
  python3 - "$1" <<'PY'
import json
import pathlib
import sys

init_pid = int(sys.argv[1])
processes = {}
for entry in pathlib.Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        encoded = (entry / "stat").read_text()
        opening = encoded.find(" (")
        closing = encoded.rfind(") ")
        pid = int(encoded[:opening])
        fields = encoded[closing + 2:].split()
        if fields[0] in {"Z", "X", "x"}:
            continue
        processes[pid] = {
            "pid": pid,
            "parent_pid": int(fields[1]),
            "process_group_id": int(fields[2]),
            "start_time_ticks": int(fields[19]),
        }
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        continue

def descends_from(pid, ancestor):
    seen = set()
    while pid > 0 and pid not in seen:
        if pid == ancestor:
            return True
        seen.add(pid)
        process = processes.get(pid)
        if process is None:
            return False
        pid = process["parent_pid"]
    return False

candidates = []
for process in processes.values():
    pid = process["pid"]
    if pid == init_pid or process["process_group_id"] != pid:
        continue
    if not descends_from(pid, init_pid):
        continue
    descendants = [
        candidate for candidate in processes.values()
        if candidate["pid"] != pid
        and candidate["process_group_id"] == pid
        and descends_from(candidate["pid"], pid)
    ]
    if descendants:
        descendants.sort(key=lambda item: (item["start_time_ticks"], item["pid"]))
        candidates.append((process, descendants[-1]))

if len(candidates) != 1:
    raise RuntimeError(
        f"expected one private Hook process group below init PID {init_pid}, found {len(candidates)}"
    )
leader, descendant = candidates[0]
for identity in (leader, descendant):
    identity.pop("parent_pid")
print(json.dumps({"leader": leader, "descendant": descendant}, separators=(",", ":")))
PY
}

prepare_hook_owner_death_bundle() {
  local bundle_path=$1
  local command

  hook_recovery_leader="$bundle_path/rootfs/.a3s-oci-hook-owner-leader"
  hook_recovery_descendant="$bundle_path/rootfs/.a3s-oci-hook-owner-descendant"
  # shellcheck disable=SC2016 # Expanded by the interrupted startContainer Hook.
  command='IFS= read -r A3S_HOOK_STATE || :; trap "" HUP TERM; (trap "" HUP TERM; exec /bin/busybox sleep 300) & child=$!; printf "%s\n" "$$" > /.a3s-oci-hook-owner-leader; printf "%s\n" "$child" > /.a3s-oci-hook-owner-descendant; exec /bin/busybox sleep 300'
  jq \
    --arg command "$command" \
    '
      .linux.cgroupsPath = "a3s-oci-hook-owner-recovery"
      | .hooks = {
          startContainer: [{
            path: "/bin/sh",
            args: ["sh", "-c", $command],
            timeout: 120
          }]
        }
    ' \
    "$bundle_path/config.json" >"$bundle_path/config.json.tmp"
  mv "$bundle_path/config.json.tmp" "$bundle_path/config.json"
}

run_hook_owner_death_recovery() {
  local recovery_root="$qualification_root/native-hook-owner-recovery"
  local ready_file="$qualification_root/native-hook-owner-recovery-ready.json"
  local evidence_file="$qualification_root/native-hook-owner-recovery-evidence.json"
  local owner_log="$qualification_root/native-hook-owner-recovery-owner.log"
  local output
  local status
  local generation
  local ready_json
  local ready_owner_pid
  local ready_owner_start
  local init_pid
  local deadline
  local owner_identity
  local hook_group
  local hook_leader
  local hook_descendant
  local evidence_json

  sudo rm -f \
    "$hook_recovery_leader" \
    "$hook_recovery_descendant" \
    "$hook_recovery_bundle/rootfs/.a3s-oci-native-smoke"
  sudo "$native_runtime_binary" native-linux-hook-owner-death-owner \
    --agent "$native_agent_binary" \
    --root "$recovery_root" \
    --bundle "$hook_recovery_bundle" \
    --container-id native-hook-owner-recovery \
    --ready-file "$ready_file" >"$owner_log" 2>&1 &
  recovery_owner_pid=$!

  deadline=$((SECONDS + 30))
  while [[ ! -f "$ready_file" || ! -s "$hook_recovery_leader" || \
      ! -s "$hook_recovery_descendant" ]]; do
    if ! kill -0 "$recovery_owner_pid" 2>/dev/null; then
      wait "$recovery_owner_pid" || true
      cat "$owner_log" >&2
      printf '%s\n' 'Native Hook recovery owner exited before Hook readiness' >&2
      return 1
    fi
    if ((SECONDS >= deadline)); then
      cat "$owner_log" >&2
      printf '%s\n' 'Timed out waiting for Native Hook owner-death readiness' >&2
      return 1
    fi
    sleep 0.025
  done

  test "$(sudo stat --format '%u:%g:%a' "$ready_file")" = '0:0:600'
  ready_json="$(sudo cat -- "$ready_file")"
  jq --exit-status \
    '.schema_version == "a3s.oci.native-linux-recovery-owner-ready.v3"
     and .status == "available" and .platform == "linux"
     and .target.id == "native-hook-owner-recovery"
     and .target.generation == 1
     and .recovery_point == "start-container-hook"
     and (.owner_pid > 0) and (.owner_start_time_ticks > 0)
     and (.init_pid > 0)
     and .effective_uid == 0 and .effective_gid == 0
     and (.cgroup_delegation_requested | not)
     and (.cgroup_delegation_verified | not)
     and (.running_observed | not)' \
    <<<"$ready_json" >/dev/null
  ready_owner_pid="$(jq --raw-output '.owner_pid' <<<"$ready_json")"
  ready_owner_start="$(jq --raw-output '.owner_start_time_ticks' <<<"$ready_json")"
  init_pid="$(jq --raw-output '.init_pid' <<<"$ready_json")"
  generation="$(jq --raw-output '.target.generation' <<<"$ready_json")"
  recovery_runtime_owner_pid="$ready_owner_pid"

  owner_identity="$(read_linux_process_identity "$ready_owner_pid")"
  test "$(jq --raw-output '.start_time_ticks' <<<"$owner_identity")" = \
    "$ready_owner_start"
  hook_group="$(read_hook_process_group "$init_pid")"
  hook_leader="$(jq --compact-output '.leader' <<<"$hook_group")"
  hook_descendant="$(jq --compact-output '.descendant' <<<"$hook_group")"
  hook_recovery_group_pid="$(jq --raw-output '.pid' <<<"$hook_leader")"
  jq --exit-status \
    --argjson leader "$hook_leader" \
    --argjson descendant "$hook_descendant" \
    '$leader.pid == $leader.process_group_id
     and $descendant.pid != $leader.pid
     and $descendant.process_group_id == $leader.pid' \
    <<<null >/dev/null
  evidence_json="$(
    jq --compact-output --null-input \
      --arg schema 'a3s.oci.native-linux-hook-owner-death-evidence.v1' \
      --argjson generation "$generation" \
      --argjson owner "$owner_identity" \
      --argjson leader "$hook_leader" \
      --argjson descendant "$hook_descendant" \
      '{
        schema_version: $schema,
        target: {id: "native-hook-owner-recovery", generation: $generation},
        owner: $owner,
        hook_leader: $leader,
        hook_descendant: $descendant
      }'
  )"
  (umask 077; printf '%s\n' "$evidence_json" >"$evidence_file")

  sudo kill -KILL "$ready_owner_pid"
  set +e
  wait "$recovery_owner_pid"
  status=$?
  set -e
  recovery_owner_pid=""
  recovery_runtime_owner_pid=""
  if ((status == 0)); then
    cat "$owner_log" >&2
    printf '%s\n' 'Native Hook recovery owner exited cleanly after SIGKILL' >&2
    return 1
  fi

  if output="$(sudo "$native_runtime_binary" \
      native-linux-hook-owner-death-resume \
      --agent "$native_agent_binary" \
      --root "$recovery_root" \
      --bundle "$hook_recovery_bundle" \
      --container-id native-hook-owner-recovery \
      --generation "$generation" \
      --evidence "$evidence_file")"; then
    status=0
  else
    status=$?
  fi
  printf '%s\n' "$output"
  if [[ -n "${A3S_OCI_NATIVE_HOOK_RECOVERY_REPORT:-}" ]]; then
    mkdir -p "$(dirname "$A3S_OCI_NATIVE_HOOK_RECOVERY_REPORT")"
    printf '%s\n' "$output" >"$A3S_OCI_NATIVE_HOOK_RECOVERY_REPORT"
  fi
  if ((status != 0)); then
    cat "$owner_log" >&2
    report_native_failure "$hook_recovery_bundle/rootfs"
    return "$status"
  fi
  jq --exit-status \
    --argjson evidence "$evidence_json" \
    '.schema_version == "a3s.oci.native-linux-hook-owner-death-smoke.v1"
     and .status == "available" and .platform == "linux"
     and .target == $evidence.target
     and .evidence == $evidence
     and (.replacement_owner.pid != $evidence.owner.pid
          or .replacement_owner.start_time_ticks
             != $evidence.owner.start_time_ticks)
     and .evidence_validated
     and .owner_replaced
     and .owner_terminated
     and .hook_leader_terminated
     and .hook_descendant_terminated
     and .recovery.schema_version == "a3s.oci.native-linux-recovery-smoke.v2"
     and .recovery.status == "available"
     and .recovery.target == $evidence.target
     and .recovery.host_service_reopened
     and .recovery.recorded_workload_terminated
     and .recovery.stopped_observed
     and .recovery.process_inventory_empty
     and .recovery.kill_idempotent
     and .recovery.exact_wait_evidence_refused
     and .recovery.stopped_delete_succeeded
     and .recovery.durable_record_removed
     and .recovery.current_driver_shutdown
     and .recovery.executor_transients_clean
     and .recovery.cgroup_delegation_clean
     and (.recovery.reason == null)
     and (.reason == null)' \
    <<<"$output" >/dev/null
  hook_recovery_group_pid=""
  test -z "$(sudo find "$recovery_root/executor" -mindepth 1 -print -quit)"
  sudo rm -f \
    "$hook_recovery_leader" \
    "$hook_recovery_descendant" \
    "$hook_recovery_bundle/rootfs/.a3s-oci-native-smoke"
}
