#!/usr/bin/env bash
# Opt-in Native Linux Live Host reopen evidence wrapper.
#
# Distinct from stopped-only native-linux-recovery. Requires
# A3S_OCI_NATIVE_SESSION_SUPERVISOR=1. Proves create+start → retained exec I/O
# (Pipe stdin + Capture stdout) → FileOp upload → Host SIGKILL → init survival
# → replacement Host Running reattach → same-process write_stdin/read_output →
# new post-reattach Pipe+Capture exec → FileOp download under schema
# a3s.oci.linux-native-live-recovery-smoke.v3.
#
# Rootful Host Service must observe a reachable cgroup hierarchy (nsdelegate
# returns ENOENT when source/destination are not in the writer's cgroup
# namespace). When entering the host via docker nsenter, include -C.
set -Eeuo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Native Linux Live recovery qualification requires a Linux host\n' >&2
  exit 2
fi

for command in cargo chmod cp jq ln mkdir mktemp realpath rm tail uname wc
do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required Native Linux Live recovery command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

export A3S_OCI_NATIVE_SESSION_SUPERVISOR="${A3S_OCI_NATIVE_SESSION_SUPERVISOR:-1}"

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$PWD/$target_dir"
fi
profile="${A3S_OCI_BUILD_PROFILE:-debug}"
build_arguments=(build -p a3s-oci-cli -p a3s-oci-agent)
case "$profile" in
  debug) ;;
  release) build_arguments+=(--release) ;;
  *) build_arguments+=(--profile "$profile") ;;
esac
binary_dir="$target_dir/$profile"
cli="$binary_dir/a3s-oci"
agent="${A3S_OCI_NATIVE_AGENT:-$binary_dir/a3s-oci-agent}"

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
# Keep the private work prefix short: SUN_LEN bounds the Host Service socket path.
work="$(mktemp -d "$temporary_root/a3s-oci-nlr.XXXXXX")"
runtime_report="$work/runtime-report.json"
runtime_stderr="$work/runtime.stderr.log"
cleanup() {
  local status=$?
  if [[ "$status" -ne 0 && "${A3S_OCI_KEEP_FAILED_WORK:-0}" == "1" ]]; then
    printf 'preserving failed Native Linux Live recovery work directory: %s\n' \
      "$work" >&2
    return 0
  fi
  case "$work" in
    "$temporary_root"/a3s-oci-nlr.*)
      rm -rf -- "$work"
      ;;
    *)
      printf 'refusing to clean unexpected Native Linux Live recovery path: %s\n' "$work" >&2
      return 1
      ;;
  esac
}
trap cleanup EXIT

on_error() {
  local status=$?
  trap - ERR
  printf 'Native Linux Live recovery qualification failed with status %s near line %s\n' \
    "$status" "${BASH_LINENO[0]}" >&2
  if [[ -s "$runtime_report" ]]; then
    jq --compact-output \
      '{schema_version, status, reason, recovery}' \
      "$runtime_report" >&2 2>/dev/null || true
  fi
  if [[ -s "$runtime_stderr" ]]; then
    tail -n 40 "$runtime_stderr" >&2 || true
  fi
  exit "$status"
}
trap on_error ERR

report_path="${A3S_OCI_LINUX_NATIVE_LIVE_RECOVERY_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite Native Linux Live recovery report: %s\n' "$report_path" >&2
  exit 1
fi
test -d "$(dirname "$report_path")"

cargo "${build_arguments[@]}"
test -x "$cli"
test -x "$agent"

if [[ -n "${A3S_OCI_NATIVE_LIVE_BUNDLE:-}" ]]; then
  bundle="$(realpath -e "$A3S_OCI_NATIVE_LIVE_BUNDLE")"
  test -d "$bundle"
  test -f "$bundle/config.json"
else
  if ! command -v busybox >/dev/null 2>&1; then
    printf 'busybox is required to prepare the Native Live sleep bundle\n' >&2
    exit 1
  fi
  bundle="$work/bundle"
  mkdir -p "$bundle/rootfs/bin" "$bundle/rootfs/dev" "$bundle/rootfs/proc"
  cp "$native_linux_fixture" "$bundle/config.json"
  cp "$(command -v busybox)" "$bundle/rootfs/bin/busybox"
  ln -s busybox "$bundle/rootfs/bin/sh"
  # Rootful sleep bundle: strip Box userns id maps and mapped-root assertions so
  # create's rootfs device scan runs as host root (not mapped UID 100000) and can
  # traverse the harness work tree. Keep namespaces/mounts minimal for sleep 3600.
  jq \
    'del(.hooks)
     | del(.linux.uidMappings, .linux.gidMappings)
     | del(.linux.personality, .linux.memoryPolicy, .linux.timeOffsets)
     | del(.linux.sysctl)
     | del(.process.oomScoreAdj, .process.ioPriority, .process.scheduler)
     | del(.process.rlimits, .process.capabilities)
     | .linux.namespaces |= map(select(
         .type != "user" and .type != "time" and .type != "network"
       ))
     | .linux.cgroupsPath = "a3s-oci-native-live"
     | .process.args = ["/bin/sh", "-c", "exec /bin/busybox sleep 3600"]
     | .process.noNewPrivileges = true' \
    "$bundle/config.json" >"$bundle/config.json.tmp"
  mv "$bundle/config.json.tmp" "$bundle/config.json"
fi

evidence_parent="$work/evidence"
mkdir "$evidence_parent"
# Rootful create needs traversable parents; keep leaves private.
chmod 0755 "$work"
chmod 0700 "$evidence_parent"
if [[ -z "${A3S_OCI_NATIVE_LIVE_BUNDLE:-}" ]]; then
  chmod 0755 "$bundle"
  chmod 0755 "$bundle/rootfs"
fi

cli="$(realpath -e "$cli")"
agent="$(realpath -e "$agent")"
source_revision="$(git rev-parse HEAD)"
architecture="$(uname -m)"

# Rootless native executor open requires cleared supplementary groups.
run_smoke=( "$cli" )
group_count="$(id -G | wc -w)"
if [[ "$group_count" -gt 1 ]]; then
  if ! command -v setpriv >/dev/null 2>&1; then
    printf 'Native Live recovery requires setpriv (or a launch with supplementary groups cleared)\n' >&2
    exit 2
  fi
  uid="$(id -u)"
  gid="$(id -g)"
  if ! setpriv --reuid="$uid" --regid="$gid" --clear-groups -- true >/dev/null 2>&1; then
    printf 'Native Live recovery cannot clear supplementary groups (need CAP_SETGID / sudo / matched-cred CI)\n' >&2
    exit 2
  fi
  run_smoke=( setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$cli" )
fi

set +e
"${run_smoke[@]}" linux-native-live-recovery-smoke \
  --agent "$agent" \
  --bundle "$bundle" \
  --work-parent "$evidence_parent" \
  --source-revision "$source_revision" \
  >"$runtime_report" 2>"$runtime_stderr"
status=$?
set -e

if [[ -s "$runtime_report" ]]; then
  jq --compact-output '{schema_version, status, reason, recovery}' "$runtime_report" >&2 || true
fi

test "$status" -eq 0
test -s "$runtime_report"

jq --exit-status \
  --arg architecture "$architecture" \
  --arg source_revision "$source_revision" \
  '.schema_version == "a3s.oci.linux-native-live-recovery-smoke.v3"
   and .architecture == $architecture
   and .status == "available"
   and .case_count == 1
   and .recovery.session_supervisor_mode_opt_in
   and (.recovery.retained_exec_process_id | type == "string" and length > 0)
   and .recovery.exec_io_before_kill
   and .recovery.write_stdin_after_reattach
   and .recovery.read_output_after_reattach
   and .recovery.retained_exec_io_proven
   and (.recovery.new_exec_process_id | type == "string" and length > 0)
   and .recovery.new_exec_io_after_reattach_proven
   and .recovery.file_upload_before_kill
   and .recovery.host_sigkill_delivered
   and .recovery.init_survived_host_sigkill
   and .recovery.replacement_state_running
   and .recovery.file_download_after_reattach
   and .recovery.retained_filesystem_proven
   and (.reason == null)
   and (.recovery.reason == null)' "$runtime_report" >/dev/null

cp "$runtime_report" "$report_path"
printf 'Native Linux Live recovery harness succeeded (filesystem + retained + new exec I/O)\n' >&2
exit 0
