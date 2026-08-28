#!/usr/bin/env bash

set -euo pipefail

runtime_binary="${A3S_OCI_NATIVE_RUNTIME_BINARY:-}"
agent_binary="${A3S_OCI_NATIVE_AGENT_BINARY:-}"
criu_binary="${A3S_OCI_CRIU_BINARY:-}"
source_commit="${A3S_QUALIFICATION_SOURCE_COMMIT:-}"
report_path="${A3S_OCI_NATIVE_CHECKPOINT_REPORT:-}"
negative_report_path="${A3S_OCI_NATIVE_CHECKPOINT_PIDNS_REPORT:-}"
qualification_root=""
owned_cgroups=()

if ((EUID == 0)); then
  sudo_command=()
else
  command -v sudo >/dev/null || {
    printf '%s\n' 'Native checkpoint qualification requires root or sudo' >&2
    exit 2
  }
  sudo_command=(sudo)
fi

cleanup_cgroup() {
  local path=$1
  local child

  [[ -d "$path" ]] || return 0
  if [[ -e "$path/cgroup.freeze" ]]; then
    printf '0' | "${sudo_command[@]}" tee "$path/cgroup.freeze" >/dev/null || true
  fi
  if [[ -e "$path/cgroup.kill" ]]; then
    printf '1' | "${sudo_command[@]}" tee "$path/cgroup.kill" >/dev/null || true
  fi
  for _ in $(seq 1 100); do
    [[ ! -r "$path/cgroup.events" ]] ||
      grep -q '^populated 0$' "$path/cgroup.events" && break
    sleep 0.01
  done
  for child in a3s-workload a3s-control; do
    "${sudo_command[@]}" rmdir -- "$path/$child" 2>/dev/null || true
  done
  "${sudo_command[@]}" rmdir -- "$path" 2>/dev/null || true
}

cleanup() {
  local command_status=$?
  local cleanup_status=0
  local path

  set +e
  for path in "${owned_cgroups[@]}"; do
    cleanup_cgroup "$path"
    if [[ -e "$path" ]]; then
      printf 'Checkpoint qualification left cgroup state: %s\n' "$path" >&2
      cleanup_status=1
    fi
  done
  if [[ -n "$qualification_root" ]]; then
    case "$qualification_root" in
      /var/tmp/a3s-oci-native-checkpoint.*)
        "${sudo_command[@]}" rm -rf --one-file-system -- "$qualification_root"
        ;;
      *)
        printf 'Refusing to remove unexpected qualification root: %s\n' \
          "$qualification_root" >&2
        cleanup_status=1
        ;;
    esac
  fi
  if ((command_status != 0)); then
    exit "$command_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

for command in jq realpath sha256sum stat busybox; do
  command -v "$command" >/dev/null || {
    printf 'Native checkpoint qualification requires %s\n' "$command" >&2
    exit 2
  }
done
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' \
    'A3S_QUALIFICATION_SOURCE_COMMIT must be one lowercase 40-character Git commit' >&2
  exit 2
fi
if [[ -z "$criu_binary" || "$criu_binary" != /* ]]; then
  printf '%s\n' 'A3S_OCI_CRIU_BINARY must name one absolute CRIU executable' >&2
  exit 2
fi
criu_binary="$(realpath -e -- "$criu_binary")"
criu_mode="$(stat --format '%a' -- "$criu_binary")"
if [[ ! -f "$criu_binary" || -L "$criu_binary" || ! -x "$criu_binary" ]] ||
  [[ "$(stat --format '%u' -- "$criu_binary")" != 0 ]] ||
  (((8#$criu_mode & 8#022) != 0)); then
  printf '%s\n' \
    'CRIU must be a root-owned nonsymlink executable without group/world write access' >&2
  exit 2
fi

validate_binaries() {
  local candidate

  for candidate in "$runtime_binary" "$agent_binary"; do
    if [[ ! -f "$candidate" || -L "$candidate" || ! -x "$candidate" ]]; then
      printf 'Native qualification binary is not a regular executable: %s\n' \
        "$candidate" >&2
      exit 2
    fi
  done
  runtime_binary="$(realpath -e -- "$runtime_binary")"
  agent_binary="$(realpath -e -- "$agent_binary")"
  if [[ "$runtime_binary" == "$agent_binary" ]]; then
    printf '%s\n' 'Native runtime and Agent binaries must be distinct' >&2
    exit 2
  fi
}

if [[ -z "$runtime_binary" && -z "$agent_binary" ]]; then
  command -v cargo >/dev/null || {
    printf '%s\n' 'Development checkpoint qualification requires cargo' >&2
    exit 2
  }
  cargo build -p a3s-oci-agent -p a3s-oci-cli
  runtime_binary="$PWD/target/debug/a3s-oci"
  agent_binary="$PWD/target/debug/a3s-oci-agent"
elif [[ -z "$runtime_binary" || -z "$agent_binary" ]]; then
  printf '%s\n' \
    'A3S_OCI_NATIVE_RUNTIME_BINARY and A3S_OCI_NATIVE_AGENT_BINARY must be supplied together' >&2
  exit 2
fi
validate_binaries

default_features="$("$runtime_binary" features)"
jq --exit-status \
  '(.operations | index("checkpoint")) == null
   and (.operations | index("restore")) == null' \
  <<<"$default_features" >/dev/null

qualification_root="$(mktemp -d /var/tmp/a3s-oci-native-checkpoint.XXXXXXXX)"
"${sudo_command[@]}" chown root:root "$qualification_root"
"${sudo_command[@]}" chmod 0755 "$qualification_root"
nonce="${qualification_root##*.}"
work_parent="$qualification_root/work"
supported_bundle="$qualification_root/supported"
pidns_bundle="$qualification_root/private-pidns"
"${sudo_command[@]}" install -d -m 0700 -o root -g root "$work_parent"
for bundle in "$supported_bundle" "$pidns_bundle"; do
  "${sudo_command[@]}" install -d -m 0755 -o root -g root \
    "$bundle" "$bundle/rootfs" "$bundle/rootfs/bin"
  "${sudo_command[@]}" install -m 0755 -o root -g root \
    "$(command -v busybox)" "$bundle/rootfs/bin/busybox"
done

supported_cgroup="a3s-oci-checkpoint-${nonce}"
pidns_cgroup="a3s-oci-checkpoint-pidns-${nonce}"
for cgroup in "$supported_cgroup" "$pidns_cgroup"; do
  cgroup_host_path="/sys/fs/cgroup/$cgroup"
  if [[ -e "$cgroup_host_path" ]]; then
    printf 'Refusing to reuse checkpoint qualification cgroup: %s\n' \
      "$cgroup_host_path" >&2
    exit 2
  fi
  owned_cgroups+=("$cgroup_host_path")
done

checkpoint_command='set -eu; printf 0 >&7; printf checkpoint-ready > /.a3s-oci-native-smoke; exec 0<&- 1>&- 2>&- 6>&- 7>&-; while :; do /bin/busybox sleep 1 || :; done'
jq \
  --arg cgroup "$supported_cgroup" \
  --arg command "$checkpoint_command" \
  '
    del(.hooks, .linux.uidMappings, .linux.gidMappings)
    | .linux.cgroupsPath = $cgroup
    | .linux.namespaces |= map(select(.type != "user" and .type != "pid"))
    | .process.args = ["/bin/busybox", "sh", "-c", $command]
    | .linux.resources = {
        memory: {limit: 268435456},
        cpu: {quota: 100000, period: 100000},
        pids: {limit: 64}
      }
    | .mounts += [{
        destination: "/sys/fs/cgroup",
        type: "cgroup",
        source: "cgroup",
        options: ["nosuid", "noexec", "nodev", "relatime", "ro"]
      }]
    | .annotations = ((.annotations // {}) + {
        "dev.a3s.oci.cgroup.layout": "control-workload-v1",
        "dev.a3s.oci.cgroup.control-memory-headroom-bytes": "67108864",
        "dev.a3s.oci.cgroup.control-cpu-headroom-micros": "25000",
        "dev.a3s.oci.cgroup.control-pids-headroom": "16"
      })
  ' \
  fixtures/native-linux/config.json |
  "${sudo_command[@]}" tee "$supported_bundle/config.json" >/dev/null
"${sudo_command[@]}" cp -- "$supported_bundle/config.json" "$pidns_bundle/config.json"
"${sudo_command[@]}" jq \
  --arg cgroup "$pidns_cgroup" \
  '.linux.cgroupsPath = $cgroup | .linux.namespaces += [{type: "pid"}]' \
  "$pidns_bundle/config.json" |
  "${sudo_command[@]}" tee "$pidns_bundle/config.json.next" >/dev/null
"${sudo_command[@]}" mv -- \
  "$pidns_bundle/config.json.next" "$pidns_bundle/config.json"

run_checkpoint_smoke() {
  local bundle=$1
  "${sudo_command[@]}" "$runtime_binary" native-linux-checkpoint-smoke \
    --agent "$agent_binary" \
    --criu "$criu_binary" \
    --bundle "$bundle" \
    --work-parent "$work_parent" \
    --source-revision "$source_commit"
}

set +e
report="$(run_checkpoint_smoke "$supported_bundle")"
report_status=$?
set -e
printf '%s\n' "$report"
if ((report_status != 0)); then
  printf '%s\n' 'Native checkpoint qualification returned an unavailable report' >&2
  exit 1
fi
jq --exit-status \
  --arg source "$source_commit" \
  --arg criu_digest "sha256:$(sha256sum "$criu_binary" | cut -d ' ' -f 1)" \
  '
    .schemaVersion == "a3s.oci.native-linux-checkpoint-smoke.v1"
    and .platform == "linux" and .status == "available"
    and .sourceRevision == $source
    and .checkpointAdvertised and .restoreNotAdvertised
    and .preexistingDestinationRejected
    and .preexistingDestinationPreserved
    and .driverAfterCallFaultInjected
    and .artifactPublishedBeforeHostCommit
    and .driverReplayCompletedHostCommit
    and .hostReplayExact and .artifactDigestVerified
    and .artifactBytesUnchangedAcrossReplay
    and .sourceRemainedPaused and .resumeSucceeded
    and .artifactSurvivedContainerDelete
    and .driverJournalAcknowledged and .unpublishedPartialsAbsent
    and .executorRuntimeClean and .sessionRootClean
    and .driverEvidence.checkpoint_backend == "criu"
    and .driverEvidence.checkpoint_format == "native-linux-criu-v1"
    and .driverEvidence.checkpoint_criu_digest == $criu_digest
    and (.driverEvidence.checkpoint_driver_build_digest | test("^sha256:[0-9a-f]{64}$"))
    and (.artifactDigest | test("^sha256:[0-9a-f]{64}$"))
    and (.artifactSizeBytes > 0)
    and (.reason == null)
  ' \
  <<<"$report" >/dev/null
if [[ -n "$report_path" ]]; then
  (umask 077; printf '%s\n' "$report" >"$report_path")
fi

set +e
pidns_report="$(run_checkpoint_smoke "$pidns_bundle")"
pidns_status=$?
set -e
printf '%s\n' "$pidns_report"
if ((pidns_status == 0)); then
  printf '%s\n' 'Private PID namespace checkpoint unexpectedly succeeded' >&2
  exit 1
fi
jq --exit-status \
  '
    .schemaVersion == "a3s.oci.native-linux-checkpoint-smoke.v1"
    and .status == "unavailable"
    and .checkpointAdvertised and .restoreNotAdvertised
    and .pausedSourceObserved
    and .preexistingDestinationRejected
    and .preexistingDestinationPreserved
    and .executorRuntimeClean and .sessionRootClean
    and (.reason | contains("format v1 does not support a private PID namespace"))
  ' \
  <<<"$pidns_report" >/dev/null
if [[ -n "$negative_report_path" ]]; then
  (umask 077; printf '%s\n' "$pidns_report" >"$negative_report_path")
fi
