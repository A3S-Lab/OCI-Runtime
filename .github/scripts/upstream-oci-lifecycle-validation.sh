#!/usr/bin/env bash

set -euo pipefail

validation_root=''
service_pid=''
service_job_pid=''
service_stopped=false
sudo_command=()

stop_service() {
  local exit_status=0

  if [[ -z "$service_pid" || -z "$service_job_pid" || "$service_stopped" == true ]]; then
    return 0
  fi
  if "${sudo_command[@]}" kill -0 "$service_pid" 2>/dev/null; then
    "${sudo_command[@]}" kill -TERM "$service_pid"
  fi
  for _ in {1..200}; do
    if ! "${sudo_command[@]}" kill -0 "$service_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if "${sudo_command[@]}" kill -0 "$service_pid" 2>/dev/null; then
    printf '%s\n' 'Native Host Service did not stop after SIGTERM' >&2
    "${sudo_command[@]}" kill -KILL "$service_pid" || true
    exit_status=1
  fi
  if ! wait "$service_job_pid"; then
    exit_status=1
  fi
  service_stopped=true
  return "$exit_status"
}

cleanup() {
  local command_status=$?
  local cleanup_status=0

  trap - EXIT
  if ! stop_service; then
    cleanup_status=1
  fi
  if [[ -n "$validation_root" ]]; then
    case "$validation_root" in
      /var/tmp/a3s-oci-upstream-lifecycle.????????)
        "${sudo_command[@]}" rm -rf --one-file-system -- "$validation_root" || \
          cleanup_status=1
        ;;
      *)
        printf 'Refusing to remove unexpected upstream lifecycle root: %s\n' \
          "$validation_root" >&2
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

if [[ "$#" -ne 6 ]]; then
  printf '%s\n' \
    "usage: $0 <tool> <tool-build.json> <runtime> <agent> <source-commit> <report>" >&2
  exit 2
fi

tool=$1
tool_manifest=$2
runtime_binary=$3
agent_binary=$4
source_commit=$5
report=$6

if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' 'Source commit must be one lowercase 40-character Git commit' >&2
  exit 2
fi
for command in awk basename chmod cut dirname file find grep head install jq \
  kill mktemp mv readelf realpath rm sed sha256sum sleep sort stat tail uname; do
  command -v "$command" >/dev/null || {
    printf 'Upstream OCI lifecycle validation requires %s\n' "$command" >&2
    exit 2
  }
done
if ((EUID == 0)); then
  sudo_command=()
else
  command -v sudo >/dev/null || {
    printf '%s\n' 'Upstream OCI lifecycle validation requires root or sudo' >&2
    exit 2
  }
  sudo_command=(sudo)
fi

script_directory="$(dirname -- "$(realpath -e -- "$0")")"
repository_root="$(realpath -e -- "$script_directory/../..")"
lock_file="$repository_root/compat/upstream-runtime-tools.json"
if [[ ! -f "$lock_file" || -L "$lock_file" ]]; then
  printf 'Runtime Tools lock must be a regular nonsymlink file: %s\n' \
    "$lock_file" >&2
  exit 2
fi
jq --exit-status \
  '.schema_version == "a3s.oci.upstream-runtime-tools-lock.v1"
   and (.repository | type == "string" and length > 0)
   and (.commit | test("^[0-9a-f]{40}$"))
   and (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
   and (.runtime_spec.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))
   and (.runtime_spec.module_sum | startswith("h1:"))
   and (.build.go_version | test("^go[0-9]+\\.[0-9]+\\.[0-9]+$"))
   and .build.cgo_enabled == false
   and .build.trimpath == true
   and .build.buildvcs == false
   and .build.static_elf == true
   and .upstream_interface == "oci-runtime-command-line-interface"
   and .integration.lifecycle_validation == "native-linux-core-preflight-v1"
   and .lifecycle.profile == "native-linux-core-v1"
   and .lifecycle.validated_architectures == []
   and .lifecycle.preflight_architectures == ["x86_64"]
   and .lifecycle.blockers.x86_64 ==
     "unsupported-upstream-seccomp-compat-architectures"
   and .lifecycle.blockers.aarch64 == "missing-upstream-aarch64-rootfs"
   and (.lifecycle.tests | length) > 0
   and (.lifecycle.tests | length) == (.lifecycle.tests | unique | length)
   and (.lifecycle.limitations | index("stdio-descriptor-transport")) != null
   and (.lifecycle.limitations | index("terminal-console-socket")) != null
   and (.lifecycle.limitations | index("listen-fds")) != null
   and (.lifecycle.limitations | index("aarch64-upstream-rootfs")) != null' \
  "$lock_file" >/dev/null

upstream_repository="$(jq --raw-output '.repository' "$lock_file")"
upstream_commit="$(jq --raw-output '.commit' "$lock_file")"
upstream_version="$(jq --raw-output '.version' "$lock_file")"
runtime_spec_version="$(jq --raw-output '.runtime_spec.version' "$lock_file")"
runtime_spec_sum="$(jq --raw-output '.runtime_spec.module_sum' "$lock_file")"
required_go_version="$(jq --raw-output '.build.go_version' "$lock_file")"
lifecycle_profile="$(jq --raw-output '.lifecycle.profile' "$lock_file")"
x86_64_blocker="$(jq --raw-output '.lifecycle.blockers.x86_64' "$lock_file")"
aarch64_blocker="$(jq --raw-output '.lifecycle.blockers.aarch64' "$lock_file")"
mapfile -t lifecycle_tests < <(jq --raw-output '.lifecycle.tests[]' "$lock_file")
lifecycle_test_names="$(jq --compact-output '.lifecycle.tests' "$lock_file")"
lifecycle_limitations="$(jq --compact-output '.lifecycle.limitations' "$lock_file")"

for executable in "$tool" "$runtime_binary" "$agent_binary"; do
  if [[ "$executable" != /* ]] ||
    [[ ! -f "$executable" || -L "$executable" || ! -x "$executable" ]]; then
    printf 'Lifecycle executable must be absolute, regular, nonsymlink, and executable: %s\n' \
      "$executable" >&2
    exit 2
  fi
done
tool="$(realpath -e -- "$tool")"
runtime_binary="$(realpath -e -- "$runtime_binary")"
agent_binary="$(realpath -e -- "$agent_binary")"
if [[ "$tool_manifest" != /* ]] ||
  [[ ! -f "$tool_manifest" || -L "$tool_manifest" ]]; then
  printf 'Runtime Tools build manifest must be an absolute regular nonsymlink file: %s\n' \
    "$tool_manifest" >&2
  exit 2
fi
tool_manifest="$(realpath -e -- "$tool_manifest")"
tools_directory="$(dirname -- "$tool_manifest")"
expected_tools_directory="/usr/local/lib/a3s-oci-tools/runtime-tools-$upstream_commit"
if [[ "$tools_directory" != "$expected_tools_directory" ]] ||
  [[ "$tool" != "$tools_directory/oci-runtime-tool" ]]; then
  printf 'Runtime Tools lifecycle inputs must come from %s\n' \
    "$expected_tools_directory" >&2
  exit 2
fi
for protected in "$tool" "$tool_manifest"; do
  protected_mode="$(stat --format '%a' -- "$protected")"
  if [[ "$(stat --format '%u:%g' -- "$protected")" != '0:0' ]] ||
    (((8#$protected_mode & 8#022) != 0)); then
    printf 'Runtime Tools input must be root-owned without group/world write access: %s\n' \
      "$protected" >&2
    exit 2
  fi
done

if [[ "$report" != /* ]]; then
  printf 'Upstream OCI lifecycle report path must be absolute: %s\n' "$report" >&2
  exit 2
fi
if [[ -e "$report" || -L "$report" || -e "$report.tmp" || -L "$report.tmp" ]]; then
  printf 'Refusing to replace an upstream OCI lifecycle report: %s\n' "$report" >&2
  exit 2
fi
report_parent="$(dirname -- "$report")"
if [[ ! -d "$report_parent" || -L "$report_parent" ]]; then
  printf 'Upstream OCI lifecycle report parent must be a nonsymlink directory: %s\n' \
    "$report_parent" >&2
  exit 2
fi
report_parent="$(realpath -e -- "$report_parent")"
report="$report_parent/$(basename -- "$report")"
if [[ -e "$report" || -L "$report" || -e "$report.tmp" || -L "$report.tmp" ]]; then
  printf 'Refusing to replace an upstream OCI lifecycle report: %s\n' "$report" >&2
  exit 2
fi

architecture="$(uname -m)"
case "$architecture" in
  x86_64)
    package_architecture=x86_64
    go_architecture=amd64
    ;;
  aarch64 | arm64)
    package_architecture=aarch64
    go_architecture=arm64
    ;;
  *)
    printf 'Unsupported upstream lifecycle architecture: %s\n' "$architecture" >&2
    exit 2
    ;;
esac

tool_sha256="$(sha256sum "$tool" | cut -d ' ' -f 1)"
tool_size="$(stat --format '%s' "$tool")"
tool_manifest_sha256="$(sha256sum "$tool_manifest" | cut -d ' ' -f 1)"
jq --exit-status \
  --arg sha256 "$tool_sha256" \
  --argjson size "$tool_size" \
  --arg repository "$upstream_repository" \
  --arg commit "$upstream_commit" \
  --arg version "$upstream_version" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg runtime_spec_sum "$runtime_spec_sum" \
  --arg go_version "$required_go_version" \
  --arg lifecycle_profile "$lifecycle_profile" \
  --arg architecture "$go_architecture" \
  --argjson validated_architectures "$(jq --compact-output '.lifecycle.validated_architectures' "$lock_file")" \
  --argjson preflight_architectures "$(jq --compact-output '.lifecycle.preflight_architectures' "$lock_file")" \
  --argjson lifecycle_blockers "$(jq --compact-output '.lifecycle.blockers' "$lock_file")" \
  --argjson lifecycle_tests "$lifecycle_test_names" \
  --argjson lifecycle_limitations "$lifecycle_limitations" \
  '.schema_version == "a3s.oci.upstream-runtime-tools-build.v2"
   and .repository == $repository
   and .commit == $commit
   and .version == $version
   and .runtime_spec.version == $runtime_spec_version
   and .runtime_spec.module_sum == $runtime_spec_sum
   and .build.go_version == $go_version
   and .build.cgo_enabled == false
   and .build.trimpath == true
   and .build.buildvcs == false
   and .binary.sha256 == $sha256
   and .binary.size == $size
   and .binary.static_elf == true
   and .lifecycle.profile == $lifecycle_profile
   and .lifecycle.architecture == $architecture
   and .lifecycle.validated_architectures == $validated_architectures
   and .lifecycle.preflight_architectures == $preflight_architectures
   and .lifecycle.blockers == $lifecycle_blockers
   and [(.lifecycle.tests[]).name] == $lifecycle_tests
   and all(.lifecycle.tests[]; .static_elf == true)
   and .lifecycle.limitations == $lifecycle_limitations' \
  "$tool_manifest" >/dev/null

expected_version_output="oci-runtime-tool version ${upstream_version}, commit: ${upstream_commit}"
if [[ "$("$tool" --version)" != "$expected_version_output" ]]; then
  printf '%s\n' 'OCI Runtime Tools version output does not match its build manifest' >&2
  exit 1
fi
"$repository_root/.github/scripts/verify-static-elf.sh" \
  "$tool" "$runtime_binary" "$agent_binary" >/dev/null

runtime_sha256="$(sha256sum "$runtime_binary" | cut -d ' ' -f 1)"
agent_sha256="$(sha256sum "$agent_binary" | cut -d ' ' -f 1)"
qualified_input_available="$(
  jq --raw-output '.lifecycle.qualified_input_available' "$tool_manifest"
)"
if [[ "$qualified_input_available" != true && \
  "$qualified_input_available" != false ]]; then
  printf '%s\n' 'Runtime Tools manifest has an invalid lifecycle availability value' >&2
  exit 1
fi

if [[ "$package_architecture" == aarch64 ]]; then
  if [[ "$qualified_input_available" != false ]] ||
    [[ "$(jq --raw-output '.lifecycle.rootfs == null' "$tool_manifest")" != true ]]; then
    printf '%s\n' 'AArch64 Runtime Tools manifest must retain the missing-rootfs limitation' >&2
    exit 1
  fi
  jq --null-input \
    --arg schema_version 'a3s.oci.upstream-lifecycle-validation.v1' \
    --arg status 'unavailable' \
    --arg reason 'the pinned upstream source has no aarch64 lifecycle rootfs' \
    --arg source_commit "$source_commit" \
    --arg architecture "$package_architecture" \
    --arg repository "$upstream_repository" \
    --arg upstream_commit "$upstream_commit" \
    --arg upstream_version "$upstream_version" \
    --arg runtime_spec_version "$runtime_spec_version" \
    --arg go_version "$required_go_version" \
    --arg tool_sha256 "$tool_sha256" \
    --argjson tool_size "$tool_size" \
    --arg tool_manifest_sha256 "$tool_manifest_sha256" \
    --arg runtime_sha256 "$runtime_sha256" \
    --argjson runtime_size "$(stat --format '%s' "$runtime_binary")" \
    --arg agent_sha256 "$agent_sha256" \
    --argjson agent_size "$(stat --format '%s' "$agent_binary")" \
    --arg lifecycle_profile "$lifecycle_profile" \
    --arg blocker "$aarch64_blocker" \
    --argjson selected_tests "$lifecycle_test_names" \
    --argjson limitations "$lifecycle_limitations" \
    '{
      schema_version: $schema_version,
      status: $status,
      reason: $reason,
      blocker: $blocker,
      source_commit: $source_commit,
      platform: "linux",
      architecture: $architecture,
      upstream: {
        repository: $repository,
        commit: $upstream_commit,
        version: $upstream_version,
        runtime_spec_version: $runtime_spec_version,
        go_version: $go_version,
        tool_sha256: $tool_sha256,
        tool_size: $tool_size,
        build_manifest_sha256: $tool_manifest_sha256,
        static_elf: true
      },
      package_executables: {
        runtime: {sha256: $runtime_sha256, size: $runtime_size},
        agent: {sha256: $agent_sha256, size: $agent_size}
      },
      validation: {
        interface: "oci-runtime-command-line-interface",
        profile: $lifecycle_profile,
        isolation: "shared-host-kernel",
        endpoint_transport: "unix-socket",
        cli_state_journal_schema: "a3s.oci.cli-lifecycle.v1",
        selected_tests: $selected_tests,
        results: [],
        all_selected_passed: false,
        all_lifecycles_retired: false,
        service_shutdown_clean: false,
        service_log_sha256: null
      },
      core_lifecycle_qualified: false,
      full_lifecycle_qualified: false,
      limitations: $limitations
    }' >"$report.tmp"
  chmod 0644 "$report.tmp"
  mv "$report.tmp" "$report"
  jq --exit-status \
    --arg source_commit "$source_commit" \
    --arg blocker "$aarch64_blocker" \
    --arg runtime_sha256 "$runtime_sha256" \
    --arg agent_sha256 "$agent_sha256" \
    --argjson selected_tests "$lifecycle_test_names" \
    'select(
       .schema_version == "a3s.oci.upstream-lifecycle-validation.v1"
       and .status == "unavailable"
       and .source_commit == $source_commit
       and .architecture == "aarch64"
       and .blocker == $blocker
       and .package_executables.runtime.sha256 == $runtime_sha256
       and .package_executables.agent.sha256 == $agent_sha256
       and .validation.selected_tests == $selected_tests
       and (.validation.results | length) == 0
       and .validation.all_selected_passed == false
       and .validation.all_lifecycles_retired == false
       and .validation.service_shutdown_clean == false
       and .core_lifecycle_qualified == false
       and .full_lifecycle_qualified == false
     )' "$report" >/dev/null
  exit 0
fi

if [[ "$qualified_input_available" != true ]] ||
  [[ "$(jq --raw-output '.lifecycle.rootfs.path' "$tool_manifest")" != \
    'lifecycle/rootfs-amd64.tar.gz' ]]; then
  printf '%s\n' 'x86_64 Runtime Tools manifest lacks its locked lifecycle rootfs' >&2
  exit 1
fi

lifecycle_directory="$tools_directory/lifecycle"
if [[ ! -d "$lifecycle_directory" || -L "$lifecycle_directory" ]]; then
  printf 'Runtime Tools lifecycle directory is invalid: %s\n' \
    "$lifecycle_directory" >&2
  exit 1
fi
if [[ "$(stat --format '%u:%g:%a' -- "$lifecycle_directory")" != \
  '0:0:755' ]]; then
  printf 'Runtime Tools lifecycle directory has invalid identity: %s\n' \
    "$lifecycle_directory" >&2
  exit 1
fi
rootfs="$lifecycle_directory/rootfs-amd64.tar.gz"
runtimetest="$lifecycle_directory/runtimetest"
for lifecycle_input in "$rootfs" "$runtimetest"; do
  if [[ ! -f "$lifecycle_input" || -L "$lifecycle_input" ]]; then
    printf 'Runtime Tools lifecycle input is invalid: %s\n' "$lifecycle_input" >&2
    exit 1
  fi
done
if [[ ! -x "$runtimetest" ]] ||
  [[ "$(stat --format '%u:%g:%a' -- "$runtimetest")" != '0:0:755' ]] ||
  [[ "$(stat --format '%u:%g:%a' -- "$rootfs")" != '0:0:644' ]] ||
  [[ "$(sha256sum "$runtimetest" | cut -d ' ' -f 1)" != \
    "$(jq --raw-output '.lifecycle.runtimetest.sha256' "$tool_manifest")" ]] ||
  [[ "$(sha256sum "$rootfs" | cut -d ' ' -f 1)" != \
    "$(jq --raw-output '.lifecycle.rootfs.sha256' "$tool_manifest")" ]]; then
  printf '%s\n' 'Installed Runtime Tools lifecycle fixture differs from its manifest' >&2
  exit 1
fi
for lifecycle_test in "${lifecycle_tests[@]}"; do
  lifecycle_binary="$lifecycle_directory/$lifecycle_test.t"
  expected_sha256="$(
    jq --raw-output --arg name "$lifecycle_test" \
      '.lifecycle.tests[] | select(.name == $name) | .sha256' "$tool_manifest"
  )"
  if [[ ! -f "$lifecycle_binary" || -L "$lifecycle_binary" || \
    ! -x "$lifecycle_binary" ]] ||
    [[ "$(stat --format '%u:%g' -- "$lifecycle_binary")" != '0:0' ]] ||
    [[ "$(sha256sum "$lifecycle_binary" | cut -d ' ' -f 1)" != \
      "$expected_sha256" ]]; then
    printf 'Installed lifecycle test differs from its manifest: %s\n' \
      "$lifecycle_binary" >&2
    exit 1
  fi
done
lifecycle_executables=("$runtimetest")
for lifecycle_test in "${lifecycle_tests[@]}"; do
  lifecycle_executables+=("$lifecycle_directory/$lifecycle_test.t")
done
"$repository_root/.github/scripts/verify-static-elf.sh" \
  "${lifecycle_executables[@]}" >/dev/null

validation_root="$(mktemp -d /var/tmp/a3s-oci-upstream-lifecycle.XXXXXXXX)"
service_root="$validation_root/service"
adapter_root="$validation_root/adapter"
service_log="$validation_root/host-service.log"
service_pid_file="$validation_root/host-service.pid"
entries="$validation_root/entries.jsonl"
"${sudo_command[@]}" install -d -m 0700 -o root -g root -- \
  "$service_root" "$adapter_root"

# The inner shell must expand $$ after sudo has selected the target process.
# shellcheck disable=SC2016
"${sudo_command[@]}" sh -c '
  pid_file=$1
  shift
  umask 077
  printf "%s\n" "$$" >"$pid_file"
  exec "$@"
' a3s-oci-upstream-lifecycle "$service_pid_file" \
  "$runtime_binary" native-linux-host-service \
  --root "$service_root" \
  --agent "$agent_binary" >"$service_log" 2>&1 &
service_job_pid=$!
for _ in {1..200}; do
  if "${sudo_command[@]}" test -s "$service_pid_file"; then
    service_pid="$("${sudo_command[@]}" sed -n '1p' "$service_pid_file")"
    break
  fi
  if ! kill -0 "$service_job_pid" 2>/dev/null; then
    printf '%s\n' 'Native Host Service launcher exited before publishing its PID' >&2
    sed -n '1,160p' "$service_log" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ ! "$service_pid" =~ ^[1-9][0-9]*$ ]] || ((service_pid <= 1)); then
  printf '%s\n' 'Native Host Service did not publish a valid process ID' >&2
  exit 1
fi
socket_path="$service_root/runtime.sock"
for _ in {1..200}; do
  if "${sudo_command[@]}" test -S "$socket_path"; then
    break
  fi
  if ! "${sudo_command[@]}" kill -0 "$service_pid" 2>/dev/null; then
    printf '%s\n' 'Native Host Service exited before publishing runtime.sock' >&2
    sed -n '1,160p' "$service_log" >&2
    exit 1
  fi
  sleep 0.1
done
if ! "${sudo_command[@]}" test -S "$socket_path" ||
  [[ "$("${sudo_command[@]}" stat --format '%u:%g:%a' -- "$socket_path")" != \
    '0:0:600' ]]; then
  printf '%s\n' 'Native Host Service did not publish a protected root-owned socket' >&2
  exit 1
fi

known_blocker=''
for lifecycle_test in "${lifecycle_tests[@]}"; do
  lifecycle_binary="$lifecycle_directory/$lifecycle_test.t"
  output="$validation_root/$lifecycle_test.tap"
  set +e
  (
    cd "$lifecycle_directory"
    "${sudo_command[@]}" env \
      RUNTIME="$runtime_binary" \
      A3S_OCI_RUNTIME_ENDPOINT="$socket_path" \
      A3S_OCI_CLI_STATE_ROOT="$adapter_root" \
      A3S_OCI_CLI_ISOLATION=shared-host-kernel \
      "$lifecycle_binary"
  ) >"$output" 2>&1
  test_status=$?
  set -e
  if ((test_status != 0)); then
    printf 'Upstream lifecycle test %s exited with %d:\n' \
      "$lifecycle_test" "$test_status" >&2
    sed -n '1,200p' "$output" >&2
    exit 1
  fi
  tap_summary="$(awk '
    BEGIN { version = 0; plan = -1; results = 0; failures = 0; directives = 0 }
    $0 == "TAP version 13" { version = 1 }
    /^not ok [0-9]+/ { failures += 1; results += 1; next }
    /^ok [0-9]+/ { results += 1 }
    /#[[:space:]]*(SKIP|TODO)/ { directives += 1 }
    /^1\.\.[0-9]+([[:space:]]*#.*)?$/ {
      value = $1
      sub(/^1\.\./, "", value)
      plan = value + 0
    }
    END {
      printf "%d %d %d %d %d", plan, results, failures, directives, version
    }
  ' "$output")"
  read -r tap_plan tap_results tap_failures tap_directives tap_version \
    <<<"$tap_summary"
  if ((tap_version != 1 || tap_plan <= 0 || tap_results != tap_plan || \
    tap_failures != 0 || tap_directives != 0)); then
    if [[ "$lifecycle_test" == create && "$test_status" -eq 0 && \
      "$tap_version" -eq 1 && "$tap_plan" -eq 3 && \
      "$tap_results" -eq 3 && "$tap_failures" -eq 1 && \
      "$tap_directives" -eq 0 ]] &&
      grep --fixed-strings --line-regexp \
        'not ok 2 - create MUST create a new container' "$output" >/dev/null &&
      grep --fixed-strings \
        'linux.seccomp.architectures[1]: seccomp architecture ScmpArchX86 is not advertised' \
        "$output" >/dev/null; then
      known_blocker="$x86_64_blocker"
      jq --compact-output --null-input \
        --arg name "$lifecycle_test" \
        --arg blocker "$known_blocker" \
        --arg binary_sha256 "$(sha256sum "$lifecycle_binary" | cut -d ' ' -f 1)" \
        --arg output_sha256 "$(sha256sum "$output" | cut -d ' ' -f 1)" \
        --argjson output_size "$(stat --format '%s' "$output")" \
        --argjson tap_plan "$tap_plan" \
        --argjson tap_results "$tap_results" \
        --argjson tap_failures "$tap_failures" \
        '{
          name: $name,
          result: "blocked",
          blocker: $blocker,
          binary_sha256: $binary_sha256,
          output_sha256: $output_sha256,
          output_size: $output_size,
          tap_plan: $tap_plan,
          tap_results: $tap_results,
          tap_failures: $tap_failures
        }' >>"$entries"
      break
    fi
    printf 'Upstream lifecycle test %s emitted failing or incomplete TAP:\n' \
      "$lifecycle_test" >&2
    sed -n '1,200p' "$output" >&2
    exit 1
  fi
  jq --compact-output --null-input \
    --arg name "$lifecycle_test" \
    --arg binary_sha256 "$(sha256sum "$lifecycle_binary" | cut -d ' ' -f 1)" \
    --arg output_sha256 "$(sha256sum "$output" | cut -d ' ' -f 1)" \
    --argjson output_size "$(stat --format '%s' "$output")" \
    --argjson tap_plan "$tap_plan" \
    --argjson tap_results "$tap_results" \
    '{
      name: $name,
      result: "passed",
      binary_sha256: $binary_sha256,
      output_sha256: $output_sha256,
      output_size: $output_size,
      tap_plan: $tap_plan,
      tap_results: $tap_results
    }' >>"$entries"
done

mapfile -t journal_directories < <(
  "${sudo_command[@]}" find "$adapter_root" -mindepth 1 -maxdepth 1 \
    -type d -print | sort
)
if [[ "${#journal_directories[@]}" -eq 0 ]]; then
  printf '%s\n' 'Upstream lifecycle suite created no CLI lifecycle journals' >&2
  exit 1
fi
for journal_directory in "${journal_directories[@]}"; do
  latest_snapshot="$(
    "${sudo_command[@]}" find "$journal_directory" -mindepth 1 -maxdepth 1 \
      -type f -name 'journal-*.json' -print | sort | tail -n 1
  )"
  if [[ -z "$latest_snapshot" ]] ||
    ! "${sudo_command[@]}" jq --exit-status \
      '.schema_version == "a3s.oci.cli-lifecycle.v1"
       and .lifecycle == null' "$latest_snapshot" >/dev/null; then
    printf 'CLI lifecycle did not retire cleanly: %s\n' "$journal_directory" >&2
    exit 1
  fi
done

if ! stop_service; then
  printf '%s\n' 'Native Host Service did not shut down cleanly' >&2
  exit 1
fi
if "${sudo_command[@]}" test -e "$socket_path" ||
  "${sudo_command[@]}" test -L "$socket_path"; then
  printf '%s\n' 'Native Host Service socket remained after shutdown' >&2
  exit 1
fi
service_log_sha256="$(sha256sum "$service_log" | cut -d ' ' -f 1)"
rootfs_sha256="$(sha256sum "$rootfs" | cut -d ' ' -f 1)"

if [[ -n "$known_blocker" ]]; then
  jq --null-input \
    --arg schema_version 'a3s.oci.upstream-lifecycle-validation.v1' \
    --arg status 'unavailable' \
    --arg reason 'the pinned upstream default seccomp profile requests unsupported x86 and x32 compatibility architectures' \
    --arg blocker "$known_blocker" \
    --arg source_commit "$source_commit" \
    --arg architecture "$package_architecture" \
    --arg repository "$upstream_repository" \
    --arg upstream_commit "$upstream_commit" \
    --arg upstream_version "$upstream_version" \
    --arg runtime_spec_version "$runtime_spec_version" \
    --arg go_version "$required_go_version" \
    --arg tool_sha256 "$tool_sha256" \
    --argjson tool_size "$tool_size" \
    --arg tool_manifest_sha256 "$tool_manifest_sha256" \
    --arg rootfs_sha256 "$rootfs_sha256" \
    --argjson rootfs_size "$(stat --format '%s' "$rootfs")" \
    --arg runtime_sha256 "$runtime_sha256" \
    --argjson runtime_size "$(stat --format '%s' "$runtime_binary")" \
    --arg agent_sha256 "$agent_sha256" \
    --argjson agent_size "$(stat --format '%s' "$agent_binary")" \
    --arg lifecycle_profile "$lifecycle_profile" \
    --argjson selected_tests "$lifecycle_test_names" \
    --argjson limitations "$lifecycle_limitations" \
    --arg service_log_sha256 "$service_log_sha256" \
    --slurpfile results "$entries" \
    '{
      schema_version: $schema_version,
      status: $status,
      reason: $reason,
      blocker: $blocker,
      source_commit: $source_commit,
      platform: "linux",
      architecture: $architecture,
      upstream: {
        repository: $repository,
        commit: $upstream_commit,
        version: $upstream_version,
        runtime_spec_version: $runtime_spec_version,
        go_version: $go_version,
        tool_sha256: $tool_sha256,
        tool_size: $tool_size,
        build_manifest_sha256: $tool_manifest_sha256,
        rootfs_sha256: $rootfs_sha256,
        rootfs_size: $rootfs_size,
        static_elf: true
      },
      package_executables: {
        runtime: {sha256: $runtime_sha256, size: $runtime_size},
        agent: {sha256: $agent_sha256, size: $agent_size}
      },
      validation: {
        interface: "oci-runtime-command-line-interface",
        profile: $lifecycle_profile,
        isolation: "shared-host-kernel",
        endpoint_transport: "unix-socket",
        cli_state_journal_schema: "a3s.oci.cli-lifecycle.v1",
        selected_tests: $selected_tests,
        results: $results,
        all_selected_passed: false,
        all_lifecycles_retired: true,
        service_shutdown_clean: true,
        service_log_sha256: $service_log_sha256
      },
      core_lifecycle_qualified: false,
      full_lifecycle_qualified: false,
      limitations: $limitations
    }' >"$report.tmp"
  chmod 0644 "$report.tmp"
  mv "$report.tmp" "$report"
  jq --exit-status \
    --arg source_commit "$source_commit" \
    --arg blocker "$known_blocker" \
    'select(
       .schema_version == "a3s.oci.upstream-lifecycle-validation.v1"
       and .status == "unavailable"
       and .source_commit == $source_commit
       and .architecture == "x86_64"
       and .blocker == $blocker
       and (.validation.results | length) == 1
       and .validation.results[0].name == "create"
       and .validation.results[0].result == "blocked"
       and .validation.results[0].tap_failures == 1
       and .validation.all_selected_passed == false
       and .validation.all_lifecycles_retired
       and .validation.service_shutdown_clean
       and .core_lifecycle_qualified == false
       and .full_lifecycle_qualified == false
     )' "$report" >/dev/null
  exit 0
fi

jq --null-input \
  --arg schema_version 'a3s.oci.upstream-lifecycle-validation.v1' \
  --arg status 'available' \
  --arg source_commit "$source_commit" \
  --arg architecture "$package_architecture" \
  --arg repository "$upstream_repository" \
  --arg upstream_commit "$upstream_commit" \
  --arg upstream_version "$upstream_version" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg go_version "$required_go_version" \
  --arg tool_sha256 "$tool_sha256" \
  --argjson tool_size "$tool_size" \
  --arg tool_manifest_sha256 "$tool_manifest_sha256" \
  --arg rootfs_sha256 "$rootfs_sha256" \
  --argjson rootfs_size "$(stat --format '%s' "$rootfs")" \
  --arg runtime_sha256 "$runtime_sha256" \
  --argjson runtime_size "$(stat --format '%s' "$runtime_binary")" \
  --arg agent_sha256 "$agent_sha256" \
  --argjson agent_size "$(stat --format '%s' "$agent_binary")" \
  --arg lifecycle_profile "$lifecycle_profile" \
  --argjson selected_tests "$lifecycle_test_names" \
  --argjson limitations "$lifecycle_limitations" \
  --arg service_log_sha256 "$service_log_sha256" \
  --slurpfile results "$entries" \
  '{
    schema_version: $schema_version,
    status: $status,
    reason: null,
    blocker: null,
    source_commit: $source_commit,
    platform: "linux",
    architecture: $architecture,
    upstream: {
      repository: $repository,
      commit: $upstream_commit,
      version: $upstream_version,
      runtime_spec_version: $runtime_spec_version,
      go_version: $go_version,
      tool_sha256: $tool_sha256,
      tool_size: $tool_size,
      build_manifest_sha256: $tool_manifest_sha256,
      rootfs_sha256: $rootfs_sha256,
      rootfs_size: $rootfs_size,
      static_elf: true
    },
    package_executables: {
      runtime: {sha256: $runtime_sha256, size: $runtime_size},
      agent: {sha256: $agent_sha256, size: $agent_size}
    },
    validation: {
      interface: "oci-runtime-command-line-interface",
      profile: $lifecycle_profile,
      isolation: "shared-host-kernel",
      endpoint_transport: "unix-socket",
      cli_state_journal_schema: "a3s.oci.cli-lifecycle.v1",
      selected_tests: $selected_tests,
      results: $results,
      all_selected_passed: true,
      all_lifecycles_retired: true,
      service_shutdown_clean: true,
      service_log_sha256: $service_log_sha256
    },
    core_lifecycle_qualified: true,
    full_lifecycle_qualified: false,
    limitations: $limitations
  }' >"$report.tmp"
chmod 0644 "$report.tmp"
mv "$report.tmp" "$report"

jq --exit-status \
  --arg source_commit "$source_commit" \
  --arg upstream_commit "$upstream_commit" \
  --arg runtime_sha256 "$runtime_sha256" \
  --arg agent_sha256 "$agent_sha256" \
  --argjson selected_tests "$lifecycle_test_names" \
  'select(
     .schema_version == "a3s.oci.upstream-lifecycle-validation.v1"
     and .status == "available"
     and .source_commit == $source_commit
     and .architecture == "x86_64"
     and .upstream.commit == $upstream_commit
     and .package_executables.runtime.sha256 == $runtime_sha256
     and .package_executables.agent.sha256 == $agent_sha256
     and .validation.selected_tests == $selected_tests
     and (.validation.results | length) == ($selected_tests | length)
     and all(.validation.results[]; .result == "passed")
     and .validation.all_selected_passed
     and .validation.all_lifecycles_retired
     and .validation.service_shutdown_clean
     and .core_lifecycle_qualified
     and .full_lifecycle_qualified == false
   )' "$report" >/dev/null
