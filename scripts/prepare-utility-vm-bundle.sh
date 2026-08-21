#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'usage: %s --alpine-archive FILE --config FILE --bundle DIR [--cgroups-path PATH]\n' "$0" >&2
}

alpine_archive=""
config=""
bundle=""
cgroups_path=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --alpine-archive)
      alpine_archive="${2:-}"
      shift 2
      ;;
    --config)
      config="${2:-}"
      shift 2
      ;;
    --bundle)
      bundle="${2:-}"
      shift 2
      ;;
    --cgroups-path)
      cgroups_path="${2:-}"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$alpine_archive" || -z "$config" || -z "$bundle" ]]; then
  usage
  exit 2
fi

host_os="$(uname -s)"
architecture="$(uname -m)"
case "$architecture" in
  x86_64)
    expected_sha256="4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282"
    expected_size=3638276
    ;;
  aarch64 | arm64)
    expected_sha256="3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70"
    expected_size=3966256
    ;;
  *)
    printf 'unsupported utility-VM fixture architecture: %s\n' "$architecture" >&2
    exit 2
    ;;
esac

case "$host_os" in
  Darwin) hash_command="shasum" ;;
  Linux) hash_command="sha256sum" ;;
  *)
    printf 'utility-VM ownership fixtures require macOS or Linux, found %s\n' "$host_os" >&2
    exit 2
    ;;
esac

for command in awk basename dirname find jq mkdir pwd sort stat tar uname "$hash_command"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required utility-VM fixture command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

sha256_file() {
  if [[ "$host_os" == "Darwin" ]]; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

file_size() {
  if [[ "$host_os" == "Darwin" ]]; then
    stat -f '%z' "$1"
  else
    stat --format '%s' "$1"
  fi
}

file_owner() {
  if [[ "$host_os" == "Darwin" ]]; then
    stat -f '%u:%g' "$1"
  else
    stat --format '%u:%g' "$1"
  fi
}

ownership_inventory() {
  if [[ "$host_os" == "Darwin" ]]; then
    find "$1" -xdev -exec stat -f '%u:%g' {} + | LC_ALL=C sort -u
  else
    find "$1" -xdev -exec stat --format '%u:%g' {} + | LC_ALL=C sort -u
  fi
}

alpine_archive="$(cd "$(dirname "$alpine_archive")" && pwd -P)/$(basename "$alpine_archive")"
config="$(cd "$(dirname "$config")" && pwd -P)/$(basename "$config")"
if [[ ! -f "$alpine_archive" || -L "$alpine_archive" ]]; then
  printf 'Alpine archive must be a real regular file: %s\n' "$alpine_archive" >&2
  exit 1
fi
if [[ ! -f "$config" || -L "$config" ]]; then
  printf 'OCI fixture config must be a real regular file: %s\n' "$config" >&2
  exit 1
fi
if [[ -e "$bundle" || -L "$bundle" ]]; then
  printf 'refusing to overwrite OCI bundle: %s\n' "$bundle" >&2
  exit 1
fi

actual_sha256="$(sha256_file "$alpine_archive")"
actual_size="$(file_size "$alpine_archive")"
if [[ "$actual_sha256" != "$expected_sha256" || "$actual_size" -ne "$expected_size" ]]; then
  printf 'Alpine archive mismatch: expected %s/%s bytes, found %s/%s bytes\n' \
    "$expected_sha256" "$expected_size" "$actual_sha256" "$actual_size" >&2
  exit 1
fi

mkdir -p "$bundle/rootfs"
tar --extract --gzip --file "$alpine_archive" --directory "$bundle/rootfs" --no-same-owner

owner="$(file_owner "$bundle/rootfs")"
root_uid="${owner%%:*}"
root_gid="${owner##*:}"
if [[ ! "$root_uid" =~ ^[0-9]+$ || ! "$root_gid" =~ ^[0-9]+$ ]]; then
  printf 'failed to read numeric utility-VM rootfs ownership\n' >&2
  exit 1
fi
ownerships="$(ownership_inventory "$bundle/rootfs")"
if [[ "$ownerships" != "$root_uid:$root_gid" ]]; then
  printf 'utility-VM fixture rootfs must have one uniform owner; found:\n' >&2
  printf '%s\n' "$ownerships" >&2
  exit 1
fi

# jq, rather than the shell, expands these named arguments.
# shellcheck disable=SC2016
jq_filter='if (.linux.uidMappings | length) != 1 or (.linux.gidMappings | length) != 1 then
  error("fixture must contain exactly one UID and one GID mapping")
else . end |
.linux.uidMappings[0] = {containerID: 0, hostID: $uid, size: 1} |
.linux.gidMappings[0] = {containerID: 0, hostID: $gid, size: 1} |
.process.args[2] |= (
  sub("\\$1 == 0 && \\$2 == 0 && \\$3 == 1";
      "$1 == 0 && $2 == \($uid) && $3 == 1") |
  sub("\\$1 == 0 && \\$2 == 0 && \\$3 == 1";
      "$1 == 0 && $2 == \($gid) && $3 == 1")
)'
if [[ -n "$cgroups_path" ]]; then
  # shellcheck disable=SC2016
  jq_filter+=' | .linux.cgroupsPath = $cgroups_path'
fi

jq --argjson uid "$root_uid" \
  --argjson gid "$root_gid" \
  --arg cgroups_path "$cgroups_path" \
  "$jq_filter" "$config" > "$bundle/config.json"

jq --exit-status \
  --argjson uid "$root_uid" \
  --argjson gid "$root_gid" \
  '.linux.uidMappings == [{"containerID": 0, "hostID": $uid, "size": 1}]
   and .linux.gidMappings == [{"containerID": 0, "hostID": $gid, "size": 1}]
   and (.process.args[2] | contains("$1 == 0 && $2 == " + ($uid | tostring) + " && $3 == 1"))
   and (.process.args[2] | contains("$1 == 0 && $2 == " + ($gid | tostring) + " && $3 == 1"))' \
  "$bundle/config.json" >/dev/null

printf 'utility-VM OCI fixture owner: %s:%s\n' "$root_uid" "$root_gid"
