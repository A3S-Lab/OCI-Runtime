#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --alpine-archive FILE --config FILE --bundle DIR [--cgroups-path PATH]" >&2
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
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "the portable ownership fixture is implemented only for macOS" >&2
  exit 2
fi
for command in jq shasum stat tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is unavailable: $command" >&2
    exit 1
  fi
done

alpine_archive="$(cd "$(dirname "$alpine_archive")" && pwd -P)/$(basename "$alpine_archive")"
config="$(cd "$(dirname "$config")" && pwd -P)/$(basename "$config")"
if [[ ! -f "$alpine_archive" || -L "$alpine_archive" ]]; then
  echo "Alpine archive must be a real regular file: $alpine_archive" >&2
  exit 1
fi
if [[ ! -f "$config" || -L "$config" ]]; then
  echo "OCI fixture config must be a real regular file: $config" >&2
  exit 1
fi
if [[ -e "$bundle" || -L "$bundle" ]]; then
  echo "refusing to overwrite OCI bundle: $bundle" >&2
  exit 1
fi

alpine_sha256="3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70"
actual_sha256="$(shasum -a 256 "$alpine_archive" | awk '{print $1}')"
if [[ "$actual_sha256" != "$alpine_sha256" ]]; then
  echo "Alpine archive SHA-256 mismatch: expected $alpine_sha256, found $actual_sha256" >&2
  exit 1
fi

mkdir -p "$bundle/rootfs"
tar --extract --gzip --file "$alpine_archive" --directory "$bundle/rootfs" --no-same-owner

root_uid="$(stat -f '%u' "$bundle/rootfs")"
root_gid="$(stat -f '%g' "$bundle/rootfs")"
if [[ ! "$root_uid" =~ ^[0-9]+$ || ! "$root_gid" =~ ^[0-9]+$ ]]; then
  echo "failed to read numeric macOS rootfs ownership" >&2
  exit 1
fi
ownerships="$(
  find "$bundle/rootfs" -xdev -exec stat -f '%u:%g' {} + |
    LC_ALL=C sort -u
)"
if [[ "$ownerships" != "$root_uid:$root_gid" ]]; then
  echo "macOS fixture rootfs must have one uniform owner; found:" >&2
  printf '%s\n' "$ownerships" >&2
  exit 1
fi

jq_filter=''
jq_filter+='if (.linux.uidMappings | length) != 1 or (.linux.gidMappings | length) != 1 then '
jq_filter+='  error("fixture must contain exactly one UID and one GID mapping") '
jq_filter+='else . end | '
jq_filter+='.linux.uidMappings[0] = {containerID: 0, hostID: $uid, size: 1} | '
jq_filter+='.linux.gidMappings[0] = {containerID: 0, hostID: $gid, size: 1} | '
jq_filter+='.process.args[2] |= ('
jq_filter+='  sub("\\$1 == 0 && \\$2 == 0 && \\$3 == 1"; '
jq_filter+='      "$1 == 0 && $2 == \($uid) && $3 == 1") | '
jq_filter+='  sub("\\$1 == 0 && \\$2 == 0 && \\$3 == 1"; '
jq_filter+='      "$1 == 0 && $2 == \($gid) && $3 == 1")'
jq_filter+=')'
if [[ -n "$cgroups_path" ]]; then
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

printf 'macOS OCI fixture owner: %s:%s\n' "$root_uid" "$root_gid"
