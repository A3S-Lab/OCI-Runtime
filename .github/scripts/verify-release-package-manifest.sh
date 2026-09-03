#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <staged-package-directory>\n' "$0" >&2
  exit 2
fi

package_directory=$1
expected_source_commit=$(printenv A3S_QUALIFICATION_SOURCE_COMMIT || true)
manifest_name='package-manifest.json'

if [[ ! -d "$package_directory" || -L "$package_directory" ]]; then
  printf 'Release package must be a nonsymlink directory: %s\n' "$package_directory" >&2
  exit 2
fi
package_directory=$(realpath -e -- "$package_directory")
manifest_path="$package_directory/$manifest_name"
if [[ ! -f "$manifest_path" || -L "$manifest_path" ]]; then
  printf 'Release package manifest must be a regular nonsymlink file: %s\n' \
    "$manifest_path" >&2
  exit 1
fi
if [[ "$(stat --format '%a' -- "$manifest_path")" != '644' ]]; then
  printf 'Release package manifest must use mode 0644: %s\n' "$manifest_path" >&2
  exit 1
fi

for command in basename find jq realpath sha256sum stat cmp rm sort comm mktemp cut; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Release package manifest verification requires command: %s\n' "$command" >&2
    exit 2
  fi
done

symlink=$(find -P "$package_directory" -type l -print -quit)
if [[ -n "$symlink" ]]; then
  printf 'Release package contains a symlink: %s\n' "$symlink" >&2
  exit 1
fi
special=$(find -P "$package_directory" \( -type b -o -type c -o -type p -o -type s \) \
  -print -quit)
if [[ -n "$special" ]]; then
  printf 'Release package contains a non-regular entry: %s\n' "$special" >&2
  exit 1
fi

manifest=$(jq -e \
  'def nonnegative_integer:
     if type == "number" then (. >= 0 and . == floor) else false end;
   def positive_integer:
     if type == "number" then (. > 0 and . == floor) else false end;
   select(
     .schema_version == "a3s.oci.release-package-manifest.v1"
     and (.source_commit | type == "string" and test("^[0-9a-f]{40}$"))
     and (.package.name | type == "string" and length > 0)
     and (.package.version | type == "string" and length > 0)
     and .package.platform == "linux"
     and (.package.architecture | . == "x86_64" or . == "aarch64")
     and .package.driver == "native-linux"
     and .package.isolation_class == "shared-host-kernel"
     and .qualification.schema_version ==
       "a3s.oci.native-linux-package-qualification.v7"
     and .qualification.path == "qualification/native-linux-package.json"
     and (.qualification.sha256 | test("^[0-9a-f]{64}$"))
     and (.qualification.size_bytes | positive_integer)
     and .containerd.compatibility_record.path ==
       "compat/containerd-runtime-v2.json"
     and (.containerd.compatibility_record.sha256 | test("^[0-9a-f]{64}$"))
     and (.containerd.compatibility_record.size_bytes | positive_integer)
     and .containerd.contract.version == 1
     and .containerd.contract.runtime_type == "io.containerd.a3s-oci.v2"
     and .containerd.contract.task_api == "containerd.task.v2.Task"
     and .containerd.contract.identity_encoding == "sha256-length-framed-u64be-v1"
     and (.containerd.qualified_protocols | type == "array" and length > 0)
     and all(
       .containerd.qualified_protocols[];
       type == "object"
       and (.sdk | type == "object")
       and (.agent | type == "object")
       and (.sdk.minimum | nonnegative_integer)
       and (.sdk.maximum | nonnegative_integer)
       and (.agent.minimum | nonnegative_integer)
       and (.agent.maximum | nonnegative_integer)
       and (.sdk.minimum <= .sdk.maximum)
       and (.agent.minimum <= .agent.maximum)
     )
     and (.files | type == "array" and length > 0)
     and all(
       .files[];
       type == "object"
       and (.path | type == "string" and length > 0)
       and (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
       and (.size_bytes | nonnegative_integer)
       and (.mode | nonnegative_integer)
     )
     and (([.files[].path] | length) == ([.files[].path] | unique | length))
     and (([.files[].path] | sort) == [.files[].path])
   )' "$manifest_path")

source_commit=$(jq -r '.source_commit' <<<"$manifest")
if [[ -n "$expected_source_commit" && "$source_commit" != "$expected_source_commit" ]]; then
  printf 'Release package source commit differs: expected %s, found %s\n' \
    "$expected_source_commit" "$source_commit" >&2
  exit 1
fi
if [[ "$(jq -r '.package.name' <<<"$manifest")" != "$(basename "$package_directory")" ]]; then
  printf '%s\n' 'Release package manifest name does not match its directory' >&2
  exit 1
fi

qualification_report="$package_directory/qualification/native-linux-package.json"
compatibility_record="$package_directory/compat/containerd-runtime-v2.json"
for required in "$qualification_report" "$compatibility_record"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Release package is missing a regular required record: %s\n' "$required" >&2
    exit 1
  fi
done

actual_qualification_sha256=$(sha256sum -- "$qualification_report" | cut -d ' ' -f 1)
actual_qualification_size=$(stat --format '%s' -- "$qualification_report")
actual_compatibility_sha256=$(sha256sum -- "$compatibility_record" | cut -d ' ' -f 1)
actual_compatibility_size=$(stat --format '%s' -- "$compatibility_record")
if [[ "$actual_qualification_sha256" != "$(jq -r '.qualification.sha256' <<<"$manifest")" ||
  "$actual_qualification_size" != "$(jq -r '.qualification.size_bytes' <<<"$manifest")" ]]; then
  printf '%s\n' 'Release package qualification record does not match its manifest' >&2
  exit 1
fi
if [[ "$actual_compatibility_sha256" != "$(jq -r '.containerd.compatibility_record.sha256' <<<"$manifest")" ||
  "$actual_compatibility_size" != "$(jq -r '.containerd.compatibility_record.size_bytes' <<<"$manifest")" ]]; then
  printf '%s\n' 'Release package compatibility record does not match its manifest' >&2
  exit 1
fi

jq -e --arg source_commit "$source_commit" \
  --arg package_name "$(basename "$package_directory")" \
  --arg runtime_version "$(jq -r '.package.version' <<<"$manifest")" \
  --arg architecture "$(jq -r '.package.architecture' <<<"$manifest")" \
  'select(
     .schema_version == "a3s.oci.native-linux-package-qualification.v7"
     and .status == "available"
     and .source_commit == $source_commit
     and .package_name == $package_name
     and .runtime_version == $runtime_version
     and .architecture == $architecture
     and .driver == "native-linux"
     and .isolation_class == "shared-host-kernel"
     and (.executables.runtime.sha256 | test("^[0-9a-f]{64}$"))
     and (.executables.agent.sha256 | test("^[0-9a-f]{64}$"))
     and (.executables.containerd_shim.sha256 | test("^[0-9a-f]{64}$"))
     and (.executables.runtime.size | type == "number" and . > 0)
     and (.executables.agent.size | type == "number" and . > 0)
     and (.executables.containerd_shim.size | type == "number" and . > 0)
   )' "$qualification_report" >/dev/null
jq -e \
  'select(
     .schema_version == "a3s.oci.containerd-runtime-v2-compatibility.v1"
     and .contract == {
       version: 1,
       runtime_type: "io.containerd.a3s-oci.v2",
       task_api: "containerd.task.v2.Task",
       identity_encoding: "sha256-length-framed-u64be-v1"
     }
   )' "$compatibility_record" >/dev/null
jq -e --argjson expected_protocols \
  "$(jq -c '.containerd.qualified_protocols' "$manifest_path")" \
  'select(([.qualification_runs[].protocols] | unique) == $expected_protocols)' \
  "$compatibility_record" >/dev/null

for executable in \
  'runtime|a3s-oci|.executables.runtime.sha256|.executables.runtime.size' \
  'agent|a3s-oci-agent|.executables.agent.sha256|.executables.agent.size' \
  'containerd-shim|containerd-shim-a3s-oci-v2|.executables.containerd_shim.sha256|.executables.containerd_shim.size'; do
  IFS='|' read -r role path report_pointer report_size_pointer <<<"$executable"
  report_sha256=$(jq -r "$report_pointer" "$qualification_report")
  report_size=$(jq -r "$report_size_pointer" "$qualification_report")
  manifest_sha256=$(jq -r --arg path "$path" \
    '.files[] | select(.path == $path) | .sha256' "$manifest_path")
  manifest_size=$(jq -r --arg path "$path" \
    '.files[] | select(.path == $path) | .size_bytes' "$manifest_path")
  if [[ ! "$report_sha256" =~ ^[0-9a-f]{64}$ || "$manifest_sha256" != "$report_sha256" ||
    "$manifest_size" != "$report_size" ]]; then
    printf 'Qualification digest for %s does not match the package manifest: %s\n' \
      "$role" "$path" >&2
    exit 1
  fi
done

manifest_paths=$(mktemp)
actual_paths=$(mktemp)
cleanup() {
  rm -f -- "$manifest_paths" "$actual_paths"
}
trap cleanup EXIT
jq -r '.files[] | .path' "$manifest_path" | sort >"$manifest_paths"
: >"$actual_paths"
while IFS= read -r -d '' relative; do
  if [[ "$relative" == "$manifest_name" ]]; then
    continue
  fi
  if [[ "$relative" == /* || "$relative" == *$'\t'* || "$relative" == *$'\r'* ||
    "$relative" == *$'\n'* || "$relative" =~ (^|/)\.\.(/|$) ]]; then
    printf 'Release package path is not a safe relative manifest path: %q\n' \
      "$relative" >&2
    exit 1
  fi
  printf '%s\n' "$relative" >>"$actual_paths"
done < <(find -P "$package_directory" -type f -printf '%P\0' | sort -z)
sort -o "$actual_paths" "$actual_paths"
if ! cmp -s "$manifest_paths" "$actual_paths"; then
  printf '%s\n' 'Release package file inventory differs from its manifest' >&2
  comm -3 "$manifest_paths" "$actual_paths" >&2 || true
  exit 1
fi

while IFS=$'\t' read -r relative expected_sha256 expected_size expected_mode; do
  if [[ -z "$relative" || "$relative" == /* || "$relative" == *$'\t'* ||
    "$relative" == *$'\r'* || "$relative" == *$'\n'* ||
    "$relative" =~ (^|/)\.\.(/|$) ]]; then
    printf 'Release package manifest contains an unsafe path: %q\n' "$relative" >&2
    exit 1
  fi
  path="$package_directory/$relative"
  if [[ ! -f "$path" || -L "$path" ]]; then
    printf 'Manifest file is not a regular nonsymlink file: %s\n' "$relative" >&2
    exit 1
  fi
  actual_sha256=$(sha256sum -- "$path" | cut -d ' ' -f 1)
  actual_size=$(stat --format '%s' -- "$path")
  actual_mode=$(stat --format '%a' -- "$path")
  if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ || "$actual_sha256" != "$expected_sha256" ||
    "$actual_size" != "$expected_size" || "$actual_mode" != "$expected_mode" ]]; then
    printf 'Release package file identity mismatch: %s\n' "$relative" >&2
    exit 1
  fi
done < <(jq -r '.files[] | [.path, .sha256, (.size_bytes | tostring), (.mode | tostring)] | @tsv' \
  "$manifest_path")

printf 'Verified release package manifest: %s\n' "$manifest_path"
