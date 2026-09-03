#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <staged-package-directory>\n' "$0" >&2
  exit 2
fi

package_directory=$1
source_commit=$(printenv A3S_QUALIFICATION_SOURCE_COMMIT || true)
manifest_name='package-manifest.json'

if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf '%s\n' \
    'A3S_QUALIFICATION_SOURCE_COMMIT must be one lowercase 40-character Git commit' >&2
  exit 2
fi
if [[ ! -d "$package_directory" || -L "$package_directory" ]]; then
  printf 'Release package must be a nonsymlink directory: %s\n' "$package_directory" >&2
  exit 2
fi
package_directory=$(realpath -e -- "$package_directory")
manifest_path="$package_directory/$manifest_name"
if [[ -e "$manifest_path" || -L "$manifest_path" ]]; then
  printf 'Refusing to replace an existing release package manifest: %s\n' \
    "$manifest_path" >&2
  exit 2
fi

for command in basename chmod find jq realpath sha256sum stat mktemp ln rm cut sort; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Release package manifest requires command: %s\n' "$command" >&2
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

qualification_report="$package_directory/qualification/native-linux-package.json"
compatibility_record="$package_directory/compat/containerd-runtime-v2.json"
for required in "$qualification_report" "$compatibility_record"; do
  if [[ ! -f "$required" || -L "$required" ]]; then
    printf 'Release package is missing a regular required record: %s\n' "$required" >&2
    exit 1
  fi
done

package_report=$(jq -e --arg source_commit "$source_commit" \
  --arg package_name "$(basename "$package_directory")" \
  'select(
     .schema_version == "a3s.oci.native-linux-package-qualification.v7"
     and .status == "available"
     and .source_commit == $source_commit
     and .package_name == $package_name
     and (.runtime_version | type == "string" and length > 0)
     and (.architecture | . == "x86_64" or . == "aarch64")
     and .driver == "native-linux"
     and .isolation_class == "shared-host-kernel"
     and (.executables.runtime.sha256 | test("^[0-9a-f]{64}$"))
     and (.executables.agent.sha256 | test("^[0-9a-f]{64}$"))
     and (.executables.containerd_shim.sha256 | test("^[0-9a-f]{64}$"))
     and (.executables.runtime.size | type == "number" and . > 0)
     and (.executables.agent.size | type == "number" and . > 0)
     and (.executables.containerd_shim.size | type == "number" and . > 0)
   )' "$qualification_report")
compatibility=$(jq -e \
  'def nonnegative_integer:
     if type == "number" then (. >= 0 and . == floor) else false end;
   select(
     .schema_version == "a3s.oci.containerd-runtime-v2-compatibility.v1"
     and .contract.version == 1
     and .contract.runtime_type == "io.containerd.a3s-oci.v2"
     and .contract.task_api == "containerd.task.v2.Task"
     and .contract.identity_encoding == "sha256-length-framed-u64be-v1"
     and (.qualification_runs | length > 0)
     and all(
       .qualification_runs[];
       (.protocols | type == "object")
       and (.protocols.sdk | type == "object")
       and (.protocols.agent | type == "object")
       and (.protocols.sdk.minimum | nonnegative_integer)
       and (.protocols.sdk.maximum | nonnegative_integer)
       and (.protocols.agent.minimum | nonnegative_integer)
       and (.protocols.agent.maximum | nonnegative_integer)
       and (.protocols.sdk.minimum <= .protocols.sdk.maximum)
       and (.protocols.agent.minimum <= .protocols.agent.maximum)
     )
   )' "$compatibility_record")

package_name=$(jq -r '.package_name' <<<"$package_report")
runtime_version=$(jq -r '.runtime_version' <<<"$package_report")
architecture=$(jq -r '.architecture' <<<"$package_report")
driver=$(jq -r '.driver' <<<"$package_report")
isolation_class=$(jq -r '.isolation_class' <<<"$package_report")
qualification_schema=$(jq -r '.schema_version' <<<"$package_report")
qualification_sha256=$(sha256sum "$qualification_report" | cut -d ' ' -f 1)
qualification_size=$(stat --format '%s' "$qualification_report")
compatibility_sha256=$(sha256sum "$compatibility_record" | cut -d ' ' -f 1)
compatibility_size=$(stat --format '%s' "$compatibility_record")

files_json=$(
  {
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
      path="$package_directory/$relative"
      mode=$(stat --format '%a' -- "$path")
      size=$(stat --format '%s' -- "$path")
      sha256=$(sha256sum -- "$path" | cut -d ' ' -f 1)
      jq -cn \
        --arg path "$relative" \
        --arg sha256 "$sha256" \
        --argjson size_bytes "$size" \
        --argjson mode "$mode" \
        '{path: $path, sha256: $sha256, size_bytes: $size_bytes, mode: $mode}'
    done < <(find -P "$package_directory" -type f -printf '%P\0' | sort -z)
  } | jq -s 'sort_by(.path)'
)

if [[ -z "$files_json" || "$files_json" == '[]' ]]; then
  printf '%s\n' 'Release package must contain at least one file besides its manifest' >&2
  exit 1
fi

for executable in \
  'runtime|a3s-oci|.executables.runtime.sha256|.executables.runtime.size' \
  'agent|a3s-oci-agent|.executables.agent.sha256|.executables.agent.size' \
  'containerd-shim|containerd-shim-a3s-oci-v2|.executables.containerd_shim.sha256|.executables.containerd_shim.size'; do
  IFS='|' read -r role path report_pointer report_size_pointer <<<"$executable"
  report_sha256=$(jq -r "$report_pointer" <<<"$package_report")
  report_size=$(jq -r "$report_size_pointer" <<<"$package_report")
  manifest_sha256=$(jq -r --arg path "$path" \
    '.[] | select(.path == $path) | .sha256' <<<"$files_json")
  manifest_size=$(jq -r --arg path "$path" \
    '.[] | select(.path == $path) | .size_bytes' <<<"$files_json")
  if [[ ! "$report_sha256" =~ ^[0-9a-f]{64}$ || "$manifest_sha256" != "$report_sha256" ||
    "$manifest_size" != "$report_size" ]]; then
    printf 'Qualification digest for %s does not match the staged package: %s\n' \
      "$role" "$path" >&2
    exit 1
  fi
done

manifest_json=$(jq -cn \
  --arg schema_version 'a3s.oci.release-package-manifest.v1' \
  --arg source_commit "$source_commit" \
  --arg package_name "$package_name" \
  --arg runtime_version "$runtime_version" \
  --arg platform 'linux' \
  --arg architecture "$architecture" \
  --arg driver "$driver" \
  --arg isolation_class "$isolation_class" \
  --arg qualification_schema "$qualification_schema" \
  --arg qualification_path 'qualification/native-linux-package.json' \
  --arg qualification_sha256 "$qualification_sha256" \
  --argjson qualification_size_bytes "$qualification_size" \
  --arg compatibility_path 'compat/containerd-runtime-v2.json' \
  --arg compatibility_sha256 "$compatibility_sha256" \
  --argjson compatibility_size_bytes "$compatibility_size" \
  --argjson contract "$(jq -c '.contract' <<<"$compatibility")" \
  --argjson qualified_protocols "$(jq -c '[.qualification_runs[].protocols] | unique' <<<"$compatibility")" \
  --argjson files "$files_json" \
  '{
    schema_version: $schema_version,
    source_commit: $source_commit,
    package: {
      name: $package_name,
      version: $runtime_version,
      platform: $platform,
      architecture: $architecture,
      driver: $driver,
      isolation_class: $isolation_class
    },
    qualification: {
      schema_version: $qualification_schema,
      path: $qualification_path,
      sha256: $qualification_sha256,
      size_bytes: $qualification_size_bytes
    },
    containerd: {
      compatibility_record: {
        path: $compatibility_path,
        sha256: $compatibility_sha256,
        size_bytes: $compatibility_size_bytes
      },
      contract: $contract,
      qualified_protocols: $qualified_protocols
    },
    files: $files
  }')

temporary=$(mktemp "$package_directory/.$manifest_name.XXXXXX")
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT
printf '%s\n' "$manifest_json" >"$temporary"
chmod 0644 -- "$temporary"
if ! ln -- "$temporary" "$manifest_path"; then
  printf 'Release package manifest publication raced or failed: %s\n' "$manifest_path" >&2
  exit 1
fi
rm -f -- "$temporary"
trap - EXIT

printf 'Created release package manifest: %s\n' "$manifest_path"
