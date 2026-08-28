#!/usr/bin/env bash

set -euo pipefail

build_root=''
destination=''
destination_created=false
expected_destination=''
sudo_command=()

cleanup() {
  local command_status=$?
  local cleanup_status=0

  trap - EXIT
  if [[ -n "$build_root" ]]; then
    case "$build_root" in
      /var/tmp/a3s-oci-runtime-tools-build.????????)
        rm -rf --one-file-system -- "$build_root" || cleanup_status=1
        ;;
      *)
        printf 'Refusing to remove unexpected Runtime Tools build root: %s\n' \
          "$build_root" >&2
        cleanup_status=1
        ;;
    esac
  fi
  if ((command_status != 0)) && [[ "$destination_created" == true ]]; then
    if [[ -n "$expected_destination" && "$destination" == "$expected_destination" ]]; then
      "${sudo_command[@]}" rm -rf --one-file-system -- "$destination" || \
        cleanup_status=1
    else
      printf 'Refusing to remove unexpected Runtime Tools destination: %s\n' \
        "$destination" >&2
      cleanup_status=1
    fi
  fi
  if ((command_status != 0)); then
    exit "$command_status"
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <absolute-install-directory>\n' "$0" >&2
  exit 2
fi

destination=$1
if [[ "$destination" != /* ]]; then
  printf 'Pinned Runtime Tools install directory must be absolute: %s\n' \
    "$destination" >&2
  exit 2
fi
if [[ -e "$destination" || -L "$destination" ]]; then
  printf 'Refusing to replace an existing Runtime Tools install directory: %s\n' \
    "$destination" >&2
  exit 2
fi

for command in basename chmod cut dirname file git go grep install jq make \
  mktemp readelf realpath rm sha256sum stat; do
  command -v "$command" >/dev/null || {
    printf 'Pinned Runtime Tools build requires %s\n' "$command" >&2
    exit 2
  }
done

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
   and .build.static_elf == true' \
  "$lock_file" >/dev/null

upstream_repository="$(jq --raw-output '.repository' "$lock_file")"
upstream_commit="$(jq --raw-output '.commit' "$lock_file")"
upstream_version="$(jq --raw-output '.version' "$lock_file")"
runtime_spec_version="$(jq --raw-output '.runtime_spec.version' "$lock_file")"
runtime_spec_sum="$(jq --raw-output '.runtime_spec.module_sum' "$lock_file")"
required_go_version="$(jq --raw-output '.build.go_version' "$lock_file")"
actual_go_version="$(go env GOVERSION)"
if [[ "$actual_go_version" != "$required_go_version" ]]; then
  printf 'Pinned Runtime Tools requires %s, found %s\n' \
    "$required_go_version" "$actual_go_version" >&2
  exit 2
fi

destination="$(realpath -m -- "$destination")"
expected_destination="/usr/local/lib/a3s-oci-tools/runtime-tools-$upstream_commit"
if [[ "$destination" != "$expected_destination" ]]; then
  printf 'Pinned Runtime Tools install directory must be exactly %s, found %s\n' \
    "$expected_destination" "$destination" >&2
  exit 2
fi
if [[ -e "$destination" || -L "$destination" ]]; then
  printf 'Refusing to replace an existing Runtime Tools install directory: %s\n' \
    "$destination" >&2
  exit 2
fi

if ((EUID == 0)); then
  sudo_command=()
else
  command -v sudo >/dev/null || {
    printf '%s\n' 'Pinned Runtime Tools installation requires root or sudo' >&2
    exit 2
  }
  sudo_command=(sudo)
fi

build_root="$(mktemp -d /var/tmp/a3s-oci-runtime-tools-build.XXXXXXXX)"
source_directory="$build_root/source"
git init --quiet "$source_directory"
git -C "$source_directory" remote add origin "$upstream_repository"
git -C "$source_directory" fetch --quiet --depth 1 origin "$upstream_commit"
resolved_commit="$(git -C "$source_directory" rev-parse 'FETCH_HEAD^{commit}')"
if [[ "$resolved_commit" != "$upstream_commit" ]]; then
  printf 'Pinned Runtime Tools fetch resolved to %s instead of %s\n' \
    "$resolved_commit" "$upstream_commit" >&2
  exit 1
fi
git -C "$source_directory" checkout --quiet --detach "$upstream_commit"
if [[ "$(git -C "$source_directory" rev-parse HEAD)" != "$upstream_commit" ]]; then
  printf '%s\n' 'Pinned Runtime Tools checkout changed after verification' >&2
  exit 1
fi

grep --fixed-strings --line-regexp "module github.com/opencontainers/runtime-tools" \
  "$source_directory/go.mod" >/dev/null
grep --extended-regexp --line-regexp \
  "[[:space:]]+github.com/opencontainers/runtime-spec v${runtime_spec_version}" \
  "$source_directory/go.mod" >/dev/null
grep --fixed-strings --line-regexp \
  "github.com/opencontainers/runtime-spec v${runtime_spec_version} ${runtime_spec_sum}" \
  "$source_directory/go.sum" >/dev/null
if [[ "$(<"$source_directory/VERSION")" != "$upstream_version" ]]; then
  printf 'Pinned Runtime Tools VERSION does not match lock %s\n' \
    "$upstream_version" >&2
  exit 1
fi

CGO_ENABLED=0 GOFLAGS=-mod=readonly make -C "$source_directory" tool \
  COMMIT="$upstream_commit" \
  EXTRA_FLAGS='-trimpath -buildvcs=false'
built_binary="$source_directory/oci-runtime-tool"
if [[ ! -f "$built_binary" || -L "$built_binary" || ! -x "$built_binary" ]]; then
  printf 'Pinned Runtime Tools build did not produce one executable: %s\n' \
    "$built_binary" >&2
  exit 1
fi
expected_version_output="oci-runtime-tool version ${upstream_version}, commit: ${upstream_commit}"
if [[ "$("$built_binary" --version)" != "$expected_version_output" ]]; then
  printf '%s\n' 'Pinned Runtime Tools version output does not match the lock' >&2
  exit 1
fi
if readelf --program-headers "$built_binary" | grep --quiet 'INTERP'; then
  printf '%s\n' 'Pinned Runtime Tools binary unexpectedly has an ELF interpreter' >&2
  exit 1
fi
file "$built_binary" | grep --fixed-strings 'statically linked' >/dev/null
git -C "$source_directory" diff --exit-code --check
git -C "$source_directory" diff --exit-code

built_sha256="$(sha256sum "$built_binary" | cut -d ' ' -f 1)"
built_size="$(stat --format '%s' "$built_binary")"
manifest="$build_root/upstream-runtime-tools-build.json"
jq --null-input \
  --arg schema_version 'a3s.oci.upstream-runtime-tools-build.v1' \
  --arg repository "$upstream_repository" \
  --arg commit "$upstream_commit" \
  --arg version "$upstream_version" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg runtime_spec_module_sum "$runtime_spec_sum" \
  --arg go_version "$actual_go_version" \
  --arg sha256 "$built_sha256" \
  --argjson size "$built_size" \
  '{
    schema_version: $schema_version,
    repository: $repository,
    commit: $commit,
    version: $version,
    runtime_spec: {
      version: $runtime_spec_version,
      module_sum: $runtime_spec_module_sum
    },
    build: {
      go_version: $go_version,
      cgo_enabled: false,
      trimpath: true,
      buildvcs: false
    },
    binary: {
      name: "oci-runtime-tool",
      sha256: $sha256,
      size: $size,
      static_elf: true
    }
  }' >"$manifest"
chmod 0644 "$manifest"

destination_parent="$(dirname -- "$destination")"
if [[ ! -d "$destination_parent" ]]; then
  "${sudo_command[@]}" install -d -m 0755 -o root -g root -- \
    "$destination_parent"
fi
destination_parent="$(realpath -e -- "$destination_parent")"
destination="$destination_parent/$(basename -- "$destination")"
if [[ "$destination" != "$expected_destination" ]]; then
  printf 'Runtime Tools install parent resolved outside the locked destination: %s\n' \
    "$destination" >&2
  exit 2
fi
if [[ -e "$destination" || -L "$destination" ]]; then
  printf 'Refusing to replace an existing Runtime Tools install directory: %s\n' \
    "$destination" >&2
  exit 2
fi
destination_parent_mode="$(stat --format '%a' -- "$destination_parent")"
if [[ "$(stat --format '%u:%g' -- "$destination_parent")" != '0:0' ]] ||
  (((8#$destination_parent_mode & 8#022) != 0)); then
  printf 'Runtime Tools install parent must be root-owned and not group/world writable: %s\n' \
    "$destination_parent" >&2
  exit 2
fi

"${sudo_command[@]}" install -d -m 0755 -o root -g root -- "$destination"
destination_created=true
"${sudo_command[@]}" install -m 0755 -o root -g root -- \
  "$built_binary" "$destination/oci-runtime-tool"
"${sudo_command[@]}" install -m 0644 -o root -g root -- \
  "$manifest" "$destination/build.json"

installed_binary="$destination/oci-runtime-tool"
installed_manifest="$destination/build.json"
for installed_file in "$installed_binary" "$installed_manifest"; do
  if [[ ! -f "$installed_file" || -L "$installed_file" ]] ||
    [[ "$(stat --format '%u:%g' -- "$installed_file")" != '0:0' ]]; then
    printf 'Installed Runtime Tools entry has invalid identity: %s\n' \
      "$installed_file" >&2
    exit 1
  fi
done
if [[ "$(stat --format '%a' -- "$installed_binary")" != '755' ]] ||
  [[ "$(stat --format '%a' -- "$installed_manifest")" != '644' ]]; then
  printf '%s\n' 'Installed Runtime Tools modes do not match the lock' >&2
  exit 1
fi
if [[ "$(sha256sum "$installed_binary" | cut -d ' ' -f 1)" != "$built_sha256" ]] ||
  [[ "$("$installed_binary" --version)" != "$expected_version_output" ]]; then
  printf '%s\n' 'Installed Runtime Tools binary differs from the verified build' >&2
  exit 1
fi
jq --exit-status \
  --arg sha256 "$built_sha256" \
  --argjson size "$built_size" \
  '.binary.sha256 == $sha256 and .binary.size == $size' \
  "$installed_manifest" >/dev/null

printf 'Installed OCI Runtime Tools %s from %s at %s (sha256:%s)\n' \
  "$upstream_version" "$upstream_commit" "$destination" "$built_sha256"
