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

for command in basename chmod curl cut dirname file git go grep install jq make \
  mktemp mv readelf readlink realpath rm sed sha256sum stat tar; do
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
  '.schema_version == "a3s.oci.upstream-runtime-tools-lock.v2"
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
   and .integration.bundle_validation == "native-linux-package"
   and .integration.lifecycle_validation == "native-linux-core-qualified-v1"
   and .lifecycle.profile == "native-linux-core-v1"
   and .lifecycle.validated_architectures == ["aarch64", "x86_64"]
   and .lifecycle.preflight_architectures == []
   and .lifecycle.blockers == {}
   and (.lifecycle.rootfs_sources | keys) == ["aarch64", "x86_64"]
   and all(
     .lifecycle.rootfs_sources[];
     .distribution == "alpine"
     and .version == "3.22.5"
     and (.url | test("^https://dl-cdn\\.alpinelinux\\.org/alpine/v3\\.22/releases/(aarch64|x86_64)/alpine-minirootfs-3\\.22\\.5-(aarch64|x86_64)\\.tar\\.gz$"))
     and (.sha256 | test("^[0-9a-f]{64}$"))
     and (.size | type == "number" and . > 0)
   )
   and .lifecycle.upstream_harness_defects == [
     "runtime-tools-start-process-unset-inverted-assertion",
     "runtime-tools-pidfile-true-kill-race"
   ]
   and (.lifecycle.tests | length) > 0
   and all(
     .lifecycle.tests[];
     type == "string" and test("^[a-z0-9][a-z0-9_]{0,63}$")
   )
   and (.lifecycle.tests | length) == (.lifecycle.tests | unique | length)
   and .lifecycle.limitations == [
     "stdio-descriptor-transport",
     "terminal-console-socket",
     "listen-fds"
   ]' \
  "$lock_file" >/dev/null

upstream_repository="$(jq --raw-output '.repository' "$lock_file")"
upstream_commit="$(jq --raw-output '.commit' "$lock_file")"
upstream_version="$(jq --raw-output '.version' "$lock_file")"
runtime_spec_version="$(jq --raw-output '.runtime_spec.version' "$lock_file")"
runtime_spec_sum="$(jq --raw-output '.runtime_spec.module_sum' "$lock_file")"
required_go_version="$(jq --raw-output '.build.go_version' "$lock_file")"
lifecycle_profile="$(jq --raw-output '.lifecycle.profile' "$lock_file")"
mapfile -t lifecycle_tests < <(jq --raw-output '.lifecycle.tests[]' "$lock_file")
go_architecture="$(go env GOARCH)"
case "$go_architecture" in
  amd64)
    package_architecture=x86_64
    rootfs_elf_machine='Advanced Micro Devices X86-64'
    ;;
  arm64)
    package_architecture=aarch64
    rootfs_elf_machine='AArch64'
    ;;
  *)
    printf 'Pinned Runtime Tools lifecycle fixtures do not support GOARCH=%s\n' \
      "$go_architecture" >&2
    exit 2
    ;;
esac
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

validation_targets=()
for lifecycle_test in "${lifecycle_tests[@]}"; do
  validation_source="$source_directory/validation/$lifecycle_test/$lifecycle_test.go"
  if [[ ! -f "$validation_source" || -L "$validation_source" ]]; then
    printf 'Locked lifecycle validation source is missing: %s\n' \
      "$validation_source" >&2
    exit 1
  fi
  validation_targets+=("validation/$lifecycle_test/$lifecycle_test.t")
done

CGO_ENABLED=0 GOFLAGS=-mod=readonly make -C "$source_directory" \
  tool runtimetest "${validation_targets[@]}" \
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
built_runtimetest="$source_directory/runtimetest"
if [[ ! -f "$built_runtimetest" || -L "$built_runtimetest" || \
  ! -x "$built_runtimetest" ]]; then
  printf 'Pinned Runtime Tools build did not produce runtimetest: %s\n' \
    "$built_runtimetest" >&2
  exit 1
fi
if readelf --program-headers "$built_runtimetest" | grep --quiet 'INTERP'; then
  printf '%s\n' 'Pinned runtimetest unexpectedly has an ELF interpreter' >&2
  exit 1
fi
file "$built_runtimetest" | grep --fixed-strings 'statically linked' >/dev/null
git -C "$source_directory" diff --exit-code --check
git -C "$source_directory" diff --exit-code

built_sha256="$(sha256sum "$built_binary" | cut -d ' ' -f 1)"
built_size="$(stat --format '%s' "$built_binary")"
built_runtimetest_sha256="$(sha256sum "$built_runtimetest" | cut -d ' ' -f 1)"
built_runtimetest_size="$(stat --format '%s' "$built_runtimetest")"
lifecycle_entries="$build_root/lifecycle-tests.jsonl"
for lifecycle_test in "${lifecycle_tests[@]}"; do
  lifecycle_binary="$source_directory/validation/$lifecycle_test/$lifecycle_test.t"
  if [[ ! -f "$lifecycle_binary" || -L "$lifecycle_binary" || \
    ! -x "$lifecycle_binary" ]]; then
    printf 'Pinned lifecycle build did not produce %s\n' "$lifecycle_binary" >&2
    exit 1
  fi
  if readelf --program-headers "$lifecycle_binary" | grep --quiet 'INTERP'; then
    printf 'Pinned lifecycle executable unexpectedly has an ELF interpreter: %s\n' \
      "$lifecycle_binary" >&2
    exit 1
  fi
  file "$lifecycle_binary" | grep --fixed-strings 'statically linked' >/dev/null
  jq --compact-output --null-input \
    --arg name "$lifecycle_test" \
    --arg path "lifecycle/$lifecycle_test.t" \
    --arg sha256 "$(sha256sum "$lifecycle_binary" | cut -d ' ' -f 1)" \
    --argjson size "$(stat --format '%s' "$lifecycle_binary")" \
    '{name: $name, path: $path, sha256: $sha256, size: $size, static_elf: true}' \
    >>"$lifecycle_entries"
done

rootfs_available=true
rootfs_name="rootfs-$go_architecture.tar.gz"
rootfs_source="$build_root/$rootfs_name"
rootfs_download="$rootfs_source.download"
rootfs_distribution="$(
  jq --raw-output --arg architecture "$package_architecture" \
    '.lifecycle.rootfs_sources[$architecture].distribution' "$lock_file"
)"
rootfs_version="$(
  jq --raw-output --arg architecture "$package_architecture" \
    '.lifecycle.rootfs_sources[$architecture].version' "$lock_file"
)"
rootfs_url="$(
  jq --raw-output --arg architecture "$package_architecture" \
    '.lifecycle.rootfs_sources[$architecture].url' "$lock_file"
)"
rootfs_sha256="$(
  jq --raw-output --arg architecture "$package_architecture" \
    '.lifecycle.rootfs_sources[$architecture].sha256' "$lock_file"
)"
rootfs_size="$(
  jq --raw-output --arg architecture "$package_architecture" \
    '.lifecycle.rootfs_sources[$architecture].size' "$lock_file"
)"

curl --fail --location --retry 3 --output "$rootfs_download" "$rootfs_url"
if [[ ! -f "$rootfs_download" || -L "$rootfs_download" ]] ||
  [[ "$(stat --format '%s' "$rootfs_download")" != "$rootfs_size" ]] ||
  [[ "$(sha256sum "$rootfs_download" | cut -d ' ' -f 1)" != \
    "$rootfs_sha256" ]]; then
  printf 'Downloaded %s %s %s rootfs differs from the compatibility lock\n' \
    "$rootfs_distribution" "$rootfs_version" "$package_architecture" >&2
  exit 1
fi
mv -- "$rootfs_download" "$rootfs_source"

rootfs_entries="$build_root/rootfs.entries"
tar --list --gzip --file "$rootfs_source" >"$rootfs_entries"
while IFS= read -r rootfs_entry; do
  if [[ "$rootfs_entry" == './' || "$rootfs_entry" == '.' ]]; then
    continue
  fi
  normalized_entry="${rootfs_entry#./}"
  if [[ -z "$normalized_entry" || "$normalized_entry" == /* ]]; then
    printf 'Locked lifecycle rootfs contains an invalid path: %s\n' \
      "$rootfs_entry" >&2
    exit 1
  fi
  case "/$normalized_entry/" in
    */../*)
      printf 'Locked lifecycle rootfs contains a parent traversal: %s\n' \
        "$rootfs_entry" >&2
      exit 1
      ;;
  esac
done <"$rootfs_entries"
for required_rootfs_entry in bin/busybox bin/sh etc/group etc/passwd; do
  if ! sed 's#^\./##' "$rootfs_entries" |
    grep --fixed-strings --line-regexp "$required_rootfs_entry" >/dev/null; then
    printf 'Locked lifecycle rootfs lacks required entry: %s\n' \
      "$required_rootfs_entry" >&2
    exit 1
  fi
done

rootfs_verification="$build_root/rootfs-verification"
install -d -m 0700 -- "$rootfs_verification"
tar --extract --gzip --file "$rootfs_source" \
  --directory "$rootfs_verification" \
  --no-same-owner --no-same-permissions -- \
  ./bin/busybox ./bin/sh ./etc/group ./etc/passwd
if [[ ! -f "$rootfs_verification/bin/busybox" || \
  -L "$rootfs_verification/bin/busybox" || \
  ! -x "$rootfs_verification/bin/busybox" ]] ||
  ! readelf --file-header "$rootfs_verification/bin/busybox" |
    grep --extended-regexp \
      "Machine:[[:space:]]+$rootfs_elf_machine" >/dev/null; then
  printf 'Locked lifecycle rootfs has an invalid %s BusyBox executable\n' \
    "$package_architecture" >&2
  exit 1
fi
if [[ ! -L "$rootfs_verification/bin/sh" ]] ||
  [[ "$(readlink -- "$rootfs_verification/bin/sh")" != '/bin/busybox' ]]; then
  printf '%s\n' 'Locked lifecycle rootfs has an invalid /bin/sh identity' >&2
  exit 1
fi
for rootfs_identity_file in etc/group etc/passwd; do
  if [[ ! -f "$rootfs_verification/$rootfs_identity_file" || \
    -L "$rootfs_verification/$rootfs_identity_file" ]]; then
    printf 'Locked lifecycle rootfs has an invalid identity file: %s\n' \
      "$rootfs_identity_file" >&2
    exit 1
  fi
done

manifest="$build_root/upstream-runtime-tools-build.json"
jq --null-input \
  --arg schema_version 'a3s.oci.upstream-runtime-tools-build.v3' \
  --arg repository "$upstream_repository" \
  --arg commit "$upstream_commit" \
  --arg version "$upstream_version" \
  --arg runtime_spec_version "$runtime_spec_version" \
  --arg runtime_spec_module_sum "$runtime_spec_sum" \
  --arg go_version "$actual_go_version" \
  --arg sha256 "$built_sha256" \
  --argjson size "$built_size" \
  --arg lifecycle_profile "$lifecycle_profile" \
  --arg architecture "$go_architecture" \
  --argjson validated_architectures "$(jq --compact-output '.lifecycle.validated_architectures' "$lock_file")" \
  --argjson preflight_architectures "$(jq --compact-output '.lifecycle.preflight_architectures' "$lock_file")" \
  --argjson lifecycle_blockers "$(jq --compact-output '.lifecycle.blockers' "$lock_file")" \
  --argjson upstream_harness_defects "$(jq --compact-output '.lifecycle.upstream_harness_defects' "$lock_file")" \
  --arg runtimetest_sha256 "$built_runtimetest_sha256" \
  --argjson runtimetest_size "$built_runtimetest_size" \
  --argjson lifecycle_tests "$(jq --slurp '.' "$lifecycle_entries")" \
  --argjson lifecycle_limitations "$(jq --compact-output '.lifecycle.limitations' "$lock_file")" \
  --argjson rootfs_available "$rootfs_available" \
  --arg rootfs_name "$rootfs_name" \
  --arg rootfs_sha256 "$rootfs_sha256" \
  --argjson rootfs_size "$rootfs_size" \
  --arg rootfs_distribution "$rootfs_distribution" \
  --arg rootfs_version "$rootfs_version" \
  --arg rootfs_url "$rootfs_url" \
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
    },
    lifecycle: {
      profile: $lifecycle_profile,
      architecture: $architecture,
      validated_architectures: $validated_architectures,
      preflight_architectures: $preflight_architectures,
      blockers: $lifecycle_blockers,
      upstream_harness_defects: $upstream_harness_defects,
      qualified_input_available: $rootfs_available,
      runtimetest: {
        path: "lifecycle/runtimetest",
        sha256: $runtimetest_sha256,
        size: $runtimetest_size,
        static_elf: true
      },
      tests: $lifecycle_tests,
      rootfs: (
        if $rootfs_available then {
          path: ("lifecycle/" + $rootfs_name),
          sha256: $rootfs_sha256,
          size: $rootfs_size,
          source: {
            distribution: $rootfs_distribution,
            version: $rootfs_version,
            url: $rootfs_url,
            sha256: $rootfs_sha256,
            size: $rootfs_size
          }
        } else null end
      ),
      limitations: $lifecycle_limitations
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
"${sudo_command[@]}" install -d -m 0755 -o root -g root -- \
  "$destination/lifecycle"
"${sudo_command[@]}" install -m 0755 -o root -g root -- \
  "$built_binary" "$destination/oci-runtime-tool"
"${sudo_command[@]}" install -m 0755 -o root -g root -- \
  "$built_runtimetest" "$destination/lifecycle/runtimetest"
for lifecycle_test in "${lifecycle_tests[@]}"; do
  "${sudo_command[@]}" install -m 0755 -o root -g root -- \
    "$source_directory/validation/$lifecycle_test/$lifecycle_test.t" \
    "$destination/lifecycle/$lifecycle_test.t"
done
if [[ "$rootfs_available" == true ]]; then
  "${sudo_command[@]}" install -m 0644 -o root -g root -- \
    "$rootfs_source" "$destination/lifecycle/$rootfs_name"
fi
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
if [[ ! -d "$destination/lifecycle" || -L "$destination/lifecycle" ]] ||
  [[ "$(stat --format '%u:%g:%a' -- "$destination/lifecycle")" != \
    '0:0:755' ]]; then
  printf '%s\n' 'Installed Runtime Tools lifecycle directory has invalid identity' >&2
  exit 1
fi
if [[ "$(sha256sum "$installed_binary" | cut -d ' ' -f 1)" != "$built_sha256" ]] ||
  [[ "$("$installed_binary" --version)" != "$expected_version_output" ]]; then
  printf '%s\n' 'Installed Runtime Tools binary differs from the verified build' >&2
  exit 1
fi
installed_runtimetest="$destination/lifecycle/runtimetest"
if [[ ! -f "$installed_runtimetest" || -L "$installed_runtimetest" || \
  ! -x "$installed_runtimetest" ]] ||
  [[ "$(stat --format '%u:%g' -- "$installed_runtimetest")" != '0:0' ]] ||
  [[ "$(stat --format '%a' -- "$installed_runtimetest")" != '755' ]] ||
  [[ "$(sha256sum "$installed_runtimetest" | cut -d ' ' -f 1)" != \
    "$built_runtimetest_sha256" ]]; then
  printf '%s\n' 'Installed runtimetest differs from the verified build' >&2
  exit 1
fi
for lifecycle_test in "${lifecycle_tests[@]}"; do
  installed_test="$destination/lifecycle/$lifecycle_test.t"
  expected_test_sha256="$(
    jq --raw-output --arg name "$lifecycle_test" \
      '.lifecycle.tests[] | select(.name == $name) | .sha256' "$manifest"
  )"
  if [[ ! -f "$installed_test" || -L "$installed_test" || ! -x "$installed_test" ]] ||
    [[ "$(stat --format '%u:%g' -- "$installed_test")" != '0:0' ]] ||
    [[ "$(stat --format '%a' -- "$installed_test")" != '755' ]] ||
    [[ "$(sha256sum "$installed_test" | cut -d ' ' -f 1)" != \
      "$expected_test_sha256" ]]; then
    printf 'Installed lifecycle test differs from the verified build: %s\n' \
      "$installed_test" >&2
    exit 1
  fi
done
if [[ "$rootfs_available" == true ]]; then
  installed_rootfs="$destination/lifecycle/$rootfs_name"
  if [[ ! -f "$installed_rootfs" || -L "$installed_rootfs" ]] ||
    [[ "$(stat --format '%u:%g' -- "$installed_rootfs")" != '0:0' ]] ||
    [[ "$(stat --format '%a' -- "$installed_rootfs")" != '644' ]] ||
    [[ "$(sha256sum "$installed_rootfs" | cut -d ' ' -f 1)" != \
      "$rootfs_sha256" ]]; then
    printf '%s\n' 'Installed lifecycle rootfs differs from the verified source' >&2
    exit 1
  fi
fi
jq --exit-status \
  --arg sha256 "$built_sha256" \
  --argjson size "$built_size" \
  --arg lifecycle_profile "$lifecycle_profile" \
  --arg architecture "$go_architecture" \
  --argjson rootfs_source "$(
    jq --compact-output --arg architecture "$package_architecture" \
      '.lifecycle.rootfs_sources[$architecture]' "$lock_file"
  )" \
  --argjson test_count "${#lifecycle_tests[@]}" \
  --argjson upstream_harness_defects "$(jq --compact-output '.lifecycle.upstream_harness_defects' "$lock_file")" \
  '.schema_version == "a3s.oci.upstream-runtime-tools-build.v3"
   and .binary.sha256 == $sha256
   and .binary.size == $size
   and .lifecycle.profile == $lifecycle_profile
   and .lifecycle.architecture == $architecture
   and .lifecycle.qualified_input_available == true
   and .lifecycle.rootfs.source == $rootfs_source
   and .lifecycle.upstream_harness_defects == $upstream_harness_defects
   and (.lifecycle.tests | length) == $test_count
   and all(.lifecycle.tests[]; .static_elf)' \
  "$installed_manifest" >/dev/null

printf 'Installed OCI Runtime Tools %s from %s at %s (sha256:%s)\n' \
  "$upstream_version" "$upstream_commit" "$destination" "$built_sha256"
