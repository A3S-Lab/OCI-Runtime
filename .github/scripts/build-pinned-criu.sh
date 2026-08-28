#!/usr/bin/env bash

set -euo pipefail

criu_repository='https://github.com/checkpoint-restore/criu.git'
criu_tag='v4.2.1'
criu_commit='9539417f3e3cfa4eb84c319cd71f4d52f1f08645'
build_root=''

cleanup() {
  local command_status=$?
  local cleanup_status=0

  trap - EXIT
  if [[ -n "$build_root" ]]; then
    case "$build_root" in
      /var/tmp/a3s-oci-criu-build.????????)
        rm -rf --one-file-system -- "$build_root" || cleanup_status=1
        ;;
      *)
        printf 'Refusing to remove unexpected CRIU build root: %s\n' \
          "$build_root" >&2
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

if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s <absolute-install-path>\n' "$0" >&2
  exit 2
fi

destination=$1
if [[ "$destination" != /* ]]; then
  printf 'Pinned CRIU install path must be absolute: %s\n' "$destination" >&2
  exit 2
fi
if [[ -e "$destination" || -L "$destination" ]]; then
  printf 'Refusing to replace an existing CRIU install path: %s\n' \
    "$destination" >&2
  exit 2
fi

for command in basename cut dirname git grep install make mktemp nproc realpath rm sha256sum stat; do
  command -v "$command" >/dev/null || {
    printf 'Pinned CRIU build requires %s\n' "$command" >&2
    exit 2
  }
done
for command in cc pkg-config protoc protoc-c; do
  command -v "$command" >/dev/null || {
    printf 'Pinned CRIU build dependency is unavailable: %s\n' "$command" >&2
    exit 2
  }
done

destination="$(realpath -m -- "$destination")"
if [[ -e "$destination" || -L "$destination" ]]; then
  printf 'Refusing to replace an existing CRIU install path: %s\n' \
    "$destination" >&2
  exit 2
fi

if ((EUID == 0)); then
  sudo_command=()
else
  command -v sudo >/dev/null || {
    printf '%s\n' 'Pinned CRIU installation requires root or sudo' >&2
    exit 2
  }
  sudo_command=(sudo)
fi

build_root="$(mktemp -d /var/tmp/a3s-oci-criu-build.XXXXXXXX)"
source_directory="$build_root/source"
git init --quiet "$source_directory"
git -C "$source_directory" remote add origin "$criu_repository"
git -C "$source_directory" fetch --quiet --depth 1 origin \
  "refs/tags/${criu_tag}:refs/tags/${criu_tag}"
resolved_commit="$(git -C "$source_directory" rev-parse "${criu_tag}^{commit}")"
if [[ "$resolved_commit" != "$criu_commit" ]]; then
  printf 'Pinned CRIU tag resolved to %s instead of %s\n' \
    "$resolved_commit" "$criu_commit" >&2
  exit 1
fi
git -C "$source_directory" checkout --quiet --detach "$criu_commit"
if [[ "$(git -C "$source_directory" rev-parse HEAD)" != "$criu_commit" ]]; then
  printf '%s\n' 'Pinned CRIU checkout changed after verification' >&2
  exit 1
fi

make -C "$source_directory" -j"$(nproc)" criu/criu
built_binary="$source_directory/criu/criu"
if [[ ! -f "$built_binary" || -L "$built_binary" || ! -x "$built_binary" ]]; then
  printf 'Pinned CRIU build did not produce one executable: %s\n' \
    "$built_binary" >&2
  exit 1
fi
built_version="$("$built_binary" --version)"
grep --fixed-strings --line-regexp 'Version: 4.2.1' <<<"$built_version" >/dev/null
grep --fixed-strings --line-regexp 'GitID: v4.2.1' <<<"$built_version" >/dev/null
built_sha256="$(sha256sum "$built_binary" | cut -d ' ' -f 1)"

destination_parent="$(dirname -- "$destination")"
if [[ ! -d "$destination_parent" ]]; then
  "${sudo_command[@]}" install -d -m 0755 -o root -g root -- \
    "$destination_parent"
fi
destination_parent="$(realpath -e -- "$destination_parent")"
destination="$destination_parent/$(basename -- "$destination")"
if [[ -e "$destination" || -L "$destination" ]]; then
  printf 'Refusing to replace an existing CRIU install path: %s\n' \
    "$destination" >&2
  exit 2
fi
destination_parent_mode="$(stat --format '%a' -- "$destination_parent")"
if [[ "$(stat --format '%u:%g' -- "$destination_parent")" != '0:0' ]] ||
  (((8#$destination_parent_mode & 8#022) != 0)); then
  printf 'CRIU install parent must be root-owned and not group/world writable: %s\n' \
    "$destination_parent" >&2
  exit 2
fi
"${sudo_command[@]}" install -m 0755 -o root -g root -- \
  "$built_binary" "$destination"

installed_mode="$(stat --format '%a' -- "$destination")"
if [[ ! -f "$destination" || -L "$destination" || ! -x "$destination" ]] ||
  [[ "$(stat --format '%u:%g' -- "$destination")" != '0:0' ]] ||
  [[ "$installed_mode" != '755' ]]; then
  printf 'Installed CRIU identity or permissions are invalid: %s\n' \
    "$destination" >&2
  exit 1
fi
installed_version="$("$destination" --version)"
grep --fixed-strings --line-regexp 'Version: 4.2.1' \
  <<<"$installed_version" >/dev/null
grep --fixed-strings --line-regexp 'GitID: v4.2.1' \
  <<<"$installed_version" >/dev/null
installed_sha256="$(sha256sum "$destination" | cut -d ' ' -f 1)"
if [[ "$installed_sha256" != "$built_sha256" ]]; then
  printf '%s\n' 'Installed CRIU digest differs from the verified build output' >&2
  exit 1
fi

printf 'Installed CRIU %s from %s at %s (sha256:%s)\n' \
  "$criu_tag" "$criu_commit" "$destination" "$installed_sha256"
