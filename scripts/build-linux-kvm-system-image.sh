#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/build-system-image.sh
source "$script_directory/lib/build-system-image.sh"

usage() {
  echo "usage: $0 --architecture x86_64|aarch64 --alpine-archive FILE --agent FILE --output-dir DIR [--reproducibility-delay SECONDS]" >&2
}

architecture=""
builder_arguments=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --architecture)
      if [[ -n "$architecture" ]]; then
        echo "architecture may be specified only once" >&2
        exit 2
      fi
      architecture="${2:-}"
      shift 2
      ;;
    *)
      builder_arguments+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$architecture" ]]; then
  usage
  exit 2
fi

export A3S_SYSTEM_IMAGE_SCHEMA_VERSION='a3s.oci.linux-kvm-system-image.v1'
export A3S_SYSTEM_IMAGE_ARCHITECTURE="$architecture"
case "$architecture" in
  x86_64)
    export A3S_SYSTEM_IMAGE_ELF_PATTERN='ELF 64-bit.*x86-64.*(static-pie|statically) linked'
    export A3S_SYSTEM_IMAGE_ALPINE_URL='https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.5-x86_64.tar.gz'
    export A3S_SYSTEM_IMAGE_ALPINE_SHA256='4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282'
    export A3S_SYSTEM_IMAGE_ALPINE_SIZE=3638276
    export A3S_SYSTEM_IMAGE_FILESYSTEM_UUID='a3a30c1a-2026-4000-8000-000000000021'
    export A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED='a3a30c1a-2026-4000-8000-000000000022'
    ;;
  aarch64)
    export A3S_SYSTEM_IMAGE_ELF_PATTERN='ELF 64-bit.*ARM aarch64.*statically linked'
    export A3S_SYSTEM_IMAGE_ALPINE_URL='https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz'
    export A3S_SYSTEM_IMAGE_ALPINE_SHA256='3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70'
    export A3S_SYSTEM_IMAGE_ALPINE_SIZE=3966256
    export A3S_SYSTEM_IMAGE_FILESYSTEM_UUID='a3a30c1a-2026-4000-8000-000000000031'
    export A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED='a3a30c1a-2026-4000-8000-000000000032'
    ;;
  *)
    usage
    exit 2
    ;;
esac

runtime_assets="$script_directory/../crates/krun/runtime/runtime-assets.json"
if [[ ! -f "$runtime_assets" || -L "$runtime_assets" ]]; then
  echo "checked-in runtime asset manifest must be a real regular file: $runtime_assets" >&2
  exit 1
fi
export A3S_SYSTEM_IMAGE_RUNTIME_JSON="$(
  jq --compact-output --exit-status --arg architecture "$architecture" '
    if .schema_version != "a3s.oci.krun-runtime-assets.v1" then
      error("unexpected runtime asset schema")
    else
      [.bundles[] | select(
        .target_os == "linux" and .target_arch == $architecture
      )] as $matches
      | if ($matches | length) != 1 then
          error("Linux runtime asset target must resolve exactly once")
        else
          $matches[0]
        end
    end
  ' "$runtime_assets"
)"

a3s_build_system_image "${builder_arguments[@]}"
