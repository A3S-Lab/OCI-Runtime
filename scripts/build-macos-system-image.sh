#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --alpine-archive FILE --agent FILE --output-dir DIR [--reproducibility-delay SECONDS]" >&2
}

alpine_archive=""
agent=""
output_dir=""
reproducibility_delay=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --alpine-archive)
      alpine_archive="${2:-}"
      shift 2
      ;;
    --agent)
      agent="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --reproducibility-delay)
      reproducibility_delay="${2:-}"
      shift 2
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$alpine_archive" || -z "$agent" || -z "$output_dir" ]]; then
  usage
  exit 2
fi

if [[ ! "$reproducibility_delay" =~ ^[0-9]+$ ]]; then
  echo "reproducibility delay must be a non-negative integer" >&2
  exit 2
fi

for command in cmp debugfs file find install jq mkfs.ext4 readelf seq sha256sum stat tar touch tune2fs truncate xz; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command is unavailable: $command" >&2
    exit 1
  fi
done

alpine_archive="$(readlink -f "$alpine_archive")"
agent="$(readlink -f "$agent")"
output_dir="$(mkdir -p "$output_dir" && readlink -f "$output_dir")"

alpine_sha256="3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70"
alpine_size=3966256
source_date_epoch=1735689600
image_size=67108864
filesystem_uuid="a3a30c1a-2026-4000-8000-000000000001"
directory_hash_seed="a3a30c1a-2026-4000-8000-000000000002"
filesystem_label="a3s-oci-system"

actual_alpine_sha256="$(sha256sum "$alpine_archive" | cut -d ' ' -f 1)"
actual_alpine_size="$(stat --format '%s' "$alpine_archive")"
if [[ "$actual_alpine_sha256" != "$alpine_sha256" || "$actual_alpine_size" -ne "$alpine_size" ]]; then
  echo "Alpine input does not match the pinned 3.22.5 aarch64 archive" >&2
  exit 1
fi

if ! file "$agent" | grep -Eq 'ELF 64-bit.*ARM aarch64.*statically linked'; then
  echo "guest agent must be a statically linked aarch64 ELF executable" >&2
  exit 1
fi
if readelf --program-headers "$agent" | grep -q INTERP; then
  echo "guest agent contains a dynamic interpreter" >&2
  exit 1
fi
if readelf --dynamic "$agent" | grep -q NEEDED; then
  echo "guest agent contains a dynamic dependency" >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

build_image() {
  local iteration="$1"
  local root="$temporary/root-$iteration"
  local image="$temporary/system-$iteration.ext4"

  mkdir "$root"
  tar --extract --gzip --file "$alpine_archive" --directory "$root" --numeric-owner
  install -D -m 0755 "$agent" "$root/usr/bin/a3s-oci-agent"
  install -d -m 0755 "$root/run/a3s-oci-runtime"
  find "$root" -xdev -exec touch -h -d "@$source_date_epoch" {} +

  truncate -s "$image_size" "$image"
  E2FSPROGS_FAKE_TIME="$source_date_epoch" \
    mkfs.ext4 -q -F -b 4096 -I 256 -N 8192 -m 0 \
      -U "$filesystem_uuid" \
      -L "$filesystem_label" \
      -O '^has_journal,^metadata_csum_seed,^orphan_file' \
      -E "root_owner=0:0,lazy_itable_init=0,hash_seed=$directory_hash_seed" \
      -d "$root" \
      "$image"

  # `mkfs.ext4 -d` copies host inode change times even when source access and
  # modification times are fixed. Normalize every inode table entry in one
  # debugfs transaction so builds started at different wall-clock times remain
  # byte-for-byte identical. Free inode entries are normalized too because
  # their table bytes are part of the immutable image digest.
  local inode_count
  local debugfs_commands="$temporary/debugfs-$iteration.commands"
  inode_count="$(tune2fs -l "$image" | sed -n 's/^Inode count:[[:space:]]*//p')"
  if [[ ! "$inode_count" =~ ^[1-9][0-9]*$ ]]; then
    echo "failed to read ext4 inode count from $image" >&2
    exit 1
  fi
  for inode in $(seq 1 "$inode_count"); do
    printf 'set_inode_field <%s> ctime @%s\n' "$inode" "$source_date_epoch"
  done > "$debugfs_commands"
  E2FSPROGS_FAKE_TIME="$source_date_epoch" \
    debugfs -w -f "$debugfs_commands" "$image" >/dev/null 2>&1
}

build_image 1
if [[ "$reproducibility_delay" -gt 0 ]]; then
  sleep "$reproducibility_delay"
fi
build_image 2
if ! cmp "$temporary/system-1.ext4" "$temporary/system-2.ext4"; then
  echo "two independent system-image builds were not byte-for-byte reproducible" >&2
  exit 1
fi

image="$temporary/system-1.ext4"
archive="$temporary/a3s-oci-system.ext4.xz"
xz --threads=1 --check=crc64 -9e --stdout "$image" > "$archive"

image_sha256="$(sha256sum "$image" | cut -d ' ' -f 1)"
archive_sha256="$(sha256sum "$archive" | cut -d ' ' -f 1)"
archive_size="$(stat --format '%s' "$archive")"
agent_sha256="$(sha256sum "$agent" | cut -d ' ' -f 1)"
agent_size="$(stat --format '%s' "$agent")"
e2fsprogs_version="$(mkfs.ext4 -V 2>&1 | sed -n '1s/^mke2fs //p')"

install -m 0644 "$image" "$output_dir/a3s-oci-system.ext4"
install -m 0644 "$archive" "$output_dir/a3s-oci-system.ext4.xz"
jq --null-input --sort-keys \
  --arg schema_version 'a3s.oci.macos-system-image.v1' \
  --arg compatibility_level 'a3s-oci-runtime-0.2.0-agent-protocol-v9' \
  --arg architecture 'aarch64' \
  --arg image_name 'a3s-oci-system.ext4' \
  --arg image_sha256 "$image_sha256" \
  --arg archive_name 'a3s-oci-system.ext4.xz' \
  --arg archive_sha256 "$archive_sha256" \
  --arg filesystem 'ext4' \
  --arg filesystem_uuid "$filesystem_uuid" \
  --arg filesystem_label "$filesystem_label" \
  --arg directory_hash_seed "$directory_hash_seed" \
  --arg alpine_version '3.22.5' \
  --arg alpine_url 'https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz' \
  --arg alpine_sha256 "$alpine_sha256" \
  --arg agent_version '0.2.0' \
  --arg agent_sha256 "$agent_sha256" \
  --arg e2fsprogs_version "$e2fsprogs_version" \
  --arg runtime_archive_sha256 '5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56' \
  --arg libkrun_sha256 'c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d' \
  --arg firmware_sha256 '841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4' \
  --arg kernel_bundle_sha256 'b1180b50148ed14f5fbeadf17288ce8abcf245daa468255b7ff41113bbf01199' \
  --argjson image_size "$image_size" \
  --argjson archive_size "$archive_size" \
  --argjson alpine_size "$alpine_size" \
  --argjson agent_size "$agent_size" \
  --argjson source_date_epoch "$source_date_epoch" \
  --argjson kernel_bundle_size 22740992 \
  --arg kernel_guest_load_address '0x0000000080000000' \
  --arg kernel_entry_address '0x0000000080000000' \
  '{
    schema_version: $schema_version,
    compatibility_level: $compatibility_level,
    architecture: $architecture,
    image: {
      name: $image_name,
      size: $image_size,
      sha256: $image_sha256,
      archive_name: $archive_name,
      archive_size: $archive_size,
      archive_sha256: $archive_sha256,
      filesystem: $filesystem,
      filesystem_uuid: $filesystem_uuid,
      filesystem_label: $filesystem_label,
      directory_hash_seed: $directory_hash_seed
    },
    sources: {
      alpine: {
        version: $alpine_version,
        url: $alpine_url,
        archive_size: $alpine_size,
        archive_sha256: $alpine_sha256
      },
      agent: {
        version: $agent_version,
        size: $agent_size,
        sha256: $agent_sha256
      },
      builder: {
        source_date_epoch: $source_date_epoch,
        e2fsprogs_version: $e2fsprogs_version
      }
    },
    runtime: {
      archive_sha256: $runtime_archive_sha256,
      libkrun_sha256: $libkrun_sha256,
      firmware_sha256: $firmware_sha256,
      kernel_bundle_size: $kernel_bundle_size,
      kernel_bundle_sha256: $kernel_bundle_sha256,
      kernel_guest_load_address: $kernel_guest_load_address,
      kernel_entry_address: $kernel_entry_address
    }
  }' > "$output_dir/system-image.json"

printf 'system image: %s\n' "$image_sha256"
printf 'compressed archive: %s\n' "$archive_sha256"
printf 'manifest: %s\n' "$(sha256sum "$output_dir/system-image.json" | cut -d ' ' -f 1)"
