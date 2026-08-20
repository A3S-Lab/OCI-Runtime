#!/usr/bin/env bash

# Shared deterministic ext4 system-image builder. Platform wrappers must set
# every A3S_SYSTEM_IMAGE_* variable below before calling this function.
a3s_build_system_image() {
  local alpine_archive=""
  local agent=""
  local output_dir=""
  local reproducibility_delay=0

  usage() {
    echo "usage: $0 --alpine-archive FILE --agent FILE --output-dir DIR [--reproducibility-delay SECONDS]" >&2
  }

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
        return 2
        ;;
    esac
  done

  if [[ -z "$alpine_archive" || -z "$agent" || -z "$output_dir" ]]; then
    usage
    return 2
  fi
  if [[ ! "$reproducibility_delay" =~ ^[0-9]+$ ]]; then
    echo "reproducibility delay must be a non-negative integer" >&2
    return 2
  fi

  local required_variables=(
    A3S_SYSTEM_IMAGE_SCHEMA_VERSION
    A3S_SYSTEM_IMAGE_ARCHITECTURE
    A3S_SYSTEM_IMAGE_ELF_PATTERN
    A3S_SYSTEM_IMAGE_ALPINE_URL
    A3S_SYSTEM_IMAGE_ALPINE_SHA256
    A3S_SYSTEM_IMAGE_ALPINE_SIZE
    A3S_SYSTEM_IMAGE_FILESYSTEM_UUID
    A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED
    A3S_SYSTEM_IMAGE_RUNTIME_JSON
  )
  local variable
  for variable in "${required_variables[@]}"; do
    if [[ -z "${!variable:-}" ]]; then
      echo "required system-image builder variable is unset: $variable" >&2
      return 2
    fi
  done

  local command
  for command in cmp debugfs file find install jq mkfs.ext4 readelf seq sha256sum stat tar touch tune2fs truncate xz; do
    if ! command -v "$command" >/dev/null 2>&1; then
      echo "required command is unavailable: $command" >&2
      return 1
    fi
  done

  alpine_archive="$(readlink -f "$alpine_archive")"
  agent="$(readlink -f "$agent")"
  output_dir="$(mkdir -p "$output_dir" && readlink -f "$output_dir")"
  local output_name
  for output_name in a3s-oci-system.ext4 a3s-oci-system.ext4.xz system-image.json; do
    if [[ -e "$output_dir/$output_name" ]]; then
      echo "refusing to overwrite existing system-image output: $output_dir/$output_name" >&2
      return 1
    fi
  done

  local source_date_epoch=1735689600
  local image_size=67108864
  local filesystem_label="a3s-oci-system"
  local compatibility_level="a3s-oci-runtime-0.2.0-agent-protocol-v10"

  local actual_alpine_sha256
  local actual_alpine_size
  actual_alpine_sha256="$(sha256sum "$alpine_archive" | cut -d ' ' -f 1)"
  actual_alpine_size="$(stat --format '%s' "$alpine_archive")"
  if [[ "$actual_alpine_sha256" != "$A3S_SYSTEM_IMAGE_ALPINE_SHA256" || "$actual_alpine_size" -ne "$A3S_SYSTEM_IMAGE_ALPINE_SIZE" ]]; then
    echo "Alpine input does not match the pinned 3.22.5 $A3S_SYSTEM_IMAGE_ARCHITECTURE archive" >&2
    return 1
  fi

  if ! file "$agent" | grep -Eq "$A3S_SYSTEM_IMAGE_ELF_PATTERN"; then
    echo "guest agent must be a statically linked $A3S_SYSTEM_IMAGE_ARCHITECTURE ELF executable" >&2
    return 1
  fi
  if readelf --program-headers "$agent" | grep -q INTERP; then
    echo "guest agent contains a dynamic interpreter" >&2
    return 1
  fi
  if readelf --dynamic "$agent" | grep -q NEEDED; then
    echo "guest agent contains a dynamic dependency" >&2
    return 1
  fi

  local temporary
  local quoted_temporary
  temporary="$(mktemp -d)"
  printf -v quoted_temporary '%q' "$temporary"
  trap "rm -rf -- $quoted_temporary" EXIT

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
        -U "$A3S_SYSTEM_IMAGE_FILESYSTEM_UUID" \
        -L "$filesystem_label" \
        -O '^has_journal,^metadata_csum_seed,^orphan_file' \
        -E "root_owner=0:0,lazy_itable_init=0,hash_seed=$A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED" \
        -d "$root" \
        "$image"

    # mkfs.ext4 -d retains host inode change times. Normalize allocated and
    # free inode entries so separate builds have identical table bytes.
    local inode_count
    local debugfs_commands="$temporary/debugfs-$iteration.commands"
    inode_count="$(tune2fs -l "$image" | sed -n 's/^Inode count:[[:space:]]*//p')"
    if [[ ! "$inode_count" =~ ^[1-9][0-9]*$ ]]; then
      echo "failed to read ext4 inode count from $image" >&2
      return 1
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
    return 1
  fi

  local image="$temporary/system-1.ext4"
  local installed_agent="$temporary/installed-a3s-oci-agent"
  debugfs -R "dump /usr/bin/a3s-oci-agent $installed_agent" "$image" >/dev/null 2>&1
  if ! cmp "$agent" "$installed_agent"; then
    echo "system image does not contain the exact supplied guest agent" >&2
    return 1
  fi

  local archive="$temporary/a3s-oci-system.ext4.xz"
  xz --threads=1 --check=crc64 -9e --stdout "$image" > "$archive"

  local image_sha256 archive_sha256 archive_size agent_sha256 agent_size e2fsprogs_version
  image_sha256="$(sha256sum "$image" | cut -d ' ' -f 1)"
  archive_sha256="$(sha256sum "$archive" | cut -d ' ' -f 1)"
  archive_size="$(stat --format '%s' "$archive")"
  agent_sha256="$(sha256sum "$agent" | cut -d ' ' -f 1)"
  agent_size="$(stat --format '%s' "$agent")"
  e2fsprogs_version="$(mkfs.ext4 -V 2>&1 | sed -n '1s/^mke2fs //p')"

  install -m 0644 "$image" "$output_dir/a3s-oci-system.ext4"
  install -m 0644 "$archive" "$output_dir/a3s-oci-system.ext4.xz"
  jq --null-input --sort-keys \
    --arg schema_version "$A3S_SYSTEM_IMAGE_SCHEMA_VERSION" \
    --arg compatibility_level "$compatibility_level" \
    --arg architecture "$A3S_SYSTEM_IMAGE_ARCHITECTURE" \
    --arg image_sha256 "$image_sha256" \
    --arg archive_sha256 "$archive_sha256" \
    --arg filesystem_uuid "$A3S_SYSTEM_IMAGE_FILESYSTEM_UUID" \
    --arg filesystem_label "$filesystem_label" \
    --arg directory_hash_seed "$A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED" \
    --arg alpine_url "$A3S_SYSTEM_IMAGE_ALPINE_URL" \
    --arg alpine_sha256 "$A3S_SYSTEM_IMAGE_ALPINE_SHA256" \
    --arg agent_sha256 "$agent_sha256" \
    --arg e2fsprogs_version "$e2fsprogs_version" \
    --argjson image_size "$image_size" \
    --argjson archive_size "$archive_size" \
    --argjson alpine_size "$A3S_SYSTEM_IMAGE_ALPINE_SIZE" \
    --argjson agent_size "$agent_size" \
    --argjson source_date_epoch "$source_date_epoch" \
    --argjson runtime "$A3S_SYSTEM_IMAGE_RUNTIME_JSON" \
    '{
      schema_version: $schema_version,
      compatibility_level: $compatibility_level,
      architecture: $architecture,
      image: {
        name: "a3s-oci-system.ext4",
        size: $image_size,
        sha256: $image_sha256,
        archive_name: "a3s-oci-system.ext4.xz",
        archive_size: $archive_size,
        archive_sha256: $archive_sha256,
        filesystem: "ext4",
        filesystem_uuid: $filesystem_uuid,
        filesystem_label: $filesystem_label,
        directory_hash_seed: $directory_hash_seed
      },
      sources: {
        alpine: {
          version: "3.22.5",
          url: $alpine_url,
          archive_size: $alpine_size,
          archive_sha256: $alpine_sha256
        },
        agent: {
          version: "0.2.0",
          size: $agent_size,
          sha256: $agent_sha256
        },
        builder: {
          source_date_epoch: $source_date_epoch,
          e2fsprogs_version: $e2fsprogs_version
        }
      },
      runtime: $runtime
    }' > "$output_dir/system-image.json"

  printf 'system image: %s\n' "$image_sha256"
  printf 'compressed archive: %s\n' "$archive_sha256"
  printf 'manifest: %s\n' "$(sha256sum "$output_dir/system-image.json" | cut -d ' ' -f 1)"

  rm -rf -- "$temporary"
  trap - EXIT
}
