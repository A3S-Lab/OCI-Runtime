#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/build-system-image.sh
source "$script_directory/lib/build-system-image.sh"

export A3S_SYSTEM_IMAGE_SCHEMA_VERSION='a3s.oci.macos-system-image.v1'
export A3S_SYSTEM_IMAGE_ARCHITECTURE='aarch64'
export A3S_SYSTEM_IMAGE_ELF_PATTERN='ELF 64-bit.*ARM aarch64.*statically linked'
export A3S_SYSTEM_IMAGE_ALPINE_URL='https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz'
export A3S_SYSTEM_IMAGE_ALPINE_SHA256='3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70'
export A3S_SYSTEM_IMAGE_ALPINE_SIZE=3966256
export A3S_SYSTEM_IMAGE_FILESYSTEM_UUID='a3a30c1a-2026-4000-8000-000000000001'
export A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED='a3a30c1a-2026-4000-8000-000000000002'
export A3S_SYSTEM_IMAGE_RUNTIME_JSON='{
  "archive_sha256": "5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56",
  "libkrun_sha256": "c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d",
  "firmware_sha256": "841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4",
  "kernel_bundle_size": 22740992,
  "kernel_bundle_sha256": "b1180b50148ed14f5fbeadf17288ce8abcf245daa468255b7ff41113bbf01199",
  "kernel_guest_load_address": "0x0000000080000000",
  "kernel_entry_address": "0x0000000080000000"
}'

a3s_build_system_image "$@"
