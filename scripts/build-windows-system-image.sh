#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/build-system-image.sh
source "$script_directory/lib/build-system-image.sh"

export A3S_SYSTEM_IMAGE_SCHEMA_VERSION='a3s.oci.windows-system-image.v1'
export A3S_SYSTEM_IMAGE_ARCHITECTURE='x86_64'
export A3S_SYSTEM_IMAGE_ELF_PATTERN='ELF 64-bit.*x86-64.*(static-pie|statically) linked'
export A3S_SYSTEM_IMAGE_ALPINE_URL='https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.5-x86_64.tar.gz'
export A3S_SYSTEM_IMAGE_ALPINE_SHA256='4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282'
export A3S_SYSTEM_IMAGE_ALPINE_SIZE=3638276
export A3S_SYSTEM_IMAGE_FILESYSTEM_UUID='a3a30c1a-2026-4000-8000-000000000011'
export A3S_SYSTEM_IMAGE_DIRECTORY_HASH_SEED='a3a30c1a-2026-4000-8000-000000000012'
export A3S_SYSTEM_IMAGE_RUNTIME_JSON='{
  "archive_size": 8106464,
  "archive_sha256": "ce178184bc9e309c9f8fef181312cd6c398fc825807124e31afab949b790627e",
  "krun_dll": {
    "name": "krun.dll",
    "size": 7428608,
    "sha256": "f21293b65ee16058c9014b543c708d84c50dc28d7775dbd77bac32faabafa59e"
  },
  "import_library": {
    "name": "krun.lib",
    "size": 11870,
    "sha256": "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d"
  },
  "firmware": {
    "name": "libkrunfw.dll",
    "size": 21473280,
    "sha256": "44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077"
  },
  "sources": {
    "box_revision": "93fc281a798cdfd8ee463f69add3f6989d561ee3",
    "libkrun_revision": "dc5519faeabd8bf38d984ed29c44e6da977f0b5c",
    "firmware_wrapper_revision": "2692169b7567363244fdd21cb83de3220ebf3021",
    "libkrunfw_revision": "ec4b297964877d83432f9ccda6dad8ff6e9de3e4",
    "kernel_version": "6.12.91",
    "kernel_source_sha256": "0ff2ab9e169f9f1948557471fbb450d3018f8c5b77caf288e1a3982582597969"
  },
  "kernel": {
    "bundle_size": 21364736,
    "bundle_sha256": "781375ea09f4279ec5bfeab26ecc7067358a3fc98190467e2ab01cc6e98936dd",
    "guest_load_address": "0x0000000001000000",
    "entry_address": "0x0000000001000123"
  }
}'

a3s_build_system_image "$@"
