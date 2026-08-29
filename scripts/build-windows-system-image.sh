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
  "archive_size": 8967364,
  "archive_sha256": "5650721e43c2a1825314367d60bc2bdace2a88be4a424ba42711f9580c4b69af",
  "krun_dll": {
    "name": "krun.dll",
    "size": 7579648,
    "sha256": "cc18d354fec2c235fdce53b723b96dccb2ef3994a7dda141c923a0efa0bba7db"
  },
  "import_library": {
    "name": "krun.lib",
    "size": 11870,
    "sha256": "3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d"
  },
  "firmware": {
    "name": "libkrunfw.dll",
    "size": 29413376,
    "sha256": "295e8a8e660f396fd0007d48c43175d9ed5b19243570640ad65fc47b41e7596a"
  },
  "sources": {
    "box_revision": "93fc281a798cdfd8ee463f69add3f6989d561ee3",
    "libkrun_revision": "de07dd8a4f94b1e5f70ce2d8e3f99359b3a02eb9",
    "firmware_wrapper_revision": "10dca312c63080916dbb456c3a019dba3e8b4da0",
    "libkrunfw_revision": "ec4b297964877d83432f9ccda6dad8ff6e9de3e4",
    "kernel_version": "6.12.91",
    "kernel_source_sha256": "0ff2ab9e169f9f1948557471fbb450d3018f8c5b77caf288e1a3982582597969"
  },
  "kernel": {
    "bundle_size": 23158784,
    "bundle_sha256": "1c211df81b481a906409cb32f25f392577389a2f5ccf48bc2dd913bb64a1f6b4",
    "guest_load_address": "0x0000000001000000",
    "entry_address": "0x0000000001000123"
  }
}'

a3s_build_system_image "$@"
