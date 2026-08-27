#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 <elf-artifact>..." >&2
  exit 2
fi

command -v file >/dev/null
command -v readelf >/dev/null

for artifact in "$@"; do
  if [[ ! -f "$artifact" ]]; then
    echo "static ELF artifact is missing: $artifact" >&2
    exit 1
  fi

  description="$(LC_ALL=C file "$artifact")"
  printf '%s\n' "$description"
  case "$description" in
    *"statically linked"* | *"static-pie linked"*) ;;
    *)
      echo "artifact is not statically linked: $artifact" >&2
      exit 1
      ;;
  esac

  program_headers="$(LC_ALL=C readelf --program-headers "$artifact")"
  if [[ "$program_headers" == *INTERP* ]]; then
    echo "artifact contains a dynamic interpreter: $artifact" >&2
    exit 1
  fi

  dynamic_section="$(LC_ALL=C readelf --dynamic "$artifact" 2>&1 || true)"
  if [[ "$dynamic_section" == *NEEDED* ]]; then
    echo "artifact contains a dynamic dependency: $artifact" >&2
    exit 1
  fi
done
