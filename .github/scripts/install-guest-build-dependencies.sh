#!/usr/bin/env bash

set -euo pipefail

readonly max_attempts=3
readonly -a packages=(
  binutils
  e2fsprogs
  file
  jq
  musl-tools
  xz-utils
)

for ((attempt = 1; attempt <= max_attempts; attempt += 1)); do
  if sudo timeout --signal=TERM --kill-after=30s 120s \
    apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=60 update \
    && sudo timeout --signal=TERM --kill-after=30s 300s \
      apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=60 \
        install --yes --no-install-recommends "${packages[@]}"; then
    exit 0
  fi

  if ((attempt == max_attempts)); then
    echo "failed to install guest build dependencies after ${max_attempts} attempts" >&2
    exit 1
  fi

  sleep "$((attempt * 10))"
done
