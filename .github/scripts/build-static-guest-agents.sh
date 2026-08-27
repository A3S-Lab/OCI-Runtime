#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

"$script_directory/build-static-musl.sh" \
  x86_64-unknown-linux-musl \
  a3s-oci-agent
"$script_directory/build-static-musl.sh" \
  aarch64-unknown-linux-musl \
  a3s-oci-agent
