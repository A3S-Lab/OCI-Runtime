#!/usr/bin/env bash

set -euo pipefail

host_triple="$(rustc -vV | sed -n 's/^host: //p')"
rust_lld="$(
  rustc --print sysroot
)/lib/rustlib/$host_triple/bin/rust-lld"
if [[ ! -x "$rust_lld" ]]; then
  echo "Rust linker is unavailable: $rust_lld" >&2
  exit 1
fi

CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$rust_lld" \
  cargo build -p a3s-oci-agent --release \
    --target x86_64-unknown-linux-musl
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$rust_lld" \
  cargo build -p a3s-oci-agent --release \
    --target aarch64-unknown-linux-musl
