#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -lt 2 ]]; then
  echo "usage: $0 <musl-target> <cargo-package>..." >&2
  exit 2
fi

target="$1"
shift

case "$target" in
  x86_64-unknown-linux-musl)
    linker_environment="CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER"
    ;;
  aarch64-unknown-linux-musl)
    linker_environment="CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"
    ;;
  *)
    echo "unsupported static Linux target: $target" >&2
    exit 2
    ;;
esac

host_triple="$(rustc -vV | sed -n 's/^host: //p')"
rust_lld="$(
  rustc --print sysroot
)/lib/rustlib/$host_triple/bin/rust-lld"
if [[ ! -x "$rust_lld" ]]; then
  echo "Rust linker is unavailable: $rust_lld" >&2
  exit 1
fi

package_arguments=()
for package in "$@"; do
  if [[ -z "$package" || "$package" == -* ]]; then
    echo "invalid Cargo package name: $package" >&2
    exit 2
  fi
  package_arguments+=(--package "$package")
done

env "$linker_environment=$rust_lld" \
  cargo build --release --target "$target" "${package_arguments[@]}"
