#!/usr/bin/env bash

set -euo pipefail

runner_temp="${RUNNER_TEMP:?RUNNER_TEMP must identify the CI job temporary directory}"
run_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID must identify the CI run}"
run_attempt="${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT must identify the CI attempt}"

sudo apt-get update
sudo apt-get install --yes busybox-static jq
cargo build -p a3s-oci-agent -p a3s-oci-cli

bundle="$runner_temp/a3s-native-bundle"
work_parent="$runner_temp/a3s-native-work"
mkdir -p "$bundle/rootfs/bin" "$work_parent"
cp fixtures/native-linux/config.json "$bundle/config.json"
cp "$(command -v busybox)" "$bundle/rootfs/bin/busybox"
ln -s busybox "$bundle/rootfs/bin/sh"

run_smoke() {
  local expected_kvm_present="$1"
  local output
  output="$(sudo "$PWD/target/debug/a3s-oci" native-linux-smoke \
    --agent "$PWD/target/debug/a3s-oci-agent" \
    --bundle "$bundle" \
    --work-parent "$work_parent")"
  printf '%s\n' "$output"
  jq --exit-status \
    --argjson expected "$expected_kvm_present" \
    '.status == "available" and .kvm_device_present == $expected' \
    <<<"$output" >/dev/null
}

saved_kvm="/dev/a3s-oci-kvm-${run_id}-${run_attempt}"
restore_kvm() {
  if [[ -d /dev/kvm ]]; then
    sudo rmdir /dev/kvm
  fi
  if [[ -e "$saved_kvm" || -L "$saved_kvm" ]]; then
    sudo mv "$saved_kvm" /dev/kvm
  fi
}
trap restore_kvm EXIT

if [[ -e /dev/kvm || -L /dev/kvm ]]; then
  sudo mv /dev/kvm "$saved_kvm"
fi

run_smoke false
sudo mkdir /dev/kvm
run_smoke true
