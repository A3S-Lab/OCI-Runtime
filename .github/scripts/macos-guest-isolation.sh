#!/usr/bin/env bash
set -Eeuo pipefail

: "${RUNNER_TEMP:?macOS Guest isolation requires RUNNER_TEMP}"
: "${A3S_OCI_MACOS_SYSTEM_IMAGE_MANIFEST:?set the exact macOS system-image manifest}"

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repository_root"

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  printf '%s\n' 'macOS Guest isolation qualification requires Apple Silicon' >&2
  exit 2
fi
for command in chmod find jq mkdir sort sysctl uname; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required macOS Guest isolation command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

rootfs_archive="$RUNNER_TEMP/alpine-minirootfs-3.22.5-aarch64.tar.gz"
signed_dir="$RUNNER_TEMP/a3s-oci-agent-vm-signed"
bootstrap="$RUNNER_TEMP/a3s-oci-guest-isolation-bootstrap"
runtime_share="$RUNNER_TEMP/a3s-oci-guest-isolation-share"
bundle="$runtime_share/var/lib/a3s-oci-guest-isolation/bundle"
marker="$bundle/rootfs/.a3s-oci-create-start-smoke"
console="$RUNNER_TEMP/a3s-oci-guest-isolation.log"
system_image_manifest="$A3S_OCI_MACOS_SYSTEM_IMAGE_MANIFEST"
cli="target/debug/a3s-oci"
shim="$signed_dir/a3s-oci-krun-shim"

test -x "$cli"
test -x "$shim"
test -x scripts/prepare-utility-vm-bundle.sh
test -f "$rootfs_archive"
test -f "$system_image_manifest"
test ! -L "$system_image_manifest"
mkdir "$bootstrap" "$runtime_share"
mkdir "$runtime_share/run"
chmod 0700 "$bootstrap" "$runtime_share" "$runtime_share/run"
scripts/prepare-utility-vm-bundle.sh \
  --alpine-archive "$rootfs_archive" \
  --config fixtures/utility-vm/config.json \
  --bundle "$bundle" \
  --cgroups-path a3s-oci-macos-guest-isolation

endpoint_baseline="$(
  find /private/tmp -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
)"
set +e
output="$(
  "$cli" oci-vm-guest-isolation-smoke \
    --shim "$shim" \
    --vm-rootfs "$bootstrap" \
    --system-image-manifest "$system_image_manifest" \
    --runtime-share "$runtime_share" \
    --bundle "$bundle" \
    --console "$console"
)"
status=$?
set -e
printf '%s\n' "$output"

support="$(sysctl -n kern.hv_support 2>/dev/null || printf unavailable)"
if [[ "$support" == "1" ]]; then
  test "$status" -eq 0
  jq --exit-status \
    '.schema_version == "a3s.oci.oci-vm-guest-isolation.v1"
     and .platform == "macos" and .status == "available"
     and .bundle_loaded and .separate_runtime_share
     and .expected_case_count == 10 and (.cases | length) == 10
     and [.cases[].name] == [
       "bundle-system-directory",
       "bundle-runtime-share-root",
       "bundle-agent-state-root",
       "absolute-rootfs",
       "rootfs-symlink-escape",
       "absolute-bind-source",
       "relative-bind-traversal",
       "bind-source-symlink-escape",
       "file-intermediate-magic-link-escape",
       "filesystem-intermediate-magic-link-escape"
     ]
     and all(.cases[];
       .expected_error_code == "permission-denied"
       and .request_rejected
       and .observed_error_code == .expected_error_code
       and .observed_error_operation == .expected_error_operation
       and (.observed_error_retryable | not)
       and .container_state_absent_after_case
       and .canary_unchanged)
     and .fixture_removed and .canary_removed
     and .guest_runtime_clean
     and .bridge.platform == "macos"
     and .bridge.status == "available"
     and .bridge.protocol_negotiated
     and .bridge.selected_protocol == 10
     and .bridge.guest_architecture == "aarch64"
     and .bridge.shim_report_verified
     and .bridge.shim_exit_code == 0
     and .bridge.macos_cleanup.endpoint_removed
     and .bridge.macos_cleanup.shim_reaped
     and .bridge.macos_cleanup.bridge_reaped
     and .bridge.macos_cleanup.descriptor_inventory_restored
     and (.bridge.macos_cleanup.open_descriptors_before
          == .bridge.macos_cleanup.open_descriptors_after)
     and (.bridge.macos_cleanup.reason == null)
     and (.reason == null)' <<<"$output" >/dev/null
else
  test "$status" -eq 2
  jq --exit-status \
    '.schema_version == "a3s.oci.oci-vm-guest-isolation.v1"
     and .platform == "macos" and .status == "unavailable"
     and .bundle_loaded and .separate_runtime_share
     and .expected_case_count == 10 and .cases == []
     and .fixture_removed and .canary_removed
     and .guest_runtime_clean
     and .bridge.platform == "macos"
     and .bridge.status == "unavailable"
     and .bridge.macos_cleanup.endpoint_removed
     and .bridge.macos_cleanup.shim_reaped
     and .bridge.macos_cleanup.bridge_reaped
     and .bridge.macos_cleanup.descriptor_inventory_restored
     and (.bridge.macos_cleanup.open_descriptors_before
          == .bridge.macos_cleanup.open_descriptors_after)
     and (.bridge.macos_cleanup.reason == null)
     and (.reason | length > 0)' <<<"$output" >/dev/null
fi

endpoint_after="$(
  find /private/tmp -maxdepth 1 -name 'a3s-oci-agent-*' -print | sort
)"
test "$endpoint_after" = "$endpoint_baseline"
test -z "$(find "$bootstrap" -mindepth 1 -print -quit)"
test -z "$(find "$runtime_share/run" -mindepth 1 -print -quit)"
test -z "$(
  find "$runtime_share" -name '.a3s-oci-guest-isolation-*' -print -quit
)"
test ! -e "$marker"
