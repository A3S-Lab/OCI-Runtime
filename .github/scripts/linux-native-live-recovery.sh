#!/usr/bin/env bash
# Opt-in Native Linux Live Host reopen evidence wrapper.
#
# Distinct from stopped-only native-linux-recovery. Requires
# A3S_OCI_NATIVE_SESSION_SUPERVISOR=1 for the eventual greened harness.
#
# TODO(evidence): implement create → upload → Host SIGKILL → Running reattach →
# download under schema a3s.oci.linux-native-live-recovery-smoke.v1. Product
# path and unit tests land first; this script currently fails closed.
set -Eeuo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Native Linux Live recovery qualification requires a Linux host\n' >&2
  exit 2
fi

export A3S_OCI_NATIVE_SESSION_SUPERVISOR="${A3S_OCI_NATIVE_SESSION_SUPERVISOR:-1}"

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$PWD/$target_dir"
fi
profile="${A3S_OCI_BUILD_PROFILE:-debug}"
cli="$target_dir/$profile/a3s-oci"

if [[ ! -x "$cli" ]]; then
  cargo build -p a3s-oci-cli
fi

temporary_root="${RUNNER_TEMP:-/tmp}"
work="$(mktemp -d "$temporary_root/a3s-oci-nlr.XXXXXX")"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

report_path="${A3S_OCI_LINUX_NATIVE_LIVE_RECOVERY_REPORT:-$work/report.json}"
bundle="${A3S_OCI_NATIVE_LIVE_BUNDLE:?set A3S_OCI_NATIVE_LIVE_BUNDLE to an OCI bundle directory}"
agent="${A3S_OCI_NATIVE_AGENT:-$target_dir/$profile/a3s-oci-agent}"
source_revision="$(git rev-parse HEAD)"

set +e
"$cli" linux-native-live-recovery-smoke \
  --agent "$agent" \
  --bundle "$bundle" \
  --work-parent "$work" \
  --source-revision "$source_revision" \
  >"$report_path"
status=$?
set -e

if [[ -s "$report_path" ]]; then
  jq --compact-output '{schema_version, status, reason, recovery}' "$report_path" >&2 || true
fi

printf 'Native Linux Live recovery harness is a fail-closed stub until evidence lands (exit %s)\n' \
  "$status" >&2
exit 2
