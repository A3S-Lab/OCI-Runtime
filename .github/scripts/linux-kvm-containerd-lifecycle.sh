#!/usr/bin/env bash
set -Eeuo pipefail

# Linux KVM + containerd dedicated-vm vertical slice.
# Observation-only: does not promote readiness or close fresh-host/AArch64.

: "${A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST:?set the exact Linux KVM system-image manifest}"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'Linux KVM containerd lifecycle requires a Linux host\n' >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  printf 'Linux KVM containerd lifecycle must run as root\n' >&2
  exit 2
fi

for command in cargo containerd ctr jq mkdir mktemp rm sha256sum systemctl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required command unavailable: %s\n' "$command" >&2
    exit 1
  fi
done

temporary_root="${RUNNER_TEMP:-/tmp}"
test -d "$temporary_root"
work="$(mktemp -d "$temporary_root/a3s-oci-kvm-containerd.XXXXXX")"
report_path="${A3S_OCI_LINUX_KVM_CONTAINERD_REPORT:-$work/report.json}"
if [[ -e "$report_path" || -L "$report_path" ]]; then
  printf 'refusing to overwrite report: %s\n' "$report_path" >&2
  exit 1
fi
test -d "$(dirname "$report_path")"

unit_name=""
host_pid=""
cleanup() {
  local status=$?
  if [[ -n "$host_pid" ]] && kill -0 "$host_pid" 2>/dev/null; then
    kill -TERM "$host_pid" 2>/dev/null || true
    wait "$host_pid" 2>/dev/null || true
  fi
  if [[ -n "$unit_name" ]]; then
    systemctl stop "$unit_name" 2>/dev/null || true
    systemctl disable "$unit_name" 2>/dev/null || true
    rm -f "/etc/systemd/system/${unit_name}.service"
    systemctl daemon-reload 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 && "${A3S_OCI_KEEP_FAILED_WORK:-0}" == "1" ]]; then
    printf 'preserving failed work directory: %s\n' "$work" >&2
    return 0
  fi
  case "$work" in
    "$temporary_root"/a3s-oci-kvm-containerd.*)
      rm -rf -- "$work"
      ;;
  esac
}
trap cleanup EXIT

chmod 0700 "$work"
mkdir -m 0700 "$work/host" "$work/containerd" "$work/bin" "$work/path"

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$PWD/$target_dir"
fi
profile="${A3S_OCI_BUILD_PROFILE:-debug}"
build_args=(build -p a3s-oci-cli -p a3s-oci-krun -p a3s-oci-containerd-shim)
case "$profile" in
  debug) ;;
  release) build_args+=(--release) ;;
  *) build_args+=(--profile "$profile") ;;
esac
cargo "${build_args[@]}"
case "$profile" in
  release)
    cargo test -p a3s-oci-containerd-shim --test containerd_runtime_v2 --release --no-run
    ;;
  debug)
    cargo test -p a3s-oci-containerd-shim --test containerd_runtime_v2 --no-run
    ;;
  *)
    cargo test -p a3s-oci-containerd-shim --test containerd_runtime_v2 --profile "$profile" --no-run
    ;;
esac

cli="$target_dir/$profile/a3s-oci"
krun_shim="$target_dir/$profile/a3s-oci-krun-shim"
krun_runtime="$target_dir/$profile/a3s-oci-krun-runtime"
ctrd_shim="$(find "$target_dir/$profile/deps" -maxdepth 1 -type f -name 'containerd_runtime_v2-*' ! -name '*.d' | sort | tail -n 1)"
shim_bin="$target_dir/$profile/containerd-shim-a3s-oci-v2"
test -x "$cli"
test -x "$krun_shim"
test -d "$krun_runtime"
test -x "$shim_bin"
test -n "$ctrd_shim" && test -x "$ctrd_shim"

cp -p "$cli" "$work/bin/a3s-oci"
cp -p "$krun_shim" "$work/bin/a3s-oci-krun-shim"
cp -a "$krun_runtime" "$work/bin/a3s-oci-krun-runtime"
cp -p "$shim_bin" "$work/path/containerd-shim-a3s-oci-v2"
chmod 0700 "$work/bin/a3s-oci" "$work/bin/a3s-oci-krun-shim" "$work/path"/*
export LD_LIBRARY_PATH="$work/bin/a3s-oci-krun-runtime${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# A stale absolute binary at the filesystem root hijacks LookPath when PATH
# contains an empty component or cwd is /. Never let that shadow the gate shim.
if [[ -e /containerd-shim-a3s-oci-v2 || -L /containerd-shim-a3s-oci-v2 ]]; then
  printf 'removing hijacking shim at /containerd-shim-a3s-oci-v2\n' >&2
  rm -f /containerd-shim-a3s-oci-v2
fi

# Private containerd with KillMode=process (shim survives daemon restart).
ctrd_root="$work/containerd/root"
ctrd_state="$work/containerd/state"
mkdir -m 0700 "$ctrd_root" "$ctrd_state"
sock="$work/containerd/containerd.sock"
ttrpc="$work/containerd/containerd.sock.ttrpc"
config="$work/containerd/config.toml"
shim_path_env="$work/path:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
cat >"$config" <<EOF
version = 2
root = "$ctrd_root"
state = "$ctrd_state"
[grpc]
  address = "$sock"
[plugins."io.containerd.grpc.v1.cri"]
  disable_tcp_service = true
[plugins."io.containerd.shim.v1.manager"]
  env = ["A3S_OCI_RUNTIME_ENDPOINT=$work/host/runtime.sock", "A3S_OCI_RUNTIME_ROOT=$work/host/runtime", "PATH=$shim_path_env"]
EOF

unit_name="a3s-oci-kvm-ctrd-$(basename "$work")"
cat >"/etc/systemd/system/${unit_name}.service" <<EOF
[Unit]
Description=A3S OCI private containerd for Linux KVM dedicated-vm qualification
[Service]
Type=notify
ExecStart=/usr/bin/containerd --config $config
KillMode=process
Delegate=yes
Environment=PATH=$shim_path_env
Environment=A3S_OCI_RUNTIME_ENDPOINT=$work/host/runtime.sock
Environment=A3S_OCI_RUNTIME_ROOT=$work/host/runtime
Environment=LD_LIBRARY_PATH=$work/bin/a3s-oci-krun-runtime
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$unit_name"
for _ in $(seq 1 80); do
  if [[ -S "$sock" ]]; then
    break
  fi
  sleep 0.25
done
test -S "$sock"
# Ensure Transient=no / FragmentPath for restart-safe units (not required for this slice).
systemctl show -p FragmentPath -p Transient -p KillMode "$unit_name" | tee "$work/unit.props" >/dev/null
grep -q '^KillMode=process$' "$work/unit.props"
grep -q '^Transient=no$' "$work/unit.props"

# Load busybox into the private daemon (pull, else import a local OCI archive).
image_ref="${A3S_OCI_CONTAINERD_IMAGE:-docker.io/library/busybox:latest}"
image_tar="${A3S_OCI_CONTAINERD_IMAGE_TAR:-}"
if [[ -z "$image_tar" && -f /tmp/a3s-oci-image-cache/busybox-latest.tar ]]; then
  image_tar=/tmp/a3s-oci-image-cache/busybox-latest.tar
fi
if ! ctr --address "$sock" images pull "$image_ref" >/dev/null 2>"$work/image-pull.err"; then
  if [[ -n "$image_tar" && -s "$image_tar" ]]; then
    ctr --address "$sock" images import "$image_tar" >/dev/null
  else
    cat "$work/image-pull.err" >&2 || true
    printf 'failed to pull %s and no usable A3S_OCI_CONTAINERD_IMAGE_TAR\n' "$image_ref" >&2
    exit 1
  fi
fi

# KVM Host Service (dedicated-vm only).
nohup "$work/bin/a3s-oci" box-kvm-qualification-service \
  --root "$work/host" \
  --shim "$work/bin/a3s-oci-krun-shim" \
  --system-image-manifest "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" \
  >"$work/host-service.log" 2>&1 &
host_pid=$!
echo "$host_pid" >"$work/host-service.pid"
for _ in $(seq 1 120); do
  if [[ -S "$work/host/runtime.sock" ]]; then
    break
  fi
  if ! kill -0 "$host_pid" 2>/dev/null; then
    printf 'Host Service exited early\n' >&2
    tail -40 "$work/host-service.log" >&2 || true
    exit 1
  fi
  sleep 0.25
done
test -S "$work/host/runtime.sock"

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
set +e
A3S_OCI_CONTAINERD_QUALIFY=1 \
A3S_OCI_CONTAINERD_ALLOW_RESTART=1 \
A3S_OCI_CONTAINERD_SOCKET="$sock" \
CONTAINERD_ADDRESS="$sock" \
A3S_OCI_CONTAINERD_TTRPC_ADDRESS="$ttrpc" \
A3S_OCI_CONTAINERD_STATE_ROOT="$ctrd_state/io.containerd.runtime.v2.task" \
A3S_OCI_RUNTIME_ENDPOINT="$work/host/runtime.sock" \
A3S_OCI_CONTAINERD_SERVICE="$unit_name" \
A3S_OCI_CONTAINERD_IMAGE=docker.io/library/busybox:latest \
A3S_OCI_CONTAINERD_RUNTIME=io.containerd.a3s-oci.v2 \
"$ctrd_shim" --ignored --exact real_containerd_linux_kvm_dedicated_vm_lifecycle --nocapture \
  >"$work/test.log" 2>&1
status=$?
set -e
completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

manifest_sha256="$(sha256sum "$A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST" | cut -d ' ' -f 1)"
source_commit="${A3S_QUALIFICATION_SOURCE_COMMIT:-}"
if [[ -z "$source_commit" ]]; then
  source_commit="$(
    git -c safe.directory="$PWD" rev-parse HEAD 2>/dev/null \
      || printf 'unknown'
  )"
fi
result="failed"
if [[ "$status" -eq 0 ]]; then
  result="passed"
fi

jq -n \
  --arg schema_version "a3s.oci.linux-kvm-containerd-lifecycle.v1" \
  --arg result "$result" \
  --argjson exit_status "$status" \
  --arg started_at "$started_at" \
  --arg completed_at "$completed_at" \
  --arg source_commit "$source_commit" \
  --arg manifest_sha256 "$manifest_sha256" \
  --arg containerd_version "$(containerd --version | head -n 1)" \
  --arg host_class "existing" \
  --argjson promotes_readiness false \
  --arg test_log "$work/test.log" \
  '{
    schema_version: $schema_version,
    result: $result,
    exit_status: $exit_status,
    started_at: $started_at,
    completed_at: $completed_at,
    source_commit: $source_commit,
    system_image_manifest_sha256: $manifest_sha256,
    containerd_version: $containerd_version,
    host_class: $host_class,
    promotes_readiness: $promotes_readiness,
    isolation: "dedicated-vm",
    driver: "libkrun-kvm",
    claim_effect: "observation-only",
    reason: (if $result == "passed"
      then "existing-host containerd dedicated-vm lifecycle passed; does not promote readiness"
      else "dedicated-vm containerd lifecycle failed; see test log"
      end)
  }' >"$report_path"

if [[ "$status" -ne 0 ]]; then
  printf 'dedicated-vm containerd lifecycle failed; log tail:\n' >&2
  tail -60 "$work/test.log" >&2 || true
  exit "$status"
fi

printf 'Linux KVM containerd dedicated-vm lifecycle passed: %s\n' "$report_path"
sha256sum "$report_path"
