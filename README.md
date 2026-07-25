# A3S OCI Runtime

<p align="center">
  <strong>Cross-Platform OCI Runtime for A3S</strong>
</p>

<p align="center">
  <em>Run one reviewed Linux container executor natively on Linux or inside utility VMs on macOS and Windows</em>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#runtime-model">Runtime Model</a> •
  <a href="#platform-status">Platform Status</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#development">Development</a>
</p>

---

## Overview

**A3S OCI Runtime** is the low-level execution boundary for Linux OCI
workloads across Linux, macOS, and Windows. It is designed to replace A3S
Box's direct dependency on an external `crun` binary while keeping image
management, builds, volumes, networks, and product policy in A3S Box.

The release target is complete
[OCI Runtime Specification 1.3.0](https://github.com/opencontainers/runtime-spec)
conformance for every Linux-container requirement and every advertised driver.
The public SDK carries the official OCI `Spec`, `Process`, `LinuxResources`,
`State`, and `Features` models without translating them into a reduced A3S
profile.

The runtime has two execution paths:

- **Native Linux** runs the reviewed namespace and mount profile with
  PID-reuse-safe process control without requiring KVM. Complete cgroup,
  seccomp, capability, and supervision enforcement remains a release gate.
- **Utility VM** hosts the same Linux executor behind an authenticated guest
  agent, using KVM on Linux, HVF on macOS, or WHPX on Windows.

The project is under active development. Host capability, driver maturity, and
effective isolation are reported separately so a working hypervisor probe can
never be mistaken for a production-ready workload driver.

### Basic usage

Feature discovery is available through the transport-independent Rust SDK:

```rust,no_run
use a3s_oci_runtime::HostRuntimeService;
use a3s_oci_sdk::RuntimeClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> a3s_oci_sdk::Result<()> {
    let client = RuntimeClient::new(HostRuntimeService::new());
    let features = client.features().await?;

    println!("{:?}", features.platform);
    for driver in features.drivers {
        println!(
            "{:?}: host={:?}, readiness={:?}",
            driver.driver, driver.status, driver.readiness
        );
    }
    Ok(())
}
```

Normal discovery exposes only operations backed by the selected implementation.
Workload calls require an explicitly supplied launch-ready `RuntimeDriver`.

## Features

- **Complete OCI Types**: Preserve official OCI runtime models and exact
  accepted `config.json` text across SDK and wire boundaries
- **Strict Validation**: Validate OCI 1.0.0 through 1.3.0 schemas, semantic
  relationships, paths, payload bounds, and immutable SHA-256 digests before
  state mutation
- **Durable Lifecycle**: Persist create, start, kill, and delete with monotonic
  generations, operation IDs, replay, fencing, reconciliation, and quarantine;
  expose driver-backed state and stable init-process exit status
- **Shared Linux Executor**: Reuse one fail-closed namespace, mount, pidfd
  process-control, exit-status, and cleanup implementation directly on Linux
  and through the guest agent, with independently fenced per-container
  generations
- **Cross-Platform Drivers**: Inspect native Linux, KVM, HVF, and WHPX
  prerequisites without silently weakening requested isolation
- **Typed SDK and IPC**: Expose an async `Send + Sync` Rust contract with
  bounded local IPC over Unix sockets or Windows named pipes
- **Authenticated Guest Protocol**: Bind exact bundles and generations to a
  version-negotiated host/guest session with one-time token authentication
- **Retained Conformance Evidence**: Lock the OCI schemas and normative
  requirement inventory in CI so unreviewed coverage changes fail closed

### Driver readiness

Host availability and implementation readiness are independent:

| Readiness | Workload launch | Meaning |
| --- | --- | --- |
| `probe-only` | Forbidden | Platform discovery or diagnostic smoke only |
| `experimental` | Explicit opt-in | Reviewed development profile with incomplete certification |
| `supported` | Allowed | Certified runtime profile |

`DriverCapability::can_launch()` requires both an available host capability and
`experimental` or `supported` readiness.

### Isolation classes

| Isolation | Boundary | Kernel sharing |
| --- | --- | --- |
| `dedicated-vm` | Hardware VM | One workload or pod owns the guest kernel |
| `shared-guest-kernel` | Hardware VM | One trust domain shares a guest Linux kernel |
| `shared-host-kernel` | No VM boundary | Containers share the Linux host kernel |

Windows and macOS cannot provide `shared-host-kernel` for Linux workloads.
Native Linux does not require KVM. An unavailable `dedicated-vm` request fails
before runtime state, image, or driver mutation.

## Quick Start

### Build and inspect

```sh
git clone git@github.com:A3S-Lab/OCI-Runtime.git
cd OCI-Runtime

cargo run -p a3s-oci-cli -- features
```

The command emits versioned JSON. A driver can report an available host
prerequisite while remaining `probe-only`.

### Native Linux lifecycle

The explicit rootful development driver proves the current OCI
create/start/kill/wait/delete vertical slice without opening `/dev/kvm` or
initializing libkrun:

```sh
sudo apt-get install busybox-static
cargo build -p a3s-oci-agent -p a3s-oci-cli

demo_root="$(mktemp -d)"
bundle="$demo_root/bundle"
work_parent="$demo_root/work"
mkdir -p "$bundle/rootfs/bin" "$bundle/rootfs/proc" "$work_parent"
cp fixtures/native-linux/config.json "$bundle/config.json"
cp "$(command -v busybox)" "$bundle/rootfs/bin/busybox"
ln -s busybox "$bundle/rootfs/bin/sh"
sudo chown -R 0:0 "$bundle/rootfs"

sudo target/debug/a3s-oci native-linux-smoke \
  --agent "$PWD/target/debug/a3s-oci-agent" \
  --bundle "$bundle" \
  --work-parent "$work_parent"
```

Success requires the exact create/start barrier, a bounded wait while running,
the exact SIGKILL terminal result and repeated wait, running and stopped
observation, idempotent mutation replay, marker verification, post-delete
`NotFound`, and scoped cleanup. See
[Native Linux Development](docs/linux-native.md) for the accepted profile and
remaining production gates.

Create a second distinct bundle to run the multi-container gate:

```sh
bundle_b="$demo_root/bundle-b"
mkdir -p "$bundle_b/rootfs/bin" "$bundle_b/rootfs/proc"
cp fixtures/native-linux/config.json "$bundle_b/config.json"
cp "$(command -v busybox)" "$bundle_b/rootfs/bin/busybox"
ln -s busybox "$bundle_b/rootfs/bin/sh"
sudo chown -R 0:0 "$bundle_b/rootfs"

sudo target/debug/a3s-oci native-linux-multi-container-smoke \
  --agent "$PWD/target/debug/a3s-oci-agent" \
  --bundle-a "$bundle" \
  --bundle-b "$bundle_b" \
  --work-parent "$work_parent"
```

The versioned report retains two simultaneous create barriers, distinct
positive PIDs, operation replay isolation, A/B lifecycle independence,
nonblocking observation of B while A is being waited on, exact repeated exit
status for both containers, generation-1 rejection after A is recreated as
generation 2, and complete process, marker, executor-root, and durable-session
cleanup.

The separate fault-cleanup diagnostic deliberately stops before OCI delete and
requires executor shutdown to reclaim the live process and all scoped state:

```sh
for fault in after-create after-start after-kill; do
  sudo target/debug/a3s-oci native-linux-fault-cleanup \
    --agent "$PWD/target/debug/a3s-oci-agent" \
    --bundle "$bundle" \
    --work-parent "$work_parent" \
    --fault-after "$fault"
done
```

Each `a3s.oci.native-linux-fault-cleanup.v2` success identifies the exact
injected boundary, records that normal delete was not attempted, and proves
that the init PID, executor root, marker, and complete diagnostic session were
removed.

### macOS host gates

On Apple Silicon, sign a disposable CLI copy with the checked-in Hypervisor
entitlement and exercise the real HVF VM-object lifecycle:

```sh
cargo build -p a3s-oci-cli

smoke_dir="$(mktemp -d)"
cp target/debug/a3s-oci "$smoke_dir/a3s-oci"
codesign --force --sign - \
  --entitlements packaging/macos/a3s-oci-hvf.entitlements \
  "$smoke_dir/a3s-oci"
"$smoke_dir/a3s-oci" hvf-smoke
```

The `a3s.oci.hvf-smoke.v1` report succeeds only when
`hv_vm_create` and `hv_vm_destroy` both complete. An executable without the
entitlement fails closed with `HV_DENIED`.

The isolated shim has a separate libkrun context gate:

```sh
cargo build -p a3s-oci-krun

smoke_dir="$(mktemp -d)"
cp target/debug/a3s-oci-krun-shim "$smoke_dir/"
cp -R target/debug/a3s-oci-krun-runtime "$smoke_dir/"
codesign --force --sign - \
  --entitlements packaging/macos/a3s-oci-hvf.entitlements \
  "$smoke_dir/a3s-oci-krun-shim"
"$smoke_dir/a3s-oci-krun-shim" context-smoke
```

This verifies the checksum-pinned runtime bundle, required libkrun symbols,
context allocation, VM resource configuration, plain-vsock guest port mapping,
and context release.

The VM-entry gate then boots the bundled arm64 kernel with a pinned Alpine
userspace and accepts success only after the guest writes an exact marker into
the shared rootfs:

```sh
rootfs_dir="$(mktemp -d)"
rootfs_archive="$rootfs_dir/alpine-minirootfs-3.22.5-aarch64.tar.gz"
curl --fail --location --output "$rootfs_archive" \
  https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz
printf '%s  %s\n' \
  '3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70' \
  "$rootfs_archive" | shasum -a 256 --check
mkdir "$rootfs_dir/rootfs"
tar -xzf "$rootfs_archive" -C "$rootfs_dir/rootfs"

"$smoke_dir/a3s-oci-krun-shim" vm-smoke \
  --rootfs "$rootfs_dir/rootfs" \
  --console "$rootfs_dir/console.log"
```

Because `krun_start_enter` takes over its process, the command configures and
enters the VM in a private worker, enforces a 30-second bound, reaps the worker,
checks its exit status, verifies and removes the guest marker, and fails closed
when HVF is unavailable. See
[macOS HVF Development](docs/macos-hvf.md) for the exact boundary and retained
evidence.

The authenticated bridge gate installs the static arm64 Linux agent into that
rootfs and exercises the complete host-to-guest negotiation:

```sh
rustup target add aarch64-unknown-linux-musl
host_triple="$(rustc -vV | sed -n 's/^host: //p')"
rust_lld="$(
  rustc --print sysroot
)/lib/rustlib/$host_triple/bin/rust-lld"
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$rust_lld" \
  cargo build -p a3s-oci-agent --release \
    --target aarch64-unknown-linux-musl
cargo build -p a3s-oci-cli

install -d "$rootfs_dir/rootfs/usr/bin"
install -m 0755 \
  target/aarch64-unknown-linux-musl/release/a3s-oci-agent \
  "$rootfs_dir/rootfs/usr/bin/a3s-oci-agent"

target/debug/a3s-oci agent-vm-smoke \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --rootfs "$rootfs_dir/rootfs" \
  --console "$rootfs_dir/agent-console.log"
```

An `a3s.oci.agent-vm-smoke.v4` success proves a private host socket, the
expected shim and direct worker PID relationship, one-time token
authentication, protocol version 2, the arm64 guest identity, and the exact
six guest operations (`create`, `state`, `start`, `kill`, `delete`, and
`wait`). It also requires the exact runtime-owned
endpoint to be removed, the current process's complete descriptor inventory to
return to its pre-session baseline, and both observed host process IDs to
disappear.

The fixed lifecycle gate then runs the same reviewed OCI bundle through HVF
that the Windows qualification runs through WHPX:

```sh
bundle="$rootfs_dir/rootfs/var/lib/a3s-oci-smoke/bundle"
mkdir -p "$bundle/rootfs"
cp fixtures/utility-vm/config.json "$bundle/config.json"
tar -xzf "$rootfs_archive" -C "$bundle/rootfs"
sudo chown -R 0:0 "$bundle/rootfs"

target/debug/a3s-oci oci-vm-smoke \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --vm-rootfs "$rootfs_dir/rootfs" \
  --bundle "$bundle" \
  --console "$rootfs_dir/oci-console.log"
```

Success proves distinct create and start, exact create/kill/delete replay, a
bounded wait while running, exact and replayed normal exit status after the
SIGTERM trap, running and stopped observation, marker verification,
post-delete `NotFound`, and nominal endpoint, process, marker, and
guest-runtime cleanup. This remains a fixed development profile rather than an
arbitrary-workload driver.

The multi-container gate places two distinct bundles in the same guest and
keeps both init processes behind the create barrier:

```sh
bundle_b="$rootfs_dir/rootfs/var/lib/a3s-oci-smoke/bundle-b"
mkdir -p "$bundle_b/rootfs"
cp fixtures/utility-vm/config.json "$bundle_b/config.json"
tar -xzf "$rootfs_archive" -C "$bundle_b/rootfs"
sudo chown -R 0:0 "$bundle_b/rootfs"

target/debug/a3s-oci oci-vm-multi-container-smoke \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --vm-rootfs "$rootfs_dir/rootfs" \
  --bundle-a "$bundle" \
  --bundle-b "$bundle_b" \
  --console "$rootfs_dir/oci-multi-container.log"
```

`a3s.oci.oci-vm-multi-container-smoke.v2` requires that starting, killing,
waiting for, and deleting A never changes or blocks B; both waits return and
replay the exact normal exit status; recreating A advances generation 1 to 2;
stale and cross-container replay requests fail; B then completes
independently; and VM shutdown restores guest-runtime, endpoint, descriptor,
shim, and worker inventories.

Fault cleanup reuses the same signed shim and bundle but stops after each
successful lifecycle boundary:

```sh
fault_dir="$(mktemp -d)"
for fault in after-create after-start after-kill; do
  target/debug/a3s-oci oci-vm-fault-cleanup \
    --shim "$smoke_dir/a3s-oci-krun-shim" \
    --vm-rootfs "$rootfs_dir/rootfs" \
    --bundle "$bundle" \
    --console "$fault_dir/$fault.log" \
    --fault-after "$fault"
done
```

An `a3s.oci.oci-vm-fault-cleanup.v2` success requires no normal delete call,
guest executor shutdown, marker and runtime-root removal, exact endpoint
removal, shim and VM-worker reap, and restoration of the complete host
descriptor inventory.

### Windows utility VM diagnostics

On a WHPX-capable Windows host:

```powershell
cargo run -p a3s-oci-cli -- whpx-smoke
cargo run -p a3s-oci-krun --bin a3s-oci-krun-shim -- context-smoke
```

The repository also provides a real guest command smoke, authenticated guest
agent smoke, and fixed OCI lifecycle smoke. See
[Windows WHPX Development](docs/windows-whpx.md) for the required runtime
assets and commands.

## Runtime Model

### OCI lifecycle

The create/start barrier is explicit:

```text
creating ── create completed ──▶ created
created  ── start completed  ──▶ running
running  ── process exited   ──▶ stopped
```

`create` prepares isolation and the init process without executing the
configured program. Only `start` releases that process. Invalid transitions
fail without weakening the barrier.

The host lifecycle stores:

- the exact validated OCI configuration and digest;
- a monotonically increasing container generation;
- global idempotency records keyed by `OperationId`;
- active operation intent and terminal replay results;
- reconciliation and quarantine state for interrupted operations.

Matching retries reproduce the original result. Stale generations, reused
operation IDs with different payloads, invalid isolation, and unsupported
configuration fail before driver mutation.

The shared Linux executor independently indexes every live `(container ID,
generation)` pair, retains a highest-generation fence after delete, and gives
each container a private runtime slot. The native Linux and macOS utility-VM
multi-container gates keep two slots live concurrently and verify that every
state transition and replay remains container-scoped.

### Linux executor boundary

The current executor implements a reviewed bootstrap vertical slice:

- new UTS, mount, IPC, network, cgroup, PID, user, and time namespaces;
- parent-authenticated rootful UID/GID mappings plus read-back verification,
  with normalized monotonic and boottime offsets applied before the first
  time-namespace child;
- hostname and domain name configuration;
- recursively private mount propagation and `pivot_root`;
- ordered existing-target OCI mounts with bind/rbind and common VFS options;
- PID- and namespace-authenticated create/start barrier;
- credentials, umask, `no_new_privileges`, `execve`, PID-reuse-safe pidfd
  signaling, exact normal-or-signal exit status, repeated wait, observation,
  and scoped cleanup.

The supported user-namespace slice is rootful: it requires both UID and GID
mappings, coverage for every configured process ID, and an `allow` setgroups
policy. Unimplemented OCI fields are rejected instead of ignored. Rootless
mapping policy, namespace joins, complete mount semantics, cgroup resources,
capabilities, hooks, seccomp, full I/O, recovery, and the remaining SDK
operations are still release gates.

### SDK and protocols

`a3s-oci-sdk` defines:

- OCI `features`, `create`, `state`, `start`, `kill`, and `delete`;
- exec, wait, list, pause, resume, update, processes, stats, and events;
- stdin, stdout, stderr, PTY resize, per-process signal, and wait;
- checkpoint and restore;
- typed IDs, operation IDs, deadlines, generations, and isolation requests.

The durable host implements the five core lifecycle operations around an
injected `RuntimeDriver` and exposes `wait` only when that exact driver
implements it. The native Linux driver and protocol-v2 Linux guest executor
return a stable normal-exit or signal result across repeated waits. Methods
without enforcement remain explicitly unsupported and are not advertised
early.

The local IPC and guest-agent protocols are versioned, length-delimited, and
64 MiB bounded. Every untrusted request is revalidated at the receiving
boundary.

## Platform Status

| Host | Execution path | Retained evidence | Current readiness |
| --- | --- | --- | --- |
| Linux x86_64/aarch64 | Native Linux executor | Kernel pidfd signaling probe, real rootful lifecycle with exact SIGKILL status and repeated wait, two-container wait and mutation isolation, plus shutdown cleanup after create, start, and kill without delete; `/dev/kvm` absent and present-but-unusable | Default inventory `probe-only`; explicitly opened development instance `experimental` |
| Linux x86_64/aarch64 | libkrun + KVM utility VM | Device access, ioctl result, and KVM API version | `probe-only`; VM driver not implemented |
| macOS arm64 | libkrun + HVF utility VM | Direct HVF VM create/destroy, checksum-pinned context lifecycle, authenticated protocol-v2 arm64 guest agent, pidfd-backed fixed and two-container OCI lifecycles with exact repeated exit status and nonblocking wait evidence, and no-delete cleanup after create, start, and kill | `probe-only`; complete enforcement and recovery pending |
| Windows x86_64 | libkrun + WHPX utility VM | Partition, context, guest command, authenticated agent, and fixed OCI core lifecycle | `probe-only`; complete enforcement and recovery pending |

Linux installation, feature inspection, and the native SDK path must work when
KVM is missing or inaccessible. KVM is an optional VM backend, not a Linux
runtime prerequisite.

## Architecture

The platform-neutral control plane is independent of the host isolation
mechanism. Native libraries and Linux-specific execution stay behind explicit
driver, shim, and guest-agent boundaries:

```text
A3S Box / a3s-oci CLI / Rust SDK consumers
                    │
        RuntimeClient / OciRuntimeService
                    │
      in-process call or bounded local IPC
                    │
          OCI validation and lifecycle
                    │
            HostRuntimeService
 exact bundle · generations · journal · reconciliation
                    │
               RuntimeDriver
          ┌─────────┴──────────┐
          │                    │
 Native Linux host      Utility VM qualification
 NativeLinuxDriver      a3s-oci-krun-shim → libkrun
          │             KVM · HVF · WHPX
          │                    │
          │          authenticated guest protocol
          │                    │
          │              a3s-oci-agent
          │                    │
          └─────────┬──────────┘
                    │
             LinuxExecutor
 namespaces · mounts · PID 1 · pidfds · wait · cleanup
```

The same `LinuxExecutor` is called directly on Linux and through the guest
agent in a utility VM. The utility-VM branch represents the qualification
architecture; readiness remains defined by the
[platform status](#platform-status), not by presence in the diagram.

A3S Box owns product-level images, builds, volumes, networks, and policy. A3S
OCI Runtime owns the validated OCI lifecycle, platform execution, durable
state, guest protocol, and runtime-scoped cleanup.

The main runtime, CLI, and SDK do not link libkrun. Only
`a3s-oci-krun-shim` loads the checksum-verified native runtime bundle, keeping
feature inspection and native Linux independent of KVM, HVF, WHPX, or
native-library startup failures.

### Source layout

```text
crates/
├── sdk/             # Public async OCI and process-control contract
├── core/            # Lifecycle, capability, readiness, and isolation types
├── runtime/         # Durable host service, drivers, probes, and reports
├── agent-protocol/  # Authenticated host/guest wire contract
├── agent/           # Static Linux guest agent and LinuxExecutor
├── krun/            # Isolated libkrun shim and pinned native bundles
└── cli/             # Machine-readable diagnostics and lifecycle gates
```

## Conformance and Security

The repository pins the OCI 1.3.0 schemas, upstream fixtures, and all 764
RFC 2119 keyword occurrences from the normative specification. CI verifies:

- all 423 named schema properties and enum values remain classified;
- the normative inventory remains digest-bound to the pinned source;
- typed OCI models round-trip without field loss;
- semantic reports are bounded and phase-aware;
- SDK, IPC, and guest boundaries reject malformed or oversized input.

This is not yet a claim of full OCI conformance. Remaining normative entries,
complete enforcement, hooks, descriptor-relative filesystem operations,
utility-VM host/agent transition fault injection, upstream lifecycle suites,
and platform security certification must pass before a driver becomes
`supported`.

Security-sensitive platform controls include:

- system-scoped WHPX loading and protected Windows runtime state;
- exact Windows shim PID verification and one-time guest authentication;
- direct macOS Hypervisor.framework status reporting;
- checksum-pinned macOS and Windows native bundles, with macOS assets
  reverified immediately before loading;
- bounded macOS VM workers whose success requires a guest-written marker,
  natural zero exit, worker reap, and marker cleanup;
- private `0700` macOS agent directories and `0600` Unix sockets, with
  `LOCAL_PEERPID` plus direct shim-child verification before token negotiation;
- retained pidfds for every authenticated init PID, with all lifecycle and
  cleanup signals delivered through the descriptor rather than a reused
  numeric PID;
- isolated macOS shim process groups so timeout and failure cleanup terminate
  both the public shim and its VM worker;
- shared Windows/macOS fixed-lifecycle evidence with exact mutation replay,
  marker removal, and nominal guest-runtime cleanup;
- macOS no-delete fault cleanup after create, start, and kill, with exact
  endpoint removal, descriptor-inventory restoration, process reap, marker
  removal, and guest-runtime restoration;
- fail-closed dedicated-VM selection;
- no silent fallback from VM isolation to a shared host kernel.

See [OCI 1.3 Conformance Contract](docs/oci-conformance.md),
[Normative Coverage](docs/normative-coverage.md), and
[Durable State](docs/durable-state.md) for the detailed evidence model.

## Development

Run checks from the OCI Runtime repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Cross-check Linux compilation without treating the monorepo root as a Rust
workspace:

```sh
cargo clippy \
  --target x86_64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
cargo clippy \
  --target aarch64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
```

Platform CI covers:

- the 237-point durable commit matrix and all 14 `RuntimeDriver` call
  boundaries on Linux, macOS, and Windows;
- Ubuntu x86_64 native pidfd probe, lifecycle, multi-container isolation, and
  three-phase no-delete cleanup without KVM;
- Ubuntu aarch64 native pidfd probe, lifecycle, multi-container isolation, and
  three-phase no-delete cleanup without KVM;
- macOS HVF, isolated libkrun context, guest-marker, authenticated-agent,
  pidfd-backed fixed and multi-container OCI lifecycles, three-phase no-delete
  cleanup, and missing-entitlement fail-closed gates;
- Windows WHPX and libkrun context gates;
- static x86_64 and aarch64 musl guest-agent output.

Further design and test contracts:

- [Roadmap](ROADMAP.md)
- [SDK Transport](docs/sdk-transport.md)
- [Guest Agent Protocol](docs/agent-protocol.md)
- [Guest Agent Bootstrap](docs/guest-agent.md)
- [OCI Semantic Validation](docs/semantic-validation.md)
- [Native Linux Development](docs/linux-native.md)
- [macOS HVF Development](docs/macos-hvf.md)
- [Windows WHPX Development](docs/windows-whpx.md)

## License

MIT
