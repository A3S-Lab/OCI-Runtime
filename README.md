# A3S OCI Runtime

<p align="center">
  <strong>Cross-Platform OCI Runtime for A3S</strong>
</p>

<p align="center">
  <em>Run one reviewed Linux container executor natively on Linux or inside utility VMs on macOS and Windows</em>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#capabilities">Capabilities</a> •
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

- **Native Linux** uses namespaces, mounts, cgroup v2, seccomp, capabilities,
  and process supervision without requiring KVM.
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

## Capabilities

- **Complete OCI Types**: Preserve official OCI runtime models and exact
  accepted `config.json` text across SDK and wire boundaries
- **Strict Validation**: Validate OCI 1.0.0 through 1.3.0 schemas, semantic
  relationships, paths, payload bounds, and immutable SHA-256 digests before
  state mutation
- **Durable Lifecycle**: Persist create, state, start, kill, and delete with
  monotonic generations, operation IDs, replay, fencing, reconciliation, and
  quarantine
- **Shared Linux Executor**: Reuse one fail-closed namespace, mount, process,
  and cleanup implementation directly on Linux and through the guest agent
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
create/start/kill/delete vertical slice without opening `/dev/kvm` or
initializing libkrun:

```sh
sudo apt-get install busybox-static
cargo build -p a3s-oci-agent -p a3s-oci-cli

demo_root="$(mktemp -d)"
bundle="$demo_root/bundle"
work_parent="$demo_root/work"
mkdir -p "$bundle/rootfs/bin" "$work_parent"
cp fixtures/native-linux/config.json "$bundle/config.json"
cp "$(command -v busybox)" "$bundle/rootfs/bin/busybox"
ln -s busybox "$bundle/rootfs/bin/sh"

sudo target/debug/a3s-oci native-linux-smoke \
  --agent "$PWD/target/debug/a3s-oci-agent" \
  --bundle "$bundle" \
  --work-parent "$work_parent"
```

Success requires the exact create/start barrier, running and stopped
observation, idempotent mutation replay, marker verification, post-delete
`NotFound`, and scoped cleanup. See
[Native Linux Development](docs/linux-native.md) for the accepted profile and
remaining production gates.

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
and context release. It does not boot a guest or run an OCI workload. See
[macOS HVF Development](docs/macos-hvf.md) for the exact boundary.

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

### Linux executor boundary

The current executor implements a reviewed bootstrap vertical slice:

- new UTS, mount, IPC, network, cgroup, and PID namespaces;
- hostname and domain name configuration;
- recursively private mount propagation and `pivot_root`;
- ordered existing-target OCI mounts with bind/rbind and common VFS options;
- PID-authenticated create/start barrier;
- credentials, umask, `no_new_privileges`, `execve`, signaling, observation,
  and scoped cleanup.

Unimplemented OCI fields are rejected instead of ignored. User and time
namespaces, namespace joins, complete mount semantics, cgroup resources,
capabilities, hooks, seccomp, full I/O, recovery, and the remaining SDK
operations are still release gates.

### SDK and protocols

`a3s-oci-sdk` defines:

- OCI `features`, `create`, `state`, `start`, `kill`, and `delete`;
- exec, wait, list, pause, resume, update, processes, stats, and events;
- stdin, stdout, stderr, PTY resize, per-process signal, and wait;
- checkpoint and restore;
- typed IDs, operation IDs, deadlines, generations, and isolation requests.

The durable host currently implements the five core lifecycle mutations around
an injected `RuntimeDriver`. Methods without enforcement remain explicitly
unsupported and are not advertised early.

The local IPC and guest-agent protocols are versioned, length-delimited, and
64 MiB bounded. Every untrusted request is revalidated at the receiving
boundary.

## Platform Status

| Host | Execution path | Retained evidence | Current readiness |
| --- | --- | --- | --- |
| Linux x86_64/aarch64 | Native Linux executor | Real rootful core lifecycle with `/dev/kvm` absent and present-but-unusable | Default inventory `probe-only`; explicitly opened development instance `experimental` |
| Linux x86_64/aarch64 | libkrun + KVM utility VM | Device access, ioctl result, and KVM API version | `probe-only`; VM driver not implemented |
| macOS arm64 | libkrun + HVF utility VM | Direct HVF VM create/destroy plus checksum-pinned libkrun context create/configure/vsock/release | `probe-only`; guest boot and workload driver not implemented |
| Windows x86_64 | libkrun + WHPX utility VM | Partition, context, guest command, authenticated agent, and fixed OCI core lifecycle | `probe-only`; complete enforcement and recovery pending |

Linux installation, feature inspection, and the native SDK path must work when
KVM is missing or inaccessible. KVM is an optional VM backend, not a Linux
runtime prerequisite.

## Architecture

The SDK and lifecycle core are platform-neutral. Platform-specific hypervisor
and native-library code stays behind explicit driver or shim boundaries:

```text
 A3S Box / a3s-oci CLI / future containerd shim
                         │
                         ▼
                   a3s-oci-sdk
             typed OCI requests + local IPC
                         │
                         ▼
                HostRuntimeService
       validation │ durable state │ operation journal
                         │
             explicit driver selection
                         │
          ┌──────────────┴──────────────────┐
          │                                 │
          ▼                                 ▼
 NativeLinuxDriver               Utility-VM host path
  explicit experimental             (in development)
          │                                 │
          │                        isolated libkrun shim
          │                                 │
          │                          KVM / HVF / WHPX
          │                                 │
          │                          A3S Linux guest
          │                                 │
          │                         authenticated AF_VSOCK
          │                                 │
          │                           a3s-oci-agent
          │                                 │
          └──────────────┬──────────────────┘
                         ▼
                   LinuxExecutor
       namespaces │ mounts │ cgroups │ processes
```

The same `LinuxExecutor` is called directly on Linux and through the guest
agent in a utility VM. A3S Box owns product-level images, builds, volumes,
networks, and policy; A3S OCI Runtime owns validated OCI lifecycle,
platform-driver execution, guest protocol, durable state, and cleanup.

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
recovery fault injection, upstream lifecycle suites, and platform security
certification must pass before a driver becomes `supported`.

Security-sensitive platform controls include:

- system-scoped WHPX loading and protected Windows runtime state;
- exact Windows shim PID verification and one-time guest authentication;
- direct macOS Hypervisor.framework status reporting;
- checksum-pinned macOS and Windows native bundles, with macOS assets
  reverified immediately before loading;
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

- Ubuntu x86_64 native lifecycle without KVM;
- Ubuntu aarch64 native lifecycle without KVM;
- macOS HVF and isolated libkrun context gates;
- Windows WHPX and libkrun context gates;
- static x86_64 musl guest-agent output.

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
