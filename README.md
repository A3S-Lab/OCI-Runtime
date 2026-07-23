# A3S OCI Runtime

<p align="center">
  <strong>Cross-Platform OCI Runtime for A3S</strong>
</p>

<p align="center">
  <em>One Linux container executor, native on Linux and hosted in utility VMs through KVM, HVF, and WHPX.</em>
</p>

---

## Overview

**A3S OCI Runtime** is the low-level runtime boundary for Linux OCI workloads
across Linux, macOS, and Windows. It is designed to replace A3S Box's direct
dependency on an external `crun` binary while keeping product policy, image
management, builds, and SDK behavior in A3S Box.

The release contract is complete OCI Runtime Specification 1.3.0 conformance
for every normative requirement applicable to Linux containers and the
advertised native or utility-VM driver. The implementation will not ship a
permanent restricted "A3S profile." The public Rust SDK carries the complete
official OCI `Spec`, `Process`, `LinuxResources`, `State`, and `Features`
models without translating them into a reduced A3S configuration.

The runtime has two execution families:

- native Linux execution through namespaces, mounts, cgroup v2, seccomp,
  capabilities, and process supervision, without requiring KVM;
- Linux utility VMs through libkrun with KVM on Linux, HVF on macOS, and WHPX
  on Windows.

Both families will use one reviewed Linux container executor. Native Linux
calls it directly; utility-VM drivers call it through a versioned guest agent.
Backend identity, driver maturity, and effective isolation are always reported
separately.

The project is experimental. The current Windows milestone implements:

- versioned, machine-readable driver capability output;
- an async, transport-independent `a3s-oci-sdk` contract for the full OCI
  lifecycle and A3S Box process-control surface;
- strict, size-bounded OCI 1.0.0 through 1.3.0 bundle loading with an immutable
  SHA-256 configuration digest;
- secure loading of the system `WinHvPlatform.dll`;
- `WHvCapabilityCodeHypervisorPresent` probing;
- a real WHPX partition-object create/delete smoke;
- the pure OCI `creating -> created -> running -> stopped` state contract;
- Windows and Linux CI scaffolding.

It does **not** yet boot an A3S Linux kernel or create, start, or execute an OCI
container. The WHPX driver therefore reports `probe-only` readiness even when
the host capability and partition-object smoke succeed.

See [Roadmap](ROADMAP.md) and
[OCI 1.3 Conformance Contract](docs/oci-conformance.md) for the release gates
and current field-by-field implementation status.

## Quick Start

Clone and inspect the current runtime:

```sh
git clone git@github.com:A3S-Lab/OCI-Runtime.git
cd OCI-Runtime

cargo run -p a3s-oci-cli -- features
```

On a WHPX-capable Windows host, the versioned feature inventory resembles:

```json
{
  "schema_version": "a3s.oci.features.v1",
  "platform": "windows",
  "architecture": "x86_64",
  "drivers": [
    {
      "driver": "libkrun-whpx",
      "status": "available",
      "readiness": "probe-only",
      "isolation_classes": [
        "dedicated-vm",
        "shared-guest-kernel"
      ],
      "evidence": {
        "hypervisor_present": "true",
        "win_hv_platform_dll": "true"
      }
    }
  ]
}
```

Feature discovery succeeds when WHPX is unavailable and records the reason
instead of converting host limitations into a startup failure.

Run the real Windows partition-object smoke:

```sh
cargo run -p a3s-oci-cli -- whpx-smoke
```

A successful result is:

```json
{
  "schema_version": "a3s.oci.whpx-smoke.v1",
  "status": "available",
  "dll_loaded": true,
  "hypervisor_present": true,
  "partition_object_round_trip": true
}
```

The command exits with status `2` when WHPX is unsupported or unavailable.
See [Windows WHPX Development](docs/windows-whpx.md) for the exact evidence
boundary and the next workload gate.

## Capability And Readiness

Host availability does not imply that a runtime driver may launch workloads.
Every driver publishes both values:

| Field | Meaning |
| --- | --- |
| `status` | Whether the required host platform capability is available |
| `readiness` | Whether the runtime implementation may launch workloads |
| `isolation_classes` | Security boundaries the completed driver is designed to provide |
| `evidence` | Stable facts collected by the platform probe |
| `reason` | Diagnostic context when a prerequisite is unavailable |

Driver readiness is monotonic through reviewed release gates:

| Readiness | Workload launch |
| --- | --- |
| `probe-only` | Forbidden; only platform discovery and smoke are implemented |
| `experimental` | Allowed only through explicit experimental selection |
| `supported` | Allowed for the certified runtime profile |

`DriverCapability::can_launch()` requires both an available host capability and
`experimental` or `supported` readiness. This prevents a working hypervisor API
from being mistaken for a complete OCI runtime.

## Isolation Model

Driver selection and isolation are different contracts:

| Isolation class | Host boundary | Kernel sharing |
| --- | --- | --- |
| `dedicated-vm` | Hardware VM | One workload or pod owns the guest kernel |
| `shared-guest-kernel` | Hardware VM | Containers in one trust domain share a guest Linux kernel |
| `shared-host-kernel` | No VM boundary | Containers share the Linux host kernel |

Windows and macOS cannot provide `shared-host-kernel` for Linux workloads.
Their shared-kernel path is a Linux utility VM scoped to one explicit trust
domain. Native Linux provides `shared-host-kernel` without depending on KVM.

An explicit dedicated-VM request must fail before runtime state mutation when
the required hypervisor is unavailable. The runtime never silently weakens an
isolation request.

## OCI Lifecycle Contract

The core crate models the OCI create/start boundary explicitly:

```text
creating --create-completed--> created
created  --start-completed---> running
running  --process-exited----> stopped
```

`create` must prepare namespaces, mounts, resources, I/O, and the init process
without executing the configured user program. Only an explicit `start`
operation may release that program.

The state machine rejects invalid transitions:

```rust
use a3s_oci_core::{LifecycleEvent, LifecycleState, TransitionError};

fn main() -> Result<(), TransitionError> {
    let created = LifecycleState::Creating
        .transition(LifecycleEvent::CreateCompleted)?;
    let running = created.transition(LifecycleEvent::StartCompleted)?;

    assert_eq!(running, LifecycleState::Running);
    Ok(())
}
```

Durable state, operation idempotency, generation fencing, and recovery journals
will be layered on this pure contract before workload launch is enabled.

## Windows WHPX

The Windows probe loads `WinHvPlatform.dll` with
`LOAD_LIBRARY_SEARCH_SYSTEM32`, resolves only the required documented symbols,
and records contextual HRESULT or Win32 errors.

The current smoke verifies:

- the WHPX API DLL is available from the Windows system directory;
- the required capability and partition symbols exist;
- the Windows hypervisor reports itself present;
- the process can create and release a WHPX partition object.

It does not verify:

- libkrun context creation or VM entry;
- the pinned A3S kernel or guest agent;
- virtio-fs, vsock, named-pipe transport, networking, or process I/O;
- OCI bundle validation or lifecycle commands;
- single-container or shared-guest-kernel execution.

The next Windows gate boots a one-vCPU utility VM through
`a3s-libkrun-sys`, negotiates a versioned guest protocol, mounts one protected
runtime root, and runs a fixed local Alpine bundle with an exact create/start
barrier. Only that gate may promote WHPX readiness to `experimental`.

## Target Architecture

```text
A3S Box / a3s-oci / future containerd shim
                    |
              a3s-oci-sdk
                    |
            OCI runtime service
                    |
       durable state + operation journal
                    |
        +-----------+---------------------+
        |                                 |
NativeLinuxDriver                  LibkrunVmDriver
        |                                 |
        |                       KVM / HVF / WHPX
        |                                 |
        |                         a3s-oci-agent
        |                                 |
        +----------- LinuxExecutor -------+
                           |
               namespaces / mounts / cgroups
               seccomp / capabilities / processes
```

The runtime repository does not depend on `a3s-box-core` or
`a3s-box-runtime`. The Rust crate dependency direction is:

```text
a3s-box ---------> a3s-oci-sdk <--------- a3s-oci-runtime
                                                |
                                                v
                               a3s-libkrun-sys + platform driver
```

The SDK contains contracts and client transport, never a driver. The runtime
implements those contracts. A3S Box owns OCI bundle policy, images, builds,
volumes, networks, product SDKs, and product lifecycle. A3S OCI Runtime owns
the lower-level OCI lifecycle, platform drivers, guest protocol, runtime
state, and cleanup.

## Platform Direction

| Host | Execution path | Current state |
| --- | --- | --- |
| Windows x86_64 | libkrun + WHPX utility VM | WHPX capability and partition-object smoke implemented; driver is `probe-only` |
| Linux x86_64/aarch64 without KVM | Native Linux executor | Required before `crun` removal; not implemented |
| Linux x86_64/aarch64 with KVM | libkrun + KVM utility VM | Planned after the shared executor contract |
| macOS arm64 | libkrun + HVF utility VM | Planned after the shared executor contract |

Linux installation, runtime inspection, A3S Box Sandbox isolation, and Rust,
Python, and TypeScript SDK operations must work when `/dev/kvm` is absent or
inaccessible. KVM is an optional VM backend, not a Linux runtime prerequisite.

## Design Direction

| Concern | Direction |
| --- | --- |
| Runtime frontend | Thin CLI and service surfaces over one Rust lifecycle implementation |
| Linux executor | One fail-closed namespace, mount, cgroup, seccomp, capability, and process implementation |
| Utility VM | Version-pinned libkrun, kernel, guest agent, firmware, and protocol artifacts |
| Shared VM | Multiple containers only inside one explicit trust domain |
| State | Durable, versioned, crash-reconcilable records with generation fencing |
| Filesystem | Protected runtime-owned roots and descriptor-relative path resolution |
| Networking | Explicit staged support; unsupported modes fail before create |
| Capability output | Host evidence, driver readiness, and isolation reported separately |
| Compatibility | Complete OCI Runtime Specification 1.3.0 for all normative Linux-container and advertised-driver requirements; no permanent A3S subset |
| Migration | Certified `crun` remains a rollback backend until release gates pass |

The runtime rejects unsupported OCI properties instead of ignoring them. A
working platform probe is evidence for the next development step, never a
substitute for lifecycle, security-negative, recovery, and soak validation.

## Source Layout

The repository is split only at real compilation and deployment boundaries:

```text
crates/
|-- core/
|   `-- src/
|       |-- capability.rs  # Driver evidence, readiness, and isolation types
|       `-- lifecycle.rs   # Pure OCI lifecycle state transitions
|-- sdk/
|   `-- src/
|       |-- bundle.rs      # Strict, digest-bound complete OCI spec loading
|       |-- service.rs     # Async full lifecycle and process-control contract
|       `-- client.rs      # Cloneable A3S Box client
|-- runtime/
|   `-- src/
|       |-- platform/      # Windows WHPX and unsupported-host probes
|       |-- report.rs      # Versioned WHPX smoke result
|       `-- service.rs     # Host implementation of the SDK contract
`-- cli/
    |-- src/main.rs        # a3s-oci features and whpx-smoke
    `-- tests/cli.rs       # Public machine-readable CLI contract
```

Future `linux-executor` and `agent` crates will be added only when the native
Linux implementation and static guest binary require those build boundaries.

## Development

Run focused checks from this repository:

```sh
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

On Windows, also run the real host probe:

```sh
cargo run -p a3s-oci-cli -- features
cargo run -p a3s-oci-cli -- whpx-smoke
```

Cross-check the non-Windows capability path when the target is installed:

```sh
cargo clippy \
  --target x86_64-unknown-linux-musl \
  --workspace \
  --all-targets \
  -- \
  -D warnings
```

The generic Windows CI lane accepts an unavailable WHPX host only for
`features`; release promotion requires retained smoke and lifecycle evidence
from a real WHPX-capable host.

## Rust SDK

`a3s-oci-sdk` is the only runtime lifecycle API A3S Box should consume. It is
async, `Send + Sync`, cloneable, strongly typed, and independent of WHPX,
libkrun, native Linux internals, and transport selection.

Its operation surface includes:

- required OCI `features`, `create`, `state`, `start`, `kill`, and `delete`;
- `exec`, `wait`, `list`, `pause`, `resume`, `update`, processes, stats, and
  cursor-based events;
- streaming-friendly stdin, stdout, stderr, PTY resize, per-process signals,
  and per-process wait;
- checkpoint and restore;
- operation IDs, deadlines, typed container and process IDs, generation
  fencing, explicit isolation requirements, and stable error classes.

Current host integration supports feature discovery through the SDK. Other
methods deliberately return `unsupported` until their durable implementation
and conformance tests land; they are never reported as available early.

```rust
use a3s_oci_runtime::HostRuntimeService;
use a3s_oci_sdk::RuntimeClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> a3s_oci_sdk::Result<()> {
    let client = RuntimeClient::new(HostRuntimeService::new());
    let info = client.features().await?;

    assert_eq!(info.operations.len(), 1);
    Ok(())
}
```

## License

MIT
