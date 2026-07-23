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
- wire-safe bundle serialization that carries the exact validated
  `config.json` text and rechecks schema, version, path, and digest on decode;
- a version-negotiated, 64 MiB-bounded local IPC transport that maps every SDK
  operation, preserves typed service errors, and fails closed on correlation
  or protocol mismatches;
- tested Windows named-pipe and Unix-domain-socket client connectors;
- a separate authenticated, version-negotiated, 64 MiB-bounded host/guest
  protocol for exact-generation create/state/start/kill/delete, with immutable
  `config.json` and digest preservation, response-barrier checks, and poisoned
  connection handling after protocol violations;
- a static-musl-capable Linux guest binary that removes and zeroizes its
  bootstrap token, connects to host CID 2 port 4093 over AF_VSOCK, and
  advertises the five core operations only with its fail-closed bootstrap
  executor active;
- a root-only guest bootstrap executor with exact-generation state,
  session-bounded idempotency, a PID-authenticated abstract Unix start
  barrier, `chroot`, credentials, umask, `no_new_privileges`, `execve`,
  signaling, stopped observation, and scoped cleanup;
- the complete pinned OCI Runtime Specification 1.3.0 schema and upstream
  fixture set, compiled into an offline validator for configuration, state,
  and feature documents;
- a checked-in coverage lock classifying all 423 named schema properties and
  enum values;
- a SHA-256-locked inventory of all 764 RFC 2119 keyword occurrences in the
  15 normative OCI 1.3.0 documents, with CI rejection of missing or stale
  entries;
- phase-aware, bounded semantic reports with an initial fail-closed rule set
  for common, Linux, and VM cross-field requirements;
- a typed registry for all 67 semantic rules, with 20 normative rules bound to
  25 exact OCI source entries and positive and negative tests;
- SDK request validation at the in-process client, IPC client, and
  authenticated server boundaries, including bounded event, output, and stdin
  payloads;
- a single-writer durable core lifecycle with atomic JSON replacement, exact
  `config.json` snapshots, monotonic generations, generation fencing, global
  idempotent create/start/kill/delete journals, crash reconciliation, terminal
  failure replay, and quarantine;
- a public async `RuntimeDriver` integration boundary used by
  `HostRuntimeService` to expose `create`, `state`, `start`, `kill`, and
  `delete` only for an explicitly supplied launch-ready enforcing driver;
- runtime-owned Windows state paths with protected DACLs limited to the
  runtime principal and LocalSystem;
- a first-instance, remote-client-rejecting Windows guest-agent pipe whose
  protected DACL is verified from the live kernel handle and whose connected
  peer must match the previously spawned libkrun shim PID before use;
- secure loading of the system `WinHvPlatform.dll`;
- `WHvCapabilityCodeHypervisorPresent` probing;
- a real WHPX partition-object create/delete smoke;
- an isolated shim pinned to the `a3s-libkrun-sys 3.1.0` FFI ABI and a
  runtime-owned native bundle imported from `A3S-Lab/Box@46e17a8`;
- a real libkrun context create/configure/release smoke that replaces implicit
  TSI with plain vsock and configures the fixed guest port-to-pipe mapping;
- a real local Windows agent-pipe test covering OS-generated session tokens,
  authenticated protocol negotiation, exact endpoint sharing, and pipe-name
  squatting rejection;
- a real WHPX utility-VM entry smoke that boots the packaged Linux kernel,
  executes `/bin/sh` in an untouched Alpine rootfs, and verifies a
  guest-written marker on the host;
- a real end-to-end WHPX guest-agent smoke that boots the static musl agent,
  carries its AF_VSOCK connection through libkrun to the protected Windows
  pipe, authenticates the exact shim PID and one-time token, negotiates
  protocol version 1, and retains nested host/shim evidence;
- a real fixed-bundle WHPX OCI smoke that proves create does not execute the
  process, replays create and delete exactly, releases the process only on
  start, observes stopped, verifies and removes its marker, returns NotFound
  after delete, and leaves no new guest runtime directory;
- the pure OCI `creating -> created -> running -> stopped` state contract;
- Windows and Linux CI scaffolding.

The durable host lifecycle and its driver-facing Rust API are implemented and
tested with an injected conformance driver. The static A3S guest agent now
executes one deliberately narrow OCI bootstrap profile and fails every
unimplemented property instead of ignoring it. This is a verified vertical
slice, not full OCI enforcement: namespaces, mounts, cgroups, capabilities,
hooks, seccomp, complete I/O, recovery, and the remaining SDK operations are
still pending. The built-in WHPX driver therefore remains `probe-only`, and
the default host service advertises only `features`.

See [Roadmap](ROADMAP.md) and
[OCI 1.3 Conformance Contract](docs/oci-conformance.md) for the release gates
and current field-by-field implementation status. The machine-readable
[schema coverage lock](conformance/oci-1.3.0-schema-coverage.json) fails tests
if an upstream field or enum value is missing or unclassified. The separate
[normative coverage lock](conformance/oci-1.3.0-normative-coverage.json)
tracks specification statements through validation, enforcement, and retained
conformance evidence.

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

Run the libkrun context smoke without entering a VM:

```sh
cargo run -p a3s-oci-krun --bin a3s-oci-krun-shim -- context-smoke
```

The successful Windows report is:

```json
{
  "schema_version": "a3s.oci.krun-context-smoke.v2",
  "platform": "windows",
  "status": "available",
  "runtime_bundle_loaded": true,
  "context_created": true,
  "vm_configured": true,
  "agent_vsock_configured": true,
  "context_released": true,
  "vcpus": 1,
  "memory_mib": 128
}
```

Run a real guest command against an extracted Linux rootfs:

```sh
cargo run -p a3s-oci-krun --bin a3s-oci-krun-shim -- \
  vm-smoke --rootfs C:\path\to\rootfs --console C:\path\to\console.log
```

This command succeeds only after `/bin/sh` runs in the guest, writes a unique
marker through virtiofs, the host verifies and removes that marker, and
libkrun reports exit code zero. A VM API return alone is not accepted as
workload evidence.

After installing the static `a3s-oci-agent` at
`<rootfs>/usr/bin/a3s-oci-agent`, run the authenticated end-to-end bridge
smoke:

```powershell
cargo build -p a3s-oci-krun -p a3s-oci-cli
cargo run -p a3s-oci-cli -- agent-vm-smoke `
  --shim target\debug\a3s-oci-krun-shim.exe `
  --rootfs C:\path\to\rootfs `
  --console C:\path\to\new-console.log
```

The console destination must not already exist. Success requires the exact
shim PID to connect, token authentication and protocol-v1 negotiation from
the real Linux guest, a zero guest/shim exit, and a validated nested shim
report. The agent must advertise the exact core operation set.

Place a supported OCI bundle below the VM rootfs, then verify the real
create/start barrier:

```powershell
cargo run -p a3s-oci-cli -- oci-vm-smoke `
  --shim target\debug\a3s-oci-krun-shim.exe `
  --vm-rootfs C:\path\to\vm-rootfs `
  --bundle C:\path\to\vm-rootfs\bundle `
  --console C:\path\to\new-oci-console.log
```

The fixed bootstrap bundle uses a writable `rootfs`, null standard I/O,
`noNewPrivileges: true`, an absolute executable and working directory, and no
unimplemented OCI properties. See
[Guest Agent Bootstrap](docs/guest-agent.md) for the exact current boundary.

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

The runtime applies this transition contract to durable
`creating`/`created`/`running`/`stopped` records. It persists the exact accepted
`config.json`, allocates monotonically increasing generations, fences stale
requests, and journals create, start, kill, and delete by global
`OperationId`. Matching retries replay the exact result; retryable driver
errors retain the active intent, terminal errors are replayed and release the
container claim, and failed creates are quarantined.

`HostRuntimeService::open` exposes the five core lifecycle operations only
around a launch-ready `RuntimeDriver`. The built-in WHPX implementation does
not yet provide that driver, so normal CLI/service discovery remains
feature-only. Descriptor-relative traversal, hooks, the guest executor, and
real platform lifecycle conformance remain release gates.

See [Durable State](docs/durable-state.md) for the on-disk contract and its
current recovery boundary.

## Windows WHPX

The Windows probe loads `WinHvPlatform.dll` with
`LOAD_LIBRARY_SEARCH_SYSTEM32`, resolves only the required documented symbols,
and records contextual HRESULT or Win32 errors.

The current WHPX smoke verifies:

- the WHPX API DLL is available from the Windows system directory;
- the required capability and partition symbols exist;
- the Windows hypervisor reports itself present;
- the process can create and release a WHPX partition object.

The separate libkrun smoke also verifies:

- the pinned Windows libkrun runtime bundle loads;
- one context can be created, configured for the certified one-vCPU path, and
  released without a leak;
- the utility VM enters through WHPX with one vCPU and bounded memory;
- `/bin/sh` executes from an unmodified Linux rootfs, including its normal
  absolute `/bin/sh -> /bin/busybox` symlink;
- the guest can write a marker through virtiofs and the host can verify and
  remove it;
- a fatal WHPX exit is not misreported as a successful guest exit.

The end-to-end agent smoke additionally verifies:

- the static Linux agent starts as `/usr/bin/a3s-oci-agent`;
- guest CID 2 port 4093 reaches the first-instance-only Windows pipe through
  libkrun's plain-vsock mapping;
- the pipe client is the exact spawned shim process;
- the guest authenticates the one-time 256-bit token and negotiates protocol
  version 1;
- the guest reports its version and `x86_64` architecture and advertises the
  exact create/state/start/kill/delete operation set;
- the host validates and retains bounded shim evidence before reporting
  success.

The fixed OCI VM smoke additionally verifies:

- the host accepts only a bundle strictly contained by the VM rootfs;
- create returns `created` with a positive guest PID while the configured
  process remains blocked;
- state and an exact create retry reproduce the created state;
- start alone releases the PID-authenticated abstract Unix barrier;
- state observes the natural process exit as `stopped`;
- the configured process writes the exact marker, and the host removes it;
- stopped-only delete and its exact retry succeed;
- state returns `NotFound` after delete;
- VM shutdown leaves no new guest-agent runtime directory or host process.

The smokes do not yet verify:

- a pinned immutable A3S system image;
- networking or full process I/O;
- complete OCI configuration enforcement, hooks, or recovery;
- multiple concurrent containers or shared-guest-kernel execution.

The next Windows gate replaces the diagnostic share with a protected,
runtime-owned immutable system image and expands the shared Linux executor
through process I/O, namespaces, mounts, resources, hooks, recovery, and
negative isolation cases. WHPX remains `probe-only` until those gates pass.

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
| Windows x86_64 | libkrun + WHPX utility VM | Fixed OCI create/start/delete vertical slice passes; complete enforcement and recovery pending; driver is `probe-only` |
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
|       |-- client.rs      # Cloneable in-process or local-IPC A3S Box client
|       |-- conformance.rs # Pinned normative requirement inventory
|       |-- schema.rs      # Offline pinned OCI schema validation
|       |-- semantic/      # Phase-aware common, Linux, and VM semantics
|       |-- service.rs     # Async full lifecycle and process-control contract
|       |-- transport/     # Negotiated framing and platform IPC connectors
|       `-- validation.rs  # Fail-closed validation for every SDK request
|-- agent-protocol/
|   `-- src/               # Authenticated host/guest lifecycle protocol
|-- agent/
|   `-- src/
|       |-- executor/      # Fail-closed Linux bootstrap executor
|       `-- vsock.rs       # Bounded AF_VSOCK host bootstrap
|-- krun/
|   |-- src/
|   |   |-- lib.rs         # Safe shim-local libkrun context and VM smoke boundary
|   |   `-- main.rs        # Isolated a3s-oci-krun-shim process
|   |-- build.rs           # Hash-verified native runtime extraction and staging
|   `-- RUNTIME-PROVENANCE.md
|-- runtime/
|   `-- src/
|       |-- agent_smoke.rs # Authenticated host-to-guest WHPX evidence
|       |-- agent_session.rs
|       |                   # Reusable authenticated WHPX agent session
|       |-- oci_smoke/     # Fixed-bundle create/start lifecycle evidence
|       |-- platform/      # Windows WHPX and unsupported-host probes
|       |-- report.rs      # Versioned WHPX, bridge, and OCI smoke results
|       |-- service.rs     # Host implementation of the SDK contract
|       `-- state/         # Durable records, generations, operation journals
`-- cli/
    |-- src/main.rs        # Feature, WHPX, and guest-agent diagnostics
    `-- tests/cli.rs       # Public machine-readable CLI contract
```

The future `linux-executor` crate will be added only when the shared native
Linux implementation requires that compilation boundary.

## Development

Run focused checks from this repository:

```sh
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Regenerate review baselines only when intentionally updating the pinned
conformance inputs:

```sh
cargo run -p a3s-oci-sdk --example generate_schema_coverage -- \
  conformance/oci-1.3.0-schema-coverage.json
cargo run -p a3s-oci-sdk --example generate_normative_coverage -- \
  conformance/oci-1.3.0-normative-evidence.json \
  conformance/oci-1.3.0-normative-coverage.json
```

The normative generator applies the reviewed evidence file to a fresh corpus
baseline. Unknown requirements or rules, duplicate bindings, and orphaned
normative semantic rules fail generation.

On Windows, also run the real host probe:

```sh
cargo run -p a3s-oci-cli -- features
cargo run -p a3s-oci-cli -- whpx-smoke
cargo run -p a3s-oci-krun --bin a3s-oci-krun-shim -- context-smoke
cargo run -p a3s-oci-krun --bin a3s-oci-krun-shim -- \
  vm-smoke --rootfs C:\path\to\rootfs --console C:\path\to\console.log
cargo run -p a3s-oci-cli -- agent-vm-smoke \
  --shim target\debug\a3s-oci-krun-shim.exe \
  --rootfs C:\path\to\rootfs \
  --console C:\path\to\new-console.log
cargo run -p a3s-oci-cli -- oci-vm-smoke \
  --shim target\debug\a3s-oci-krun-shim.exe \
  --vm-rootfs C:\path\to\vm-rootfs \
  --bundle C:\path\to\vm-rootfs\bundle \
  --console C:\path\to\new-oci-console.log
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

The SDK also exposes `OciSchemaValidator`. It validates raw JSON or typed
`Spec`, `State`, and `Features` values against the pinned official schemas
without filesystem or network resolution and returns bounded, structured
violations with instance and schema paths.

`OciSemanticValidator` performs the cross-field checks that JSON Schema cannot
express. Its configuration, create, and start phases return bounded,
machine-readable violations with stable rule identifiers. Bundle construction
always applies the configuration phase; start-time validation additionally
requires a runnable process. The current rule set establishes the mandatory
fail-closed boundary, while the generated normative-requirement manifest and
driver enforcement evidence remain release gates.

`OciSemanticValidator::rules()` returns the complete typed rule registry and
classifies each entry as a direct normative rule, a runtime/kernel constraint,
or platform policy. CI requires every direct normative rule to appear in the
reviewed OCI evidence map.

`OciNormativeInventory` exposes the pinned specification-document digests and
all RFC 2119 occurrences to conformance tooling. Its verifier requires a
one-to-one match between the embedded corpus and the checked-in coverage lock,
rejects duplicate IDs, and requires rule and test evidence before an item can
claim validation or enforcement.

`OciBundle` retains the exact validated `config.json` text in addition to its
typed `Spec`. Its custom wire decoder reconstructs the typed model and rejects
relative paths, digest tampering, invalid schemas, unknown fields, and
unsupported specification versions before a request reaches a service.

Out-of-process callers use `RuntimeClient::connect` with a validated Windows
local named pipe or absolute Unix-domain socket. Protocol version 1 negotiates
before the first call, uses bounded length-delimited JSON frames, correlates
every response with a nonzero request ID, preserves stable typed service
errors, and permanently closes a connection after framing or correlation
failure. The runtime owns listener access control and passes each authenticated
stream to `serve_transport_connection`.

Every request type implements `ValidateRequest`. `RuntimeClient`, the IPC
client, and the server all invoke it, so an untrusted peer cannot bypass
semantic process/resource checks, terminal consistency, path requirements, or
the public event/output/input bounds by constructing wire JSON directly.

Its operation surface includes:

- required OCI `features`, `create`, `state`, `start`, `kill`, and `delete`;
- `exec`, `wait`, `list`, `pause`, `resume`, `update`, processes, stats, and
  cursor-based events;
- streaming-friendly stdin, stdout, stderr, PTY resize, per-process signals,
  and per-process wait;
- checkpoint and restore;
- operation IDs, deadlines, typed container and process IDs, generation
  fencing, explicit isolation requirements, and stable error classes.

The default host integration supports feature discovery and deliberately
returns `unsupported` for workload calls. Runtime integrators construct
`HostRuntimeService::open` with a launch-ready, isolation-enforcing
`RuntimeDriver`; that configured service exposes durable `create`, `state`,
`start`, `kill`, and `delete`. Remaining SDK methods stay unsupported and are
never reported as available early. No built-in platform driver is promoted
from `probe-only` yet.

See [SDK Transport](docs/sdk-transport.md) for the Box-facing connection
contract and platform examples,
[Guest Agent Protocol](docs/agent-protocol.md) for the utility-VM boundary,
[Guest Agent Bootstrap](docs/guest-agent.md) for the Linux binary and AF_VSOCK
startup contract,
[OCI Semantic Validation](docs/semantic-validation.md) for the current
phase/rule boundary, and
[Normative Coverage](docs/normative-coverage.md) for the generated
requirements lock and promotion rules. The internal persistence contract is
documented in [Durable State](docs/durable-state.md).

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
