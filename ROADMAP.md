# A3S OCI Runtime Roadmap

Status: **In development**

Standards baseline: **OCI Runtime Specification 1.3.0**

Primary consumer: **A3S Box through `a3s-oci-sdk`**

## Release Contract

The production runtime must implement every normative OCI Runtime
Specification 1.3.0 requirement applicable to Linux containers and every
driver it advertises. A reduced A3S-only OCI profile is not an acceptable
terminal state.

Complete means all of the following:

1. every applicable `config.json`, state, and feature property is represented
   without loss;
2. every applicable value and cross-field rule is validated before runtime
   state mutation;
3. every requested control is enforced or the operation fails;
4. lifecycle and hook ordering matches the specification;
5. recovery preserves the same externally observable state;
6. upstream OCI validation and lifecycle suites pass;
7. the feature report describes only behavior that passed the same release
   build's tests.

The SDK is also a release blocker. A3S Box must be able to perform the complete
supported lifecycle without constructing CLI commands or importing platform
driver internals.

## Current Baseline

Completed:

- independent `A3S-Lab/OCI-Runtime` repository and monorepo submodule;
- pure OCI lifecycle transition contract;
- versioned driver status, readiness, isolation, and evidence;
- secure WHPX DLL loading and hypervisor capability probe;
- WHPX partition-object create/delete smoke on Windows;
- async, `Send + Sync`, transport-independent Rust SDK contract;
- complete official OCI runtime model pass-through in the SDK;
- strict, bounded OCI 1.0.0 through 1.3.0 bundle decoding;
- rejection of unknown configuration properties;
- immutable SHA-256 binding of the loaded `config.json`;
- existing `features` CLI path routed through the Rust SDK;
- Windows and Linux CI.

Not yet complete:

- durable container state and operation journal;
- a libkrun/WHPX VM boot;
- guest protocol and Linux executor;
- any workload lifecycle operation;
- OCI hook execution;
- OCI configuration enforcement;
- native Linux execution;
- A3S Box migration;
- upstream conformance and security certification.

The WHPX driver remains `probe-only`, and the host service advertises only the
`features` operation.

## Delivery Sequence

### R0 — Contract And Spec Ingestion

- [x] Create `a3s-oci-sdk`.
- [x] Use official Rust OCI types for `Spec`, `Process`, `LinuxResources`,
  `State`, and `Features`.
- [x] Define all OCI lifecycle and A3S Box control operations.
- [x] Add typed IDs, operation IDs, generation fencing, deadlines, isolation,
  I/O, stats, events, checkpoint, restore, and stable errors.
- [x] Strictly load and digest-bind OCI bundles.
- [ ] Import the pinned OCI 1.3.0 JSON schemas and fixture inventory.
- [ ] Generate a schema-property coverage manifest in CI.
- [ ] Add semantic validators for common, Linux, and VM configuration.
- [ ] Add version-negotiated local IPC transport for out-of-process callers.

Exit gate: every OCI 1.3.0 schema property is accounted for as accepted,
rejected as inapplicable, or rejected because the selected driver cannot
enforce it. No property is silently ignored.

### R1 — Durable OCI Lifecycle

- [ ] Protected runtime root and descriptor-relative path operations.
- [ ] Atomic container records with monotonically increasing generations.
- [ ] Idempotent operation journal keyed by `OperationId`.
- [ ] Crash reconciliation and quarantine for ambiguous state.
- [ ] Implement `create`, `state`, `start`, `kill`, and `delete`.
- [ ] Preserve an exact create/start barrier.
- [ ] Implement all OCI hook phases and error behavior.
- [ ] Implement `run` as a client composition, not a second lifecycle.

Exit gate: lifecycle tests pass under fault injection at every durable write
and host/agent transition.

### R2 — Windows WHPX Utility VM

- [x] Load and probe Windows Hypervisor Platform securely.
- [x] Create and delete a real WHPX partition object.
- [ ] Add a version-pinned `a3s-libkrun-sys` dependency and artifact manifest.
- [ ] Create a libkrun context backed by WHPX.
- [ ] Configure one vCPU, memory, protected runtime share, and console.
- [ ] Boot the pinned A3S Linux kernel and immutable system root.
- [ ] Establish the named-pipe/vsock bridge.
- [ ] Negotiate the guest protocol and retain boot evidence.
- [ ] Run a fixed init process through distinct OCI create and start calls.
- [ ] Prove deterministic VM, handle, process, and filesystem cleanup.

Exit gate: a fresh Windows host test boots a utility VM, runs the fixed OCI
bundle, validates negative isolation cases, and leaves no process, handle, or
runtime-root leak. Only then may WHPX become `experimental`.

### R3 — Shared Linux Executor And Guest Agent

- [ ] Multi-container guest registry with per-container generations.
- [ ] Namespace creation and joining for PID, mount, IPC, UTS, user, network,
  cgroup, and time namespaces.
- [ ] Rootfs, mount order, propagation, idmapped mounts, masked paths, and
  read-only paths.
- [ ] UID/GID mappings, credentials, capabilities, rlimits, scheduler, I/O
  priority, affinity, `no_new_privileges`, LSMs, and seccomp.
- [ ] cgroup v2 CPU, memory, pids, I/O, hugepage, RDMA, device, and unified
  resource enforcement.
- [ ] Init supervision, zombie reaping, pidfd signaling, exec, and wait.
- [ ] Ordered hooks with OCI state on stdin.
- [ ] Backpressured stdin/stdout/stderr, PTY, resize, signals, and output
  cursors.
- [ ] Pause, resume, update, processes, stats, and ordered events.

Exit gate: the same executor passes its lifecycle, configuration, security,
and recovery suites in the Windows guest and on native Linux.

### R4 — Native Linux Without KVM

- [ ] Add the native Linux driver without linking or initializing libkrun.
- [ ] Reuse the R3 Linux executor directly.
- [ ] Prove runtime install, startup, inspection, and SDK loading without KVM.
- [ ] Run the full Sandbox SDK suite with `/dev/kvm` absent and inaccessible.
- [ ] Fail explicit dedicated-VM requests before image or state mutation.

Exit gate: A3S Box Sandbox and its Rust, Python, and TypeScript SDK tests pass
on supported x86_64 and aarch64 Linux hosts without KVM.

### R5 — Full OCI 1.3 Conformance

- [ ] Complete common configuration and process semantics.
- [ ] Complete Linux configuration and feature reporting.
- [ ] Complete applicable VM configuration semantics without executing
  untrusted hypervisor, kernel, or firmware paths.
- [ ] Pass OCI JSON schema validation for config, state, and features.
- [ ] Pass upstream lifecycle validation tools.
- [ ] Differential-test supported bundles against the certified `crun`.
- [ ] Run hook-order, rollback, recovery, security-negative, and soak suites.
- [ ] Publish an exact, generated support manifest with no unclassified field.

Exit gate: the release report contains retained evidence for every applicable
normative MUST and MUST NOT requirement in OCI Runtime Specification 1.3.0.

### R6 — A3S Box Migration

- [ ] Add the pinned `a3s-oci-sdk` dependency to A3S Box.
- [ ] Implement the Box adapter using SDK types only.
- [ ] Preserve commands, files, exec, PTY, logs, stats, pause/resume, stop,
  kill, recovery, and cleanup behavior.
- [ ] Run differential Box suites against A3S OCI Runtime and certified
  `crun`.
- [ ] Keep `crun` as an explicit rollback backend during the release window.
- [ ] Remove direct `crun` invocation only after every release gate passes.

## Platform Promotion

| Driver | Probe-only | Experimental | Supported |
| --- | --- | --- | --- |
| Windows libkrun/WHPX | Capability and partition smoke | Fixed bundle plus full SDK lifecycle | OCI, security, recovery, and soak gates |
| Native Linux | Host feature inventory | Full A3S Box Sandbox suite without KVM | OCI and adversarial gates on x86_64/aarch64 |
| Linux libkrun/KVM | KVM capability evidence | Same guest lifecycle as WHPX | Driver-specific isolation and soak gates |
| macOS libkrun/HVF | HVF capability evidence | Same guest lifecycle as WHPX | Driver-specific isolation and soak gates |

Promotion is monotonic and evidence-based. Host hypervisor availability alone
never enables workload launch.

## Commit And Integration Policy

Each coherent, tested increment is committed and pushed to
`git@github.com:A3S-Lab/OCI-Runtime.git`. The `a3s` monorepo gitlink is updated
only after the runtime commit is remotely available and all focused checks
pass. Unrelated dirty submodules are never staged.
