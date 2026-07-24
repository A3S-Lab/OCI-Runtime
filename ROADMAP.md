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
- native Linux namespace and cgroup v2 prerequisite reporting that does not
  touch `/dev/kvm`;
- Linux KVM device, access, ioctl, and API-version reporting without libkrun
  initialization;
- Apple Silicon and Hypervisor.framework capability reporting through a
  direct `kern.hv_support` query;
- entitlement-aware direct Hypervisor.framework VM-object create/destroy
  evidence with versioned, fail-closed diagnostics;
- isolated macOS libkrun context create/configure/plain-vsock/release evidence
  from a checksum-pinned, runtime-reverified arm64 bundle;
- explicit rootful native Linux driver integration that reuses the shared
  executor without linking or initializing libkrun;
- real native Linux create/state/start/kill/delete SDK evidence on x86_64 and
  aarch64, repeated with `/dev/kvm` absent and present but unusable;
- WHPX partition-object create/delete smoke on Windows;
- isolated libkrun shim with a pinned, checksum-verified Windows runtime
  bundle;
- libkrun context create/configure/release smoke on Windows;
- real WHPX VM entry, Linux userspace command, virtiofs marker, and natural
  exit-code smoke on Windows;
- real WHPX guest-agent boot through AF_VSOCK and the protected Windows pipe,
  with exact shim-PID authentication, protocol-v1 negotiation, and retained
  host/shim evidence;
- root-only Linux guest bootstrap executor for an exact fail-closed OCI
  profile, with a PID-authenticated abstract Unix create/start barrier,
  create-time UTS, mount, IPC, network, cgroup, and PID namespaces, hostname
  and domainname, recursively private mount propagation, ordered
  existing-target OCI mounts, `pivot_root`, authenticated host-visible PID
  reporting, exact-generation state, bounded typed init rejection reporting,
  session idempotency, signaling, and cleanup;
- real WHPX fixed-bundle create/state/start/kill/delete evidence, including
  exact mutation retries, pre-start non-execution, running and stopped
  observation, marker verification, post-delete NotFound, and nominal leak
  checks;
- async, `Send + Sync`, transport-independent Rust SDK contract;
- complete official OCI runtime model pass-through in the SDK;
- strict, bounded OCI 1.0.0 through 1.3.0 bundle decoding;
- pinned OCI Runtime Specification 1.3.0 schemas and upstream fixtures;
- offline configuration, state, and features schema validation;
- a CI-checked coverage lock for all 423 schema properties and enum values;
- a CI-checked inventory of all 764 RFC 2119 occurrences across the 15
  normative OCI 1.3.0 documents;
- rejection of unknown configuration properties;
- immutable SHA-256 binding of the loaded `config.json`;
- exact `config.json` retention and fail-closed SDK wire deserialization;
- phase-aware, bounded common, Linux, and VM semantic validation boundary;
- exhaustive SDK request validation on in-process and transport boundaries;
- version-negotiated, length-delimited transport for every SDK operation;
- tested Windows named-pipe and Unix-domain-socket client connectors;
- authenticated, version-negotiated, bounded host/guest lifecycle protocol
  with exact bundle and response correlation;
- existing `features` CLI path routed through the Rust SDK;
- single-writer durable state for the complete core lifecycle, with exact
  bundle snapshots, monotonic generations, generation fencing, global
  idempotent create/start/kill/delete journals, active-operation claims,
  terminal failure replay, crash reconciliation, and quarantine;
- async `RuntimeDriver` integration plus a tested host implementation of
  `create`, `state`, `start`, `kill`, and `delete`;
- runtime-owned Windows state paths with protected DACLs limited to the
  runtime principal and LocalSystem, inheritance disabled, and every applied
  owner and ACL verified;
- Windows, Linux, and macOS CI.

Not yet complete:

- fault injection at every durable write and host/driver boundary;
- descriptor-relative path resolution;
- complete shared guest OCI executor;
- a production workload driver;
- OCI hook execution;
- OCI configuration enforcement;
- production-ready native Linux execution;
- A3S Box migration;
- upstream conformance and security certification.

The built-in WHPX driver remains `probe-only`, and the default host service
advertises only `features`. A host explicitly opened around a launch-ready
`RuntimeDriver` advertises the five durable core lifecycle operations.

## Delivery Sequence

### R0 — Contract And Spec Ingestion

- [x] Create `a3s-oci-sdk`.
- [x] Use official Rust OCI types for `Spec`, `Process`, `LinuxResources`,
  `State`, and `Features`.
- [x] Define all OCI lifecycle and A3S Box control operations.
- [x] Add typed IDs, operation IDs, generation fencing, deadlines, isolation,
  I/O, stats, events, checkpoint, restore, and stable errors.
- [x] Strictly load and digest-bind OCI bundles.
- [x] Import the pinned OCI 1.3.0 JSON schemas and fixture inventory.
- [x] Generate and verify a schema-property and enum-value coverage manifest
  in CI.
- [x] Generate and verify a SHA-256-bound normative requirement inventory in
  CI.
- [x] Add phase-aware semantic validators for common, Linux, and VM
  configuration and enforce them at SDK request boundaries.
- [ ] Review and bind all 630 pending common, Linux, and VM normative entries
  to exact rules, enforcement owners, and positive and negative evidence.
- [x] Add version-negotiated local IPC transport for out-of-process callers.

Exit gate: every OCI 1.3.0 schema property is accounted for as accepted,
rejected as inapplicable, or rejected because the selected driver cannot
enforce it. No property is silently ignored.

### R1 — Durable OCI Lifecycle

- [x] Add an absolute, single-writer runtime root with plain-path/reparse-point
  checks, bounded reads, and atomic file replacement.
- [x] Create, apply, and verify runtime ownership plus protected Windows state
  DACLs limited to the runtime principal and LocalSystem.
- [ ] Use descriptor-relative path operations on every supported host.
- [x] Add atomic creating/created records with exact configuration snapshots
  and monotonically increasing generations.
- [x] Add a global idempotent create journal keyed by `OperationId`.
- [x] Extend the operation journal to start, kill, and delete.
- [ ] Extend idempotent journals to every remaining process mutation.
- [x] Reconcile interrupted core lifecycle operations and quarantine failed
  create/delete state.
- [x] Implement driver-independent `create`, `state`, `start`, `kill`, and
  `delete` host orchestration.
- [x] Preserve the exact create/start barrier in the durable host/driver
  contract.
- [x] Verify the barrier against the real Linux guest bootstrap executor.
- [ ] Implement all OCI hook phases and error behavior.
- [ ] Implement `run` as a client composition, not a second lifecycle.

Exit gate: lifecycle tests pass under fault injection at every durable write
and host/agent transition.

### R2 — Windows WHPX Utility VM

- [x] Load and probe Windows Hypervisor Platform securely.
- [x] Create and delete a real WHPX partition object.
- [x] Pin the `a3s-libkrun-sys 3.1.0` FFI ABI and stage a runtime-owned,
  checksum-verified Windows bundle imported from `A3S-Lab/Box@46e17a8` only
  for the isolated shim.
- [x] Create, configure, and release a real context using the Windows WHPX
  libkrun build.
- [x] Configure a plain-vsock device and the fixed guest control port through
  the Windows named-pipe mapping ABI without enabling TSI.
- [x] Enter the VM and execute a guest command through WHPX.
- [x] Configure one vCPU, bounded memory, a diagnostic rootfs share, and
  console output.
- [x] Define and test the versioned host/guest lifecycle protocol over a
  transport-independent byte stream.
- [x] Bind the host half of the Windows agent bridge with a verified protected
  DACL, first-instance ownership, remote-client rejection, expected-shim PID
  verification, and authenticated protocol negotiation over a real named
  pipe.
- [x] Implement the Linux guest binary, bounded AF_VSOCK connection retry,
  secret-zeroizing bootstrap, and static musl build.
- [ ] Replace the diagnostic path with a protected runtime-owned share.
- [ ] Boot the pinned A3S Linux kernel and immutable system root.
- [x] Establish the named-pipe/vsock bridge.
- [x] Negotiate the guest protocol and retain boot evidence.
- [x] Run a fixed init process through distinct OCI create and start calls.
- [x] Verify running state, exact create/kill/delete replay, signal-driven
  stopped state, post-delete NotFound, marker cleanup, and no new guest
  runtime directory on the nominal path.
- [ ] Prove deterministic VM, handle, process, and filesystem cleanup.

Exit gate: a fresh Windows host test boots a utility VM, runs the fixed OCI
bundle, validates negative isolation cases, and leaves no process, handle, or
runtime-root leak. Only then may WHPX become `experimental`.

### R2M — macOS HVF Utility VM

- [x] Query Apple Silicon Hypervisor.framework support directly.
- [x] Add the minimal checked-in Hypervisor entitlement used to sign runtime
  development and CI artifacts.
- [x] Create and destroy a real process-owned HVF VM object through the system
  framework, with symbolic failure reporting and cleanup ownership.
- [x] Retain the versioned success or fail-closed unavailable report in the
  CLI and macOS CI.
- [x] Verify a signed round trip on a local Apple Silicon host and verify that
  a missing entitlement returns `HV_DENIED`.
- [x] Stage a runtime-owned, checksum-verified macOS libkrun bundle only for
  the isolated shim.
- [x] Create, configure plain agent vsock, and release one libkrun context
  without entering a VM.
- [ ] Boot the pinned A3S Linux kernel and immutable system root.
- [ ] Establish the macOS host endpoint and AF_VSOCK guest-agent bridge.
- [ ] Run the same fixed create/state/start/kill/delete OCI lifecycle used by
  WHPX.
- [ ] Prove deterministic VM, process, descriptor, and filesystem cleanup.
- [ ] Retain negative evidence for unavailable virtualization and failed guest
  startup. Missing-entitlement and invalid-runtime-asset evidence is complete.

Exit gate: a fresh Apple Silicon host test boots the utility VM, completes the
fixed OCI lifecycle through the authenticated guest agent, validates negative
isolation cases, and leaves no process, descriptor, or runtime-root leak. Only
then may HVF become `experimental`.

### R3 — Shared Linux Executor And Guest Agent

- [ ] Multi-container guest registry with per-container generations.
- [x] Create a new UTS namespace and apply the configured hostname and
  domainname before the created barrier.
- [x] Create a new mount namespace, make the inherited mount tree recursively
  private, self-bind the rootfs, and complete `pivot_root` before the created
  barrier.
- [x] Apply existing-target OCI mount entries in listed order, including
  bind/rbind, common VFS flags, propagation modes, and filesystem-specific
  data.
- [x] Create new IPC, network, and cgroup namespaces atomically before the
  created barrier.
- [x] Create a new PID namespace, run the container init as namespace PID 1,
  and authenticate its host-visible PID before the created barrier.
- [ ] Namespace creation for user and time namespaces, plus joining existing
  namespaces.
- [ ] Mount-target creation, rootfs propagation overrides, idmapped and
  recursive-attribute mounts, masked paths, read-only paths, and read-only
  rootfs.
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

- [x] Report native namespace and cgroup v2 prerequisites without opening
  `/dev/kvm` or initializing libkrun.
- [x] Report optional KVM absence, permission failure, ioctl failure, and API
  version independently from native readiness.
- [x] Add the native Linux driver without linking or initializing libkrun.
- [x] Reuse the R3 Linux executor directly.
- [x] Prove runtime binary startup, feature inspection, Rust SDK loading, and
  the rootful core lifecycle without KVM on x86_64 and aarch64.
- [ ] Prove packaged installation and A3S Box product startup without KVM.
- [ ] Run the full Sandbox SDK suite with `/dev/kvm` absent and inaccessible.
- [x] Fail explicit dedicated-VM requests before runtime state or driver
  mutation.
- [ ] Reject unavailable dedicated-VM selection in A3S Box before image
  mutation.

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
| macOS libkrun/HVF | HVF capability and signed VM-object evidence | Same guest lifecycle as WHPX | Driver-specific isolation and soak gates |

Promotion is monotonic and evidence-based. Host hypervisor availability alone
never enables workload launch.

## Commit And Integration Policy

Each coherent, tested increment is committed and pushed to
`git@github.com:A3S-Lab/OCI-Runtime.git`. The `a3s` monorepo gitlink is updated
only after the runtime commit is remotely available and all focused checks
pass. Unrelated dirty submodules are never staged.
