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
- native Linux namespace, cgroup v2, and pidfd signaling prerequisite
  reporting that does not touch `/dev/kvm`;
- Linux KVM device, access, ioctl, and API-version reporting without libkrun
  initialization;
- Apple Silicon and Hypervisor.framework capability reporting through a
  direct `kern.hv_support` query;
- entitlement-aware direct Hypervisor.framework VM-object create/destroy
  evidence with versioned, fail-closed diagnostics;
- isolated macOS libkrun context create/configure/plain-vsock/release evidence
  from a checksum-pinned, runtime-reverified arm64 bundle;
- real macOS HVF guest entry using the pinned libkrun firmware kernel and a
  digest-verified Alpine arm64 userspace, with natural exit status, exact
  host-visible marker verification, bounded worker reap, and marker cleanup;
- real macOS static arm64 guest-agent boot through AF_VSOCK and a private Unix
  socket, with `LOCAL_PEERPID`, direct shim-worker parent verification,
  one-time token authentication, protocol-v2 negotiation, exact six-operation
  advertisement, process-group termination, exact endpoint removal,
  observed PID reap, and in-process descriptor-inventory restoration;
- real macOS fixed-bundle create/state/start/kill/wait/delete evidence using
  the shared Windows lifecycle harness, including exact mutation retries,
  create/start separation, bounded running wait, exact repeated normal exit
  status, running and stopped observation, post-delete NotFound, and nominal
  process, endpoint, marker, and runtime-root cleanup;
- real macOS no-delete cleanup after successful create, start, and kill
  boundaries, with exact fault identity, guest executor shutdown, endpoint and
  marker removal, shim/worker reap, descriptor-inventory restoration, and no
  new guest runtime root;
- explicit rootful native Linux driver integration that reuses the shared
  executor without linking or initializing libkrun;
- real native Linux create/state/start/kill/wait/delete SDK evidence on x86_64
  and aarch64, including exact repeated SIGKILL status and bounded running
  wait, repeated with `/dev/kvm` absent and present but unusable;
- type-checked joins for existing UTS, mount, IPC, network, cgroup, PID, user,
  and time namespaces, including retained rootfs execution after a mount join,
  three-pass user-namespace permission recovery, and shared native Linux/macOS
  utility-VM lifecycle evidence;
- detached ID-mapped filesystem and bind mounts using exact dedicated or
  container user-namespace mappings, including native `idmap` versus `ridmap`
  recursion and unchanged source-ownership evidence plus shared native
  Linux/macOS utility-VM lifecycle evidence;
- real native Linux no-delete cleanup after create, start, and kill on x86_64
  and aarch64, including init-PID reap and executor, durable-state, marker, and
  session-root removal;
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
  create-time UTS, mount, IPC, network, cgroup, PID, user, and time namespaces,
  parent-installed UID/GID maps, verified time offsets, hostname and domainname,
  isolated rootfs propagation, ordered OCI mounts with missing target
  creation, masked and read-only paths, read-only rootfs enforcement,
  `pivot_root`, authenticated host-visible PID reporting, exact-generation
  state, bounded typed init rejection reporting, session idempotency, retained
  pidfd signaling, and cleanup;
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
  with exact bundle and response correlation, protocol-v1 compatibility, and
  protocol-v2 stable init wait;
- existing `features` CLI path routed through the Rust SDK;
- single-writer durable state for the complete core lifecycle, with exact
  bundle snapshots, monotonic generations, generation fencing, global
  idempotent create/start/kill/delete journals, active-operation claims,
  terminal failure replay, crash reconciliation, and quarantine;
- async `RuntimeDriver` integration plus a tested host implementation of
  `create`, `state`, `start`, `kill`, `delete`, and driver-advertised `wait`;
- typed, exhaustive recovery injection at all 237 registered durable commit
  stages and all 14 before/after `RuntimeDriver` method boundaries;
- runtime-owned Windows state paths with protected DACLs limited to the
  runtime principal and LocalSystem, inheritance disabled, and every applied
  owner and ACL verified;
- Windows, Linux, and macOS CI.

Not yet complete:

- fault injection inside every utility-VM host/agent transport transition;
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
`RuntimeDriver` advertises the five required core lifecycle operations plus
only the optional operations that driver implements.

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
- [x] Fault-inject every registered core-lifecycle durable commit stage and
  every `RuntimeDriver` method boundary, then reopen and replay.
- [ ] Implement all OCI hook phases and error behavior.
- [ ] Implement `run` as a client composition, not a second lifecycle.

Exit gate: lifecycle tests pass under fault injection at every durable write
and host/agent transition. The durable-write and `RuntimeDriver` portions pass;
the utility-VM host/agent transport portion remains open.

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
- [x] Enter a real HVF VM in an isolated, bounded worker and require a
  guest-written host marker, natural zero exit, worker reap, and marker
  cleanup.
- [x] Retain fail-closed unavailable-HVF and missing-entitlement evidence
  without accepting pre-entry configuration as guest execution.
- [ ] Boot the pinned A3S Linux kernel and immutable system root.
- [x] Establish the private macOS Unix endpoint and AF_VSOCK guest-agent
  bridge, verify that the peer is the shim's direct VM worker child, and
  authenticate protocol-v2 negotiation with a one-time token.
- [x] Run the same fixed create/state/start/kill/wait/delete OCI lifecycle used
  by WHPX, including bounded running wait and exact repeated exit status.
- [x] Prove deterministic VM, process, descriptor, and filesystem cleanup
  without normal delete after successful create, start, and kill boundaries.
  Each phase requires exact endpoint removal, observed-PID reap, complete
  descriptor-inventory restoration, marker removal, and no new guest runtime
  root.
- [x] Retain fail-closed unavailable-virtualization, missing-entitlement,
  invalid-runtime-asset, missing-agent-rootfs, wrong-token, and unexpected-peer
  evidence without reporting false negotiation.

Exit gate: a fresh Apple Silicon host test boots the utility VM, completes the
fixed OCI lifecycle through the authenticated guest agent, validates negative
isolation cases, and leaves no process, descriptor, or runtime-root leak. Only
then may HVF become `experimental`.

### R3 — Shared Linux Executor And Guest Agent

- [x] Multi-container guest registry with per-container generations, proven
  with two distinct bundles, simultaneous create barriers, independent
  start/kill/wait/delete, nonblocking wait/state progress, exact replay
  isolation, generation-1 fencing after generation-2 recreation, and complete
  cleanup through native Linux and the macOS utility VM.
- [x] Create a new UTS namespace and apply the configured hostname and
  domainname before the created barrier.
- [x] Create a new mount namespace, make the inherited mount tree recursively
  private, self-bind the rootfs, and complete `pivot_root` before the created
  barrier.
- [x] Apply OCI mount entries in listed order, including safe missing
  directory/file target creation, bind/rbind, common VFS flags, propagation
  modes, and filesystem-specific data.
- [x] Create new IPC, network, and cgroup namespaces atomically before the
  created barrier.
- [x] Create a new PID namespace, run the container init as namespace PID 1,
  and authenticate its host-visible PID before the created barrier.
- [x] Prove executor shutdown cleanup without delete after successful create,
  start, and kill through native Linux and the macOS utility-VM path.
- [x] Open and retain a pidfd for every authenticated init process, reject
  kernels without `pidfd_open` and `pidfd_send_signal`, and deliver lifecycle
  and cleanup signals without a numeric-PID reuse race. Prove the path through
  native Linux and the macOS utility VM.
- [x] Retain exact normal-or-signal init termination, return the same result
  from repeated waits, enforce bounded wait timeouts, and prove one container's
  wait does not block another container's state request.
- [x] Create new rootful user and time namespaces, install and read back exact
  UID/GID mappings through the authenticated parent, apply and verify
  monotonic/boottime offsets, switch to mapped namespace-root credentials
  before rootfs mutation, and prove the path through native Linux and the
  macOS utility VM.
- [x] Open and type-check all existing namespace descriptors before mutation,
  join non-user namespaces around the user-namespace capability transition,
  preserve PID/time next-child semantics, and prove UTS, mount, IPC, network,
  cgroup, PID, user, and time joins through native Linux and the macOS
  utility-VM path.
- [x] Apply private, shared, slave, and unbindable rootfs propagation,
  masked paths, read-only paths, and read-only rootfs enforcement; prove the
  same create/start barrier and exact cleanup through native Linux and the
  macOS utility VM.
- [x] Apply all OCI recursive VFS mount attributes with `mount_setattr`,
  descriptor-pin each destination, and prove top-level and nested submount
  enforcement through native Linux and the macOS utility VM.
- [x] Apply ID-mapped filesystem and bind mounts through the Linux mount API,
  use either exact per-mount mappings or the newly created container user
  namespace, distinguish non-recursive `idmap` from recursive `ridmap`, and
  prove filesystem ownership through native Linux and the macOS utility VM
  plus unchanged bind sources and exact recursion through native Linux.
- [ ] Rootless ID-mapping policy, remaining credentials, capabilities, rlimits,
  scheduler, I/O priority, affinity, LSMs, and seccomp.
- [ ] cgroup v2 CPU, memory, pids, I/O, hugepage, RDMA, device, and unified
  resource enforcement.
- [ ] Namespace-internal init supervision, orphan/zombie reaping, and exec.
- [ ] Ordered hooks with OCI state on stdin.
- [ ] Backpressured stdin/stdout/stderr, PTY, resize, signals, and output
  cursors.
- [ ] Pause, resume, update, processes, stats, and ordered events.

Exit gate: the same executor passes its lifecycle, configuration, security,
and recovery suites in the Windows guest and on native Linux.

### R4 — Native Linux Without KVM

- [x] Report native namespace, cgroup v2, and pidfd signaling prerequisites
  without opening `/dev/kvm` or initializing libkrun.
- [x] Report optional KVM absence, permission failure, ioctl failure, and API
  version independently from native readiness.
- [x] Add the native Linux driver without linking or initializing libkrun.
- [x] Reuse the R3 Linux executor directly.
- [x] Prove runtime binary startup, feature inspection, Rust SDK loading, and
  the rootful lifecycle including exact repeated init wait without KVM on
  x86_64 and aarch64.
- [x] Prove shutdown cleanup without delete after create, start, and kill on
  x86_64 and aarch64 without KVM.
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
