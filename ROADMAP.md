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

## Repository Boundary

A3S OCI Runtime is the sole low-level execution engine. It owns exact OCI
validation, actual container state, durable operation replay, process control,
platform drivers, utility VMs, the guest agent, and runtime-scoped cleanup.

A3S Box owns product configuration and desired state, image distribution and
builds, named volumes and product snapshots, network/IPAM/DNS policy, Compose,
health and restart policy, log retention, and secret authorization. Box passes
prepared, immutable execution inputs through `a3s-oci-sdk`; OCI Runtime does
not pull images, build images, implement Compose, or become a Docker daemon.

The dependency direction is strict:

```text
A3S Box or containerd shim
          |
          | a3s-oci-sdk over bounded local IPC
          v
OCI Runtime host service
          |
          +-- native Linux driver
          `-- utility-VM drivers (KVM / HVF / WHPX)
                          |
                          `-- authenticated Linux guest agent
```

Boundary rules:

1. OCI Runtime must not depend on Box product crates or durable state types.
   Box-specific fixtures may test compatibility but cannot define runtime
   semantics.
2. Box requests `DedicatedVm`, `SharedGuestKernel`, or `SharedHostKernel`.
   Runtime selects an enforcing driver and never silently weakens isolation.
3. Runtime owns actual OCI state, process/VM identity, generation, exit status,
   operation journals, recovery, and quarantine. Callers own desired state and
   retain only an exact runtime reference.
4. Image, storage, network, secret, and TEE policy stay outside the OCI core.
   Versioned extensions may attach already-authorized resources or expose
   runtime mechanisms without moving product policy into this repository.
5. The containerd runtime-v2 shim belongs here and calls the SDK directly. It
   must not shell out to A3S Box or duplicate lifecycle state.

## Delivery Milestones

The detailed workstreams below are not a strict waterfall. Integration begins
with an early vertical slice so contract problems are found before every OCI
field and platform feature is implemented.

| Milestone | Runtime delivery | Cross-repository exit gate |
| --- | --- | --- |
| M0 - Boundary freeze | Generic public contracts, attachment schemas, driver/isolation vocabulary, and state ownership | Box depends only on `a3s-oci-sdk`; runtime behavior does not depend on Box types |
| M1 - Host service | Multi-driver registry, secure Unix/Windows service endpoints, durable routing, state migration, restart reconciliation, and reattachment/cleanup | A service restart at every lifecycle boundary preserves or safely terminates the exact workload |
| M2 - Windows experimental | Launch-ready WHPX driver, protected runtime storage, pinned kernel, immutable system root, authenticated protocol-v8 agent, and leak gates | A fresh Windows host passes complete SDK lifecycle, I/O, resource, recovery, and multi-container suites |
| M3 - Box cutover | Stable SDK surface and Linux/KVM/HVF drivers needed by the unified Box adapter | Box routes `microvm` and `sandbox` through the SDK with no silent fallback |
| M4 - containerd | Runtime-v2 shim using OCI bundles and SDK operations directly | containerd task, restart, I/O, and cleanup suites pass without invoking the Box CLI |
| M5 - parity extensions | Storage/network attachments, reusable guest sessions, checkpoint/restore, and TEE mechanisms | Box storage, networking, warm-pool, snapshot, and security gates pass through public extensions |
| M6 - supported release | OCI 1.3 evidence, adversarial security, upgrade compatibility, signed packages, and long-running real-host qualification | Every advertised driver and operation has evidence from the exact release artifacts |

Conformance is continuous across M1-M6. R5 is the final audit, not the first
time normative requirements are enforced. Box migration starts after the M1
vertical slice and does not wait for every optional OCI feature.

## Current Baseline

Completed:

- independent `A3S-Lab/OCI-Runtime` repository and monorepo submodule;
- pure OCI lifecycle transition contract;
- versioned driver status, readiness, isolation, and evidence;
- deterministic multi-driver selection and durable recorded-driver routing,
  including fail-closed startup audit for missing or isolation-drifted drivers;
- protected Windows SDK host serving over a local named pipe with first-owner,
  DACL, remote-client rejection, concurrency, and shutdown-release gates;
- explicit clone-wide guest-agent transport shutdown before utility-VM shim
  reap, providing the ownership boundary required by a long-lived VM driver;
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
  one-time token authentication, protocol-v8 negotiation, exact
  eighteen-operation advertisement, process-group termination, exact endpoint
  removal, observed PID reap, and in-process descriptor-inventory restoration;
- real macOS fixed-bundle create/state/start/kill/wait/delete evidence using
  the shared Windows lifecycle harness, including exact mutation retries,
  create/start separation, bounded running wait, exact repeated normal exit
  status, exact live process inventory, cgroup-v2 pause/resume with real
  workload-progress evidence, replay-safe live CPU/memory/cpuset/PID update,
  normalized cgroup-v2 stats, running and stopped observation, post-delete
  NotFound, and nominal process, endpoint, marker, and runtime-root cleanup;
- real macOS no-delete cleanup after successful create, start, and kill
  boundaries, with exact fault identity, guest executor shutdown, endpoint and
  marker removal, shim/worker reap, descriptor-inventory restoration, and no
  new guest runtime root;
- bounded, versioned macOS HVF soak orchestration that starts a fresh utility
  VM for every complete two-container lifecycle, namespace-join, rootfs/mount,
  and PID-supervision matrix, and retains unique endpoint, process,
  descriptor, marker, runtime-root, and per-wave console evidence;
- explicit native Linux driver integration that reuses the shared executor
  without linking or initializing libkrun;
- real native Linux create/state/start/kill/wait/delete SDK evidence on x86_64
  and aarch64, including exact repeated SIGKILL status and bounded running
  wait, plus public SDK exec replay, duplicate process-ID rejection, durable
  process journals, pidfd signal replay, stable per-process wait, and init-exit
  exec cleanup, plus durable cgroup-v2 pause/resume and exact live process
  inventory, replay-safe resource update, and normalized stats with real
  workload-progress evidence, plus controlling PTY allocation, initial and
  resized dimensions, interactive I/O, merged output, and VEOF close, repeated
  with `/dev/kvm` absent and present but unusable;
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
- Linux guest bootstrap executor for an exact fail-closed OCI
  profile, with a PID-authenticated abstract Unix create/start barrier,
  create-time UTS, mount, IPC, network, cgroup, PID, user, and time namespaces,
  parent-installed UID/GID maps, verified time offsets, hostname and domainname,
  isolated rootfs propagation, ordered OCI mounts with missing target
  creation, masked and read-only paths, read-only rootfs enforcement,
  `pivot_root`, authenticated host-visible PID reporting, exact-generation
  state, a dedicated namespace PID 1 supervisor with adopted-child reaping,
  bounded typed init rejection reporting, session idempotency, retained
  workload pidfd signaling, exact-target exec registries with retained rootfs
  and namespace descriptors, per-process pidfds and replay journals, stable
  process wait, cgroup-v2 pause/resume, live process inventory, init-exit
  supervision, and complete session cleanup;
- helper-backed rootless native Linux create/start/exec/signal/wait/kill/delete
  evidence on x86_64 and aarch64, with container root mapped exactly to the
  nonzero effective host UID/GID, subordinate UID/GID ranges installed through
  verified setuid-root `newuidmap`/`newgidmap`, `setgroups=deny`, exact map and
  ownership read-back, ordered durable events, and complete cleanup;
- single-container native Linux runtime ownership behind a private `0600`
  same-UID Unix SDK endpoint, with an owner-only root, automatic A3S Box FD
  3/4/5 binding for one exact container ID, full transported lifecycle evidence,
  `SIGINT`/`SIGTERM` driver shutdown, inode-scoped socket removal, and empty
  executor-root evidence on x86_64 and aarch64 without KVM;
- shared Linux executor support for all six OCI hook phases in normative order,
  with runtime/container namespace placement, exact OCI state on stdin,
  bounded configuration, timeout and process-group cleanup, typed
  create/start failures, warning-only poststop continuation, and native Linux
  lifecycle trace evidence;
- direct A3S Box compiler compatibility fixture pinned to Box commit
  `d24c951989c8ee8dbc772ccd0021713855613656`, with schema/semantic loading and
  fail-closed executor planning for its absolute rootfs, annotations,
  capabilities, cgroup v2 resources, exact device allowlist, legacy `cgroup`
  mount normalization, and AArch64 seccomp policy;
- Linux executor enforcement for exact capability sets and exec bounding
  ceilings, private controller-enabled cgroup-v2 management,
  memory/CPU/cpuset/PID settings and live updates with read-back and rollback,
  normalized cgroup stats, exact static device nodes within a bounded
  default-deny profile, and pure-Rust x86_64/AArch64 seccomp BPF retained
  across init and exec;
- versioned control/workload cgroup topology for trusted A3S Box init: exact
  `linux.resources` enforcement on `a3s-workload`, derived outer control-plane
  headroom, pre-opened FD 6/7 membership handoff, read-only guest cgroupfs,
  workload-scoped update/freeze/stats, non-group OOM behavior, and complete
  topology cleanup;
- real WHPX fixed-bundle create/state/start/kill/delete evidence, including
  exact mutation retries, pre-start non-execution, running and stopped
  observation, marker verification, post-delete NotFound, and nominal leak
  checks;
- focused real-host WHPX transport regression evidence across one serial and
  two parallel lifecycles, network namespace, storage, volume-init, nine
  negative, and four owner-termination cases, including a request above the
  4 KiB stream boundary;
- a runtime-owned Windows libkrun bundle pinned to the 3 KiB host-to-guest
  stream segmentation fix, with deterministic archive and payload checksums;
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
- OCI feature reporting for all eight Linux namespaces, 41 capability names,
  cgroup v2, x86_64/AArch64 seccomp actions and operators, and ID-mapped
  mounts, with unsupported managers, flags, and security modules disabled;
- phase-aware, bounded common, Linux, and VM semantic validation boundary;
- exhaustive SDK request validation on in-process and transport boundaries;
- version-negotiated, length-delimited transport for every SDK operation;
- tested Windows named-pipe and Unix-domain-socket client connectors;
- authenticated, version-negotiated, bounded host/guest lifecycle protocol
  with exact bundle and response correlation, protocol-v1 compatibility, and
  protocol-v2 stable init wait plus protocol-v3 exact-target exec, process
  signal, and process wait messages, all dispatched by the shared Linux
  executor with version-filtered capability advertisement, plus protocol-v4
  pause, resume, and live process inventory, protocol-v5 update and stats,
  protocol-v6 bounded process I/O, protocol-v7 terminal resize, and
  protocol-v8 durable process-I/O mutation contexts with exact session replay;
- existing `features` CLI path routed through the Rust SDK;
- foreground `run` implemented only as a typed SDK composition of durable
  create, start, wait, and stable force-delete cleanup;
- deterministic durable container enumeration with isolation filtering,
  complete record validation, host-service reopen evidence, and no driver
  dispatch;
- durable exact-generation lifecycle and process events with global ordered
  cursors, replay-safe identities, bounded filtering, long polling, crash
  repair, host-service reopen evidence, and no driver dispatch;
- single-writer durable state for the complete core lifecycle, with exact
  bundle snapshots, monotonic generations, generation fencing, global
  idempotent create/start/kill/delete journals, active-operation claims,
  terminal failure replay, crash reconciliation, and quarantine;
- deterministic multi-driver registration with one owner per isolation class,
  identical advertised operation/Hook surfaces, create-time selection, and
  exact recorded-driver routing across host-service reopen;
- async `RuntimeDriver` integration plus a tested host implementation of
  `create`, `state`, `start`, `kill`, `delete`, and driver-advertised `wait`,
  `exec`, `signal-process`, `wait-process`, `pause`, `resume`, `processes`,
  `update`, `stats`, `read-output`, `write-stdin`, `close-stdin`, and `resize`;
- generation-scoped durable process records, global exec, per-process signal,
  and write-stdin/close-stdin/resize journals, durable update journals,
  terminal failure replay, active-operation claims, and stable init/exec
  exit-status caching across host-service reopen;
- typed, exhaustive recovery injection at all 657 registered durable commit
  stages and all 38 before/after `RuntimeDriver` method boundaries;
- runtime-owned Windows state paths with protected DACLs limited to the
  runtime principal and LocalSystem, inheritance disabled, and every applied
  owner and ACL verified;
- Windows, Linux, and macOS CI.

Not yet complete:

- fault injection inside every utility-VM host/agent transport transition;
- descriptor-relative path resolution;
- complete shared guest OCI executor;
- a production workload driver;
- OCI hook rollback, crash recovery, security-negative, and soak
  certification;
- OCI configuration enforcement;
- production-ready native Linux execution;
- A3S Box migration;
- upstream conformance and security certification.

The built-in WHPX driver remains `probe-only`, and the default host service
advertises only `features`. A host explicitly opened around a launch-ready
`RuntimeDriver` advertises the five required core lifecycle operations,
host-owned durable `list` and `events`, plus only the optional operations that
driver implements.

## Detailed Workstreams

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
- [x] Extend idempotent journals to exec and per-process signal, including
  generation-scoped process claims and terminal failure replay.
- [x] Extend idempotent journals to pause and resume, including exact freezer
  observation, reconciliation, claim release, and terminal failure replay.
- [x] Extend idempotent journals to update, including exact retry, terminal
  failure replay, claim release, and fault-injected recovery.
- [x] Extend idempotent journals to write-stdin, close-stdin, and resize,
  including exact driver/guest replay, claim release, terminal failure replay,
  and fault-injected recovery.
- [x] Reconcile interrupted core lifecycle operations and quarantine failed
  create/delete state.
- [x] Implement driver-independent `create`, `state`, `start`, `kill`, and
  `delete` host orchestration.
- [x] Register multiple launch-ready drivers behind one host service, reject
  ambiguous isolation ownership and inconsistent advertised surfaces before
  state creation, and route every post-create operation by the durable driver
  identity rather than registration order.
- [x] Preserve the exact create/start barrier in the durable host/driver
  contract.
- [x] Verify the barrier against the real Linux guest bootstrap executor.
- [x] Fault-inject every registered core-lifecycle durable commit stage and
  every `RuntimeDriver` method boundary, then reopen and replay.
- [x] Implement all OCI hook phases with typed create/start failure, bounded
  timeout/process-group cleanup, and warning-only poststop behavior.
- [x] Implement `run` as a client composition, not a second lifecycle.

Exit gate: lifecycle tests pass under fault injection at every durable write
and host/agent transition. The durable-write and `RuntimeDriver` portions pass;
the utility-VM host/agent transport portion remains open.

### R2 — Windows WHPX Utility VM

- [x] Load and probe Windows Hypervisor Platform securely.
- [x] Create and delete a real WHPX partition object.
- [x] Pin the `a3s-libkrun-sys 3.1.0` FFI ABI and stage a runtime-owned,
  checksum-verified Windows bundle for the isolated shim, with firmware
  provenance from `A3S-Lab/Box@46e17a8` and WHPX stream transport from
  `A3S-Lab/libkrun@9480ee3`.
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
- [x] Run a fixed configured process through distinct OCI create and start
  calls.
- [x] Verify running state, exact create/kill/delete replay, signal-driven
  stopped state, post-delete NotFound, marker cleanup, and no new guest
  runtime directory on the nominal path.
- [x] Qualify the 3 KiB stream fix with serial and two-lane parallel lifecycle,
  network namespace, storage, volume-init, typed negative, and four-point
  owner-termination cleanup paths without residual host processes or guest
  runtime directories.
- [ ] Prove in-process native handle reclamation independently of Windows
  process teardown.

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
  authenticate protocol-v8 negotiation with a one-time token.
- [x] Run the same fixed create/state/start/kill/wait/delete OCI lifecycle used
  by WHPX, including bounded running wait, exact repeated exit status,
  pause/resume, live process inventory, resource update, and normalized stats.
- [x] Prove deterministic VM, process, descriptor, and filesystem cleanup
  without normal delete after successful create, start, and kill boundaries.
  Each phase requires exact endpoint removal, observed-PID reap, complete
  descriptor-inventory restoration, marker removal, and no new guest runtime
  root.
- [x] Add a bounded, versioned 25-wave HVF soak gate that creates a fresh VM
  for every complete two-container matrix, retains three primary generations
  per wave, rejects endpoint and descriptor drift, and uploads its JSON report
  and per-wave consoles in CI.
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
- [x] Create a new PID namespace, retain a dedicated namespace PID 1
  supervisor, run the configured container process as PID 2+, and authenticate
  the launcher-to-supervisor-to-process identity chain before the created
  barrier.
- [x] Prove executor shutdown cleanup without delete after successful create,
  start, and kill through native Linux and the macOS utility-VM path.
- [x] Open and retain a pidfd for every authenticated configured process,
  reject kernels without `pidfd_open` and `pidfd_send_signal`, and deliver
  lifecycle and cleanup signals without a numeric-PID reuse race. Prove the
  path through native Linux and the macOS utility VM.
- [x] Retain exact normal-or-signal configured-process termination, return the
  same result from repeated waits, enforce bounded wait timeouts, and prove one
  container's wait does not block another container's state request.
- [x] Create new rootful user and time namespaces, install and read back exact
  UID/GID mappings through the authenticated parent, apply and verify
  monotonic/boottime offsets, switch to mapped namespace-root credentials
  before rootfs mutation, and prove the path through native Linux and the
  macOS utility VM.
- [x] Create a new rootless user namespace from a non-root native executor,
  require exact size-1 effective-UID/GID mappings for container root, install
  subordinate ranges through fixed root-owned setuid mapping helpers, deny
  supplementary groups, read back both maps and `setgroups=deny`, and prove
  the core lifecycle plus exec and ordered events on x86_64 and aarch64.
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
- [x] Apply and verify OCI capability bounding, effective, permitted,
  inheritable, and ambient sets, and prevent exec from exceeding the
  configured init bounding ceiling.
- [x] Validate, retain, and apply every OCI `process.rlimits` type before
  credential reduction for both init and exec; reject duplicates, inverted
  soft/hard values, and unbounded plans, and verify `RLIMIT_NOFILE` through
  the native Linux workload.
- [x] Compile and install pure-Rust x86_64/AArch64 seccomp BPF with OCI
  argument comparisons, stacked default/specific actions, and retained exec
  policy.
- [x] Apply and read back cgroup v2 memory limit/reservation/swap, CPU
  shares/quota/period/cpuset, and PID limits; join init and exec to the same
  owned leaf; freeze and thaw that leaf through `cgroup.freeze` and verify the
  exact transition through `cgroup.events`.
- [x] Create a private controller-enabled cgroup-v2 manager, apply
  generation-fenced partial resource updates with exact read-back and
  reverse-order rollback, and expose normalized CPU, memory, PID, and event
  statistics through native Linux and the shared utility-VM lifecycle harness.
- [x] Add the opt-in `control-workload-v1` topology for a trusted configured
  init: retain exact workload limits in `linux.resources`, derive a bounded
  outer management envelope, create fixed control/workload children, pass
  collision-checked membership FDs, keep guest cgroupfs read-only, and update,
  freeze, inspect, and clean up the workload topology through the same cgroup
  owner.
- [x] Enforce the bounded A3S Box static device-node profile with
  default-deny policy-shape validation, rootfs scans, `nodev` bind mounts,
  CAP_MKNOD exclusion, and verified device-node creation.
- [ ] Rootless ID-mapping policy, remaining credentials, scheduler,
  I/O priority, affinity, LSMs, multi-architecture/notification seccomp, and
  broader device policies.
- [ ] cgroup v2 I/O, hugepage, RDMA, unified resources, device-access BPF,
  delegation breadth, and full lifecycle evidence.
- [x] Reap adopted orphan and zombie processes under namespace PID 1, terminate
  all remaining namespace processes after the configured process exits, and
  preserve that process's exact exit code or terminating signal.
- [x] Add exact-generation container exec with a reserved init process ID,
  shared fail-closed OCI process planning, retained rootfs and all configured
  namespace descriptors, authenticated helper/parent/PID/root/namespace
  identities, per-process pidfds, replay-safe signal, stable repeated wait,
  WNOWAIT process-group cleanup, and automatic exec termination when init or
  the agent session exits. Prove the path through native Linux and the shared
  utility-VM lifecycle harness.
- [x] Put configured and exec workloads in separately supervised process
  groups, retain each leader with pidfd plus non-reaping wait ownership, use
  `waitid(WNOWAIT)` in fork supervisors, serialize signal/reap through a
  cross-process lease, and fan replay-safe `kill(all=true)` signals across
  every live group without requiring delegated cgroup v2. Prove descendant
  delivery and the closed PGID-reuse race with real Linux regressions and the
  rootless native lifecycle.
- [x] Add exact-generation live init/exec process inventory plus replay-safe
  pause/resume, and prove with a progress-producing workload that cgroup freeze
  stops execution and resume restarts it through native Linux and the shared
  utility-VM lifecycle harness.
- [x] Ordered hooks with OCI state on stdin.
- [x] Backpressured piped stdin, bounded captured stdout/stderr, controlling
  PTYs, initial terminal dimensions, resize, merged terminal output, VEOF
  close, signals, and byte-accurate output cursors.
- [x] Native inherited descriptor handoff for the A3S Box exec listener on FD
  3, PTY listener on FD 4, and dedicated init log on FD 5, with type/role/count
  validation, collision-safe child `dup2`, stable host/agent replay schemas,
  non-native rejection, exact listener/log lifecycle evidence, and cleanup.
- [x] Update and stats.
- [x] Persist exact-generation lifecycle and process events behind a global
  nonzero sequence, deterministic replay identity, bounded pagination and
  filtering, exclusive cursors, long polling, crash repair, and host-service
  reopen. The configured host owns and advertises `events` without driver or
  guest dispatch, and native Linux verifies the exact lifecycle stream.

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
  the rootful lifecycle including exact repeated init wait plus public SDK
  exec/signal/wait, pause/resume, process inventory, resource update, and
  normalized stats plus PTY allocation, resize, interactive I/O, and VEOF
  without KVM on x86_64 and aarch64.
- [x] Prove the helper-backed non-root core lifecycle with subordinate
  UID/GID ownership and `setgroups=deny` on x86_64 and aarch64; rootless
  cgroup-v2 delegation remains a separate release gate.
- [x] Prove shutdown cleanup without delete after create, start, and kill on
  x86_64 and aarch64 without KVM.
- [x] Add the Sandbox-scoped native runtime owner, bind its protected Unix SDK
  endpoint, route the complete lifecycle through `a3s-oci-sdk`, fence inherited
  Box descriptors to one container ID, and prove signal-driven cleanup on
  x86_64 and aarch64 without KVM.
- [x] Add a bounded, versioned native complex-container soak that repeatedly
  drives concurrent lifecycle, query, captured exec, pause, durable service
  reopen, resume, generation reuse, and leak checks across four independent
  slots on x86_64 and aarch64 without KVM. CI defaults to 25 waves, verifies
  100 complete lifecycles from dynamic operation counts, and retains each
  architecture's JSON report.
- [x] Retain a versioned real-driver configuration matrix for private,
  host-inherited, and donor-shared network namespaces; shared/read-only bind
  and private-tmpfs storage; inline/script/direct/nonzero init; and selected
  create/start/timeout/poststop Hook failure behavior on x86_64 and aarch64.
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
- [ ] Cross-check supported bundles with upstream OCI lifecycle validation
  tools without shipping a second runtime backend.
- [ ] Run hook-order, rollback, recovery, security-negative, and soak suites.
- [ ] Publish an exact, generated support manifest with no unclassified field.

Exit gate: the release report contains retained evidence for every applicable
normative MUST and MUST NOT requirement in OCI Runtime Specification 1.3.0.

### R6 — A3S Box Migration

- [x] Add the pinned `a3s-oci-sdk` dependency to A3S Box.
- [x] Implement the Box adapter using SDK types only.
- [ ] Add an early cross-platform vertical slice for create, state, start,
  wait, kill, delete, exact exit status, and runtime-service restart before
  completing every optional OCI field.
- [ ] Route both Box isolation choices through the SDK: `microvm` requests
  `DedicatedVm`, while `sandbox` requests `SharedHostKernel`.
- [ ] Persist only the exact OCI container ID, generation, endpoint, and driver
  evidence needed for reconciliation; stop persisting runtime-owned process,
  VM, socket, pipe, and cgroup identities in new records.
- [ ] Preserve commands, files, exec, PTY, logs, stats, pause/resume, stop,
  kill, recovery, and cleanup behavior.
- [ ] Complete the Box cross-platform behavior and soak suites against A3S OCI
  Runtime.
- [ ] Qualify the Box R17 resource profile against `control-workload-v1`,
  including exact CPU/memory/PID enforcement, control-service survival under
  workload OOM pressure, and zero leaked processes or cgroups.
- [x] Remove external-runtime discovery, direct invocation, configuration, and
  fallback paths.
- [ ] Remove Box's direct libkrun, VMM, guest-init, and containerd-shim paths
  only after their replacement gates pass through the packaged OCI Runtime.

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
