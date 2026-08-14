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
| M2 - Windows experimental | Launch-ready WHPX driver, protected runtime storage, pinned kernel, immutable system root, authenticated protocol-v10 agent, and leak gates | A fresh Windows host passes complete SDK lifecycle, I/O, filesystem, resource, recovery, and multi-container suites |
| M3 - Box cutover | Stable SDK surface and Linux/KVM/HVF drivers needed by the unified Box adapter | Box routes `microvm` and `sandbox` through the SDK with no silent fallback |
| M4 - containerd | Runtime-v2 shim using OCI bundles and SDK operations directly | containerd task, restart, I/O, and cleanup suites pass without invoking the Box CLI |
| M5 - parity extensions | Storage/network attachments, reusable guest sessions, checkpoint/restore, and TEE mechanisms | Box storage, networking, warm-pool, snapshot, and security gates pass through public extensions |
| M6 - supported release | OCI 1.3 evidence, adversarial security, upgrade compatibility, signed packages, and long-running real-host qualification | Every advertised driver and operation has evidence from the exact release artifacts |

Conformance is continuous across M1-M6. R5 is the final audit, not the first
time normative requirements are enforced. Box migration starts after the M1
vertical slice and does not wait for every optional OCI feature.

## Remaining Work Execution Plan

The detailed workstreams below are the canonical task checklist. This section
orders that work; it does not maintain a second completion state.

| Wave | Outcome | Canonical workstreams | Exit evidence |
| --- | --- | --- | --- |
| W0 - Evidence and host safety | Close normative classification, descriptor-relative ownership, and utility-VM transport recovery gaps before widening launch claims | R0, R1, R5 | No unclassified requirement or silent path fallback; every injected host/agent interruption recovers or cleans up the exact generation |
| W1 - Native Linux qualification | Turn the existing explicit Native Linux path into a packaged, reproducible A3S Box Sandbox baseline without KVM | R3, R4 | Signed or checksummed packages pass the complete Rust, Python, TypeScript, and Go Sandbox suites on x86_64 and aarch64 with `/dev/kvm` absent and inaccessible |
| W2 - Real-driver restart continuity | Reattach supported live process, I/O, and filesystem sessions after an out-of-process runtime restart, or terminate them with exact durable evidence | R1, R6 | Native Linux and one utility-VM driver pass the same owner-death and service-restart matrix without duplicate effects, invented exit status, or leaked resources |
| W3 - Utility-VM experimental drivers | Qualify immutable guest assets and complete WHPX first, followed by HVF and KVM through the same SDK and guest-agent contract | R2, R2M, R2L, R3 | Each promoted driver independently passes lifecycle, I/O, filesystem, resource, recovery, negative-isolation, multi-container, and soak gates on a fresh host |
| W4 - A3S Box cutover | Route both Box isolation choices through the SDK and remove fallback only after behavior and recovery parity pass | R6 | `microvm` and `sandbox` use recorded SDK routes with no direct VMM path, no silent fallback, and complete cross-platform behavior and soak evidence |
| W5 - Downstream adapters and extensions | Add containerd and optional parity mechanisms without moving product policy into the runtime | R7, R8 | Each adapter or extension is version-negotiated, separately advertised, restart-safe, and tested through public SDK contracts |
| W6 - Supported release | Finish upstream OCI, adversarial security, upgrade, packaging, and long-running qualification against exact release artifacts | R5, M6 | The release report binds every advertised driver and operation to passing evidence from the published artifacts |

R5 work runs throughout every wave. W6 is the final audit of evidence produced
earlier, not a late conformance implementation phase. Work within a wave may
run in parallel, but a readiness promotion waits for that wave's complete exit
evidence.

Every retained real-host report must identify the source commit, package or
runtime-asset digest, platform, architecture, driver, isolation class, schema
version, and exact test profile. A green capability probe, an unretained local
run, or evidence from a different artifact does not satisfy an exit gate.

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
- single-owner utility-VM sessions with clone-safe guest access and idempotent
  retained cleanup evidence, exercised by WHPX/HVF lifecycle harnesses;
- one shared 20-workload-operation guest-to-driver adapter, including
  exact-target
  file transfer and filesystem metadata/mutations, plus a
  qualification-only WHPX `RuntimeDriver` candidate that owns one VM per
  exact dedicated-VM generation, serializes same-ID launch without blocking
  distinct container VMs, retains retryable create sessions, reaps terminal
  failures and deletes once, and refuses bundles outside a protected,
  per-generation runtime share mounted separately from the system root;
  owner-death restart reconciliation retains an exact-generation stopped
  tombstone and replays authenticated exit evidence when available;
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
  one-time token authentication, protocol-v10 negotiation, exact advertisement
  of 20 workload operations plus one maintenance acknowledgement,
  process-group termination, exact endpoint
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
- real macOS protocol-v9 `create` interruption at all four Host and five Guest
  request/dispatch/response transitions, with one exact crossing, nonce-bound
  Guest cleanup evidence, no normal delete, complete Guest runtime cleanup,
  and Host endpoint, process, and descriptor restoration, plus both explicit
  Host shutdown transitions after a successful `create`, with idempotent owner
  close and the same complete cleanup evidence;
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
- a long-lived multi-container Native Linux host owner behind the same private
  same-UID Unix SDK contract. It opens the durable service and experimental
  driver before publishing `runtime.sock`, accepts ordinary SDK attachments
  without Box process-local descriptors, preserves exact recorded-driver and
  generation routing across reopen, and performs bounded driver shutdown. The
  explicitly opted-in x86_64 and aarch64 Box production routes now prepare
  bundles and launch through this owner; default routing, transparent
  live-session reattachment, and cross-platform cutover remain;
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
- public-SDK-only A3S Box lifecycle, process-session, filesystem,
  observability, and resource-control consumer at Box commit `a16772c3`, with
  isolation preflight before product reservation, distinct product/runtime
  identities and generations, exact endpoint/driver/configuration/attachment
  binding, attachment-schema negotiation before product mutation, stable SDK
  operation IDs, lost create/start response recovery without duplicate create,
  stopped-only cleanup, graceful-signal escalation, exact terminal projection,
  and memory-retaining pause/resume with capability preflight, claim-scoped
  replay identities, immutable binding validation, and lost-response
  reconciliation without repeating freezer mutations. The same in-process
  contract suite now binds captured and streaming exec to the exact OCI
  generation; rejects unavailable capabilities, stale generations, alternate
  rootfs, invalid IDs, empty commands, and changed keyed content before a
  second process can start; proves replay-safe stdin, cursor-checked output,
  signal/wait, PTY/resize, exact normal and signaled status, raw-log separation,
  timeout cleanup, and caller-cancellation cleanup. Exact live process targets,
  normalized stats, and strict ordered-event cursors are rechecked against the
  same runtime binding. Partial Box resource intent is compiled into one
  complete OCI contract, claimed before mutation, replayed after a lost
  response with one runtime effect, and published atomically to both managed
  restart state and compatibility state. An immutable create-intent digest
  keeps the original create operation replayable after later resource changes.
  File upload/download and filesystem stat/mkdir/move/list/remove use the same
  cross-platform session facade with capability and Box-generation preflight,
  bounded response conversion, target/shape drift rejection, and one-effect
  replay of explicitly retryable mutations. Native Linux executes those calls
  in a bounded parent-death helper that inherits only the retained root plus
  exact user/mount namespace descriptors, validates descriptor order and
  uniqueness, and enters the namespaces before applying container IDs. The
  native fixture now mounts `/tmp` as tmpfs so the real filesystem smoke covers
  namespace-owned mounts rather than only the image rootfs. The deterministic cross-process
  contract now retains the Box process stream and input handle through an
  observed owner disconnect, then continues inventory, stdin, output, signal,
  wait, and cleanup after reconnecting to a replacement durable host service.
  The x86_64 and aarch64 production owner routes and fresh-Box-process
  stopped-only restart gates now pass; real-driver live-session reattachment
  plus WHPX, default-routing, and broader cutover gates remain open;
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
- direct qualification-only WHPX `RuntimeDriver` evidence through the exact
  protected per-generation share, including create/start/kill/wait replay,
  authenticated shutdown-report publication, stopped-only delete, and
  process/share/recovery cleanup;
- focused real-host WHPX transport regression evidence across one serial and
  two parallel lifecycles, network namespace, storage, volume-init, nine
  negative, and four owner-termination cases, including a request above the
  4 KiB stream boundary;
- a runtime-owned Windows libkrun bundle pinned to the 3 KiB host-to-guest
  stream segmentation and writable virtio-fs `fsync` fixes, with deterministic
  archive and payload checksums;
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
- public `a3s.oci.attachments.v1` derivation and validation for rootfs, mounts,
  networking, process I/O, secret classifications, and optional runtime
  extensions, with fail-closed protocol-3 negotiation, durable manifest
  retention, and exact digest replay;
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
  protocol-v8 durable process-I/O mutation contexts with exact session replay,
  plus protocol-v9 descriptor-confined file and filesystem sessions and
  protocol-v10 bounded Host acknowledgement of completed Guest replay records;
- an exhaustive negotiated-version fault registry for all 21 guest
  operations, spanning four host request/response stages, five guest
  read/dispatch/write stages, and two host shutdown stages. An authenticated
  in-memory matrix injects every one of the 189 operation-stage pairs, proves
  one crossing and terminal disconnect per point. A portable agent-backed
  `RuntimeDriver` matrix also arms each of the nine transport stages exactly
  once for all 20 public workload operations across durable
  `HostRuntimeService` reopen.
  Pre-dispatch faults defer the
  guest request until the replacement connection; post-dispatch mutation faults
  replay the guest journal while read-only state and uncached wait observations
  are safely reissued. A fully written mutation response replays the completed
  durable record, while a fully written wait response replays its durable terminal
  cache. Every path preserves the exact generation; mutations retain one effect
  and reject changed retries, state resolves a current target to that exact
  generation, wait and wait-process return stable exact exit results while
  stale targets fail closed, exec preserves the exact process ID, PID, and terminal mode, and
  signal-process preserves the exact target and signal;
- existing `features` CLI path routed through the Rust SDK;
- reconnectable local SDK endpoints that expose the first broken-stream result
  without hidden replay, discard the poisoned stream, and renegotiate on the
  next caller-initiated request. Real Windows named-pipe and Unix-socket tests
  restart the server behind one retained `RuntimeClient`; caller-supplied
  `from_io` streams remain fail-closed and non-reconnectable;
- cross-platform runtime-owner process restart coverage that launches two
  distinct test-binary processes on the same platform-local endpoint and
  durable `HostRuntimeService` state root. One retained client exposes owner
  death, reconnects to the replacement, recovers the exact generation and live
  exec target, replays create/start/exec with one deterministic test-driver
  dispatch each, and continues inventory, stdin, signal, wait, output, and
  cleanup through the replacement owner;
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
  stages and all 44 before/after `RuntimeDriver` boundaries, including startup
  recovery;
- runtime-owned Windows state paths with protected DACLs limited to the
  runtime principal and LocalSystem, inheritance disabled, and every applied
  owner and ACL verified;
- Windows, Linux, and macOS CI.

Not yet complete:

- real utility-VM and host-service-reopen injection at every host/agent
  transport transition;
- descriptor-relative path resolution;
- complete shared guest OCI executor;
- a production workload driver;
- OCI hook rollback, crash recovery, security-negative, and soak
  certification;
- OCI configuration enforcement;
- production-ready native Linux execution;
- real-driver live process and filesystem session reattachment;
- A3S Box default routing and cross-platform real-host cutover;
- containerd runtime-v2 task, restart, I/O, and cleanup integration;
- versioned storage, networking, reusable-session, checkpoint/restore, and TEE
  extensions;
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
- [ ] Close the 630-entry pending normative evidence backlog.
  - [ ] Classify every entry by common/process, Linux, VM, state, or feature
    semantics and record whether it is applicable to each driver profile.
  - [ ] Bind every applicable entry to an exact validator, enforcement owner,
    positive test, negative test, and retained evidence field; bind every
    inapplicable entry to a reviewed reason.
  - [ ] Make CI reject pending, unclassified, duplicate, stale, or
    source-digest-mismatched entries and require the generated ledger to reach
    zero pending entries.
- [x] Add version-negotiated local IPC transport for out-of-process callers.

Exit gate: every OCI 1.3.0 schema property is accounted for as accepted,
rejected as inapplicable, or rejected because the selected driver cannot
enforce it. No property is silently ignored.

### R1 — Durable OCI Lifecycle

- [x] Add an absolute, single-writer runtime root with plain-path/reparse-point
  checks, bounded reads, and atomic file replacement.
- [x] Create, apply, and verify runtime ownership plus protected Windows state
  DACLs limited to the runtime principal and LocalSystem.
- [ ] Use descriptor-relative path operations on every supported host and
  prove that symlink, mount, and Windows reparse-point replacement cannot move
  a validated runtime-owned path before mutation.
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
- [x] Reclaim completed Native Linux guest mutation records only after the Host
  durably commits success or terminal failure. Keep prepared, retryable, and
  asynchronous in-flight effects replayable; acknowledge every derived stdin
  chunk identity; and reject mixed pending/completed acknowledgement batches
  atomically. Unit evidence fills all 4,096 guest slots before releasing them,
  and three complete containerd matrices pass through one unchanged Host PID.
- [x] Carry the same post-commit reclamation boundary across utility-VM
  protocol v10. Keep protocol-v1 through protocol-v9 acknowledgement as a
  compatibility no-op, bound each v10 batch to 1..=4,096 unique operation
  identities, and fan out safely across live HVF/WHPX sessions without holding
  session locks across transport I/O. The protocol matrix covers all 189
  operation/stage pairs; the 20-operation Host reopen matrix proves that a
  response-write disconnect returns a retryable acknowledgement error, then
  replays the durable result without redispatch and acknowledges it once after
  reopen. A real Apple Silicon Guest negotiates v10 and advertises the exact 20
  workload operations plus the maintenance acknowledgement.
- [x] Reconcile interrupted core lifecycle operations and quarantine failed
  create/delete state.
- [x] Implement driver-independent `create`, `state`, `start`, `kill`, and
  `delete` host orchestration.
- [x] Register multiple launch-ready drivers behind one host service, reject
  ambiguous isolation ownership and inconsistent advertised surfaces before
  state creation, and route every post-create operation by the durable driver
  identity rather than registration order.
- [x] Invoke an idempotent startup recovery handshake on each record's exact
  persisted driver, commit optional state observations before serving, and
  fault-inject both sides of that boundary.
- [x] Preserve the exact create/start barrier in the durable host/driver
  contract.
- [x] Verify the barrier against the real Linux guest bootstrap executor.
- [x] Fault-inject every registered core-lifecycle durable commit stage and
  every `RuntimeDriver` method boundary, then reopen and replay.
- [ ] Fault-inject every versioned utility-VM host/agent request, response,
  disconnect, replay, and shutdown transition, then prove exact-generation
  recovery or complete cleanup after host-service reopen.
  - [x] Release the clone-shared host transport immediately after terminal
    request-write, response EOF/read, correlation, or response-shape failure;
    prove retained clones cannot dispatch or keep the failed guest connection
    alive.
  - [x] Expose negotiated-version fault points for every current operation at
    four host request/response stages, five guest read/dispatch/write stages,
    and two host shutdown stages. Prove that a create completed before its
    response is lost can reconnect over a newly authenticated stream and replay
    the exact `OperationId` and request with one effect, while changed content
    under that ID fails with `Conflict`.
  - [x] Arm and cross all 189 current Guest operation-stage pairs over
    authenticated in-memory streams. Require each selected point exactly once, disconnect the
    session after every injected failure, and prove that a fault after a fully
    written response preserves that response but fails the next request.
  - [x] Carry the post-dispatch create-response-loss case through a portable
    agent-backed `RuntimeDriver`: retain the durable `creating` record after the
    first retryable failure, open a new authenticated connection and driver,
    reopen `HostRuntimeService`, and resume the same generation with two driver
    dispatches but one guest effect. Reject changed content at both the durable
    host and guest journals. Real utility-VM reopen evidence remains required.
  - [x] Expand portable create recovery across all nine host/guest transport
    stages and require each selected boundary exactly once. Prove pre-dispatch
    faults perform the first effect after reopen, post-dispatch faults replay
    one cached guest effect, and a fully written response replays directly from
    the completed durable host journal without a second driver dispatch.
  - [x] Carry read-only `state` through all nine portable reopen stages after an
    exact durable create. Resolve a current host target to the exact generation,
    expose every retryable first-call transport failure, reopen through a new
    authenticated connection and driver, and reissue the query even after a
    fully written first response. Keep durable state unchanged and reject a
    stale generation at both the host and guest boundaries without driver
    dispatch from the host.
  - [x] Apply the same nine-stage portable reopen matrix to `start` after an
    exact durable create. Keep the host record `created` after every retryable
    first-call failure even when the guest already reached `running`, resume
    through the original operation on a new authenticated connection and
    driver, and prove exactly one start effect. A fully written start response
    must replay from the completed durable journal without another dispatch.
  - [x] Apply the same nine-stage portable reopen matrix to `kill` after an
    exact durable create and start. Keep the host record `running` after every
    retryable first-call failure even when the guest already reached `stopped`,
    resume through the original operation on a new authenticated connection and
    driver, and prove exactly one kill effect. A fully written kill response
    must replay from the completed durable journal without another dispatch.
  - [x] Apply the same nine-stage portable reopen matrix to stopped-only
    `delete` after an exact durable create, start, and kill. Keep the stopped
    host record after every retryable first-call failure even when the guest
    already removed the generation, resume cleanup through the original
    operation on a new authenticated connection and driver, and prove exactly
    one delete effect. A fully written response must leave no live host record
    and replay from the completed durable journal without driver recovery or
    another dispatch.
  - [x] Carry init `wait` through all nine portable reopen stages after an exact
    durable create, start, and signal-9 kill. Reissue an uncached observation on
    the replacement connection after every retryable first-call failure and
    require the same exact signal result. A fully written response must survive
    reopen in the durable terminal cache without another driver or guest
    dispatch; all later waits must use that cache, and stale host and guest
    generations must fail closed.
  - [x] Carry `exec` through all nine portable reopen stages after an exact
    durable create and start. Keep the prepared process claim resumable after
    every retryable first-call failure, replay post-dispatch effects through the
    exact guest request journal, and replay a fully written response from the
    completed durable host journal without another dispatch. Preserve the exact
    generation, process ID, PID, and terminal mode, require one exec effect, and
    reject changed content under the same operation ID at both boundaries.
  - [x] Carry `signal-process` through all nine portable reopen stages after an
    exact durable create, start, and exec. Resolve the current host target to the
    exact generation and process ID, keep the process claim resumable after each
    retryable first-call failure, replay the exact guest mutation after dispatch,
    and replay a fully written response from the durable host journal. Require
    one signal effect and reject a changed signal under the same operation ID at
    both boundaries.
  - [x] Carry `wait-process` through all nine portable reopen stages after an
    exact durable create, start, exec, and signal. Reissue an uncached process
    observation after retryable first-call failures, then durably cache one
    exact exit result. A fully written response and every later retry must avoid
    another driver or guest dispatch; current targets resolve to the exact
    generation and process ID, and stale targets fail closed at both boundaries.
  - [x] Carry `pause` through all nine portable reopen stages after an exact
    durable create and start. Keep the host record running and unpaused after
    every retryable first-call failure even when the guest is already frozen,
    resume through the original operation on a new authenticated connection and
    driver, and prove exactly one pause effect. A fully written response must
    replay from the durable host journal without another dispatch, and changed
    targets under the same operation ID must fail closed at both boundaries.
  - [x] Carry `resume` through all nine portable reopen stages after an exact
    durable create, start, and pause. Keep the host record running and paused
    after every retryable first-call failure even when the guest is already
    thawed, retry the original operation on a new authenticated connection and
    driver, and prove exactly one resume effect. A fully written response must
    replay from the durable host journal without another dispatch, and changed
    targets under the same operation ID must fail closed at both boundaries.
  - [x] Carry read-only `processes` through all nine portable reopen stages
    after an exact durable create, start, and exec. Resolve the current host
    target to the exact generation, return the same live init and exec process
    identities after reconnect, and reissue the observation after every
    retryable first-call failure, including a fully written first response.
    Keep durable state unchanged and reject stale generations before host
    driver dispatch and at the guest boundary.
  - [x] Carry `update` through all nine portable reopen stages after an exact
    durable create and start. Keep the complete OCI `LinuxResources` request
    resumable after every retryable first-call failure, replay post-dispatch
    effects through the exact guest request journal, and replay a fully written
    response from the durable host journal without another dispatch. Require
    one resource-update effect and reject changed resources under the same
    operation ID at both boundaries.
  - [x] Carry read-only `stats` through all nine portable reopen stages after an
    exact durable create and start. Resolve the current host target to the exact
    generation, validate the same normalized CPU, memory, process-count, and
    named metrics after reconnect, and reissue the observation after every
    retryable first-call failure, including a fully written first response.
    Keep durable state unchanged and reject stale generations before host
    driver dispatch and at the guest boundary.
  - [x] Carry read-only `read-output` through all nine portable reopen stages
    for an exact running init process. Resolve the current host target to the
    exact container generation, preserve the inclusive byte cursor and response
    limit, and return the same contiguous stdout chunk after reconnect. Reissue
    the poll after every retryable first-call failure, including a fully written
    first response, and reject stale process generations before host driver
    dispatch and at the guest boundary.
  - [x] Carry replay-safe `write-stdin` through all nine portable reopen stages
    for a running init process. Resolve the current host target to the exact
    generation, retain the original operation context and input bytes, and keep
    the durable claim resumable after each retryable first-call failure. Replay
    a post-dispatch guest request without a second input effect, replay a fully
    written response from the completed host journal without another dispatch,
    and reject changed bytes under the same operation ID at both boundaries.
  - [x] Carry replay-safe `close-stdin` through all nine portable reopen stages
    for a running init process. Resolve the current host target to the exact
    generation, retain the original operation context, and keep the durable
    claim resumable after each retryable first-call failure. Replay a
    post-dispatch guest request without a second close effect, replay a fully
    written response from the completed host journal without another dispatch,
    and reject changed process targets under the same operation ID at both
    boundaries.
  - [x] Carry replay-safe `resize` through all nine portable reopen stages for
    an exact terminal exec process. Resolve the current host target to the exact
    generation and process ID, retain the original operation context and
    terminal dimensions, and keep the durable claim resumable after each
    retryable first-call failure. Replay a post-dispatch guest request without a
    second resize effect, replay a fully written response from the completed
    host journal without another dispatch, and reject changed dimensions under
    the same operation ID at both boundaries.
  - [x] Carry a journaled file upload through all nine portable `file` reopen
    stages. Resolve the current host target to the exact generation and retain
    the path, user, base64 payload, operation context, and acknowledgement.
    Reissue the session-scoped request after every reopen, including after a
    fully written first response, while the guest journal guarantees one upload
    effect. Reject changed upload content through that journal and reject stale
    generations at the guest boundary and before host driver dispatch.
  - [x] Carry a journaled directory creation through all nine portable
    `filesystem` reopen stages. Resolve the current host target to the exact
    generation and retain the path, user, operation context, and directory
    metadata response. Reissue the session-scoped request after every reopen,
    including after a fully written first response, while the guest journal
    guarantees one mkdir effect. Reject changed paths through that journal and
    reject stale generations at the guest boundary and before host driver
    dispatch. This completes the portable 20-operation, 180-pair matrix without
    claiming real utility-VM replacement evidence.
  - [x] Cross the four host-side `create` request/response transitions inside
    fresh, authenticated utility VMs. The qualification-only client injector
    records the exact negotiated protocol-v9 point once, returns a retryable
    `Unavailable` result, never attempts normal delete, and requires the Guest
    executor, VM, endpoint, shim, bridge process, workload marker, runtime root,
    and host descriptor inventory to return to baseline. The Apple Silicon HVF
    gate passed all four stages once and then five repeated four-stage waves
    (24 fresh VMs total) with a valid unprivileged UID/GID mapping. The
    machine-readable evidence now uses the expanded
    `a3s.oci.oci-vm-transport-fault-cleanup.v3` schema.
  - [x] Cross the five Guest-side `create` read/dispatch/response transitions
    inside fresh authenticated utility VMs. The qualification handoff is
    versioned, accepted only for Guest stages, and bound to the exact validated
    `OperationId` carried by `create`. The one-shot Guest injector emits a
    nonce-bound console record only after the Linux executor has completed
    cleanup. The four pre-response points expose a retryable disconnect on the
    current call; the fully written response is delivered and a follow-up
    request must expose the disconnect. Apple Silicon HVF passed all five
    stages in five fresh VMs with exact endpoint, process, descriptor, marker,
    and runtime-root cleanup.
  - [x] Cross both explicit Host shutdown stages in fresh authenticated utility
    VMs. Require a successful exact `create` first, inject one retryable error
    before or after orderly stream shutdown, then prove clone-wide idempotent
    close and complete Guest, VM, endpoint, process, marker, runtime-root, and
    Host descriptor cleanup. Apple Silicon HVF passed both points in two fresh
    VMs, then passed the complete eleven-stage matrix in eleven fresh VMs with
    `a3s.oci.oci-vm-transport-fault-cleanup.v3` evidence.
  - [x] Resume one real `create` after `host-before-request-write` through both
    `HostRuntimeService` reopen and actual HVF VM/session-owner replacement.
    The first VM returns a retryable `Unavailable`, closes with complete Host
    and Guest cleanup, and leaves the durable record in `creating`. A new
    service and fresh authenticated VM accept that exact record through
    `DriverRecovery::none`, reuse its OperationId and generation, complete
    `create`, force-delete it, and return every resource inventory to baseline.
    The August 10, 2026 Apple Silicon gate passed with two distinct endpoint,
    shim, and VM-worker identities under
    `a3s.oci.oci-vm-reopen-replacement.v2`.
  - [x] Carry the other three Host-side `create` request/response stages through
    the same durable reopen and actual HVF owner replacement. The selected
    point is explicit in the CLI and retained report; every run requires the
    original OperationId and generation, a distinct endpoint/shim/VM-worker
    owner, force delete, and complete Host and Guest cleanup. The August 10,
    2026 four-stage matrix passed in eight fresh VMs.
  - [x] Carry all five Guest-side `create` stages through the same durable
    reopen and actual HVF owner replacement. The first four points retain
    `creating` and complete on the replacement Guest. The fully written
    response retains `created`; a State probe exposes the disconnect, then an
    explicit recreated-process recovery rebuilds the pre-start workload,
    reconciles a changed Guest PID when necessary, and repairs the completed
    Create journal before replay. Nonce-bound Guest evidence, exact
    OperationId and generation reuse, two distinct owners, force delete, and
    complete cleanup are required. Rebinding the record and repairing the
    journal each pass all seven durable file-commit fault stages. The August
    10, 2026 five-stage matrix passed in ten fresh VMs; three additional
    post-response waves passed in six fresh VMs, including a real replacement
    PID change.
  - [x] Carry all nine Host/Guest `state` stages through durable service reopen
    and an actual HVF owner replacement. State has no request OperationId, so
    Guest qualification binds the boot-time nonce, exact operation, and stage;
    the evidence returns that nonce after cleanup. The durable record stays in
    `created`, replacement recovery rebuilds the pre-start process with the
    original Create identity and generation, and the reissued State response
    must equal the recovered record. A fully written first response also
    requires a follow-up disconnect probe. The August 10, 2026 matrix passed
    all nine stages in 18 fresh VMs, including real Guest PID changes, distinct
    owners, force delete, and complete Host and Guest cleanup.
  - [x] Carry all nine Host/Guest `start` stages through durable service reopen
    and an actual HVF owner replacement. The first eight paths keep the durable
    record in `created`; replacement recovery rebuilds the pre-start process,
    rebinds its PID, and reuses the original Create and Start identities before
    completing Start. A fully written response instead keeps `running`;
    replacement recovery recreates and starts the process, repairs the completed
    Create and Start journals with the new PID, and lets the unchanged Start
    replay return without another driver dispatch. Every path resets any
    first-owner marker, verifies the replacement workload, force-deletes the
    generation, and restores Host and Guest inventories. The August 10, 2026
    matrix passed all nine stages in 18 fresh VMs.
  - [x] Carry all nine Host/Guest `kill` stages through durable service reopen
    and an actual HVF owner replacement. The first eight paths keep the durable
    record in `running`; replacement recovery recreates and starts the workload,
    rebinds its PID, repairs the completed Create and Start journal responses,
    and completes the unchanged signal-9 Kill identity once. A fully written
    response instead keeps `stopped`; recovery recreates, starts, and kills the
    replacement workload to rebuild the Guest tombstone, then the completed
    durable Kill journal replays without an API-driven driver dispatch. Every
    path verifies the replacement workload before Kill, uses stopped-only
    Delete, and restores Host and Guest inventories. The August 10, 2026 matrix
    passed all nine stages in 18 fresh VMs.
  - [x] Carry all nine Host/Guest `delete` stages through durable service reopen
    and an actual HVF owner replacement. The first eight paths retain the exact
    stopped live record and a Prepared Delete journal. Replacement recovery
    recreates, starts, and kills the workload with the original setup
    identities, rebuilds the Guest stopped tombstone, and dispatches the
    unchanged stopped-only Delete once. A fully written response instead leaves
    no live record and a SucceededEmpty journal; the fresh owner performs no
    workload recovery or driver Delete and replays that exact journal. Every
    path reuses the original Delete identity and generation, uses two distinct
    endpoint/shim/VM-worker owners, and restores Host and Guest inventories.
    The August 10, 2026 matrix passed all nine stages in 18 fresh VMs.
  - [x] Carry all nine Host/Guest init `wait` stages through durable service
    reopen and an actual HVF owner replacement after exact Create, Start, and
    signal-9 Kill setup. The first eight paths retain the stopped generation
    without an init-exit cache; replacement recovery recreates, starts, and
    kills the workload with the original setup identities, then dispatches the
    exact resolved Wait target and timeout once and durably caches
    `signal=9, oom_killed=false`. A fully written first response already leaves
    that cache committed, so the replacement Host and every later Wait return
    without another driver or Guest dispatch. Every path rejects a stale Guest
    generation with NotFound and a stale Host generation with Conflict before
    driver dispatch, uses two distinct endpoint/shim/VM-worker owners, performs
    stopped-only Delete, and restores Host and Guest inventories. The August
    10, 2026 matrix passed all nine stages in 18 fresh VMs.
  - [x] Carry all nine Host/Guest terminal `exec` stages through durable service
    reopen and an actual HVF owner replacement after exact Create and Start.
    The Linux executor now waits for close-on-exec proof before reporting a
    successful Exec, so pre-exec failures return through the typed start
    barrier instead of becoming false process records. The first eight paths
    retain a Prepared Exec journal and a prepared process record with no live
    PID; replacement recovery recreates and starts the init process, then the
    unchanged Exec identity dispatches once. A fully written first response
    instead retains the exact live `ProcessRecord` and Succeeded journal;
    replacement recovery recreates both init and Exec, rebinds their Guest
    PIDs, repairs the completed journals, and the Host replay returns without
    another API-driven dispatch. Every path preserves the generation, process
    ID, terminal mode, and complete request identity; rejects stale and changed
    Host and Guest requests; accepts a first-owner marker only when it exactly
    matches the nonce; requires the replacement long-running terminal process
    to write that marker; force-deletes the generation; and restores Host and
    Guest inventories. The August 10, 2026 matrix passed all nine stages in 18
    fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v6`.
  - [x] Carry all nine Host/Guest `signal-process` stages through durable
    service reopen and an actual HVF owner replacement after exact Create,
    Start, and a long-running terminal Exec. The first eight paths retain a
    Prepared SignalProcess journal; replacement recovery recreates init and
    Exec, then the unchanged signal-10 request dispatches once. A fully written
    response instead retains SucceededEmpty. Recovery recreates Exec, waits for
    its nonce-bound readiness marker after the SIGUSR1 trap is installed, and
    reapplies the committed signal before Host replay returns without another
    API-driven dispatch. Every path preserves the generation, process ID,
    complete Exec and SignalProcess identities, and terminal mode; rejects
    stale and changed Host and Guest requests; requires the replacement trap to
    write the exact signal marker; force-deletes the generation; and restores
    Host and Guest inventories. The August 11, 2026 matrix passed all nine
    stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v7`.
  - [x] Carry all nine Host/Guest non-init `wait-process` stages through
    durable service reopen and an actual HVF owner replacement after exact
    Create, Start, terminal Exec, and signal-10 setup. Recovery always rebuilds
    the Exec, waits for its nonce-bound readiness marker, and reapplies the
    committed signal. The first eight paths have no Host process-exit cache, so
    the unchanged exact target and 15-second timeout dispatch once after
    reopen. A fully written response already holds `signal=10,
    oom_killed=false`; replacement and later waits return from that cache with
    no driver dispatch, while the rebuilt exited process is not advertised as
    live. Every path preserves setup identities, terminal mode, generation,
    and process ID; rejects stale Host and Guest generations; force-deletes the
    still-running init; and restores Host and Guest inventories. The August 11,
    2026 matrix passed all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v8`.
  - [x] Carry all nine Host/Guest `pause` stages through durable service reopen
    and an actual HVF owner replacement after exact Create and Start. The first
    eight paths retain an unpaused running record and a Prepared Pause journal;
    recovery recreates and starts init, rebinds its PID, repairs the completed
    Create and Start responses, and dispatches the unchanged Pause once. A
    fully written response instead retains the paused running record and a
    Succeeded journal. Recovery recreates and starts init, waits for its exact
    nonce-bound readiness marker, reapplies the committed freezer state, and
    repairs the Create, Start, and Pause journal PIDs before Host replay returns
    without API-driven dispatch. Every path preserves generation and complete
    request identities, rejects changed and stale Host and Guest requests,
    force-deletes the paused generation, and restores Host and Guest
    inventories. The August 11, 2026 Apple Silicon matrix passed all nine
    stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v9`.
  - [x] Carry all nine Host/Guest `resume` stages through durable service
    reopen and an actual HVF owner replacement after exact Create, Start, and
    Pause. Every recovery recreates and starts init, waits for the exact
    nonce-bound readiness marker, and reapplies the setup Pause with its
    original identity. The first eight paths retain a paused running record and
    Prepared Resume journal, then dispatch the unchanged Resume once. A fully
    written response instead retains an unpaused running record and Succeeded
    journal; recovery replays Pause and the committed Resume before returning
    recreated-running evidence, so Create, Start, Pause, and Resume responses
    all bind to the replacement PID and the Host retry does not dispatch.
    Every path preserves generation and complete request identities, rejects
    changed and stale Host and Guest requests, force-deletes the resumed
    generation, and restores Host and Guest inventories. The August 11, 2026
    Apple Silicon matrix passed all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v10`.
  - [x] Carry all nine Host/Guest read-only `processes` stages through durable
    service reopen and an actual HVF owner replacement after exact Create,
    Start, and live terminal Exec setup. Recovery always recreates init and
    Exec, rebinds both durable PIDs, repairs their completed responses, and
    verifies the nonce-bound replacement markers. The Processes query then
    resolves the same exact generation and returns exactly those two logical
    process identities from the fresh Guest. Because the query is not
    journaled, every replacement path dispatches it once, including when the
    first owner wrote a complete response. Every path rejects stale Host and
    Guest generations, force-deletes the live generation, and restores both
    owner inventories. The August 11, 2026 Apple Silicon matrix passed all
    nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v11`.
  - [x] Carry all nine Host/Guest `update` stages through durable service
    reopen and an actual HVF owner replacement after exact Create and Start.
    The first eight paths retain a Prepared Update journal and dispatch the
    unchanged exact target plus complete `LinuxResources` once after recovery
    recreates the running init. A fully written response retains a Succeeded
    journal; recovery waits for the fresh nonce-bound workload marker and
    reapplies the committed resource request before returning recreated-running
    evidence, so the Host retry repairs the Update response PID and does not
    dispatch again. Every path preserves the operation, target, resources, and
    generation; rejects changed resources and stale Host and Guest generations;
    reads two replacement Stats snapshots proving the 512 MiB memory limit and
    monotonic live counters; force-deletes the generation; and restores both
    owner inventories. The August 11, 2026 Apple Silicon matrix passed all
    nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v12`.
  - [x] Carry all nine Host/Guest read-only `stats` stages through durable
    service reopen and an actual HVF owner replacement after exact Create,
    Start, and committed Update setup. Every recovery recreates and starts
    init, waits for its nonce-bound readiness marker, reapplies the complete
    resource profile to the fresh cgroup, and repairs the completed Create,
    Start, and Update response PIDs. Stats has no Host response journal, so the
    replacement query dispatches exactly once at every stage, including after
    the first owner wrote a complete snapshot. Both delivered snapshots must
    prove the exact 512 MiB profile and required live counters; the completed
    first-owner path additionally requires a newer, distinct replacement
    snapshot. Every path preserves the target and generation, rejects stale
    Host and Guest generations, force-deletes the generation, and restores
    both owner inventories. The August 11, 2026 Apple Silicon matrix passed
    all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v13`.
  - [x] Carry all nine Host/Guest read-only `read-output` stages through
    durable service reopen and actual HVF owner replacement. Recovery rebuilds
    the exact Create, Start, and non-terminal captured-output Exec requests,
    repairs all completed response PIDs, and dispatches the same cursor,
    byte-limit, and long-poll query once to every fresh owner. A delivered
    first response must match the nonce-bound stdout chunk, while replacement
    output must come from the rebuilt Exec. Stale Host and Guest generations
    fail closed, force delete removes the generation, and both owner
    inventories return to baseline. The August 11, 2026 Apple Silicon matrix
    passed all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v14`.
  - [x] Carry all nine Host/Guest `write-stdin` stages through durable
    service reopen and actual HVF owner replacement. Recovery always rebuilds
    the exact pipe-backed Exec. The first eight stages leave the Host journal
    resumable and dispatch the write once after reopen; when the first owner
    committed the response, recovery replays those exact bytes into the fresh
    Exec before Host open completes and the API retry returns from the durable
    journal without another driver call. Exact effect markers, request
    identity, changed-payload rejection, stale generations, PID rebinding,
    force delete, and both owner cleanup inventories are required. The
    August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs
    under `a3s.oci.oci-vm-operation-reopen-replacement.v15`.
  - [x] Carry all nine Host/Guest `close-stdin` stages through durable
    service reopen and actual HVF owner replacement. Recovery always rebuilds
    the exact pipe-backed Exec. The first eight stages leave the Host journal
    resumable and dispatch the close once after reopen; when the first owner
    committed the response, recovery closes the fresh Exec input before Host
    open completes and the API retry returns from the durable journal without
    another driver call. Exact EOF markers, request identity, changed-target
    rejection, stale generations, PID rebinding, force delete, and both owner
    cleanup inventories are required. The August 11, 2026 Apple Silicon matrix
    passed all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v16`.
  - [x] Carry all nine Host/Guest `resize` stages through durable service
    reopen and actual HVF owner replacement. Recovery always rebuilds the
    exact terminal-backed Exec. The first eight stages leave the Host journal
    resumable and dispatch the resize once after reopen; when the first owner
    committed the response, recovery restores `120x40` in the fresh terminal
    before Host open completes and the API retry returns without another
    driver call. Exact SIGWINCH effect markers, request identity,
    changed-dimension rejection, stale generations, PID rebinding, force
    delete, and both owner cleanup inventories are required. The August 11,
    2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v17`.
  - [x] Carry all nine Host/Guest `file` stages through service reopen and
    actual HVF owner replacement. Upload remains session-scoped, so every API
    retry reaches the replacement driver. After a delivered first response,
    driver recovery rebuilds the upload and Guest journal in the fresh `/tmp`
    filesystem before Host open; the retry then receives the cached Guest
    response without a second upload effect. Exact binary bytes, response
    shape, request identity, changed-content rejection, stale generations,
    explicit removal, force delete, and both owner cleanup inventories are
    required. The August 11, 2026 Apple Silicon matrix passed all nine stages
    in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v18`.
  - [x] Carry all nine Host/Guest `filesystem` stages through service reopen
    and actual HVF owner replacement. MakeDir remains session-scoped, so every
    API retry reaches the replacement driver. After a delivered first
    response, driver recovery rebuilds the directory and Guest journal in the
    fresh `/tmp` filesystem before Host open; the retry then receives the
    cached Guest response without a second mkdir effect. Exact directory
    metadata, request identity, changed-path rejection, stale generations,
    replacement Stat, explicit Remove, force delete, and both owner cleanup
    inventories are required. The August 11, 2026 Apple Silicon matrix passed
    all nine stages in 18 fresh VMs under
    `a3s.oci.oci-vm-operation-reopen-replacement.v19`, completing all 180 real
    operation-stage paths across all 20 protocol-v9 operations.
- [x] Implement all OCI hook phases with typed create/start failure, bounded
  timeout/process-group cleanup, and warning-only poststop behavior.
- [x] Implement `run` as a client composition, not a second lifecycle.

Exit gate: lifecycle tests pass under fault injection at every durable write
and host/agent transition. The durable-write and `RuntimeDriver` portions pass;
the real HVF host/agent operation-stage matrix passes, while equivalent
real-driver coverage remains open for the other utility-VM backends.

### R2 — Windows WHPX Utility VM

- [x] Load and probe Windows Hypervisor Platform securely.
- [x] Create and delete a real WHPX partition object.
- [x] Pin the `a3s-libkrun-sys 3.1.0` FFI ABI and stage a runtime-owned,
  checksum-verified Windows bundle for the isolated shim, with firmware
  provenance from `A3S-Lab/Box@93fc281` and segmented WHPX stream plus
  writable virtio-fs flush fixes from `A3S-Lab/libkrun@dc5519f`.
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
- [x] Replace the diagnostic path with a protected runtime-owned share.
  - [x] Separate the guest system root from a protected writable share, export
    only `shares/<container>/<generation>` with a fixed virtio-fs tag, mount it
    before agent token access, and reject external or cross-generation bundles
    before VM launch.
  - [x] Move one-time token and recovery-report handoff into the exact share and
    require versioned shim evidence that the device was configured.
  - [x] Add an explicit digest-bound product bundle-handoff extension that
    stages by create-operation identity, moves only after the runtime allocates
    the real generation, and preserves exact replay and owned cleanup.
  - [x] Add an SDK-owned portable-rootfs metadata contract used by Box and
    replay Linux ownership, modes, and symlink identity inside the guest before
    OCI mounts, with bounded all-before-mutation validation and one-shot
    consumption.
  - [x] Run the qualification-only `RuntimeDriver` nominal lifecycle through
    that share on a real WHPX host and retain its versioned lifecycle, replay,
    authenticated recovery-publication, and cleanup evidence.
  - [x] Run the owner-death and service-restart matrix through that share on a
    fresh WHPX-enabled Windows host and retain its machine-readable evidence.
    Clean commit `2d91cd0` emitted `a3s.oci.whpx-recovery-smoke-run.v1` after
    exact owner termination, both Recover fault boundaries, service reopen,
    terminal replay, stopped-only delete, and complete transient cleanup.
- [ ] Boot the pinned A3S Linux kernel and immutable system root.
  - [ ] Record source revisions, reproducible build inputs, checksums, and the
    runtime-to-guest compatibility level in the release evidence.
  - [ ] Mount the immutable system root separately from the protected
    per-generation runtime share and reject any digest or provenance drift
    before VM entry.
  - [ ] Run the complete WHPX SDK and recovery matrices against those exact
    assets on a fresh Windows host.
- [x] Establish the named-pipe/vsock bridge.
- [x] Negotiate the guest protocol and retain boot evidence.
- [x] Run a fixed configured process through distinct OCI create and start
  calls.
- [x] Factor native and transport-backed guest execution through one exact
  twenty-operation driver adapter.
- [x] Implement a one-VM-per-container WHPX `RuntimeDriver` candidate with
  exact-generation routing, retry/terminal-failure ownership, delete and
  whole-driver cleanup, and protected-root bundle containment tests. Keep it
  `probe-only` and non-registerable until the remaining exit gates pass.
- [x] Reconcile owner-death cleanup after host restart as an exact-generation
  stopped tombstone. Permit state, idempotent kill, empty process inventory,
  and delete while rejecting live-only operations and never synthesizing an
  exit status.
- [x] Retain exact init exit evidence across WHPX owner death and host-service
  restart, including before/after recovery faults.
  - [x] Define a versioned and bounded exact-generation report, authenticate it
    with the ephemeral agent session token, and emit it only after complete
    guest executor shutdown.
  - [x] Have the owner-PID shim verify and copy the normalized report into
    protected host storage before its owner-death grace expires.
  - [x] Consume the report through durable startup recovery, cache exact wait
    replay, retain the artifact through before/after recovery fault gates, and
    close the replacement-host/shim handoff race with a protected pending
    marker plus bounded retryable wait.
  - [x] Run the complete owner-death and service-restart gate on a fresh
    WHPX-enabled Windows host and retain its machine-readable evidence.
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
bundle, validates negative isolation cases, retains exact terminal evidence
across host restart, and leaves no process, handle, or runtime-root leak. Only
then may WHPX become `experimental`.

### R2M — macOS HVF Utility VM qualification harness — 15/15 complete

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
- [x] Boot the same pinned A3S Linux kernel and immutable system root through
  HVF, retain their digests in the host report, keep the writable
  per-generation share separate, and rerun the complete macOS SDK and soak
  matrices against those exact assets. The retained Apple Silicon run used
  manifest SHA-256
  `e7206ea5c645259fcc9f00d8b3042792d6a6b380436a0a38a1b85dda7c0d4284`,
  raw-image SHA-256
  `e8f5f6713ac093b278b5851129f154b783c08bb8489fe6964bbd93dae0c43910`,
  and agent SHA-256
  `ee7099e367c91b70a1c84cc6f8921da67e7aec4805e6b5c99b6aa683e7544ed1`.
- [x] Establish the private macOS Unix endpoint and AF_VSOCK guest-agent
  bridge, verify that the peer is the shim's direct VM worker child, and
  authenticate version-negotiated protocol with a one-time token. The current
  immutable Guest negotiates protocol v10; retained v9 evidence remains valid
  for backward compatibility.
- [x] Run the same fixed create/state/start/kill/wait/delete OCI lifecycle used
  by WHPX, including bounded running wait, exact repeated exit status,
  pause/resume, live process inventory, resource update, normalized stats, and
  the exact six-device privileged profile. Keep durable target-cleanup evidence
  on the writable runtime share, create temporary source nodes only on
  Guest-local devtmpfs, and remove those sources at the Create barrier without
  weakening device identity validation.
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
- [x] Expose the launch-ready `HvfRuntimeDriver` through a public Apple Silicon
  Host Service and CLI. Use one same-UID mode-0600 Unix socket below a real
  owner-only mode-0700 root, separate durable `state/` from writable HVF
  `runtime/`, accept concurrent clients, scope disconnect failures to one
  connection, clean up only the bound inode, advertise all 20 driver
  operations and the runtime bundle-handoff extension, and reap every active
  VM once on graceful shutdown.
- [x] Abstract exact-generation VM launch and ownership behind testable
  factory/owner interfaces. Prove concurrent Create reuses one VM, interrupted
  Create resumes the moved bundle and starts one VM, and terminal Create
  failure reaps the VM and removes runtime-owned handoff state.
- [x] Advertise only `DedicatedVm` from both the macOS probe and the public HVF
  driver until trust-domain-aware shared-guest pooling exists.
- [x] Requalify the current public Host Service through `RuntimeClient` on the
  signed Apple Silicon build, including all 20 driver operations, public
  `features`/`list`/`events`, and Box-style bundle handoff without invoking a
  qualification-only lifecycle entry point. The August 13 closing run
  exercised all 23 advertised operations and consumed the exact staged bundle.
- [x] Kill the public Host Service while a real generation is live, require
  exact shim/worker owner-death cleanup and authenticated recovery evidence,
  reopen a replacement service, resume Creating or expose exact stopped/exit
  state, and prove no socket, process, descriptor, share, or runtime-root leak.
  The replacement was accepted only after its kernel peer PID differed from the
  killed service; it recovered exact `signal=9, oom_killed=false` state and
  restored the service descriptor inventory from 13 descriptors to 13.
- [x] Run a new 25/25 fresh-VM soak through the current public Host Service and
  retain current-commit evidence. Every wave used distinct shim/worker process
  identities, replayed create/kill/wait/delete exactly once, rejected stale
  generations, restored the 13-descriptor baseline, and left no endpoint,
  bundle handoff, runtime share, recovery report, socket, or process behind.

Exit gate: a fresh Apple Silicon host test boots the utility VM, completes the
fixed OCI lifecycle through the authenticated guest agent, validates negative
isolation cases, and leaves no process, descriptor, or runtime-root leak. Only
then may HVF become `experimental`. The August 13, 2026 Apple Silicon
qualification passed the same immutable-image multi-container matrix, all 3
no-delete cleanup points, all 11 transport fault points, all 180 operation
replacement paths, the asset/authentication/entitlement negatives, and 25/25
fresh-VM soak waves with 75 primary generations and a stable 10-descriptor
baseline. The built-in HVF capability is therefore `experimental`.
That evidence qualifies the historical R2M harness. Separate August 13, 2026
closing runs through the public Host Service passed the three real-host gates
above against signed Apple Silicon artifacts, including a complete post-fix
rerun after Unix socket path capacity became a configuration-time invariant.
The currently advertised macOS/HVF public product path is therefore 100%
function-complete and remains `experimental`. Signed release-package
qualification, upstream OCI conformance, adversarial security review, upgrade
and rollback compatibility, and longer release soak remain promotion gates
before `supported`.

### R2L — Linux KVM Utility VM

- [x] Report `/dev/kvm` presence, access, ioctl, and API-version evidence
  independently from Native Linux readiness.
- [ ] Pin and verify the Linux libkrun runtime, A3S Linux kernel, immutable
  system root, and guest agent as one compatibility set for every advertised
  architecture.
- [ ] Start the KVM worker in an isolated shim, mount only the protected
  per-generation runtime share, and authenticate the AF_VSOCK guest-agent
  session without falling back to host-kernel execution.
- [ ] Implement a launch-ready KVM `RuntimeDriver` through the shared
  twenty-operation adapter with exact-generation routing, bounded shutdown,
  and complete process, endpoint, share, and runtime-root ownership.
- [ ] Run the same lifecycle, process I/O, filesystem, resource, namespace,
  multi-container, fault-cleanup, owner-death, and service-restart matrices
  used to qualify WHPX and HVF.
- [ ] Add a bounded real-host KVM soak for every advertised architecture and
  retain per-wave process, descriptor, marker, cgroup, endpoint, and
  runtime-root leak evidence.
- [ ] Retain fail-closed evidence for an absent, inaccessible, wrong-version,
  or initialization-failing KVM device and for invalid or drifted runtime
  assets.

Exit gate: a fresh KVM-capable Linux host boots the pinned utility VM, passes
the complete SDK and recovery matrices through the authenticated guest agent,
and leaves no process, descriptor, cgroup, endpoint, share, or runtime-root
leak. Only then may KVM become `experimental`.

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
  cgroup-controlled `mknod`, and verified device-node creation.
- [ ] Complete the remaining process and rootless configuration boundary.
  - [x] Enforce or explicitly reject supplementary credentials, scheduler,
    I/O priority, CPU affinity, and unsupported rootless ID-mapping shapes
    before executor mutation.
  - [x] Advertise and enforce the exact supported LSM set, with fail-closed
    behavior and positive and negative evidence for every reported module.
  - [x] Extend seccomp classification and enforcement to every advertised
    architecture and notification mode; reject every other requested action,
    flag, or architecture before launch.
  - [x] Replace the Box-specific device profile boundary with an exact
    generated support policy or reject broader OCI device requests without
    mutating the rootfs or cgroup by requiring an explicit cgroup path before
    any device-policy mutation.
- [ ] Complete the remaining cgroup v2 resource boundary.
  - [x] Enforce or explicitly reject I/O, hugepage, RDMA, and unified resource
    requests with exact read-back and rollback.
  - [x] Add rootful device-access BPF with exact block/char allowlists, access
    subsets, and live filter replacement on update.
  - [x] Qualify the rootless delegation model and device support for every
    advertised profile on real hosts. The v4 rootless gate retains an exact
    user-owned cgroup-v2 descriptor, starts a parent-bound privileged helper
    before Tokio, permanently drops the owner to its real UID/GID, and accepts
    only structured install/replace/remove requests for normalized descendants.
    The first bounded profile is the exact six-device A3S Box fixture. Its smoke
    verifies retained device-node mounts, read-only replacement, failed-update
    rollback, disable/re-enable, durable events, helper shutdown, and complete
    cgroup/runtime cleanup. Runtime commit `bed43d2` passed both x86_64 and
    aarch64 real-host lanes in CI run `31714178349`. Both retained v4 reports
    record `available`, UID/GID 20000, verified helper, nodes, updates, events,
    deletion replay, durable-state removal, and empty cgroup, runtime, session,
    and marker cleanup. This is the only advertised rootless device profile;
    broader device and controller profiles remain outside that boundary.
  - [ ] Run create, update, stats, pause/resume, recovery, and cleanup evidence
    for every newly advertised controller on x86_64 and aarch64.
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
  the rootful lifecycle through the versioned create-attachment contract,
  including exact repeated init wait plus public SDK exec/signal/wait,
  pause/resume, process inventory, resource update, and normalized stats plus
  PTY allocation, resize, interactive I/O, and VEOF without KVM on x86_64 and
  aarch64.
- [x] Prove the helper-backed non-root core lifecycle with subordinate
  UID/GID ownership and `setgroups=deny` on x86_64 and aarch64.
- [x] Qualify explicit rootless cgroup-v2 delegation on x86_64 and aarch64.
  The v4 lifecycle gate covers create, update, stats, pause/resume, replay,
  events, and runtime-owned subtree cleanup on both architectures. A separate
  owner-`SIGKILL` gate now reopens the exact delegation as the same non-root
  UID/GID and requires stopped-only recovery plus complete cgroup cleanup.
  Runtime commit `49cea11` passed both real-host lanes in CI run `31674526443`;
  the retained x86_64 and aarch64 v2 recovery reports bind UID/GID 20000,
  verified delegation use, workload termination, stopped-only deletion, and
  an empty runtime-created cgroup subtree.
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
- [x] Prove the Box-owned production bundle and explicitly opted-in long-lived
  Native Linux owner composition on x86_64 and aarch64 through the Rust, Python,
  TypeScript, and Go SDK lifecycle, exec, filesystem, route-aware stats,
  pause/resume, snapshot restore, restart, and cleanup surfaces.
- [x] Safely reconcile abrupt Native Linux owner death on x86_64 and aarch64.
  Bind the launcher and all helper chains to their authenticated parents,
  persist PID-start-time/config-digest/cgroup recovery evidence per exact
  generation, kill the owner with `SIGKILL`, reopen the real driver in a
  distinct process, commit only a stopped tombstone, refuse invented wait
  evidence, and prove stopped-only delete plus complete transient cleanup.
  Live process-session reattachment remains an R6 gate.
- [ ] Prove packaged installation and A3S Box product startup without KVM.
- [ ] Run the full Sandbox SDK suite with `/dev/kvm` absent and inaccessible.
- [x] Fail explicit dedicated-VM requests before runtime state or driver
  mutation.
- [ ] Reject unavailable dedicated-VM selection in A3S Box before image
  mutation.

Exit gate: A3S Box Sandbox and its Rust, Python, TypeScript, and Go SDK tests
pass on supported x86_64 and aarch64 Linux hosts without KVM.

### R5 — Full OCI 1.3 Conformance

- [ ] Complete common configuration and process semantics and bind every
  accepted or rejected field to the zero-pending normative evidence ledger.
- [ ] Complete Linux configuration enforcement and generate feature reporting
  from the same driver-specific support data used by validation and execution.
- [ ] Complete applicable VM configuration semantics without executing
  untrusted hypervisor, kernel, or firmware paths during validation.
- [ ] Pass the pinned OCI JSON schema suites for config, state, and features
  using fixtures emitted by every advertised driver profile.
- [ ] Pass upstream lifecycle validation tools on every supported platform and
  architecture using the exact packaged runtime binaries.
- [ ] Cross-check supported bundles with upstream OCI lifecycle validation
  tools without shipping a second runtime backend.
- [ ] Run hook-order, rollback, crash-recovery, security-negative, and
  long-running soak suites on every advertised driver profile.
- [ ] Publish an exact, generated support manifest with no unclassified field.

Exit gate: the release report contains retained evidence for every applicable
normative MUST and MUST NOT requirement in OCI Runtime Specification 1.3.0.

### R6 — A3S Box Migration

- [x] Add the pinned `a3s-oci-sdk` dependency to A3S Box.
- [x] Implement the Box adapter using SDK types only.
- [x] Route explicitly opted-in new Linux Sandbox records through Box-owned
  resource and bundle preparation into the long-lived Native Linux host owner,
  with a persisted route and no fallback after selection.
- [ ] Add an early cross-platform vertical slice for create, state, start,
  wait, kill, delete, exact exit status, and runtime-service restart before
  completing every optional OCI field.
- [ ] Route both Box isolation choices through the SDK: `microvm` requests
  `DedicatedVm`, while `sandbox` requests `SharedHostKernel`.
- [x] Persist only the exact OCI container ID, generation, endpoint, driver,
  isolation, configuration digest, and attachment digest needed for
  reconciliation; stop persisting runtime-owned process, VM, socket, pipe, and
  cgroup identities in new records.
- [x] Preserve memory-retaining pause/resume through exact SDK targets with
  operation capability checks, durable replay identities, immutable binding
  validation, and lost-response reconciliation.
- [x] Preserve captured and streaming exec, initial and streaming stdin,
  cursor-checked output, signal/wait, PTY/resize, exact terminal status, and
  cancellation-safe timeout cleanup through exact-generation SDK operations.
- [x] Preserve exact-generation process inventory, resource updates, normalized
  stats, and ordered events through the public SDK, including capability
  preflight, binding drift rejection, durable Box claims, and lost-response
  replay.
- [x] Preserve exact-generation file upload/download and filesystem
  stat/mkdir/move/list/remove through the public SDK with bounded payloads,
  capability preflight, mutation replay identities, descriptor-confined
  rootfs resolution, and Box type conversion.
- [ ] Preserve Box log policy and complete stop, kill, recovery, and cleanup
  parity.
- [x] Prove the production x86_64 Native Linux owner/Box process restart
  boundary: kill the exact owner, cascade launcher/init termination, rebind
  through a fresh Box process, reconcile stopped state without invented exit
  evidence, delete the exact old generation, and restart the next Box and OCI
  generations.
- [ ] Prove Box process-session recovery across an out-of-process runtime
  restart on real native Linux and utility-VM drivers.
- [ ] Complete the Box cross-platform behavior and soak suites against A3S OCI
  Runtime.
- [ ] Qualify the Box R17 resource profile against `control-workload-v1`,
  including exact CPU/memory/PID enforcement, control-service survival under
  workload OOM pressure, and zero leaked processes or cgroups.
- [x] Remove external-runtime discovery, direct invocation, configuration, and
  fallback paths.
- [ ] Remove Box's direct libkrun, VMM, guest-init, and containerd-shim paths
  only after their replacement gates pass through the packaged OCI Runtime.

The Native Linux side now exposes a packaged, long-lived multi-container host
service suitable for the unified Box adapter. Box persists an explicit
`box_vm` or `oci_sdk` route before preflight, prepares its product resources and
minimal OCI bundle, and passes the opt-in x86_64 and aarch64 production-owner
composition through all four SDKs. Separate gates on both architectures now
prove owner/Box process restart with safe stopped-only reconciliation and
explicit next-generation restart. The broader gate remains unchecked until
live session reattachment passes on the real driver, the same production
composition passes WHPX, and the default/MicroVM cutover is complete. OCI
Runtime independently proves that abrupt Native Linux owner death safely
terminates and reconciles the exact generation without inventing terminal
evidence.

### R7 — containerd Runtime V2

- [ ] Define the supported containerd runtime-v2 API and version matrix, the
  shim binary and package layout, and the exact mapping from containerd
  namespace and task identity to OCI container ID and runtime generation.
- [ ] Load the containerd-provided OCI bundle and translate create, start,
  state, wait, kill, delete, exec, resize, close-I/O, and stats operations into
  public `a3s-oci-sdk` calls without invoking A3S Box or importing driver
  internals.
- [ ] Preserve containerd stdin/stdout/stderr and terminal semantics through
  the SDK's bounded process-I/O contract, including reconnect, EOF, resize,
  exact exit status, and cancellation cleanup.
- [ ] Reconcile shim and containerd restart at every lifecycle boundary using
  the runtime's durable generation and operation identities; prove that
  restart never duplicates a mutation, reroutes a driver, or invents process
  state.
- [ ] Run real `containerd` and `ctr` integration suites for lifecycle, exec,
  I/O, signals, stats, restart, forced cleanup, stale identity, and parallel
  tasks against every advertised driver profile.
- [ ] Publish the shim with signed or checksummed runtime packages and retain
  the exact containerd, shim, SDK, runtime, and driver compatibility record.

Current Native Linux development evidence covers containerd 2.2.2 lifecycle,
exec, pause/resume, update, stats, PID inventory, exact init and exec exits,
separate stdout/stderr plus stdin from empty input through 4 MiB,
Created/Running/Stopped daemon-restart boundaries, terminal exec resize before
and after daemon restart, schema-v8 durable exec incarnations plus init/exec
stdin, signal, and resize sequences, exact pending input payloads, signals,
and terminal sizes,
Open/Closing/Closed stdin state, output cursors, and per-task control
sequencing, live
terminal-exec input and output continuation without replay after manual shim
replacement, including a pending WriteStdin operation committed remotely
before the replacement can observe its response and replayed with exactly one
input effect, plus a committed CloseStdin boundary that persists Closing,
loses the original response, replays through the replacement, commits Closed,
and delivers one terminal EOF effect without reopening its FIFO, plus a
committed exec SignalProcess boundary that retains sequence 1 SIGSTOP as
pending, commits it remotely, replaces the shim, joins the completed operation,
and then proves the real process transitions through
`SIGCONT→SIGSTOP→SIGCONT` under fresh sequences 2 through 4, stale task
incarnation and runtime-generation replacement, a
four-task parallel Create/Start/running-restart/137-cleanup matrix, and exact
cleanup after shim
`SIGKILL` with init Created or Running and exec Added or Running. A durable
pre-generation create intent now also replays an in-flight Create through its
exact incarnation and operation identity after shim `SIGKILL`, obtains the one
runtime generation, and force-cleans it without task, process, bundle, or
runtime-state residue. A post-commit Start boundary runs the exact stable Start
identity while shim metadata still records Created, then kills the shim and
proves bounded DeleteShim cleanup terminates and deletes that running exact
generation. A separate post-commit Delete boundary removes the exact runtime
generation before killing the shim, then proves DeleteShim treats only that
generation's `NotFound` result plus a successful replay of its stable normal or
force Delete identity as a completed remote effect. It then finishes local
metadata, rootfs, and bundle cleanup without touching caller-owned container
metadata; unconfirmed state loss fails closed. A post-commit Exec boundary
submits the exact stable generation-scoped process identity while shim metadata
still records the exec as Added, verifies its live PID, then proves DeleteShim
reaps both init and exec and removes the exact generation without touching
caller-owned metadata. A post-commit SignalProcess boundary starts an exec,
suspends the shim before submitting its exact stable SIGKILL identity directly
to the runtime, observes the exact signal-9 exit while the init remains Running
at its original PID, then kills the stopped shim and proves bounded cleanup
removes both processes and the exact generation. A post-commit Kill boundary
also submits the exact stable SIGSTOP mutation against a running generation,
kills the shim while the stopped process remains live, and proves bounded
cleanup delivers the terminal signal and reaps the exact PID. Post-commit Pause,
Resume, and PID-limit Update boundaries retain the same exact generation,
verify the real paused state or applied `pids.max`, then kill the shim and prove
the same bounded cleanup converges without leaked cgroups or processes. Paused
cleanup uses the exact force Delete operation so the runtime thaws and stops
the generation as one cleanup operation instead of waiting on a frozen
terminal signal. Repeated controls now use a monotonically increasing durable
sequence instead of one fixed operation identity: two different Updates and
two complete Pause/Resume cycles dispatch distinct mutations, identical
completed retries do not dispatch twice, concurrent same-task controls are
serialized, and an in-flight retry retains the same sequence across shim
metadata reopen. Canonical JSON request fingerprints keep unordered resource
maps stable across shim, host, and guest reconstruction. Runtime operation
schema v2 records that encoding explicitly while retaining schema-v1 retry
validation with the legacy serializer. The August 14, 2026
Ubuntu arm64/containerd 2.2.2 release build also freezes the Runtime before a
terminal ResizePty, persists the next per-exec sequence and size, freezes the
original shim, commits that exact Resize directly, and replaces the shim before
its local journal can observe the response. The replacement replays the same
sequence without a second terminal effect, commits the observed size,
suppresses an identical retry, and proves that `A→B→A` allocates fresh
identities and restores the real PTY to A instead of replaying the first A.
The latest gate also runs one exec to exit 7, deletes it, reuses the same
containerd exec ID, restarts containerd while the replacement is Added, and
requires exit 23 from a fresh SDK process identity. Its durable per-task exec
sequence survives `DeleteProcess`; exit monitors are incarnation-bound so a
late result cannot terminate or poison the replacement. The latest
qualification also releases each Native Linux guest mutation record only
after its Host result is durable, including every derived chunk identity for a
stdin payload larger than the 4 MiB guest frame limit. Three complete 46.92,
47.39, and 47.23-second matrices passed consecutively through Host PID 3605
with installed shim SHA-256
`a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`.
The matching Host and agent SHA-256 values were
`f097da3529c47a06b32271550417ed810d698a2a6e385f122771c197b7de2b67`
and `be0b13215c21a2312f8a3e8d79cc9a39ed1a4b07b539f3d557e0f4e168c3345a`.
The qualification recreates the killed task ID with a new incarnation and
generation and leaves no matching task, container, shim, agent child,
workload process, bundle, live runtime record, prepared Host operation,
session, marker, workload cgroup, or zombie. The R7 items remain open until
the version and package contract, remaining failure boundaries, every
advertised driver profile, and release-artifact record pass.

Exit gate: containerd task, restart, I/O, and cleanup suites pass through the
public SDK without the Box CLI, a direct VMM path, duplicate lifecycle state,
or leaked runtime resources.

### R8 — Optional Parity Extensions

- [ ] Add versioned extension discovery and negotiation so an optional
  operation is advertised only when the selected driver and exact release
  artifact passed its own gate.
- [ ] Accept already-authorized storage attachments with immutable identity,
  access mode, ownership, and cleanup contracts while leaving named-volume
  and snapshot policy in A3S Box.
- [ ] Accept already-authorized network attachments with exact namespace,
  interface, and cleanup identities while leaving IPAM, DNS, and network
  policy in A3S Box.
- [ ] Add reusable guest-session ownership with trust-domain, isolation,
  generation, capacity, reset, and leak fences; never reuse a guest across an
  incompatible or undeclared trust boundary.
- [ ] Implement checkpoint and restore as generation-fenced SDK operations
  with immutable artifact identity, compatibility validation, durable replay,
  rollback, and exact restored-process evidence.
- [ ] Carry TEE launch measurements and attestation evidence through typed SDK
  contracts without moving attestation authorization or product policy into
  the runtime.
- [ ] Run Box storage, networking, warm-session, snapshot, restart, and
  security suites through only the public extensions on each driver that
  advertises them.

Exit gate: every advertised extension has a versioned contract, fail-closed
capability report, recovery semantics, exact release-artifact evidence, and a
passing Box consumer gate. Unadvertised optional extensions do not block a
supported core runtime release.

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
