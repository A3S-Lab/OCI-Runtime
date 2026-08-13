# Changelog

All notable changes to A3S OCI Runtime are documented in this file.

## [Unreleased]

### Added

- Real utility-VM transport interruption evidence for all nine Host/Guest
  protocol-v9 `create` transitions and both explicit Host shutdown stages. The
  `oci-vm-transport-fault-cleanup` command injects one exact negotiated point
  and never sends normal delete. Host points use the qualification-only client
  injector. Guest points use a dedicated versioned handoff bound to the same
  `OperationId` as `create`; the fixed Guest emits matching console evidence
  only after executor cleanup succeeds. The first four Guest points fail the
  current call with a retryable `Unavailable`, while
  `guest-after-response-write` delivers the completed response and requires a
  follow-up request to observe the disconnect. A shutdown run first receives a
  successful `create` response, faults the retained client's first explicit
  close, and lets the sole VM owner complete the clone-wide idempotent close.
  Report v3 requires the
  workload marker and Guest runtime root to be absent, the VM endpoint, shim,
  and bridge process to be reaped, and the Host descriptor inventory to return
  to baseline. Apple Silicon HVF passed the four Host stages once plus five
  repeated waves (24 fresh VMs) and the five Guest stages in five fresh VMs
  during v2 qualification. The final v3 requalification passed all eleven
  stages in eleven fresh VMs. Durable Host reopen, other operations, and
  VM/owner replacement remain open.
- Native Linux owner-death recovery with fail-closed, PID-reuse-safe cleanup.
  Every executor instance and exact container generation now persists a
  private, versioned recovery record bound to the owner, launcher, and init
  PID start times, the immutable OCI configuration digest, and only the
  runtime-created cgroup paths. The top-level launcher is armed with
  `PR_SET_PDEATHSIG(SIGKILL)` before it can create namespace children, so an
  uncatchable host-owner exit terminates the authenticated launcher,
  namespace init, payload, exec helpers, and filesystem helpers rather than
  leaving an uncontrolled host process. A replacement driver commits a
  stopped tombstone only after the old owner identity and exact workload have
  disappeared and all recovery evidence revalidates; it exposes idempotent
  kill, empty process inventory, explicit refusal to invent an exit status,
  and stopped-only delete with bounded executor/cgroup cleanup. The new
  `a3s.oci.native-linux-recovery-smoke.v1` real-process gate kills the owner
  with `SIGKILL`, reopens durable state in a distinct process, verifies those
  semantics, and is retained by x86_64 and aarch64 Linux CI. Live process-I/O
  session reattachment remains a separate promotion gate.
- Production A3S Box consumer evidence at Box commit `a16772c3` against this
  runtime's `a6cdae7` SDK revision. Box now validates its managed home,
  prepares snapshot, named-volume, network, rootfs, and OCI bundle resources,
  then starts or reuses the identity-fenced `native-linux-host-service` for an
  explicitly opted-in Linux Sandbox record. The blocking native x86_64 and
  aarch64 lanes pass Rust, Python, TypeScript, and Go lifecycle, exec,
  filesystem, route-aware stats, pause/resume, snapshot restore, restart, and
  cleanup through that production owner. Both lanes kill the exact owner,
  prove launcher/init termination, use fresh Box processes to rebind and
  reconcile stopped state without invented exit evidence, delete the old
  generation, and restart the next Box and OCI generations. The cancellation
  replay probe uses an explicit post-cancellation release marker instead of a
  host-speed-dependent delay. The retained Box
  [pull-request CI run](https://github.com/A3S-Lab/Box/actions/runs/30754808084)
  and
  [main-branch CI run](https://github.com/A3S-Lab/Box/actions/runs/30755797650)
  both completed successfully. Default routing, transparent live-session
  reattachment, and utility-VM composition remain release gates.
- A long-lived `native-linux-host-service` command and public
  `NativeLinuxHostService` boundary for the production Box migration. One
  owner opens durable state and the experimental Native Linux driver before
  publishing its private `0600` Unix socket, authenticates concurrent same-UID
  clients, accepts independently generation-fenced containers without
  process-local Box descriptors, and reaps the driver on graceful shutdown.
  The existing single-container FD 3/4/5 service remains available for
  compatibility and focused qualification while the default and cross-platform
  Box cutover is completed.
- Out-of-process runtime-owner restart coverage for the durable host service.
  The cross-platform test launches the runtime test binary as one OS process,
  creates and starts a generation plus a live exec through real local IPC,
  terminates that owner, and launches a second process against the same state
  root and endpoint. One retained `RuntimeClient` exposes the disconnect,
  reconnects to the new owner, replays create/start/exec without duplicate
  driver dispatch, recovers live process inventory, and continues stdin,
  signal, wait, output, and cleanup on the exact process target. The fixture
  deliberately uses a deterministic driver; real native/WHPX live-process
  reattachment remains a separate gate.
- Reconnectable local SDK transport for retained `RuntimeClient` instances.
  The request that first observes a broken Unix socket or Windows named pipe
  still returns a retryable ambiguity and is never replayed inside the
  transport. A later explicit request reconnects to the same validated local
  endpoint and performs a fresh protocol handshake, allowing callers to retry
  or reconcile with the original durable operation identity. Caller-supplied
  `from_io` streams remain permanently closed after a protocol or transport
  failure. Real named-pipe and Unix-socket server-restart tests cover both
  boundaries. A3S Box now uses the transport for production x86_64 owner
  rebinding; live-session reattachment on real drivers remains open.
- Public-SDK-only A3S Box consumer evidence at Box commit `09a9e5d3` for exact
  live process inventory, normalized CPU/memory stats, bounded ordered-event
  polling, and replay-safe complete OCI resource updates. Box rechecks read
  targets around every SDK response, persists an `updating_resources` claim
  before dispatch, reuses the same runtime operation after backend recreation
  or a lost response, and publishes acknowledged limits atomically to restart
  and compatibility state. Its immutable create-intent digest preserves create
  replay after mutable resource changes; changed keyed content, unavailable
  capabilities, target drift, malformed stats, and event cursor drift fail
  closed. Real-driver live-session reattachment remains an explicit release
  gate.
- Public-SDK-only A3S Box consumer evidence at Box commit `8ea5f366` for
  exact-generation captured and streaming exec, replay-safe keyed process and
  stdin identities, cursor-checked stdout/stderr, signal/wait, PTY/resize,
  exact terminal status, raw-log separation, and detached timeout cleanup.
  Missing capabilities, stale generations, alternate rootfs, invalid IDs,
  empty commands, and same-key changed content fail before a second runtime
  process can start. Real-driver live-session reattachment and cross-platform
  cutover remain explicit release gates.
- Public `a3s.oci.attachments.v1` create/restore contracts for rootfs, mounts,
  networking, process I/O, secret classifications, and optional namespaced
  runtime extensions. SDK protocol 3 rejects older peers instead of dropping
  attachment evidence; the host advertises exact schema/extension support,
  fails unsupported required extensions before mutation, fingerprints and
  persists the complete manifest, and returns a durable attachment digest in
  every new `ContainerRecord`. Reopen revalidates the manifest against the
  immutable bundle snapshot, while legacy records remain explicitly
  unversioned rather than being reinterpreted.
- A protected, per-generation WHPX runtime share separate from the guest
  system root. The candidate accepts bundles only below
  `shares/<container>/<generation>`, rejects cross-generation and external
  paths before VM launch, exports only that exact directory with the fixed
  `a3s-oci-runtime` virtio-fs tag, and requires the Linux agent to mount it at
  `/run/a3s-oci-runtime` before reading bootstrap material. One-time session
  tokens and authenticated recovery reports now use that share instead of the
  system root. Shim evidence schema v2 records the device configuration, and
  the host requires that evidence for every driver-owned WHPX session. The
  system root and writable share must be disjoint and protected by the runtime
  DACL; immutable-system-image and fresh-host qualification remain separate
  gates.
- A versioned, bounded guest shutdown report for restart-stable utility-VM
  evidence. The Linux executor now retains the exact init terminal result for
  every exact container generation only after complete cleanup, binds each
  result to its canonical configuration digest, and authenticates the sorted
  report with a session-scoped HMAC-SHA256 tag. Missing, partial, oversized,
  malformed, stale-generation, and tampered reports remain unusable. The
  owner-PID-aware Windows shim verifies that tag during its bounded owner-death
  grace, removes the guest copy, and atomically writes only the normalized
  result into a protected host-only directory. WHPX startup validates the exact
  target and durable configuration digest, commits `stopped`, durably caches
  the init result, retains the source artifact across recovery faults, and
  removes it only with container deletion. A protected empty pending marker
  spans VM launch through shim handoff, so a racing replacement host waits only
  when the exact old shim can still be publishing evidence and fails retryably
  if the owner-death grace is exceeded.
- An idempotent startup `RuntimeDriver::recover` handshake that dispatches each
  durable generation only to its recorded driver, commits an optional exact
  state observation before the host accepts requests, and is covered by the
  same typed before/after fault matrix as every lifecycle call. The WHPX
  candidate now converts owner-death cleanup into a stopped, generation-fenced
  tombstone that supports state, idempotent kill, empty process inventory, and
  delete without relaunching the generation. When authenticated evidence is
  present, repeated `wait` now returns its exact exit result; otherwise it
  retains the original fail-closed error instead of inventing one.
- Clone-wide, idempotent guest-agent client shutdown that waits for an
  in-flight request, blocks every later dispatch, and actively closes the
  shared transport before a utility-VM owner reaps its shim process.
- A shareable utility-VM session boundary with one VM owner, cloned concurrent
  guest clients, and one cached shutdown/cleanup result. WHPX and HVF smoke,
  fault-cleanup, and multi-container paths now exercise that driver-ready
  ownership model.
- A shared eighteen-operation agent driver adapter used by native Linux and a
  new one-VM-per-container WHPX `RuntimeDriver` candidate. The candidate binds
  exact generations to one guest session, serializes same-ID create while
  launching distinct container VMs concurrently, reuses the VM for retryable
  create, reaps terminal create failures and successful deletes once, requires
  bundles below an exact protected per-generation share, and intentionally
  remains non-registerable at `probe-only` readiness while real-host
  qualification of runtime-share restart behavior and the immutable system
  root are pending.
- Target-correct KVM ioctl request typing so both glibc (`c_ulong`) and musl
  (`c_int`) Linux builds compile against their actual libc ABI.
- A protected Windows host SDK service that binds the first local named-pipe
  instance with a verified current-user/LocalSystem DACL, rejects remote
  clients, serves bounded concurrent connections, and releases the endpoint
  on graceful shutdown.
- A deterministic multi-driver host registry that selects exactly one
  launch-ready driver for each requested isolation class, routes every later
  operation through the driver persisted in the container record, preserves
  routing across host-service reopen, and rejects duplicate isolation owners
  or inconsistent operation and hook surfaces before creating durable state.
  Service startup now audits every durable container and fails closed if its
  recorded driver is missing or no longer advertises the recorded isolation,
  without dispatching to any driver or silently rerouting the workload.
- An opt-in `control-workload-v1` cgroup-v2 layout that keeps
  `linux.resources` exact for the workload, derives bounded control-plane
  headroom, hands fixed membership descriptors to a trusted init, and keeps
  update, freeze, statistics, OOM behavior, and cleanup scoped to one
  runtime-owned topology.

### Fixed

- Reject unrepresentable Unix SDK socket paths during endpoint configuration
  instead of after writable service state has been opened. The macOS HVF public
  Host Service qualification now uses compact private service directories, and
  validates all lifecycle, owner-death, and soak endpoint paths before creating
  its evidence root, so the documented `/private/tmp` command reaches every
  real-host phase on macOS rather than failing at the longer owner-death path.
- Newly created Linux network namespaces now activate their loopback interface
  before the OCI create-hook barrier. Loopback-only Sandbox services are
  therefore reachable inside their private namespace without requiring a host
  networking helper, while inherited and donor-shared network namespaces are
  left unchanged.
- Execute native Linux file transfer and descriptor-confined filesystem calls
  in a bounded parent-bound helper that enters the container's retained user
  and mount namespaces. Rootfs, bind, ID-mapped, and tmpfs paths now preserve
  the container identity while retaining the same `openat2` confinement and
  helper authentication; the real native fixture covers binary transfer plus
  mkdir/stat/list/move/remove on its container-created `/tmp` tmpfs.
- Native Linux lifecycle, rootless, multi-container, and soak fixtures now
  derive `a3s.oci.attachments.v1` from each immutable bundle and requested I/O
  contract. They no longer initialize the removed `CreateRequest::io` field,
  restoring Linux runtime-test compilation after the attachment protocol
  migration.
- Prepare read-only bind mounts from parent-namespace filesystems as detached
  mount objects before entering a container user namespace. Requested kernel
  security attributes are applied with `mount_setattr` and the prepared mount
  is attached with `move_mount`, avoiding an impossible less-privileged bind
  remount without falling back to a writable Secret mount. Native Linux
  conformance now proves this boundary with a real private tmpfs source, and
  its multi-container report advances to
  `a3s.oci.native-linux-multi-container-smoke.v14`.
- Root the native init's cgroup namespace at the empty management envelope,
  move trusted bootstrap processes into `control` through the inherited
  descriptor, and only then delegate domain controllers and apply exact
  workload limits. This preserves both namespace visibility and the cgroup-v2
  no-internal-process invariant. The native Linux gate now executes this exact
  layout and proves management-root visibility plus control/workload
  membership before the normal lifecycle, update, freeze, stats, and cleanup
  checks.

## [0.2.0] - 2026-07-27

### Added

- A bounded, versioned native Linux complex-container soak with concurrent
  lifecycle, captured exec, pause/resume, durable reopen, generation reuse,
  and process/descriptor/runtime leak evidence.
- Real x86_64 and aarch64 network-mode evidence for private, host-inherited,
  and donor-shared network namespaces.
- Real shared read-write bind, read-only bind, private tmpfs, and
  delete/recreate persistence evidence.
- Real inline-shell, executable-script, direct-argv, and exact nonzero init
  profiles, plus create/start/timeout/poststop OCI Hook failure behavior.
- A tag-driven GitHub Release workflow with checksummed Linux, macOS, and
  Windows archives.

### Changed

- Native multi-container report schema advanced to
  `a3s.oci.native-linux-multi-container-smoke.v13`.
- Documentation and conformance evidence now distinguish runtime namespace and
  mount enforcement from A3S Box product-level network and volume management.

[0.2.0]: https://github.com/A3S-Lab/OCI-Runtime/releases/tag/v0.2.0
