# Changelog

All notable changes to A3S OCI Runtime are documented in this file.

## [Unreleased]

### Added

- OCI 1.3 RDMA enforcement for cgroup v2. The shared Linux executor validates
  bounded device names, requires at least one HCA handle or object limit per
  entry, checks the optional `rdma` controller and live device inventory before
  device-policy mutation, and applies deterministic keyed writes on Create and
  live Update. Omitted fields survive partial updates, values at the kernel's
  signed-counter ceiling normalize to `max`, every effective value is read back,
  and failures roll prior RDMA and cgroup mutations back in reverse order.
  `control-workload-v1` applies RDMA only to the workload leaf, feature discovery
  reports the implemented capability, and Native Linux qualification performs
  real control/workload read-back when the host exposes a usable RDMA device.
  One owner-bound executor rule plus the existing semantic rule promote all five
  RDMA requirements, leaving 490 enforced, 50 validated, two conformant, and 113
  pending entries. Arbitrary `linux.resources.unified` writes remain explicitly
  unsupported.
- OCI 1.3 HugeTLB enforcement for cgroup v2. `hugepageLimits` now retains the
  complete normative `uint64` limit range, requires both `pageSize` and `limit`,
  rejects unsafe, overflowing, duplicate, or unavailable page-size controls,
  and enables the optional `hugetlb` controller only when requested. Create and
  live Update apply kernel-representable limits to `hugetlb.<size>.max` and, when
  present, `hugetlb.<size>.rsvd.max`; every write is read back, omitted page
  sizes survive partial updates, and failures roll prior dynamic controls back
  in reverse order. The control/workload topology keeps HugeTLB on the workload
  leaf, and Native Linux qualification verifies a real host page size when the
  runner exposes the controller. A version-local `oci-spec` 0.10 patch corrects
  its HugeTLB limit wire type from `i64` to OCI's `uint64` until upstream ships
  the fix. One owner-bound rule promotes all three HugeTLB requirements, leaving
  485 enforced, 51 validated, two conformant, and 117 pending entries.
- Owner-bound OCI Linux namespace, user-mapping, and time-offset evidence.
  Pinned schema tests require namespace types and every UID/GID mapping member.
  The executor now has one table-driven contract test covering inherit,
  create, and join planning for all eight namespace types, exact mapping range
  preservation and host-ID translation, and optional signed time-offset
  members. Existing descriptor type/identity checks, real Native Linux and
  utility-VM UID/GID map and time-offset read-back, unchanged ID-mapped mount
  source ownership, and mapping-count bounds are tied to nine owner-bound
  rules. Seventeen requirements move from pending to enforced, leaving 482
  enforced, 51 validated, two conformant, and 120 pending entries.
- OCI 1.3 cgroup-v2 ownership delegation. The shared Linux executor now
  changes ownership only when the bundle requests a newly created cgroup
  namespace and an exact writable `cgroup` mount at `/sys/fs/cgroup`. It maps
  `process.user.uid` to the host UID, rejects unsafe rootless transfers and the
  Linux chown no-change sentinel, preserves the group, and uses retained
  descriptor-relative operations with ownership read-back. Only the container
  cgroup directory and existing files named by
  `/sys/kernel/cgroup/delegate` are changed; a missing inventory uses the
  normative three-file fallback, while unlisted controls remain untouched.
  Native Linux positive and read-only profiles prove write access, mapped
  ownership, preservation of unlisted files, and complete lifecycle cleanup.
  One owner-bound executor rule promotes all ten cgroup-ownership
  requirements, leaving 465 enforced, 51 validated, two conformant, and 137
  pending entries.
- OCI Linux device and configured-init console enforcement. Rootful execution
  now accepts block, character, unbuffered-character, and FIFO nodes at any
  normalized container path; preserves exact type, device identity, mode, and
  mapped ownership; rejects duplicate paths, duplicate kernel identities, and
  conflicting existing targets; supplies all six default devices and the
  required `/dev/ptmx`; and binds the configured PTY slave to `/dev/console`.
  A rootfs-identity-bound manifest removes only runtime-created placeholders
  after Delete, shutdown, owner death, or failed Create while preserving
  caller-owned files. Joined or inherited mount namespaces reject device
  injection and instead verify the exact pre-existing rootfs devices through
  the descriptor retained before namespace entry. Device-access rules retain
  list order and treat omitted or empty access masks as no-ops beneath an
  immutable cgroup-v2 BPF upper bound containing only declared and default
  device identities. Clearing rules and allow-all updates cannot widen that
  inventory. When `linux.cgroupsPath` is omitted, the runtime creates a private
  generation-fenced path so rootful and delegated-rootless launches retain the
  same boundary.
  The rootful Native Linux gate proves a 120x40 configured-init PTY, console
  identity, a mapped FIFO outside `/dev`, new-target cleanup, and preservation
  of a pre-existing console file. Its device-boundary profile grants
  `CAP_MKNOD`, permits a declared node, rejects an undeclared node, remounts a
  `nodev` device source with `dev`, and still rejects access with `EPERM`. Five
  owner-bound executor rules and four semantic rules promote all 20 device
  requirements, leaving 455 enforced, 51 validated, two conformant, and 147
  pending entries.
- Complete OCI Block I/O enforcement for cgroup v2. The shared Linux executor
  maps default and per-device weights through BFQ or generic `io.weight`,
  combines read/write BPS and IOPS throttles by device in `io.max`, reads every
  requested value back, preserves omitted keyed fields during live Update, and
  reverses prior writes if a later mutation fails. The optional `io`
  controller is required only when Block I/O is requested and is propagated
  through rootless delegation only when the delegator enabled it. Device
  identities and throttle rates are required; zero rates remove the matching
  cgroup v2 limit through `max`, while invalid or duplicate devices and cgroup
  v1-only leaf weights fail before mutation. Three
  owner-bound executor rules and one semantic rule promote 14 requirements,
  leaving 435 enforced, 51 validated, two conformant, and 167 pending entries.
- OCI 1.3 `linux.netDevices` support in the shared Linux executor. The SDK and
  executor validate bounded interface names, appended `%d` templates, exact
  target uniqueness, deterministic source order, and a distinct network
  namespace before mutation. The runtime-namespace parent authenticates the
  prepared init PID, duplicates its retained network namespace, and uses a
  disposable OS thread plus bounded route-netlink messages to preflight and
  move each source. Exact target collisions fail, template names are assigned
  by the kernel, stable link attributes and permanent global addresses are
  checked after the move, and every interface is brought up. Earlier moves are
  rolled back in reverse order if Create fails before the created state is
  durably committed; normal delete leaves post-commit interface lifecycle to
  the network-namespace owner. Rootless requests fail before mutation without
  explicit host network-device authority. OCI Features now reports
  `linux.netDevices.enabled=true`. The Native Linux gate installs `iproute2`
  and exercises real dummy-interface move/rename with MTU, MAC, address, and
  state read-back, exact target conflict, partial-failure rollback, rootless
  rejection, and exit-path cleanup. Four owner-bound enforcement rules promote
  ten requirements, leaving 312 enforced, 45 validated, two conformant, and
  296 pending entries.
- Complete OCI cgroup v2 CPU-control mapping in the shared Linux executor.
  Create and live Update now apply `shares`, `quota`, `burst`, `period`,
  `cpus`, `mems`, and `idle`; quota and period may be supplied independently,
  with cgroup v2 defaults used at Create and current values preserved during
  Update. Live quota/burst changes are ordered to avoid a transient invalid
  kernel state, retain exact read-back and reverse rollback, and fail as
  `Unsupported` when a requested control file is unavailable. The cgroup
  v1-only realtime fields are rejected before mutation. In the opt-in
  `control-workload-v1` layout, burst and idle remain exact workload-leaf
  controls rather than being copied into the derived management envelope.
  Rootful and rootless Native Linux gates now request both controls. Two
  owner-bound executor rules and one idle semantic rule promote ten entries to
  enforced and two to validated, leaving 302 enforced, 45 validated, two
  conformant, and 306 pending entries.
- Exact OCI Linux `cgroupsPath` semantics. One host-independent SDK parser
  rejects empty, traversing, ambiguous, overlong, control-character, and
  systemd-form paths before runtime mutation while preserving the absolute or
  relative identity. The Linux executor resolves absolute values from the
  visible cgroup v2 mount, confines rootless absolute values to the verified
  delegation, and resolves relative values from one stable private manager.
  Runtime-owned shared prefixes are retained for normal and owner-death
  cleanup. Native Linux multi-container report v19 reads the exact host
  memberships, recreates a relative path at the same location, verifies an
  absolute path at the mount root, and requires both leaves to disappear.
  One shared semantic rule and two owner-bound executor rules promote seven OCI
  requirements, leaving 292 enforced, 43 validated, two conformant, and 318
  pending entries.
- Accurate OCI potentially-unsafe configuration annotation discovery. One SDK
  registry owns the six built-in A3S keys that can change or gate runtime
  behavior, and configured host services merge only annotation-backed
  extensions advertised by their active drivers. Probe-only discovery remains
  empty, while every reported list is sorted, deduplicated, and schema-valid.
  One owner-bound rule promotes the OCI feature requirement, leaving 285
  enforced, 43 validated, two conformant, and 325 pending entries.
- OCI Linux Intel RDT enforcement in the shared Linux executor. The SDK now
  applies one bounded CLOS/schemata contract, including nonempty safe CLOS
  names, 256 schemata lines, 4 KiB per line, and 64 KiB across all ordered
  writes. The runtime-namespace parent discovers resctrl, creates or verifies
  the requested CLOS, applies `l3CacheSchema`, `memBwSchema`, and complete
  `schemata` in OCI order with read-back, and assigns the authenticated init
  PID before prestart and createRuntime hooks. `/` selects the default CLOS;
  omitted `closID` creates and later removes the container-ID CLOS; explicit
  CLOS directories remain externally owned. Dedicated monitoring groups are
  assigned and removed with the same lifecycle. Native recovery record v3
  retains only the exact owned resctrl paths and removes monitoring before an
  owned CLOS after owner death. OCI Features now reports Intel RDT, schemata,
  and monitoring support. Seven owner-bound rules promote all 32 Intel RDT
  configuration requirements and four feature-report requirements, leaving
  283 enforced, 25 validated, two conformant, and 345 pending entries.
- OCI Linux NUMA memory-policy enforcement for configured init. One SDK
  registry owns all seven OCI modes and all three flags for validation,
  execution, and feature reporting. The bounded planner validates node lists
  and mode/flag relationships, while the shared Linux executor applies the
  policy before credential reduction and seccomp and immediately reads the
  complete mode, flags, and effective node mask back through
  `get_mempolicy`. `MPOL_PREFERRED` selects the lowest requested node, matching
  Linux, and omission performs no syscall. Native Linux smoke report v20 plus
  HVF and WHPX fixtures verify `MPOL_BIND` with `MPOL_F_STATIC_NODES` on node
  0 from inside the workload. Nine requirements move to enforced, leaving 247
  enforced, 25 validated, two conformant, and 381 pending entries.
- OCI Linux execution personality for configured init. The SDK requires a
  domain whenever `linux.personality` is present and rejects every nonempty
  flags list because OCI 1.3 defines no supported flag values. The shared
  Linux executor applies `LINUX` or `LINUX32` before credential reduction and
  seccomp, immediately reads the syscall state back, and leaves inherited
  state untouched when the field is omitted. Native Linux smoke report v19
  plus HVF and WHPX fixtures verify `LINUX32` from inside the workload. Three
  requirements move to enforced, leaving 238 enforced, 25 validated, two
  conformant, and 390 pending entries.
- OCI exec CPU affinity enforcement around the workload cgroup transition.
  The SDK canonicalizes empty `initial` and `final` values to omission, while
  the Linux executor validates, normalizes, applies, and reads back `initial`
  before cgroup membership and `final` afterward. Init ignores the exec-only
  field, and omitted phases perform no affinity syscall. Native Linux, HVF,
  and WHPX lifecycle probes now request CPU 0 and verify the final kernel mask
  inside the workload. Two owner-bound rules promote all four
  `execCPUAffinity` requirements, moving the ledger to 235 enforced, 25
  validated, two conformant, and 393 pending entries.
- OCI terminal `consoleSize` enforcement for init and exec. The SDK now
  resolves one effective initial PTY size from the immutable OCI process and
  the optional transport copy, accepts an omitted copy, and rejects conflicts
  before runtime mutation. The Linux executor passes that resolved size to
  the existing PTY setup, while the shared Native Linux, HVF, and WHPX
  terminal lifecycle gate now omits the transport size and verifies the OCI
  dimensions inside the workload before and after resize. One new owner-bound
  rule promotes the `consoleSize`, `height`, and `width` requirements, moving
  the ledger to 231 enforced, 25 validated, two conformant, and 397 pending
  entries.
- Exact OCI lifecycle, rootfs, and non-terminal console-size evidence. The
  Linux executor's existing read-only-root enforcement is now bound to both
  normative occurrences and its real Native Linux read-only write rejection.
  Init and exec planning now accept and discard `consoleSize` when `terminal`
  is false or absent. This established the non-terminal half of the contract;
  the terminal PTY binding is completed by the entry above. The lifecycle
  destroy step shares the already retained owned-resource cleanup evidence
  from Delete. Two new owner-bound rules plus the existing Delete rule promote
  four requirements, moving the ledger to 228 enforced, 25 validated, two
  conformant, and 400 pending entries.
- Transactional OCI Linux sysctl enforcement for known namespaced controls.
  One SDK parser preserves OCI dot/slash notation without losing literal dots,
  rejects host-global controls, traversal, aliases, and `kernel.hostname`, and
  binds every accepted key to its IPC, network, UTS, or user namespace. The
  executor refuses mutation through the agent's current namespace, applies a
  bounded deterministic procfs transaction, verifies kernel read-back, and
  rolls back in reverse order if Create fails before its ready barrier. The
  native x86_64/aarch64 fixture now reads back IPC and network values. One
  owner-bound rule promotes the OCI sysctl requirement, moving the ledger to
  224 enforced, 25 validated, two conformant, and 404 pending entries.
- OCI 1.3 warning-and-continue handling for requested Linux capabilities that
  the running kernel or inherited executor authority cannot grant. Init and
  exec now resolve every requested set against the live kernel ceiling,
  bounding set, permitted set, and inheritable authority; apply the remaining
  set exactly; and send one bounded structured warning per unavailable
  capability over the authenticated internal control socket. The supervising
  agent logs validated warnings before accepting exec success, while malformed,
  duplicate, or unbounded frames fail closed. One owner-bound rule promotes the
  two capability warning-policy requirements to enforced, moving the ledger to
  223 enforced, 25 validated, two conformant, and 405 pending entries.
- Complete OCI 1.3 Linux mount-option control coverage. A new SDK registry is
  the source of truth for all 61 standard option names and their requirement
  levels. The Linux executor recognizes every required and recommended
  control option, preserves unknown options as filesystem-specific data,
  rejects optional `tmpcopyup` with a typed `Unsupported` error, maps recursive
  `rnorelatime` to strict-atime semantics, and avoids a duplicate bind remount
  when `remount` was explicit. Feature reporting derives its sorted 61-name
  result from the same registry, excludes `tmpcopyup`, and retains the
  `rnodev` extension. Five owner-bound rules move 80 requirements to enforced
  and two optional requirements to conformant; three related feature-report
  requirements also move to enforced. The ledger now records 221 enforced,
  25 validated, two conformant, and 407 pending entries.
- Exact OCI capability and `noNewPrivileges` enforcement evidence. The SDK now
  owns the 41 recognized Linux capability names and kernel numbers used by
  both execution and feature reporting. Init and exec read back bounding,
  effective, permitted, inheritable, and ambient sets from the kernel, and a
  shared `PR_SET_NO_NEW_PRIVS` path requires `PR_GET_NO_NEW_PRIVS` to return
  one. Native Linux smoke report v17 retains different init and exec profiles
  and verifies both profiles through `/proc/self/status`. Three owner-bound
  rules promote nine requirements to enforced, moving the ledger to 138
  enforced, 25 validated, and 492 pending. The two capability warning-policy
  requirements remain pending because the executor still fails closed when a
  requested capability cannot be granted.
- Exact OCI process rlimit enforcement and evidence. The Linux executor maps
  all 16 OCI resource types, reads every successful `setrlimit` back through
  `getrlimit`, and fails closed unless both soft and hard values match. Native
  Linux smoke report v16 retains separate init and exec rlimit results for
  configured `RLIMIT_NOFILE` values 64 and 48. Two owner-bound rules promote
  eight pending requirements and the existing duplicate-type validation to
  enforced, moving the ledger to 129 enforced, 25 validated, and 501 pending.
- Complete owner-bound OCI Hook evidence. Native Linux multi-container report
  v18 now drives independent failing prestart, createRuntime, createContainer,
  startContainer, and poststart hooks, requires typed failure plus exact stopped
  cleanup for every phase, retains bounded timeout/process-group termination,
  and proves poststop failure remains warning-only. Six registered enforcement
  rules bind command handling, runtime/container namespace placement, lifecycle
  order, exact State on stdin, and failure policy. Sixty-four OCI 1.3.0 entries
  move from pending to enforced, reducing the ledger from 573 to 509 entries.
- Exact create-to-delete lifecycle operation evidence. Raw wire tests reject
  Start, Kill, and Delete requests without a container ID, while the Host
  boundary test retains the configured start argv, exact signal and all flag,
  and stopped-only delete mode. The real Native Linux gate proves the workload
  marker remains absent after create, direct argv executes only after start,
  signal 9 produces the exact terminal result, delete removes runtime-owned
  state and resources without deleting caller-owned bind storage, and a
  deleted ID can be reused with a new generation. Fourteen OCI 1.3.0 entries
  move from pending to enforced, reducing the ledger from 588 to 574 entries.
- Exact Create and Query State operation contracts at the public SDK boundary.
  Raw wire tests reject State without a container ID and Create without either
  the container ID or bundle before dispatch. Runtime evidence also rejects
  invalid or duplicate live IDs without creating a second container, reports
  a missing container, durably creates a fresh exact generation, and returns
  its complete generation-fenced State. Seven OCI 1.3.0 entries move from
  pending to enforced, reducing the ledger from 595 to 588 entries.
- Owner-bound OCI State enforcement for required version, ID, status, and
  bundle fields; host-unique live container IDs; positive created/running
  Linux PIDs; stopped-state PID removal; exact optional annotations; and the
  pinned State schema. Focused tests now reject a duplicate live container ID
  before journaling, reject missing or invalid lifecycle PIDs without changing
  durable state, validate emitted State values against the pinned schema, and
  preserve both present and absent annotation forms. Nine OCI 1.3.0 entries
  move from pending to enforced, reducing the ledger from 604 to 595 entries.
- Owner-bound runtime state gates for start, kill, and stopped-only delete.
  Tests now prove each invalid-state request returns an error without changing
  container state or writing an operation journal, reducing the pending OCI
  1.3.0 ledger from 610 to 604 entries.
- Runtime-lifecycle evidence that caller-side `config.json` changes after
  create cannot affect the container. A Host reopen test mutates the source
  process, then proves start receives the original private snapshot and digest.
  The same boundary revalidates that a process exists before journaling or
  dispatching start, reducing the pending OCI 1.3.0 ledger from 612 to 610
  entries.
- Exact normative evidence for the required `ociVersion` field and its SemVer
  syntax. Dedicated positive and negative SDK tests now bind both obligations
  to owner-checked bundle-validation rules, reducing the pending OCI 1.3.0
  ledger from 614 to 612 entries.
- Owner-bound normative evidence for non-semantic runtime enforcement. Bundle
  loading now pins the canonical directory, opens only the root `config.json`
  entry without following symlinks or Windows reparse points, and rejects a
  missing, renamed, nested, non-file, or redirected configuration before
  decoding it. The evidence verifier combines the existing semantic-rule
  registry with an explicit owner-bound non-semantic rule registry, rejecting
  unknown, duplicate, orphaned, or owner-drifted rules. The three RFC 2119
  occurrences defining the root `config.json` contract move from pending to
  enforced, reducing the pending OCI 1.3.0 ledger from 617 to 614 entries.
- A reproducible, manifest-bound Windows WHPX system image. The new x86_64
  builder pins Alpine 3.22.5, Linux 6.12.91, the Box/libkrun/firmware source
  revisions, native DLL and kernel digests, filesystem identity, and the
  protocol-v10 compatibility level. The Windows shim rejects unknown or
  drifted manifest data, reparse paths, replaced file identities, and loaded
  DLL mismatches; read-only handles pin the manifest, ext4 image, `krun.dll`,
  and `libkrunfw.dll` through VM entry. libkrun receives the ext4 image as a
  read-only block root, while an empty bootstrap directory and a separate
  writable runtime share carry only bundle, token, and recovery data. The
  manifest digest is also part of the driver capability binding, so durable
  service reopen rejects asset changes. CI now
  publishes the system image and a v2 WHPX qualification artifact with
  disjoint `bin/` and `system-image/` directories. Fresh-host WHPX SDK and
  recovery qualification remains open.
- Durable Host journals for File upload and Filesystem mkdir, move, and remove.
  `a3s.oci.operation.v3` retains each complete validated request and typed
  response, keeps prepared work resumable, replays completed results without a
  second driver dispatch, and permanently rejects changed OperationId reuse
  after the Guest record is acknowledged. Host state files now allow 64 MiB so
  the bounded 32 MiB decoded upload and its base64 request fit the journal. The
  typed durability registry grows from 657 to 741 commit fault points. On
  August 15, 2026, File and Filesystem passed all 18 real Apple Silicon HVF
  reopen/owner-replacement paths, and all 14 journaled mutations passed the
  `guest-after-response-write` Host-first acknowledgement gate.
- Utility-VM replay-journal acknowledgement over guest protocol v10. The
  existing 20 public workload operations are unchanged; a twenty-first
  maintenance operation releases a non-empty, duplicate-free batch of at most
  4,096 completed Guest operation identities after the Host outcome is
  durable. Protocol-v1 through protocol-v9 peers preserve the previous no-op
  compatibility behavior. HVF and WHPX snapshot their live session clients
  before sending acknowledgements, so no session lock is held across a
  transport await, and unknown identities remain safe during fan-out or
  replay. The protocol fault matrix now covers all 189 operation/stage pairs.
  The portable Host reopen matrix proves all 20 workload operations across all
  nine transport stages; for a connection lost after response write, the first
  call exposes the retryable acknowledgement failure and the reopened Host
  returns the already-durable result without redispatch before acknowledging
  it exactly once. macOS and Ubuntu arm64 workspace tests pass, as does strict
  all-feature Clippy. A real Apple Silicon HVF Guest negotiated protocol 10,
  advertised all 21 Guest operations, exited cleanly, restored the 11-FD Host
  baseline, and left no endpoint or owner process. Its immutable system-image
  and manifest SHA-256 values were
  `1dc03afe727242cc124a9f80553b2f3f1b5bbcab333391c869e4eca01e55e570`
  and `01ba5cb1fd71c114e5e7e98a601181504b895fcf6a679e23c93b1fc6443632e5`.
- Bounded Native Linux guest replay-journal reclamation. The Host now asks a
  driver to release mutation replay evidence only after the corresponding
  success or terminal failure is durable, and repeats that acknowledgement
  when serving an already-completed Host operation. Prepared, retryable, and
  in-flight operations remain replayable. The Linux executor rejects a batch
  containing an asynchronous operation that is still pending without removing
  any completed record, treats unknown identities as already released, and
  restores capacity after all 4,096 journal slots have been exercised. Large
  stdin writes retain every deterministically derived 4 MiB guest chunk
  identity until the parent Host operation commits. On Ubuntu arm64 with
  containerd 2.2.2, three complete 46.92, 47.39, and 47.23-second qualification
  matrices passed consecutively through one Host PID. The release-built Host,
  agent, and shim SHA-256 values were
  `f097da3529c47a06b32271550417ed810d698a2a6e385f122771c197b7de2b67`,
  `be0b13215c21a2312f8a3e8d79cc9a39ed1a4b07b539f3d557e0f4e168c3345a`,
  and `a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`.
  An independent audit found no task, container, shim, agent child, task
  bundle, workload cgroup, live Runtime record, or prepared Host operation.
- Durable containerd exec-ID reuse. Metadata schema v8 retains a monotonic
  per-task exec sequence and the incarnation allocated to every current exec.
  SDK `ProcessId` and exec-scoped `OperationId` values include that
  incarnation, while schema-v1 through schema-v7 records keep incarnation zero
  and their original identity encoding. `DeleteProcess` commits removal of the
  current exec without resetting the sequence, and allocation, deletion, and
  exit recording share the metadata gate. Exit monitors are bound to one
  incarnation, so a late result from a deleted exec cannot terminate or poison
  a new exec with the same containerd ID. The Ubuntu arm64/containerd 2.2.2
  gate ran `Exec restart-exec`, observed exit 7, deleted it, reused
  `restart-exec`, restarted containerd while the replacement was Added, and
  observed exit 23 from the new process. The complete 48.29-second matrix and
  an independent zero-residue audit passed with release shim SHA-256
  `9b5978d9d9c2b88634115864d2010e949a377b45f5722c55e54f6e331ee7ac6f`.
- Durable containerd init and exec signal sequencing across live shim
  replacement. Metadata schema v7 gives init and every exec an independent
  monotonic signal sequence plus one pending signal request, including the
  init-only `all` flag. SDK identities use `kill-{sequence}` and
  `signal-{sequence}`, so `SIGSTOP→SIGCONT→SIGSTOP` cannot replay the first
  `SIGSTOP`. Per-process gates serialize concurrent requests, retryable
  failures retain the pending identity, terminal failures advance the
  sequence, and a replacement shim replays pending signals before accepting
  new work. The Ubuntu arm64/containerd 2.2.2 gate froze the Runtime and the
  original shim, committed sequence 1 `SIGSTOP` directly to the Runtime, then
  replaced the shim while its local journal remained pending. The replacement
  joined the completed operation and continued through
  `SIGCONT→SIGSTOP→SIGCONT` as sequences 2 through 4 while `/proc` proved the
  real process state changed at every step. The complete 46.89-second matrix
  and its independent residue audit passed with release shim SHA-256
  `25d12487f51e68ef176fbf7e8b62bd769b1cf149df9fb9b926916aca4b6c89ed`.
- Durable containerd terminal resize recovery across live shim replacement.
  Metadata schema v6 gives init and each exec an independent monotonic resize
  sequence, one pending size, and the last committed terminal size. Resize
  operation identities use the sequence instead of the dimensions, so an
  `A→B→A` transition dispatches three distinct mutations while an identical
  completed retry is answered without another Runtime call. Per-process gates
  serialize concurrent requests. A replacement shim automatically replays a
  pending resize with the same sequence and payload before serving containerd.
  The Ubuntu arm64/containerd 2.2.2 release gate freezes the Host Runtime,
  persists a pending exec resize, freezes the original shim, commits the exact
  Runtime resize, and kills the shim before it can observe the response. The
  replacement joins that completed operation, clears the pending record,
  preserves the process and generation, suppresses a same-size retry, and
  proves the real PTY returns from A through B to A. The 44.23-second matrix and
  its independent residue audit passed with release shim SHA-256
  `f13165079acc22d73e14bab6118ca77da78dc88be47a254b3b7cb2d0ca845f29`.
- Durable containerd stdin continuation across live shim replacement. Metadata
  schema v5 gives init and each exec an independent completed sequence, one
  bounded pending payload, and an explicit Open, Closing, or Closed state. The
  shim persists exact bytes or close intent before dispatch, replays a lost
  response with the same SDK operation identity, rejects sequence, payload, or
  close-state drift, and never reopens a FIFO after close has started.
  The Ubuntu arm64/containerd 2.2.2 release gate now also persists a pending
  exec write, commits that exact operation directly to the Runtime while the
  original shim is frozen, and replaces the shim before its local journal can
  observe the response. The replacement joins the completed operation without
  duplicating input and resumes at the next sequence. A second boundary freezes
  the shim after durable Closing, commits the exact Runtime CloseStdin, kills
  the shim before it can observe the response, and requires the replacement to
  replay the operation, commit Closed, avoid reopening the FIFO, and emit the
  buffered close effect exactly once. The gate proves terminal input and output
  continuation, PTY resize, unchanged process identity, and zero task,
  container, shim, bundle, process, or cgroup residue.
- Rootless Native Linux owner-death recovery qualification. The hidden owner
  and replacement commands now accept the same explicit user-owned cgroup-v2
  delegation and record effective credentials, verified delegation use,
  authenticated workload termination, stopped-only reconciliation, and exact
  delegated subtree cleanup in report v2. The x86_64 and aarch64 Linux lanes
  kill the non-root owner with `SIGKILL`, reopen the durable generation as the
  same UID/GID, refuse invented exit evidence, and retain a separate JSON
  report. Rootless device-policy privilege separation and broader controller
  profiles remain open.
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
  `a3s.oci.native-linux-recovery-smoke.v2` real-process gate kills the owner
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

- On Windows, run CLI parsing, the Tokio runtime, and command dispatch on an
  explicit 8 MiB worker stack. Debug binaries no longer overflow the
  platform's 1 MiB main-thread stack before even `features` or fail-closed
  smoke commands can return. Non-Windows entry remains on the process main
  thread so Linux rootless security bootstrap still precedes every worker.
  Command selection heap-boxes only the chosen branch, with a bounded-stack
  construction regression test.
- Clean every live device-target manifest during Linux executor shutdown
  before removing the Guest runtime root. VM owner replacement now removes OCI
  rootfs placeholders such as `dev/null`, so the fresh Guest can prepare the
  same bundle without `EEXIST`; cleanup failure retains the runtime root and
  fails shutdown closed. Prepared File/Filesystem recovery also rebinds the
  replacement Guest PID, and completed Create/Start responses are repaired to
  that PID.
- Normalize absent OCI annotations across Pause/Resume recovery. Removing the
  reserved freezer annotation now restores `None` instead of retaining an empty
  map, while unrelated annotations remain unchanged, so exact durable response
  replay survives owner replacement.
- Create privileged OCI device nodes for utility-VM workloads from a private,
  per-container directory on the Guest's local `/dev` devtmpfs instead of the
  host-backed virtiofs runtime share. The exact durable device-target cleanup
  manifest remains in the shared runtime directory, source directories reject
  symbolic-link substitution, and the executor removes each source directory
  as soon as Create is ready with a root-level shutdown sweep as a fallback.
  This preserves strict character/block device identity checks across macOS
  and Linux rather than accepting Darwin device metadata as a Linux source.
  Apple Silicon source revision
  `a5a6b535fb69e16c10708fbc94927cf515e6b4d7` passed the revision-bound public
  Host Service gate: all 23 operations, owner death and replacement, and 25/25
  fresh-VM soak iterations restored the 14-descriptor baseline and left no
  endpoint, bundle handoff, runtime share, recovery report, shim, or worker.
  The full report SHA-256 is
  `51611842e214a769f69994451bd494cab7491bfef7c761b60ba1ec2ef9ca56c9`.
- Reject unrepresentable Unix SDK socket paths during endpoint configuration
  instead of after writable service state has been opened. The macOS HVF public
  Host Service qualification now uses compact private service directories, and
  validates all lifecycle, owner-death, and soak endpoint paths before creating
  its evidence root, so the documented `/private/tmp` command reaches every
  real-host phase on macOS rather than failing at the longer owner-death path.
- Prepared device cleanup manifests are now published and opened while the
  trusted Linux launcher still owns its private runtime directory. Device
  placeholders created after entering a mapped user namespace update that
  supervisor-owned record only through the retained `CLOEXEC` descriptor, so
  root-mapped containers no longer fail OCI create with `EACCES` and never
  gain path-based write access to recovery state.
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
