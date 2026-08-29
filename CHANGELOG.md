# Changelog

All notable changes to A3S OCI Runtime are documented in this file.

## Rust SDK crates 0.3.1 — 2026-08-25

### Added

- Published `a3s-oci-core` and `a3s-oci-sdk` as independently consumable
  crates. The 0.3 contract includes generation-fenced lifecycle operations,
  versioned attachment manifests, reconnectable local transport, bounded
  filesystem sessions, portable rootfs metadata, and runtime bundle handoff.
- Added an immutable, main-ancestry-gated crates.io release path under the
  `sdk/rust/v0.3.1` tag namespace. Internal path dependencies retain exact
  registry versions so downstream packages can be reproduced without Git
  dependency substitutions.

### Fixed

- Made the SDK crate self-contained by packaging the exact checked-in OCI
  Runtime and Image specification snapshots consumed by its embedded schemas,
  conformance inventory, and tests. The incomplete 0.3.0 attempt published
  only `a3s-oci-core`; `a3s-oci-sdk` starts at 0.3.1 together with the matching
  Core patch release.

## [Unreleased]

### Added

- Added the OAR-03 explicit rootful Native Linux CRIU checkpoint and restore
  backend without changing default capability advertisement. The opt-in
  constructor binds one exact root-owned CRIU executable and advertises both
  operations. Format `native-linux-criu` v1 requires a paused
  `control-workload-v1` source with exact init membership, no private PID,
  user, or network namespace, and no live execs. It streams sorted CRIU images
  and a canonical evidence manifest into one digest-bound artifact, publishes
  with no-replace filesystem semantics, and restores a newer paused generation
  from retained immutable images. Durable allocated, prepared, restored, and
  Host-committed phases survive owner replacement. Real-kernel schema-v3
  qualification replaces the runtime process after the Restore driver call
  and after the completed-operation directory sync, reopens through a fresh
  service and driver, verifies live restored PIDs and exact response replay,
  preserves the caller artifact, and leaves no journal, staging, executor, or
  session residue. Companion reports retain deterministic private-PID- and
  configured-network-namespace rejection.
- Added signed SLSA build provenance for all five full Runtime archives and
  `SHA256SUMS`. The tag workflow grants signing and artifact metadata access
  only to the publish job, pins every external release Action to an immutable
  commit, uploads the provenance through GitHub's attestation API, and
  publishes a portable Sigstore bundle with verification instructions in every
  archive. Provenance verification remains separate from driver, containerd,
  OCI, security, upgrade, rollback, and soak qualification.
- Added exact staged-package qualification for tagged Linux x86_64 and arm64
  archives. The static musl CLI and Agent run the complete Native Linux matrix
  with `/dev/kvm` removed before compression. Package schema v7 additionally
  builds CRIU v4.2.1 from pinned upstream commit
  `9539417f3e3cfa4eb84c319cd71f4d52f1f08645` and requires the three-report
  OAR-03 checkpoint/restore matrix. It also builds OCI Runtime Tools 0.9.0 from
  exact commit `8a4db579f5c88af5a0d036fad34bddc9c1f703f3` with Go 1.24.0 and validates
  the staged Native Linux and utility-VM OCI 1.3.0 bundles, including a
  fail-closed escaping-rootfs negative. Both x86_64 and AArch64 start the pinned
  lifecycle profile through the staged CLI and Host Service using
  architecture-matched Alpine 3.22.5 minirootfs archives whose URLs, sizes, and
  SHA-256 identities are compatibility-locked. The builder rejects unsafe
  paths, missing BusyBox identities, and architecture drift before publication.
  All nine selected tests execute: seven pass their original TAP assertions,
  while `start` and `pidfile` are transparently retained as conformant with two
  exact, source-audited Runtime Tools harness defects. The report requires the
  locked rootfs provenance, those exact defect identifiers, retired CLI
  journals, clean service shutdown, and a qualified core profile on both Linux
  architectures. The report binds the source commit,
  platform, driver/isolation profile, all three packaged executable digests,
  both external tool identities, and thirteen subordinate evidence records.
  CRIU and Runtime Tools remain host-provided and outside the archive. The
  package gate does not promote Native Linux beyond `probe-only` or replace
  the remaining A3S Box, descriptor-preserving/full upstream lifecycle,
  security, or release-host gates.
- Completed the OCI Runtime Tools Linux execution-compatibility slice. The
  shared Linux executor now accepts the X86 and X32 compatibility ABIs beside
  native x86_64 and the 32-bit ARM ABI beside native AArch64. It compiles
  ABI-scoped pure-Rust seccomp BPF with fail-closed architecture dispatch,
  resolves legacy x86 multiplexers plus x32 and ARM syscall numbers, and
  implements OCI `MASKED_EQ` operand semantics. Relative
  `root.path`, omitted `process`, false or omitted `noNewPrivileges`, exact
  `execvp` argv/PATH behavior, ENOEXEC shell fallback, and the six normative
  default devices are covered without weakening the immutable device
  inventory or caller resource narrowing.
- Qualified the policy-neutral OAR-01 network-enforcement boundary on rootful
  Native Linux. The driver advertises `dev.a3s.network.enforcement@1` only with
  network-device authority. A real caller-owned namespace fixture proves exact
  interface attachment, redirect and rejection behavior, live Host reopen with
  generation/PID/opaque-evidence replay, and namespace/interface/mechanism
  preservation after Delete. Package qualification v6 retains this among its
  thirteen digest-bound evidence reports; rootless Native and VM drivers remain
  unadvertised.
- Qualified the policy-neutral OAR-02 pause/resume mechanism on rootful Native
  Linux. Soak schema v2 retains every exact generation and caller operation ID,
  proves atomic workload counters remain frozen across Pause and a Host Service
  reopen, exactly replays the committed Pause response, then proves progress
  resumes and exactly replays Resume after a second reopen. Package
  qualification v6 binds all 100 per-generation records from the 25-by-4 soak
  to the staged static runtime and Agent without assigning idle or wake policy
  to OCI Runtime.
- Added a canonical machine-readable containerd runtime-v2 compatibility
  record that is schema-checked against the code-owned support matrix and
  retains exact qualification environments, protocol ranges, digests,
  durations, and cleanup evidence without promoting observation-only runs.
  The current post-commit containerd `ResizePty` cleanup boundary has three
  consecutive real-daemon observations through one unchanged Host process.
  Tagged Linux x86_64 and arm64 host archives now build the CLI, agent, and
  containerd shim against musl with the bundled Rust linker and reject ELF
  interpreters or dynamic dependencies before packaging the record.
- Bridged containerd runtime-v2 `Task.Checkpoint` and checkpoint-backed
  `Task.Create` into the SDK checkpoint and restore contracts. The shim now
  commits a digest-verified immutable checkpoint package, restores into a
  durable created-before-start barrier, resumes exactly once from `Task.Start`,
  and rehydrates or cleans up interrupted restore operations without exposing
  the SDK's paused runtime state early. Optional capability negotiation remains
  bound to the exact source isolation and driver, and metadata schema v10 plus
  create-intent schema v2 retain the restore state across shim restarts.
- Added the protocol-9 policy-neutral TEE launch and attestation boundary
  without widening any production driver capability. Dedicated-VM create and
  restore can carry one exact AMD SEV-SNP or Intel TDX required extension in
  explicit hardware or simulated mode. The new durable `attest` operation
  binds an exact generation and 64-byte report-data value to bounded opaque
  evidence, SHA-384 launch measurement, configuration and attachment digests,
  driver/build identity, and the exact Host artifact. Operation schema v6
  retains and replays the exact request, success, terminal failure, and
  `ContainerAttested` event across reopen; startup audit rejects source or
  evidence drift. Driver registration requires `Attest`, a known TEE extension,
  and dedicated-VM isolation as one fail-closed capability set. Runtime does
  not appraise provider claims or make policy decisions; production SEV-SNP
  and TDX execution and qualification remain open.
- Added durable Host checkpoint and restore orchestration behind explicit
  current-platform driver capabilities. Checkpoint's v4-compatible journal
  retains the exact normalized request and immutable typed response and fences
  the paused source against lifecycle and process-I/O mutations. The new
  `a3s.oci.operation.v5` restore journal performs read-only artifact and exact
  runtime/driver compatibility validation before generation allocation,
  retains the complete request, resumes only through an idempotent driver,
  commits one paused running generation, and replays a committed response
  without reopening the caller artifact. Terminal failures are journaled
  before their exact generation moves to `.failed-restore`, permitting later
  monotonic ID reuse. The registry permits `Restore` only together with
  `Checkpoint`; no production driver advertises either operation. Deterministic
  coverage now exercises 877 durable commit stages and 52 Host/driver
  boundaries.
- Added the protocol-8 immutable checkpoint and restore SDK contract without
  widening production capability advertisement. The typed reference binds an
  exact paused source generation, configuration and attachment digests,
  driver/isolation/platform/architecture, Host executable and driver-build
  identities, driver format, and artifact digest and size. Checkpoint and
  restore use normalized single-file paths and request-bound paused responses;
  legacy `leave_running` and reference-free restore requests fail closed. The
  Production checkpoint and restore drivers remain unadvertised until atomic
  artifact handling, scoped cleanup, replay, and real-host qualification are
  implemented.
- Added a fail-closed, dedicated-VM Linux KVM transport implementation for
  authorized v2 storage attachments without widening the production capability
  advertisement. The Host accepts only caller-owned, detach-only, non-bind
  `ext4` mounts backed by canonical single-link raw images outside the
  runtime-owned bundle and share, binds exact inode, size, access, and public
  attachment evidence into the internal v2 manifest, and never copies or
  deletes the backing image. The isolated shim reopens each image with
  `O_NOFOLLOW`, retains descriptor-pinned access through VM entry, rejects
  system-disk aliases and virtio serial collisions, and configures a raw
  `krun_add_disk2` device with VMM-enforced read-only state. The Guest locates
  disks by the libkrun serial instead of enumeration order, verifies size and
  read-only state, and rewrites only the exact authorized OCI mount source to
  the matched block device. Source replacement, hard links, size or access
  drift, duplicate disks, stale manifests, and reusable Guest sessions fail
  closed. KVM still advertises v1 until destructive real-host v2/v3 restart,
  cleanup, replay, and soak gates pass; HVF remains v1.
- Added a fail-closed, dedicated-VM Linux KVM transport implementation for
  authorized v3 network attachments without widening the production capability
  advertisement. The Host validates the exact attachment contract and TAP,
  derives a locally administered unicast MAC from immutable attachment
  evidence, and atomically persists a private digest-bound manifest in the
  exact-generation runtime share. The isolated shim descriptor-pins and
  reverifies that manifest before `/dev/kvm`, configures each TAP through the
  pinned `krun_add_net_tap` ABI when available, and passes only the manifest
  digest into the Guest. The Guest revalidates the manifest, bundle, JSON
  pointers, and configuration digests, identifies each VMM NIC by MAC, stages
  collision-safe interface renames, and binds the result to the later exact
  Create target. Joined caller namespaces, reusable Guest sessions, stale
  evidence, replay drift, duplicate MACs, and partial bootstrap all fail
  closed. KVM still advertises v1 until the cumulative v2/v3 destructive
  real-host restart, cleanup, replay, and soak gates pass; HVF remains v1.
- Added `a3s.oci.attachments.v4` as the fail-closed public foundation for
  reusable utility-VM guest sessions. Each shared-guest request binds a
  path-safe logical session ID, positive incarnation, immutable trust domain,
  bounded capacity, runtime ownership, and explicit empty-session reset mode.
  SharedGuestKernel create/restore now requires that exact binding; other
  isolation classes reject it. Protocol 7 prevents v4 create downgrade, while
  restore now requires protocol 8. `ContainerRecord` retains the binding so
  restart audit and operation replay
  reject session or generation drift. The platform-neutral HVF/KVM lifecycle
  now implements session-scoped private shares, immutable ownership markers,
  serialized member admission, exact capacity and generation fences,
  destroy-on-empty and same-trust-domain retention, session-scoped owner-death
  reports, member-local terminal cleanup, and one-owner shutdown. Production
  utility-VM drivers still do not advertise v4; cumulative storage/network
  transport plus real-host restart, cleanup, and soak qualification remain
  required before either driver enables the profile. Utility-VM attachment
  schemas are now configured independently from isolation classes, rechecked
  at the driver boundary, and passed intact to the VM factory so a future
  platform transport cannot silently lose v2/v3 launch evidence.
- Added `a3s.oci.attachments.v3` for already-authorized Linux network
  interfaces. Each binding carries caller-issued namespace, interface, and
  cleanup incarnation IDs plus exact OCI network-namespace and
  `linux.netDevices` descriptors. New namespaces require runtime-namespace
  release; joined caller namespaces require preservation. Exact bindings
  reject target-name templates, identity drift, conflicting cleanup units,
  descriptor reuse, and non-canonical wire inventories. Protocol 6 prevents
  v3 create downgrade, while restore now requires protocol 8. Rootful Native
  Linux advertises cumulative v1-v3; rootless Native stays v1-v2 because it has
  no host network-device authority. Utility-VM drivers stay v1: dedicated KVM
  has the internal transport described above but still lacks cumulative v2 and
  real-host v3 qualification, while HVF has no independent NIC transport. IPAM, DNS,
  routes, aliases, policy, and backing-network deletion remain outside Runtime.
- Added `a3s.oci.attachments.v2` for already-authorized storage. Each entry
  binds one validated OCI mount to a caller-issued immutable allocation ID,
  exact read-only/read-write mode, caller ownership, and detach-only cleanup.
  The SDK rejects duplicate identities or mounts, access drift, secret/storage
  overlap, runtime-owned bundle handoff, and non-canonical wire inventories.
  Protocol 5 prevents v2 create requests from downgrading to older peers;
  restore now requires protocol 8, while v1 create serialization and
  protocol-3 compatibility remain unchanged. The Native Linux driver advertises
  v2. Dedicated Linux KVM now has a separate
  internal raw-disk transport but remains v1 until its destructive real-host
  qualification gate passes; the other utility-VM drivers remain v1 until they
  have equivalent transports and evidence. The legacy aggregate capability
  remains the safe driver intersection.
- Added `a3s.oci.extensions.v1`, an exact-artifact, per-driver capability
  catalog returned by `RuntimeInfo`. Every entry binds canonical v1 operation
  contracts and attachment versions to one launch-ready driver and its unique
  isolation classes; the catalog binds the complete response to the SHA-256 of
  the running host executable. `RuntimeNegotiationRequest` fails closed on an
  unavailable operation, schema, extension version, ambiguous isolation, or a
  legacy peer without the catalog. The existing flat operation and attachment
  fields now retain only the common multi-driver surface, while OCI unsafe
  annotation reporting still covers the complete recognized driver set.
- Added a startup-wide durable-state audit before an opened store can serve
  requests. It recursively validates root and namespace entries, exact
  generation and operation ownership, unique Create identities, live
  container and process claims, quarantine contents and live-generation
  exclusion, and event claim/record relationships while retaining documented
  crash-recoverable intermediate states. Fourteen focused tests plus the
  complete 877-point durable fault matrix cover fail-closed corruption and
  recovery compatibility.
- Committed containerd `ResizePty` cleanup after shim death. A focused
  DeleteShim boundary starts with one already committed terminal resize and
  schema-v9 metadata that still records the pending size, then proves cleanup
  never dispatches a second resize and fences both Kill and force Delete to
  the exact Runtime generation. The ignored real-containerd gate creates a
  terminal exec, stops the Host, sends `ResizePty` through the shim's validated
  ttrpc endpoint, and requires exec incarnation 1 to retain pending sequence 1
  at 166x52. It then stops the shim, resumes the Host, and commits the same
  `resize-1` operation directly through the public SDK. The gate verifies the
  live PTY dimensions through `TIOCGWINSZ`, kills the shim, requires the
  original response to be lost, and checks exact-generation cleanup without
  removing caller-owned container metadata. Unit, Linux, musl, macOS, and
  Windows CI coverage passes. The destructive three-pass real-host
  qualification record remains open and is not claimed by this change.
- Committed containerd `CloseStdin` cleanup after shim death. A focused
  DeleteShim boundary starts with one already committed stdin close and
  schema-v9 metadata that still records Closing, then proves cleanup never
  dispatches a second close and fences both Kill and force Delete to the exact
  Runtime generation. The real-containerd gate creates a non-terminal exec
  that exits 29 only on EOF, stops the Host, invokes `CloseIO` through the task
  shim's advertised ttrpc endpoint, and waits for exec incarnation 1 to retain
  Closing with no pending write. It then stops the shim, resumes the Host, and
  commits the same `close-stdin-1` operation directly through the public SDK.
  The exec must exit 29 from that one EOF while init stays Running at its
  original PID and generation. After shim `SIGKILL`, containerd leak cleanup
  must remove the exec, init, exact Runtime generation, shim metadata, bundle,
  cgroup, and mounts while retaining caller-owned container metadata. Source
  revision `9726719e5a66156cd61f8be36ca00998bbcfc871` passed three complete
  Ubuntu 24.04 x86_64/containerd 2.2.3 matrices consecutively in 117.37,
  119.36, and 118.94 seconds through unchanged Host PID 2678296. Release CLI,
  agent, shim, qualification executable, and Cargo.lock SHA-256 values were
  `80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`,
  `68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`,
  `99bacac7a308e4830ca55101ef8148a511526722cf9006d8a37ef9cba89dbf50`,
  `3e752abc8ada3b8e3dae9d86e370feb7d17bf04c2245f13888d52ba7537b2fd2`,
  and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
  The qualification used a dedicated private containerd root, state, socket,
  and systemd unit; the production daemon remained active at PID 2485480.
  Independent audits after the probe and every pass found no matching task,
  container, bundle, live Runtime record, cgroup, snapshot, shim,
  qualification process, or workload process.
- Committed containerd `WriteStdin` cleanup after shim death. A focused
  DeleteShim boundary starts with one already committed stdin write and
  schema-v9 metadata that still retains the pending bytes, then proves cleanup
  never dispatches a second write and fences both Kill and force Delete to the
  exact Runtime generation. The real-containerd gate creates a non-terminal
  exec, stops the Host until exec incarnation 1 durably retains sequence 1 and
  the exact pending bytes, stops the shim, and commits the same
  `write-stdin-1` operation directly through the public SDK. The exec must exit
  23 from that one input while init stays Running at its original PID and
  generation. After shim `SIGKILL`, containerd leak cleanup must remove the
  exec, init, exact Runtime generation, shim metadata, bundle, cgroup, and
  mounts while retaining caller-owned container metadata. Qualification
  decoding now accepts schema-v9's canonical omission of a zero committed
  stdin sequence, with a Linux regression test for that exact document shape.
  Source revision `a3865075d8ced661447a85196e17136379535fa7` passed three
  complete Ubuntu 24.04 x86_64/containerd 2.2.3 matrices consecutively in
  89.96, 93.40, and 94.55 seconds through unchanged Host PID 2504484.
  Release CLI, agent, shim, qualification executable, and Cargo.lock SHA-256
  values were
  `80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`,
  `68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`,
  `ca14a7d28f3b95656b831006c22e2e88561c272a19c48aab19b43d6592ca652c`,
  `c560b1d92d4e786a026fd2c8002bcb0330c06d620304a08c5df4951ebdaf9ce4`,
  and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
  The qualification used a dedicated private containerd root, state, socket,
  and systemd unit; the production daemon remained active at PID 2485480.
  Independent audits after every pass found no matching task, container,
  bundle, live Runtime record, cgroup, mount, shim, agent child, qualification
  process, Host child, zombie, or prepared operation.
- Crash-stable containerd task Delete responses. A separate v1 receipt binds
  the namespace, task incarnation, container identity, Runtime generation,
  bundle, PID, exit status, and nanosecond exit time before the shim dispatches
  the generation-fenced delete and removes its main metadata. Rehydration
  discards the receipt when retained metadata and a live generation prove an
  uncommitted intent. A metadata-free replacement validates the serving task
  and replays the exact first response; after serving it, the replay-only shim
  signals exit so containerd 2.2.3 cannot retain an unowned replacement. Task
  restoration now publishes validated in-memory state before starting output
  pumps, allowing immediately replayable output to commit its durable cursor
  without racing a missing task. Partial pump-start failure stops every pump
  already created before rollback. Unit gates cover receipt binding,
  uncommitted-intent consumption, response replay through service reopen and
  DeleteShim, replacement exit, and the output ordering race. Source revision
  `97bb74e5df238f58a7dab913314d38c510ddea9b` passed three complete Ubuntu
  24.04 x86_64/containerd 2.2.3 matrices consecutively in 105.07, 119.86, and
  115.81 seconds through unchanged Host PID 2291109. Release CLI, agent, shim,
  qualification executable, and Cargo.lock SHA-256 values were
  `87265be5b6a6c3f27a68516b1e536ddf3ca0e031e82f43aa300c294575578f32`,
  `19d53e9ae569cec3f096cb99d947e5ff73bfad2c502c6fd6f032a102fcaeee2a`,
  `399ff8d64a735519048c281177fdba2dc5f7f40f85b0fce986b2b6e162490cb3`,
  `7a9b03fe2f0d924513d612049d149591e11ada3e76b7afc0a574d24575a370f6`,
  and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
  The qualification used a dedicated private containerd service and socket;
  the system daemon remained active at PID 2485480. Independent audits after
  every pass found no matching task, container, bundle, cgroup, mount, shim,
  agent child, or qualification process.
- Crash-stable containerd DeleteProcess responses. A separate v1 receipt
  journal stores the exact exec incarnation, PID, exit status, and nanosecond
  exit time under the task identity, Runtime generation, and bundle before the
  shim removes that exec from schema-v9 metadata. The main metadata entry is
  the commit marker: rehydration discards an intent while the exec remains and
  replays the receipt after the exec is absent. A new durable incarnation of
  the same exec ID consumes the old receipt, and full task Delete or DeleteShim
  removes the journal. Unit gates cover response replay after service reopen,
  uncommitted-intent reconciliation, and receipt removal during exec-ID reuse.
  The real-containerd gate verifies the exact receipt, suspends containerd,
  kills and reaps the current shim, launches its replacement from the same
  bundle, restarts containerd, and requires a retry to reproduce the first
  response field-for-field while init stays Running. Source
  revision `5a6d5f2d817d5951929c2394dff57ef925dd5822` passed three complete
  Ubuntu arm64/containerd 2.2.2 matrices consecutively in 65.15, 66.76, and
  64.11 seconds through unchanged Host PID 436920. Release Host, agent, shim,
  qualification executable, and Cargo.lock SHA-256 values were
  `53bf14d72adb347b35d19f936bf91d15adcc3cce65aa88f63886746f07f5ddb2`,
  `28dad74972b28b400a9e5e9f9b38ba59aeaf6662532dfefc7dd5527ff17d6b48`,
  `801c6ebd6bb6a41f1049dbd64d6ae60165a0914254edb953b2eaf633c6c368f2`,
  `fa3a513bf2f5aba01a511bc953dcfc5cb1bb05080fbd58bb993d9a0a44a10363`,
  and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
  Independent audits after every pass found no matching task, container,
  bundle, cgroup, mount, live Runtime record, shim, agent, qualification, or
  Host-child process and no zombie or prepared operation. The original
  installed shim was restored at SHA-256
  `a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`;
  the temporary Runtime root, release target, checkout, and logs were removed.
- Committed terminal exec-SignalProcess settlement through a live shim
  replacement. Before replaying a pending exec signal, rehydration performs an
  exact zero-timeout WaitProcess. A durable Runtime exit moves the exec to
  Exited, persists the first observation time, and settles the original signal
  sequence without another SignalProcess; a live exec returns DeadlineExceeded
  and continues through the existing identity-stable replay path. The
  real-containerd gate freezes the Host and original shim with sequence 1
  SIGTERM pending, commits both the exact `signal-1` effect and normal exec
  exit, replaces the shim, and requires that replacement plus restarted
  containerd Wait and DeleteProcess retain the same exit while init stays
  Running at its original PID. Source revision
  `ac2323424cbc34b6f175cbfda8ff9b9c5103901d` passed three complete Ubuntu
  arm64/containerd 2.2.2 matrices consecutively in 68.837, 63.125, and 62.831
  seconds through unchanged Host PID 420621. Release Host, agent, shim,
  qualification executable, and Cargo.lock SHA-256 values were
  `8ddfc57e159632001bc7afe40f548876da2f04e81f9469bc5be8be9bb55be0ad`,
  `dac069562f4bca28cfac82fcf6b9638d2f5826cb09a0f9d96a04ecd9d01a4c24`,
  `a7bcad743a4c495336b91a403e0f7b357e8dedac2c6dd3a98044d225938cf682`,
  `e1e3e613ece5f3afecd7b20ca29e4fa8e3ea967a902188319d4dfaa2f1b77285`,
  and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
  Independent audits found no matching task, container, bundle, cgroup,
  mount, live Runtime record, shim, agent, qualification, or Host-child
  process and no zombie or prepared operation. The original installed shim
  was restored at SHA-256
  `a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`;
  the temporary Runtime root, release target, checkout, and logs were removed.
- Committed terminal init-Kill settlement through a live shim replacement.
  Rehydration now reconciles an exact Runtime `Stopped` record before replaying
  pending controls or signals: when shim metadata has no init exit, it performs
  one bounded exact-generation Wait, persists the Runtime's durable exit, and
  then settles the pending signal sequence without issuing another Kill. The
  real gate freezes the Host with sequence 1 `SIGTERM` durable in the shim,
  freezes that shim, resumes the Host, commits the same `kill-1` request, and
  replaces the shim after the workload exits 42 but before the original
  response can be observed. The replacement preserves the generation, clears
  the pending signal, serves shim and containerd Wait with exit 42, and permits
  exact Delete cleanup. On August 24, 2026, three complete Ubuntu
  arm64/containerd 2.2.2 matrices passed in 73.69, 63.38, and 62.19 seconds
  through Host PID 405903. Release Host, agent, and shim SHA-256 values were
  `c4341f7f9a963115d4804d9ff5e7cacf6e94dcf2e21ee0e49acc6e056973a596`,
  `035eabf393834844b04375c4d79ff4c0ca50f3ebf09977fac36543f03b5f3ecb`,
  and `00a2ffbf46b0db90c5112ffa9388212cbd2a4031cbd9a16762a852f0ce44202f`.
  The qualification executable and Cargo lock SHA-256 values were
  `f64c6c114fbfc0431ad69ec58746d9f5d728eed410af44f11ced6a89f15db903`
  and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
  An independent audit found no matching task, container, bundle, cgroup,
  mount, shim process, live Runtime container record, agent child, or Host
  child; the original installed shim was restored and the temporary Runtime
  root and 5.6 GiB Linux build target were removed.
- Committed containerd exec-Start reconciliation through a live shim
  replacement. Exec Start now persists schema-v9 `Starting` metadata before
  any Runtime adapter connection, so a Host outage cannot leave an accepted
  request indistinguishable from an untouched Added exec. The real-containerd
  gate freezes the Host after exec incarnation 1 is Added, observes the exact
  durable transition, freezes the original shim, commits the same
  incarnation-bound Runtime Exec, and replaces the shim before the original
  response can be observed. Rehydration adopts the one existing process and
  PID without redispatch, a Start retry returns that PID, Runtime inventory
  contains exactly one matching exec, and exec cleanup leaves init Running.
  On August 24, 2026, three complete Ubuntu arm64/containerd 2.2.2 matrices
  passed in 71.60, 60.26, and 62.72 seconds through one Host PID; the same
  runs retained the committed init-Start, init-Kill, Pause, Resume, and Update
  replacement gates and left zero matching task, container, bundle, cgroup,
  mount, shim, agent child, or Runtime task-state residue.
- Durable init-Kill reconciliation through a live shim replacement. The
  real-containerd gate persists sequence 1 `SIGSTOP` with `all=true`, freezes
  the original shim, commits the exact incarnation-bound `kill-1` identity
  directly through the public SDK, and replaces the shim before the original
  response can be observed. Rehydration must join that operation without a
  duplicate signal, preserve the generation plus init and exec PIDs, and prove
  both real processes stopped. Fresh sequences then verify `all=true` continue
  fanout and `all=false` init-only stop/continue isolation through `/proc`.
  Unit coverage separately proves that durable terminal exit evidence settles
  a pending init signal without redispatch. This boundary is retained by the
  August 24, 2026 three-pass Native Linux/containerd 2.2.2 matrix.
- Committed init-Start reconciliation through a live shim replacement. The
  real-containerd gate suspends the Host with Start pending, freezes the
  original shim, commits the exact incarnation-bound Start identity directly
  through the public SDK, and replaces the shim before the original response
  can be observed. Rehydration must adopt the Runtime's exact Running record,
  preserve PID, generation, driver, isolation, and configuration digests, and
  replay a containerd Start retry without a second lifecycle effect. Unit
  gates separately prove that a committed init Start is adopted from exact
  Runtime state and that a `Starting` exec missing from process inventory is
  replayed once with its durable incarnation. This boundary is retained by
  the August 24, 2026 three-pass Native Linux/containerd 2.2.2 matrix.
- Durable containerd task-control replay during shim rehydration. Metadata
  schema v9 persists the exact `LinuxResources` body beside a pending Update's
  canonical digest, while Pause and Resume remain body-free. A replacement
  shim now replays pending Pause, Resume, and body-complete Update operations
  with the original sequence-bound SDK identity before accepting task work;
  retryable errors keep recovery pending, terminal errors settle the sequence,
  and response identity, generation, driver, isolation, and freezer drift fail
  closed. Schema-v3 through schema-v8 digest-only pending Updates remain
  readable and wait for a digest-matching caller retry to supply the body
  before upgrading. Unit gates cover exact round trips, corruption, replay,
  legacy migration, and failure semantics. The ignored real-containerd gate
  carries committed Pause, Resume, and PID-limit Update across three live
  shim replacements and is retained by the August 24, 2026 three-pass Native
  Linux/containerd 2.2.2 matrix.
- A real post-commit containerd Create fault gate. It stops the Host before
  dispatch, waits for the shim's complete create intent, stops that shim,
  submits the exact same public-SDK Create identity, and kills the shim only
  after the Runtime returns the committed generation. DeleteShim must replay
  that identity, join and remove the original generation, and leave no task,
  process, runtime state, rootfs, bundle, or shim while preserving caller-owned
  containerd metadata. Exact-generation and current-state checks expose a
  duplicate generation or driver reroute instead of accepting apparent local
  cleanup. The broader restart-boundary gate remains open pending the remaining
  mutation audit and retained real-host evidence.
- Byte-exact containerd output cancellation and reconnect handling. The shim
  now commits the durable output cursor after every kernel-accepted FIFO write
  instead of after an entire SDK chunk, so cancellation preserves the exact
  delivered prefix and a replacement resumes at the unwritten suffix. Output
  endpoints fail closed without a durable cursor committer, and malformed,
  gapped, or post-EOF SDK chunks are rejected. Together with the retained
  bounded stdin, separate stdout/stderr, PTY, EOF, resize, exit-status,
  reconnect, and real-host evidence, this closes the R7 process-I/O gate.
- A code-owned containerd-to-SDK translation contract. Twenty-three exact
  Task and FIFO-pump routes collapse to the 18 public `a3s-oci-sdk` operations
  required by the shim; endpoint admission now derives directly from that
  table and fails before task dispatch when any operation is absent. Shim
  version output and RuntimeInfo expose the same contract, while manifest
  tests prohibit dependencies on A3S Box, the Host Runtime implementation, the
  Agent, or Core internals. This closes the R7 public-SDK translation gate;
  complete I/O, restart-boundary, cross-driver, and published-artifact gates
  remain separate.
- One frozen OCI Linux support profile from driver registration through
  execution. The SDK now owns `OciLinuxSupport`; every runtime driver must
  publish an exact profile, mixed-driver services reject profile drift while
  opening, and OCI `Features` is generated from the retained value. Create,
  Exec, and Update enforce it before durable operation claims, while the Linux
  Agent consumes the same shared profile again at init, process, and cgroup
  planning. AppArmor, SELinux, unadvertised Seccomp controls, mount labels, and
  cgroup-v1-only resources therefore fail at the same advertised boundary. New
  exact gates freeze the 190 Linux configuration schema items as 145 enforced
  and 45 rejected unsupported, all 218 `config-linux.md` requirements as 206
  enforced, nine validated, and three conformant, and all 41
  `features-linux.md` requirements as enforced. This closes report/admission
  drift; platform, lifecycle, security, and packaged release conformance remain
  separate gates.
- A closed OCI 1.3 common configuration and process semantics gate. It freezes
  all 79 common configuration schema items outside the separately reviewed VM
  section as 69 enforced, two validated, four rejected unsupported, and four
  rejected inapplicable entries. A second exact gate freezes all 278
  `config.md` requirements as 227 enforced, 35 validated, 13 reviewed
  external, and three conformant entries with zero pending ownership. The
  Linux executor no longer applies a C-string restriction to arbitrary OCI
  annotation metadata: escaped NUL, control characters, empty values, and
  unknown keys survive bundle decoding and executor planning exactly, while
  empty keys and bounded resource limits remain fail-closed. Linux-specific,
  lifecycle, security, cross-driver, and packaged-artifact conformance remain
  open.
- A closed OCI 1.3 VM configuration semantics gate. It freezes all 26
  VM-related schema items as explicitly unsupported by current drivers and all
  24 normative VM requirements as four validated absolute runtime paths plus
  20 fail-closed runtime-owned controls. A dedicated negative semantic fixture
  rejects NUL bytes in executable VM paths and hypervisor or kernel
  parameters. Three non-overlapping evidence bindings keep the 20 generic
  controls, four executable paths, and two parameter arrays tied only to their
  applicable rules. Exact scoped manifest tests prevent owner, disposition,
  count, rule, or test-evidence drift, while the Host Service still rejects a
  complete schema-valid caller `vm` section before durable reservation,
  bundle handoff, hypervisor entry, or mutating driver dispatch. This closes
  bundle-supplied VM semantics only; lifecycle, security, real-host, and
  packaged-artifact conformance remain open.
- An exhaustive pinned OCI 1.3 JSON Schema release gate. The SDK now runs all
  19 vendored configuration, State, and Features fixtures, including malformed
  JSON and schema-invalid negatives, and SHA-256-binds the exact fixture paths
  and canonical LF text so any upstream suite drift requires review on every
  checkout platform. A separate runtime matrix validates the checked-in
  Native Linux, Linux KVM, macOS HVF, and Windows WHPX configurations, each
  profile's generated Features document, and
  its created, running, and stopped State documents through the real durable
  Host Service boundary. This closes schema-suite compatibility only;
  semantic, lifecycle, security, real-host, and packaged-artifact conformance
  gates remain open.
- A shared fail-closed `a3s.oci.linux-kvm-provenance.v1` contract for every
  retained Linux KVM entry, compatibility, lifecycle, recovery, and soak
  artifact. It requires a clean exact checkout and binds the Git object format,
  commit and tree, platform and architecture, Cargo and qualification profiles,
  CLI and shim bytes, runtime manifest and selected runtime files, immutable
  system-image manifest, `libkrun-kvm` driver, and `dedicated-vm` isolation.
  Aggregate compatibility, lifecycle, recovery, and soak schemas advance to v2,
  unavailable runners retain the same identity evidence with zero cases, and PR
  artifacts name the merge commit that was actually checked out and built.
- A separately scoped bounded Linux KVM soak for x86_64 and AArch64. The
  qualification-only `linux-kvm-bounded-soak-only-v1` Host Service runs 25
  fresh exact generations by default without promoting the public `probe-only`
  candidate. Every wave retains generation and stale-target fencing, replayed
  Create/Kill/Wait/Delete, Guest marker, unique shim/worker process identities,
  descriptor and endpoint restoration, bundle-handoff/runtime-share/recovery
  cleanup, console retention, and configured Guest `cgroupsPath` lifetime.
  CI emits `a3s.oci.linux-kvm-soak-matrix.v2` on both architectures; a host
  without usable KVM records zero completed iterations and does not download
  Alpine. Fresh-host `available` reports remain outstanding.
- A qualification-only Linux KVM owner-death and Host Service restart gate for
  x86_64 and AArch64. The public KVM candidate remains non-registerable and
  `probe-only`; the new Unix service accepts only the exact
  `linux-kvm-owner-death-restart-only-v1` override. On real KVM it starts one
  generation, SIGKILLs the owning service, requires pidfd-bound shim/worker
  reap plus authenticated SIGKILL recovery, and opens a distinct
  kernel-authenticated replacement that replays stopped state and Wait before
  stopped-only Delete. The report rejects descriptor, endpoint, bundle
  handoff, runtime-share, recovery-report, and socket residue. CI runners
  without KVM skip the Alpine fixture and retain an explicit zero-case
  `unavailable` matrix rather than claiming hardware recovery.
- A Linux KVM utility-VM lifecycle qualification entry for x86_64 and AArch64.
  When the KVM probe is available, its 16 cases run the complete 20-operation
  OCI lifecycle, two-container generation and namespace isolation, three
  no-delete lifecycle cleanup boundaries, and all 11 Host/Guest transport
  interruption points through the same authenticated Guest implementation
  used by HVF. Every case restores endpoint, shim-process, runtime-state,
  bootstrap, token/recovery, and marker inventories. Hosts without usable KVM
  emit a versioned `unavailable` report with zero executed cases and skip the
  Alpine fixture download; that report is retained evidence, not a successful
  hardware qualification. The portable Utility VM bundle preparer now
  verifies the pinned Alpine archive and normalizes ownership on both Linux
  and macOS.
- A 14-case Linux KVM compatibility-drift matrix at the configured worker
  boundary on x86_64 and AArch64. The worker now reverifies the runtime,
  libkrun, firmware-exported kernel, immutable manifest and root image, Guest
  Agent evidence, and runtime share before it opens `/dev/kvm`, then repeats
  the same checks after the device is pinned. A hidden qualification barrier
  covers manifest and image replacement, same-size mutation, and symlinks;
  architecture, runtime target, Guest Agent identity, and archive, libkrun,
  firmware, and kernel provenance mismatches fail during worker load. Every
  case requires exit code 2 before VM entry plus exact endpoint, process,
  token-handoff, and runtime-share cleanup, so both Linux CI architectures can
  retain this evidence even when their runner exposes no usable KVM device.
- Qualification-only Linux KVM post-probe failure coverage. On a KVM-capable
  host, the entry gate now runs a second isolated session that opens and pins
  the real `/dev/kvm`, requires API version 12, and fails deliberately before
  the native libkrun VM-entry call. Shim schema v7 distinguishes this path with
  `kvm_post_probe_failure_injected`, while the outer gate requires exit code 2,
  no bridge or protocol negotiation, and exact endpoint, shim-process,
  token-handoff, and runtime-share inventory restoration. Normal production
  sessions cannot enable the injection.
- Fail-closed in-process Windows handle reclamation evidence for real WHPX
  entry. Shim schema v6 records the nonzero current-process handle inventory
  immediately before libkrun context creation and after `krun_start_enter`
  returns; its own success contract, Host report validation, and the WHPX
  hardware soak all require exact equality before process teardown. The
  release gate remains open until a fresh WHPX host retains this evidence
  across the complete SDK, recovery, negative, and soak matrices.
- Deterministic Linux x86_64 and AArch64 libkrun runtime inputs plus an
  isolated context gate. One shared manifest now pins the archive, native
  library, firmware, and firmware-exported kernel identities for every
  Windows, macOS, and Linux bundle. The Linux shim rejects non-regular or
  symbolic-link assets, size or digest drift, unexpected kernel size,
  addresses, or digest, and missing ABI symbols before creating a context. It
  then configures VM resources and a plain agent vsock and releases the
  context without opening `/dev/kvm` or entering a VM. Linux x86_64 and
  AArch64 CI retain positive lifecycle plus tampered-asset and symlink-negative
  coverage. KVM remains `probe-only`; fresh-host lifecycle, recovery, and soak
  reports plus the remaining promotion gates are still required.
- Complete classification of the OCI 1.3 normative inventory. The final 17
  common, Linux, and Features entries now bind invalid-value rejection,
  explicit supported subsets, typed additional file descriptors, deliberate
  null-descriptor omission, network-device termination ownership, cgroup fit
  checks, private default paths, controller scope, v1-to-v2 conversion,
  rootfs propagation, masked and read-only paths, unsupported SELinux mount
  labels, and stable configured-service feature reports to exact owners and
  retained tests. Selected drivers reject `linux.mountLabel` before durable
  reservation or mutating dispatch. Fifteen owner-bound rules move 12 entries
  to enforced and five to conformant, leaving 578 enforced, 51 validated, 12
  conformant, 14 reviewed external, and zero pending entries.
- Explicit review boundaries for normative requirements owned by roles outside
  the runtime. The coverage model now has a `reviewed-external` disposition
  that requires a non-empty rationale, stable rule, and test evidence; it
  cannot be used as an implementation claim. Fourteen bundle-packager,
  bundle-author, configuration-author, image-converter, runtime-caller, and
  subsequent-specification entries are classified through that path. The SDK
  also validates `org.opencontainers.image.os.features` as the JSON string
  representation of the OCI Image Specification array, matching established
  converter output while rejecting malformed or non-string members. This
  leaves 566 enforced, 51 validated, seven conformant, 14 reviewed external,
  and 17 pending entries.
- Complete owner binding for all 66 OCI 1.3 runtime lifecycle requirements.
  The runtime now binds the exact four-state domain, Linux PID shape, complete
  preflight and Create application, the create-to-start process barrier,
  failure rollback, and no-container-on-error behavior to durable and real
  Native Linux evidence. It deliberately defines no nonstandard State values
  or properties and continues to defer optional process application until
  Start. Capability warnings returned by init and exec are now actually logged
  by their parent paths while the successful operation continues; poststop
  warnings retain the same non-blocking policy. Seven owner-bound rules promote
  eleven entries to enforced and four to conformant, leaving 566 enforced, 50
  validated, seven conformant, and 32 pending entries.
- OCI Linux default filesystem provisioning. For a newly created mount
  namespace, the executor now supplies `/proc`, `/dev/pts`, and writable
  `/dev/shm` when the OCI mount list omits an exact destination. It also
  supplies read-only `/sys` when the execution context owns a compatible
  network namespace.
  `/proc` and `/sys` are installed before configured child mounts, while the
  two `/dev` filesystems are installed after a configured parent, so defaults
  do not hide `/sys/fs/cgroup` and cannot be hidden by a caller-provided
  `/dev`. Exact configured destinations remain authoritative. A non-initial
  user namespace that inherits networking deliberately receives no host
  sysfs: Linux rejects a fresh mount there, while exposing the host mount would
  cross the isolation boundary. Unit and Native Linux coverage prove the
  omission, override, phase-ordering, rootful, new-network, and rootless
  security paths. One owner-bound rule resolves this recommended requirement,
  leaving 555 enforced, 50 validated, three conformant, and 47 pending entries.
- Complete owner binding for all 24 OCI 1.3 VM configuration requirements.
  Pinned-schema tests cover every hypervisor, kernel, image, and hardware
  member, all five image formats, optional forms, required relationships, and
  invalid field types. The generic SDK retains valid VM configuration for a
  future enforcing driver, while every current A3S driver rejects caller-owned
  VM launch configuration before durable generation reservation, bundle
  handoff, hypervisor launch, or mutating driver dispatch. Runtime-pinned
  hypervisor, kernel, image, and hardware policy therefore cannot be silently
  replaced by untrusted bundle paths or parameters. One owner-bound VM-driver
  rule promotes the remaining 20 entries, leaving 555 enforced, 50 validated,
  two conformant, and 48 pending entries.
- Complete owner binding for all 36 OCI 1.3 Seccomp configuration and
  notification-state requirements. New pinned-schema fixtures cover required,
  optional, empty, and invalid nested fields plus action, architecture, flag,
  and operator registries. The shared executor retains real x86_64/AArch64 BPF
  installation for every advertised action and operator, checks errno and
  argument relationships, and rejects unadvertised flags, architecture sets,
  listener fields, and `SCMP_ACT_NOTIFY` during immutable init planning before
  runtime mutation. Because userspace notification is not advertised, its
  socket, `SCM_RIGHTS`, and process-state transport requirements are bound to
  that explicit rejection boundary rather than treated as implemented. Three
  owner-bound rules promote the 36 entries, leaving 535 enforced, 50
  validated, two conformant, and 68 pending entries.
- Fail-closed handling for OCI `linux.resources.network` on the cgroup v2
  execution boundary. The shared Create and live Update planner now reports
  that the cgroup v1 `net_cls` and `net_prio` controls are unsupported before
  any cgroup or device-policy mutation, instead of relying on the generic
  unknown-resource error. Dedicated tests cover both `classID` and interface
  priorities on both paths. One owner-bound executor rule promotes all five
  Network requirements, leaving 499 enforced, 50 validated, two conformant,
  and 104 pending entries.
- OCI 1.3 `linux.resources.unified` enforcement for cgroup v2. The shared
  Linux executor accepts bounded, deterministic control-file maps, preserves
  controller names discovered from the running kernel, and enables every
  requested controller before creating the leaf. Unsafe paths, runtime-owned
  `cgroup.*` state, typed/unified ownership conflicts, unavailable controllers,
  missing files, and unwritable controls fail with typed errors before
  device-policy mutation. Create and live Update write each value without
  assuming how an unknown kernel control formats its state. Update snapshots
  readable controls for no-op suppression and rollback, while still accepting
  write-only controls. `control-workload-v1` keeps unified settings on the
  workload leaf. Native Linux qualification reads `memory.high` from both
  children, verifies kernel-normalized partial `io.max` writes when a usable
  device exists, and exercises rootful and delegated-rootless updates. The
  stats reader also accepts legal device-only `io.stat` entries emitted for
  devices with no published counters. One owner-bound executor rule promotes
  all four Unified requirements, leaving 494 enforced, 50 validated, two
  conformant, and 109 pending entries.
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
  RDMA requirements.
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
- Promote the Native Linux multi-container report to v20 and require a timed-out
  prestart Hook to launch a signal-resistant background descendant. The gate
  now retains both startup evidence and the absence of its delayed escape
  marker, while focused script and executor regressions cover the same complete
  process-group boundary.

### Fixed

- Prepare the protected `run` directory for both pre-positioned and
  runtime-owned WHPX bundles inside the serialized Create boundary before the
  first utility-VM launch. Failed Agent-session establishment now also removes
  only the attempt-owned console, recovery directories, reports, and pending
  markers, while established sessions preserve the same artifacts for exact
  evidence and owner-death recovery. This keeps an exact-generation Create
  retryable after a pre-negotiation shim timeout without weakening existing
  recovery evidence.
- Prevent OCI Hook process groups from surviving an uncatchable runtime or
  Agent-owner exit. Every Hook now starts a detached, descriptor-minimal
  watchdog bound to exact owner and Hook-leader pidfds before `exec`; owner
  death kills the private group, including signal-resistant descendants, while
  setup failures reject the Hook. The new
  `a3s.oci.native-linux-hook-owner-death-smoke.v1` real-host gate interrupts a
  live `startContainer` Hook, binds PID-reuse-safe process evidence, and requires
  the existing stopped-only Native replacement recovery and complete cleanup.
- Prevent OCI Hooks from inheriting runtime-private file descriptors even when
  a future caller accidentally omits `FD_CLOEXEC`. Every Hook child now marks
  the complete descriptor range above standard error close-on-exec with one
  fail-closed Linux `close_range` operation before executing untrusted code. A
  subprocess regression clears `FD_CLOEXEC` on a live descriptor and verifies
  that the Hook cannot observe it.
- Retry Windows handle-relative file replacement for at most one second when
  an existing destination is transiently held without delete sharing. The
  retry is limited to access, sharing, and lock violations and runs only on
  the blocking filesystem path; a deterministic real-handle regression holds
  the destination for 100 ms before releasing it.
- Preserve identity UID/GID translation when an OCI process inherits the
  current user namespace. Explicit mappings remain mandatory for created or
  joined user namespaces, while a bundle with no user-namespace request now
  treats container IDs as the same host IDs instead of rejecting ownership
  preparation because empty mapping arrays contain no range.
- Validate empty cpuset values at the host- or delegation-owned cgroup
  authority root through `cpuset.cpus.effective` and
  `cpuset.mems.effective` without writing that boundary. Runtime-owned
  descendants still copy nonempty effective values before controller
  enablement, avoiding permission failures without mutating host-owned state.
- Validate a utility-VM bundle handoff completely before creating its exact
  `shares/<container>/<generation>` directory. Missing, symbolic-link,
  non-private, digest-drifted, rootfs-link, and absolute-bind sources now fail
  without leaving a Guest-visible generation share or launching a VM. The
  same pre-mutation boundary also covers both shared-kernel isolation classes,
  targets without an exact generation, and requests that omit the atomic
  bundle-handoff contract. This closes a common KVM/HVF cleanup gap and
  gives Linux x86_64 and AArch64 a KVM-independent isolation preflight.
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
