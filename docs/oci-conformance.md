# OCI 1.3 Conformance Contract

## Baseline

A3S OCI Runtime targets the released
[OCI Runtime Specification 1.3.0](https://github.com/opencontainers/runtime-spec/releases/tag/v1.3.0).
The exact release tag, not the moving `main` branch, defines the conformance
input for a runtime release.

The SDK currently uses `oci-spec` 0.10.0 for complete Rust data models. A3S
defines its supported range explicitly as 1.0.0 through 1.3.0 and does not use
that dependency's older `runtime::VERSION` constant as a conformance claim.

The complete upstream `schema/` tree and fixtures are vendored without
modification from release commit
`92249139eea7161e13745abd4cb6d0ea02a3227a`. Schema references resolve only
from embedded bytes; validation performs no filesystem or network retrieval.
The validator applies one explicit in-memory compatibility correction for the
release's single legacy `#definitions/uint32` fragment and fails compilation
if that upstream condition changes. The suite gate enumerates all 19 vendored
configuration, State, and Features fixtures and SHA-256-binds their sorted
paths and canonical LF text, so adding, removing, omitting, or changing a
fixture requires an explicit review while CRLF checkout conversion is ignored.

The 15 Markdown documents linked by the same release's `spec.md` table of
contents are also vendored without modification. Their document digests and
all 764 RFC 2119 keyword occurrences are locked in
`conformance/oci-1.3.0-normative-coverage.json`.

The separate schema-support v2 lock classifies all 423 named properties and
enum values: 257 are enforced, two validated, 75 rejected as unsupported, and
89 rejected as inapplicable native workload platforms. It has zero pending
items and zero conformant items. The 334 applicable entries come from 31
reviewed evidence bindings; this is exact field classification, not a release
conformance declaration.

The Linux-specific lock is exact as well. `config-linux.json` and
`defs-linux.json` contain 190 items: 145 are enforced and 45 are rejected as
unsupported before mutation. `config-linux.md` contains 218 requirements: 206
are enforced, nine validated, and three conformant. All 41
`features-linux.md` requirements are enforced by the runtime feature report.
Those counts are guarded independently from the global totals.

## Meaning Of Complete

There are five separate states for an OCI property:

| State | Meaning |
| --- | --- |
| Represented | The public SDK can decode, preserve, and encode the property |
| Validated | Schema and semantic constraints are checked before mutation |
| Planned | A reviewed implementation milestone owns enforcement |
| Enforced | The selected driver applies the requested behavior or fails |
| Conformant | Positive, negative, lifecycle, and recovery evidence passes |

Only `Conformant` counts as implemented in release feature output.
Representing a field in Rust is necessary but is not an enforcement claim.

No known field may disappear during SDK, host service, durable state,
transport, or guest-agent serialization. Unknown JSON properties remain in
the immutable raw configuration and its digest across transport, but are
ignored by the typed execution projection as OCI requires. A known property
that is inapplicable to the selected workload platform or cannot be enforced
by the selected driver is rejected before create-time state mutation.

## Platform Applicability

The product executes Linux OCI containers:

- directly on Linux through the native driver;
- inside an A3S Linux utility VM on Windows, macOS, and optional KVM-backed
  Linux.

Consequently, complete conformance means:

- all common configuration, process, state, lifecycle, error, warning, and
  hook requirements;
- all Linux configuration requirements;
- all VM configuration requirements that apply when the VM section is used;
- all feature-report schema and accuracy requirements;
- driver-independent behavior identical across native Linux and the guest
  Linux executor.

Solaris, z/OS, and native Windows container configuration remains represented
losslessly by the public `Spec` type, but those workload platforms are not
advertised. A submitted incompatible platform section must produce a typed
pre-create error. Running a Linux container on a Windows host through WHPX
does not make it a native Windows container.

The Linux mount-option table is no longer an unreviewed inventory. One pinned
SDK registry defines all 61 OCI 1.3 names and requirement levels. The shared
executor handles every required and recommended control name, forwards only
unknown filesystem-specific strings, and rejects the optional unimplemented
`tmpcopyup` behavior without advertising it. The ledger binds all 82
requirements in the table and its surrounding rules: 80 are enforced and the
two optional `tmpcopyup` entries are conformant through explicit rejection and
accurate discovery.

All 66 `runtime.md` requirements are now owner-bound. The Host and shared
executor expose only the four standard State values, preserve the exact Linux
PID contract, validate and apply or reject the complete accepted configuration
before committing Create, keep the configured process behind the Start
barrier, and leave no live container after a failed operation. Durable fault
injection and real hook rollback cover the error policy. Init, exec, and
poststop warnings are logged while successful operation and cleanup flow
continue unchanged. Optional nonstandard State values and properties remain
unadvertised, and optional remaining process properties are deliberately
deferred until Start.

The common configuration gate now freezes all 79 non-VM items in
`config-schema.json` and `defs.json`: 69 enforced, two validated, four rejected
unsupported, and four rejected as inapplicable. Its normative companion
freezes all 278 `config.md` requirements as 227 enforced, 35 validated, 13
reviewed external, and three conformant entries. OCI annotations remain exact
JSON metadata through bundle and Linux executor planning, including escaped
NUL and control characters, while empty keys and resource bounds still fail
closed. This closes common field semantics only; Linux, lifecycle, security,
cross-driver, and release conformance remain separate gates.

## Current Matrix

| Area | Represented | Validated | Enforced | Conformant |
| --- | --- | --- | --- | --- |
| Complete `Spec` object | Yes | Official schema, version range, known fields, and initial semantics | Exact raw configuration and digest survive SDK wire serialization while unknown top-level and nested properties are excluded from Agent planning | No |
| Common root, mounts, process, hostname, annotations | Yes | Initial cross-field rules; every Root, Mounts, POSIX-platform Mounts, Process, POSIX-platform User, Hostname, Domainname, and top-level platform-section inventory entry except the conventional `rootfs` authoring recommendation is owner-bound. Pinned positive and negative schema evidence covers the common and feature annotation map shapes, optional and empty forms, string keys and values, and structured or unstructured string metadata. The exact OCI Image Specification reference used by Runtime Specification 1.3.0 is retained offline; all eight standard image keys are accepted, seven unambiguous values are checked against it, creation times require RFC 3339, and image stop signals resolve to bounded Linux names, real-time expressions, or numbers. All 82 Linux mount-option entries and the recommended Linux default-filesystem requirement are owner-bound alongside the conditional `/dev`-link entry, terminal and non-terminal `consoleSize`, seven capability and `noNewPrivileges` entries, nine rlimit entries, 14 `oomScoreAdj`, scheduler, and I/O-priority entries, three init-personality entries, four exec CPU-affinity entries, both common value-policy entries, both runtime file-descriptor entries, rootfs propagation, masked/read-only paths, and selected-driver mount-label rejection. The complete OCI 1.3 normative manifest has a reviewed disposition with zero pending entries | Bootstrap slice rejects a missing or non-directory root before namespace entry, applies mounts in source order, roots legacy relative destinations at `/`, accepts OCI-optional mount fields, supplies omitted `/proc`, `/dev/pts`, and writable `/dev/shm`, and supplies read-only `/sys` only when the execution context owns a compatible network namespace. It never replaces exact caller destinations or hides configured parent/child mounts; a user namespace inheriting host networking deliberately receives no host sysfs. The executor also consumes the complete required/recommended OCI 1.3 mount-option control set, preserves unknown filesystem and annotation data, rejects optional `tmpcopyup`, creates the four conditional Linux `/dev` links after mount processing, applies four rootfs propagation modes, recursive VFS attributes, detached ID-mapped filesystem and bind mounts, masked/read-only paths, and read-only rootfs. Utility-VM execution pins the exact mounted runtime share, bundle, rootfs, and existing bind sources with descriptor-relative `openat2` lookups that reject traversal, symbolic links, magic links, and directory-entry swaps before mutation; Native Linux absolute-path semantics remain unchanged. It also applies exact hostname/domainname with post-apply read-back, exact argv/environment/cwd/terminal defaults/UID/GID/supplementary groups/umask, OCI-configured initial PTY dimensions, all five process capability sets with real kernel read-back, exact `no_new_privileges`, all 16 OCI process rlimit types with immediate exact soft/hard kernel read-back, exact optional `oomScoreAdj`, all seven scheduler policies and flags, all three Linux I/O-priority classes, exact `LINUX`/`LINUX32` init personality, exec CPU affinity applied and read back around workload cgroup membership, and process launch for init and exec; native Linux reads back all four synthesized filesystem types and a real `/dev/shm` write/remove cycle in the owned-network profile, proves the three safe defaults plus absent sysfs in the rootless inherited-network profile, rechecks hostname/domainname through procfs, the common process profile inside the executable-script workload, and distinct configured capability, `NoNewPrivs`, `RLIMIT_NOFILE`, `oom_score_adj`, scheduler, I/O-priority, init-personality, and exec CPU-affinity values, plus real shared read-write/read-only bind, private-tmpfs, inline-script, direct-argv, and exact nonzero-exit evidence on x86_64 and aarch64 | No |
| POSIX hooks | Yes | Absolute path, environment shape, positive timeout, and executor bounds | Shared Linux executor runs all six phases in normative order and namespace, passes exact bounded OCI state on stdin, isolates runtime-private descriptors, supervises the exact Hook owner with pidfds, enforces timeout and owner-death cleanup for the complete private process group including signal-resistant background descendants, rolls back independent prestart, createRuntime, createContainer, startContainer, and poststart failures, and continues warning-only poststop hooks | No |
| Linux namespaces and ID mappings | Yes | All 19 namespace, UID/GID-mapping, and time-offset occurrences are owner-bound: 17 enforced and two validated, with pinned required-member, range, create/join/inherit, wrong-type, mapping-bound, no-chown, and normalized-offset evidence | Bootstrap slice creates or type-checks and joins UTS, mount, IPC, network, cgroup, PID, user, and time namespaces; activates loopback only in newly created network namespaces before the create-hook barrier; compares real network namespace identities for new-private, host-inherited, and donor-shared profiles; installs and reads back direct rootful UID/GID maps; proves the A3S Box container-root mapping to host UID 100000 and GID 200000; installs rootless effective-ID and subordinate ranges through verified `newuidmap`/`newgidmap` with `setgroups=deny`; proves rootless create/start/exec/signal/wait/kill/delete, ownership translation, durable events, and cleanup on x86_64 and aarch64; switches to mapped namespace-root credentials before rootfs mutation; and preserves retained-rootfs execution after mount joins. Explicit rootless cgroup delegation and the bounded six-device profile are qualified. For a new mount namespace joined to an existing user namespace, the executor pins and type-checks the namespace, observes its bounded UID/GID maps from inside it, rechecks its identity before entry, and supplies all six default devices with namespace-root ownership. Broader join hardening remains incomplete | No |
| Linux devices, seccomp, capabilities, LSM, sysctl | Yes | Exact schema and semantic rules cover all four device-node types, conditional major/minor values, duplicate kernel identities, optional metadata, and allowed-device types and access masks; all 36 Seccomp configuration and notification-state entries are owner-bound to exact schema, policy, or fail-closed rejection evidence; namespaced sysctls share one dot/slash parser with execution; exact capability-set rules and warning-and-continue handling for recognized capabilities the kernel cannot grant are enforced; AppArmor and SELinux reports are disabled | Bootstrap creates rootful block, character, unbuffered-character, and FIFO sources at normalized paths inside or outside `/dev`, verifies type, identity, mode, and mapped ownership, rejects conflicting existing paths, supplies the six default nodes and `/dev/ptmx`, and binds terminal init's exact PTY slave to `/dev/console`. A rootfs-identity-bound manifest removes only runtime-created targets after Delete, shutdown, failed Create, or owner death. An immutable cgroup-v2 BPF boundary limits access to the declared inventory while always preserving the six normative default device identities plus PTMX/Unix98 PTYs; ordered resource rules can narrow caller-declared non-default devices but cannot remove those required defaults. Omitted `linux.cgroupsPath` receives a private generation-fenced path. Rootful evidence grants `CAP_MKNOD`, rejects an undeclared node, and still rejects a late device source after its bind is remounted with `dev`. Rootless launch installs the same boundary through a parent-bound helper without fabricating a resource policy; the exact A3S Box profile additionally applies live-replaceable device rules. Seccomp installs every advertised AArch64, X86, x86_64, and X32 action and argument operator as ABI-scoped pure-Rust BPF, including legacy x86 multiplexers, x32 syscall numbers, and OCI `MASKED_EQ` operands; unadvertised flags, listener fields, and notification actions fail during immutable init planning. Userspace notification, broader rootless device profiles, and wider sysctl compatibility/security-negative profiles remain open | No |
| Linux cgroup resources | Yes | CPU burst/quota and idle-domain relationships, memory and PIDs finite/zero/unlimited semantics, complete Block I/O device identity, weight, throttle-rate, duplicate, and cgroup-v2 representability rules, complete RDMA entry relationships, bounded Unified key/value and typed-file ownership rules, and one shared parser that rejects unsafe `cgroupsPath` values before runtime mutation | Bootstrap slice resolves absolute `cgroupsPath` values from the visible cgroup v2 mount, resolves relative values from one stable private manager, and creates a private generation-fenced path when the field is omitted. It retains exact cleanup and recovery paths, applies and reads back memory limit/reservation/swap, CPU shares/quota/burst/period/cpuset/idle, PID limits, and Block I/O default/per-device weights plus read/write BPS/IOPS limits, and explicitly rejects cgroup v1 realtime CPU, memory-only controls, and leaf weights. Memory and PIDs Create and Update write non-negative values verbatim, map OCI `-1` to cgroup v2 `max`, and reject values below `-1`. Finite combined swap requires a compatible finite hard limit, while `memory.low` remains independent of `memory.max`; `control-workload-v1` preserves zero plus management headroom but rejects an unlimited workload. Quota and period are independent; live quota/burst and keyed Block I/O changes preserve omitted current values, use safe ordering, retain exact read-back, and reverse prior writes on failure. Block I/O uses BFQ when available, falls back to generic `io.weight`, combines throttle fields by device in `io.max`, maps an OCI zero rate to the cgroup v2 `max` token, and applies only to the workload leaf. HugeTLB and RDMA remain optional until requested, use live kernel inventories, preserve omitted keyed fields during Update, read effective values back, roll earlier writes back in reverse order, and apply only to the workload leaf. Unified accepts safe bounded control-file maps, retains runtime-unknown kernel controllers, enables requested controllers, rejects missing or unwritable files and typed-file conflicts, writes values without imposing a generic kernel read-back format, snapshots readable controls for no-op suppression and rollback, accepts write-only controls, and remains workload-only. For an exact writable OCI cgroup mount paired with a new cgroup namespace, the executor maps `process.user.uid` to the host, preserves GID, and delegates only the cgroup directory plus existing files from the bounded kernel inventory; read-only mounts and unlisted files retain ownership, and an absent inventory uses the normative fallback. Init and exec join the same owned leaf; normalized CPU/memory/PID/event stats and pause/resume use that leaf through `cgroup.freeze` and `cgroup.events`. Native x86_64/aarch64 evidence reads the host membership for an absolute value, recreates a relative value at the same location, and requires both leaves to disappear. Rootless native execution accepts only an explicit canonical user-owned delegation with the four baseline controllers enabled and propagates every enabled optional controller, including runtime-unknown names; absolute values outside it fail closed. A synchronous effective-root bootstrap confines rootless default-device preparation, mandatory inventory BPF, and optional resource-rule narrowing to a parent-bound helper; the exact six-node A3S Box policy has live replace/clear/re-enable and fail-closed cleanup evidence on x86_64 and aarch64. Its opt-in `control-workload-v1` gate roots the cgroup namespace at management, moves trusted init into the fixed control child before controller delegation, moves the configured workload through the inherited descriptor, keeps `linux.resources` exact on the workload child, keeps burst, idle, Block I/O, HugeTLB, RDMA, and Unified out of the derived management envelope, and targets update/freeze/stats there without granting a writable cgroup mount. Failed Create paths kill all descendants through `cgroup.kill`, wait for `populated=0`, detach device policy, remove every runtime-owned cgroup directory, and append cleanup failures to the primary typed error; broader device and delegation profiles remain incomplete | No |
| Linux Intel RDT, memory policy, time offsets, net devices | Yes | Bounded Intel RDT CLOS names and schemata; memory-policy mode presence, bounded node lists, and mode/flag relationships; bounded time-offset and network-device names, templates, target uniqueness, and namespace relationships | The runtime parent discovers resctrl, implements default, container-owned, and explicit CLOS behavior, applies schemata in OCI order with read-back, assigns the authenticated init PID before runtime hooks, creates dedicated monitoring groups, and cleans owned paths after normal or owner-death termination. Feature reporting advertises Intel RDT, schemata, and monitoring. The bootstrap slice also applies all seven recognized NUMA memory-policy modes and three flags to configured init with immediate kernel read-back, preserves inherited policy on omission, reports the same registry through OCI Features, and applies and reads back normalized monotonic/boottime offsets. For `linux.netDevices`, the runtime-namespace parent checks every source and target before mutation, moves source-sorted interfaces through retained namespace descriptors, supports exact and appended `%d` names, preserves stable link attributes and permanent global addresses, sets interfaces up, and rolls back earlier moves if Create fails before its durable commit. Rootless requests fail before mutation without explicit network-device authority. Native Linux qualification uses real dummy interfaces for move/rename, MTU/MAC/address/state read-back, conflict, partial rollback, and cleanup | No |
| VM hypervisor, kernel, initrd, image, and parameters | Yes | Complete pinned schema shapes, all five image formats, four absolute runtime paths, NUL-free executable paths and parameters, and no invented hardware minima; an exact gate freezes 26 schema items and 24 normative requirements | Current drivers reject caller-provided VM launch configuration before durable reservation or platform mutation; runtime-owned, digest-pinned launch assets remain authoritative | No |
| OCI `State` | Yes | Official schema, exact four-value domain, required fields, typed transitions, and generation fences | Durable `creating`/`created`/`running`/`stopped` records retain exact bundle metadata, enforce host-unique live IDs and Linux PID shape, preserve optional annotations, omit nonstandard properties, and produce State values verified against the pinned schema | Optional nonstandard State values and properties are not defined |
| OCI `Features` | Yes | Official schema, version and operation separation; the generated runtime document is validated against the pinned 1.3.0 schema | Every driver publishes one validated Linux support profile when the Host Service opens. Multi-driver services require exact equality; the frozen value generates Features and gates pre-durable Create, Exec, and Update, while the Linux Agent consumes the same shared profile during planning. Linux reports the 60 implemented OCI mount options plus `rnodev` in sorted order, excludes optional `tmpcopyup`, and reports eight namespace types, all 41 recognized capability names, all seven memory-policy modes plus three flags, `netDevices.enabled=true`, cgroup v2 with RDMA support, AArch64/X86/x86_64/X32 seccomp support, and ID-mapped mounts while unsupported controls remain empty or disabled | No |
| `create/state/start/kill/delete` plus init `wait` | SDK contract and core OCI CLI adapter | Required wire arguments, exact Host-to-driver process/signal/delete requests, protocol-v1/v2 compatibility tests, protocol-v3 process-message tests, protocol-v4 control-message tests, protocol-v5 resource-message tests, protocol-v6 process-I/O tests, protocol-v7 terminal-resize tests, protocol-v8 durable process-I/O context tests, durable lifecycle tests, native/utility-VM lifecycle gates, a versioned native four-container churn/leak soak on x86_64 and aarch64, and an exact-package nine-test pinned upstream Runtime Tools lifecycle profile on x86_64 | Driver-independent core orchestration; Native Linux keeps a configured process behind the created barrier, accepts processless Create with a deterministic stopped Start outcome, executes exact argv/PATH and ENOEXEC shell fallback semantics, retains exact signal exit, deletes runtime-owned state and resources, preserves caller-owned bind storage, and permits generation-fenced ID reuse after delete. The short-process OCI CLI adapter journals exact bundle, isolation, generation, operation identity, PID-file, and acknowledgement state before mutation so response-loss retries cannot create a second lifecycle. Seven upstream tests pass raw TAP; `start` and `pidfile` are transparently classified as conformant only under two exact source-audited upstream harness-defect signatures | x86_64 pinned core profile only; inherited stdio descriptors, terminal console sockets, `LISTEN_FDS`, AArch64 upstream rootfs input, broader lifecycle suites, and every other advertised platform remain open |
| Ordered runtime events | SDK contract | Bounded request validation, exact-generation filters, exclusive cursor pagination, long-poll wake and timeout tests, host-service reopen replay, corruption checks, exhaustive durable commit recovery, and native Linux lifecycle evidence | The configured host persists ordered lifecycle and process events independently of driver and guest capability advertisement | No |
| Hooks and rollback ordering | SDK contract | Native Linux retains the six-phase order and exact `creating`/`created`/`running`/`stopped` state trace; real-driver prestart, createRuntime, createContainer, startContainer, and poststart failures each prove typed failure, stopped cleanup, and empty runtime state; prestart timeout proves termination of a signal-resistant background descendant with the Hook process group; a versioned real `startContainer` owner-death gate binds exact process incarnations and nests stopped-only Native recovery; poststop failure remains warning-only; focused planning and control-barrier tests cover the shared executor | The complete ordered phase, failure policy, and one owner-crash boundary are enforced; additional crash points, process-group escape security negatives, and adversarial hook-soak suites remain pending | No |
| Exec, I/O, PTY, per-process wait, pause/resume, processes, update, stats | SDK contract | Typed requests; protocol-v3 exact process target/correlation tests; protocol-v4 exact freezer and inventory tests; protocol-v5 live-update and typed-stats tests; protocol-v6 byte-cursor output, EOF, piped-stdin, close, target, and payload-bound tests; protocol-v7 exact-target resize, positive-size, capability-filtering, and forged-request tests; protocol-v8 mutation-context compatibility and exact replay tests; exhaustive durable process/freezer/update/process-I/O recovery and driver-boundary matrices; real piped, inherited, and terminal I/O, update/stats, frozen/resumed workload, and A3S Box FD 3/4/5 listener/log evidence | Native Linux exposes durable exact-target exec, pidfd-backed process signal, stable process wait, inherited launcher stdio, exactly replayed piped stdin, bounded captured stdout/stderr, controlling PTYs, terminal resize and `VEOF`, init-exit supervision, pause/resume, live process inventory, partial live cgroup resource updates, normalized stats, and cleanup through `RuntimeClient`; its process-local create path enforces the fixed A3S Box exec-listener, PTY-listener, and init-log descriptor contract, while utility-VM host-console projection remains a separate integration concern | No |
| File transfer and filesystem sessions | SDK contract | Protocol-v4 SDK transport, protocol-v10 Guest replay-record acknowledgement, v3 Host journal recovery, exact request-shape, size/depth, capability, target-correlation, generation-fence, driver-boundary tests, and 18/18 real-HVF File/Filesystem owner-replacement paths | The shared executor confines paths to a retained rootfs descriptor with `openat2` and descriptor-relative syscalls, maps container users through the retained namespace, bounds payloads and listings, and journals upload/mkdir/move/remove by `OperationId`; the Host retains each exact mutating request and typed response, commits before Guest acknowledgement, replays without redispatch, and permanently fences changed reuse | No |
| Checkpoint and restore | SDK contract | Protocol-v8 typed single-file paths, exact paused source generations, immutable content/configuration/attachment/driver/Host-build/driver-build/format references, request-bound paused responses, legacy-semantics rejection, capability-advertisement exclusion tests, and a rootful real-CRIU v3 lifecycle, two-boundary replacement-process recovery, and rejection gate | The explicit Native Linux CRIU constructor implements a constrained experimental checkpoint/restore profile with immutable publication, read-only validation, exact device remapping, paused restore, response-loss replay, durable driver-local restore stages, exact recreation after owner replacement, and scoped cleanup; default and production drivers remain fail-closed pending broader profiles, cross-driver/package, multi-architecture, and release qualification | No |

The Linux cgroup-resource boundary now explicitly rejects OCI cgroup v1
`net_cls` and `net_prio` network controls before Create or Update mutation. It
also includes OCI 1.3 HugeTLB, RDMA, and Unified. Both
HugeTLB fields are schema-checked, limits retain the complete `uint64` range, and the
executor resolves canonical page sizes against live `hugetlb.<size>.max`
controls before mutation. It also writes `hugetlb.<size>.rsvd.max` when the
kernel exposes reservation accounting, preserves omitted page sizes on Update,
rolls back earlier dynamic writes, and keeps HugeTLB on the workload leaf in
`control-workload-v1`. The `hugetlb` controller remains optional unless a
bundle requests it; Native Linux qualification performs real read-back when a
runner exposes a usable controller and page size. RDMA uses the same
request-scoped controller model with device preflight, keyed partial updates,
exact read-back, reverse rollback, and workload-only placement. Qualification
checks zero workload limits against an unlimited control child when the host
exposes a usable RDMA device. Unified preserves controller files unknown to the
runtime, enables their live controllers, rejects unsafe or unavailable files
and typed-file conflicts, and applies bounded writes only to the workload leaf.
Readable controls supply no-op and best-effort rollback snapshots; write-only
controls remain valid without claiming reversibility. Native qualification
reads `memory.high` from the control and workload children and exercises
rootful and delegated-rootless Update.

The current runtime must therefore remain `probe-only`.

## SDK Preservation Boundary

The following official types are public SDK inputs or outputs:

```text
oci_spec::runtime::Spec
oci_spec::runtime::Process
oci_spec::runtime::LinuxResources
oci_spec::runtime::State
oci_spec::runtime::Features
```

`OciBundle` holds the complete decoded `Spec`, the exact validated
`config.json` text, an absolute bundle directory, and a SHA-256 digest of
those exact bytes. Its wire decoder recomputes all derived state and rejects a
relative path, digest mismatch, invalid schema, unknown field, or unsupported
version. The create implementation must durably retain those bytes or a
cryptographically equivalent immutable snapshot before returning `created`.
Changes to the source bundle after create must not affect the container.

The SDK transport maps every service method to a protocol-versioned request
and response variant. Its length-delimited frames are bounded before
allocation, request IDs are correlated, service errors remain typed, and a
protocol violation poisons the connection. Transport decoding invokes
`OciBundle`'s custom fail-closed decoder, so crossing a named pipe, Unix
socket, or guest bridge cannot bypass bundle validation.

`OciSemanticValidator` returns bounded, phase-aware reports with stable rule
identifiers. It currently covers an initial set of common process, mount,
hook, Linux namespace, ID mapping, sysctl, seccomp, resource, Intel RDT,
memory-policy, time-offset, network-device, and VM path relationships.
`ValidateRequest` applies the relevant bundle, process, resource, I/O, path,
and payload checks at the in-process client, IPC client, and server
boundaries. This is a fail-closed foundation, not a claim that every normative
requirement is already conformant.

The SDK adds only runtime-call metadata that OCI intentionally leaves
implementation-specific:

- validated container, process, operation, and trust-domain IDs;
- generation fences and idempotency IDs;
- explicit isolation requirement;
- deadline and I/O attachment policy;
- stable error class;
- driver and effective-isolation evidence.

These additions do not replace or reinterpret OCI configuration fields.

## OCI command-line adapter

On Unix, `a3s-oci` exposes the standard short-process core commands `create`,
`state`, `start`, `kill`, and `delete`. Each invocation connects to an
already-running Host Service through `A3S_OCI_RUNTIME_ENDPOINT`. It also requires
`A3S_OCI_CLI_STATE_ROOT` to name an existing canonical private directory;
the directory and its per-container children must be owned by the invoking
identity and deny group/world access. `create` additionally requires
`A3S_OCI_CLI_ISOLATION` to be `shared-host-kernel`, `dedicated-vm`, or
`shared-guest-kernel`; the last form also requires
`A3S_OCI_CLI_TRUST_DOMAIN`.

The adapter stores an append-only, locked, generation-fenced journal before
each mutating request. It binds the canonical bundle, configuration and
attachment digests, isolation request, PID-file path, exact Host generation,
operation sequence, and acknowledgement state. An ambiguous invocation must
be retried with the same arguments and operation identity; acknowledged
duplicate Create or Start commands fail, while a completed Delete retires the
incarnation and permits safe container-ID reuse. Corrupt, linked, incorrectly
owned, or overly permissive state fails closed. Non-Unix hosts currently reject
the adapter before journal mutation because equivalent private ACL validation
has not been integrated.

The current adapter intentionally rejects terminal bundles and
`--console-socket`, and rejects nonzero `LISTEN_FDS`. Inherited standard-I/O
descriptor lifetime cannot yet cross the short-lived CLI process and durable
SDK Host Service boundary. Those descriptor transports, broader upstream
Runtime Tools suites, AArch64 lifecycle input, and other platform package gates
remain outside the qualified x86_64 core profile.

## Automated Evidence

The conformance pipeline pins the OCI 1.3.0 release. It currently provides:

1. a generated and checked-in v2 support manifest for all 423 named JSON
   Schema properties and enum values, regenerated from reviewed evidence and
   rejected on unknown, duplicate, stale, pending, or incomplete bindings;
2. a generated and checked-in inventory of all 764 RFC 2119 occurrences from
   the 15 normative source documents, including source-document SHA-256
   digests and stable requirement IDs;
3. all 19 upstream positive, schema-negative, and malformed-JSON fixtures,
   plus a four-profile Host Service matrix covering the checked-in Native
   Linux, Linux KVM, macOS HVF, and Windows WHPX configurations, generated
   Features documents, and created/running/stopped State documents;
4. an exact-source official OCI Runtime Tools 0.9.0 bundle gate at commit
   `8a4db579f5c88af5a0d036fad34bddc9c1f703f3`, built statically with Go 1.24.0,
   that validates the packaged Native Linux and utility-VM OCI 1.3.0
   configurations at MUST level and rejects an escaping rootfs path;
5. an exact-package x86_64 OCI command-line lifecycle qualification using the
   same pinned Runtime Tools source and `rootfs-amd64.tar.gz`. All nine selected
   tests execute; seven pass raw TAP, while `start` and `pidfile` retain two
   exact source-audited upstream harness-defect signatures plus the runtime's
   conformant state, error, cleanup, retired-journal, and clean-shutdown
   evidence. AArch64 retains a separate unavailable record because that
   revision has no AArch64 rootfs fixture;
6. strict typed round-trip tests for applicable upstream Linux, State, and
   Features fixtures;
7. positive and negative semantic fixtures with stable rule identifiers;
8. request-validation tests, including an untrusted raw-wire rejection test;
9. in-memory end-to-end transport tests plus real Windows named-pipe and Unix
   socket connector tests;
10. a versioned ten-case real-Guest path-isolation profile, wired into macOS
   Apple Silicon CI and the Linux KVM 17-case lifecycle matrix, that requires
   exact typed rejection, unchanged canaries, absent container state, and
   complete fixture/runtime cleanup.

Both generated inventories have zero pending entries. The schema manifest has
zero `conformant` items, so remaining release-conformance evidence includes:

1. positive decode/round-trip fixtures for every applicable property;
2. negative cross-field and semantic fixtures;
3. additional hook crash-boundary, process-group escape security-negative, and
   adversarial hook-soak traces beyond the retained native six-phase failure,
   `startContainer` owner-death, and bounded complex-container churn reports;
4. feature-report comparisons against actual driver behavior;
5. crash-recovery and cleanup evidence;
6. descriptor-preserving inherited stdio, terminal console-socket, and
   `LISTEN_FDS` support in the OCI command-line adapter, followed by broader
   pinned upstream lifecycle suites and exact-package validation on every
   advertised platform and architecture, without shipping a fallback runtime
   backend.

CI must fail when a pinned schema property has no classification or when code
advertises an operation without a passing implementation test. It also fails
when a normative source document changes digest or a coverage item is missing,
duplicated, or claims implementation without rule and test evidence.

## Update Policy

An OCI specification upgrade begins with a dedicated commit that updates the
pinned schemas, model dependency, property inventory, support range, fixtures,
and this matrix together. Supporting a new model field does not by itself
raise `OCI_RUNTIME_SPEC_VERSION_MAX`; semantic and enforcement gates must pass
first.
