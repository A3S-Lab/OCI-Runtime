<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="A3S OCI Runtime binds each container to an exact generation, durable lifecycle, and evidence-gated execution driver">
</p>

<p align="center">
  <strong>The low-level execution plane for A3S: official OCI types, durable lifecycle replay, and one reviewed Linux executor across native and utility-VM paths.</strong>
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/OCI-Runtime/actions/workflows/ci.yml"><img alt="CI status" src="https://img.shields.io/github/actions/workflow/status/A3S-Lab/OCI-Runtime/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/A3S-Lab/OCI-Runtime/releases/latest"><img alt="Latest A3S OCI Runtime release" src="https://img.shields.io/github/v/release/A3S-Lab/OCI-Runtime?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=68c7ff"></a>
  <img alt="OCI Runtime Specification 1.3.0" src="https://img.shields.io/badge/OCI_Runtime_Spec-1.3.0-68c7ff?style=flat-square">
  <img alt="Rust workspace" src="https://img.shields.io/badge/implementation-Rust-dbe7f0?style=flat-square&amp;logo=rust&amp;logoColor=111827">
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-f0b85a?style=flat-square"></a>
</p>

<p align="center">
  <a href="#inspect-before-you-launch">Inspect</a> ·
  <a href="#what-exists-today">Implementation</a> ·
  <a href="#the-runtime-contract">Contract</a> ·
  <a href="#platform-status">Platforms</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#run-the-real-gates">Qualification</a> ·
  <a href="#development">Development</a>
</p>

---

**A3S OCI Runtime** owns actual Linux-container execution for A3S: exact OCI
validation, container and process state, monotonic generations, operation
journals, terminal status, platform drivers, utility VMs, the authenticated
guest agent, and runtime-scoped cleanup.

It deliberately does not pull images, build images, implement Compose, own
product networks or volumes, or become a Docker daemon. Those responsibilities
remain in [A3S Box](https://github.com/A3S-Lab/Box), which supplies prepared
bundles, an isolation requirement, and a versioned attachment manifest through
the public `a3s-oci-sdk`.

The provider-neutral Rust contracts are also available independently as
`a3s-oci-core = "=0.3.1"` and `a3s-oci-sdk = "=0.3.1"`. Their
`sdk/rust/v*` source tags are separate from full Runtime binary releases.

> [!WARNING]
> This repository is in active development. No built-in driver is currently
> advertised as `supported`. The default host service exposes discovery
> only; Native Linux becomes `experimental` only when explicitly opened as a
> development instance, Apple Silicon HVF is `experimental`, and KVM and WHPX
> remain `probe-only`. Experimental means the reviewed development profile may
> launch; it does not imply production certification.

## Inspect before you launch

The first successful action is intentionally read-only:

```bash
git clone https://github.com/A3S-Lab/OCI-Runtime.git
cd OCI-Runtime
cargo run -p a3s-oci-cli -- features
```

On the qualified Windows x86_64 host used for the current branch, the command
reports an available hypervisor and still refuses to overstate driver
readiness:

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

The evidence object is host-specific. The selection rule is not:

| Reported state | May launch? | Meaning |
| --- | --- | --- |
| host `available` + `probe-only` | No | Diagnostics or qualification only |
| host `available` + `experimental` | With explicit opt-in | Reviewed development profile; release gates remain |
| host `available` + `supported` | Yes | Certified profile |
| host `unavailable` or `unsupported` | No | Prerequisite absent or platform does not apply |

`DriverCapability::can_launch()` requires both an available host capability
and `experimental` or `supported` readiness.

## What exists today

| Layer | Implemented boundary |
| --- | --- |
| Public SDK | Async `Send + Sync` Rust contract using official OCI `Spec`, `Process`, `LinuxResources`, `State`, and `Features` types; typed IDs, generations, operation contexts, exact-artifact per-driver capability negotiation, versioned attachments including already-authorized storage, Linux network interfaces, opaque network-enforcement/local-redirect evidence, reusable guest-session identity, immutable checkpoint references and paused restore responses, I/O, filesystem sessions, stats, events, and stable errors |
| Validation and transport | OCI 1.0.0–1.3.0 schema and semantic validation with forward-compatible unknown-property retention and ignore semantics, an exact 79-item common configuration and 278-requirement owner gate, an exhaustive 19-case pinned upstream JSON Schema suite, four launch-profile configuration/State/Features matrices, immutable configuration, attachment, and checkpoint SHA-256 binding, and bounded protocol-8 local IPC over Unix sockets or protected Windows named pipes |
| Durable host service | Exact create/state/start/kill/delete, driver-advertised optional operations including immutable checkpoint and paused-generation restore orchestration, global idempotency journals including File upload and Filesystem mkdir/move/remove, replay, generation fencing, startup recovery, startup-wide cross-journal orphan auditing, failed-generation quarantine, capability-rooted state traversal with Unix mount-identity fencing, post-commit replay-record acknowledgement for local and utility-VM drivers, sorted list, ordered events, and same-UID multi-container owners for Native Linux and Apple Silicon HVF |
| Shared Linux executor | Namespace create/join, declared-root directory admission before namespace entry, `pivot_root`, ordered OCI mounts with root-relative legacy destinations and optional-field handling, the complete OCI 1.3 Linux mount-option control registry, exact init/exec argv, environment, cwd, terminal default, UID/GID, supplementary groups, and umask, conditional `/dev/fd`, `/dev/stdin`, `/dev/stdout`, and `/dev/stderr` links after mount processing, OCI hooks with fail-closed private-descriptor isolation and exact-owner pidfd process-group supervision, user mappings, exact absolute and stable relative `cgroupsPath` resolution plus a private generation-fenced path on omission, complete cgroup v2 CPU shares/quota/burst/period/cpuset/idle mapping with explicit cgroup v1 realtime rejection, exact memory limit/reservation/swap and PIDs create/update mapping with zero preserved and OCI `-1` encoded as `max`, finite total-swap validation, complete cgroup v2 Block I/O default/per-device weight and read/write BPS/IOPS throttle mapping with zero-rate clearing, keyed read-back, partial-update preservation, reverse rollback, and explicit leaf-weight rejection, dynamic HugeTLB usage/reservation controls, keyed RDMA HCA handle/object limits, bounded OCI 1.3 unified control-file writes with dynamic controller enablement, kernel-defined formatting, typed-file conflict rejection, readable no-op/rollback snapshots, and write-only control support, typed rejection of cgroup v1-only memory and network `net_cls`/`net_prio` controls, all five capability sets with kernel read-back, exact `no_new_privileges` verification, all 16 OCI rlimit types with exact kernel read-back, `oomScoreAdj`, scheduler policy, I/O priority, exact `LINUX`/`LINUX32` init personality, all seven OCI NUMA memory-policy modes and three flags with kernel read-back, parent-owned Intel RDT CLOS, ordered schemata, process assignment, monitoring, and owner-death cleanup, exec CPU affinity applied around cgroup membership, transactional namespaced sysctls with descriptor-confined apply, read-back, and rollback, exact rootful block/character/FIFO nodes, the six default devices, `/dev/ptmx`, PTY-backed `/dev/console`, durable placeholder cleanup, immutable declared/default device inventory BPF with ordered resource-rule narrowing, seccomp, PID 1 supervision, pidfds, exec, process I/O, PTY with OCI `consoleSize` initialization, a bounded Host-acknowledged mutation replay journal, parent-bound launch/session helpers, PID-start-time-bound owner-death tombstones, descriptor-confined file/filesystem sessions, pause/resume, resource updates, normalized CPU/memory/PID/block-I/O stats, and scoped cleanup for the qualified profile |
| Utility-VM boundary | Isolated libkrun shim, authenticated protocol v10 with v1-v9 compatibility, 20 public workload operations plus one bounded maintenance acknowledgement, clone-wide shutdown, exact-generation VM sessions, and the same Linux executor behind the static guest agent. A platform-neutral one-VM-per-generation lifecycle now backs both the public HVF driver and the Linux KVM candidate, including bundle ownership handoff, concurrent Create fencing, retry and terminal cleanup, stopped recovery tombstones, and bounded shutdown. Durable recovery records remain on the per-generation share, privileged OCI device sources are created only on Guest-local devtmpfs and removed at the Create barrier, and shutdown consumes every retained device-target manifest before deleting the Guest runtime root |
| containerd runtime-v2 | SDK-only `containerd-shim-a3s-oci-v2` with a code-owned contract for all 17 methods of `containerd.task.v2.Task`, a 24-route translation table whose exact 18-operation required SDK union gates endpoint admission, and per-driver `Checkpoint`/`Restore` v1 negotiation. Task Checkpoint commits a digest-validated directory package; checkpoint-backed Create restores a paused generation and schema-v10 metadata preserves its CREATED-to-Start barrier across shim replacement. The shim also retains exact 2.2.2 arm64 Native Linux development qualification, 2.2.3 x86_64 regression evidence, and a current three-pass 2.2.1 WSL2 observation covering all 23 restart/rehydration boundaries. Durable namespace/task/exec identities, replayable task and `DeleteProcess` receipts, sequenced input/signal/resize/control journals, bounded FIFO/PTY I/O, exact-generation crash cleanup, and restart recovery are retained. Schema v9 remains readable and introduced exact pending-Update bodies; schemas v1-v8 remain compatible under their documented defaults. Unit coverage includes package replay and tamper rejection, restore-intent DeleteShim cleanup, committed-Resume adoption, committed init/exec Start adoption, terminal signal settlement, response-receipt replay, and race-free output cursor restoration. No production driver advertises Checkpoint or Restore yet, and broader version, published-artifact, cross-driver, and real-host checkpoint qualification remain open. |
| A3S Box consumer | Public-SDK-only lifecycle and attachments; pause/resume; process and filesystem sessions; exact live inventory, normalized stats, bounded ordered events, and replay-safe complete resource updates; explicit Native Linux Sandbox production routing and real-host SDK composition pass, while default and cross-platform cutover remain open |
| Retained evidence | Schema and normative locks, 189-pair authenticated protocol fault coverage, portable nine-stage Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem host reopen with exact post-commit acknowledgement, real-HVF nine-stage Host/Guest Create plus two-stage Host shutdown interruption and cleanup, all nine real-HVF Create, State, Start, Kill, Delete, Wait, Exec, SignalProcess, WaitProcess, Pause, Resume, Processes, Update, Stats, ReadOutput, WriteStdin, CloseStdin, Resize, File, and Filesystem transitions through durable service reopen and VM/session-owner replacement, a real protocol-v10 Apple Silicon Guest boot, native Linux real-container with distinct exact init/exec capability, `NoNewPrivs`, rlimit, OOM-score, I/O-priority, scheduler, init personality, init NUMA memory policy, exec CPU-affinity, and namespaced-sysctl read-back, rootless default-device and device-policy gates, soak, owner-death safe-termination, exact `startContainer` Hook process-group owner-death recovery, and three consecutive same-Host live containerd 2.2 lifecycle/restart/I/O matrices with deleted exec-ID reuse, lost `DeleteProcess` and task Delete response replay, post-commit guest-journal reclamation, and committed init-Start, exec-Start, init-Kill, Pause, Resume, Update, WriteStdin, CloseStdin, SignalProcess, and ResizePty shim-replacement gates, post-commit `WriteStdin` and `CloseStdin` forced cleanup, fresh-VM HVF soak, fail-closed Linux KVM lifecycle/recovery/25-wave soak entries, and WHPX nominal plus owner-death/service-restart qualification |

Shim restoration now reconciles an exact Runtime `Stopped` record before it
replays a pending init signal. If local metadata has no exit, one bounded
exact-generation Wait imports the Runtime's durable exit; the signal journal
then advances without a second Kill. Three consecutive Ubuntu
arm64/containerd 2.2.2 matrices on August 24, 2026 retained this terminal
init-Kill boundary through one unchanged Host PID, including exit-42 shim and
containerd Wait/Delete evidence and an independent zero-live-residue audit.

Exec restoration applies the same authoritative-exit rule without delaying a
live process: before replaying a pending process signal, it performs an exact
zero-timeout `WaitProcess`. A durable exit moves the exec to `Exited`, records
the first observation time, and settles the pending sequence without a second
`SignalProcess`; `DeadlineExceeded` proves the exec is still live and preserves
the normal identity-stable replay path.

`DeleteProcess` now writes an exact response receipt before atomically removing
the stopped exec from the main shim metadata. If the exec remains in that main
record after a crash, the receipt is only an uncommitted intent and rehydration
discards it. If the exec is absent, a replacement shim replays the receipt's
PID, exit status, and nanosecond exit time. A new durable incarnation of the
same exec ID clears the old receipt, and full task Delete or DeleteShim removes
the journal.

Task Delete now stores `a3s-oci-shim-task-delete-v1.json` before dispatching
the generation-fenced Runtime delete. The receipt binds the namespace, task
incarnation, container identity, generation, bundle, PID, exit status, and
nanosecond exit time. Retained main metadata plus a live Runtime generation
marks an uncommitted intent and consumes the receipt; after task removal, a
metadata-free replacement validates the serving namespace, task ID, and
bundle and returns the exact first response. That replay-only shim signals its
exit after serving the response, so containerd 2.2.3 leak cleanup cannot leave
an unowned replacement process waiting forever.

Restoration also publishes the validated task into in-memory state before it
starts any output pump. An immediately replayable output chunk can therefore
commit its durable cursor against the restored task instead of racing a
missing state entry. A deterministic FIFO regression covers that ordering,
and partial pump-start failure stops every pump already created before the
published task is rolled back.

Post-commit `WriteStdin` forced cleanup now has its own exact boundary. The
gate stops the Host until schema-v10 metadata retains exec incarnation 1,
pending sequence 1, and the exact stdin bytes, then stops the shim and commits
the same `write-stdin-1` identity directly through the public SDK. The exec
must exit 23 from one input effect while init stays Running at its original
PID and generation. After shim `SIGKILL`, DeleteShim must not redispatch the
pending bytes; it removes the exact Runtime generation, workload processes,
bundle, cgroup, and shim state while preserving caller-owned container
metadata.

Post-commit `CloseStdin` forced cleanup now has the matching exact boundary.
With the Host stopped, `CloseIO` reaches the task shim through its advertised
ttrpc endpoint and schema-v10 metadata retains exec incarnation 1, stdin state
Closing, and no pending write. The shim is then stopped, the Host resumed, and
the same incarnation-bound `close-stdin-1` identity committed directly through
the public SDK. EOF makes the exec exit 29 while init remains Running at its
original PID and generation. After shim `SIGKILL`, DeleteShim must not dispatch
a second close; it removes the exact Runtime generation, workload processes,
bundle, cgroup, and shim state while preserving caller-owned container
metadata. The focused unit boundary starts with one recorded Runtime close and
proves cleanup leaves that count unchanged while fencing Kill and force Delete
to the exact generation.

Post-commit `ResizePty` forced cleanup now has the matching automated
boundary. The ignored real-containerd gate creates a terminal exec, stops the
Host, sends `ResizePty` through the shim's validated ttrpc endpoint, and
requires schema-v10 metadata to retain exec incarnation 1 with pending sequence
1 at 166x52. It then stops the shim, resumes the Host, and commits the same
incarnation-bound `resize-1` identity directly through the public SDK. The
gate reads the live PTY dimensions through `/proc/<pid>/fd/0` and
`TIOCGWINSZ`, then kills the shim and requires the original response to be
lost. DeleteShim must not dispatch a second resize; it removes only the exact
Runtime generation, workload processes, bundle, cgroup, and shim state while
preserving caller-owned container metadata. The focused unit boundary begins
with one recorded Runtime resize and proves cleanup leaves that count
unchanged while fencing Kill and force Delete to the exact generation.

All non-destructive CI targets pass with this gate, including Linux, musl,
macOS, Windows, and Native Linux arm64 coverage. Source revision
`2fef85c6e68a07f114d211175b77841301d57985` also passed three complete
containerd 2.2.1 matrices on Ubuntu 24.04.3 LTS/WSL2 x86_64 in 91.96, 91.89,
and 91.92 seconds through unchanged Host PID 1566. Every pass crossed all 23
daemon-restart and post-commit rehydration boundaries, including the current
forced-cleanup `ResizePty` gate. The static-musl CLI, agent, shim, qualification
executable, and Cargo.lock SHA-256 values were
`e22a08d884ad59187fce39e170f6ca21d367a77c2d3a1a297cb8650adf6f7561`,
`c73cc2356552de6f2def62598a44fb370df7300a56af5c7be33e63d148b865e2`,
`c4c8ce162cdb0c031eac6e792e2bbdf9c99c30e7ef971ca8791b123f2b4ce00c`,
`ba458b70cb1c879ed78095d326ccfe8992b22f12198728b45cc8d50a52e0451f`,
and `1f00f4ec1b0f1ba9f3e39daf2b8782e42c922d9fa696aaa07c709c38123edca0`.
The default containerd remained active at PID 184. Final audits found zero
tasks, containers, live Runtime containers, matching processes, mounts, or
cgroups before both isolated roots were removed. This source-build WSL2 record
is observation-only and does not promote the exact containerd 2.2.2 Ubuntu
arm64 development claim; exact release-package range qualification and the
remaining R7 release gates stay open.

Source revision `9726719e5a66156cd61f8be36ca00998bbcfc871` passed three
complete Ubuntu 24.04 x86_64/containerd 2.2.3 matrices consecutively in
117.37, 119.36, and 118.94 seconds through unchanged Host PID 2678296. The
release CLI, agent, shim, qualification executable, and Cargo.lock SHA-256
values were
`80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`,
`68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`,
`99bacac7a308e4830ca55101ef8148a511526722cf9006d8a37ef9cba89dbf50`,
`3e752abc8ada3b8e3dae9d86e370feb7d17bf04c2245f13888d52ba7537b2fd2`,
and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
The suite used a dedicated private containerd root, state, socket, and systemd
unit; the production containerd remained active at PID 2485480 throughout.
Independent audits after the probe and every pass found zero matching tasks,
containers, bundles, live Runtime records, cgroups, snapshots, shim processes,
qualification processes, or workload processes.

Source revision `a3865075d8ced661447a85196e17136379535fa7` passed three
complete Ubuntu 24.04 x86_64/containerd 2.2.3 matrices consecutively in
89.96, 93.40, and 94.55 seconds through unchanged Host PID 2504484. The
release CLI, agent, shim, qualification executable, and Cargo.lock SHA-256
values were
`80d0b69686c73516fc3a507f2545af77b405918584176bdb0a96ab3bcf067102`,
`68219e592a061b9dba7f491d54716354195cd8f8005fa792ab367681dda5352e`,
`ca14a7d28f3b95656b831006c22e2e88561c272a19c48aab19b43d6592ca652c`,
`c560b1d92d4e786a026fd2c8002bcb0330c06d620304a08c5df4951ebdaf9ce4`,
and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
The suite used a dedicated private containerd root, state, socket, and systemd
unit; the production containerd remained active at PID 2485480 throughout.
Independent audits after every pass found zero matching tasks, containers,
bundles, live Runtime records, cgroups, mounts, shim processes, agent or Host
children, qualification processes, zombies, or prepared operations.

Source revision `5a6d5f2d817d5951929c2394dff57ef925dd5822` passed three
complete Ubuntu arm64/containerd 2.2.2 matrices consecutively in 65.15,
66.76, and 64.11 seconds through unchanged Host PID 436920. The release
Host, agent, shim, qualification executable, and Cargo.lock SHA-256 values were
`53bf14d72adb347b35d19f936bf91d15adcc3cce65aa88f63886746f07f5ddb2`,
`28dad74972b28b400a9e5e9f9b38ba59aeaf6662532dfefc7dd5527ff17d6b48`,
`801c6ebd6bb6a41f1049dbd64d6ae60165a0914254edb953b2eaf633c6c368f2`,
`fa3a513bf2f5aba01a511bc953dcfc5cb1bb05080fbd58bb993d9a0a44a10363`,
and `c31f4bb3ea8394cbb05adcb25051994e75c8592b53be7b7d3b5e82f74cfd1727`.
Every pass retained the exact sequence-1 SIGTERM, normal exec exit 29,
replacement-shim and restarted-containerd Wait evidence, the first and
replayed `DeleteProcess` PID, status, and exit timestamp, and the original
running init PID. Independent audits after every pass found zero matching
tasks, containers, bundles, cgroups, mounts, live Runtime records, shim,
agent, qualification, or Host-child processes and zero zombies or prepared
operations. The original installed shim was restored at SHA-256
`a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`;
the test Runtime root, release target, checkout, and logs were removed.

OCI 1.3 `linux.netDevices` is implemented by the shared Linux executor. The
runtime validates a bounded deterministic move plan, requires a separate
network namespace, rejects exact target-name collisions, supports appended
`%d` templates, preserves stable link attributes and permanent global
addresses, and brings each moved interface up. A failed Create rolls earlier
moves back in reverse order; the rollback lease is released only after the
created state is durably committed. Rootless execution rejects the request
before mutation because the current helper contract does not grant host
network-device authority. The Native Linux gate uses real dummy interfaces to
exercise move, rename, address/MTU/MAC preservation, target conflict, partial
rollback, rootless rejection, and cleanup.

The rootful public `a3s.oci.attachments.v3` profile adds immutable caller-issued
namespace, interface, and cleanup identities around that OCI mechanism. It
requires an exact target interface name rather than `%d`, binds all three
identities into durable replay evidence, and distinguishes runtime-created
namespace release from preservation of a joined caller namespace. It never
receives or decides IPAM, DNS, routes, aliases, or network policy.

The required `dev.a3s.network.enforcement@1` extension adds an opaque,
generation- and SHA-256-bound caller enforcement identity plus an optional
node-local redirect identity to one exact joined caller namespace. Its closed
schema cannot carry hostname/IP rules, routes, endpoints, credentials, tenant
metadata, or policy decisions. The Host negotiates it independently, passes it
unchanged to the driver, and revalidates exact `ContainerRecord` evidence after
restart. No production driver advertises the extension until its real-host
namespace attachment, cleanup, redirect, and enforcement gates pass.

Pause and resume remain separately negotiated runtime operations with stable
`OperationContext` identities, exact-generation fencing, durable replay, and
restart reconciliation. Their committed `ContainerPaused` and
`ContainerResumed` observations now expose the exact mutation through typed
`RuntimeEvent::operation_id`; the Host validates it against both the durable
event claim and the legacy `operation-id` attribute. Older event-v1 records
without the typed projection remain readable through that validated attribute.
The Runtime does not decide when a workload is idle or should wake; callers own
that policy and issue the explicit operations.

The public `a3s.oci.attachments.v4` profile establishes the reusable
guest-session boundary. A SharedGuestKernel create or restore must bind one
logical session ID, positive incarnation, immutable trust domain, capacity
from 1 through 64, runtime ownership, and an explicit destroy-on-empty or
same-trust-domain retain mode. Protocol 7 and durable `ContainerRecord`
evidence fence downgrade, restart, and operation-ID reuse. The shared HVF/KVM
driver core implements session-scoped shares and ownership markers, serialized
admission, capacity and generation fencing, both reset modes, member-local
failure cleanup, session recovery reports, and one-owner shutdown. Production
HVF, KVM, and WHPX registrations continue to advertise only their qualified
attachment profiles until the corresponding real-host restart, cleanup, and
soak evidence is retained and their cumulative storage/network transports are
implemented.

OCI 1.3 `linux.resources.hugepageLimits` is also implemented by the shared
executor. The SDK preserves the complete normative `uint64` range, while the
executor validates each canonical page-size name against the live cgroup-v2
inventory, enables `hugetlb` only when requested, and applies both usage and
reservation limits when the kernel exposes reservation accounting. Create and
live Update use kernel-representable values with read-back and reverse rollback;
partial updates leave omitted page sizes unchanged. In `control-workload-v1`,
HugeTLB remains an exact workload-only limit rather than being copied into the
management envelope. Native Linux CI reads the selected host page-size controls
back on x86_64 and aarch64 whenever the runner exposes `hugetlb`.

OCI 1.3 `linux.resources.rdma` is implemented as a separate keyed cgroup-v2
controller. Each device may limit HCA handles, HCA objects, or both; device
names and available kernel entries are checked before device-policy mutation.
Create and live Update preserve omitted fields, normalize the kernel's signed
counter ceiling to `max`, read every effective value back, and roll applied
devices back in reverse order. RDMA is required only when requested and remains
workload-only in `control-workload-v1`. Native Linux qualification reads the
control and workload entries back when a runner exposes both the controller and
a usable InfiniBand device.

OCI 1.3 `linux.resources.unified` accepts bounded cgroup-v2 control-file maps.
The executor validates one safe file name per key, rejects runtime-owned
`cgroup.*` state and files already owned by typed OCI resources, preserves
stable write order, and carries controller names unknown to the runtime through
the live kernel inventory. Needed controllers are enabled before leaf creation;
an absent or unenableable controller, missing control file, or unwritable
control returns a typed error before device-policy mutation. Create and Update
write every value in stable order without imposing a generic read-back format.
Update uses readable controls for no-op suppression and reverse rollback, while
write-only controls remain valid. `control-workload-v1` applies them only to the
workload leaf; Native Linux qualification reads `memory.high` from both
children, verifies a kernel-normalized partial `io.max` write when possible, and
exercises rootful and delegated-rootless live updates.

The current Box adapter at `A3S-Lab/Box@a16772c3` rechecks every read against
the exact runtime binding. File upload/download and filesystem
stat/mkdir/move/list/remove now use the same cross-platform session facade;
capability and Box-generation checks happen before dispatch, response targets
and shapes are revalidated, and one explicitly retryable mutation response is
replayed with the same context and one runtime effect. A partial product
resource request is compiled into one complete OCI `LinuxResources` contract,
claimed durably before dispatch, and replayed with the same runtime operation
after a lost response. Runtime acknowledgement updates Box restart intent
atomically without changing the original create identity.

New mutation records use `a3s.oci.operation.v6`. Version 3 File uploads and
Filesystem mkdir/move/remove remain readable; version 4 additionally retains
each exact checkpoint request and typed immutable response; version 5 adds the
exact restore request, allocated generation, and paused-running response; and
version 6 retains each exact TEE attestation challenge and immutable evidence
response. Versions 1 through 5 remain readable for the operations they encode.
The Host commits a journaled result before acknowledging driver replay
evidence, so a disconnect returns a retryable error and the next owner replays
the Host result without dispatching the mutation again. The Host journal
remains the permanent changed-request fence after driver evidence has been
released.

Durable state now pins its canonical root as a directory capability. All
descendant reads, enumeration, creation, replacement, and quarantine moves are
resolved from retained directory handles. macOS, Linux, and Windows gates prove
that an ambient-root rename, layout or transaction symlink/reparse-point
substitution, foreign filesystem handle, same-device Linux bind-mount
replacement, or racing Windows file/directory destination replacement cannot
redirect a mutation. Windows commits each already-open source object relative
to a retained destination-parent handle and applies file DACLs through that
same opened object. File replacement tolerates only a bounded transient Windows
destination share lock. Opening the store recursively audits committed
generation, operation, live-container, process, quarantine, and event
relationships before driver recovery or request serving, while retaining the
explicit intermediate states required for idempotent crash replay.

The exact containerd API, identity, installation, restart, cleanup, and
qualification boundary is documented in
[containerd Runtime V2](docs/containerd-runtime-v2.md).

Contract v1 freezes runtime type `io.containerd.a3s-oci.v2`, task service
`containerd.task.v2.Task`, and Linux archive entry
`containerd-shim-a3s-oci-v2`. Install that entry as
`/usr/local/bin/containerd-shim-a3s-oci-v2`. Namespace and task IDs use the
`sha256-length-framed-u64be-v1` encoding to produce a stable SDK container ID;
the Host assigns the monotonic runtime generation returned by Create, and the
shim persists and addresses that exact generation on every later request.
The same code-owned table maps every Task branch and FIFO pump to its public
SDK operations. RuntimeInfo publishes the exact 18-operation union as
`dev.a3s.oci.containerd-sdk-operations`; the shim refuses an endpoint missing
any member, and its crate manifest is tested to keep A3S Box and driver
implementations outside this adapter boundary.
The bounded process-I/O path reads and writes at most 64 KiB per shim step,
keeps non-terminal stdout and stderr separate, and merges terminal output on
the PTY stream. Every kernel-accepted FIFO prefix advances the durable byte
cursor before the next write, so cancellation never commits an unwritten
suffix and a replacement resumes without loss.

Create recovery covers both sides of the remote commit boundary. The shim
persists the complete bundle, isolation, I/O, rootfs-ownership, task
incarnation, and stable operation identity before dispatch. The real fault
gate can stop the Host before dispatch, stop the shim after that intent is
durable, commit the exact Create directly through the public SDK, and kill the
shim before full metadata exists. DeleteShim must join that one generation,
remove its exact process, runtime state, rootfs, and bundle, and preserve the
caller-owned containerd metadata; a duplicate generation or driver reroute
leaves exact evidence and fails the gate.

That exact Box revision also validates its managed home, durably prepares the
snapshot lower, named volumes, and networking, compiles the product-owned OCI
bundle, and starts or reuses this runtime's identity-fenced long-lived Native
Linux owner. Its blocking x86_64 and aarch64 Linux lanes drive Rust, Python,
TypeScript, and Go Sandbox lifecycle, exec, filesystem, route-aware stats,
pause/resume, snapshot restore, restart, and cleanup through the explicit
production route.

Box completion and Runtime readiness measure different scopes. Box can finish
its current product contract against a qualified Runtime slice; this repository
still owns all 20 public workload operations, every advertised driver, owner-replacement
semantics, OCI conformance, and release qualification. A completed consumer is
therefore not evidence that the lower-level runtime is complete.

Linux file and filesystem calls execute in a fresh internal helper that inherits
only the exact retained root, user-namespace, and mount-namespace descriptors.
The helper authenticates its parent, rejects duplicate or reordered descriptors,
enters the user namespace before the mount namespace, and then performs the
bounded `openat2` operations. Container IDs therefore remain correct on the
rootfs, bind mounts, ID-mapped mounts, and container-created tmpfs filesystems.

The complete release target is every applicable OCI Runtime Specification
1.3.0 requirement for Linux containers and every advertised driver—not a
reduced A3S-only profile. [ROADMAP.md](ROADMAP.md) keeps completed evidence and
open release gates separate.

Capability set enforcement remains exact and fail-closed for every value the
runtime can grant. When the running kernel or the executor's inherited
authority cannot grant a recognized requested capability, init and exec remove
only that unavailable set membership and send a bounded structured warning to
the supervising agent before crossing exec. Malformed or duplicate warning
frames fail closed instead of becoming untrusted log text.

Linux sysctls now follow the same fail-closed boundary. The SDK accepts only
known IPC, network, UTS-domain, and user-namespace controls in OCI dot or slash
notation. The executor rejects host-global controls and same-host namespace
joins, applies a bounded deterministic transaction through retained procfs,
verifies each value, and restores earlier values if Create does not commit.

Intel RDT is owned by the runtime-namespace parent rather than the container
init process. When `linux.intelRdt` is present, the parent finds the mounted
resctrl filesystem, prepares or verifies the requested CLOS, applies
`l3CacheSchema`, `memBwSchema`, and complete `schemata` in OCI order, reads the
effective values back, and assigns the authenticated init PID before runtime
hooks run. Dedicated monitoring groups and runtime-created CLOS directories are
removed on Delete, shutdown, failed Create, or native owner-death recovery.
Explicit and root CLOS directories remain externally owned.

## The runtime contract

### Create and start stay separate

```text
creating ── create committed ──▶ created
created  ── start committed  ──▶ running
running  ── init terminated  ──▶ stopped
```

`create` validates and prepares the requested boundary without executing
`process.args`. Only `start` releases the configured process. Invalid
transitions fail without weakening that barrier.

Each durable container record retains:

- the exact validated configuration and digest;
- the complete `a3s.oci.attachments.v1`, storage-aware v2, network-aware v3, or
  guest-session-aware v4 manifest and its digest for newly created records;
- the exact reusable guest-session incarnation when using shared-guest-kernel
  isolation;
- a monotonically increasing runtime generation;
- the runtime-selected driver and effective isolation;
- active operation intent and terminal replay results;
- the exact init and exec-process exit status when observed;
- recovery or quarantine state for an interrupted mutation.

A matching retry reproduces the original result. A stale generation, reused
operation ID with a different payload, unsupported OCI field, unavailable
isolation class, or changed recorded driver fails before mutation.

### Isolation is a requirement, not a driver name

| Request | Boundary | Kernel sharing |
| --- | --- | --- |
| `DedicatedVm` | Hardware utility VM | One workload or pod owns the guest kernel |
| `SharedGuestKernel` | Hardware utility VM | One declared trust domain shares a guest kernel |
| `SharedHostKernel` | Native Linux | Containers share the host kernel |

`SharedGuestKernel` requests must carry an `a3s.oci.attachments.v4` binding for
one exact guest-session incarnation. This is durable identity and authority
evidence, not a claim that the currently registered utility-VM driver provides
pooling; capability negotiation still rejects v4 until that driver advertises
the schema.

The caller requests an isolation class. The runtime selects one launch-ready
owner for that class, persists the selected driver, and routes every later
operation back to that exact owner—even after the service reopens with drivers
registered in a different order. It never reroutes historical state or falls
back from a VM boundary to the host kernel.

### The SDK is the execution boundary

```rust,no_run
use a3s_oci_runtime::HostRuntimeService;
use a3s_oci_sdk::RuntimeClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> a3s_oci_sdk::Result<()> {
    let client = RuntimeClient::new(HostRuntimeService::new());
    let info = client.features().await?;

    println!(
        "host={:?} arch={}",
        info.drivers.platform,
        info.drivers.architecture
    );
    for capability in &info.drivers.drivers {
        println!(
            "{:?}: host={:?}, readiness={:?}, launch={}",
            capability.driver,
            capability.status,
            capability.readiness,
            capability.can_launch()
        );
    }
    println!("operations={:?}", info.operations);
    Ok(())
}
```

`RuntimeClient` can wrap an in-process service or connect over bounded local
IPC. A broken local stream is reported without hidden replay; the next explicit
request reconnects and renegotiates so the caller can retry or reconcile with
the original operation identity. Foreground `run` is only a client composition
of durable create/start/wait/delete calls; it does not create a second
lifecycle API or state machine.

On Linux, the explicit experimental host owner publishes one durable SDK
endpoint without opening KVM:

```bash
a3s-oci native-linux-host-service \
  --root /run/a3s/oci-native \
  --agent /usr/libexec/a3s-oci-agent
```

The owner opens the Native Linux driver and durable state before publishing
`runtime.sock`, serves independently fenced container generations to
authenticated same-UID clients, and reaps driver-owned processes on graceful
shutdown. Box's explicit `A3S_BOX_OCI_MIGRATION=sandbox` production route uses
this owner. The existing `native-linux-service` command remains the
Sandbox-scoped FD 3/4/5 owner for compatibility and focused qualification.

On Apple Silicon, the public HVF owner exposes the same SDK contract while
keeping durable state separate from per-generation VM state:

```bash
a3s-oci macos-hvf-host-service \
  --root "$HOME/Library/Application Support/A3S/oci-hvf" \
  --shim /absolute/path/to/a3s-oci-krun-shim \
  --system-image-manifest /absolute/path/to/system-image.json
```

It prepares an owner-only `0700` root, publishes a same-UID `0600`
`runtime.sock`, accepts concurrent clients, and removes only the socket inode
it created. The service advertises all 20 HVF driver operations plus
`features`, `list`, and `events`, requires the runtime bundle-handoff
extension, and reaps every live dedicated VM on graceful shutdown. The HVF
driver advertises only `DedicatedVm`; shared-guest pooling is not implemented.

The runtime contract suite also restarts the owner across two distinct OS
processes on the same Unix socket or Windows named pipe. The replacement opens
the same durable `HostRuntimeService` state, while one retained client recovers
the exact generation and a live exec target, replays create/start/exec without
duplicate test-driver dispatch, and continues inventory, stdin, signal, wait,
output, and cleanup. This proves the generic process and transport boundary,
not native Linux or utility-VM reattachment on real hardware.

The real Native Linux gate now crosses that process boundary with the actual
driver. The launcher is parent-death-bound before it forks namespace children;
after an owner `SIGKILL`, a replacement process revalidates the immutable
configuration plus owner/launcher/init start-time identities, waits for the
exact workload to disappear, and exposes a stopped cleanup tombstone. It never
claims that a live stream was reattached or fabricates an exit code when no
authenticated parent survived to reap it. Idempotent kill, empty inventory,
explicit missing-exit evidence, stopped-only delete, and executor/cgroup
cleanup are machine-checked on x86_64 and aarch64. Live process-session
reattachment remains open for the Box B2 cutover.

## Platform status

| Host path | Retained real evidence | Current readiness and open gate |
| --- | --- | --- |
| Native Linux x86_64/aarch64 | Rootful and helper-backed rootless lifecycle, including all six OCI default devices, `/dev/ptmx`, configured-init `/dev/console`, an explicit FIFO outside `/dev`, the immutable declared/default device boundary, and the bounded A3S Box device policy; SDK service transport; exec/PTY/I/O; init/exec scheduler and namespaced-sysctl read-back; cgroup update/stats; hooks; namespace and mount profiles; multi-container fencing; fault cleanup; owner-`SIGKILL` safe termination and stopped cleanup; exact `startContainer` Hook owner-death process-group cleanup and replacement recovery; 25 waves × 4 containers; x86_64/aarch64 Box production-owner composition through all four SDKs plus fresh-Box-process owner-death/restart gates | Default inventory `probe-only`; explicitly opened development driver `experimental`. Live session reattachment, default cutover, production security, and OCI conformance remain |
| Linux KVM utility VM | Independent device/access/ioctl/API-version probes; deterministic x86_64 and AArch64 runtime archives and immutable ext4 roots; exact libkrun, firmware, exported kernel, and static Guest Agent compatibility sets; descriptor-pinned read-only root attachment; isolated create/configure/root/plain-vsock/release context gates; an isolated real-entry worker with descriptor-pinned KVM and runtime-share checks, pidfd owner death, kernel-authenticated Unix peer identity, protocol-v10 negotiation, and fail-closed cleanup evidence when KVM is unavailable. Both architecture lanes retain the 14-case pre-entry compatibility-drift matrix and invoke a KVM-gated 17-case lifecycle matrix. Its versioned ten-case Guest path-isolation entry checks traversal, symbolic-link, and magic-link escapes; focused regressions also swap bundle, rootfs, and bind-source entries after descriptor validation. The lanes also invoke a scoped owner-death/restart gate and a scoped 25-wave fresh-generation soak. A KVM-independent driver preflight rejects both shared-kernel classes, inexact generations, missing handoff ownership, and missing, linked, non-private, drifted, escaping-rootfs, or absolute-bind handoffs before creating a Guest-visible generation share. The soak audits generation fencing and replay plus per-wave process, marker, endpoint, descriptor, bundle-handoff, runtime-share, recovery-report, and configured Guest `cgroupsPath` lifetime. The public candidate owns one VM per exact generation, rejects host-kernel fallback, keeps bootstrap and writable shares separate, and remains non-registerable | `probe-only`; neither architecture has yet retained `available` lifecycle, recovery, and soak reports from real KVM hardware. Fresh-host reports for x86_64 and AArch64 must retain the integrated Guest-isolation entry; other real-entry negative-isolation profiles remain separate promotion evidence |
| macOS arm64/HVF | Public same-UID SDK host service; one dedicated VM per exact generation; manifest-bound immutable ext4 system image with pinned A3S Linux kernel and agent; read-only root disk plus separate writable runtime share; Guest-local devtmpfs sources for privileged OCI device nodes; a real protocol-v10 bridge with all 21 Guest operations; retained full protocol-v9 lifecycle, multi-container, namespace/rootfs enforcement, 3 no-delete cleanup points, 11 transport fault points, 180/180 workload-operation replacement paths, negative asset/authentication gates, and 25 fresh-VM waves; source revision `a5a6b53` passed the revision-bound public-path gate across all 20 driver operations plus `features`/`list`/`events`, Host Service `SIGKILL` recovery, and a separate 25/25 fresh-VM soak with zero transient leaks | `experimental` on Apple Silicon. Every currently advertised public macOS/HVF function is implemented and the protocol-v10 public path is qualified at the recorded revision. The versioned ten-case Guest path-isolation profile is implementation-complete and CI-wired; its first `available` artifact at the updated revision remains pending. Signed release-package qualification, OCI conformance, security review, upgrade/rollback compatibility, and longer release soak remain before `supported` |
| Windows x86_64/WHPX | Real partition/context/guest gates, protocol-v9 lifecycle and filesystem sessions, direct driver qualification, protected per-generation shares, exact exit replay, owner death at both recovery fault boundaries, host-service reopen, stopped-only delete, and complete transient cleanup. The current implementation also builds a reproducible x86_64 ext4 system image, pins Linux 6.12.91 and all native boot assets, attaches the root read-only, and keeps the runtime share separate | `probe-only`; the complete SDK/recovery matrix must still pass with those exact assets on a fresh WHPX host. The v7 shim and Host retain the v6 in-process handle-restoration contract, but the complete fresh-host matrix has not retained that evidence yet |

All retained Linux KVM entry, compatibility, lifecycle, recovery, and soak
artifacts carry the shared provenance contract described below. This closes
artifact identity ambiguity; it does not substitute unavailable-runner output
for successful real-KVM evidence.

Linux discovery and Native Linux development must work when `/dev/kvm` is
missing or unusable. KVM is an optional utility-VM driver, never a prerequisite
for host-kernel execution.

On August 15, 2026, a focused Apple Silicon rerun passed all 14 journaled
`guest-after-response-write` mutation cases with post-commit Guest
acknowledgement. File and Filesystem also passed their complete nine-stage
reopen and real owner-replacement matrices, 18/18 paths in total. The run used
agent SHA-256
`eea01813858f5dd16bed70cbfba87221da6daebb4201b7a628665aad3f615a7d`
and system-image SHA-256
`e888c52e35ba8ed8f747d55bdc32316190dc317865e6919014e434a1e644e6ef`.

The latest WHPX owner-death gate emitted
`a3s.oci.whpx-recovery-smoke-run.v1` from clean runtime commit `2d91cd0`.
That closes the service-restart evidence item. The immutable-image code and
qualification artifact are now present, but they have not yet produced the
fresh-host matrix required to promote the public candidate. The current shim
also records its Windows handle inventory immediately before libkrun context
creation and after VM exit; Host validation and the hardware soak reject any
drift. This remains implementation evidence until the fresh-host matrix
retains matching counts in every session.

## Architecture

```text
A3S Box (current Sandbox consumer; explicit Native Linux production route
         owns bundle/resource preparation and uses the long-lived SDK owner;
         default, MicroVM, and cross-platform cutover remain open)
a3s-oci CLI
containerd runtime-v2 shim
                         │
                         ▼
                  RuntimeClient
             in-process or bounded local IPC
                         │
                         ▼
              ┌──────────────────────┐
              │ HostRuntimeService   │
              │ validation           │
              │ generations + replay │
              │ recovery + quarantine│
              └──────────┬───────────┘
                         ▼
                 DriverRegistry
             isolation owner selected once
                 ┌───────┴────────┐
                 │                │
       NativeLinuxDriver     utility-VM driver
          host kernel        KVM · HVF · WHPX
                 │                │
                 │        isolated libkrun shim
                 │                │
                 │        authenticated guest agent
                 └───────┬────────┘
                         ▼
                   LinuxExecutor
          namespaces · mounts · hooks · pidfds
          cgroups · process I/O · confined filesystem · exact cleanup
```

Only the isolated `a3s-oci-krun-shim` loads checksum-pinned native libkrun
assets. The SDK, CLI discovery path, durable host service, and Native Linux
driver do not initialize a hypervisor library.

On Linux x86_64 and AArch64, `a3s-oci-krun-shim context-smoke` verifies and
loads the selected native bundle, checks the firmware-exported kernel, and
creates, configures, and releases one libkrun context. That command does not
open `/dev/kvm`, enter a VM, or change the KVM driver's `probe-only` readiness.
The stronger pre-entry gate also binds the exact static agent and immutable
root disk from the same target manifest:

```bash
a3s-oci-krun-shim system-image-context-smoke \
  --system-image-manifest /absolute/path/to/system-image.json
```

It pins the manifest and raw image with read-only descriptors, rechecks every
byte immediately before native API use, attaches the root read-only, and then
releases the context. It still does not enter KVM or claim guest execution.

The public Linux API exposes `KvmRuntimeDriver::open_candidate` with a
`KvmRuntimeDriverConfig` containing the isolated shim, writable runtime root,
and immutable system-image manifest. It prepares an empty private bootstrap
root separately from exact-generation runtime shares, delegates all 20
workload operations and six OCI hook phases through the shared utility-VM
core, and disables Native Linux fallback. Its capability deliberately remains
`probe-only`, so `HostRuntimeService` rejects normal registration until the
real-host promotion gates below pass.

The separate authenticated entry gate adds a UID-owned mode-`0700` generation
share, a same-UID Unix endpoint, a pidfd-bound shim owner, and a direct isolated
VM worker. The worker revalidates every non-KVM entry asset before it opens
`/dev/kvm`, then repeats the complete compatibility and device checks after
pinning the device and requiring API version 12. It enters only through the
immutable system root. The Host accepts only the kernel-reported direct worker
child before protocol-v10 token negotiation:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-agent-entry.sh
```

The separate compatibility matrix stops at the configured worker boundary and
does not require KVM:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-compatibility-drift.sh
```

Its 14 cases cover manifest and raw-image replacement, same-size content
mutation, and symlinks; architecture and runtime-target mismatches; Guest Agent
version and digest drift; and runtime archive, libkrun, firmware, and exported
kernel provenance drift. Every case must fail with no KVM-device access or VM
entry and restore endpoint, shim-process, token-handoff, and runtime-share
inventories. The machine-readable result uses
`a3s.oci.linux-kvm-compatibility-drift.v2`.

On a host without usable KVM the authenticated entry command must fail after
non-KVM setup, retain nested KVM evidence, and restore endpoint, process, and
handoff inventories. When KVM is usable, the gate first requires a real
authenticated boot and then runs a hidden qualification-only failure after
`/dev/kvm` and API
version 12 are verified but before libkrun enters the VM. Shim schema v7 records
that exact boundary and the script rejects any endpoint, process, token, or
runtime-share residue. This implementation does not promote the driver:
successful real-entry evidence on both x86_64 and AArch64 plus the
complete lifecycle, recovery, and soak matrices remain required.

The script retains normal entry in
`a3s.oci.linux-kvm-agent-entry.v1` and the injected boundary in
`a3s.oci.linux-kvm-post-probe-failure.v1`. Both wrap the raw v10/v7 Host and
shim reports with `a3s.oci.linux-kvm-provenance.v1`. The common object requires
a clean checkout, binds the Git object format, actual checkout commit and tree,
Linux platform and target architecture, and hashes the CLI, shim, runtime-assets
manifest, selected runtime files, and system-image manifest. It also records
the exact build profile, qualification profile, `libkrun-kvm` driver, and
`dedicated-vm` isolation class. The other KVM gates reuse the same contract, so
an otherwise green report from different source or runtime bytes cannot satisfy
a promotion gate.

The KVM-gated lifecycle entry reuses the same Utility VM implementation as the
Apple Silicon qualification instead of maintaining a second Linux-only test
harness:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-lifecycle.sh
```

The separate owner-death/restart entry exercises that candidate through an
explicitly scoped Unix Host Service without making it normally registerable:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-recovery.sh
```

The bounded soak uses its own qualification scope and one durable Host Service:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-soak.sh
```

When KVM is available, the lifecycle entry downloads the pinned Alpine fixture,
prepares two bundles under a private runtime share, and runs 17 cases: one full
lifecycle, one multi-container lifecycle, one versioned Guest-isolation entry,
three no-delete cleanup boundaries, and all 11 transport fault points. The
Guest-isolation entry contains ten ordered hostile-path cases for bundle,
rootfs, bind-source, File, and Filesystem boundaries. It requires typed
`permission-denied` errors from the exact owning operation, unchanged canaries,
absent container state, and complete fixture/runtime cleanup. The
`a3s.oci.linux-kvm-lifecycle-matrix.v2` report
retains every nested runtime report plus endpoint, process, runtime-state,
bootstrap, token/recovery, and marker cleanup checks. Without usable KVM it
skips the fixture download and emits `status: unavailable` with zero cases.
That keeps CI honest about runner capability; it does not count as a hardware
pass. The `a3s.oci.linux-kvm-recovery-matrix.v2` entry likewise skips Alpine
when KVM is unavailable. With KVM it kills the live Host Service, requires
authenticated SIGKILL recovery,
opens a distinct replacement socket owner, replays exact stopped state and
Wait, and proves stopped-only Delete plus transient cleanup. The soak also
skips Alpine on an unavailable host; its retained aggregate schema is
`a3s.oci.linux-kvm-soak-matrix.v2`. On KVM it runs 25 fresh generations and
requires every process, descriptor, endpoint, handoff, share, recovery record,
and Guest marker to return to baseline after each wave. Available lifecycle,
recovery, and soak reports, including the integrated Guest-isolation entry, are
still required from fresh x86_64 and AArch64 KVM hosts. Other real-entry
negative-isolation profiles remain separate promotion evidence.

| Owner | Keeps | Must not absorb |
| --- | --- | --- |
| A3S Box product plane | Desired state, images/builds, named volumes, product networks, Compose, health/restart policy, log retention, and secret authorization | Actual PID/VM identity or runtime operation journals |
| OCI Runtime control plane | Exact OCI validation, actual state, generations, replay, exit status, driver selection, recovery, and cleanup | Registry pulls, image builds, Compose, or silent isolation fallback |
| Platform execution plane | Linux enforcement, utility VM, transport, process control, and runtime attachments | Product orchestration or a second durable lifecycle |

## Run the real gates

The portable workspace gate is:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
```

Full Runtime tags produced by the current release workflow include signed SLSA
build provenance for all five archives and `SHA256SUMS`, plus a portable
Sigstore bundle. Follow
[Release verification](docs/release-verification.md) to enforce the repository,
workflow, tag, and digest identity. Successful verification does not promote
the selected driver's advertised readiness or replace its real-host gates.

Real execution gates require a prepared host and isolated runtime root.

| Host | Entry point | Guide |
| --- | --- | --- |
| Linux x86_64/aarch64 | `bash .github/scripts/native-linux-smoke.sh` and `bash .github/scripts/linux-kvm-lifecycle.sh` with the pinned KVM manifest | [Native Linux development](docs/linux-native.md) |
| Apple Silicon | `cargo run -p a3s-oci-cli -- hvf-smoke` followed by the signed utility-VM profiles | [macOS HVF development](docs/macos-hvf.md) |
| Windows x86_64 | `scripts/windows-whpx-driver-smoke.ps1` and `scripts/windows-whpx-recovery-smoke.ps1` with a verified container-rootfs archive and `windows-system-image` manifest | [Windows WHPX development](docs/windows-whpx.md) |

The Linux smoke prepares an explicit user-owned cgroup-v2 subtree for the
rootless v4 gate. Before Tokio starts, the CLI retains that exact delegation,
starts a parent-bound effective-root helper, and permanently drops the runtime
owner to its real identity. Ordinary rootless launch uses the helper to provide
the six OCI default device nodes and install the same immutable inventory
boundary as rootful execution; it does not invent a `linux.resources.devices`
policy. The separate A3S Box profile also exercises bounded device-access BPF
replacement and rollback. Runtime commit `bed43d2`
passed the full policy profile on x86_64 and aarch64 in CI run `31714178349`.
The v4 gates verify create, live update/stats, workload-proven pause/resume,
durable events, all six nodes, exact policy updates where requested, and
complete cgroup, runtime, session, and marker cleanup. Broader delegated
profiles remain unadvertised promotion work.

The rootful device-boundary profile intentionally omits `linux.cgroupsPath`,
grants `CAP_MKNOD`, and proves that only declared/default identities remain
usable. It also remounts a `nodev` bind source with `dev` inside the workload
and verifies that the late device access still fails with `EPERM`. Run the
focused gate with
`A3S_OCI_NATIVE_FOCUS=device-boundary bash .github/scripts/native-linux-smoke.sh`.

Writable OCI cgroup mounts now follow the OCI 1.3 delegation boundary. The
executor changes ownership only for an exact `source: "cgroup"` mount at
`/sys/fs/cgroup`, with no `ro` option and a newly created cgroup namespace. It
maps `process.user.uid` to the host UID, preserves the group, and changes only
the container cgroup directory plus existing files listed by
`/sys/kernel/cgroup/delegate`; if that inventory is absent, it uses the three
normative fallback files. The focused Native Linux gate also proves that a
read-only cgroup mount and unlisted controller files keep their ownership:
`A3S_OCI_NATIVE_FOCUS=cgroup-ownership bash .github/scripts/native-linux-smoke.sh`.

The rootful terminal-init profile derives init I/O from `process.terminal`,
applies the configured 120x40 size before launch, and binds the exact PTY slave
to `/dev/console`. It also creates a configured FIFO outside `/dev` with mapped
mode and ownership. The gate runs once with a new console target and once with
a caller-owned placeholder; Delete removes only runtime-created targets and
restores the pre-existing file unchanged.

When a container creates a private mount namespace but joins an existing user
namespace, the executor pins and type-checks that namespace, observes its real
UID/GID maps through a short-lived namespace helper, and rechecks the namespace
identity before entry. The same detached-mount path then supplies the six
default devices with namespace-root ownership. Native Linux multi-container
v20 and real Apple Silicon utility-VM multi-container v11 both verify the
device type, major/minor number, mode, ownership, workload access, and cleanup.
The same reports cover the image's `/dev` with a fresh tmpfs and require the
four OCI Linux links to resolve to their exact `/proc/self/fd` targets after
every configured mount is in place.

Mount-option discovery and execution now share the SDK's pinned 61-entry OCI
1.3 registry. The executor consumes all required and recommended control
options without leaking them into filesystem data, treats unknown strings as
filesystem-specific data, and returns a typed `Unsupported` error for the
optional `tmpcopyup` behavior. Feature discovery reports the 60 implemented
OCI names plus the `rnodev` extension, in sorted order, and does not advertise
`tmpcopyup`.

All remaining OCI Linux capability reporting follows the same rule. Each
`RuntimeDriver` supplies one validated `OciLinuxSupport` value when the Host
Service opens. The registry freezes that value, rejects a multi-driver set if
any profile differs, and builds `Features` from it. Create, Exec, and Update
check the same value before durable mutation; the Linux Agent reuses the shared
profile at init, process, and cgroup planning. AppArmor, SELinux, mount labels,
unadvertised Seccomp controls, and cgroup-v1-only resources therefore cannot be
reported one way and admitted another.

Configured host services also report every built-in annotation that can alter
runtime behavior, together with annotation-backed extensions implemented by
their active drivers. Probe-only discovery stays empty, and driver-specific
extensions such as bundle handoff appear only when the selected driver set
actually advertises them.

`RuntimeInfo::extensions` is the versioned `a3s.oci.extensions.v1` source of
truth for selecting that driver-specific surface. It binds the catalog to the
running Host executable's SHA-256 and publishes canonical operation-contract
and attachment versions for each launch-ready driver and its unique isolation
classes. `RuntimeNegotiationRequest` selects by typed `IsolationClass` and
fails before workload preparation if any requested version is absent. The
legacy flat `operations` and `attachments` fields expose only the intersection
safe for every registered driver; a response from an older peer defaults to an
empty catalog and cannot silently satisfy negotiation.

`a3s.oci.attachments.v2` binds already-authorized storage to an exact OCI
mount, immutable caller-issued allocation identity, matching read-only or
read-write access, caller ownership, and detach-only cleanup. The runtime never
resolves a named volume or snapshot and never deletes the caller-owned backing
resource. Storage create requires SDK protocol 5, while v1 create manifests
retain protocol-3 compatibility. Every restore requires the immutable
protocol-8 checkpoint reference described below.

`a3s.oci.attachments.v3` binds an already-authorized Linux interface to an
exact OCI network namespace and `linux.netDevices` entry, together with
immutable namespace, interface, and cleanup identities. Runtime-created
namespaces are released with the container; joined caller namespaces are
preserved. IPAM, DNS, routes, aliases, policy, and backing-network cleanup stay
in A3S Box. Network create requires SDK protocol 6; restore requires protocol
8. Rootful Native Linux advertises cumulative v1-v3; rootless Native stays
v1-v2 because it has no host network-device authority. Dedicated Linux KVM now
has internal, fail-closed v2/v3 transports. Caller-owned non-bind `ext4` raw
images remain
outside the runtime share and are descriptor-pinned into read-only or
read-write virtio-blk devices; the Guest matches their libkrun serial, size,
and read-only state before rewriting only the authorized OCI mount source. An
exact-generation private manifest also binds authorized network JSON pointers
and attachment evidence to deterministic Guest MACs; the Guest renames only
uniquely matching VMM NICs. Joined caller namespaces and reusable Guest
sessions are rejected. KVM nevertheless continues to advertise v1 until its
cumulative v2/v3 destructive real-host restart, cleanup, replay, and soak
qualification passes. HVF remains v1 until it gains equivalent independent
transports and evidence.

`dev.a3s.network.enforcement@1` is an independently negotiated required
extension over v3. It binds one opaque caller-compiled enforcement incarnation
and optional opaque local-redirect incarnation to the exact joined,
caller-owned namespace, using only positive generations and lowercase SHA-256
digests. Runtime neither receives policy contents nor gains mechanism cleanup
authority. The exact decoded binding is retained in
`ContainerRecord::network_enforcement` and checked against the durable manifest
and configuration snapshot after reopen. The SDK/Host contract is implemented;
production drivers continue to omit this capability pending driver-specific
real-host qualification.

`a3s.oci.attachments.v4` binds a SharedGuestKernel request to one reusable
guest-session ID and positive incarnation, the request's immutable trust
domain, a capacity bounded at 64 members, runtime ownership, and an explicit
empty-session reset mode. Create requires SDK protocol 7, while restore
requires protocol 8. The exact binding is retained in `ContainerRecord` and
revalidated against the durable manifest after reopen. The common HVF/KVM
implementation enforces admission, capacity, reset, generation rotation,
member cleanup, and shared-owner reclamation, but no production utility-VM
driver advertises v4 until its prerequisite storage/network transport and
real-host restart/leak qualification pass. See the
[attachment contract](docs/attachment-contracts.md) for the fail-closed
composition rules.

SDK protocol 8 freezes `a3s.oci.checkpoint-reference.v1`: one exact paused
source generation, configuration and attachment digests, driver/isolation,
platform and architecture, Host executable and driver-build evidence,
driver-defined format, and exact artifact digest and size. Checkpoint accepts
only an already-paused running generation and leaves it paused; restore returns
a new paused running generation and requires an explicit later `resume`.
Artifact storage, lineage, retention, and object policy remain caller-owned.
The Host now owns durable checkpoint and restore orchestration. Checkpoint
fences the exact paused source and all process I/O. Restore first replays any
committed v5 or v6 outcome without reopening caller data; otherwise it
validates the immutable artifact and exact runtime/driver compatibility before
allocating a generation, dispatches an idempotent driver restore, and commits
a paused running record. Terminal restore failures quarantine only their allocated
generation so the ID can be reused monotonically. The registry accepts
`Checkpoint` only from an explicitly advertising current-platform driver and
accepts `Restore` only together with `Checkpoint`. No production driver
advertises either operation yet; atomic driver execution and real-host
qualification remain required. See the [immutable checkpoint
contract](docs/checkpoint-contract.md).

The containerd runtime-v2 shim now exposes this optional contract without
making it part of the endpoint's 18-operation base admission set. A paused
Task Checkpoint writes `a3s-oci-checkpoint-v1.bin` plus an atomically committed
`a3s-oci-checkpoint-v1.json` reference manifest into containerd's requested
directory. Create with that directory validates the immutable package and
calls SDK Restore. Although SDK restore returns a paused running generation,
the shim reports CREATED until the first Start performs one replay-stable
Resume; schema-v10 metadata and schema-v2 create intents recover both sides of
that barrier after a shim crash. Unsupported selected drivers return
Unimplemented only for the optional request. Incremental checkpoints and
non-neutral runc checkpoint options remain rejected.

SDK protocol 9 adds the policy-neutral TEE mechanism boundary. A dedicated-VM
create or restore may require exactly one `dev.a3s.tee.amd-sev-snp@1` or
`dev.a3s.tee.intel-tdx@1` launch extension in explicit `hardware` or
`simulated` mode. The separate durable `attest` operation carries an exact
64-byte report-data binding and returns bounded opaque provider evidence plus
the launch measurement, configuration and attachment digests, driver and
driver-build identity, and exact Host artifact. Runtime validates and replays
those bindings but does not verify provider claims or make authorization
decisions; Box or Cloud owns appraisal and policy. A driver may advertise
`Attest` only together with at least one exact TEE extension and dedicated-VM
isolation. No production driver advertises either TEE extension or `Attest`
until hardware execution, evidence collection, restart, upgrade, and
destructive real-host qualification pass. See the [TEE launch and attestation
contract](docs/tee-attestation-contract.md).

These commands can require root privileges, hypervisor access, signed
artifacts, or destructive cleanup within an explicitly supplied test root.
Read the linked host guide before running them.

## Evidence, not slogans

The repository turns release claims into checked inventories:

| Evidence | Current lock |
| --- | ---: |
| Named OCI schema properties and enum values classified | 423 |
| OCI schema dispositions | 257 enforced · 2 validated · 75 rejected unsupported · 89 rejected inapplicable · 0 pending · 0 conformant |
| Reviewed schema evidence | 334 applicable items in 31 bindings · 132 rules · 103 tests |
| OCI Linux configuration and Features profile | 190 / 190 schema items: 145 enforced · 45 rejected unsupported; 218 / 218 `config-linux.md`: 206 enforced · 9 validated · 3 conformant; 41 / 41 `features-linux.md` enforced |
| OCI VM configuration profile | 26 / 26 schema items · 24 / 24 normative requirements · 4 validated absolute paths · 20 fail-closed runtime-owned controls |
| Pinned OCI JSON Schema suites | 19 / 19 upstream fixtures · 4 / 4 launch profiles with configuration, Features, and created/running/stopped State documents |
| RFC 2119 occurrences across 15 pinned normative OCI 1.3 documents | 764 |
| Typed semantic validation rules | 95 |
| Owner-bound non-semantic rules | 156 |
| OCI normative dispositions | 578 enforced · 51 validated · 12 conformant · 14 reviewed external · 0 pending review |
| Registered durable commit fault stages | 877 |
| Durable-state replacement qualification | macOS/Linux/Windows complete, including a real Linux bind mount and the Windows reparse-point matrix |
| Live containerd terminal init-Kill rehydration | 3 / 3 consecutive same-Host Ubuntu arm64/containerd 2.2.2 matrices on August 24, 2026 |
| Live containerd `DeleteProcess` response replay | 3 / 3 consecutive same-Host Ubuntu arm64/containerd 2.2.2 matrices on August 24, 2026 |
| Live containerd task Delete response replay | 3 / 3 consecutive same-Host Ubuntu x86_64/containerd 2.2.3 matrices on August 24, 2026 |
| Post-commit containerd `WriteStdin` forced cleanup | 3 / 3 consecutive same-Host Ubuntu x86_64/containerd 2.2.3 matrices on August 24, 2026 |
| Post-commit containerd `CloseStdin` forced cleanup | 3 / 3 consecutive same-Host Ubuntu x86_64/containerd 2.2.3 matrices on August 24, 2026 |
| Post-commit containerd `ResizePty` forced cleanup | 3 / 3 consecutive same-Host Ubuntu 24.04.3 LTS/WSL2 x86_64 observations on August 28, 2026 |
| Before/after `RuntimeDriver` fault boundaries | 52 |
| Authenticated agent operation-stage fault pairs | 180 |
| Portable Create/State/Start/Kill/Delete/Wait/Exec/SignalProcess/WaitProcess/Pause/Resume/Processes/Update/Stats/ReadOutput/WriteStdin/CloseStdin/Resize/File/Filesystem host-service reopen pairs | 180 |
| Real HVF Create Host/Guest plus Host shutdown interruption and cleanup stages | 11 |
| Real HVF durable Create reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable State reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Start reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Kill reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Delete reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Wait reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Exec reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable SignalProcess reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable WaitProcess reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Pause reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Resume reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Processes reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Update reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Stats reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable ReadOutput reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable WriteStdin reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable CloseStdin reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Resize reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable File reopen plus VM/session-owner replacement paths | 9 |
| Real HVF durable Filesystem reopen plus VM/session-owner replacement paths | 9 |
| Real HVF operation replacement coverage | 180 / 180 paths (20 / 20 operations) |
| Real HVF journaled post-response acknowledgement rerun | 14 / 14 mutations on August 15, 2026 |
| Real HVF lifecycle/transport cleanup fault points | 14 / 14 |
| Real HVF immutable-system-image soak | 25 / 25 fresh VMs (75 primary generations) |
| macOS HVF R2M implementation gates | 15 / 15 |
| Public macOS HVF Host Service implementation | Complete; revision `a5a6b53` passed 23/23 operations, owner replacement, and 25/25 fresh VMs |
| Linux KVM owner-death/restart entry | Implemented for x86_64 and AArch64; fresh-host `available` evidence remains 0 / 2 architectures |
| Linux KVM bounded soak entry | Implemented at 25 fresh generations for x86_64 and AArch64; fresh-host `available` evidence remains 0 / 2 architectures |
| Guest operations behind protocol v10 | 21 (20 public workload operations + 1 maintenance acknowledgement) |

The locks prove inventory and exercised boundaries, not full conformance by
themselves. The OCI 1.3 normative inventory has no unclassified entries, but
upstream lifecycle suites, adversarial security, upgrade compatibility, and
exact release-artifact qualification must all pass before a driver becomes
`supported`.

### Still intentionally open

- real-kernel Intel RDT qualification on CAT/MBA-capable Linux hosts;
- real-host qualification of descriptor-confined filesystem sessions on each
  remaining utility-VM driver;
- production-ready Native Linux and utility-VM drivers;
- live Native Linux process-I/O reattachment across owner death and exact
  terminal evidence when a persistent authenticated reaper can retain it;
- fresh-host qualification of the implemented immutable WHPX system root, and
  real-entry qualification of the implemented KVM system root;
- utility-VM hook recovery and security certification;
- the default and cross-platform A3S Box cutover, plus the remaining
  containerd compatibility, packaging, and cross-driver gates;
- production checkpoint/restore driver execution and real-host qualification;
- production SEV-SNP/TDX launch and attestation drivers, hardware evidence
  qualification, and verifier-policy integration outside Runtime;
- exact published-package qualification, upgrade, rollback, security, and
  long-duration release gates.

## Workspace map

```text
crates/sdk/             public async OCI contract, bundle validation, local IPC
crates/core/            lifecycle, isolation, readiness, and capability types
crates/runtime/         durable host service, drivers, probes, state, reports
crates/agent-protocol/  authenticated host/guest wire contract
crates/agent/           static Linux guest agent and shared LinuxExecutor
crates/krun/            isolated shim plus pinned native runtime bundles
crates/cli/             capability inspection and real-host qualification gates
```

## Documentation

- [Roadmap and release gates](ROADMAP.md)
- [Release verification](docs/release-verification.md)
- [Durable lifecycle and recovery](docs/durable-state.md)
- [SDK transport](docs/sdk-transport.md)
- [Immutable checkpoint and restore contract](docs/checkpoint-contract.md)
- [TEE launch and attestation contract](docs/tee-attestation-contract.md)
- [Versioned attachment contracts](docs/attachment-contracts.md)
- [Guest-agent protocol](docs/agent-protocol.md)
- [OCI 1.3 conformance contract](docs/oci-conformance.md)
- [Normative coverage](docs/normative-coverage.md)
- [Semantic validation](docs/semantic-validation.md)
- [Native Linux development](docs/linux-native.md)
- [macOS HVF development](docs/macos-hvf.md)
- [Windows WHPX development](docs/windows-whpx.md)

## Development

Run checks from the repository root:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Cross-check the supported Linux compilation targets without treating a parent
monorepo as the Rust workspace:

```bash
cargo clippy --target x86_64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
cargo clippy --target aarch64-unknown-linux-gnu \
  --workspace --all-targets -- -D warnings
```

Tagged archives contain host diagnostics and the matching platform assets.
Linux x86_64 and arm64 archives carry statically linked musl CLI, agent, and
containerd shim executables whose release gate rejects ELF interpreters and
dynamic dependencies. Before either Linux directory is archived, its exact
CLI and Agent run the complete Native Linux SDK, rootless, owner-death,
Hook-recovery, fault-cleanup, and bounded-soak matrix with `/dev/kvm` removed.
The archive retains `qualification/native-linux-package.json` plus the seven
digest-bound subordinate reports. Package availability never overrides the
readiness reported by the exact binary's `features` result.

## License

A3S OCI Runtime is available under the [MIT License](LICENSE).
