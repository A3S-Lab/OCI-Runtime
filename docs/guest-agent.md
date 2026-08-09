# Guest Agent Bootstrap

`a3s-oci-agent` is the Linux process behind utility-VM execution. It shares
one versioned protocol with the Windows, Linux, and macOS host drivers and does
not link libkrun.

## Bootstrap Contract

The host must:

1. generate an `AgentVsockEndpoint` and `SessionToken` from the operating
   system random source;
2. bind the protected host transport before starting the VM;
3. provision the token through the protected
   `A3S_OCI_AGENT_SESSION_TOKEN` environment entry;
4. execute `/usr/bin/a3s-oci-agent` as the fixed guest process.

At startup the agent removes the environment entry, retains the encoded input
in zeroizing memory only while decoding it, and connects to host CID 2 port
4093 through Linux AF_VSOCK. Connection attempts and the complete retry window
are bounded. The accepted token is zeroized when its last Rust owner is
dropped.

On Windows, the host verifies that the connected named-pipe client is the
exact libkrun shim PID before it sends the token.

## Current Executor Boundary

The current bootstrap executor advertises `create`, `state`,
`start`, `kill`, `delete`, `wait`, `exec`, `signal-process`, and
`wait-process`, `pause`, `resume`, `processes`, `update`, `stats`,
`read-output`, `write-stdin`, `close-stdin`, and `resize`. It is intentionally narrower
than the final OCI executor and rejects every property it cannot enforce.

The accepted bootstrap profile requires:

- only `ociVersion`, `root`, `process`, optional `hostname`, optional
  `domainname`, optional `mounts`, optional `hooks`, optional `annotations`,
  and optional `linux` at the configuration root;
- a writable normalized relative `root.path` equal to `rootfs`;
- either `terminal: false` with null, piped, or inherited stdin, null,
  captured, or inherited stdout and stderr, and no terminal size; or
  `terminal: true` with terminal mode on all three streams and positive
  initial dimensions;
- `noNewPrivileges: true`;
- an absolute executable and working directory;
- numeric UID, GID, optional supplementary groups, and optional umask;
- bounded arguments and environment with unique environment names.

The opt-in portable rootfs-metadata extension is narrower than the general OCI
profile. Its exact `dev.a3s.oci.rootfs-metadata` annotation requires a relative
root, a new mount namespace, no user namespace, and the fixed
`.a3s-oci-rootfs-metadata.v1.json` manifest. The prepared init validates the
whole bounded manifest without following symlink parents, restores
guest-visible UID/GID and mode values, consumes the manifest durably, and only
then begins OCI rootfs and mount setup. Bundles without the extension are
unchanged.

When `linux.namespaces` is present, it accepts unique UTS, mount, IPC, network,
cgroup, PID, user, and time namespace entries in any order. Omitting `path`
creates a namespace; an absolute `path` joins an existing namespace; omitting
the entry inherits the runtime namespace of that type. Configured hostname and
domainname values are bounded to the Linux kernel limit and require a created
or joined UTS namespace.

New user namespaces require both `uidMappings` and `gidMappings`. Each list is
bounded to the kernel's 340-entry limit, and container ID 0 plus the process
UID, GID, and every supplementary GID must be covered. The wrapper creates the
user namespace first and blocks on the authenticated control channel while the
parent verifies that the target entered a distinct namespace.

When the executor runs as root, the parent writes each
`/proc/<pid>/{uid,gid}_map` directly, reads both maps back, and requires
`/proc/<pid>/setgroups` to remain `allow`. Native rootful qualification uses
the A3S Box mapping of container root to host UID 100000 and GID 200000.

When the native executor runs without host root, startup requires no active
supplementary groups, enabled unprivileged user namespaces, and fixed
root-owned, non-writable, executable, setuid-root `newuidmap` and `newgidmap`
helpers. The OCI maps must map container ID 0 exclusively to the effective
host UID/GID with size 1, must never map host ID 0, and must place later IDs in
the caller's `/etc/subuid` and `/etc/subgid` ranges. The parent runs
`newuidmap`, verifies `uid_map`, writes and verifies `setgroups=deny`, runs
`newgidmap`, and verifies `gid_map`. Rootless
`process.user.additionalGids` is rejected because the namespace cannot call
`setgroups` after that transition.

After creating the remaining namespaces and verifying any time offsets, the
wrapper switches all UID/GID slots to mapped namespace root before any rootfs
or mount mutation. Credential setup clears or applies supplementary groups
only when the namespace policy is `allow`; an empty group request under
`deny` is verified without issuing the forbidden syscall. Native x86_64 and
aarch64 qualification reads both rootless maps and `setgroups` from `/proc`,
proves a subordinate-owned host file appears as container ID 1, and exercises
create, start, exec, signal, wait, kill, delete, events, and cleanup.

Before any namespace transition, the wrapper opens every join target and
verifies its type with `NS_GET_NSTYPE`. It joins non-user namespaces, then the
user namespace, gains the target namespace's capabilities, and retries
non-user joins that initially lacked permission. After join and time-offset
setup it clears inherited supplementary groups and switches all UID/GID slots
to namespace root. A retained `/proc/self/ns` directory descriptor lets it
verify each resulting namespace identity even after a joined mount namespace
hides the original proc path.

The wrapper then requests newly created UTS, mount, IPC, network, cgroup, PID,
and time namespaces in one `unshare` call. Time offsets accept only normalized
`monotonic` and `boottime` values; the wrapper writes and reads them back
through `/proc/self/timens_offsets` before forking. A new PID or time namespace
applies to the caller's next child; joined PID and time namespaces have the
same next-child execution requirement. The wrapper therefore remains as a
launcher and forks a namespace child whenever either type is configured. For
a newly created PID namespace, that child remains as namespace PID 1, applies
all create-time setup, and then forks the configured container process as PID
2 or greater. Joined PID namespaces and time-only transitions keep the direct
launcher-to-process path because their namespace already has an init process.
The create-time child applies and reads back hostname and domainname with
`uname`. When a new mount namespace is requested, it makes `/` recursively
private, recursively bind-mounts the rootfs onto itself, applies every
configured mount in listed order, and uses
`pivot_root(".", ".")` followed by a detached unmount of the old root. All of
this succeeds before readiness is reported, so namespace, mount, and rootfs
isolation are part of the create barrier. When the mount namespace is inherited
or joined, the wrapper uses `fchdir` plus `chroot` through a rootfs directory
descriptor retained before namespace entry. Mount entries are rejected on
that path to prevent changes from escaping into a shared or donor mount
namespace.

The current mount slice:

- resolves each destination strictly inside the rootfs and creates a missing
  directory or file target according to the filesystem or bind-source type;
- interprets relative destinations from `/` and relative bind sources from the
  bundle directory;
- supports bind/rbind, common mount flags, all required propagation modes, and
  bounded filesystem-specific option data;
- remounts bind attributes explicitly and fails the complete create operation
  on any syscall error;
- applies recursive read-only, suid, device, execute, access-time, directory
  access-time, and symbolic-link-follow policies with `mount_setattr` against
  a descriptor-pinned destination;
- creates detached ID-mapped filesystem and bind mounts with `fsopen`,
  `fsmount`, `open_tree`, `mount_setattr`, and `move_mount`; paired per-mount
  mappings create a dedicated retained user namespace, while `idmap` or
  `ridmap` without per-mount mappings uses the newly created container user
  namespace;
- applies `idmap` only to the detached top-level mount and applies `ridmap`
  recursively, without changing the ownership of the original bind source;
- rejects target creation through an escaping symlink before mutation;
- supports private, shared, slave, and unbindable `rootfsPropagation`, masked
  files and directories, read-only paths, and a read-only rootfs when the
  container creates its own mount namespace;
- rejects root replacement, missing bind sources, multiple mount-entry
  propagation or ID-map modes, comma-packed options, `tmpcopyup`, and mount
  moves instead of silently ignoring them.

Create snapshots the exact digest-bound configuration, starts an internal
wrapper, and waits on a randomly named Linux abstract Unix socket. The parent
accepts only the exact kernel-reported launcher PID. The wrapper revalidates
the bundle, resolves a contained rootfs, and returns either a bounded typed
error or one of two readiness barriers. The first barrier is reached after the
container environment and mounts exist but before `pivot_root`; it carries the
runtime-visible configured-process PID and, for a new PID namespace, its
namespace-init PID. The authenticated parent permits exactly one expected
user-mapping request and rejects a bypass, repeat, or request without a
configured user namespace. Before releasing any runtime hook, it verifies the
complete launcher → namespace PID 1 → configured-process parent chain, the
init's `NSpid` mapping to 1, the configured process's mapping above 1, both PID
namespace links, and the requested user/time namespace identities.

At that first barrier the parent runs `prestart` and `createRuntime` in the
runtime namespace with `creating` OCI state. It then releases the wrapper to
run `createContainer` in the container namespace before pivoting. The wrapper
reports the same authenticated PIDs at the second barrier only after final
rootfs setup. A mismatch is rejected. Create therefore preserves the exact
rejection or returns `created` before the configured process runs. Before
returning `created`, the executor opens a pidfd for that exact PID—the PID
exposed through OCI state. Failure to open the descriptor terminates the
wrapper and fails create.

Start sends the one-byte release signal directly to the prepared process. The
wrapper enters the retained root when needed, runs `startContainer` with
`created` state, applies working directory, groups, GID, UID, umask,
capabilities, `PR_SET_NO_NEW_PRIVS`, and seccomp, and calls `execve`. Its
control descriptor is close-on-exec, so EOF confirms that the configured
program crossed `execve`; a pre-exec failure instead returns a bounded typed
error. The parent then runs `poststart` in the runtime namespace with
`running` state before start returns.

State observes the configured process, kill delivers one positive Linux signal
through its retained pidfd, and delete supports stopped-only and force cleanup.
Cleanup also signals through the pidfd and always reaps the authenticated
launcher before removing its runtime directory. After the container record,
retained namespaces/rootfs, cgroup leaf, and runtime directory are gone,
`poststop` receives `stopped` state without a PID. A failed poststop hook logs
a warning and does not prevent later hooks or successful cleanup. Session
shutdown uses the same ordering. Numeric PID reuse can therefore never
redirect a lifecycle signal to an unrelated process.

Namespace PID 1 continuously calls `waitpid(-1)` so exited descendants and
adopted orphans cannot remain as zombies. After the configured process exits,
PID 1 repeatedly sends `SIGKILL` to every remaining namespace process and
reaps until `ECHILD`. It then reports the configured process's exact normal or
signal outcome over a private channel. Only after namespace cleanup completes
does the outer launcher exit with the same code or reset, unblock, and
re-raise the same terminating signal. The executor converts that raw Linux
status into exactly one SDK exit code or signal, caches it per generation, and
returns it from every repeated wait. A bounded wait returns
`DeadlineExceeded` while the process is still running, and the executor
releases its registry lock between observations so another container remains
independently queryable.

Exec accepts one exact `(container ID, generation, process ID)` target while
the configured process is running. `init` is reserved, duplicate process IDs
fail, and exact mutation retries replay their original process or signal
result. Init and exec share the same fail-closed OCI process planner and I/O
owner. The current process-I/O slice accepts null, piped, or inherited stdin,
null, captured, or inherited stdout/stderr, or the exact all-terminal PTY
contract, while rejecting scheduler and other unenforced process settings.
Inherited descriptors remain owned by the runtime launcher and are
deliberately absent from SDK read/write operations. A separate Linux-only
native create attachment implements the fixed
A3S Box control contract: validated Unix stream listeners become FD 3 and FD 4
and a writable regular init log becomes FD 5. Raw handles never enter the
guest protocol; the native driver supplies a process-local descriptor plan
directly to `LinuxExecutor`. It retains and applies all 16 OCI
`process.rlimits` types to init and exec before credentials are reduced, with
duplicate, count, and soft/hard validation.

Piped stdin is written asynchronously with backpressure and can be closed
idempotently. Dedicated tasks continuously drain captured stdout and stderr so
the child cannot block on a full pipe. Both streams share one globally ordered
8 MiB retained buffer. Output polls use an inclusive byte cursor, may split a
buffered frame exactly at the requested byte bound, optionally long-poll, and
emit one empty EOF frame per captured stream. A cursor older than retained
data or ahead of produced output fails closed. Guest messages carry at most
4 MiB of process-I/O payload; the native host driver splits larger SDK stdin
writes at that boundary and derives a stable operation ID for each chunk.
Protocol-v8 write, close, and resize mutations retain their exact session-local
success or failure. Replaying a stdin write therefore cannot append its bytes
again, while changing the payload, target, size, or mutation kind under the
same operation ID fails closed.

Terminal execution adapts the A3S Box PTY design. `openpty` supplies one
runtime-owned master and child descriptors 0-2 use the slave. The launcher
creates a session and acquires the slave as its controlling terminal. The
configured payload then becomes the leader of its dedicated supervised
process group and moves that group into the foreground before untrusted code
runs. Terminal output is merged into the existing stdout cursor, `resize`
applies `TIOCSWINSZ`, and close-stdin delivers the active `VEOF` byte while
retaining the readable master.

Create retains descriptors for the configured process's root and every
configured namespace. A fresh single-threaded exec helper inherits only those
validated descriptors plus init's pidfd, authenticates its launcher, enters
retained user, cgroup, IPC, UTS, network, mount, PID, and time namespaces in a
fixed order, and forks for PID/time next-child semantics. The payload creates
its own process group, enters the retained root with `chroot`, applies cwd,
groups, GID, UID, umask, and `PR_SET_NO_NEW_PRIVS`, and blocks before `execve`.
The parent verifies the helper's kernel peer PID, the payload parent and
host-visible PID, an exact pidfd, root identity, every namespace identity, and
the continued liveness of init before releasing that barrier.

Every exec process has a retained pidfd and stable cached terminal result.
Per-process signal and wait are bound to the exact target; bounded wait returns
`DeadlineExceeded`, and repeated wait returns the same exit code or signal.
The helper monitors init's pidfd and terminates the complete exec process group
when init exits. It peeks natural exit with `waitid(WNOWAIT)` before killing
remaining group members, preserving the leader PID/PGID until cleanup is
issued—the same ownership mechanism proven by A3S Box's PID 1 reaper. Delete,
shutdown, and session EOF also force-stop and reap every registered exec
helper and process group before removing state.

A container-wide kill first authenticates every registered exec leader and the
configured leader through their retained pidfds, then delivers the requested
Linux signal to each owned process group, with init signaled last. Supervisors
keep exited leaders waitable with `waitid(WNOWAIT)` until descendant cleanup;
the direct launcher remains wait-owned by the executor. Numeric PID/PGID reuse
therefore cannot redirect the group signal: a cross-process advisory lease on
the private process directory serializes pidfd validation and group delivery
against final cleanup/reap. The path works without delegated cgroup v2 and
retains exact operation replay.

The executor creates one private controller-enabled cgroup-v2 root. The
default layout places init and exec in one owned leaf, which permits a later
update even when create supplied no initial limits.

A trusted in-container control plane can opt in to the versioned
`control-workload-v1` layout with these OCI annotations:

| Annotation | Meaning |
| --- | --- |
| `dev.a3s.oci.cgroup.layout=control-workload-v1` | Select the versioned two-child layout |
| `dev.a3s.oci.cgroup.control-memory-headroom-bytes` | Positive memory added only to the outer management envelope |
| `dev.a3s.oci.cgroup.control-cpu-headroom-micros` | Positive CPU quota added to the outer envelope for the configured period |
| `dev.a3s.oci.cgroup.control-pids-headroom` | Positive process capacity added only to the outer envelope |

This layout requires finite memory, CPU, and PID limits in
`linux.resources` plus a newly created cgroup namespace. The runtime creates
an outer management cgroup and fixed `a3s-control` and `a3s-workload`
children before spawning init. It starts the namespace root in the empty
outer cgroup and installs pre-opened `cgroup.procs` files at FD 6 and FD 7.
Init creates the cgroup namespace, moves itself into `a3s-control`, and reports
the create barrier; only then does the runtime delegate domain controllers and
apply the exact workload settings. This ordering keeps the management envelope
visible as the namespace root without violating cgroup v2's no-internal-process
rule.
The trusted configured init receives those descriptor numbers through
`A3S_CONTROL_CGROUP_PROCS_FD` and `A3S_WORKLOAD_CGROUP_PROCS_FD`; conflicting
environment variables or inherited descriptor targets fail create. The
container can therefore keep `/sys/fs/cgroup` read-only while its trusted init
moves control and workload processes through authority retained by the
runtime-opened files.

`linux.resources` remains the only exact workload source of truth. The
runtime applies it to `a3s-workload` with `memory.oom.group=0`, derives the
outer memory, CPU, and PID envelope from the declared headroom, and sends all
later OCI exec processes directly to the workload child. Live updates modify
the derived outer envelope and exact workload settings in one rollback-safe
transaction. Stats and freeze/thaw observe only the workload child, so memory
pressure cannot kill or freeze the trusted control transport. Cleanup removes
both children and the complete owned topology.

For either layout, update preserves omitted fields, applies supported memory,
CPU, cpuset, and PID changes with exact read-back, and rolls earlier writes
back in reverse order if a later write fails. Stats normalizes CPU counters to
nanoseconds, memory counters to bytes, and includes PID plus memory/PID event
counters. It also sums `io.stat` read and write bytes across every workload
block device into `io.read_bytes` and `io.write_bytes`; an unavailable I/O
controller leaves those optional metrics absent. Pause writes `1` to
`cgroup.freeze`, resume writes `0`, and neither operation returns until
`cgroup.events` reports the exact `frozen` state. The process inventory
refreshes the init and exec supervisors, excludes terminal processes, and
returns only positive PIDs bound to the exact container generation. Exec is
rejected while the workload target is frozen. Force cleanup thaws a paused
target before signaling and reaping its processes.

Exact request retries are fingerprinted by `OperationId`, and reused IDs with
different requests fail. This includes pause, resume, and resource update.
Generation fences remain in memory after delete.

All guest registry, generation, and idempotency state is session-local. The
host releases the shared transport immediately after a terminal request-write,
response-read, correlation, or response-shape failure, even when other client
clones remain. The resulting closed host connection force-stops remaining
configured processes, exec process groups and helpers, and namespace
supervisors, then removes the agent-owned runtime root. Agent restart recovery
is not implemented yet.

Qualification can now interrupt an exact negotiated-version boundary for any
of the twenty guest operations: four host request/response stages, five guest
read/dispatch/write stages, and two explicit host shutdown stages. Production
uses a no-op injector. An authenticated in-memory matrix injects every one of
the 180 operation-stage pairs, requires one exact crossing, and proves the
connection terminates after each fault. Separate evidence completes one create
dispatch, drops the response before it is written, authenticates a new
connection, and replays the identical `OperationId` and request without a
second effect; changed content under the same ID fails with `Conflict`. A
portable agent-backed `RuntimeDriver` matrix now carries all nine create,
state, start, kill, delete, wait, exec, signal-process, wait-process, pause,
resume, processes, update, stats, read-output, write-stdin, close-stdin, resize,
file, and filesystem stages through `HostRuntimeService` reopen: all 180
operation-stage pairs. Faults before guest dispatch leave a mutation resumable
and perform its first effect on the replacement connection.
Faults after dispatch replay the cached mutation response, including a guest
that reached `running` while the durable host still records `created`, reached
`stopped` while the durable host still records `running`, removed the generation
while the durable host still records `stopped`, or created an exec process while
the durable host still retains its prepared process claim, froze a running
guest while the durable host still records it as unpaused, or thawed it while
the host still records it as paused, or applied a resource update while its
durable host operation remained pending, delivered stdin, closed stdin, or
resized a terminal while the matching durable operation remained pending,
uploaded a file, or created a directory before its response was lost. Exec
replay preserves the exact process ID, PID, and terminal mode; signal-process
replay preserves the exact target and signal; pause and resume replay preserve
one exact freezer effect each; update replay preserves the complete resources
and one effect; write-stdin replay preserves the exact operation context,
process target, bytes, and one input effect; close-stdin replay preserves the
exact operation context and process target with one close effect; resize replay
preserves the exact terminal process target, operation context, dimensions, and
one resize effect; file replay preserves the path, user, payload, context,
acknowledgement, and one upload effect; filesystem replay preserves the path,
user, context, directory metadata, and one mkdir effect.
State, processes, stats, read-output, wait, and wait-process have no guest
mutation journal: state, exact live init/exec inventory, normalized counters,
and cursor-bounded output are safely reissued after every reopen, while both
wait forms are reissued only until the host durably caches the guest's stable
exact terminal result. A fully written wait response and every later retry
avoid a second driver or guest dispatch. All six observations resolve a current
host target to the exact generation and reject stale host and guest targets. A
fault after a durably journaled host mutation response write lets the completed
host journal answer the retry without a second driver dispatch; completed
delete also leaves no live record to send through driver recovery. File and
filesystem mutations are session-scoped and are dispatched again after every
reopen, including after a fully written response; the guest journals return the
same response without another mutation effect. Every case uses a newly
authenticated connection and driver and preserves the same generation;
mutations produce one effect and reject changed retries. This completes the
portable in-memory matrix, not the required real utility-VM replacement and
complete transition matrix.

A separate real-HVF diagnostic now crosses all nine Host/Guest `create` stages
and both explicit Host shutdown stages inside fresh authenticated protocol-v9
VMs. Each stage must fire once, avoid normal delete, keep the workload marker
absent, and leave no Guest runtime root, endpoint, shim, VM worker, or Host
descriptor drift. Guest qualification is bound to the exact `create`
`OperationId` and emits console evidence only after executor cleanup. The first
four Guest points fail the current call; the post-response point delivers that
response and fails a follow-up request. Each shutdown point first delivers
`create`, faults one retained-client close, and then completes idempotent owner
cleanup. Malformed protocol input, service errors, and cleanup errors remain
failures.

The durable replacement gate now covers all nine Host/Guest `create`
transitions. Eight interruptions close the first VM with the exact durable
record still in `creating`; the unchanged OperationId and generation complete
through a new `HostRuntimeService` and fresh authenticated Guest. At
`guest-after-response-write`, the first Guest finishes cleanup after delivering
the response. The replacement Guest rebuilds the pre-start container during
driver recovery, and the Host reconciles any new Guest PID into both the live
record and completed Create journal. Each Guest stage requires nonce-bound
cleanup evidence. Force delete then leaves no durable record or Guest runtime
state, while both VM reports prove different endpoint and process owners plus
complete Host descriptor restoration. This closes the Create replacement
matrix.

State now has the same nine-stage real-owner gate. Because State is a
context-free observation, its Guest qualifier uses the boot handoff nonce to
bind evidence and matches only the armed `state` operation and stage. The first
VM leaves the exact durable record in `created`; the replacement Guest rebuilds
that process with the original Create identity, and the reissued query must
match the recovered record. The post-response point additionally proves that
the first response arrived before a follow-up call observed the closed stream.
All 18 fresh VMs in the August 10, 2026 matrix returned Host and Guest resource
inventories to baseline.

The executor requires both `pidfd_open` and `pidfd_send_signal`. It currently
rejects mount entries and rootfs mutation in inherited or joined mount
namespaces, rootless supplementary groups and nondelegated cgroup paths,
unsupported cgroup I/O, hugetlb, RDMA, and unified resources, and every other
unimplemented OCI property. Rootless cgroup-v2 and device delegation, hook
rollback/recovery, security-negative, and soak certification remain release
blockers rather than silently accepted compatibility gaps.

## Build And Evidence

Build the static x86-64 Linux artifact from Windows with:

```powershell
cargo zigbuild -p a3s-oci-agent --release `
  --target x86_64-unknown-linux-musl
```

`a3s-oci agent-vm-smoke` proves the authenticated
guest-AF_VSOCK/libkrun/Windows-named-pipe path and verifies the exact
twenty-operation advertisement, including `file` and `filesystem`.
`a3s-oci oci-vm-smoke` additionally loads a
bundle below the VM rootfs and proves the distinct create/start barrier, state
observation, exact create/kill/delete replay, bounded running wait, exact
repeated init status, exact-target exec replay, duplicate process-ID rejection,
bounded and stable process wait, replayed process signal, exact live init/exec
inventory, replay-safe live resource update, normalized cgroup-v2 statistics,
replayed pause/resume, a progress-producing exec that stops while frozen and
advances after resume, exactly replayed piped stdin, bounded captured
stdout/stderr cursor pagination and EOF, idempotent stdin close, rejected late writes, controlling
PTY allocation, initial and resized dimensions, interactive input, merged
terminal output, VEOF close, init-exit exec cleanup, signal-driven stop,
post-delete NotFound, marker cleanup, and nominal guest runtime cleanup.

`a3s-oci oci-vm-multi-container-smoke` keeps two distinct bundle rootfs and
runtime slots live behind the create barrier, proves that A's start, kill,
wait, delete, recreation, stale generation, and replay conflicts do not alter
or block B, then completes B independently. The macOS HVF gate sends both
configured-process signals through distinct retained pidfds and retains both
exact repeated exit
statuses and per-container markers together with guest-runtime and
host-process cleanup evidence. Schema v9 then retains a prepared donor and
qualifies wrong-type rejection plus UTS, mount, IPC, network, cgroup, PID,
user, and time joins. Both joiner workloads must cross `exec`, remain running
for a bounded observation window, stop cleanly, and leave the donor unchanged.
A separate workload must create every missing directory and file mount
destination before start, then prove shared rootfs propagation, a distinct
read-only mount, empty read-only masked file and directory replacements,
recursive attributes on a bind mount and nested submount, read-only rootfs
enforcement, exact `idmap` and `ridmap` ownership on detached filesystem
mounts, normal exit, state removal, and removal of every host-side fixture
artifact. The same workload proves that it is PID 2+ beneath a dedicated
namespace PID 1 and that PID 1 reaps an adopted child. The native Linux
schema-v11 report additionally requires bind-source ownership preservation and
non-recursive versus recursive bind evidence.

`a3s-oci oci-vm-fault-cleanup` stops after create, start, or kill, explicitly
records that delete was not attempted, and requires guest executor shutdown to
remove the container process and runtime root. On macOS the nested report also
requires exact endpoint removal, both host PIDs to disappear, and the complete
descriptor inventory to return to its baseline.

The macOS path uses the same static agent, fixed fixture, protocol, and
lifecycle harness over the PID-verified Unix/vsock bridge. Only the host
endpoint and libkrun hypervisor backend differ.

The current native Linux and macOS lifecycle fixtures request all eight Linux
namespace types. Their workload markers are written only after `/proc` proves
the exact UID/GID maps and the configured monotonic and boottime offsets.
Multi-container and no-delete cleanup gates reuse the same fixture. Windows
uses `config.windows.json`, a separate six-namespace profile that does not
claim user/time qualification or ID-mapped mounts.

The July 24, 2026 qualification used an untouched Alpine 3.22.5 x86-64
minirootfs and the 6,328,408-byte static agent with SHA-256
`4b21a230d4183abe053823a63893f5ab0663c118811c81229bdfba0816fc9b81`.
The positive bundle requested new UTS, mount, IPC, network, and cgroup
namespaces, then ordered a relative-source rbind, a nested proc mount made
possible by that bind, and a relative-destination tmpfs. The workload verified
both filesystem types and proved that its IPC, network, and cgroup namespace
identities differed from guest PID 1 before producing its marker. A
joined-network negative bundle retained its typed `Unsupported` error and left
no guest runtime state. This historical run proves the then-current fixed
bootstrap slice, not the immutable A3S system image, complete OCI enforcement,
restart recovery, or exhaustive durable-write fault injection.

The current Windows hardware soak supersedes that historical run for the
protocol-v9 core profile. It proves process and PTY I/O, descriptor-confined
file transfer and filesystem mutations, resources and stats,
pause/resume, serial and parallel VM churn, two same-VM containers,
private/inherited networking, RW/RO bind volumes, init success/failure, ten
typed negatives, lifecycle cleanup faults, and owner-death cleanup. It retains
start/final inventories, operation and resource tables, and a hard-gated
verification result. User/time namespaces, recursive and ID-mapped mounts,
tmpfs, fresh-host qualification of restart-stable exact exit evidence, and the
immutable A3S system image remain outside that evidence. The implemented
guest/shim/host recovery chain authenticates and durably caches exact init
termination when present, with a stopped-only fallback when it is absent, but
the WHPX driver remains `probe-only` until the real-host gate passes. Candidate
sessions now attach only the exact generation's protected writable share,
mount its fixed `a3s-oci-runtime` tag at `/run/a3s-oci-runtime` before token
access, and keep that share disjoint from the guest system root. Host and guest
unit gates cover path fencing, one-time handoff, and required shim-v2 evidence;
the existing hardware report predates this layout and therefore does not yet
qualify it.

The PID qualification used the 6,371,704-byte static agent with SHA-256
`45d27bfdfec50ddedabd1f11a143dba4c11b4f472e7d2627a686594a0c514f6d`.
The workload required shell PID 1 and a matching `/proc/1/ns/pid` identity
before producing its marker. The agent returned authenticated host-visible PID
396, and the complete create/state/start/kill/delete lifecycle and cleanup
passed through WHPX. A joined-PID companion bundle retained `Unsupported` at
`linux.namespaces[5].path` and left no guest runtime state.
