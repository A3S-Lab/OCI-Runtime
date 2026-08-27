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

For an internal dedicated Linux KVM v3 network handoff, the agent processes a
fixed attachment manifest before consuming the session token. It removes the
expected SHA-256 environment entry, rejects an unrequested or missing manifest,
validates the bounded mounted bytes without following the file symlink, and
rechecks the exact Guest bundle, `config.json` digest, and every namespace and
`linux.netDevices` pointer. Each VMM NIC must match exactly one deterministic
MAC. All required interface renames are staged through unused temporary names
so cycles are safe; a missing, ambiguous, or unrelated occupied name aborts
bootstrap. The resulting in-memory binding permits only the matching exact
Create target, Guest bundle path, and configuration. This path does not enable
production KVM v3 advertisement until its cumulative storage and real-host
qualification gates pass.

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

Device setup retains a separate boundary for source nodes and cleanup
evidence. Rootful Native Linux accepts OCI block, character,
unbuffered-character, and FIFO nodes at normalized paths inside or outside
`/dev`. It rejects duplicate paths, duplicate kernel identities, and an
existing target whose type, major/minor pair, mode, or mapped ownership does
not match. Private sources live below the executor-owned source root. A
utility VM instead creates each container's short-lived sources below the
Guest-local `/dev` devtmpfs, because its durable runtime directory is a
host-backed virtiofs share and cannot provide portable Linux device identity.

Every private mount namespace also receives the six OCI default character
devices and `/dev/ptmx -> pts/ptmx`. When configured init is terminal-backed,
the launcher clones the exact PTY slave mount and binds it to `/dev/console`
before the Create barrier. Rootless Native Linux cannot create sources after
dropping privilege, so a parent-bound helper opens and verifies only the six
fixed defaults and passes detached descriptors to the unprivileged owner.
Supplying those defaults does not fabricate an OCI device-access policy; when
the exact A3S Box policy is present, the same helper owns its bounded
cgroup-device BPF operations. Ordered rootful rules preserve wildcard, reset,
and access-subset behavior. An omitted or empty access string is an ordered
no-op, and a list containing only no-ops does not load BPF.

When configuration joins or inherits a mount namespace, the executor does not
inject mounts into that shared or separately owned namespace. It instead
retains the declared rootfs before `setns` and verifies every configured and
default device plus `/dev/ptmx` beneath that exact descriptor. Missing,
substituted, or incorrectly owned nodes fail Create. The Native Linux
namespace-join gate stages the six defaults from the same fixed inventory used
by the executor, proves this descriptor-only admission path, and removes only
the qualification-owned nodes after the joiner is deleted.

The v2 device-target manifest remains in the durable runtime directory. It
pins the canonical rootfs device/inode and records only regular placeholders
created by the runtime, including a new console target. Every record is
persisted before a detached mount is attached. Delete, failed Create,
graceful shutdown, and owner-death recovery wait for the mount namespace to
release each target, recheck rootfs and target identity through `openat2`, and
unlink only exact recorded placeholders. A caller-owned console or matching
device node is never recorded and therefore survives cleanup. Every source
and cleanup boundary rejects symbolic-link substitution, and transient source
nodes are removed immediately after their detached mounts cross the
Create-ready barrier.

Graceful executor shutdown now consumes every live container's device-target
manifest before clearing its runtime state or removing the Guest runtime root.
This removes bind-target placeholders such as `rootfs/dev/null` even when the
VM owner is replaced without an API Delete, so recovery can prepare the same
bundle in a fresh VM without an `EEXIST` collision. If any manifest cleanup
fails, the runtime root is retained for diagnosis and shutdown returns the
first error.

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

If `linux.intelRdt` is configured, the same parent prepares resctrl before it
spawns init. It opens the default CLOS, creates the container-ID CLOS, or
creates or verifies an explicit CLOS according to the OCI fields; applies
`l3CacheSchema`, `memBwSchema`, and complete `schemata` in that order; and
requires read-back of every requested resource line. After authenticating the
runtime-visible PID at the first barrier, it writes that PID to the control
`tasks` file and then to the dedicated monitoring `tasks` file when monitoring
is enabled. Assignment therefore completes before prestart or createRuntime
hooks can observe the container.

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
launcher before removing its runtime directory. It removes a dedicated
monitoring group first and removes a CLOS only when the runtime created the
container-ID directory; `/` and explicit `closID` directories remain external.
After the container record, retained namespaces/rootfs, cgroup leaf, owned
resctrl paths, and runtime directory are gone,
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

Linux admission and planning share one SDK-owned support contract. The Host
freezes each driver's `OciLinuxSupport` profile when the service opens and uses
it for Features plus pre-durable Create, Exec, and Update checks. The Agent
freezes the shared-executor profile in-process and validates the full init
configuration, each exec process, and every cgroup update before constructing
their enforcement plans. Unsupported LSM, Seccomp, mount, namespace, and
cgroup-v1-only controls therefore fail against the same capability set on both
sides of the transport.

Exec accepts one exact `(container ID, generation, process ID)` target while
the configured process is running. `init` is reserved, duplicate process IDs
fail, and exact mutation retries replay their original process or signal
result. Init and exec share the same fail-closed OCI process planner and I/O
owner. The current process-I/O slice accepts null, piped, or inherited stdin,
null, captured, or inherited stdout/stderr, or the exact all-terminal PTY
contract. It accepts the enforced `oomScoreAdj`, `scheduler`, and `ioPriority`
fields plus exec-only `execCPUAffinity`, while rejecting other unenforced
process settings.
Inherited descriptors remain owned by the runtime launcher and are
deliberately absent from SDK read/write operations. A separate Linux-only
native create attachment implements the fixed
A3S Box control contract: validated Unix stream listeners become FD 3 and FD 4
and a writable regular init log becomes FD 5. Raw handles never enter the
guest protocol; the native driver supplies a process-local descriptor plan
directly to `LinuxExecutor`. It retains and applies all 16 OCI
`process.rlimits` types to init and exec before credentials are reduced, with
duplicate, count, and soft/hard validation.

Init and exec retain the host procfs directory before PID namespace and root
changes. When `process.oomScoreAdj` is present, the payload restores ordinary
self-proc ownership after a mapped-user credential transition when required,
opens `self/oom_score_adj` relative to that retained descriptor, writes the
validated Linux value before reducing credentials or capabilities, and
requires an exact read-back. An omitted field returns without opening procfs
or changing dumpability, preserving the inherited value. Values outside
`-1000..=1000`, permission failures, malformed read-back, and mismatches fail
with contextual typed errors.

The same pre-credential boundary applies optional `process.ioPriority` with
Linux `ioprio_set` and immediately verifies the exact encoded class and
priority through `ioprio_get`. Real-time, best-effort, and idle classes are
represented without normalization. Values outside `0..=7`, nonzero class data
for the kernel's data-less idle class, permission failures, unavailable
syscalls, and read-back mismatches fail with typed context. An omitted field
performs no syscall and preserves the inherited I/O priority.

Optional `process.scheduler` is applied at the same point with Linux
`sched_setattr` and verified immediately with `sched_getattr`. The planner
represents all seven OCI policies and all seven flags, validates the Linux
nice and realtime-priority ranges plus deadline ordering and kernel bounds,
and rejects duplicate or policy-incompatible flags before mutation.
`SCHED_ISO` returns `Unsupported` when the host kernel does not implement it;
permission and other syscall failures retain their typed error instead of
falling back to inherited scheduling. Omission performs no scheduler syscall.
The SDK's process adapter also preserves the exact OCI spellings for
`SCHED_FLAG_RESET_ON_FORK` and `SCHED_FLAG_DL_OVERRUN` across bundle and Guest
protocol serialization.

Optional `linux.personality` applies only to configured init. The planner
accepts the OCI `LINUX` and `LINUX32` domains and rejects every nonempty flags
list before the executor mutates process state. The dedicated init applies the
selected domain before credentials and seccomp, immediately queries the
personality syscall, and fails unless the complete value matches. Omission
performs no personality syscall and preserves inherited state.

Optional `linux.memoryPolicy` also applies only to configured init. A shared
SDK registry defines all seven OCI modes and all three flags used by semantic
validation, execution, and feature reporting. The bounded planner parses and
normalizes the node mask, rejects invalid mode/flag relationships, and follows
Linux by selecting the lowest requested node for `MPOL_PREFERRED` or observing
`MPOL_LOCAL` when that mode has no nodes. The dedicated init calls
`set_mempolicy` before credentials and seccomp, then requires `get_mempolicy`
to return the exact effective mode, flags, and node mask. Omission performs no
memory-policy syscall and preserves inherited state.

For exec, the trusted helper applies and reads back
`process.execCPUAffinity.initial` before joining the workload cgroup through
its inherited `cgroup.procs` descriptor. It then applies and reads back
`final` before entering retained namespaces and forking the payload. CPU lists
are normalized, deduplicated, sorted, and bounded by `CPU_SETSIZE`; descending
ranges and unrepresentable CPU IDs fail before mutation. Omitted or empty
phases perform no affinity syscall, and init ignores this exec-only field.

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
runs. Configured init also binds that slave to `/dev/console` and applies the
OCI `consoleSize` before the workload starts. Terminal output is merged into
the existing stdout cursor, `resize` applies `TIOCSWINSZ`, and close-stdin
delivers the active `VEOF` byte while retaining the readable master.

Create retains descriptors for the configured process's root and every
configured namespace. A fresh single-threaded exec helper inherits only those
validated descriptors plus init's pidfd, authenticates its launcher, enters
retained user, cgroup, IPC, UTS, network, mount, PID, and time namespaces in a
fixed order, and forks for PID/time next-child semantics. The payload creates
its own process group, enters the retained root with `chroot`, applies cwd,
groups, GID, UID, umask, and `PR_SET_NO_NEW_PRIVS`, and blocks before `execve`.
The parent verifies the helper's kernel peer PID, the payload parent and
host-visible PID, an exact pidfd, root identity, every namespace identity, and
the continued liveness of init before releasing that barrier. The payload's
control descriptor is close-on-exec. After release, the parent waits for EOF
before returning the process record; credential, seccomp, or `execve` failure
instead returns the bounded typed rejection over that same channel.

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

OCI 1.3 `linux.resources.unified` is enforced as a bounded, key-sorted map of
cgroup-v2 file writes. Keys must name one control file, may carry a controller
unknown to the runtime, and cannot target `cgroup.*` state or a file already
owned by a typed resource in the same request. The manager retains every
controller exposed by the kernel, enables usable optional controllers through
the private hierarchy, and returns `Unsupported` when a requested controller or
file is unavailable. Create preflights writable controls before device-policy
mutation. Create and Update write values in stable order without assuming the
format of an unknown kernel control. Update snapshots readable controls for
no-op suppression and reverse rollback while still accepting write-only files.

`linux.cgroupsPath` keeps its OCI path class through validation. An absolute
value is resolved from the visible cgroup v2 mount point; a relative value is
resolved from the executor's stable private manager. The same value is reused
for recreation, live control, recovery, and delete. Invalid or ambiguous paths
fail semantic validation before runtime mutation, and only paths recorded as
runtime-owned are removed.

For OCI 1.3 cgroup ownership, the executor requires all of the specification's
delegation signals at once: a newly created cgroup namespace, the exact raw
mount source `cgroup`, the exact raw destination `/sys/fs/cgroup`, no `ro`
option, and a cgroup-v2 mount. It resolves `process.user.uid` through the
container user mapping before mutation. Rootless execution may delegate only
to its own effective UID, and the Linux all-ones chown sentinel is rejected.
The runtime opens the created cgroup with `O_PATH`, preserves its GID, and
changes only that directory and existing single-component files listed by
`/sys/kernel/cgroup/delegate`. Missing listed files are harmless; a missing
inventory falls back to `cgroup.procs`, `cgroup.subtree_control`, and
`cgroup.threads`. Every changed UID is read back, and files outside the list
are never touched.

A non-root native executor may instead receive one explicit delegated root at
open time. The root must be a canonical empty cgroup-v2 directory owned by the
executor's effective UID/GID with `cpu`, `cpuset`, `memory`, and `pids`
already enabled. The executor pins its filesystem device and inode, rechecks
ownership and controller state before first use, and creates the same private
manager layout beneath that root. Every additional controller that is both
exposed and enabled is propagated without a runtime name allowlist. A rootless
`linux.cgroupsPath` without this authority fails before container state or
filesystem mutation. An absolute rootless value must also resolve inside that
exact delegation.

If a rootless plan also needs the six default device nodes, the CLI must start
the synchronous bounded helper before Tokio and consume that bootstrap when it
opens the executor. A delegation without this helper remains valid for
negative qualification and device-free planning, but create fails explicitly
when device preparation is required. For a private mount namespace joined to
an existing user namespace, the executor pins and type-checks the namespace
descriptor, reads its bounded UID/GID maps from a short-lived helper inside
that namespace, and rechecks the namespace identity immediately before entry.
It then prepares the same six detached device mounts using the observed
namespace-root ownership and retains the ordinary manifest-bound cleanup path.

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
the derived outer envelope and workload settings only after preflight. Typed
settings and readable Unified controls participate in reverse rollback;
write-only Unified controls are accepted but inherently have no prior state to
restore. CPU burst, idle, Block I/O, HugeTLB, RDMA, and Unified settings are
workload-only controls and are never copied into the derived outer envelope.
Stats and freeze/thaw observe only the workload child, so memory pressure
cannot kill or freeze the trusted control transport. Cleanup removes both
children and the complete owned topology.

For either layout, update preserves omitted fields and applies supported memory,
CPU, cpuset, PID, Block I/O, HugeTLB, and RDMA changes with exact read-back.
Unified controls retain kernel-defined formatting and use readable prior state
for no-op suppression and best-effort rollback. Earlier reversible writes roll
back in reverse order if a later write fails. Stats normalizes CPU counters to
nanoseconds, memory counters to bytes, and includes PID plus memory/PID event
counters. It also sums `io.stat` read and write bytes across every workload
block device into `io.read_bytes` and `io.write_bytes`, ignoring legal
device-only entries with no published counters; an unavailable I/O controller
leaves those optional metrics absent. Pause writes `1` to
`cgroup.freeze`, resume writes `0`, and neither operation returns until
`cgroup.events` reports the exact `frozen` state. The process inventory
refreshes the init and exec supervisors, excludes terminal processes, and
returns only positive PIDs bound to the exact container generation. Exec is
rejected while the workload target is frozen. Force cleanup thaws a paused
target before signaling and reaping its processes.

Exact request retries are fingerprinted by `OperationId`, and reused IDs with
different requests fail. This includes pause, resume, and resource update.
Generation fences remain in memory after delete.

All guest registry, generation, and idempotency state is session-local.
Protocol v10 adds a bounded maintenance acknowledgement so completed mutation
records can be removed after the Host outcome is durable. The Guest rejects a
batch containing any still-pending known identity without removing the
completed records in that batch; unknown identities are safe. Protocol-v1
through protocol-v9 retain no-op compatibility. The host releases the shared
transport immediately after a terminal request-write,
response-read, correlation, or response-shape failure, even when other client
clones remain. The resulting closed host connection force-stops remaining
configured processes, exec process groups and helpers, and namespace
supervisors, then removes the agent-owned runtime root. Agent restart recovery
is not implemented yet.

Qualification can now interrupt an exact negotiated-version boundary for any
of the 21 Guest operations: 20 workload operations plus the maintenance
acknowledgement, across four host request/response stages, five guest
read/dispatch/write stages, and two explicit host shutdown stages. Production
uses a no-op injector. An authenticated in-memory matrix injects every one of
the 189 operation-stage pairs, requires one exact crossing, and proves the
connection terminates after each fault. Separate evidence completes one create
dispatch, drops the response before it is written, authenticates a new
connection, and replays the identical `OperationId` and request without a
second effect; changed content under the same ID fails with `Conflict`. A
portable agent-backed `RuntimeDriver` matrix now carries all nine create,
state, start, kill, delete, wait, exec, signal-process, wait-process, pause,
resume, processes, update, stats, read-output, write-stdin, close-stdin, resize,
file, and filesystem stages through `HostRuntimeService` reopen: all 180
public workload operation-stage pairs. Faults before guest dispatch leave a
mutation resumable and perform its first effect on the replacement connection.
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
fault after a durably journaled host mutation response write commits the Host
result, then exposes the retryable acknowledgement failure. After reopen, the
completed Host journal answers the retry without a second driver dispatch and
the replacement connection acknowledges the exact operation once; completed
delete also leaves no live record to send through driver recovery. File upload
and Filesystem mkdir/move/remove now have the same durable Host boundary. Their
v3 Host records retain the exact request and typed response; after a completed
Guest response, the public call returns the acknowledgement failure, the next
owner rebuilds any VM-local effect, and Host replay returns without another
API-driven dispatch. The Host request digest permanently rejects a changed
reuse after the Guest journal has been acknowledged and reclaimed. Every case
uses a newly authenticated connection and driver and preserves the same
generation; mutations produce one effect. This completes the portable
in-memory matrix, not the required real utility-VM replacement and complete
transition matrix.

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

Start now has the same nine-stage real-owner gate. The first eight interruptions
leave Host state in `created`; the replacement Guest receives the original
Create identity, rebuilds the process, and executes the unchanged Start identity.
The fully written-response point leaves Host state in `running`; replacement
recovery recreates and starts the workload before Host journal replay, then
repairs the completed Create and Start responses with the new Guest PID. The
Start retry returns from the durable journal without another dispatch. Each run
removes any first-owner marker before replacement and requires the new Guest to
produce the exact marker. All 18 fresh VMs in the August 10, 2026 matrix returned
Host and Guest resource inventories to baseline.

Kill now has the same nine-stage real-owner gate. The first eight interruptions
leave Host state in `running`; replacement recovery reuses the original Create
and Start identities, rebuilds the running process, repairs their completed
responses with the new Guest PID, and sends the unchanged signal-9 Kill once.
The fully written-response point leaves Host state in `stopped`; replacement
recovery recreates, starts, and kills the workload to rebuild the Guest
tombstone before the Host replays the completed Kill journal without an
API-driven driver dispatch. Every run verifies the replacement marker before
Kill, uses stopped-only Delete, and restores Host and Guest resource inventories.
All 18 fresh VMs in the August 10, 2026 matrix passed.

Delete and init Wait now carry the same nine points through fresh owners. For
Delete, the first eight paths retain a stopped record plus Prepared journal and
the fully written response retains only SucceededEmpty replay evidence. For
Wait, the first eight paths rebuild the Guest tombstone before caching the
exact signal result, while the fully written response and every later retry
return from the durable terminal cache. Neither completed post-response path
dispatches the API operation again. Each matrix passed in 18 fresh VMs.

Terminal Exec now has the same real-owner matrix. The first eight paths retain
a Prepared journal and a prepared process record with no live PID; the
replacement rebuilds init and dispatches the unchanged Exec once. The fully
written response retains the live process and Succeeded journal; recovery
recreates init and Exec, rebinds their PIDs, repairs the completed responses,
and the Host retry replays
without another API-driven dispatch. Every replacement process must be
long-running, terminal-backed, and write the exact nonce-bound marker. Stale or
changed Host and Guest requests fail closed. All nine stages passed in 18 fresh
VMs on August 10, 2026.

SignalProcess now follows that live-process matrix. Setup installs a
nonce-bound SIGUSR1 trap in the terminal Exec. The first eight points leave the
Host signal journal Prepared; a replacement Guest rebuilds init and Exec, then
receives the unchanged signal-10 request once. At
`guest-after-response-write`, Host state is already SucceededEmpty. Recovery
waits until the replacement process has installed its trap, reapplies the
committed signal, and lets the API retry replay without another driver
dispatch. The replacement signal marker is mandatory even when the first VM
exits before its shell can schedule the trap. Changed content under the same
operation ID and stale generations fail at both Host and Guest boundaries. All
nine stages passed in 18 fresh VMs on August 11, 2026 under schema
`a3s.oci.oci-vm-operation-reopen-replacement.v7`.

WaitProcess now carries the same owner handoff through a terminated non-init
Exec. Recovery rebuilds the terminal process, waits for its exact readiness
marker, and reapplies the committed signal before any uncached wait. The first
eight transport points dispatch the exact resolved target and timeout once in
the replacement Guest, then store the signal exit result. A fully written
first response is already cached by the Host, so replacement and later API
calls do not reach the driver; the temporary rebuilt process is also omitted
from the recovered live inventory. Stale generations fail at both Host and
Guest boundaries. All nine stages passed in 18 fresh VMs on August 11, 2026
under `a3s.oci.oci-vm-operation-reopen-replacement.v8`.

Pause now crosses the same nine owner-handoff points. The first eight leave the
Host journal Prepared, so the replacement Guest rebuilds an unpaused init and
receives the unchanged Pause once. A fully written response is already durable
as paused. Recovery starts the replacement init, waits for its exact readiness
marker, sends the committed Pause before Host service open completes, and then
returns explicit paused-process recovery evidence. Host replay repairs Create,
Start, and Pause journal PIDs without a second API-driven dispatch. Changed
requests and stale generations fail at both Host and Guest boundaries, and
force-delete cleans up the frozen replacement. All nine stages passed in 18
fresh VMs on August 11, 2026 under
`a3s.oci.oci-vm-operation-reopen-replacement.v9`.

Resume adds a deliberately reconstructed freezer history rather than treating
the fresh init as already thawed. Every replacement Guest receives the original
Create and Start, waits for the exact init marker, and receives the setup Pause.
The first eight stages then receive the unchanged Resume once. When the first
owner already wrote the complete response, recovery also replays that committed
Resume before Host service open completes. The Host can therefore distinguish
the historical paused response from the current unpaused record while rebinding
Create, Start, Pause, and Resume to the replacement PID. Changed requests and
stale generations fail at both boundaries. All nine stages passed in 18 fresh
VMs on August 11, 2026 under
`a3s.oci.oci-vm-operation-reopen-replacement.v10`.

Processes crosses the same nine owner handoffs after a live terminal Exec has
been committed. The replacement Guest receives the original Create, Start, and
Exec requests, writes both nonce-bound markers, and exposes exactly the live
init and Exec identities with fresh PIDs. The read-only query has no mutation
journal, so it is sent once to every replacement Guest even when the first
Guest wrote a complete response. The Host validates the exact generation,
positive unique PIDs, init presence, process IDs, and terminal mode; stale
generations fail at both boundaries. All nine stages passed in 18 fresh VMs on
August 11, 2026 under
`a3s.oci.oci-vm-operation-reopen-replacement.v11`.

Update crosses the same nine owner handoffs with the complete OCI resource
profile bound to its OperationId and exact generation. The first eight paths
send that request once after the replacement Guest rebuilds the running init.
When the first Guest already wrote a complete response, the Host journal is
Succeeded but the old VM's cgroup is gone, so recovery waits for the fresh init
marker and reapplies the committed Update before Host service open completes.
The API retry then returns the response rebound to the replacement PID without
another dispatch. Two Stats queries to the fresh Guest must report the 512 MiB
memory limit, live CPU and process counters, and the required memory/PID event
metrics. Changed resources and stale generations fail at both boundaries. All
nine stages passed in 18 fresh VMs on August 11, 2026 under
`a3s.oci.oci-vm-operation-reopen-replacement.v12`.

Stats crosses all nine owner handoffs after Create, Start, and that complete
Update have committed. The replacement Guest always rebuilds init, waits for
the exact readiness marker, and receives the original Update so the fresh
cgroup has the same resource profile. Because Stats is read-only and has no
Host response journal, the replacement Guest receives one new query at every
stage, including after the first Guest wrote a complete response. Each returned
snapshot must carry the original exact generation, 512 MiB memory limit, live
CPU and process counters, and the required memory/PID event metrics. A
delivered first-owner snapshot must differ from and precede the replacement
snapshot. Stale generations fail at both boundaries. All nine stages passed in
18 fresh VMs on August 11, 2026 under
`a3s.oci.oci-vm-operation-reopen-replacement.v13`.

ReadOutput crosses the same nine handoffs with a non-terminal Exec that writes
one nonce-bound stdout chunk and stays live. Recovery replays the exact Create,
Start, and Exec requests and repairs their response PIDs. Because ReadOutput is
read-only, the replacement Guest receives one new request at every stage with
the same process target, cursor, byte limit, and timeout. Stale generations
fail at both boundaries. All nine stages passed in 18 fresh VMs on August 11,
2026 under `a3s.oci.oci-vm-operation-reopen-replacement.v14`.

WriteStdin crosses the same nine handoffs with a pipe-backed Exec waiting for
one nonce-bound line. The first eight paths receive the write once when the
prepared Host journal resumes. If the old Guest completed the response, the
fresh Guest receives the same committed request during recovery before the
Host journal serves the retry. Its journal then rejects changed bytes under
the same operation ID, and the rebuilt Exec must write the exact line to its
effect marker. Stale generations fail at both boundaries. All nine stages
passed in 18 fresh VMs on August 11, 2026 under
`a3s.oci.oci-vm-operation-reopen-replacement.v15`.

CloseStdin and Resize retain the same Host-first commit boundary under schemas
v16 and v17. File upload and Filesystem MakeDir use v18 and v19 with exact v3
Host request retention. On `guest-after-response-write`, each operation
commits its Host outcome, returns retryable `Unavailable` when Guest
acknowledgement crosses the closed connection, reconstructs any VM-local effect
under the replacement owner, and then replays without an API-driven dispatch.
The August 15, 2026 Apple Silicon rerun passed this point for all 14 journaled
mutations. File and Filesystem also passed every Host/Guest transport stage,
18/18 paths, with permanent Host changed-request fencing and complete device
placeholder cleanup between owners.

The executor requires both `pidfd_open` and `pidfd_send_signal`. It currently
rejects mount entries and rootfs mutation in inherited or joined mount
namespaces, rootless supplementary groups and nondelegated cgroup paths,
Block I/O, HugeTLB, RDMA, or Unified requests whose required cgroup-v2
controller, dynamic control, or device is unavailable, and every other
unimplemented OCI property. Rootless cgroup-v2 real-host
qualification and device-policy delegation, hook
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
20 workload operations, including `file` and `filesystem`, plus the
protocol-v10 maintenance acknowledgement.
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
