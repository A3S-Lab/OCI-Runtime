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

The current root-only bootstrap executor advertises `create`, `state`,
`start`, `kill`, `delete`, `wait`, `exec`, `signal-process`, and
`wait-process`, `pause`, `resume`, `processes`, `update`, `stats`,
`read-output`, `write-stdin`, and `close-stdin`. It is intentionally narrower
than the final OCI executor and rejects every property it cannot enforce.

The accepted bootstrap profile requires:

- only `ociVersion`, `root`, `process`, optional `hostname`, optional
  `domainname`, optional `mounts`, and optional `linux` at the configuration
  root;
- a writable normalized relative `root.path` equal to `rootfs`;
- `terminal: false`; null or piped stdin; null or captured stdout and stderr;
  and no terminal size;
- `noNewPrivileges: true`;
- an absolute executable and working directory;
- numeric UID, GID, optional supplementary groups, and optional umask;
- bounded arguments and environment with unique environment names.

When `linux.namespaces` is present, it accepts unique UTS, mount, IPC, network,
cgroup, PID, user, and time namespace entries in any order. Omitting `path`
creates a namespace; an absolute `path` joins an existing namespace; omitting
the entry inherits the runtime namespace of that type. Configured hostname and
domainname values are bounded to the Linux kernel limit and require a created
or joined UTS namespace.

The user-namespace profile is deliberately rootful. A new user namespace
requires both `uidMappings` and `gidMappings`, each list is bounded to the
kernel's 340-entry limit, and container ID 0 plus the process UID, GID, and
every supplementary GID must be covered. The wrapper creates the user
namespace first, then blocks on the authenticated control channel while the
parent verifies the distinct namespace, writes each
`/proc/<pid>/{uid,gid}_map` exactly once, reads both maps back, and requires
`/proc/<pid>/setgroups` to remain `allow`. After creating the remaining
namespaces and verifying any time offsets, the wrapper clears inherited
supplementary groups and switches all UID/GID slots to mapped namespace root
before any rootfs or mount mutation. Rootless `setgroups=deny` and
subordinate-ID helper flows are not implemented.

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
error or readiness with the runtime-visible configured-process PID and, for a
new PID namespace, its namespace-init PID before blocking. The
authenticated parent permits exactly one expected user-mapping request. It
rejects readiness that bypasses that request, a repeated request, or a request
without a configured user namespace. For a new PID namespace, the agent
verifies the complete launcher → namespace PID 1 → configured-process parent
chain, the init's `NSpid` mapping to 1, the configured process's mapping above
1, and both PID namespace links. It also verifies new user and time namespace
identities against the authenticated launcher's intended namespace links.
Create therefore preserves the exact rejection or returns `created` before the
configured process runs. Before returning `created`, the executor opens a
pidfd for that authenticated configured-process PID—the PID exposed through
OCI state. Failure to open the descriptor terminates the wrapper and fails
create. Start sends the one-byte release signal directly to that process; it
applies the inherited-namespace `chroot` when needed, then working directory,
groups, GID, UID, umask, and `PR_SET_NO_NEW_PRIVS`, and calls `execve`.

State observes the configured process, kill delivers one positive Linux signal
through its retained pidfd, and delete supports stopped-only and force cleanup.
Cleanup also signals through the pidfd and always reaps the authenticated
launcher before removing its runtime directory. Numeric PID reuse can
therefore never redirect a lifecycle signal to an unrelated process.

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
owner. The current slice accepts null or piped stdin and null or captured
stdout/stderr, while rejecting terminal, inherited descriptors, capability,
rlimit, scheduler, and other unenforced process settings.

Piped stdin is written asynchronously with backpressure and can be closed
idempotently. Dedicated tasks continuously drain captured stdout and stderr so
the child cannot block on a full pipe. Both streams share one globally ordered
8 MiB retained buffer. Output polls use an inclusive byte cursor, may split a
buffered frame exactly at the requested byte bound, optionally long-poll, and
emit one empty EOF frame per captured stream. A cursor older than retained
data or ahead of produced output fails closed. Guest messages carry at most
4 MiB of process-I/O payload; the native host driver splits larger SDK stdin
writes at that boundary.

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

The executor creates one private controller-enabled cgroup-v2 root and places
each init and exec pair in the same owned leaf. This permits a later update
even when create supplied no initial limits. Update preserves omitted fields,
applies the supported memory, CPU, cpuset, and PID changes with exact
read-back, and rolls earlier writes back in reverse order if a later write
fails. Stats normalizes CPU counters to nanoseconds, memory counters to bytes,
and includes PID plus memory/PID event counters. Pause writes `1` to
`cgroup.freeze`, resume writes `0`, and neither operation returns until
`cgroup.events` reports the exact `frozen` state. The process inventory
refreshes the init and exec supervisors, excludes terminal processes, and
returns only positive PIDs bound to the exact container generation. Exec is
rejected while the leaf is frozen. Force cleanup thaws a paused leaf before
signaling and reaping its processes.

Exact request retries are fingerprinted by `OperationId`, and reused IDs with
different requests fail. This includes pause, resume, and resource update.
Generation fences remain in memory after delete.

All guest registry, generation, and idempotency state is session-local. A
closed host connection force-stops remaining configured processes, exec
process groups and helpers, and namespace supervisors, then removes the
agent-owned runtime root. Agent restart recovery is not implemented yet.

The executor requires both `pidfd_open` and `pidfd_send_signal`. It currently
rejects mount entries and rootfs mutation in inherited or joined mount
namespaces, rootless user-mapping policy, unsupported cgroup I/O, hugetlb,
RDMA, and unified resources, hooks, terminals, inherited process I/O,
process-group signals, and every other unimplemented OCI property. These are
release blockers, not silently accepted compatibility gaps.

## Build And Evidence

Build the static x86-64 Linux artifact from Windows with:

```powershell
cargo zigbuild -p a3s-oci-agent --release `
  --target x86_64-unknown-linux-musl
```

`a3s-oci agent-vm-smoke` proves the authenticated
guest-AF_VSOCK/libkrun/Windows-named-pipe path and verifies the exact
seventeen-operation advertisement. `a3s-oci oci-vm-smoke` additionally loads a
bundle below the VM rootfs and proves the distinct create/start barrier, state
observation, exact create/kill/delete replay, bounded running wait, exact
repeated init status, exact-target exec replay, duplicate process-ID rejection,
bounded and stable process wait, replayed process signal, exact live init/exec
inventory, replay-safe live resource update, normalized cgroup-v2 statistics,
replayed pause/resume, a progress-producing exec that stops while frozen and
advances after resume, piped stdin, bounded captured stdout/stderr cursor
pagination and EOF, idempotent stdin close, rejected late writes, init-exit
exec cleanup, signal-driven stop, post-delete NotFound, marker cleanup, and
nominal guest runtime cleanup.

`a3s-oci oci-vm-multi-container-smoke` keeps two distinct bundle rootfs and
runtime slots live behind the create barrier, proves that A's start, kill,
wait, delete, recreation, stale generation, and replay conflicts do not alter
or block B, then completes B independently. The macOS HVF gate sends both
configured-process signals through distinct retained pidfds and retains both
exact repeated exit
statuses and per-container markers together with guest-runtime and
host-process cleanup evidence. Schema v8 then retains a prepared donor and
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
schema-v10 report additionally requires bind-source ownership preservation and
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
Multi-container and no-delete cleanup gates reuse the same fixture. The
retained WHPX qualification below predates this user/time requalification and
does not count as Windows evidence for the new slice.

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
the current process-I/O gate, configured networking, restart recovery, or
exhaustive durable-write fault injection. The WHPX driver therefore remains
`probe-only`.

The PID qualification used the 6,371,704-byte static agent with SHA-256
`45d27bfdfec50ddedabd1f11a143dba4c11b4f472e7d2627a686594a0c514f6d`.
The workload required shell PID 1 and a matching `/proc/1/ns/pid` identity
before producing its marker. The agent returned authenticated host-visible PID
396, and the complete create/state/start/kill/delete lifecycle and cleanup
passed through WHPX. A joined-PID companion bundle retained `Unsupported` at
`linux.namespaces[5].path` and left no guest runtime state.
