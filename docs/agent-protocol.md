# Guest Agent Protocol

`a3s-oci-agent-protocol` is the boundary between a utility-VM driver and the
Linux guest executor. Windows WHPX, Linux KVM, and macOS HVF use the same
messages. The crate does not expose libkrun, hypervisor, or guest details to
A3S Box.

## Versioned Contract

Before connection, the host calls `SessionToken::generate` to obtain a
nonzero 256-bit token from the operating system's preferred random source and
provisions it to the pinned guest through a protected bootstrap channel.
Callers may also import exactly 32 bytes from an equivalent protected
bootstrap. The token is redacted from Rust debug output.

The host opens one authenticated byte stream and sends its inclusive protocol
range plus the token. The guest selects the highest common version and returns
its agent version, architecture, operation set, and frame limit. Authentication
or negotiation failure closes the stream.

A guest may advertise an empty operation set during transport-only bootstrap.
That proves negotiation without claiming an OCI executor. The client rejects
every lifecycle call not present in the negotiated operation set.

After negotiation:

- every UTF-8 JSON message has a four-byte big-endian length prefix;
- empty frames and frames over 64 MiB are rejected before payload allocation;
- every request and response carries the negotiated version and a nonzero,
  monotonically allocated request ID;
- a correlation, framing, version, target, digest, or lifecycle-barrier
  violation permanently poisons the client connection;
- guest service errors retain the stable Rust SDK error code and retryability;
- cloned clients serialize requests on one connection.

Protocol version 1 carries `create`, `state`, `start`, `kill`, and `delete`.
Protocol version 2 preserves that contract and adds `wait`. Every target
includes a positive exact generation. A wait accepts an optional millisecond
timeout and returns exactly one terminal result: an exit code in `0..=255` or
a positive Linux signal, plus an OOM flag that is valid only for signal
termination. Repeated waits return the same cached result.

Protocol version 3 adds `exec`, `signal-process`, and `wait-process`. Exec
carries one complete OCI `Process`, its I/O contract, mutation context, and an
exact `(container ID, generation, process ID)` target. The process ID `init`
is reserved for the configured container process and cannot be reused by
exec. A successful exec response repeats that exact target, the terminal
setting, and a positive authenticated guest PID. Signal acknowledgements and
terminal results are also bound to the exact process target. A mismatched
target poisons the host connection.

The client breaks a long init or process wait into bounded 25-millisecond
guest requests. The single correlated connection therefore remains available
to query or control another container between polls. Negotiation filters
operations introduced after the selected version, and the server rejects a
forged newer request before service dispatch. A protocol-v1 peer therefore
neither advertises nor accepts `wait`; protocol-v1 and protocol-v2 peers
neither advertise nor accept the version-3 process operations.

Protocol support and executor capability remain separate. The current shared
Linux executor negotiates version 3 and advertises the exact nine implemented
operations: the six lifecycle/init-wait operations plus exec, per-process
signal, and per-process wait. It retains an exact-generation process registry,
one pidfd per authenticated init or exec process, stable replay and wait
results, process-group ownership, and session cleanup. Durable recovery across
an agent restart remains a separate host/driver release gate.

Mutating guest operations must be idempotent by `OperationId`. Production
promotion also requires recovery after an agent or host restart; the current
bootstrap executor keeps only session-local replay state.

## Bundle Preservation

Create carries:

- the exact accepted `config.json` text;
- its canonical lowercase SHA-256 digest;
- an absolute normalized Linux guest bundle path;
- the complete process I/O request.

The receiver independently applies the SDK's pinned OCI schema and semantic
validation and recomputes the digest before dispatch. Start carries the
expected digest again. The client rejects a create response other than
`created`, a start response other than `running` or `stopped`, a response for
another generation, or a changed configuration digest.

`GuestPath` is parsed using Linux syntax on every host. It rejects relative
paths, dot components, duplicate or trailing separators, backslashes, NULs,
and values over 4,096 bytes. A Windows path is never interpreted as a guest
bundle path.

## Current Evidence Boundary

In-memory duplex tests cover:

- protocol-v1 negotiation and the unchanged five-operation core lifecycle;
- protocol-v2 wait with exact repeated signal status;
- protocol-v3 exec, per-process signal, stable repeated wait, and exact process
  target correlation;
- filtering and pre-dispatch rejection of forged version-3 process operations
  on a protocol-v2 connection;
- rejection of a forged protocol-v1 wait before service dispatch;
- two simultaneously registered container IDs with distinct PIDs, independent
  lifecycle transitions, stale-generation fencing, and generation-2 reuse;
- wrong-token and incompatible-version rejection;
- oversized-frame rejection from the header alone;
- configuration-digest tampering;
- response correlation failure and permanent connection poisoning;
- secret redaction and guest-path normalization.

Windows tests create the real host-side named-pipe endpoint, verify its live
kernel-object owner and protected DACL, reject a second owner of the same name,
generate both an unguessable endpoint nonce and the session token from the OS,
and reject a connected process whose PID is not the expected libkrun shim.
PID verification occurs before the host sends the session token.

macOS tests create a random private directory below `/private/tmp` with mode
`0700`, bind a `0600` Unix socket, reject collisions and symlinks, and remove
both entries on success, rejection, timeout, or drop. After accept, the host
reads `LOCAL_PEERPID` and uses `proc_pidinfo(PROC_PIDTBSDINFO)` to require that
the connected process is the direct worker child of the exact public libkrun
shim. An unrelated peer is rejected before protocol bytes are read. A direct
child with the wrong token is rejected during the following authentication
step.

The real WHPX `agent-vm-smoke` additionally boots the static musl Linux agent,
carries its CID-host port 4093 connection through libkrun to that protected
pipe, authenticates the token, negotiates protocol version 3, and retains
bounded host and shim evidence. The current guest must advertise the exact nine
operations: `create`, `state`, `start`, `kill`, `delete`, `wait`, `exec`,
`signal-process`, and `wait-process`.

The real macOS `agent-vm-smoke` builds the same agent as a static aarch64 musl
binary, boots it through HVF, maps guest CID-host port 4093 to the verified
Unix stream, and retains both the public shim PID and the direct VM worker PID
in `a3s.oci.agent-vm-smoke.v4`. The signed path must negotiate protocol version
3 and the exact nine implemented operations. The missing-entitlement path must
exit with status `2`, report no negotiation, terminate the shim process group,
and leave no private endpoint residue. Both paths also retain in-process
evidence that the exact runtime-owned endpoint was removed, the complete
current-process descriptor inventory returned to its baseline, and every
observed shim or VM-worker PID disappeared.

The real Windows and macOS `oci-vm-smoke` paths keep the same authenticated
connection open and prove a fixed bundle through create, state, exact create
replay, start, running observation, marker verification, signal delivery,
exact kill replay, a bounded wait while running, exact repeated terminal
status, exact-target exec replay, duplicate process-ID rejection, bounded
per-process wait, exact and replayed process signal, stable repeated process
wait, init-exit cleanup of another live exec, stopped observation, stopped-only
delete, exact delete replay, and a final NotFound state query. The marker
proves that the workload did not run before start and did run afterward. The
init wrapper reads both
configured UTS names back before create returns, and the workload independently
checks its hostname. When requested, the same create barrier also covers a new
mount namespace, recursively private propagation, a self-bound rootfs, and
`pivot_root`. Ordered mount entries run before that pivot, including safe
missing directory/file target creation, relative bundle bind sources, common
VFS flags, propagation, and bounded filesystem-specific data. After the
pivot, the same barrier applies configured rootfs propagation, masked paths,
read-only paths, and read-only rootfs state. Requested IPC, network, cgroup,
PID, and time namespace setup follows the authenticated user-namespace
mapping barrier and is atomic with UTS and mount isolation. The parent accepts
one mapping request only from the already verified wrapper PID, installs and
reads back exact UID/GID maps, then acknowledges the child. The wrapper writes
and verifies monotonic/boottime offsets, clears inherited supplementary groups,
and switches to mapped namespace-root UID/GID credentials before rootfs
mutation. For a new PID namespace, a dedicated namespace PID 1 completes
create-time setup and then forks the configured process as PID 2+. The guest
agent authenticates the launcher → PID 1 → configured-process chain and
reports the configured process's host-visible PID. Before returning created
state, the guest opens a pidfd for that exact process; lifecycle and cleanup
signals use the retained descriptor rather than resolving the numeric PID
again. PID 1 reaps adopted children and terminates every remaining namespace
process after the configured process exits. The host verifies marker removal
and that VM shutdown leaves no new guest-agent runtime directory. Native Linux
and macOS HVF retain this user/time, PID-supervision, and rootfs enforcement
evidence; the historical WHPX qualification predates it.

The same create plan now retains the configured capability and seccomp
security ceiling plus its owned cgroup v2 leaf. Init and every later exec
process apply exact capability sets, join that leaf, and install the same
architecture-bound seccomp policy immediately before `execve`. The bounded
A3S Box profile additionally creates and verifies its exact device nodes after
the `/dev` mount. These controls have focused Linux tests; complete
native/utility-VM lifecycle evidence remains a promotion gate.

Exec uses the same fail-closed process planner as init. The agent snapshots the
accepted OCI `Process`, preserves descriptors for the exact configured
process's root and all configured namespaces, and starts a fresh
single-threaded helper. The helper authenticates its launcher, enters retained
user/cgroup/IPC/UTS/network/mount/PID/time namespaces in a fixed order, forks
for PID/time next-child semantics, creates a dedicated process group, chroots,
applies cwd, groups, GID, UID, umask, capabilities, `no_new_privileges`, and
the retained seccomp policy, then blocks on a start barrier. Before release,
the agent validates the helper peer PID,
payload parent, host-visible PID, pidfd, root identity, every namespace
identity, and that init is still alive. The helper monitors init's pidfd and
uses the same non-destructive `waitid(WNOWAIT)` ownership pattern as the A3S
Box PID 1 reaper so descendants are killed before the leader PID/PGID can be
reused.

The macOS `oci-vm-multi-container-smoke` path keeps two exact targets live on
the same connection. It proves distinct runtime slots and PIDs, simultaneous
create barriers, A/B transition isolation, session-local generation fencing,
exact operation replay, rejection of cross-container operation-ID reuse, a
bounded wait on A that does not block B state, exact repeated terminal results
for both containers, and independent pidfd-backed cleanup. Its schema-v7
namespace phase retains a prepared donor, rejects a wrong-type namespace
descriptor before state, joins all eight Linux namespace types across two
workloads, proves retained-rootfs execution after the mount join, and removes
all state without changing the donor's created record. A third workload proves
missing mount-target creation at the create barrier, shared rootfs propagation,
read-only and masked path enforcement, recursive VFS attributes across a nested
submount, detached `idmap` and `ridmap` filesystem ownership, read-only rootfs
behavior, PID 1 supervision, adopted-orphan reaping, exact normal exit, state
removal, and fixture cleanup. Native Linux runs the equivalent schema-v8
sequence through the durable SDK service and additionally proves ID-mapped
bind recursion without changing the source tree.

The `oci-vm-fault-cleanup` companion stops after a successful create, start, or
kill request and never sends delete. Session EOF must still make the agent call
`LinuxExecutor::shutdown`, force-stop any retained configured process and its
namespace supervisor, remove the executor root, and exit successfully. The
host retains the exact requested and injected boundary together with
guest-runtime and platform cleanup evidence.

The private parent/init control channel reports a user-mapping request,
readiness with a positive runtime-visible configured-process PID and optional
namespace-init PID, or a bounded typed SDK error. The parent validates the
kernel-reported launcher peer PID before reading any outcome. It permits the
mapping request only when the exact plan requires one, acknowledges it only
after verified writes, and rejects a bypass or repeat. For new PID isolation
it additionally verifies both parent links, the PID 1 and PID 2+ `NSpid`
mappings, and both namespace links; user and time namespace identities are
also compared with the authenticated launcher's intended links before
exposing the created state. Create-time namespace and rootfs failures
therefore retain their exact error class and context without trusting a
pathname socket.

This is the first Linux executor vertical slice, not complete OCI
enforcement. A pinned immutable system image, complete process I/O, rootless
ID mapping, advanced mount semantics, resources, hooks, exhaustive recovery
injection, broader negative isolation cases, and full platform-specific
lifecycle evidence remain required before a utility-VM driver can advance
beyond `probe-only`.
