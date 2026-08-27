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
- a terminal request-write, response EOF/read, correlation, or response-shape
  failure releases the shared transport before returning, so retained client
  clones cannot keep the failed guest connection alive;
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

Protocol version 4 adds `pause`, `resume`, and `processes`. Pause and resume
carry an idempotent mutation context and exact container generation. Their
state responses must report the requested cgroup freezer state. Processes is
an observation that returns a duplicate-free inventory of live init and exec
processes, each bound to that same exact generation with a positive PID.
Freezer state is carried separately from the standard OCI lifecycle status.

Protocol version 5 adds `update` and `stats`. Update carries an idempotent
mutation context, an exact container generation, and one OCI `LinuxResources`
patch. Omitted supported resource fields retain their current cgroup-v2
values. The executor applies supported memory, swap, reservation, CPU
shares/quota/burst/period/cpuset/idle, and PID-limit changes with exact
read-back and reverse-order rollback after a partial failure. Quota and period
are independent, and quota/burst changes are ordered so the kernel never sees
an invalid intermediate pair. Stats returns a typed,
generation-bound snapshot with a positive Unix-nanosecond timestamp,
normalized CPU nanoseconds, memory bytes, process count, and named cgroup
integer counters. When the workload cgroup exposes `io.stat`, the executor
publishes aggregate block-device byte counters under the stable
`io.read_bytes` and `io.write_bytes` metric names.

Protocol version 6 adds `read-output`, `write-stdin`, and `close-stdin`.
Every request carries an exact process target. Output polls use one globally
ordered inclusive byte cursor across captured stdout and stderr, support
partial-frame pagination and bounded long polling, and return an empty EOF
frame for each captured stream. Data frames advance the cursor by their byte
length; EOF advances it by one logical position. Stdin writes carry at most
4 MiB per guest message and preserve backpressure. The host driver splits a
larger SDK write into bounded guest messages. Closing stdin is idempotent.

Protocol version 7 adds `resize`. Terminal processes require terminal mode on
stdin, stdout, and stderr plus positive initial dimensions. The shared Linux
executor allocates a controlling PTY, reports its merged stdout/stderr bytes as
the stdout stream, and applies positive runtime dimensions with
`TIOCSWINSZ`. Closing terminal stdin delivers the active `VEOF` character
because a PTY master cannot be half-closed. A resize acknowledgement repeats
the exact process target and mismatched correlation poisons the client.

Protocol version 8 adds required `OperationContext` metadata to
`write-stdin`, `close-stdin`, and `resize`. The guest journals the exact
request and its success or failure by `OperationId`, so retrying a completed
stdin write does not deliver the bytes twice. Reusing an ID for a different
payload, target, size, or mutation kind fails closed. Version-6 and version-7
process-I/O requests omit this field for wire compatibility; a version-8 peer
rejects a missing context, and an older peer rejects a version-8 context.

Protocol version 9 adds `file` and `filesystem`. File upload and
mkdir/move/remove requests carry exact mutation contexts; downloads and
stat/list requests are read-only. Every request names an exact container
generation. The shared executor bounds decoded payloads, path/user text,
listing depth and response size, and resolves paths from the retained rootfs
descriptor with `openat2` plus descriptor-relative mutation syscalls.

Protocol version 10 adds `acknowledge-operations` as a maintenance operation.
It does not add a public `RuntimeOperation`; the public workload surface stays
at 20 operations. A request carries 1..=4,096 unique completed Guest operation
identities. The Guest removes their replay records atomically only when every
known identity has finished; unknown identities are already released and
succeed. The Host sends this request only after it has durably committed the
corresponding success or terminal failure. Prepared and retryable operations
are not acknowledged. Protocol-v1 through protocol-v9 clients, and v10 Guests
that do not advertise the maintenance operation, retain the historical no-op
behavior.

The client breaks a long init or process wait into bounded 25-millisecond
guest requests. The single correlated connection therefore remains available
to query or control another container between polls. Negotiation filters
operations introduced after the selected version, and the server rejects a
forged newer request before service dispatch. A protocol-v1 peer therefore
neither advertises nor accepts `wait`; protocol-v1 and protocol-v2 peers
neither advertise nor accept the version-3 process operations, and
protocol-v1 through protocol-v3 peers neither advertise nor accept the
version-4 control operations. Protocol-v1 through protocol-v4 peers neither
advertise nor accept the version-5 resource operations. Protocol-v1 through
protocol-v5 peers neither advertise nor accept the version-6 process-I/O
operations. Protocol-v1 through protocol-v6 peers neither advertise nor accept
the version-7 terminal resize operation. Protocol-v1 through protocol-v7 peers
reject version-8 process-I/O mutation context. Protocol-v1 through protocol-v8
peers neither advertise nor accept version-9 file or filesystem operations.
Protocol-v1 through protocol-v9 peers neither advertise nor accept the
version-10 maintenance acknowledgement.

Protocol support and executor capability remain separate. The current shared
Linux executor negotiates version 10 and advertises the exact 20 workload
operations plus one maintenance acknowledgement: the six
lifecycle/init-wait operations; exec,
per-process signal, and per-process wait; pause, resume, and processes; update
and stats; captured-output polling, stdin write/close, and terminal resize;
file transfer and filesystem metadata/mutations; and
`acknowledge-operations`. It
retains an exact-generation process registry, one pidfd per authenticated init
or exec process, the private controller-enabled cgroup-v2 root and owned
workload target, stable replay and wait results, exact session-local
write/close/resize replay, process-group and standard-I/O ownership, and
session cleanup. The target is one leaf by default; the opt-in
`control-workload-v1` layout uses a fixed workload child plus a derived outer
management envelope. The native host driver gives every bounded chunk of a
larger SDK stdin write a stable derived operation ID. The host can now ask an
exact recorded driver to reconcile durable state during startup. This does not
make session-local agent replay durable across an Agent restart. Protocol v10
bounds the lifetime of completed session-local records; restart-stable
operation and exit evidence remains a separate release gate.

`AgentClient` also implements the same `GuestAgentService` contract as the
in-process executor. One runtime adapter therefore performs target, digest,
state, process, stats, chunked-I/O, and filesystem mapping for both native
Linux and WHPX; the transport boundary cannot grow a second interpretation of
the 20 workload operations or their maintenance acknowledgement.

OCI hooks do not add guest protocol operations: they travel inside the exact
digest-bound `config.json` and execute in the shared Linux executor. Native
feature discovery separately advertises the six enforced hook phases. Every
Hook child marks all descriptors above standard error close-on-exec with one
fail-closed Linux `close_range` operation, so neither an in-process Native
executor nor a Guest agent can leak runtime-private handles into Hook code.

Mutating guest operations must be idempotent by `OperationId`. Production
promotion also requires recovery after an agent or host restart; the current
bootstrap executor keeps only session-local replay state.

## Qualification Fault Boundaries

Production connections install a no-op fault injector. Qualification can use
`AgentClient::connect_with_fault_injector` and
`serve_agent_connection_with_fault_injector` to interrupt one explicit point
without changing framing or service behavior. Every operation point carries
the negotiated protocol version and one of the complete 21-operation Guest
registry entries.

The host exposes four ordered stages: before and after request write, then
before and after response read. The guest exposes five: after a validated
request read, before and after service dispatch, then before and after response
write. Invalid envelopes do not cross either dispatch stage, but their typed
error response still crosses both response-write stages. Explicit host close
has separate before-shutdown and after-shutdown points. An injected host error
poisons the clone-shared client and releases its stream before returning.

The exhaustive in-memory matrix opens a fresh authenticated session for every
one of the 21 Guest operations at each of the nine request/response stages.
All 189 pairs must be unique. The selected point must be crossed exactly once,
and the connection must reject its next request. A fault before the response is
fully written fails the current request. A fault immediately after the complete
response write preserves the delivered response and makes the disconnect
visible on the following request.

The real-VM `create` gate uses the same nine-stage registry without exposing a
production fault switch. Host stages install a qualification-only client
injector. Guest stages pass one bounded, versioned request through the runtime
and fixed shim to the Guest agent. That request carries the exact validated
`OperationId`, operation, and Guest stage. The server presents the request ID
to the injector at every Guest transition, so an unrelated call cannot consume
the fault. After the injected disconnect, the Guest emits one prefixed,
versioned console record only if `LinuxExecutor` cleanup succeeds. The Host
accepts it only when the operation ID, stage, protocol version, point, and one
crossing all match. A fault after the response write must deliver the primary
response; a follow-up request then proves that the connection ended.
The same real-VM gate covers both explicit Host shutdown points. It first
receives the successful `create` response, then closes a retained client clone.
The selected before- or after-shutdown point returns one qualification error;
the VM owner's second close is idempotent and must still reap the Guest, shim,
bridge, endpoint, runtime root, and prepared container. Report schema
`a3s.oci.oci-vm-transport-fault-cleanup.v3` distinguishes the shutdown point
from the nine `create` request-response points.

In-memory qualification drops a create response at the guest's
after-dispatch/before-response-write boundary. The first client receives a
retryable transport failure after the service has recorded one effect. A newly
authenticated connection then sends the identical `OperationId` and request,
receives the original exact-generation response, and leaves the effect count at
one. Reusing the ID with changed request content returns `Conflict`. This proves
the protocol and session-local replay boundary.

The real `a3s.oci.oci-vm-reopen-replacement.v2` gate covers all nine Host and
Guest Create request/dispatch/response points through durable service reopen
and an actual utility-VM owner replacement. The Host points and first four
Guest points leave the journal in `creating`; a fresh VM receives the unchanged
OperationId and generation and completes that request. At
`guest-after-response-write`, the first Create response is already durable;
the following Guest acknowledgement observes the closed connection, so the
public Create call returns retryable `Unavailable`. The replacement recovery
hook then rebuilds the pre-start process, reconciles its exact Guest PID,
repairs the cached Create response before Host replay, and retries
acknowledgement. Guest points also require nonce-bound
console evidence emitted after executor cleanup. Every report retains both
owner identities and requires force-delete cleanup. In-place Guest-agent
restart remains open.

The companion `a3s.oci.oci-vm-operation-reopen-replacement.v1` gate applies
the same nine points to `state`. State intentionally carries no idempotency
context, so the Guest injector matches the exact operation and stage while the
boot handoff nonce binds the retained cleanup evidence. The first owner keeps
the durable record unchanged in `created`; after complete VM cleanup, the
replacement owner rebuilds that pre-start process with the original Create
identity and generation. Reissued State must return the recovered durable
record. At `guest-after-response-write`, the delivered first response must
also match that record and a second State call must expose the disconnect.

Schema `a3s.oci.oci-vm-operation-reopen-replacement.v2` adds the same real-owner
matrix for `start`. Before the completed-response point, durable state remains
`created`; the replacement Guest rebuilds the process and receives the original
Start OperationId and exact target. At `guest-after-response-write`, durable
state is already `running`. Recovery recreates and starts that workload, the
Host rebinds its PID in both completed Create and Start journal responses, and
the later Start replay does not dispatch again. The gate removes any first-owner
marker before replacement and requires the exact marker from the new workload.

Schema `a3s.oci.oci-vm-operation-reopen-replacement.v3` adds `kill`. Before the
completed-response point, durable state remains `running`; the replacement
Guest receives the original Create and Start identities, rebuilds the running
process, and receives the unchanged signal-9 Kill identity once. At
`guest-after-response-write`, durable state is already `stopped`. Recovery
recreates, starts, and kills the replacement process to rebuild its Guest
tombstone, while the completed Host Kill journal answers the retry without an
API-driven driver dispatch. Every path verifies the replacement workload before
Kill and uses stopped-only Delete.

Schema `a3s.oci.oci-vm-operation-reopen-replacement.v4` adds stopped-only
`delete`. The first eight points retain a Prepared journal and stopped record;
the completed-response point retains only SucceededEmpty replay evidence, so
the replacement performs no workload recovery or driver Delete. Version 5 adds
init `wait`: recovery dispatches only until one exact terminal result is cached,
then every retry is driver-free. Version 6 adds terminal `exec`. The Guest
executor does not return success until the process crosses `execve`. Before the
completed-response point, replacement dispatches the unchanged Exec once; after
it, recovery recreates the durable live process, rebinds its PID, repairs the
journal, and Host replay avoids another API-driven dispatch. The exact process
ID, terminal mode, generation, request identity, stale/changed fencing, and
nonce-bound replacement marker are required. Version 7 adds `signal-process`.
The first eight points resume one exact signal-10 dispatch after rebuilding the
live Exec. A completed response is already SucceededEmpty, so recovery waits
until the replacement Exec has installed its nonce-bound SIGUSR1 trap, reapplies
the committed signal, and lets Host replay return without another API-driven
dispatch. Exact Exec and signal request identities, stale/changed fencing, and
the replacement signal marker are required. Version 8 adds non-init
`wait-process`: recovery rebuilds and terminates the exact Exec, an uncached
wait dispatches once and stores the signal exit result, and a result committed
before owner loss replays without another driver dispatch. The recovered live
inventory must omit that exited process. Version 9 adds `pause`. Before the
completed-response point, recovery rebuilds an unpaused init and sends the
unchanged Pause once. After a committed response, recovery waits for the fresh
init readiness marker, reapplies the freezer state, and repairs the Create,
Start, and Pause journal PIDs before the Host retry replays without dispatch.
Both Host and Guest reject changed retries and stale generations. Version 10
adds `resume`. Recovery always reconstructs Create, Start, and the
setup Pause after the fresh init writes its exact readiness marker. The first
eight points retain paused durable state and dispatch the unchanged Resume
once. At the completed-response point, recovery also replays the committed
Resume, returns an unpaused recreated process, and repairs Create, Start,
Pause, and Resume response PIDs before the Host retry replays without dispatch.
Both request identities and changed/stale fencing are required. Version 11
adds read-only `processes`. Recovery rebuilds the exact live init and terminal
Exec records before querying the fresh Guest. The replacement inventory must
contain both logical process targets at the original generation with their
rebound PIDs. Read-only responses are not journaled, so the query is reissued
once after every owner loss, including after a completely written first
response. Stale Host and Guest generations fail closed. Version 12 adds
`update`. The exact
OperationId, resolved target, and complete `LinuxResources` request are retained
as one identity. The first eight paths dispatch that request once after the
fresh owner rebuilds init. At the completed-response point, recovery reapplies
the committed resources to the fresh Guest before the Host retry repairs the
cached response PID and returns without another API-driven dispatch. Two
replacement Stats reads must prove the updated memory limit and live monotonic
counters. Changed resources under the same identity and stale Host or Guest
generations fail closed. Version 13 adds read-only `stats` owner replacement.
Recovery first reapplies the already committed setup Update to the fresh
cgroup and repairs its response PID. Stats remains unjournaled, so a new query
must reach every replacement Guest, including after a fully written first-owner
response. Both snapshots must match the exact resource profile, and a delivered
first snapshot must be replaced by newer, distinct evidence. Stale Host and
Guest generations fail closed. Version 14 adds `read-output` replacement.
Recovery rebuilds the exact non-terminal captured-output Exec, repairs the
completed Create, Start, and Exec responses, and sends one fresh cursor request
to every replacement Guest. Version 15 adds `write-stdin` replacement. The
first eight paths resume the prepared Host journal after rebuilding that Exec.
At `guest-after-response-write`, recovery replays the committed bytes into the
fresh process before Host open completes, so the API retry returns from the
durable journal without another driver dispatch. Complete request identity,
exact effect bytes, changed-request conflicts, stale generations, and cleanup
are retained. Versions 16 and 17 add CloseStdin and Resize with the same
Host-first commit boundary. Versions 18 and 19 add File upload and Filesystem
MakeDir with exact v3 Host request retention and typed response replay. The
August 15, 2026 Apple Silicon rerun passed all nine File and Filesystem stages,
18/18 paths, and all 14 journaled `guest-after-response-write` cases. After the
Host commit, the first public call exposes the acknowledgement disconnect;
replacement recovery reconstructs any VM-local effect, Host replay avoids a
second API-driven dispatch, and the Host record permanently fences changed
reuse after Guest reclamation.

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
- protocol-v4 pause/resume state correlation, paused exec rejection, and exact
  live init/exec process inventory;
- protocol-v5 partial resource updates, typed stats, exact target correlation,
  and protocol-v4 filtering and pre-dispatch rejection of forged v5 requests;
- protocol-v6 captured-output cursor pagination and EOF, piped stdin,
  idempotent close, rejected writes after close, exact target correlation, and
  protocol-v5 filtering of forged v6 requests;
- protocol-v7 exact-target terminal resize, positive dimensions, protocol-v6
  capability filtering, and pre-dispatch rejection of forged v7 requests;
- protocol-v8 required process-I/O mutation context, successful exact dispatch,
  missing-context rejection, and rejection of v8 context by protocol-v7 peers;
- protocol-v9 file upload and filesystem-list round trips with exact target
  correlation, plus protocol-v8 capability filtering;
- protocol-v10 acknowledgement routing, pre-v10 no-op compatibility, and
  non-empty, duplicate-free, 4,096-identity batch validation;
- filtering and pre-dispatch rejection of forged version-3 process operations
  on a protocol-v2 connection;
- rejection of a forged protocol-v1 wait before service dispatch;
- two simultaneously registered container IDs with distinct PIDs, independent
  lifecycle transitions, stale-generation fencing, and generation-2 reuse;
- wrong-token and incompatible-version rejection;
- oversized-frame rejection from the header alone;
- configuration-digest tampering;
- request-write failure, response disconnect, response correlation failure,
  and response-shape mismatch, with permanent connection poisoning and
  immediate transport release while client clones remain;
- the complete versioned fault-point registry, all four ordered host operation
  stages, all five guest operation stages, all 189 current operation-stage
  pairs, both host shutdown stages, guest validation-error response stages, and
  post-dispatch create-response loss followed by authenticated exact replay
  with one service effect;
- clone-wide explicit close, idempotent repeat close, and rejection of every
  later request through any retained client clone;
- secret redaction and guest-path normalization.

Windows tests create the real host-side named-pipe endpoint, verify its live
kernel-object owner and protected DACL, reject a second owner of the same name,
generate both an unguessable endpoint nonce and the session token from the OS,
and reject a connected process whose PID is not the expected libkrun shim.
PID verification occurs before the host sends the session token.

Driver-owned WHPX sessions additionally separate the fixed guest system root
from one writable host share. The runtime accepts only the plain directory at
`shares/<container ID>/<generation>`, applies its protected DACL, and passes
only that exact directory to `krun_add_virtiofs` with tag
`a3s-oci-runtime`. The Linux agent must mount it at
`/run/a3s-oci-runtime` before it can read the one-time token or connect to the
host. Shim report schema `a3s.oci.krun-agent-vm-smoke.v7` records the separate
device plus the exact immutable boot assets. On Windows it also records the
current-process handle count immediately before libkrun context creation and
after `krun_start_enter` returns. The Host accepts cleanup only when both
nonzero counts match and the shim marks the inventory restored, so process
teardown cannot hide a leaked WHPX or libkrun handle. Candidate-driver sessions
require the runtime-share evidence and the digest of the selected system-image
manifest. Bundle paths, token files, and recovery-report paths are then
validated below the fixed guest mount rather than below the system root.

macOS tests create a random private directory below `/private/tmp` with mode
`0700`, bind a `0600` Unix socket, reject collisions and symlinks, and remove
both entries on success, rejection, timeout, or drop. After accept, the host
reads `LOCAL_PEERPID` and uses `proc_pidinfo(PROC_PIDTBSDINFO)` to require that
the connected process is the direct worker child of the exact public libkrun
shim. An unrelated peer is rejected before protocol bytes are read. A direct
child with the wrong token is rejected during the following authentication
step.

Linux KVM uses the same one-session Unix endpoint contract below `/tmp`.
`SO_PEERCRED` supplies the kernel-authenticated UID and PID, and the host reads
that PID's procfs status to require the direct worker child of the exact shim.
The shim itself must be the host runtime's direct child and the leader of its
private process group. A pidfd pins the runtime-owner incarnation; owner death
cleans the token handoff and terminates the exact shim/worker group after the
bounded recovery grace.

Before that endpoint or worker can exist, the shared Unix utility-VM driver checks
dedicated-VM isolation, exact generation, and atomic bundle-handoff ownership.
It validates the source directory, ancestry, `config.json` digest, portable
rootfs, and relative bind sources before creating the exact Guest-visible
generation share. A terminal preflight rejection therefore leaves neither a
share nor a launchable VM attachment.

The dedicated Linux KVM path can additionally carry the internal
`a3s.oci.agent-vm-attachments.v2` bootstrap manifest for authorized v2 raw
storage together with a v3 TAP contract. Network-only handoff retains the
byte-compatible v1 schema. The Host writes one canonical, mode-`0600` file in
the protected runtime share and passes its raw SHA-256 as a shim argument. The
manifest binds the exact container generation, Guest bundle, OCI configuration
and public attachment digests; storage mount pointers, caller-owned raw-image
paths, inode/size/access evidence, and deterministic block IDs; plus namespace
and `linux.netDevices` pointers, cleanup identities, source TAP names, and
deterministic Guest MACs. It rejects joined network namespaces and reusable
Guest sessions.

The worker opens the manifest through the descriptor-pinned share, rejects an
unrequested file, and reverifies file identity and content before `/dev/kvm`.
It independently reopens every single-link raw image with `O_NOFOLLOW`, pins
the exact inode and access mode, rejects system-disk alias or serial collision,
and adds a raw virtio-blk device with VMM-enforced read-only state. After
libkrun creates the devices, the Guest consumes only the digest environment
entry, revalidates the mounted bytes and exact bundle, locates storage by
libkrun serial/size/read-only state and NICs by MAC, rewrites only authorized
OCI mount sources, and completes collision-safe interface restoration before
reading the session token or serving protocol requests. The retained binding
then fences the first and replayed Create to that target, bundle path, and
configuration. This bootstrap is outside the Agent request/response wire
protocol, so it does not change protocol v10. The private Linux worker evidence
schema is v4; the public shim report remains
`a3s.oci.krun-agent-vm-smoke.v7`. KVM continues to advertise attachment v1
pending destructive real-host cumulative v2/v3 qualification.

The Linux real-host gate also has a hidden qualification-only failure path. It
uses the normal Host endpoint and one-time token setup, creates the isolated
worker, opens and pins the real `/dev/kvm`, and requires API version 12. Shim
schema `a3s.oci.krun-agent-vm-smoke.v7` then records
`kvm_post_probe_failure_injected=true` and exits before the native VM-entry
call. The Host must observe no bridge or protocol negotiation and must restore
the exact endpoint, shim-process, token-handoff, and runtime-share inventories.
Production session constructors always leave this injection disabled.

The last retained real WHPX `agent-vm-smoke` booted the static musl Linux
agent, carried its CID-host port 4093 connection through libkrun to that
protected pipe, authenticated the token, and negotiated protocol version 9.
That qualified guest advertised the exact 20 workload operations: `create`,
`state`, `start`, `kill`, `delete`, `wait`, `exec`, `signal-process`,
`wait-process`, `pause`, `resume`, `processes`, `update`, `stats`,
`read-output`, `write-stdin`, `close-stdin`, `resize`, `file`, and
`filesystem`. The current WHPX path boots the manifest-bound protocol-v10
image and also requires `acknowledge-operations`; its fresh-host qualification
is still open.
Before the utility-VM owner waits for the shim, it explicitly closes the
shared client transport. This waits for an in-flight request and invalidates
all retained clones, so a forgotten client handle cannot keep the guest or
hypervisor process alive. Terminal protocol failures take the same ownership
boundary immediately: the client drops the shared stream before returning the
error and every retained clone observes the permanently poisoned connection.
The host wraps that owner in one shareable session:
operations receive cloned clients, while concurrent shutdown callers observe
the same cached cleanup report and can never reap the VM more than once.
The WHPX driver converts a successfully reaped live session, or a durable
generation recovered in a new owner process, into a stopped tombstone. This
preserves safe state and delete semantics after owner death. When the shim
retained an authenticated shutdown report, startup also commits its exact init
exit result to the durable wait cache; without valid evidence, wait continues
to fail rather than fabricate a result. A live same-process recovery query
additionally checks the durable configuration digest.

The guest-agent shutdown path now has a separate, versioned recovery artifact
contract. After every owned process has been stopped and the complete executor
cleanup succeeds, it records the exact target generation, canonical
`sha256:` configuration digest, and validated init `ExitStatus`. Records are
sorted, unique, limited to 1,024 entries, encoded in at most 1 MiB, and
authenticated with HMAC-SHA256 under the ephemeral session token. The token is
not included in the artifact. The guest creates the fixed one-time report file
with exclusive `0600` semantics and synchronizes both file and directory.
Missing or partial cleanup produces no usable report. On Windows, the
owner-PID-aware shim stages the one-time path, preserves it throughout the
bounded owner-death grace, rejects reparse points and destinations inside the
per-generation writable share,
verifies the HMAC, removes the guest copy, and atomically commits only the
normalized report into the protected host recovery directory. A protected
empty `.pending` marker exists from VM launch until either that commit or
terminal handoff failure. WHPX remains `probe-only` while real-host
qualification remains pending. The durable
recovery path now reads the normalized report, requires the exact target and
configuration digest, commits the stopped observation, and caches the init
result for repeated wait calls. If a report is absent while its plain pending
marker exists, a replacement host waits through the shim's owner-death grace;
an overrun fails retryably instead of racing ahead. It retains the artifact
across startup faults and deletes it only with the exact container generation.
If both files are absent, recovery keeps the stopped tombstone and `wait` fails
explicitly.

The real macOS `agent-vm-smoke` builds the same agent as a static aarch64 musl
binary, boots it through HVF, maps guest CID-host port 4093 to the verified
Unix stream, and retains both the public shim PID and the direct VM worker PID
in the versioned `a3s.oci.agent-vm-smoke.v10` report schema. The current signed
path negotiates protocol version 10 and the exact 20 workload operations plus
`acknowledge-operations`. The missing-entitlement path
must exit with status `2`, report no negotiation, terminate the shim process
group, and leave no private endpoint residue. Both paths also retain
in-process evidence that the exact runtime-owned endpoint was removed, the
complete current-process descriptor inventory returned to its baseline, and
every observed shim or VM-worker PID disappeared.

The real Windows and macOS `oci-vm-smoke` paths keep the same authenticated
connection open and prove a fixed bundle through create, state, exact create
replay, start, running observation, marker verification, signal delivery,
exact kill replay, a bounded wait while running, exact repeated terminal
status, exact-target exec replay, duplicate process-ID rejection, bounded
per-process wait, exact and replayed process signal, stable repeated process
wait, exact live init/exec inventory, replayed pause/resume, a
progress-producing exec that stops while the cgroup is frozen and advances
again after resume, replay-safe live CPU, memory, cpuset, and PID updates,
normalized cgroup-v2 statistics, captured stdout/stderr with byte-accurate
pagination and EOF, exact replay of piped stdin writes with idempotent close,
rejected writes after close or exit, controlling PTY allocation, initial and resized dimensions,
interactive input, merged terminal output, VEOF close, init-exit cleanup of
another live exec, stopped observation,
stopped-only delete, exact delete replay, and a final
NotFound state query. The marker
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
reads back exact UID/GID maps, then acknowledges the child. Native Linux CI
uses the A3S Box mapping of container root to host UID 100000 and GID 200000
and requires the workload to verify both maps. The wrapper writes and verifies
monotonic/boottime offsets, clears inherited supplementary groups, and switches
to mapped namespace-root UID/GID credentials before rootfs mutation. For a new
PID namespace, a dedicated namespace PID 1 completes
create-time setup and then forks the configured process as PID 2+. The guest
agent authenticates the launcher → PID 1 → configured-process chain and
reports the configured process's host-visible PID. Before returning created
signals use the retained descriptor rather than resolving the numeric PID
again. PID 1 reaps adopted children and terminates every remaining namespace
process after the configured process exits. The host verifies marker removal
and that VM shutdown leaves no new guest-agent runtime directory. Native Linux
and macOS HVF retain the complete user/time, PID-supervision, and advanced
rootfs enforcement evidence. The current Windows WHPX profile retains PID
supervision and the core pivot/mount lifecycle but deliberately omits user and
time namespaces plus recursive and ID-mapped mount claims; its same-VM
multi-container report therefore uses the distinct
`a3s.oci.windows-oci-vm-multi-container-smoke.v1` schema.

The same create plan now retains the configured capability and seccomp
security ceiling plus its owned cgroup-v2 topology. Every later exec applies
exact capability sets, joins the selected workload target, and installs the
same architecture-bound seccomp policy immediately before `execve`. Init also
joins that target in the default layout. With `control-workload-v1`, init
starts in the outer envelope, creates the cgroup namespace there, moves into
the control child through its pre-opened descriptor, and crosses the create
barrier before the runtime delegates controllers. OCI exec joins the workload
child directly. The
bounded A3S Box profile additionally creates and verifies its exact device
nodes after the `/dev` mount. These controls have focused Linux tests;
complete native/utility-VM lifecycle evidence remains a promotion gate.

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

The configured workload now uses the same dedicated-process-group ownership.
Container-wide kill authenticates live configured and exec leaders through
their retained pidfds, signals every exec group before the configured group,
and records the exact result for replay. Fork supervisors and namespace PID 1
retain exited leaders with `waitid(WNOWAIT)` until descendant cleanup, while a
direct launcher remains wait-owned by the executor. The numeric process-group
target therefore cannot be reused during delivery. A cross-process advisory
lease on the private process directory serializes pidfd validation plus group
delivery against the supervisor's final cleanup and reap.

Terminal execution adapts the existing A3S Box PTY mechanism: `openpty`
allocates the pair, the launcher creates a session and acquires the slave as
its controlling terminal, and the workload process group becomes foreground.
OCI Runtime keeps its own Tokio backpressure and byte-cursor output buffer
around that proven descriptor model.

The macOS `oci-vm-multi-container-smoke` path keeps two exact targets live on
the same connection. It proves distinct runtime slots and PIDs, simultaneous
create barriers, A/B transition isolation, session-local generation fencing,
exact operation replay, rejection of cross-container operation-ID reuse, a
bounded wait on A that does not block B state, exact repeated terminal results
for both containers, and independent pidfd-backed cleanup. Its schema-v9
namespace phase retains a prepared donor, rejects a wrong-type namespace
descriptor before state, joins all eight Linux namespace types across two
workloads, proves retained-rootfs execution after the mount join, and removes
all state without changing the donor's created record. A third workload proves
missing mount-target creation at the create barrier, shared rootfs propagation,
read-only and masked path enforcement, recursive VFS attributes across a nested
submount, detached `idmap` and `ridmap` filesystem ownership, read-only rootfs
behavior, PID 1 supervision, adopted-orphan reaping, exact normal exit, state
removal, and fixture cleanup. Native Linux runs the equivalent schema-v11
sequence through the durable SDK service and additionally proves ID-mapped
bind recursion without changing the source tree.

The `oci-vm-fault-cleanup` companion stops after a successful create, start, or
kill request and never sends delete. Session EOF must still make the agent call
`LinuxExecutor::shutdown`, force-stop any retained configured process and its
namespace supervisor, remove the executor root, and exit successfully. The
host retains the exact requested and injected boundary together with
guest-runtime and platform cleanup evidence.

The private parent/init control channel reports a user-mapping request, a
pre-pivot hook barrier, final create readiness, start-time exec confirmation,
or a bounded typed SDK error. Both create barriers carry the positive
runtime-visible configured-process PID and optional namespace-init PID. The
parent validates the kernel-reported launcher peer PID before reading any
outcome. It permits the mapping request only when the exact plan requires one,
acknowledges it only after verified writes, and rejects a bypass or repeat. At
the first barrier it verifies both parent links, the PID 1 and PID 2+ `NSpid`
mappings, both PID namespace links, and the requested user/time namespace
identities before running runtime-namespace hooks. It releases
`createContainer` with a distinct byte and accepts final readiness only when
both reported PIDs match the authenticated first barrier. The start release is
separate again. The wrapper marks the control descriptor close-on-exec; EOF
proves the successful exec transition, while any pre-exec or start-hook error
is returned as the exact bounded rejection. Create/start failures therefore
retain their error class and context without trusting a pathname socket.

Native Linux additionally exposes an in-process create method for A3S Box
control descriptors. The host validates two listening Unix stream sockets and
one writable regular file, duplicates collision-safe close-on-exec sources
above targets 3/4/5, and installs those exact targets in the prepared child
with `dup2`. Only the stable logical role/type/target schema participates in
host and executor idempotency fingerprints. Raw FD and inode identities are
never serialized into `AgentCreateRequest` or any protocol frame; the ordinary
wire-service `create` always uses an empty descriptor plan.

This is the first Linux executor vertical slice, not complete OCI
enforcement. A pinned immutable system image, rootless ID mapping, advanced
mount semantics and resources, hook
rollback/recovery/security-negative suites, exhaustive recovery injection,
broader negative isolation cases, and full platform-specific lifecycle
evidence remain required before a utility-VM driver can advance beyond
`probe-only`.
