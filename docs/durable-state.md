# Durable State

The runtime has a driver-independent persistence boundary for OCI lifecycle
work. Idempotency, generation fencing, failure replay, and crash behavior do
not depend on a particular hypervisor or Linux executor.

`HostRuntimeService::open` advertises the durable core lifecycle only when an
explicit `RuntimeDriver` reports launch-ready status and the requested
isolation class. The default service and every built-in platform probe still
advertise only `features`; no production executor is available yet.

## Root Contract

The state root:

- must be an absolute UTF-8 path whose parent already exists;
- is canonicalized once, opened without following its final component, and
  retained as a fixed directory capability;
- resolves descendant traversal, reads, enumeration, directory creation, file
  creation, replacement, and quarantine moves from retained directory handles;
- rejects a root, layout directory, record, or transaction file that is a
  symbolic link or a Windows reparse point;
- rejects a descendant directory or file on another device, rejects a changed
  Linux mount ID even on the same device, and compares the macOS `fstatfs`
  filesystem identity;
- permits exactly one runtime writer through a cross-process exclusive lock;
- bounds every state file to 64 MiB;
- uses `0700` directories and `0600` transaction files on Unix;
- creates Windows directories with the runtime principal as owner and a
  protected DACL, grants full access only to that principal and LocalSystem,
  disables inherited access, and verifies the owner plus every applied ACE
  type, mask, flag, and principal;
- commits files by atomic rename plus directory sync on Unix;
- commits an already-open file or directory handle with
  `NtSetInformationFile(FileRenameInformation)` relative to the retained
  destination-parent handle on Windows;
- audits every runtime-owned namespace and committed cross-record identity
  before returning an opened store.

A Windows state root therefore requires a filesystem with persistent ACL
support. Opening the root fails closed when ownership or the protected DACL
cannot be applied and read back exactly.

After the root is pinned, replacing its ambient path does not redirect state
mutations. macOS and Linux tests cover ambient-root renaming, layout-directory
symlink replacement, transaction-file symlink replacement, and foreign mount
handles. A privileged Linux gate additionally bind-mounts a same-device
replacement over a live layout directory inside a private mount namespace;
`statx` mount identities make the operation fail before external mutation.
macOS uses `fstatfs` identity for the same boundary.

Windows CI covers a reparse-point root, layout-directory and transaction-file
substitution, source-name replacement after the source file is opened, racing
destination replacement, retained root and lock handles, and exact-handle
directory moves. It also holds an existing destination without delete sharing,
then proves file replacement survives the transient lock. Replacement retries
only Windows access, sharing, and lock violations for a bounded one second;
other errors fail immediately. Each case fails closed or commits the pinned
object without touching the external target.

The implementation uses the security descriptor supplied directly to
[`CreateDirectoryW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
for first directory creation. It applies and verifies directory DACLs with
[`SetNamedSecurityInfoW`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow),
and
[`GetNamedSecurityInfoW`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow),
while transaction-file DACLs are applied and verified through the already-open
handle with
[`SetSecurityInfo`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
and
[`GetSecurityInfo`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).

## Layout

```text
runtime-root/
|-- .lock
|-- root.json
|-- containers/
|   `-- <container-id>/
|       |-- config.json
|       |-- record.json
|       `-- processes/
|           `-- <process-id>.json
|-- generations/
|   `-- <container-id>.json
|-- operations/
|   `-- <operation-id>.json
|-- events/
|   |-- sequence.json
|   |-- keys/
|   |   `-- <sha256-event-identity>.json
|   `-- records/
|       `-- <20-digit-sequence>.json
`-- quarantine/
    |-- <operation-id>.deleted/
    |-- <operation-id>.failed-create/
    `-- <operation-id>.failed-restore/
```

All identifiers are validated SDK types before they become path components.
Validation rejects separators, traversal, trailing dots, and Windows reserved
device names on every host so a request has one portable identity.
Every JSON record carries an explicit schema version and redundant identity
fields. Reads reject mismatched schemas, identities, generations, OCI state,
or configuration digests.

`containers/<id>/config.json` is the exact byte-for-byte configuration
accepted from the SDK. The typed bundle is reconstructed from that snapshot
and its SHA-256 digest is checked against the container record.

## Lifecycle And Process Transactions

Create uses two durable stages:

1. `prepare_create` validates the complete request and deadline, checks the
   global operation journal, allocates the next generation, stores an exact
   configuration snapshot, and records OCI `creating`.
2. The selected driver prepares a real configured-process wrapper without
   running the user program. `complete_create` then requires its positive PID
   and atomically records OCI `created` before storing the exact successful
   response.

The create request digest excludes retry metadata but includes container ID,
bundle, isolation request, and the complete versioned attachment manifest,
including process I/O and any stable inherited-descriptor schema. The A3S Box
schema records the exec-listener, PTY-listener, and init-log roles,
kernel-object types, and targets 3/4/5; it deliberately excludes ephemeral
source FD numbers and inode identities so an exact retry after host restart may
reopen equivalent resources. A v4 SharedGuestKernel record also retains the
exact guest-session binding outside the digest for direct state and recovery
evidence. An OAR-01 record likewise retains the opaque enforcement and optional
local-redirect incarnation in `ContainerRecord::network_enforcement`. Loading
requires each explicit field to equal the durable manifest and configuration
annotation. Reusing an `OperationId` for a different request, changing either
incarnation, or omitting a previously attached schema fails with
`failed-precondition`. A matching prepared operation resumes the original
generation; a matching completed operation returns its exact recorded response.

For the non-advertised reusable Utility-VM profile, the driver additionally
stores one owner-death report per guest-session incarnation rather than per
first container. Every durable member resolves the same bounded report and
selects only its exact container generation and configuration digest. Driver
shutdown closes the shared owner once, converts each live member to an exact
stopped tombstone, and keeps the session root until the final tombstone
cleanup. Production drivers do not expose this profile until real-host restart
and leak qualification is retained.

Start, kill, pause, resume, update, delete, File upload, Filesystem
mkdir/move/remove, checkpoint, restore, and TEE attestation use the same global journal and
request fingerprinting. Mutations of an existing container claim its exact
record so a second mutation cannot race the driver call. Start revalidates the
durable configuration snapshot, not the caller's mutable source bundle, before
recording an intent. Pause and resume preserve the standard OCI `running`
status and store freezer state in the reserved
`dev.a3s.oci.runtime.paused=true` state annotation. Checkpoint requires that
paused running state, refuses any active init or exec mutation/I/O, and prevents
new process I/O until its exact response or terminal error is durable. Restore
checks for a committed replay first, validates the immutable caller artifact
and exact compatibility without lifecycle effects, and only then allocates and
claims a new `creating` generation. Success commits a positive driver PID as a
paused `running` record. Update fingerprints the complete OCI `LinuxResources`
patch and returns the exact observed container record on replay. Delete
atomically moves the owned container directory into quarantine rather than
recursively deleting an unresolved path.

TEE attestation first validates one exact created or running dedicated-VM
generation and its durable launch extension without writing a journal. It then
claims the container, dispatches the exact 64-byte report-data binding to an
explicitly capable driver, and commits the complete typed evidence response
and `ContainerAttested` event before acknowledging driver replay state.
Success replay never dispatches the driver. A changed target or report-data
value under the same operation ID fails closed.

New journals use `a3s.oci.operation.v6` and SHA-256 over canonical JSON with
every object key sorted, so unordered OCI resource maps retain the same
identity after process reconstruction. Version 3 retains the complete
validated request and typed response for File and Filesystem mutations;
version 4 adds the exact normalized checkpoint request and immutable typed
response; version 5 adds the complete restore request, generation, and paused
typed response; and version 6 adds the exact TEE attestation request and
immutable evidence response. Existing `a3s.oci.operation.v1` through
`a3s.oci.operation.v5` journals remain loadable and validate supported retries
with their original schema and digest rules. Restore is accepted in v5 and
v6; attestation requires v6.

Drivers must be idempotent by `OperationId`. A retryable driver error leaves
the intent active for an exact retry. A terminal error is stored and replayed
exactly; it releases a start, kill, pause, resume, update, delete, exec,
checkpoint, attestation, or per-process signal, write-stdin, close-stdin,
resize, File, or Filesystem claim, while a failed create or restore is moved out of the live
namespace before its ID can be reused. A checkpoint driver must remove only
its own unpublished partials before returning a terminal error. A restore
driver must remove its runtime-owned process and attachment effects while
leaving the caller artifact untouched; the Host then journals the failure and
quarantines that attempt's exact generation. Retryable or unvalidated evidence
keeps the durable operation resumable.

Exec uses the same global operation journal. Preparation reserves the
generation-scoped process ID before driver dispatch, so duplicate IDs fail
without a driver side effect. Completion stores the authenticated PID and
terminal flag in `processes/<process-id>.json`; the operation journal returns
that exact `ProcessRecord` on replay. A terminal exec failure releases the
process claim and is replayed exactly.

Per-process signal also uses the global journal and claims the exact process
record before driver dispatch. Its completion and terminal-failure paths both
release that claim. Delete refuses to move a container while a process
mutation is active. Init and exec wait are observations rather than operation
journal entries, but their first terminal result is cached in the container or
process record and returned unchanged after repeated calls and host-service
reopen.

Write-stdin, close-stdin, and resize use the same global journal. Their request
fingerprints include the exact process target plus the complete bytes or
terminal dimensions. The init container record or exec process record is
claimed before driver dispatch; successful and terminal outcomes release the
claim and replay unchanged after host-service reopen. A retryable error keeps
the intent resumable. Drivers receive the same `OperationContext` and must
deduplicate a call that completed before the host committed its outcome.

File upload and Filesystem mkdir/move/remove retain the complete validated SDK
request because a replacement utility-VM owner may need it to reconstruct an
effect that was committed in the previous VM. Read-only File download and
Filesystem stat/list remain direct observations. A completed mutation stores
its typed response and acknowledges the driver only after that response is
durable. Reusing the OperationId with any changed path, user, payload, target,
or operation is rejected by the Host even after the Guest replay record has
been acknowledged and reclaimed.

Queries may target the current container generation or provide an exact
generation fence. A stale fence fails with `conflict`. `list` takes the same
store gate as lifecycle mutations, enumerates only live `containers/<id>`
records, validates each complete record and configuration snapshot, applies an
optional exact isolation-class filter, and sorts the result by container ID.
It never dispatches the driver. A malformed or unexpected entry fails the
whole snapshot instead of being hidden from recovery callers.

## Ordered Runtime Events

The configured host also owns the runtime event stream; polling it never
dispatches a driver or guest operation. Lifecycle, freezer, resource, exec,
attestation, and wait reconciliation append exact-generation events under one global,
nonzero sequence. A deterministic identity binds each logical event to its
first sequence and contents, so retrying an operation or reopening the host
cannot duplicate it.

An append advances `events/sequence.json`, persists the identity claim under
`events/keys/`, and then persists the sequence record under
`events/records/`. This order permits a sequence gap after an interrupted
cursor advance. A retained claim whose record is missing is repaired before
polling, while an unclaimed record, duplicate claimed sequence, invalid event
kind/process pairing, or conflicting replay fails closed. The operation
outcome is committed only after its required events exist.

Every operation-scoped event now binds its exact mutation through typed
`RuntimeEvent::operation_id`. New records also retain the legacy
`attributes["operation-id"]` projection, and the two values must match the
operation ID encoded by the durable event-claim identity. Existing event-v1
records without the typed field remain readable when that compatibility
attribute is exact. A missing or conflicting identity on a new record, or any
claim/record identity drift, fails startup audit and event polling instead of
silently attributing the observation to another mutation.

`EventsRequest.after_sequence` is an exclusive cursor. Polling returns at
most the requested bounded number of matching events and a `next_sequence`
that can advance across events excluded by a container filter. A target
without a generation matches all retained generations for that container ID;
an exact target matches only that generation. An optional timeout enables
long polling without changing cursor or replay semantics.

## Crash Boundary

Each record replacement is individually crash durable. Core reconciliation
handles these interrupted states:

- a crash after generation allocation may leave an unused generation;
- a prepared create rebuilds a missing or partial configuration/record pair
  from the digest-matched request before the driver is called;
- a prepared restore rebuilds the same request-bound configuration/record pair
  and resumes only after the caller artifact is revalidated;
- a prepared operation is returned as resume work and is reconciled through
  the idempotent driver;
- a created record whose success journal was not committed can be completed
  idempotently with the same PID;
- an observed running/stopped driver state can finish an interrupted start or
  kill journal;
- an observed exact frozen/thawed driver state can finish an interrupted pause
  or resume journal without repeating a completed freezer transition;
- an interrupted update resumes the exact resource request, while a completed
  or failed update replays its exact durable outcome;
- a moved delete tombstone completes an interrupted delete journal;
- a claimed runtime event with a missing sequence record is reconstructed,
  while a cursor-only advance remains an intentional permanent gap;
- a process record created before its exec operation outcome is reconciled
  into the exact successful process result;
- an exec or per-process signal claim interrupted before driver dispatch is
  resumed without allocating another process identity;
- an interrupted write-stdin, close-stdin, or resize intent resumes through an
  idempotent driver, while a committed result replays without driver dispatch;
- an interrupted File or Filesystem mutation resumes from its retained exact
  request, while a committed typed response replays without driver dispatch;
- an interrupted attestation resumes through the driver with the same exact
  report data and operation ID, while committed evidence or a terminal error
  replays without driver dispatch;
- cached init and exec terminal results survive host-service reopen;
- a terminal create failure completes quarantine before replaying its exact
  error;
- a terminal restore failure completes its distinct quarantine move before
  replaying the exact error, while a committed success replays without touching
  the artifact;
- malformed or digest-mismatched records fail closed.

## Fault Injection Contract

Every lifecycle write is routed through one typed `DurableMutation` registry.
The registry currently contains 127 semantic mutations. One hundred twenty-four
atomic file replacements are exercised at all seven commit stages:

1. temporary file creation;
2. private permission or ACL application;
3. data write;
4. flush;
5. file sync;
6. atomic replacement;
7. parent-directory sync.

The delete, failed-create, and failed-restore quarantine moves are each
exercised after the rename, source-parent sync, and destination-parent sync.
This expands to 877 durable fault points. The host matrix separately injects
before and after all 26 `RuntimeDriver` boundaries, including capability
discovery, startup recovery, file transfer, filesystem operations, checkpoint,
restore validation, restore execution, and attestation, for another 52 boundaries.

On Unix the final file and directory boundaries follow explicit directory
`sync_all` calls. Windows reaches the same logical checkpoints after its
flushed and synced source handle is renamed relative to the retained
destination-parent handle with `NtSetInformationFile` because a separate
directory sync primitive is not used there.

Each test fails exactly once, drops the store or host service, reopens the same
state root, and replays the original operation. Recovery must preserve
monotonic generations and exact operation results, complete or safely resume
journals, avoid duplicate live and quarantined generations, and remove every
`.next` transaction file. The matrices run in Linux, macOS, and Windows CI.
Production uses a non-configurable no-op injector.

Before the store can serve a request, startup enumerates the complete durable
state graph. It rejects unexpected root, container, process, quarantine, and
event entries; filename/payload identity drift; operations without an
allocated generation; duplicate creation owners; live records below or beyond
their generation fence; missing Create/Restore or Exec ownership; incompatible
active claims; malformed configuration or attachment evidence, including
mismatched v4 guest-session, OAR-01 network-enforcement, or TEE launch records;
successful attestation evidence that differs from its exact durable source; quarantine
entries that disagree with their operation; one generation present both live
and quarantined; and event records without an exact identity claim. Quarantined
container snapshots and their process namespaces receive the same record and
configuration validation as live state.

The audit preserves the states created by documented commit ordering. An
allocated generation may have no operation after interruption, a prepared
Create or Restore may have no complete live record, a failed creation may
retain its live claim until quarantine replay, an event cursor may contain a
gap, and a committed event claim may await its sequence record. Plain, validly
named `.next` files also remain available to the operation that owns recovery.

Startup now audits each durable driver binding and calls only that exact
driver's idempotent recovery hook. An optional observation is committed through
the normal durable state transition before requests are accepted. A stopped
observation may also carry an exact init exit result, which is committed
through the same durable wait cache used by a live driver. The WHPX candidate
loads that result only from its shim-authenticated, protected report after
matching the exact generation and durable configuration digest. The source
report remains available across before/after recovery faults and is removed
only with container deletion. A host-only pending marker closes the race with
an old shim still publishing its report: startup waits through the bounded
owner-death grace and returns a retryable error if it overruns. If neither a
report nor marker exists, recovery still yields a stopped cleanup tombstone
without fabricated exit evidence.

The remaining persistence gates are real-host qualification of restart-stable
WHPX exit evidence (or qualified reattachment where another driver promises
it) and equivalent real-driver replacement evidence outside HVF. The portable
matrix already reopens the durable host
around a new authenticated connection and driver at all nine request/response
stages for create, state,
start, kill, delete, wait, exec, signal-process, wait-process, pause, resume,
processes, update, stats, read-output, write-stdin, close-stdin, resize, file,
and filesystem, retaining all 180 operation-stage pairs. Durably journaled host
mutations distinguish pre-dispatch execution, post-dispatch guest replay, and
completed durable-host replay while preserving the same generation and one
effect. After a success or terminal failure is durable, the Host invokes the
driver acknowledgement hook. Native Linux releases the local replay record;
protocol-v10 utility-VM drivers send the exact Guest identity or every derived
stdin chunk identity. If the operation response reached the Host but the
connection closed before acknowledgement completed, the first API call returns
a retryable transport error even though the Host result is durable. Reopen
replays that result without driver dispatch and retries the acknowledgement on
the replacement connection. Protocol-v1 through protocol-v9 Guests keep the
compatibility no-op. Exec additionally preserves its exact process ID, guest
PID, and terminal mode;
signal-process preserves that exact process target and the delivered signal;
pause and resume preserve the running state and commit the matching freezer
flag exactly once, including when the first guest effect preceded the lost
response; update preserves the complete OCI `LinuxResources` request and one
exact resource effect; write-stdin preserves the exact process target,
operation context, input bytes, and one input effect; close-stdin preserves the
exact process target and operation context with one close effect; resize
preserves the exact terminal process target, operation context, dimensions, and
one resize effect. File upload and Filesystem mkdir/move/remove now use that
same Host boundary: their v3 records retain the exact request and typed result,
their Guest replay records are released only after the Host commit, and a
completed Host result survives service and VM-owner replacement without a
second API-driven dispatch. The Host keeps the permanent request fingerprint,
so changed content or paths fail with `failed-precondition` after Guest
acknowledgement; stale generations fail before Host dispatch and at the Guest
boundary.

For journaled mutations, `guest-after-response-write` means the Guest response
reached the Host driver, not the public caller. The Host commits that result,
then the acknowledgement observes the closed connection and the public call
returns retryable `unavailable`. A replacement owner reconstructs any
VM-local committed effect during recovery, serves the exact Host result, and
acknowledges the recovered Guest record. Read-only operations still deliver
their first response before a follow-up request exposes the disconnect.
Read-only state, process inventory, normalized stats, and captured-output polls
resolve a current target to the exact durable generation and are safely
reissued after reopen, including after a fully written first response. Process
inventory retains the same exact live init and exec identities, stats retain
their validated timestamp, CPU, memory, process-count, and named metrics, and
output retains its inclusive byte cursor, limit, and contiguous stream chunk
without changing durable state. Init and exec waits
are reissued only until the host receives and durably caches one exact terminal
result; a fully written response and every later retry replay that cache without
another driver dispatch. Stale observation targets fail before host driver
dispatch and at the guest boundary. A fully completed delete leaves no live
container record, so service reopen skips driver recovery and replays the
durable delete journal directly.

The real utility-VM slice now interrupts `create` at all nine Host/Guest
request, dispatch, and response stages and crosses both explicit Host shutdown
points inside fresh authenticated HVF VMs. It retains the exact protocol-v9
point and retryable disconnect, skips normal delete, and requires nonce-bound
Guest cleanup evidence where applicable, VM and process reap, endpoint removal,
an unchanged runtime-root inventory, and complete Host descriptor restoration.
Twenty-four fresh local VMs passed the repeated Host request-response v2 gate
and five more passed its Guest gate. The final v3 requalification passed all
eleven stages in eleven fresh VMs.

All nine Host/Guest Create transitions now pass through the durable layer on
real HVF. Eight paths close the first VM while the original OperationId and
generation remain in `creating`; a new `HostRuntimeService` and distinct
VM/session owner reopen that record and complete the same Create. At
`guest-after-response-write`, the Host has committed `created`, but its Guest
acknowledgement observes the closed connection and the API returns retryable
`unavailable`. Replacement recovery rebuilds that pre-start process and uses
the explicit `DriverRecovery::recreated_created` contract to reconcile its
exact PID. The next Create replay repairs and returns the recovered record
without a second API-driven Create dispatch, then retries acknowledgement.
Ordinary recovery observations still reject PID drift.
Both the record rebind and journal repair recover across every durable
file-commit fault stage.
Every `a3s.oci.oci-vm-reopen-replacement.v2` path then force-deletes the
generation and leaves no durable container or transient Host/Guest resource.

Real State recovery now crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v1`. The first query never changes
the durable `created` record. Once that VM has closed, the replacement recovery
hook recreates the pre-start process and commits its exact PID through the
restricted record-rebind path above. A new State query must equal that recovered
record and preserve the generation before force delete. The August 10, 2026
Apple Silicon matrix passed all nine stages in 18 fresh VMs.

Real Start recovery now crosses all nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v2`. The first eight interruptions
leave the exact durable record in `created`; recovery rebuilds that process and
the unchanged Start identity completes once through the replacement owner. A
fully written response leaves `running`. Recovery then recreates and starts the
process, rebinds its new PID, and repairs both completed Create and Start journal
responses. Replaying Start returns that repaired durable response without a
second API-driven dispatch. Every path removes any first-owner marker before
replacement, verifies the replacement workload's exact marker, force-deletes
the generation, and restores both Host and Guest inventories. The August 10,
2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs. On August 30,
2026, clean revision `3bbdeda` also passed all nine stages on x86_64 Linux KVM,
including Running reconstruction and durable replay without another
API-driven Start dispatch at `guest-after-response-write`.

Real Kill recovery now crosses all nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v3`. The first eight interruptions
leave the durable record in `running`. Recovery recreates and starts the
workload with the original Create and Start identities, rebinds the new PID,
repairs both completed setup responses, and sends the unchanged signal-9 Kill
once. A fully written Kill response leaves `stopped`; recovery recreates,
starts, and kills the replacement workload to reconstruct the Guest tombstone,
then replays the completed durable Kill journal without another API-driven
driver dispatch. Every path verifies the replacement marker before Kill, uses
stopped-only Delete, and restores both Host and Guest inventories. The August
10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs. On August
30, 2026, clean revision `336bd5e` also passed all nine stages on x86_64 Linux
KVM, including Stopped tombstone reconstruction and completed-journal replay
without another driver dispatch at `guest-after-response-write`.

Real Delete recovery crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v4`. The first eight interruptions
retain the stopped record and a Prepared Delete journal. Replacement recovery
recreates, starts, and kills the workload with the original setup identities,
rebuilds the Guest tombstone, and dispatches the unchanged stopped-only Delete
once. A fully written response instead retains no live record and a
SucceededEmpty journal, so the replacement owner performs no workload recovery
or driver Delete. Every path restores both Host and Guest inventories. The
August 10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs. On
August 30, 2026, clean revision `3227ace` also passed all nine stages on x86_64
Linux KVM, including the distinct empty-owner replay with zero workload
recovery and zero driver Delete dispatch at `guest-after-response-write`.

Real init Wait recovery crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v5`. The first eight interruptions
retain the stopped record without cached terminal evidence. Replacement
recovery rebuilds the Guest tombstone and dispatches the exact Wait target once,
then durably caches `signal=9, oom_killed=false`. A fully written response
already has that cache, so Host reopen and later Wait calls replay it without a
driver or Guest dispatch. Stale generations fail at both Host and Guest
boundaries. The August 10, 2026 Apple Silicon matrix passed all nine stages in
18 fresh VMs. On August 30, 2026, clean revision `b491195` also passed all nine
stages on x86_64 Linux KVM. Its first eight paths rebuilt the stopped Guest
tombstone and dispatched the exact Wait once; `guest-after-response-write`
retained the terminal cache and replayed replacement and later Wait calls with
zero driver dispatch. The retained aggregate has SHA-256
`9f4c163c2d3116c8b2fae8bb1739b048b43160dd01f32b9163cad4c99c8ada10`.

Real terminal Exec recovery now crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v6`. Before returning success, the
Linux executor waits for the target process to cross `execve`; typed pre-exec
failures return through the control barrier. The first eight interruptions
retain a Prepared Exec journal and a prepared process record with no live PID.
Replacement recovery recreates and starts init, then the unchanged Exec request
completes once. A fully written response instead retains the exact live
`ProcessRecord` and Succeeded journal. Replacement recovery recreates both processes, rebinds
their Guest PIDs, repairs the completed journals, and lets the Host replay
return without another API-driven dispatch. The process ID, terminal mode, and
complete request identity remain fenced; stale or changed Host and Guest
requests fail closed. A first-owner marker is validated when scheduling reaches
it, while every replacement must run the long-lived terminal process and write
the exact nonce-bound marker before force delete. The August 10, 2026 Apple
Silicon matrix passed all nine stages in 18 fresh VMs.

Real SignalProcess recovery crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v7`. Setup first commits one
long-running terminal Exec whose SIGUSR1 trap writes a nonce-bound marker. The
first eight interruptions retain a Prepared SignalProcess journal; replacement
recovery recreates init and Exec, and the unchanged signal-10 request dispatches
once after reopen. A fully written response retains SucceededEmpty instead.
Recovery waits for the replacement Exec readiness marker, reapplies the
committed signal, and the API retry replays without driver dispatch. Every path
fences the complete Exec and signal identities plus stale generations, rejects
changed Host and Guest retries, requires the replacement signal marker, and
restores all inventories. The August 11, 2026 Apple Silicon matrix passed all
nine stages in 18 fresh VMs.

Real non-init WaitProcess recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v8`. Setup commits Create, Start,
a terminal Exec, and signal 10. Replacement recovery recreates init and Exec,
waits for the Exec readiness marker, and reapplies the committed signal. For
the first eight transport interruptions the Host has no process-exit cache, so
the exact resolved target and 15-second timeout dispatch once after reopen and
cache `signal=10, oom_killed=false`. At `guest-after-response-write` that cache
already exists: recovery does not register the rebuilt exited Exec as live,
and both replacement and later WaitProcess calls return without driver
dispatch. All nine Apple Silicon stages passed in 18 fresh VMs on August 11,
2026.
On August 30, 2026, clean revision `4338d37` also passed all nine stages on
x86_64 Linux KVM. Its first eight paths rebuilt and terminated the exact Exec
before dispatching the resolved WaitProcess once; `guest-after-response-write`
retained the process-exit cache and replayed replacement and later waits with
zero driver dispatch. The retained aggregate has SHA-256
`af1f5001f82fdd7f05a1a3f2971f6ea1b8e9a0292aa62465b03dda5df4297ac4`.

Real Pause recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v9`. Setup commits Create and
Start, then waits for the exact nonce-bound init marker before injecting Pause.
The first eight interruptions retain an unpaused running record and Prepared
Pause journal. Recovery recreates and starts init, rebinds its PID, repairs the
completed Create and Start responses, and dispatches the unchanged Pause once.
At `guest-after-response-write`, durable state is already paused and the Pause
journal is Succeeded. Recovery recreates and starts init, waits for readiness,
reapplies the freezer state, and uses the restricted paused-process recovery
mode to rebind the durable record. Create, Start, and Pause replays then repair
their cached PIDs; the Pause API retry does not dispatch again. Every path
rejects changed and stale Host and Guest requests, force-deletes the paused
generation, and restores both owner inventories. All nine Apple Silicon stages
passed in 18 fresh VMs on August 11, 2026.
On August 30, 2026, clean revision `3e9fc4b` also passed all nine stages on
x86_64 Linux KVM. Its first eight paths rebuilt an unpaused init before one
unchanged Pause dispatch; `guest-after-response-write` reapplied the committed
Pause during recovery and replayed the Host response with no additional
API-driven dispatch. The retained aggregate has SHA-256
`2b76d5fbd0620dee152d97572ab1bcbf0bed42e39a18a87d03415039405cc271`.

Real Resume recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v10`. Setup commits Create,
Start, and Pause before injecting Resume. Every fresh owner recreates and
starts init, waits for its nonce-bound readiness marker, and replays the setup
Pause. The first eight interruptions retain paused durable state and a Prepared
Resume journal, so the unchanged Resume dispatches once after reopen. At
`guest-after-response-write`, durable state is already unpaused and the Resume
journal is Succeeded; recovery therefore replays the committed Resume too and
returns recreated-running evidence. Reconciliation preserves each historical
freezer response while rebinding Create, Start, Pause, and Resume to the new
PID. Every path rejects changed and stale requests, force-deletes the resumed
generation, and restores both owner inventories. All nine Apple Silicon stages
passed in 18 fresh VMs on August 11, 2026.
On August 30, 2026, clean revision `b4c3a85` also passed all nine stages on
x86_64 Linux KVM. Its first eight paths reconstructed paused state before one
unchanged Resume dispatch; `guest-after-response-write` reapplied the committed
Resume during recovery and replayed the Host response with no additional
API-driven dispatch. The retained aggregate has SHA-256
`5a1bc69dd639a09fd6bc04b9250dd90dfd48b5d64b1b85b7762f14fac4647b4a`.

Real Processes recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v11`. Setup commits Create,
Start, and one live terminal Exec. The replacement owner recreates both live
processes, rebinds the durable init and Exec PIDs, and repairs all completed
setup responses before the query runs. Processes has no durable response
journal: all nine replacement paths therefore dispatch the read-only query
once, including `guest-after-response-write`. The returned inventory must
contain exactly the original init and Exec targets at the retained generation
with the replacement PIDs. Stale Host and Guest generations fail closed, then
force delete and owner shutdown restore all inventories. All nine Apple
Silicon stages passed in 18 fresh VMs on August 11, 2026.
On August 30, 2026, clean revision `9a1a37c` also passed all nine stages on
x86_64 Linux KVM. Every replacement owner recreated the live init and terminal
Exec with rebound positive PIDs before one exact Processes query;
`guest-after-response-write` queried the replacement after the first owner had
delivered a verified two-record inventory. The retained aggregate has SHA-256
`7b0d940c5aa1f68a9c9bbfab925e9a3385ee4ea4560dd17ff86798a1c18e66de`.

Real Update recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v12`. Setup commits Create and
Start, then waits for the nonce-bound init marker before injecting the exact
resource request. The first eight interruptions keep the Update journal
Prepared. Recreated-running recovery preserves that active claim, rebinds the
container plus completed Create and Start response PIDs, and the unchanged
Update dispatches once. At `guest-after-response-write`, the Update journal is
already Succeeded, but its cgroup effect belonged to the dead VM. Recovery
therefore reapplies the original complete `LinuxResources` request before
opening the Host service. The retry reconciles the completed Update response to
the replacement PID without dispatching again. Two fresh Stats responses prove
the 512 MiB limit and monotonic counters; changed resources and stale
generations fail closed at both boundaries. All nine Apple Silicon stages
passed in 18 fresh VMs on August 11, 2026.
On August 31, 2026, clean revision `aa0f56a` also passed all nine stages on
x86_64 Linux KVM. The first eight replacement owners dispatched the unchanged
complete Linux resource request once; `guest-after-response-write` reapplied
the committed Update during recovery and replayed the Host response without an
additional API-driven dispatch. Direct Guest Stats verified the 512 MiB limit
and live counters after every replacement. The retained aggregate has SHA-256
`61e7ccbf5c3181cce6fb0c62d1a36ad576e9860a58bcc54f8cd5bc41a766a052`.

Real Stats recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v13`. Setup commits Create,
Start, and the exact complete Update before the read-only query. Every
replacement owner recreates the running init, waits for its readiness marker,
reapplies that Update to the fresh cgroup, and rebinds all three completed
setup responses. Stats has no durable response journal, so all nine replacement
paths dispatch one new query even when the first owner wrote a complete
response. Both delivered snapshots must prove the 512 MiB limit and required
live counters; the completed-response path also requires the replacement
timestamp and snapshot to be newer and distinct. Stale Host and Guest
generations fail closed. All nine Apple Silicon stages passed in 18 fresh VMs
on August 11, 2026.
On August 31, 2026, clean revision `09286d8` also passed all nine stages on
x86_64 Linux KVM. Every replacement owner rebuilt the updated running init and
dispatched exactly one fresh Stats query. At `guest-after-response-write`, the
first delivered snapshot preceded and differed from the replacement snapshot;
both retained the exact generation and 512 MiB limit. The retained aggregate
has SHA-256
`ad2a1ec2eb72c106c1bf312253d06fcf187590b357661bed211a83ff5e5cf397`.

Real ReadOutput recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v14`. The durable Create, Start,
and Exec journals remain complete while recovery reconstructs their exact
requests and rebinds the response PIDs. ReadOutput itself is read-only and is
therefore dispatched once to every fresh owner with the same cursor, byte
limit, timeout, target, and generation. The replacement chunk must be the
nonce-bound stdout produced by the rebuilt Exec.
On August 31, 2026, clean revision `dd47146` passed all nine stages on x86_64
Linux KVM. Every replacement owner rebuilt the live non-terminal Exec and
received exactly one fresh ReadOutput request. At
`guest-after-response-write`, the first owner delivered the verified stdout
chunk before the replacement returned the same nonce-bound chunk. All paths
fenced stale Host and Guest generations and restored every transient
inventory. The retained aggregate has SHA-256
`84c75b01feb23f3d29140e61e2a7e3e56843ebaeadbe92a54c62926357b08d08`.

Real WriteStdin recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v15`. The first eight fault
stages retain a prepared Host journal, so the API retry dispatches the exact
bytes once after recovery rebuilds the pipe-backed Exec. A fully delivered
first response leaves `SucceededEmpty`; because that input effect belonged to
the dead VM, driver recovery writes the committed bytes into the rebuilt Exec
before Host service open completes. The API retry then returns from the
durable journal without another driver dispatch. Changed Host and Guest
payloads and stale generations fail closed. All nine Apple Silicon stages
passed in 18 fresh VMs on August 11, 2026.
On August 31, 2026, clean revision `17b307d` also passed all nine stages on
x86_64 Linux KVM. The first eight replacement owners dispatched the exact
bytes once from the Prepared Host journal. At `guest-after-response-write`,
recovery rehydrated the committed write into the rebuilt pipe-backed Exec and
the API retry performed no additional dispatch. Every path verified changed
request rejection, stale Host and Guest fences, the exact effect marker, and
complete cleanup. The retained aggregate has SHA-256
`a96eeace7f59f164d9fc4e1ef4ce3f48b9efa568f1eeeb2af58e54c05c9fe889`.

Real CloseStdin recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v16`. Recovery rebuilds the same
pipe-backed Exec. Prepared Host journals close the replacement input once on
API retry. A fully delivered first response leaves `SucceededEmpty`, so driver
recovery closes the fresh Exec input before Host service open completes and
the retry returns without another driver dispatch. Changed process targets and
stale generations fail closed. All nine Apple Silicon stages passed in 18
fresh VMs on August 11, 2026.
On August 31, 2026, clean revision `31d35c3` also passed all nine stages on
x86_64 Linux KVM. The first eight replacement owners dispatched the exact EOF
once from the Prepared Host journal. At `guest-after-response-write`,
recovery closed the rebuilt pipe-backed Exec before Host service open
completed, and the API retry performed no additional dispatch. Every path
verified changed-process rejection, stale Host and Guest fences, the exact EOF
effect marker, and complete cleanup. The retained aggregate has SHA-256
`dc1743b4c6f53360b40dd9ebcb39b05832322555bfb6d6c0e55f750090c6ba33`.

Real Resize recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v17`. Recovery rebuilds the same
terminal-backed Exec. Prepared Host journals resize it once on API retry. A
fully delivered first response leaves `SucceededEmpty`, so driver recovery
restores `120x40` before Host service open completes and the retry returns
without another driver dispatch. Exact SIGWINCH effect bytes, changed sizes,
stale generations, and fresh-owner PID rebinding fail or pass as required. All
nine Apple Silicon stages passed in 18 fresh VMs on August 11, 2026.

Real File recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v18`. The Host v3 journal retains
the exact upload. Prepared paths dispatch it once through the replacement
driver. At `guest-after-response-write`, the first Host commits the typed
response and returns the retryable acknowledgement failure; recovery rebuilds
the upload in the fresh session filesystem, and the API retry replays the Host
response without another driver dispatch. Exact binary bytes, permanent
changed-content fencing, stale generations, explicit removal, and owner cleanup
passed all nine Apple Silicon stages in 18 fresh VMs on August 15, 2026.

Real Filesystem recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v19`. The Host v3 journal retains
the exact MakeDir request. Prepared paths dispatch it once through the
replacement driver. At `guest-after-response-write`, the first Host commits
the typed metadata response and returns the retryable acknowledgement failure;
recovery rebuilds the directory in the fresh session filesystem, and the API
retry replays the Host response without another driver dispatch. Exact
directory metadata, replacement Stat, permanent changed-path fencing, stale
generations, explicit Remove, and owner cleanup passed all nine Apple Silicon
stages in 18 fresh VMs on August 15, 2026. This completes all 180 real-HVF
operation-stage paths across the 20 protocol-v9 operations.

The same August 15 focused rerun passed `guest-after-response-write` for all 14
journaled HVF mutations. In every case the first API call exposed the
acknowledgement disconnect, the replacement owner reconstructed any VM-local
effect, the Host replayed its durable result without redispatch, and the Guest
record was released only after the Host commit.
