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
- is canonicalized before use;
- rejects a root, layout directory, record, or transaction file that is a
  symbolic link or a Windows reparse point;
- permits exactly one runtime writer through a cross-process exclusive lock;
- bounds every state file to 16 MiB;
- uses `0700` directories and `0600` transaction files on Unix;
- creates Windows directories with the runtime principal as owner and a
  protected DACL, grants full access only to that principal and LocalSystem,
  disables inherited access, and verifies the owner plus every applied ACE
  type, mask, flag, and principal;
- commits files by atomic rename plus directory sync on Unix;
- commits files with `MoveFileExW`, replacement, and write-through semantics
  on Windows.

A Windows state root therefore requires a filesystem with persistent ACL
support. Opening the root fails closed when ownership or the protected DACL
cannot be applied and read back exactly.

Descriptor-relative traversal is still pending and remains a release gate
before lifecycle operations can be enabled. The current metadata/reparse-point
checks and protected parent directories prevent ordinary traversal and
inheritance attacks, but they are not presented as a substitute for
handle-relative resolution under adversarial races.

The implementation uses the security descriptor supplied directly to
[`CreateDirectoryW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
for first creation, applies protected DACLs with
[`SetNamedSecurityInfoW`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow),
and reads them back with
[`GetNamedSecurityInfoW`](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow).

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
    `-- <operation-id>.failed-create/
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
bundle, isolation request, process I/O, and the optional stable inherited
descriptor schema. The A3S Box schema records the exec-listener, PTY-listener,
and init-log roles, kernel-object types, and targets 3/4/5; it deliberately
excludes ephemeral source FD numbers and inode identities so an exact retry
after host restart may reopen equivalent resources. Reusing an `OperationId`
for a different request or omitting a previously attached schema fails with
`failed-precondition`. A matching prepared operation resumes the original
generation; a matching completed operation returns its exact recorded
response.

Start, kill, pause, resume, update, and delete use the same global journal and
request fingerprinting. Each accepted mutation claims the target record so a
second mutation cannot race the driver call. Start revalidates the durable
configuration snapshot, not the caller's mutable source bundle, before
recording an intent. Pause and resume preserve the standard OCI `running`
status and store freezer state in the reserved
`dev.a3s.oci.runtime.paused=true` state annotation. Update fingerprints the
complete OCI `LinuxResources` patch and returns the exact observed container
record on replay. Delete atomically moves the owned container directory into
quarantine rather than recursively deleting an unresolved path.

Drivers must be idempotent by `OperationId`. A retryable driver error leaves
the intent active for an exact retry. A terminal error is stored and replayed
exactly; it releases a start, kill, pause, resume, update, delete, exec, or
per-process signal, write-stdin, close-stdin, or resize claim, while a failed
create is moved out of the live namespace before its ID can be reused.

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
and wait reconciliation append exact-generation events under one global,
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
- cached init and exec terminal results survive host-service reopen;
- a terminal create failure completes quarantine before replaying its exact
  error;
- malformed or digest-mismatched records fail closed.

## Fault Injection Contract

Every lifecycle write is routed through one typed `DurableMutation` registry.
The registry currently contains 95 semantic mutations. Ninety-three atomic
file replacements are exercised at all seven commit stages:

1. temporary file creation;
2. private permission or ACL application;
3. data write;
4. flush;
5. file sync;
6. atomic replacement;
7. parent-directory sync.

The delete and failed-create quarantine moves are each exercised after the
rename, source-parent sync, and destination-parent sync. This expands to 657
durable fault points. The host matrix separately injects before and after all
22 `RuntimeDriver` boundaries, including capability discovery, startup
recovery, file transfer, and filesystem operations, for another 44 boundaries.

On Unix the final file and directory boundaries follow explicit directory
`sync_all` calls. Windows reaches the same logical checkpoints after its
write-through `MoveFileExW` replacement or move because a separate directory
sync primitive is not used there.

Each test fails exactly once, drops the store or host service, reopens the same
state root, and replays the original operation. Recovery must preserve
monotonic generations and exact operation results, complete or safely resume
journals, avoid duplicate live and quarantined generations, and remove every
`.next` transaction file. The matrices run in Linux, macOS, and Windows CI.
Production uses a non-configurable no-op injector.

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

The remaining persistence gates are startup-wide orphan scanning,
descriptor-relative path operations, real-host qualification of restart-stable
WHPX exit evidence (or qualified reattachment where another driver promises
it), and carrying all 180 host/agent fault pairs through a real utility VM and
host-service reopen below the `RuntimeDriver` boundary. The portable matrix
already reopens the durable host around a new authenticated connection and
driver at all nine request/response stages for create, state, start, kill,
delete, wait, exec, signal-process, wait-process, pause, resume, processes,
update, stats, read-output, write-stdin, close-stdin, resize, file, and
filesystem, retaining all 180 operation-stage pairs. Durably journaled host
mutations distinguish pre-dispatch execution, post-dispatch guest replay, and
completed durable-host replay while preserving the same generation and one
effect. Exec additionally preserves its exact process ID, guest PID, and
terminal mode;
signal-process preserves that exact process target and the delivered signal;
pause and resume preserve the running state and commit the matching freezer
flag exactly once, including when the first guest effect preceded the lost
response; update preserves the complete OCI `LinuxResources` request and one
exact resource effect; write-stdin preserves the exact process target,
operation context, input bytes, and one input effect; close-stdin preserves the
exact process target and operation context with one close effect; resize
preserves the exact terminal process target, operation context, dimensions, and
one resize effect.
File uploads and filesystem mutations remain session-scoped operations rather
than durable host journal entries. Every retry after reopen, including one after
a fully written first response, resolves and dispatches the same
exact-generation request. The guest journals return the same upload
acknowledgement or directory metadata and keep one mutation effect; changed
content under the same operation ID conflicts, while stale generations fail
before host dispatch and at the guest boundary.
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
VM/session owner reopen that record and complete the same Create. The fully
written Guest response is different: it leaves a completed `created` record,
then a follow-up State request exposes the disconnect. Replacement recovery
rebuilds that pre-start process and uses the explicit
`DriverRecovery::recreated_created` contract to reconcile its exact PID. The
next Create replay repairs and returns the same recovered record instead of the
stale cached response. Ordinary recovery observations still reject PID drift.
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
2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

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
10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

Real Delete recovery crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v4`. The first eight interruptions
retain the stopped record and a Prepared Delete journal. Replacement recovery
recreates, starts, and kills the workload with the original setup identities,
rebuilds the Guest tombstone, and dispatches the unchanged stopped-only Delete
once. A fully written response instead retains no live record and a
SucceededEmpty journal, so the replacement owner performs no workload recovery
or driver Delete. Every path restores both Host and Guest inventories. The
August 10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

Real init Wait recovery crosses the same nine points under
`a3s.oci.oci-vm-operation-reopen-replacement.v5`. The first eight interruptions
retain the stopped record without cached terminal evidence. Replacement
recovery rebuilds the Guest tombstone and dispatches the exact Wait target once,
then durably caches `signal=9, oom_killed=false`. A fully written response
already has that cache, so Host reopen and later Wait calls replay it without a
driver or Guest dispatch. Stale generations fail at both Host and Guest
boundaries. The August 10, 2026 Apple Silicon matrix passed all nine stages in
18 fresh VMs.

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

Real ReadOutput recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v14`. The durable Create, Start,
and Exec journals remain complete while recovery reconstructs their exact
requests and rebinds the response PIDs. ReadOutput itself is read-only and is
therefore dispatched once to every fresh owner with the same cursor, byte
limit, timeout, target, and generation. The replacement chunk must be the
nonce-bound stdout produced by the rebuilt Exec.

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

Real CloseStdin recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v16`. Recovery rebuilds the same
pipe-backed Exec. Prepared Host journals close the replacement input once on
API retry. A fully delivered first response leaves `SucceededEmpty`, so driver
recovery closes the fresh Exec input before Host service open completes and
the retry returns without another driver dispatch. Changed process targets and
stale generations fail closed. All nine Apple Silicon stages passed in 18
fresh VMs on August 11, 2026.

Real Resize recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v17`. Recovery rebuilds the same
terminal-backed Exec. Prepared Host journals resize it once on API retry. A
fully delivered first response leaves `SucceededEmpty`, so driver recovery
restores `120x40` before Host service open completes and the retry returns
without another driver dispatch. Exact SIGWINCH effect bytes, changed sizes,
stale generations, and fresh-owner PID rebinding fail or pass as required. All
nine Apple Silicon stages passed in 18 fresh VMs on August 11, 2026.

Real File recovery uses
`a3s.oci.oci-vm-operation-reopen-replacement.v18`. Uploads remain outside the
Host journal, so both the first retry and later replay dispatch through the
replacement driver. A delivered first response causes driver recovery to
rebuild the upload and its Guest journal in the fresh session filesystem before
Host open. The API retry then receives the cached Guest response without a
second upload effect. Exact binary bytes, changed content, stale generations,
explicit removal, and owner cleanup passed all nine Apple Silicon stages in 18
fresh VMs on August 11, 2026. Filesystem is the final real replacement matrix.
