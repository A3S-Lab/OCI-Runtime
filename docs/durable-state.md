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
host-service reopen below the `RuntimeDriver` boundary. The portable
create/start/kill/delete matrix already reopens the durable host around a new
authenticated connection and driver at all nine request/response stages for
each operation. It distinguishes pre-dispatch execution, post-dispatch guest
replay, and completed durable-host replay while preserving the same generation
and one effect per operation. A fully completed delete leaves no live container
record, so service reopen skips driver recovery and replays the durable delete
journal directly.
