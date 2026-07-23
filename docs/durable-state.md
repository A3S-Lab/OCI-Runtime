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
|       `-- record.json
|-- generations/
|   `-- <container-id>.json
|-- operations/
|   `-- <operation-id>.json
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

## Lifecycle Transactions

Create uses two durable stages:

1. `prepare_create` validates the complete request and deadline, checks the
   global operation journal, allocates the next generation, stores an exact
   configuration snapshot, and records OCI `creating`.
2. The selected driver prepares a real init process without running the user
   program. `complete_create` then requires its positive PID and atomically
   records OCI `created` before storing the exact successful response.

The create request digest excludes retry metadata but includes container ID,
bundle, isolation request, and process I/O. Reusing an `OperationId` for a
different request fails with `failed-precondition`. A matching prepared
operation resumes the original generation; a matching completed operation
returns its exact recorded response.

Start, kill, and delete use the same global journal and request fingerprinting.
Each accepted mutation claims the target record so a second mutation cannot
race the driver call. Start revalidates the durable configuration snapshot,
not the caller's mutable source bundle, before recording an intent. Delete
atomically moves the owned container directory into quarantine rather than
recursively deleting an unresolved path.

Drivers must be idempotent by `OperationId`. A retryable driver error leaves
the intent active for an exact retry. A terminal error is stored and replayed
exactly; it releases a start/kill/delete claim, while a failed create is moved
out of the live namespace before its ID can be reused.

Queries may target the current container generation or provide an exact
generation fence. A stale fence fails with `conflict`.

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
- a moved delete tombstone completes an interrupted delete journal;
- a terminal create failure completes quarantine before replaying its exact
  error;
- malformed or digest-mismatched records fail closed.

The remaining persistence gates are exhaustive fault injection at every write
and host/driver transition, startup-wide orphan scanning, descriptor-relative
path operations, and journals for all remaining mutating SDK operations.
