# Durable State

The runtime has an internal persistence boundary for OCI lifecycle work. It is
compiled and tested before any workload operation is advertised so that
idempotency, generation fencing, and crash behavior do not depend on a
particular hypervisor or Linux executor.

This is currently a foundation, not a public claim that `create` or `state`
works. `HostRuntimeService` still advertises only `features`.

## Root Contract

The state root:

- must be an absolute UTF-8 path whose parent already exists;
- is canonicalized before use;
- rejects a root, layout directory, record, or transaction file that is a
  symbolic link or a Windows reparse point;
- permits exactly one runtime writer through a cross-process exclusive lock;
- bounds every state file to 16 MiB;
- uses `0700` directories and `0600` transaction files on Unix;
- commits files by atomic rename plus directory sync on Unix;
- commits files with `MoveFileExW`, replacement, and write-through semantics
  on Windows.

Windows owner-only DACL creation and verification is not implemented yet.
Until that lands, operators must place the root under an already protected
directory. Descriptor-relative traversal is also pending. Both remain release
gates before lifecycle operations can be enabled.

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

## Create Transaction

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

Queries may target the current container generation or provide an exact
generation fence. A stale fence fails with `conflict`.

## Crash Boundary

Each record replacement is individually crash durable, but a complete
multi-record transaction and driver reconciliation are still under
development:

- a crash after generation allocation may leave an unused generation;
- a journal intent without a container record fails closed as retryable
  unavailable state;
- a prepared record is returned as resume work and must be reconciled with the
  original driver;
- a created record whose success journal was not committed can be completed
  idempotently with the same PID;
- malformed or digest-mismatched records fail closed.

The next persistence gate adds fault injection at every write, deterministic
driver reconciliation, quarantine of ambiguous resources, Windows DACL
enforcement, and journals for all mutating SDK operations.
