# Immutable Checkpoint And Restore Contract

## Status

SDK protocol 8 freezes the public checkpoint and restore contract. It does not
claim that a production driver can execute either operation. The Host Service
implements durable orchestration for both operations. The registry permits a
current-platform driver to advertise `Checkpoint`, and permits `Restore` only
when that same driver also advertises `Checkpoint`. No production driver
advertises either operation, so callers must still treat absence from
`RuntimeInfo::operations` and the exact-artifact extension catalog as
authoritative.

A production driver may advertise checkpoint only after it provides the
required atomic artifact and cleanup behavior and the relevant real-host
qualification passes. Restore additionally requires read-only artifact
validation, exact compatibility checks, idempotent paused-process recreation,
and scoped terminal cleanup. Protocol and Host availability alone are never
capability evidence.

## Artifact And Reference

One checkpoint is one immutable local file. `CheckpointArtifactPath` accepts
an already-authorized absolute, normalized, non-NUL UTF-8 file path of at most
4,096 bytes. It does not grant filesystem authority, select object storage, or
resolve a named snapshot. The caller must authorize and prepare the parent
directory before invoking the runtime.

`CheckpointReference` schema `a3s.oci.checkpoint-reference.v1` binds all of the
evidence required to identify and consume that file:

- the exact source container ID and positive generation;
- the source OCI configuration and attachment-manifest SHA-256 digests;
- the driver, isolation class, host platform, and canonical architecture;
- the exact Host executable artifact and driver-stack build SHA-256 digest;
- the driver-defined checkpoint format name and positive format version;
- paused quiescence; and
- the artifact's exact SHA-256 digest and positive byte size.

All SHA-256 identities use `sha256:` followed by 64 lowercase hexadecimal
digits. Unknown reference, compatibility, format, request, and response fields
fail decoding. A restore must match the reference's configuration, isolation,
driver, platform, architecture, Host artifact, driver build, format, size, and
content digest before it reserves durable lifecycle state or mutates the Host.

The source attachment digest records what was captured. Restore carries a new
complete `CreateAttachments` contract because already-authorized attachment
incarnations may be replaced. The returned `ContainerRecord` must bind the
exact restore-request attachment digest.

## Paused Quiescence

Version 1 has one explicit quiescence mode:

1. the caller pauses a running exact generation with the normal `pause`
   operation;
2. checkpoint accepts only that already-paused `running` generation;
3. checkpoint success or failure leaves the source paused; and
4. restore creates a new `running` generation with
   `dev.a3s.oci.runtime.paused=true`; the caller explicitly invokes `resume`
   after reconciliation.

Checkpoint never hides an automatic pause or resume transition. Restore never
returns an executing workload. The legacy `leave_running` boolean is therefore
not representable in protocol 8; a decoded legacy request fails validation.

## Creation, Cleanup, And Retry

A conforming checkpoint implementation must reject a destination that existed
before the operation. It writes a runtime-owned sibling temporary file,
flushes file contents and required directory metadata, verifies the final size
and digest, and publishes the destination without replacing another entry.
Before publication, failure removes only runtime-created partial files. After
publication and durable response commit, ownership of the immutable artifact
belongs to the caller; container deletion and runtime recovery never remove it.

Restore opens the caller-owned artifact read-only, rejects links or identity
replacement according to the driver's platform boundary, verifies size and
content before lifecycle mutation, and never changes or deletes the artifact.
A failed restore removes only runtime-owned lifecycle, driver, and attachment
resources created for that attempt.

Both requests carry `OperationContext`. New Host journals use
`a3s.oci.operation.v6`; checkpoint records written with v4 or v5 remain
readable, and restore records written with v5 remain readable.
Checkpoint retains the exact normalized request and typed response. It claims
the source before driver dispatch, rejects active process mutations and I/O,
and blocks new process I/O until success or terminal failure is durable.
Reusing an operation ID with a different target or path fails. A retry of a
committed checkpoint returns the same reference without rewriting the file,
including after service reopen.

Restore checks its durable journal before touching the caller artifact, so a
committed response or terminal error replays even when the artifact is no
longer present. A pending restore performs read-only artifact validation and
exact compatibility selection before it writes an operation or allocates a
generation. Its v5/v6 journal retains the reference, bundle, isolation,
attachments, path, target ID, and allocated generation. A prepared attempt
resumes through the same operation ID; success commits `running`, a positive
PID, and the paused annotation before returning the exact typed response.
Changing any retained field under the same operation ID fails closed.

Terminal driver errors are durable only after the driver has removed its own
unpublished partials. A retryable checkpoint driver error or Host rejection of
inconsistent compatibility evidence leaves the source claim active so another
mutation cannot race an unresolved published effect. A terminal restore error
is journaled before the runtime-owned generation directory is moved to an
operation-bound `.failed-restore` quarantine entry. Exact retries finish that
move before replaying the same error; a later operation may reuse the container
ID only with a higher generation.

## Ownership Boundary

The runtime contract deliberately excludes business lineage, fork ancestry,
retention policy, garbage collection, encryption policy, replication, remote
object naming, upload/download, and checkpoint selection. A3S Box or another
caller owns those policies and may persist `CheckpointReference` beside its own
metadata. The runtime owns only the validated local operation and its scoped
partial cleanup.

## Protocol Compatibility

Checkpoint and non-TEE restore require SDK protocol 8 regardless of attachment
schema. A restore carrying a TEE launch extension requires protocol 9. Protocol
7 and earlier cannot carry an immutable reference or typed response and are
rejected before service dispatch. Legacy request field aliases are decoded
only so a protocol-8 peer can return a stable validation error instead of
accidentally applying the old directory/boolean semantics.
