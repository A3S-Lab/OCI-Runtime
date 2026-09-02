# Immutable Checkpoint And Restore Contract

## Status

SDK protocol 8 freezes the public checkpoint and restore contract. The Host
Service implements durable orchestration for both operations. The registry
permits a current-platform driver to advertise `Checkpoint`, and permits
`Restore` only when that same driver also advertises `Checkpoint`.

The default Native Linux feature inventory and
`NativeLinuxDriver::open_experimental` advertise neither operation. The
separate rootful `NativeLinuxDriver::open_experimental_with_criu` constructor
advertises `Checkpoint` and `Restore` only after it binds and probes one exact
CRIU executable. No production driver advertises either operation. Legacy
callers must treat absence from `RuntimeInfo::operations` as unavailable;
capability-aware callers must additionally negotiate the exact-artifact
per-driver extension catalog for the selected isolation class.

A production driver may advertise checkpoint only after it provides the
required atomic artifact and cleanup behavior and the relevant real-host
qualification passes. Restore additionally requires read-only artifact
validation, exact compatibility checks, idempotent paused-process recreation,
and scoped terminal cleanup. Protocol and Host availability alone are never
capability evidence.

## Native Linux CRIU Format V1

The explicit Native Linux backend emits format `native-linux-criu` version 1.
Opening it requires effective UID 0 and an absolute, canonical, root-owned
regular CRIU executable that is executable and not group- or world-writable.
The backend retains an open descriptor, SHA-256-binds that exact file, obtains
bounded `--version` evidence, and requires `criu check` to pass before the
driver is registered. It rehashes the retained descriptor before every dump.
The driver-build digest also binds the matching Agent executable, package and
source identity, format version, CRIU identity, and dump-option template.

Version 1 has a deliberately narrow source profile:

- the source is rootful Native Linux, running and already paused;
- its cgroup annotation selects `control-workload-v1`, and the exact OCI init
  PID is the only runtime-tracked live process and is a member of the frozen
  `a3s-workload` leaf;
- a private PID namespace is rejected because this version checkpoints the OCI
  init payload, not the runtime's namespace supervisor;
- configured user and network namespaces, terminal-backed init I/O, Intel RDT,
  moved network devices, OCI hooks, and live exec processes are rejected; and
- unresolved external file descriptors fail the CRIU dump. The qualification
  workload closes host-attached standard I/O and launch-control descriptors
  before checkpoint. Newly created UTS, mount, IPC, cgroup, and time namespaces
  remain in the qualified positive profile.

The backend invokes CRIU with `--leave-running`, `--shell-job`, `--file-locks`,
`--manage-cgroups=soft`, automatic external-mount discovery, explicit stable
cookies for every OCI device mount, `--freeze-cgroup` set to the exact workload
leaf, and the exact management cgroup root. The kernel freezer is reasserted
and checked before and after the bounded dump. The complete source PID, cgroup,
and external-mount snapshot must also remain unchanged, so success and failure
both leave the exact source paused.

The single-file artifact begins with a versioned binary envelope and contains
one canonical manifest followed by CRIU image bodies in sorted name order.
The manifest binds the exact source and compatibility evidence, launcher and
OCI init PIDs, workload cgroup, CRIU identity and arguments, the sorted
cookie-to-container-mountpoint device contract, and every image's size and
SHA-256 digest. `inventory.img` is mandatory. Packaging, validation, and
extraction stream image bytes instead of accumulating memory pages in process
memory.

Version 1 restore is an explicit rootful Native Linux profile. It requires the
same configuration and attachments, null non-terminal init I/O,
`control-workload-v1`, no PID, user, or network namespace, no joined namespace,
and no hooks, Intel RDT, or moved network devices. Newly created UTS, mount,
IPC, cgroup, and time namespaces are accepted. The runtime validates the
artifact read-only, extracts images into an operation-owned stage, recreates
device placeholders without replacing bundle-owned files, prepares new
generation device sources, and supplies the exact recorded cookies to CRIU.
CRIU restores with `--leave-stopped` and `--manage-cgroups=ignore` beneath an
A3S supervisor that becomes the restored init's authenticated direct parent.
The executor adopts the supervisor and restored tree into the new generation's
control/workload cgroups, retains their namespace and pidfd evidence, and
returns the generation running but cgroup-paused. Resume remains an explicit
caller operation.

Driver-local state beneath `.a3s-oci-native-checkpoint-v1` records allocated,
prepared, and published phases under an exclusive process lock. Publication
creates one owner-token-bound sibling pending file, flushes and validates it,
uses a no-replace hard link for the final name, and flushes the parent
directory. A retry can finish an interrupted publish or return the retained
published result without reading the caller-owned final artifact. Host
acknowledgement removes the operation journal, staging directory, and any
owned pending link; it never removes the published artifact.

The Host operation journal and live executor provide exact restore replay for
response loss in one process. A separate driver-local restore journal durably
retains the allocated request, validated manifest, extracted image stage, and
completed paused Agent state. On replacement-process startup, a `creating`
Host record cleans the dead executor generation and retries from those retained
images, while a committed paused `running` Host record recreates the exact
generation before the Host rebinds its completed response. Host acknowledgement
then removes the restore journal and retained stage without mutating the
caller-owned checkpoint artifact.

The real-kernel v3 gate terminates the original runtime owner after the Restore
driver call and again after the Host's completed-operation parent-directory
sync. In both cases a distinct owner opens the same Host and driver roots,
recreates a live paused generation, replays the exact response, preserves the
artifact bytes, and removes all journal, staging, executor, and session state
after resume, kill, wait, and delete. Published-package, broader-profile,
cross-driver, multi-architecture, and production qualification remain open.

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
