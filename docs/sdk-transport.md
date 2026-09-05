# Rust SDK Transport

## Contract

`a3s-oci-sdk` is the only lifecycle API that A3S Box should consume. The same
`OciRuntimeService` trait is used for in-process tests and out-of-process
runtime calls. The transport maps every trait method; it does not invoke the
CLI or expose WHPX, libkrun, or native Linux driver internals.

The current wire contract is protocol version 9. Version 9 carries the typed
TEE attestation request and response and prevents a TEE launch extension on
create or restore from downgrading to a peer that does not understand it.
`Attest` and every TEE-backed create or restore require protocol 9 and are
rejected before service dispatch on protocol 8 or earlier. Ordinary create
retains its attachment-dependent minimum, and a non-TEE restore retains its
protocol-8 minimum.

Version 8 replaced the legacy checkpoint directory and `leave_running` boolean with an immutable
`a3s.oci.checkpoint-reference.v1`, typed single-file artifact paths, paused
quiescence, exact driver/build compatibility evidence, and request-bound
checkpoint/restore responses. Every checkpoint and non-TEE restore requires
protocol 8 regardless of attachment schema; protocol 7 and earlier reject it
before service dispatch.

The Host implements checkpoint and restore through durable journals and
dispatches them only to a current-platform driver that explicitly advertises
the operation. Restore capability is cumulative: the same driver must also
advertise checkpoint. A committed v5 or v6 restore replays without reopening its
artifact; a pending restore validates the caller-owned file and exact
compatibility evidence before allocating lifecycle state. No production driver
advertises either operation yet.

The Host implements TEE attestation through a v6 durable journal and dispatches
it only to the exact driver that owns the durable generation and advertises
`Attest` plus its technology-specific launch extension. A committed response
replays byte-for-byte without another driver call. Runtime treats evidence as
opaque and does not appraise provider claims; no production driver advertises
the TEE operation or extensions yet.

Version 7 added `a3s.oci.attachments.v4` reusable guest-session identity
evidence to create. A v4 create is rejected before dispatch when a connection
negotiated protocol 6 or earlier. Version 6 added
`a3s.oci.attachments.v3` already-authorized network identity evidence; v3
create requires protocol 6. Version 5 added `a3s.oci.attachments.v2`
already-authorized storage evidence; v2 create requires protocol 5, while
ordinary v1 create requests remain valid on protocol 3. Restore combines the
selected attachment schema with the protocol-8 checkpoint reference. The
required `dev.a3s.network.enforcement@1` extension reuses the existing
extension wire and per-driver negotiation; because it requires v3 network
bindings, protocol 6 remains its create minimum. Version 4 added exact-target
file upload/download and filesystem stat/mkdir/move/list/remove. Mutations
carry stable `OperationContext` identities, payloads and recursive listings
are bounded, and protocol-3 peers reject those file operations before
dispatch. Version 3 made the complete `a3s.oci.attachments.v1` manifest
mandatory for create and the later restore contract, moved init process I/O
inside that versioned contract, and returned its durable digest.
The transport rejects protocol-2 peers rather than silently dropping rootfs,
mount, network, I/O, secret, or runtime-extension evidence. Version 2 had
already made `OperationContext` mandatory for write-stdin, close-stdin, and
resize:

1. the client sends its inclusive supported protocol range;
2. the server selects the highest common version or rejects the connection;
3. each message is UTF-8 JSON preceded by a four-byte big-endian length;
4. empty frames and frames larger than 64 MiB are rejected before payload
   allocation;
5. every request and response carries the negotiated version and a nonzero
   request ID;
6. stable SDK errors cross the boundary without being converted to strings;
7. framing, version, correlation, or caller-cancellation failures poison the
   current byte stream; a local-endpoint client reconnects and renegotiates
   only when the caller makes a later request, while `from_io` streams remain
   permanently closed. A cancelled request is never replayed by the transport;
   callers must explicitly retry or reconcile the original operation;
8. every decoded request is validated before service dispatch.

Calls from cloned clients are serialized on one connection. This guarantees
deterministic response correlation while retaining an async, `Send + Sync`
API. A later protocol version may add multiplexing without changing the
service trait.

The transport never hides an unknown result. If a service exits after reading
a mutation but before returning its response, that call fails with a retryable
transport error and the physical connection is discarded. Once the service is
available again, the next caller-initiated request opens the same validated
local endpoint and performs a new protocol handshake. The caller must replay
the original mutation or run reconciliation with its original `OperationId`;
the runtime journal, rather than the transport, decides whether an effect has
already committed.

The cross-platform runtime contract executes that boundary with two distinct
owner processes. The first process creates and starts a durable generation over
a real Unix socket or Windows named pipe and is then terminated. A second
process opens the same `HostRuntimeService` state root and endpoint; the
retained client reconnects, reads the exact generation, and replays the original
create/start/exec requests without another deterministic test-driver dispatch.
It then recovers live process inventory and continues stdin, signal, wait,
captured output, and cleanup on the same exact process target. Real native Linux
and utility-VM driver reattachment remains platform qualification, not
transport evidence.

## Per-driver Capability Negotiation

`RuntimeInfo::extensions` carries the additive `a3s.oci.extensions.v1`
catalog. The Host hashes the currently running executable and binds its
component name, semantic version, optional source revision, and lowercase
SHA-256 to the complete catalog. Each launch-ready registered driver then owns
one canonical entry containing its unique isolation classes, versioned SDK
operations, and exact attachment schemas and extension versions.

Callers negotiate against the isolation requirement rather than a raw backend
name:

```rust,no_run
use a3s_oci_sdk::{
    IsolationClass, RuntimeClient, RuntimeNegotiationRequest, RuntimeOperation,
    ATTACHMENT_SCHEMA_V1, RUNTIME_OPERATION_CONTRACT_V1,
};

async fn require_update(client: &RuntimeClient) -> a3s_oci_sdk::Result<()> {
    let info = client.features().await?;
    let requirement = RuntimeNegotiationRequest::new(IsolationClass::SharedHostKernel)
        .with_operation(RuntimeOperation::Update, RUNTIME_OPERATION_CONTRACT_V1)?
        .with_attachment_schema(ATTACHMENT_SCHEMA_V1)?;
    let selected = info.extensions.negotiate(&requirement)?;
    println!("selected {:?}", selected.driver());
    Ok(())
}
```

One service may therefore register drivers with different optional operation
or attachment inventories. The flat `RuntimeInfo::operations` and
`RuntimeInfo::attachments` fields retain only their safe intersection for old
callers; `features`, `list`, and `events` remain Host-owned and appear in every
per-driver entry. OCI `potentiallyUnsafeConfigAnnotations` continues to list
the union of recognized driver annotations because it describes the complete
service parser rather than one selected launch path.

After a container is created, the Host resolves each request to the exact
generation and driver recorded in durable state. Optional operations are then
checked against that selected driver, so a capability absent from one driver
does not disable the same operation for another isolation class. A durable
operation is preflighted before a new journal is claimed. If a recovered
operation has already claimed a journal but targets a driver without the
requested capability, it is recorded as a terminal `Unsupported` result and
releases its claim before returning.

Catalog, artifact, driver, isolation, operation-version, schema, and extension
inventories are bounded and canonical. Missing versions return `Unsupported`
from `negotiate-runtime`. A legacy response without the additive field decodes
to an explicitly empty catalog and fails the same negotiation instead of
falling back to the flat union. No new mutation route or wire message is
introduced by this discovery schema, so protocol-3 and protocol-4 framing stay
unchanged.

The OAR-01 network-enforcement contract must be requested as the exact required
extension version in addition to attachment schema v3. Schema support alone
does not imply enforcement support, and no production driver currently
advertises the extension. The Host retains the decoded opaque incarnation in
`ContainerRecord::network_enforcement`; it never transports policy rules,
hostnames, addresses, routes, endpoints, credentials, or tenant metadata.

TEE negotiation likewise requires more than `DedicatedVm`. A caller requests
`RuntimeOperation::Attest` and exactly one
`dev.a3s.tee.amd-sev-snp@1` or `dev.a3s.tee.intel-tdx@1` extension from the
same per-driver catalog entry. The registry rejects an `Attest` operation
without a known TEE extension, a TEE extension without `Attest`, or either on a
driver that lacks dedicated-VM isolation.

## A3S Box Client

On Windows, use a local named pipe:

```rust
use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};

# async fn connect() -> a3s_oci_sdk::Result<()> {
let endpoint =
    LocalIpcEndpoint::windows_named_pipe(r"\\.\pipe\a3s-oci-runtime")?;
let client = RuntimeClient::connect(&endpoint).await?;
let info = client.features().await?;
# let _ = info;
# Ok(())
# }
```

On Linux and macOS, use an absolute Unix-domain-socket path:

```rust
use a3s_oci_sdk::{LocalIpcEndpoint, RuntimeClient};

# async fn connect() -> a3s_oci_sdk::Result<()> {
let endpoint = LocalIpcEndpoint::unix_socket("/run/a3s-oci/runtime.sock")?;
let client = RuntimeClient::connect(&endpoint).await?;
let info = client.features().await?;
# let _ = info;
# Ok(())
# }
```

The platform-specific constructors are compiled only on their corresponding
targets. Callers can also create `RuntimeTransportClient::from_io` over an
already authenticated async byte stream.

### Native Linux multi-container host owner

`a3s-oci native-linux-host-service --root <absolute-root> --agent
<absolute-agent>` publishes a long-lived Linux SDK endpoint for ordinary
transported create requests. It opens the experimental Native Linux driver and
reconciles the durable state root before binding `runtime.sock`; the endpoint
is mode `0600`, inode-scoped on cleanup, and accepts concurrent same-UID
clients. Because this owner carries no process-local descriptors, it can serve
multiple independently fenced container IDs and is the owner boundary intended
for the unified Box backend.

Graceful `SIGINT` or `SIGTERM` stops the service, aborts client tasks, shuts
down driver-owned processes, and removes only the socket inode created by that
owner. Abrupt owner replacement reopens the same durable service state; the
client still exposes the first broken request and reconnects only on a later
explicit reconciliation.

### Native Linux A3S Box owner

`a3s-oci native-linux-service` is the Linux process owner used by the Box
adapter. It binds one absolute private runtime root and one `ContainerId`.
Before starting it, Box creates and listens on its exec and PTY Unix sockets,
opens the writable init log, and inherits those handles as FD 3, FD 4, and FD
5. The explicit `--a3s-box-control-fds` flag prevents an accidental service
start with a different descriptor contract.

The owner creates `runtime.sock` beneath its `0700` runtime root, applies mode
`0600`, verifies the socket owner and inode, and authenticates every accepted
peer against the service effective UID. A normal transported `create` for the
bound ID receives the inherited handles without adding process-local types to
the SDK wire contract. Requests for another container ID are rejected before
driver dispatch.

Box should treat the runtime owner and `RuntimeClient` as one Sandbox-scoped
resource: retain one logical client for the Sandbox lifecycle, allowing its
physical stream to reconnect after an observed owner restart; close it when no
more requests are needed, then terminate the owner with `SIGTERM` and wait for
a successful exit. The signal path shuts down every driver-owned process and
transient executor slot before the exact service socket is removed. Durable
state stays inside the Sandbox runtime root until Box removes that
product-owned root.

For an in-process host integration, A3S Box can wrap
`HostRuntimeService::open(state_root, driver)` in `RuntimeClient`. The
`RuntimeDriver` trait receives exact-generation requests and the immutable
durable bundle at both create and start. Its mutating methods are async,
`Send + Sync`, and idempotent by `OperationId`. Platform resources and guest
protocol types remain behind that boundary.

### Foreground run composition

`RuntimeClient::run` composes `create`, `start`, an unbounded init-process
`wait`, and `delete`. It is deliberately absent from `OciRuntimeService` and
the wire protocol, so there is only one lifecycle implementation:

```rust,no_run
use a3s_oci_sdk::{
    ContainerId, CreateAttachments, CreateRequest, IsolationRequest,
    OperationContext, OperationId, ProcessIo, RunRequest, RuntimeClient,
};

# async fn run(client: RuntimeClient, bundle: a3s_oci_sdk::OciBundle)
#     -> a3s_oci_sdk::Result<()> {
let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())?;
let status = client
    .run(RunRequest {
        create: CreateRequest {
            context: OperationContext::new(OperationId::new("box-42-create")?),
            id: ContainerId::new("box-42")?,
            bundle,
            isolation: IsolationRequest::SharedHostKernel,
            attachments,
        },
        start_context: OperationContext::new(OperationId::new("box-42-start")?),
        delete_context: OperationContext::new(OperationId::new("box-42-delete")?),
    })
    .await?;
println!("{status:?}");
# Ok(())
# }
```

The three operation IDs must be distinct. After create succeeds, the SDK uses
the supplied delete context with `DeleteMode::Force` on both success and
start/wait failure paths. This makes foreground ownership and error cleanup
deterministic while preserving the durable replay contract of every
constituent mutation.

The configured host always implements `list` and `events` directly from its
durable state, without requiring or dispatching driver operations. Container
results are sorted by ID, may be filtered by exact `IsolationClass`, and fail
closed if any live record, identity, schema, OCI state, or configuration
digest is invalid. Event results use an exclusive global sequence cursor,
support container-ID-wide or exact-generation filtering, bounded pagination,
and optional long polling, and survive host-service reopen without
duplication.
The host also requires the five core driver operations and advertises
`wait`, `exec`, `signal-process`, `wait-process`, `pause`, `resume`, and
`processes`, `update`, `stats`, `read-output`, `write-stdin`, `close-stdin`,
`resize`, `file`, `filesystem`, and `checkpoint` only when the selected driver
implements each one. `restore` additionally requires that driver's checkpoint
capability and matching immutable compatibility evidence. `WaitRequest`
targets one exact generation, accepts an optional
millisecond timeout, and returns an `ExitStatus` containing either an exit
code in `0..=255` or a positive signal. Repeated waits must return the same
terminal result. The native Linux driver and the protocol-v10 utility-VM guest
path implement this contract while retaining agent protocol-v1 through
protocol-v9 compatibility; unsupported drivers fail before dispatch.

Poll from the beginning with cursor zero, then pass each returned
`next_sequence` to the next request. A filter without a generation follows
all retained generations of that container ID:

```rust,no_run
use a3s_oci_sdk::{ContainerTarget, EventsRequest, RuntimeClient};

async fn poll_events(
    client: &RuntimeClient,
    container: ContainerTarget,
) -> a3s_oci_sdk::Result<()> {
    let mut cursor = 0;
    let batch = client
        .events(EventsRequest {
            container: Some(container),
            after_sequence: cursor,
            limit: 256,
            wait_timeout_ms: Some(30_000),
        })
        .await?;
    for event in &batch.events {
        println!("{} {:?}", event.sequence, event.kind);
    }
    cursor = batch.next_sequence;
    let _ = cursor;
    Ok(())
}
```

`pause` and `resume` are negotiated independently, so a driver that omits
either operation is rejected before dispatch. Each accepted mutation carries
an exact `OperationContext::operation_id`. When its durable freezer transition
is committed, the corresponding `ContainerPaused` or `ContainerResumed` event
projects that identity through the typed `RuntimeEvent::operation_id`, together
with the exact container generation, event kind, sequence, and Host timestamp.
The legacy `attributes["operation-id"]` projection remains on the wire for
older consumers; new events require both representations to match. Event-v1
records written before the typed field was added remain readable only when the
compatibility attribute matches their durable operation claim.

The Runtime owns this exact mutation and observation boundary. It does not own
an idle timer, suspend policy, or wake decision; those remain caller policy and
must invoke the separately negotiated operations with their own stable IDs.

The protocol-v10 shared Linux executor implements exact-target exec,
pidfd-backed per-process signal, stable per-process wait, cgroup-v2
pause/resume, exact live process inventory, partial live CPU/memory/cpuset/PID
updates, normalized resource statistics, piped stdin, and bounded captured
stdout/stderr, plus controlling PTYs with initial dimensions, merged terminal
output, interactive input, runtime resize, and VEOF close. Output uses one
inclusive byte cursor across both streams: the
caller begins at zero and supplies the last returned `OutputChunk::sequence`
to the next poll. Data advances the cursor by its byte length and each
per-stream EOF advances it by one logical position, so a poll can split a
driver frame without loss or duplication. The public host path resolves every
I/O target to the exact durable generation and rejects malformed, oversized,
or non-contiguous driver output. It also reserves process IDs before driver
dispatch, persists generation-scoped process records, journals exec, signal,
pause, resume, update, write-stdin, close-stdin, and resize mutations, and
caches terminal results. SDK stdin writes larger than the guest's 4 MiB bound
are split into chunks with stable derived operation IDs, so a retried driver
call replays completed chunks without duplicating their bytes. Native Linux
exposes that complete path through `RuntimeClient`; the HVF and WHPX adapters
map the same 20 workload operations when their platform driver is live.

After the Host durably commits a journaled success or terminal failure, it
invokes the driver's idempotent acknowledgement hook. Native Linux releases
the local replay record directly. Protocol-v10 utility-VM drivers send a
bounded `acknowledge-operations` maintenance request; large stdin writes map
the parent Host identity back to every derived Guest chunk identity. A lost
acknowledgement is retryable, and replaying the completed Host operation sends
it again without redispatching the workload mutation. A cancelled
acknowledgement also retains every derived stdin identity until the Guest
accepts the maintenance request, so a retry cannot accidentally acknowledge
only the parent operation. Protocol-v1 through
protocol-v9 Guests retain a compatibility no-op. File upload and Filesystem
mkdir/move/remove retain their exact v3 request and typed response. New Host
mutations use v6; checkpoint retains its v4-compatible exact normalized path,
paused source target, and immutable typed response. Restore adds its complete
request, allocated generation, immutable reference, and paused-running
response. Attestation adds its exact report data and complete opaque evidence
response. These operations share the same post-commit reclamation boundary.
Reusing an acknowledged OperationId with changed content remains fenced by the
Host record.

File downloads and uploads are limited to 32 MiB decoded payloads. Directory
listings are limited to depth 64, 4,096 entries, and a 12 MiB serialized
response. The shared executor resolves every path from a retained rootfs file
descriptor with Linux `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` and
descriptor-relative mutation syscalls; it never constructs a host path from
untrusted guest text. Upload, mkdir, move, and remove replay by exact
`OperationId`, while read-only requests carry no mutation context.

## Runtime Server

Listener creation and access control belong to the runtime process because
they are part of its security boundary. After accepting and authenticating a
local stream, the runtime serves it with:

```rust
use std::sync::Arc;

use a3s_oci_sdk::{serve_transport_connection, OciRuntimeService};
use tokio::io::{AsyncRead, AsyncWrite};

async fn serve<T>(
    service: Arc<dyn OciRuntimeService>,
    stream: T,
) -> a3s_oci_sdk::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    serve_transport_connection(service, stream).await
}
```

On Windows, the runtime must apply a restrictive named-pipe security
descriptor before accepting clients. On Unix, it must bind inside a protected
runtime directory and set the intended owner and mode. The SDK deliberately
does not silently choose those authorization policies.

## Validation Boundary

`CreateRequest` and `RestoreRequest` carry `OciBundle` plus
`CreateAttachments`. Restore additionally carries one immutable checkpoint
reference and typed artifact file path. Their wire decoders revalidate the
absolute bundle path, exact `config.json`, supported OCI version, official
schema, unknown-property policy, configuration SHA-256, attachment JSON
Pointers, per-value digests, category completeness, storage
identity/access/ownership/cleanup, authorized network
namespace/interface/cleanup identity, and the process-I/O contract before the
service receives the request. The transport therefore cannot be used to bypass
either the SDK's bundle checks or its attachment boundary. Checkpoint and
restore also require normalized absolute artifact paths, exact positive source
generations, canonical content and build digests, positive artifact sizes, a
matching configuration and isolation class, and paused-quiescence response
correlation. The artifact ownership, cleanup, retry, and capability rules are
defined in the [immutable checkpoint contract](checkpoint-contract.md).

Every request implements `ValidateRequest`. The in-process `RuntimeClient`,
transport client, and server call it independently. The server-side check is
the trust boundary: manually encoded wire requests cannot bypass OCI
process/resource semantics, terminal consistency, typed checkpoint paths and
immutable references, or the 4,096-event, 16 MiB output/stdin, 32 MiB file, and
bounded filesystem response limits.

Bundle construction also applies the configuration phase of
`OciSemanticValidator`. The start phase adds the OCI requirement for a
runnable process and must be applied to the durable bundle snapshot by the
lifecycle implementation. Schema and initial semantic validity are not the
final conformance gate; complete normative-rule coverage, driver enforcement,
durable lifecycle behavior, and upstream OCI conformance remain tracked in
the project roadmap.
