# Versioned Attachment Contracts

## Boundary

`CreateAttachments` is the public, versioned description of every resource
attached to an OCI create or restore request. Schema
`a3s.oci.attachments.v1` covers the original OCI and extension inventory;
`a3s.oci.attachments.v2` adds already-authorized storage. The exact schema is
negotiated through the selected driver's `RuntimeInfo::extensions` entry before
product preparation begins.

The contract deliberately separates product policy from runtime mechanism:

| Category | Contract evidence | Not carried by the runtime manifest |
| --- | --- | --- |
| Root filesystem | Exact `/root` JSON Pointer and SHA-256 value digest | Image reference, pull/build state, layer ownership |
| Mounts | One ordered descriptor for every `/mounts/<index>` value | Named-volume policy, snapshot/commit ownership |
| Networking | Exact OCI network namespace/device descriptors plus explicit extension references | Network objects, IPAM, DNS, aliases, publication policy |
| Process I/O | Complete `ProcessIo` modes and initial terminal size | Box log retention, indexing, redaction, search policy |
| Secrets | A classified mount index or declared runtime mechanism | Secret name, value, authorization decision, materialization credential |
| Storage (v2) | Caller-issued immutable allocation ID, exact OCI mount descriptor, access mode, ownership, and cleanup action | Named-volume lookup, snapshot selection, authorization, retention, and backing-resource deletion |
| Runtime extensions | Reverse-DNS name, positive version, required/advisory bit, and digest-bound OCI annotation | Driver handles or implementation-specific internal types |

The manifest never contains a PID, VM handle, descriptor number, socket,
pipe, cgroup identity, secret value, or product-owned durable type. Standard
resources are references into the already validated immutable `config.json`;
an extension's configuration is the OCI annotation whose key exactly equals
the extension name. This makes the bundle snapshot sufficient to revalidate
every descriptor without persisting a second mutable resource document.

## Construction

Callers derive the standard inventory rather than assembling paths or digests
by hand:

```rust,no_run
use a3s_oci_sdk::{
    CreateAttachments, CreateRequest, IsolationRequest, OperationContext,
    ProcessIo,
};

fn create_request(
    context: OperationContext,
    id: a3s_oci_sdk::ContainerId,
    bundle: a3s_oci_sdk::OciBundle,
) -> a3s_oci_sdk::Result<CreateRequest> {
    let attachments = CreateAttachments::from_bundle(&bundle, ProcessIo::default())?;
    Ok(CreateRequest {
        context,
        id,
        bundle,
        isolation: IsolationRequest::SharedHostKernel,
        attachments,
    })
}
```

`mark_secret_mount` adds only a classification of an existing OCI mount.
`add_extension_from_annotation` binds an extension to the exact annotation
value; `attach_network_extension` and `attach_secret_extension` classify that
declared mechanism. Duplicate, missing, reordered, unknown, drifted, or
oversized declarations fail request validation.

## Already-authorized storage

A caller upgrades a derived v1 manifest to v2 by binding a prepared OCI mount:

```rust,no_run
use a3s_oci_sdk::{
    CreateAttachments, OciBundle, ProcessIo, StorageAccessMode,
    StorageAttachmentId, StorageCleanup, StorageOwnership,
};

fn storage_attachments(bundle: &OciBundle) -> a3s_oci_sdk::Result<CreateAttachments> {
    CreateAttachments::from_bundle(bundle, ProcessIo::default())?
        .attach_storage_mount(
            bundle,
            0,
            StorageAttachmentId::new("allocation-7")?,
            StorageAccessMode::ReadOnly,
            StorageOwnership::Caller,
            StorageCleanup::DetachOnly,
        )
}
```

`StorageAttachmentId` identifies one caller-authorized allocation incarnation;
it is not a mutable named-volume selector and is never interpreted as a host
path. The selected mount remains bound by its JSON Pointer and canonical-value
SHA-256. `ReadOnly` requires the OCI mount's `ro` option; `ReadWrite` requires
`rw` or the OCI default. Contradictory `ro`/`rw`, duplicate identities,
duplicate mount classifications, secret/storage overlap, access drift, and
non-canonical order all fail validation.

Schema v2 intentionally exposes only `StorageOwnership::Caller` and
`StorageCleanup::DetachOnly`. Container deletion tears down runtime mount,
namespace, and guest-transport resources but preserves the backing allocation.
A3S Box remains responsible for named-volume and snapshot resolution,
authorization, retention, commit, and deletion policy. A future mechanism that
lets Runtime own or delete backing storage requires a new schema; v2 cannot be
reinterpreted to grant that authority.

Caller-owned storage cannot be combined with `dev.a3s.bundle-handoff`, because
that extension transfers and later deletes the bundle tree. The Native Linux
driver advertises v2 because its mount namespace cleanup preserves external
bind sources. The current utility-VM drivers deliberately remain v1: their
exact-generation share is runtime-owned and removed as one subtree. They must
gain a separate caller-owned storage transport plus detach-cleanup evidence
before advertising v2; the runtime will not absorb the allocation into an
owned bundle as an implicit fallback.

## Runtime-owned bundle handoff

Local products that prepare a portable bundle for a utility-VM driver may
transfer ownership without predicting the runtime generation. They place the
complete bundle at
`<runtime-root>/bundle-handoffs/<container>/<create-operation>/bundle`, set
the OCI annotation `dev.a3s.bundle-handoff=move-to-runtime-v1`, and add the
required version-1 extension with `with_runtime_bundle_handoff`.

The selected driver must advertise that extension. After durable create state
allocates the real generation, the driver validates the exact protected
operation path, immutable configuration digest, relative `root.path`, and
relative bind sources, then atomically moves the directory below
`shares/<container>/<generation>/bundle`. Replay accepts only that exact
destination with matching ownership evidence. Delete and terminal create
failure remove only an exact digest- and generation-bound handoff.

The public container record deliberately retains the caller's original bundle
identity. The relocated path is an internal driver attachment and is never a
substitute durable product record.

## Negotiation And Failure Rules

SDK transport protocol 3 is the first protocol that carries v1. Protocol-2
peers are rejected during negotiation, so an attachment-aware client cannot be
silently downgraded to a server that ignores the field. Protocol 5 is required
for v2 create and restore requests. Both the client and server reject a v2
operation before dispatch when the negotiated connection is protocol 4 or
earlier; v1 wire serialization remains unchanged and keeps its protocol-3
compatibility.

The host advertises `AttachmentCapabilities`. Create fails before driver
selection or durable reservation when the schema is unsupported or any
`required` extension version is unavailable. An unsupported advisory
extension remains in the request fingerprint and returned evidence but does
not claim enforcement.

For a service with more than one launch-ready driver,
`RuntimeInfo::extensions` is the authoritative per-driver view. A typed
`RuntimeNegotiationRequest` selects the unique driver that owns the requested
`IsolationClass` and can require this schema plus exact extension versions
before product preparation. The legacy top-level attachment capability field
contains only versions common to every registered driver; it never exposes a
union that could overstate support for the selected isolation path. The v1
catalog is additionally bound to the SHA-256 of the running Host executable.

Every accepted manifest participates in the durable create request digest.
The runtime stores the exact manifest with the container record and returns
its SHA-256 digest in `ContainerRecord::attachments_digest`. On reopen it
revalidates all pointers against the immutable configuration snapshot and
checks the stored digest before returning state or resuming an operation.
Changing I/O, classification, storage identity/access/lifetime, extension
version, or referenced configuration while reusing an operation ID therefore
fails as a different request.

Records created before protocol 3 have neither a stored manifest nor an
attachment digest. The runtime retains that explicit legacy state for old
lifecycle cleanup, while attachment-aware consumers such as A3S Box must
reject it for a new unified-backend binding rather than reinterpret it.
