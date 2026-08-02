# Versioned Attachment Contracts

## Boundary

`CreateAttachments` is the public, versioned description of every resource
attached to an OCI create or restore request. The current schema is
`a3s.oci.attachments.v1` and is negotiated through
`RuntimeInfo::attachments` before product preparation begins.

The contract deliberately separates product policy from runtime mechanism:

| Category | Contract evidence | Not carried by the runtime manifest |
| --- | --- | --- |
| Root filesystem | Exact `/root` JSON Pointer and SHA-256 value digest | Image reference, pull/build state, layer ownership |
| Mounts | One ordered descriptor for every `/mounts/<index>` value | Named-volume policy, snapshot/commit ownership |
| Networking | Exact OCI network namespace/device descriptors plus explicit extension references | Network objects, IPAM, DNS, aliases, publication policy |
| Process I/O | Complete `ProcessIo` modes and initial terminal size | Box log retention, indexing, redaction, search policy |
| Secrets | A classified mount index or declared runtime mechanism | Secret name, value, authorization decision, materialization credential |
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

SDK transport protocol 3 is the first protocol that carries this contract.
Protocol-2 peers are rejected during negotiation, so an attachment-aware
client cannot be silently downgraded to a server that ignores the field.

The host advertises `AttachmentCapabilities`. Create fails before driver
selection or durable reservation when the schema is unsupported or any
`required` extension version is unavailable. An unsupported advisory
extension remains in the request fingerprint and returned evidence but does
not claim enforcement.

Every accepted manifest participates in the durable create request digest.
The runtime stores the exact manifest with the container record and returns
its SHA-256 digest in `ContainerRecord::attachments_digest`. On reopen it
revalidates all pointers against the immutable configuration snapshot and
checks the stored digest before returning state or resuming an operation.
Changing I/O, classification, extension version, or referenced configuration
while reusing an operation ID therefore fails as a different request.

Records created before protocol 3 have neither a stored manifest nor an
attachment digest. The runtime retains that explicit legacy state for old
lifecycle cleanup, while attachment-aware consumers such as A3S Box must
reject it for a new unified-backend binding rather than reinterpret it.
