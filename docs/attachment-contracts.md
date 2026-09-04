# Versioned Attachment Contracts

## Boundary

`CreateAttachments` is the public, versioned description of every resource
attached to an OCI create or restore request. Schema
`a3s.oci.attachments.v1` covers the original OCI and extension inventory;
`a3s.oci.attachments.v2` adds already-authorized storage;
`a3s.oci.attachments.v3` adds already-authorized Linux network interfaces; and
`a3s.oci.attachments.v4` adds exact reusable guest-session identity. The schemas
are cumulative and the exact schema is negotiated through the selected driver's
`RuntimeInfo::extensions` entry before product preparation begins.

The contract deliberately separates product policy from runtime mechanism:

| Category | Contract evidence | Not carried by the runtime manifest |
| --- | --- | --- |
| Root filesystem | Exact `/root` JSON Pointer and SHA-256 value digest | Image reference, pull/build state, layer ownership |
| Mounts | One ordered descriptor for every `/mounts/<index>` value | Named-volume policy, snapshot/commit ownership |
| Networking | Exact OCI network namespace/device descriptors plus explicit extension references | Network objects, IPAM, DNS, aliases, publication policy |
| Authorized networking (v3) | Caller-issued namespace, interface, and cleanup IDs bound to exact OCI namespace and `linux.netDevices` descriptors | IPAM, DNS, routes, aliases, network policy, and backing-network deletion |
| Network enforcement extension v1 | Opaque enforcement and optional local-redirect IDs, positive generations, lowercase SHA-256 mechanism digests, and one exact caller-owned joined namespace | Hostnames, addresses, rules, routes, credentials, tenant identity, destination choice, and mechanism mutation |
| Reusable guest session (v4) | Logical session ID, positive incarnation, immutable trust domain, bounded capacity, runtime ownership, and explicit empty-session reset mode | Placement policy, tenant identity, warm-pool sizing, VM handles, credentials, and cross-domain reuse authority |
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
driver advertises v2 as part of cumulative v1-v3 because its mount namespace
cleanup preserves external bind sources. Dedicated Linux KVM now has a
separate internal raw-disk transport: the allocation remains outside its
runtime-owned exact-generation share and is never absorbed into the bundle.
KVM deliberately continues to advertise v1 until the destructive real-host
v2/v3 restart, cleanup, replay, and soak gates pass. Other utility-VM drivers
remain v1 until they gain equivalent transport and detach-cleanup evidence.

## Already-authorized Linux networking

A caller upgrades a v1 or v2 manifest to v3 by binding a prepared
`linux.netDevices` entry to the exact OCI network namespace that will receive
it:

```rust,no_run
use a3s_oci_sdk::{
    CreateAttachments, NetworkAttachmentIdentity, NetworkCleanup,
    NetworkCleanupId, NetworkInterfaceId, NetworkNamespaceId, OciBundle,
    ProcessIo,
};

fn network_attachments(bundle: &OciBundle) -> a3s_oci_sdk::Result<CreateAttachments> {
    CreateAttachments::from_bundle(bundle, ProcessIo::default())?
        .attach_linux_network_interface(
            bundle,
            0,
            "tap0",
            NetworkAttachmentIdentity::new(
                NetworkNamespaceId::new("network-namespace-7")?,
                NetworkInterfaceId::new("network-interface-7")?,
                NetworkCleanupId::new("network-cleanup-7")?,
            ),
            NetworkCleanup::ReleaseRuntimeNamespace,
        )
}
```

The three IDs identify caller-authorized allocation incarnations. They are not
namespace paths, host interface names, IP addresses, DNS names, network names,
or policy selectors. The namespace and interface remain independently bound by
their JSON Pointers and canonical-value SHA-256 digests. Multiple interfaces
in one namespace must repeat the same namespace and cleanup IDs and cleanup
mode; interface IDs and OCI interface descriptors remain one-to-one. Reordered
entries, identity aliasing, conflicting cleanup units, descriptor reuse, and
wire drift fail validation.

`NetworkOwnership::Caller` is the only v3 ownership mode. A newly created OCI
network namespace requires `NetworkCleanup::ReleaseRuntimeNamespace`; Runtime
releases that namespace with the container but never releases the caller's
IPAM or backing-network allocation. An OCI namespace with a `path` is joined
and caller-owned, so it requires `NetworkCleanup::PreserveCallerNamespace` and
Runtime leaves the namespace and interface intact. The cleanup ID lets the
caller bind its matching release obligation without giving Runtime product
policy or an external cleanup credential.

Authorized bindings require an exact target interface name. The general v1
OCI mechanism may still use an appended `%d` target template, but v3 rejects
that template because the resulting interface identity is not known before
Create. Rootful Native Linux advertises cumulative v1-v3 because its executor
already type-checks namespace descriptors, moves and verifies interfaces,
rolls back failed Create in reverse order, and scopes normal cleanup to the
configured namespace lifecycle. Rootless Native stays v1-v2 because its helper
contract grants no host network-device authority.

Dedicated Linux KVM contains internal cumulative v2/v3 transports. For v2,
each selected OCI mount must be non-bind `ext4` backed by a canonical,
single-link, 512-byte-aligned raw image outside the runtime-owned bundle and
share. The Host records its exact inode, size, access grant, and deterministic
libkrun block identity without copying or taking cleanup ownership. For the v3
`ReleaseRuntimeNamespace` form, the Host requires every source name to be a
live TAP in the runtime network namespace and derives a locally administered
unicast MAC from the attachment identities and TAP name. It atomically writes
the canonical `a3s.oci.agent-vm-attachments.v2` manifest when storage is
present, retaining v1 bytes for network-only handoff, as a mode-`0600` file in
the exact-generation share. Exact replay retains identical evidence; stale,
non-private, or drifted evidence conflicts.

The isolated shim opens that file through its descriptor-pinned runtime share
and verifies its raw SHA-256 and inode before KVM access. It reopens each raw
image with the authorized access and `O_NOFOLLOW`, rejects replacement, hard
links, system-image alias or serial collision, and attaches it through
`krun_add_disk2` with the VMM read-only bit. It supplies each TAP and MAC through
`krun_add_net_tap`. The Guest independently checks the manifest, exact bundle,
and configuration pointers; maps each disk by libkrun serial, byte size, and
read-only state; rewrites only its selected OCI mount source; locates each VMM
NIC by MAC; and stages all interface renames through collision-free temporary
names before the Agent protocol starts. The resulting binding accepts only the
matching exact target, Guest bundle, and configuration on Create. Joined caller
network namespaces and reusable Guest storage or NIC hotplug are rejected.

These implementations are deliberately not advertised capabilities yet. KVM
must pass destructive real-host v2/v3 restart, cleanup, replay, read-only, and
soak qualification before advertising either cumulative profile. HVF remains
v1 until it has equivalent storage and NIC transports and evidence.

## Opaque network enforcement and local redirect

OAR-01 uses the required `dev.a3s.network.enforcement` extension version 1 on
top of attachment schema v3. It does not introduce attachment schema v5 or a
new SDK transport version. A caller places the canonical JSON returned by
`NetworkEnforcementAttachment::to_annotation_value` in the OCI annotation
whose key is the extension name, binds every configured network interface with
`NetworkCleanup::PreserveCallerNamespace`, and then calls
`attach_network_enforcement`.

The typed value contains only an opaque enforcement ID, a positive generation,
the lowercase `sha256:` digest of the caller-compiled policy artifact, and the
exact `NetworkNamespaceId` already present in the v3 binding. An optional
`LocalNetworkRedirectAttachment` adds only an opaque redirect ID, positive
generation, and mechanism digest. Both resources are caller-owned and use
`PreserveCallerMechanism`; Runtime cannot mutate or delete them.

Version 1 requires one joined OCI network namespace with a non-empty `path`,
requires every configured OCI network descriptor to be covered exactly, and
requires all authorized interfaces to bind that same namespace. The annotation
rejects unknown fields, so hostname rules, IP ranges, DNS data, endpoints,
route decisions, credentials, or tenant metadata cannot cross this boundary.
The caller, currently A3S Box, remains the policy compiler and allocation
authority.

The Host independently negotiates the exact required extension version, passes
the immutable attachment contract to the selected driver, and records the
decoded evidence in `ContainerRecord::network_enforcement`. Restart validation
requires that field, the durable manifest, annotation, configuration snapshot,
and attachment digest to agree exactly. Reusing an operation ID with a changed
generation or digest fails closed.

Rootful Native Linux advertises `dev.a3s.network.enforcement@1` when its executor
has network-device authority. Its real-host qualification joins the exact
caller namespace, moves one authorized interface, exercises an opaque redirect
and rejection mechanism, reopens the Host service around the live generation,
and proves that Delete preserves the namespace, interface, and both mechanisms.
Rootless Native Linux and the VM drivers omit the extension; callers must treat
missing per-driver extension support as unavailable.

## Reusable guest-session identity

A caller upgrades a derived manifest to v4 only for SharedGuestKernel
isolation:

```rust,no_run
use a3s_oci_sdk::{
    CreateAttachments, GuestSessionCapacity, GuestSessionGeneration,
    GuestSessionId, GuestSessionReset, IsolationRequest, OciBundle, ProcessIo,
    TrustDomainId,
};

fn guest_session_attachments(
    bundle: &OciBundle,
) -> a3s_oci_sdk::Result<(IsolationRequest, CreateAttachments)> {
    let isolation = IsolationRequest::SharedGuestKernel {
        trust_domain: TrustDomainId::new("tenant-7")?,
    };
    let attachments = CreateAttachments::from_bundle(bundle, ProcessIo::default())?
        .attach_reusable_guest_session(
            bundle,
            &isolation,
            GuestSessionId::new("guest-session-7")?,
            GuestSessionGeneration::new(3)?,
            GuestSessionCapacity::new(8)?,
            GuestSessionReset::RetainWithinTrustDomain,
        )?;
    Ok((isolation, attachments))
}
```

`GuestSessionId` is a caller-issued logical grouping identity, not a VM name,
socket, path, or handle. `GuestSessionGeneration` fences one exact incarnation
and must be positive. Capacity is fixed in the immutable request and bounded
from 1 through 64. Runtime is the only guest-lifetime owner.
`DestroyOnEmpty` requires reclamation when the final member is deleted;
`RetainWithinTrustDomain` may keep that incarnation empty but never authorizes
admission from another trust domain or reassignment under another generation.

Request validation requires exactly one v4 binding for SharedGuestKernel and
rejects a binding for DedicatedVm or SharedHostKernel. The manifest trust domain
must equal the typed isolation request. Adding storage or network bindings after
the session preserves v4 rather than downgrading the schema.

The platform-neutral HVF/KVM lifecycle uses a private root for each exact
session incarnation. An immutable mode-`0600` marker binds that root to the
complete v4 contract before a container bundle becomes Guest-visible. Marker
publication writes and syncs a complete private staging file, links it into the
pending name without replacement, and then links that complete inode into the
final name without replacement; a racing or pre-existing marker is read back
and must match the exact decoded contract. Creates for one
logical session serialize through a session gate, reuse one authenticated Guest
owner, and count admitted retryable members against the fixed capacity. A
different contract at the same incarnation, a stale generation, or a newer
generation while members remain fails with no VM replacement. A newer
generation may replace an empty retained incarnation only after the old owner
and root are reaped.

On Unix, every retained guest-session and bundle-handoff marker read opens the
final component with `O_NOFOLLOW|O_CLOEXEC`, validates the opened inode against
the pre-open device/inode snapshot, and reads from that handle. The reader also
requires stable private-file metadata and an exact byte count before decoding;
a symlink substitution, remove-and-recreate race, truncation, or growth is
rejected (or surfaced as a bounded retryable race) rather than being treated as
ownership evidence.

The same no-replace publication invariant applies to every runtime-owned
attachment marker. Bundle-handoff markers and Linux KVM attachment manifests
are written to random, fully synced private staging inodes, adopted under
their fixed pending names without replacement, and promoted to their final
names without replacement. Each incumbent or concurrent pending file is
decoded and compared with the exact request before cleanup; malformed or
cross-generation ownership evidence fails closed (a private malformed KVM
pending inode is discarded only after its unchanged inode identity is
rechecked as a legacy interruption). The Windows WHPX path uses
the protected `MoveFileExW` no-replace primitive with the same bounded retry
and read-back contract.

An owner replacement cannot infer that a persisted session root is an empty
pool. When no in-process owner or handoff admission proof exists, the runtime
rejects the create before consuming the caller bundle, even if the root is
from an older generation. The exact recovered tombstones or an explicit
cleanup must retire that root before a new guest can be launched.

Deleting a non-final member removes only its exact bundle. `DestroyOnEmpty`
reaps the owner and session root after the last member;
`RetainWithinTrustDomain` keeps the empty owner available only for the
identical binding. A terminal member Create failure does not reap an occupied
shared Guest. Driver shutdown deduplicates members to one owner close and
leaves exact stopped tombstones for durable cleanup. Owner-death reports are
named by session incarnation so every member can recover its own retained
record without pretending the first container owns the VM. Distinct session
deletes may proceed concurrently; removal of their shared private namespace is
idempotent when another exact cleanup wins the final empty-directory race.

No production utility-VM driver advertises v4 yet. The common mechanism and
deterministic driver tests are present, while cumulative v2/v3 advertisement
and per-driver real-host restart, cleanup, and soak qualification remain the
enablement gates. KVM's internal dedicated v2/v3 transports do not bypass
those qualification gates.

Utility-VM attachment capabilities are explicit driver configuration, not an
inference from the advertised isolation classes. The driver repeats schema
negotiation at its own preflight boundary and passes the complete immutable
`CreateAttachments` value into the platform VM factory. Production HVF and KVM
still advertise v1, while the reusable-session test profile opts into v4. This
keeps unsupported or unqualified storage and NIC surfaces fail-closed without
discarding their typed contracts at the future launch boundary.

## TEE launch mechanism

A dedicated utility VM may carry exactly one policy-neutral TEE launch
extension. AMD SEV-SNP uses `dev.a3s.tee.amd-sev-snp@1`; Intel TDX uses
`dev.a3s.tee.intel-tdx@1`. The matching OCI annotation value is canonical JSON
for `a3s.oci.tee-launch.v1` and selects an explicit `hardware` or `simulated`
mode. Simulated mode is mechanically testable evidence and is never a hardware
security claim.

The annotation alone is inert. Only the matching required manifest extension
creates a TEE request, and a driver must use the separately supplied typed
launch field rather than interpret an undeclared annotation.

```rust,no_run
use a3s_oci_sdk::{
    CreateAttachments, OciBundle, ProcessIo, TeeLaunchRequest, TeeMode,
    TeeTechnology, AMD_SEV_SNP_LAUNCH_EXTENSION,
};

fn tee_attachments(bundle: &OciBundle) -> a3s_oci_sdk::Result<CreateAttachments> {
    let expected = TeeLaunchRequest::new(TeeTechnology::AmdSevSnp, TeeMode::Hardware)
        .to_annotation_value()?;
    assert_eq!(
        bundle
            .spec()
            .annotations()
            .as_ref()
            .and_then(|annotations| annotations.get(AMD_SEV_SNP_LAUNCH_EXTENSION)),
        Some(&expected),
    );
    CreateAttachments::from_bundle(bundle, ProcessIo::default())?.attach_tee_launch(bundle)
}
```

Construction rejects both technology extensions in one bundle, a technology
that differs from its annotation key, a missing or advisory manifest entry,
an extension classified as network or secret material, non-canonical JSON, or
an annotation larger than 4 KiB. Request validation additionally rejects TEE
launch on SharedGuestKernel or SharedHostKernel. The exact extension,
annotation, configuration, and attachment digest remain in durable create or
restore state and are decoded again before driver dispatch and attestation.

TEE launch create and restore require SDK protocol 9. A selected driver must
advertise `Attest`, dedicated-VM isolation, and at least one exact known TEE
extension as one capability set. No production driver currently advertises
that set; the SDK, Host orchestration, durable replay, and simulated recording
driver do not constitute SEV-SNP or TDX hardware support. See
[TEE launch and attestation](tee-attestation-contract.md).

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
`shares/<container>/<generation>/bundle` for DedicatedVm. SharedGuestKernel
uses
`shares/.guest-sessions/<session>/<session-generation>/<container>/<generation>/bundle`
and mounts only that session incarnation into its Guest. Replay accepts only
the exact destination with matching container and session ownership evidence.
Delete and terminal create failure remove only an exact digest- and
generation-bound handoff.

The public container record deliberately retains the caller's original bundle
identity. The relocated path is an internal driver attachment and is never a
substitute durable product record.

## Negotiation And Failure Rules

SDK transport protocol 3 is the first protocol that carries v1. Protocol-2
peers are rejected during negotiation, so an attachment-aware client cannot be
silently downgraded to a server that ignores the field. Protocol 5 is required
for v2 create requests, protocol 6 for v3 create requests, and protocol 7 for
v4 create requests. A non-TEE restore requires protocol 8 because it also
carries an immutable checkpoint reference and typed response; a TEE create or
restore requires protocol 9. Both the client and
server reject a versioned operation before dispatch when the negotiated
connection predates its schema; v1 create wire serialization remains unchanged
and keeps its protocol-3 compatibility.

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
checks the stored digest before returning state or resuming an operation. A v4
record also retains `ContainerRecord::guest_session`; an OAR-01 record retains
`ContainerRecord::network_enforcement`. Each explicit field must equal its
manifest and annotation binding exactly. Changing I/O, classification, storage
identity/access/lifetime, network namespace/interface/cleanup identity,
enforcement or redirect identity/generation/digest, guest-session
identity/generation/trust domain/capacity/reset, TEE technology/mode,
extension version, or
referenced configuration while reusing an operation ID therefore fails as a
different request.

Records created before protocol 3 have neither a stored manifest nor an
attachment digest. The runtime retains that explicit legacy state for old
lifecycle cleanup, while attachment-aware consumers such as A3S Box must
reject it for a new unified-backend binding rather than reinterpret it.
