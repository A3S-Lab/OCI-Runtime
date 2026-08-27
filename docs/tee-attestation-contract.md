# TEE Launch And Attestation Contract

## Status

SDK protocol 9 freezes the policy-neutral launch and attestation mechanism. It
does not claim that any production driver can launch AMD SEV-SNP or Intel TDX,
collect hardware evidence, or satisfy a product security policy. The Host,
durable state, transport, capability registry, and deterministic simulated
driver coverage are implemented. Production drivers advertise neither the TEE
extensions nor `RuntimeOperation::Attest` until hardware execution, restart,
upgrade, cleanup, and destructive real-host qualification pass.

A3S Box or Cloud owns evidence appraisal, endorsement lookup, freshness policy,
allowlists, tenant authorization, and the decision to release a workload or a
secret. Runtime never converts a provider report into a trust decision.

## Launch Binding

One dedicated-VM create or restore may require exactly one launch technology:

| Technology | Required extension | Annotation schema |
| --- | --- | --- |
| AMD SEV-SNP | `dev.a3s.tee.amd-sev-snp@1` | `a3s.oci.tee-launch.v1` |
| Intel TDX | `dev.a3s.tee.intel-tdx@1` | `a3s.oci.tee-launch.v1` |

The annotation is canonical JSON and selects `hardware` or `simulated` mode.
The extension must be required, version 1, classified as neither network nor
secret material, and match the technology encoded in the annotation. Both
technology extensions in one request fail closed. The canonical annotation is
bounded to 4 KiB.

An annotation without the matching required attachment entry is not a TEE
request and makes no security claim. Drivers must treat the Host-supplied typed
`tee_launch` field as authoritative and ignore TEE-looking bundle annotations
when that field is absent.

`CreateAttachments::attach_tee_launch` derives this contract from the immutable
OCI bundle. Create and restore validation reject a TEE extension with
SharedGuestKernel or SharedHostKernel isolation. The Host decodes the typed
`TeeLaunchRequest` before durable lifecycle mutation and supplies it separately
to `DriverCreateRequest` or `DriverRestoreRequest`; a driver must enforce that
exact mechanism and mode rather than infer security from `DedicatedVm`.

The complete configuration snapshot and attachment manifest are durable. For
each retained container, Runtime revalidates the annotation, required
extension, isolation, configuration digest, and attachment digest on reopen.
Recovery fails before driver dispatch if the recorded driver no longer
advertises the required attachment schema or extension.

## Capability And Protocol Gate

TEE-backed create, TEE-backed restore, and `attest` require protocol 9. Client
and server both reject them before service dispatch on protocol 8 or earlier.
Non-TEE operation minima are unchanged.

One per-driver capability entry must advertise all of the following:

- `IsolationClass::DedicatedVm`;
- `RuntimeOperation::Attest`; and
- version 1 of at least one known TEE launch extension.

The registry rejects `Attest` without a known TEE extension, a known TEE
extension without `Attest`, or a TEE extension without dedicated-VM isolation.
Checkpoint and restore remain separately gated; advertising TEE does not imply
either operation.

## Attestation Request And Response

`TeeAttestationRequest` carries an `OperationContext`, one exact positive
container generation, and exactly 64 bytes of report data. The report data is
the caller's nonce or digest binding. Callers should put a cryptographic digest
in this field rather than raw secret material because the request and response
are retained in durable state.

A new attestation attempt accepts only a `created` or `running` generation that
was launched with a durable TEE extension. Stopped generations,
current-generation targets, non-TEE records, and isolation drift fail before
driver dispatch. Runtime then claims the exact container so another lifecycle
mutation cannot race evidence collection. An already committed exact response
or terminal error remains replayable after the source stops or is deleted.

The immutable `a3s.oci.tee-attestation.v1` response binds:

- the exact container ID and generation;
- the launch technology and hardware/simulated mode;
- the exact 64-byte report data;
- configuration and attachment-manifest SHA-256 digests;
- the durable runtime driver;
- the exact Host executable artifact and driver-build SHA-256 digest;
- one canonical SHA-384 launch measurement; and
- one bounded opaque provider-evidence payload.

Evidence is canonical base64 with its decoded size and SHA-256 digest. The
decoded payload must contain between 1 byte and 256 KiB, and its canonical
lowercase ASCII media type is bounded to 128 bytes. Unknown fields,
non-canonical encodings, uppercase or malformed digests, response/request
drift, or durable-source drift fail closed.

Runtime does not parse the provider payload or prove that its internal report
data, measurement, signer, firmware, TCB, or debug status is truthful. The
driver must copy and bind those values correctly; the external verifier must
parse the provider format and validate the claims.

## Durability And Retry

Attestation uses `a3s.oci.operation.v6`. Before writing an intent, the Host
performs read-only source, driver, extension, and current-artifact checks. The
journal then retains the exact target and report data under the caller's
`OperationId`. Drivers must collect or retrieve evidence idempotently by that
operation ID and durably retain a successful result before returning it.

A fresh result must bind the Host artifact that invoked it. During recovery
after a Host upgrade, a driver may return the retained artifact from the
original successful attempt. The Host commits the complete response and a
single `ContainerAttested` event before acknowledging driver replay evidence.
The event binds the operation ID, TEE extension, measurement, and evidence
digest. An exact retry after process or machine reopen returns the same typed
response without another driver call.

A retryable driver error leaves the operation and container claim resumable. A
terminal driver error is retained and replayed exactly after releasing the
claim. Reusing an operation ID with changed report data or another target is a
failed precondition. While the source remains retained, startup audit rebinds
every successful response to its exact durable source so a modified journal
cannot bypass the normal completion checks.

## Production Driver Gate

A production implementation must, at minimum:

1. enforce the requested technology and hardware mode at VM creation or
   restore without silently weakening it;
2. bind evidence to the exact live generation, launch measurement, 64-byte
   report data, Host artifact, and driver build;
3. make collection idempotent by operation ID across owner death and upgrade;
4. remove only attempt-owned partial resources on terminal failure;
5. pass negative launch, evidence-tamper, restart, upgrade, concurrency, and
   cleanup matrices on supported hardware; and
6. remain unadvertised when firmware, kernel, VMM, device, or endorsement
   prerequisites are unavailable.

Capability advertisement, not platform name or a requested annotation, is the
authoritative availability signal.
