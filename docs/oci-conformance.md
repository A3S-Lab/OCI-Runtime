# OCI 1.3 Conformance Contract

## Baseline

A3S OCI Runtime targets the released
[OCI Runtime Specification 1.3.0](https://github.com/opencontainers/runtime-spec/releases/tag/v1.3.0).
The exact release tag, not the moving `main` branch, defines the conformance
input for a runtime release.

The SDK currently uses `oci-spec` 0.10.0 for complete Rust data models. A3S
defines its supported range explicitly as 1.0.0 through 1.3.0 and does not use
that dependency's older `runtime::VERSION` constant as a conformance claim.

The complete upstream `schema/` tree and fixtures are vendored without
modification from release commit
`92249139eea7161e13745abd4cb6d0ea02a3227a`. Schema references resolve only
from embedded bytes; validation performs no filesystem or network retrieval.
The validator applies one explicit in-memory compatibility correction for the
release's single legacy `#definitions/uint32` fragment and fails compilation
if that upstream condition changes.

The 15 Markdown documents linked by the same release's `spec.md` table of
contents are also vendored without modification. Their document digests and
all 764 RFC 2119 keyword occurrences are locked in
`conformance/oci-1.3.0-normative-coverage.json`.

## Meaning Of Complete

There are five separate states for an OCI property:

| State | Meaning |
| --- | --- |
| Represented | The public SDK can decode, preserve, and encode the property |
| Validated | Schema and semantic constraints are checked before mutation |
| Planned | A reviewed implementation milestone owns enforcement |
| Enforced | The selected driver applies the requested behavior or fails |
| Conformant | Positive, negative, lifecycle, and recovery evidence passes |

Only `Conformant` counts as implemented in release feature output.
Representing a field in Rust is necessary but is not an enforcement claim.

No field may disappear during SDK, host service, durable state, transport, or
guest-agent serialization. An unknown JSON property is rejected rather than
ignored. A known property that is inapplicable to the selected workload
platform or cannot be enforced by the selected driver is rejected before
create-time state mutation.

## Platform Applicability

The product executes Linux OCI containers:

- directly on Linux through the native driver;
- inside an A3S Linux utility VM on Windows, macOS, and optional KVM-backed
  Linux.

Consequently, complete conformance means:

- all common configuration, process, state, lifecycle, error, warning, and
  hook requirements;
- all Linux configuration requirements;
- all VM configuration requirements that apply when the VM section is used;
- all feature-report schema and accuracy requirements;
- driver-independent behavior identical across native Linux and the guest
  Linux executor.

Solaris, z/OS, and native Windows container configuration remains represented
losslessly by the public `Spec` type, but those workload platforms are not
advertised. A submitted incompatible platform section must produce a typed
pre-create error. Running a Linux container on a Windows host through WHPX
does not make it a native Windows container.

## Current Matrix

| Area | Represented | Validated | Enforced | Conformant |
| --- | --- | --- | --- | --- |
| Complete `Spec` object | Yes | Official schema, version range, unknown fields, initial semantics | No | No |
| Common root, mounts, process, hostname, annotations | Yes | Initial cross-field rules; normative manifest pending | No | No |
| POSIX hooks | Yes | Initial path and environment rules | No | No |
| Linux namespaces and ID mappings | Yes | Initial relationship and range rules | No | No |
| Linux devices, seccomp, capabilities, LSM, sysctl | Yes | Initial path, seccomp, and namespaced-sysctl rules; capability/LSM rules pending | No | No |
| Linux cgroup resources | Yes | Initial CPU, block I/O, and RDMA relationships | No | No |
| Linux Intel RDT, memory policy, time offsets, net devices | Yes | Initial cross-field and path rules | No | No |
| VM hypervisor, kernel, initrd, image, and parameters | Yes | Initial absolute-path and NUL rules; driver policy pending | No | No |
| OCI `State` | Yes | Official schema and typed lifecycle transition contract | No durable state | No |
| OCI `Features` | Yes | Official schema, version and operation separation | Feature-only service | No |
| `create/state/start/kill/delete` | SDK contract | Exhaustive request boundary; durable start validation pending | No | No |
| Hooks and rollback ordering | SDK contract | Pending | No | No |
| Exec, I/O, PTY, wait, pause/resume, update | SDK contract | Typed requests | No | No |
| Checkpoint and restore | SDK contract | Typed requests | No | No |

The current runtime must therefore remain `probe-only`.

## SDK Preservation Boundary

The following official types are public SDK inputs or outputs:

```text
oci_spec::runtime::Spec
oci_spec::runtime::Process
oci_spec::runtime::LinuxResources
oci_spec::runtime::State
oci_spec::runtime::Features
```

`OciBundle` holds the complete decoded `Spec`, the exact validated
`config.json` text, an absolute bundle directory, and a SHA-256 digest of
those exact bytes. Its wire decoder recomputes all derived state and rejects a
relative path, digest mismatch, invalid schema, unknown field, or unsupported
version. The create implementation must durably retain those bytes or a
cryptographically equivalent immutable snapshot before returning `created`.
Changes to the source bundle after create must not affect the container.

The SDK transport maps every service method to a protocol-versioned request
and response variant. Its length-delimited frames are bounded before
allocation, request IDs are correlated, service errors remain typed, and a
protocol violation poisons the connection. Transport decoding invokes
`OciBundle`'s custom fail-closed decoder, so crossing a named pipe, Unix
socket, or guest bridge cannot bypass bundle validation.

`OciSemanticValidator` returns bounded, phase-aware reports with stable rule
identifiers. It currently covers an initial set of common process, mount,
hook, Linux namespace, ID mapping, sysctl, seccomp, resource, Intel RDT,
memory-policy, time-offset, network-device, and VM path relationships.
`ValidateRequest` applies the relevant bundle, process, resource, I/O, path,
and payload checks at the in-process client, IPC client, and server
boundaries. This is a fail-closed foundation, not a claim that every normative
requirement is already conformant.

The SDK adds only runtime-call metadata that OCI intentionally leaves
implementation-specific:

- validated container, process, operation, and trust-domain IDs;
- generation fences and idempotency IDs;
- explicit isolation requirement;
- deadline and I/O attachment policy;
- stable error class;
- driver and effective-isolation evidence.

These additions do not replace or reinterpret OCI configuration fields.

## Automated Evidence

The conformance pipeline pins the OCI 1.3.0 release. It currently provides:

1. a generated and checked-in inventory of all 423 named JSON Schema
   properties and enum values;
2. a generated and checked-in inventory of all 764 RFC 2119 occurrences from
   the 15 normative source documents, including source-document SHA-256
   digests and stable requirement IDs;
3. upstream positive and negative schema fixture tests;
4. strict typed round-trip tests for applicable upstream Linux, state, and
   feature fixtures;
5. positive and negative semantic fixtures with stable rule identifiers;
6. request-validation tests, including an untrusted raw-wire rejection test;
7. in-memory end-to-end transport tests plus real Windows named-pipe and Unix
   socket connector tests.

Remaining evidence includes:

1. positive decode/round-trip fixtures for every applicable property;
2. negative cross-field and semantic fixtures;
3. promotion of all 655 pending common, Linux, and VM normative entries to
   exact rule IDs, enforcement owners, and test IDs;
4. lifecycle and hook-order traces;
5. feature-report comparisons against actual driver behavior;
6. crash-recovery and cleanup evidence;
7. differential results against certified `crun` for shared behavior.

CI must fail when a pinned schema property has no classification or when code
advertises an operation without a passing implementation test. It also fails
when a normative source document changes digest or a coverage item is missing,
duplicated, or claims implementation without rule and test evidence.

## Update Policy

An OCI specification upgrade begins with a dedicated commit that updates the
pinned schemas, model dependency, property inventory, support range, fixtures,
and this matrix together. Supporting a new model field does not by itself
raise `OCI_RUNTIME_SPEC_VERSION_MAX`; semantic and enforcement gates must pass
first.
