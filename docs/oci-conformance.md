# OCI 1.3 Conformance Contract

## Baseline

A3S OCI Runtime targets the released
[OCI Runtime Specification 1.3.0](https://github.com/opencontainers/runtime-spec/releases/tag/v1.3.0).
The exact release tag, not the moving `main` branch, defines the conformance
input for a runtime release.

The SDK currently uses `oci-spec` 0.10.0 for complete Rust data models. A3S
defines its supported range explicitly as 1.0.0 through 1.3.0 and does not use
that dependency's older `runtime::VERSION` constant as a conformance claim.

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
| Complete `Spec` object | Yes | Syntax, version range, unknown fields | No | No |
| Common root, mounts, process, hostname, annotations | Yes | Pending semantic validators | No | No |
| POSIX hooks | Yes | Pending | No | No |
| Linux namespaces and ID mappings | Yes | Pending | No | No |
| Linux devices, seccomp, capabilities, LSM, sysctl | Yes | Pending | No | No |
| Linux cgroup resources | Yes | Pending | No | No |
| Linux Intel RDT, memory policy, time offsets, net devices | Yes | Pending | No | No |
| VM hypervisor, kernel, initrd, image, and parameters | Yes | Pending allowlist validator | No | No |
| OCI `State` | Yes | Typed lifecycle transition contract | No durable state | No |
| OCI `Features` | Yes | Version and operation separation | Feature-only service | No |
| `create/state/start/kill/delete` | SDK contract | Request types | No | No |
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

`OciBundle` holds the complete decoded `Spec`, a canonical absolute bundle
directory, and a SHA-256 digest of the exact `config.json` bytes. The create
implementation must durably retain either those exact bytes or a
cryptographically equivalent immutable snapshot before returning `created`.
Changes to the source bundle after create must not affect the container.

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

The conformance pipeline will pin the OCI 1.3.0 release and produce:

1. a generated inventory of every JSON Schema property and enum value;
2. positive decode/round-trip fixtures for every property;
3. negative schema and cross-field fixtures;
4. one enforcement owner and test ID for every applicable normative
   requirement;
5. lifecycle and hook-order traces;
6. feature-report comparisons against actual driver behavior;
7. crash-recovery and cleanup evidence;
8. differential results against certified `crun` for shared behavior.

CI must fail when a pinned schema property has no classification or when code
advertises an operation without a passing implementation test.

## Update Policy

An OCI specification upgrade begins with a dedicated commit that updates the
pinned schemas, model dependency, property inventory, support range, fixtures,
and this matrix together. Supporting a new model field does not by itself
raise `OCI_RUNTIME_SPEC_VERSION_MAX`; semantic and enforcement gates must pass
first.
