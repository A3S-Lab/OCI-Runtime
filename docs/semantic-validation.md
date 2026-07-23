# OCI Semantic Validation

## Purpose

The official OCI JSON Schemas validate document shape and scalar domains.
They cannot express every normative relationship between fields. The Rust SDK
therefore exposes `OciSemanticValidator` and applies it before runtime state
mutation.

Validation has three phases:

| Phase | Boundary |
| --- | --- |
| `configuration` | Accepting or decoding an immutable OCI bundle |
| `create` | Preparing runtime-owned resources without starting the program |
| `start` | Releasing the configured init program |

Configuration and create allow `process` to be absent. Start requires a
runnable Linux process. A lifecycle implementation must validate the durable
bundle snapshot, not a mutable source `config.json`, at the start boundary.

## Public Report

`inspect` returns a bounded `OciSemanticValidationReport`. Each violation has:

- a JSON instance path;
- a stable rule identifier;
- an `invalid` or `unsupported-platform` classification;
- a diagnostic message.

At most 64 violations are returned. `validate` converts the first violation
into a stable SDK error while retaining the total or truncated count.
Validation always runs the pinned official schema first.

## Current Rules

The initial rule set covers:

- Linux root and runnable-process requirements;
- process arguments, environment, working directory, rlimits, scheduler, and
  I/O priority;
- mount destinations, ID-mapping pairs, hooks, and annotations;
- namespace uniqueness, namespace paths, UID/GID mapping ranges, and
  namespace-dependent hostname, paths, sysctls, time offsets, and network
  devices;
- mount ID mappings, seccomp listener/errno relationships, selected CPU,
  block-I/O, and RDMA relationships;
- Intel RDT names and schemata, memory-policy node relationships, and Linux
  device/path safety;
- absolute OCI VM runtime paths and NUL rejection;
- explicit rejection of native Windows, FreeBSD, Solaris, and z/OS workload
  sections because A3S runs Linux workloads on every host.

The validator does not invent hardware minima or silently convert unsupported
controls. Host capabilities, path allowlists, and whether the selected driver
can enforce a valid request belong to driver policy and enforcement.

## SDK Request Boundary

Every SDK request implements `ValidateRequest`. Validation is applied by:

1. `RuntimeClient` for in-process callers;
2. `RuntimeTransportClient` before serialization;
3. `serve_transport_connection` after decoding and before dispatch.

The server check is authoritative for untrusted local IPC peers. In addition
to OCI bundle, process, and resource semantics, request validation checks
terminal consistency, checkpoint paths, and bounded event, output, and stdin
payloads.

## Remaining Conformance Work

This rule set establishes a fail-closed validation boundary. Complete OCI
conformance still requires:

- promotion of all pending entries in the generated normative coverage lock
  to an exact rule, enforcement owner, and test;
- complete positive and negative semantic fixtures;
- selected-driver capability and enforcement checks;
- durable lifecycle and start-time snapshot validation;
- hook-order, recovery, security-negative, and upstream conformance evidence.

Until those gates pass, no lifecycle operation is advertised as conformant.
