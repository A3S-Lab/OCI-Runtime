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
- process arguments, environment, working directory, rlimits, OOM score
  adjustment, scheduler, and I/O priority;
- mount destinations, ID-mapping pairs, hooks, and annotations;
- namespace uniqueness, namespace paths, UID/GID mapping ranges, and
  namespace-dependent hostname, paths, sysctls, time offsets, and network
  devices; sysctl parsing also preserves OCI dot/slash notation while rejecting
  traversal, aliases at execution planning, hostname conflicts, and
  host-global controls;
- absolute or relative Linux `cgroupsPath` identity with bounded normalized
  cgroupfs names and early rejection of traversal, control characters, NUL,
  systemd syntax, and ambiguous separators;
- mount ID mappings, seccomp listener/errno relationships, selected CPU,
  block-I/O, and RDMA relationships;
- bounded Intel RDT names and schemata, required memory-policy mode, bounded node
  lists and mode/flag relationships, required Linux personality domain and
  empty flags, and Linux device/path safety;
- absolute OCI VM runtime paths and NUL rejection;
- explicit rejection of native Windows, FreeBSD, Solaris, and z/OS workload
  sections because A3S runs Linux workloads on every host.

All 88 rule identifiers come from one typed registry. Twenty-five are classified
as direct OCI normative validators and are currently bound to 43 exact source
entries in the normative evidence manifest. Linux `oomScoreAdj`, scheduler,
and I/O-priority runtime constraints plus executor and real-host tests promote
14 process requirements to `enforced`. Scheduler validation covers duplicate
and policy-specific flags, nice and realtime-priority ranges, and deadline
ordering and kernel bounds. The remainder are explicit kernel/runtime
constraints or platform policy and cannot accidentally be reported as
normative coverage.

The validator does not invent hardware minima or silently convert unsupported
controls. Host capabilities, path allowlists, and whether the selected driver
can enforce a valid request belong to driver policy and enforcement.

For Linux sysctls, validation and execution share `OciLinuxSysctlKey` as the
source of truth. An accepted key is classified as IPC, network, UTS, or user
namespace state. The Linux executor then checks the selected namespace
identity, bounds the transaction, verifies procfs read-back, and rolls back any
partial change before Create can be reported as ready.

For Linux network devices, validation requires an explicit network namespace,
bounds host and target interface names, accepts `%d` only as one appended
template, and rejects duplicate exact targets. The executor repeats the
security-critical bounds while building a deterministic move plan, then
preflights real source and target namespaces before the first netlink mutation.

For Linux cgroups, validation and execution share `OciLinuxCgroupPath` rather
than applying host-native path rules. The parser therefore behaves identically
on Linux, macOS, and Windows while preserving whether a value began with `/`.
The Linux executor resolves that bit only after it has a verified cgroup v2
mount and, for rootless execution, rejects absolute targets outside the retained
delegation.

Intel RDT validation and execution share public SDK bounds: a CLOS name is at
most 255 bytes, complete `schemata` contains at most 256 entries, each line is
at most 4 KiB, and all ordered writes together are at most 64 KiB. Generic
single-line resctrl resource names remain extensible; the validator does not
freeze the kernel's resource registry. The executor separately enforces `L3:`
and `MB:` prefixes for their dedicated fields, verifies read-back, and fails if
the selected runtime namespace has no mounted resctrl filesystem.

For Linux NUMA memory policy, validation, execution, and feature reporting
share the same seven-mode and three-flag registries. A bounded parser rejects
malformed or out-of-range node lists and incompatible mode/flag combinations
before mutation. The executor then applies the normalized mask to configured
init and requires immediate kernel read-back; omission preserves inherited
policy.

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
