# OCI Normative Coverage

## Corpus

The conformance corpus is pinned to OCI Runtime Specification v1.3.0 commit
`92249139eea7161e13745abd4cb6d0ea02a3227a`. It contains the 15 Markdown
documents linked by that release's `spec.md` table of contents:

- common specification, principles, bundle, runtime, configuration, features,
  and glossary documents;
- Linux configuration, runtime, and features documents;
- VM configuration;
- FreeBSD, Solaris, Windows, and z/OS configuration documents.

Every document is embedded from `vendor/runtime-spec/v1.3.0/`. The checked-in
manifest records its SHA-256 digest, so CI fails if the source changes without
an explicit specification update.

## Inventory

`OciNormativeInventory` scans outside fenced examples and HTML comments. It
records every RFC 2119 keyword occurrence with:

- a content-derived SHA-256 ID;
- document and table-of-contents scope;
- source line and heading;
- keyword and same-line occurrence number;
- normalized source text.

The v1.3.0 corpus currently contains 764 entries:

| Disposition | Count | Meaning |
| --- | ---: | --- |
| `specification-definition` | 19 | Notational or glossary definitions |
| `rejected-inapplicable-platform` | 90 | Native FreeBSD, Solaris, Windows, or z/OS workload requirements rejected by the Linux-only workload boundary |
| `validated` | 45 | Exact semantic, bundle, annotation-map, pinned OCI Image annotation-value, and CPU burst/idle relationship rules with positive and negative SDK tests |
| `enforced` | 302 | Root `config.json` placement and read-only-root enforcement; required lifecycle arguments and operation set; valid, unique, and reusable container IDs; exact Query State results; post-create configuration immutability; the create-to-start process barrier; non-terminal `consoleSize` ignore semantics and terminal `consoleSize` PTY initialization; exact process launch and signal exit; scoped delete that removes owned resources while preserving external storage; start, kill, and delete state gates; required OCI State fields, Linux PID lifecycle, annotations, and schema; unknown configuration annotation preservation; all six POSIX Hook phases with exact command, namespace, order, state-stdin, timeout, and failure policy; the four conditional Linux `/dev` links; all required and recommended OCI 1.3 Linux mount options, ID-mapped mounts, unknown filesystem-option pass-through, and accurate mount-option feature reporting; exact absolute and stable relative Linux `cgroupsPath` resolution with invalid-path rejection and cleanup; complete cgroup v2 CPU shares/quota/burst/period/cpuset/idle enforcement with explicit cgroup v1 realtime rejection; all five process capability sets, structured warning-and-continue handling for recognized capabilities the kernel cannot grant, and `noNewPrivileges` with kernel and workload read-back; the 41-name capability feature registry; all 16 OCI rlimit mappings with exact soft/hard kernel read-back; OCI `oomScoreAdj`, scheduler, I/O-priority, init personality, init NUMA memory-policy, Intel RDT, and exec CPU-affinity semantics; accurate unsafe-annotation, memory-policy, and Intel RDT feature reporting; and bounded transactional application of namespaced Linux sysctls enforced by the SDK transport, bundle loader, runtime lifecycle, and Linux executor |
| `conformant` | 2 | The optional `tmpcopyup` entries are satisfied by typed rejection and exclusion from feature reporting; this is an explicit optional omission, not an implementation claim |
| `pending-review` | 306 | Common, Linux, or VM entries awaiting exact evidence binding |

An occurrence is an inventory unit, not an assertion that the surrounding
sentence has already been implemented. Some common documents contain
platform-specific clauses; each pending entry still requires human
applicability review.

The common configuration and runtime-feature annotation maps now have pinned
positive and negative schema evidence for omission, empty maps, string keys,
empty and non-empty string values, and structured or unstructured metadata.
Bundle round-trip evidence separately proves that unknown annotation keys and
their exact values are preserved. The OCI Image Specification reference used
by Runtime Specification 1.3.0 is pinned at
`v1.1.0-rc2@19a74bcb54ba211005a68d85c6b359c2947721ce`, with its configuration,
conversion, schema, definitions, and license sources retained verbatim. The
SDK accepts all eight standard Runtime Specification image keys and validates
the seven values with an unambiguous image-property mapping. Creation times
must satisfy RFC 3339, and stop signals resolve to a bounded Linux signal name,
real-time expression, or number on every host platform. The remaining 13
annotation entries cover reverse-domain guidance, reserved-namespace authoring
constraints, the unresolved array-to-string representation of `os.features`,
conversion provenance, and default stop-signal behavior; they remain pending
until those distinct contracts have direct evidence.

The runtime feature report now derives `potentiallyUnsafeConfigAnnotations`
from one SDK-owned registry of exact built-in keys and the active drivers'
annotation-backed attachment extensions. Configured services publish a sorted,
deduplicated list that matches their actual capability inventory; probe-only
services publish an explicit empty list instead of claiming configuration
support.

The exact capability-set requirements and the adjacent warning policy are both
enforced. Init and exec retain exact read-back for grantable values, remove only
set memberships outside the kernel or executor authority, and send one bounded
structured warning per unavailable capability to the supervising agent before
exec. The control reader rejects malformed, duplicate, or unbounded warning
frames, so the logged message is validated runtime evidence rather than
container-controlled output.

The OCI Linux sysctl entry is also enforced. Shared parsing accepts only known
namespace-scoped keys, the executor prevents mutation through its current host
namespace, and unit plus native-host evidence covers deterministic apply,
read-back, reverse rollback, alias rejection, and IPC/network workload values.

OCI Linux NUMA memory policy is enforced for configured init. One registry
defines the seven recognized modes and three flags used by the planner and
feature document. The executor applies the bounded normalized node mask before
credential reduction and seccomp, immediately reads the complete policy back,
and performs no syscall when the field is omitted. Native Linux, HVF, and WHPX
fixtures verify `MPOL_BIND` with `MPOL_F_STATIC_NODES` on node 0 from inside
the workload.

All 32 OCI Linux Intel RDT configuration entries and four feature-report
entries are owner-bound. The SDK bounds safe CLOS names and schemata input;
the runtime parent applies ordered schemata with read-back, assigns the exact
init PID to control and monitoring tasks, preserves explicit CLOS ownership,
and removes runtime-owned CLOS and monitoring paths during normal and
owner-death cleanup. Feature discovery reports the implemented Intel RDT,
schemata, and monitoring boundary. Real CAT/MBA hardware qualification remains
a release gate rather than a prerequisite for the enforcement classification.

Read-only rootfs handling is bound to planning, namespace-safety rejection,
and real workload write rejection. The same planning boundary proves that OCI
`consoleSize` is ignored for both explicit `terminal: false` and an omitted
`terminal`, for configured init and exec processes. For terminal processes,
the SDK resolves `consoleSize` into the initial PTY dimensions, accepts an
omitted or matching transport copy, and rejects a conflicting copy before
runtime mutation. Init and exec share that path, and the real lifecycle gate
reads the configured size from inside the PTY before exercising resize.

OCI `execCPUAffinity` is enforced only for exec processes. The trusted helper
applies and reads back `initial` before joining the workload cgroup through an
inherited `cgroup.procs` descriptor, then applies and reads back `final` before
entering the retained namespaces and forking the payload. CPU lists are
normalized and bounded by the runtime mask. Omitted or empty phases perform no
affinity syscall, and init planning deliberately ignores the exec-only field.
Native Linux, HVF, and WHPX lifecycle paths verify the final mask from inside
the workload.

## Promotion

Each coverage item has an owner, disposition, rule IDs, and test IDs.
`validated`, `enforced`, `conformant`, and rejected-inapplicable claims require
non-empty rule and test evidence. The verifier rejects:

- a missing, extra, duplicate, or stale requirement;
- a changed document name, scope, or digest;
- an empty owner;
- empty or duplicate rule and test IDs;
- an implementation claim without both rule and test evidence.

Reviewed promotions live in
`conformance/oci-1.3.0-normative-evidence.json`. The generator applies that
small source-of-truth file to a fresh 764-entry baseline and produces
`conformance/oci-1.3.0-normative-coverage.json`. The SDK semantic-rule registry
and the owner-bound non-semantic rule registry are checked in both
directions: an evidence rule must exist, every non-semantic rule must retain
its declared owner, and every directly normative rule must have at least one
requirement binding.

Promotion is monotonic in reviewed commits:

```text
pending-review -> validated -> enforced -> conformant
```

`validated` means static schema or semantic checks exist. `enforced` means the
selected executor or driver applies the behavior or fails. `conformant` means
the reviewed result satisfies the requirement: an optional behavior may be
intentionally omitted with typed rejection and honest discovery, while an
implemented mandatory behavior additionally requires lifecycle, negative,
recovery, and retained upstream evidence.

## Update Workflow

For an intentional OCI release update:

1. replace the vendored corpus and schemas from one exact upstream commit;
2. update the supported version and provenance;
3. generate a fresh schema baseline and apply reviewed normative evidence;
4. review every added, removed, or changed inventory item;
5. restore exact rule, owner, and test mappings only where the new release
   still has valid evidence;
6. run the full conformance and platform suites before raising support.

The normative generator rejects stale evidence instead of silently dropping
it. New or changed requirements remain `pending-review` until an explicit
binding is added.
