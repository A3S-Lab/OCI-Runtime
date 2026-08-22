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

## Schema Support Manifest

The schema inventory and the normative inventory are separate locks. The
schema inventory contains every named property and enum value in the pinned
OCI 1.3.0 JSON Schemas. Each item has a SHA-256 identity derived from the OCI
version, schema name, JSON pointer, inventory kind, and exact value.

`conformance/oci-1.3.0-schema-evidence.json` is the reviewed source of truth
for applicable items. Its 29 bindings cover 334 unique item IDs with exact
owners, rule IDs, test IDs, and rejection rationales. The Linux-only workload
boundary generates the remaining 89 native-platform rejections. Applying that
evidence to a fresh inventory produces the checked-in
`conformance/oci-1.3.0-schema-coverage.json` v2 lock:

| Disposition | Count | Meaning |
| --- | ---: | --- |
| `rejected-inapplicable-platform` | 89 | Native FreeBSD, Solaris, Windows, or z/OS workload fields rejected at the Linux workload boundary |
| `rejected-unsupported` | 75 | Known fields or values rejected before durable or platform mutation |
| `validated` | 2 | Static schema or semantic validation owns the complete current behavior |
| `enforced` | 257 | Runtime, executor, or driver behavior has direct rule and test evidence |
| `conformant` | 0 | No schema item is promoted solely by this classification audit to release conformance |
| `pending-review` | 0 | Every one of the 423 schema inventory items has an exact disposition |

The verifier rejects unknown or duplicate evidence bindings, generated
platform-disposition overrides, inventory drift, missing owners, missing or
duplicate rule and test IDs, unknown or wrongly owned rules, pending items,
and rejected items without a rationale. The checked-in lock must equal a fresh
generation from the reviewed evidence byte for byte at the data-model level.
Regenerate it with:

```sh
cargo run -q -p a3s-oci-sdk --example generate_schema_coverage -- \
  conformance/oci-1.3.0-schema-evidence.json \
  conformance/oci-1.3.0-schema-coverage.json
```

Zero pending schema items means the field inventory is classified. It does
not mean the runtime has passed release conformance; the manifest deliberately
contains zero `conformant` items while lifecycle, security-negative,
cross-driver, packaged-artifact, and upstream-tool gates remain open.

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
| `reviewed-external` | 14 | Bundle-packager, configuration-author, image-converter, runtime-caller, or subsequent-specification responsibilities with a mandatory reviewed rationale and tested runtime boundary |
| `validated` | 51 | Exact semantic, bundle, annotation-map, pinned OCI Image annotation-value including serialized `os.features`, process/root phase, Linux/utility-VM platform-section, and CPU burst/idle relationship rules with positive and negative SDK tests |
| `enforced` | 578 | Root `config.json` placement, declared-root directory admission, read-only-root enforcement, and OCI-required unknown-property ignore semantics with exact raw-document retention; Linux-only platform applicability; all eight Linux namespace types with exact inherit/create/join behavior, type-checked retained join descriptors, bounded exact UID/GID mappings without source-ownership mutation, and normalized monotonic/boottime offsets; ordered common mounts, root-relative destination normalization, optional mount fields, and ID-mapped mounts; exact hostname/domainname and init/exec argv, environment, cwd, terminal default, UID/GID, supplementary groups, and umask; required lifecycle arguments and operation set; valid, unique, and reusable container IDs; exact Query State results; post-create configuration immutability; the create-to-start process barrier; non-terminal `consoleSize` ignore semantics and terminal `consoleSize` PTY initialization; exact process launch and signal exit; scoped delete that removes owned resources while preserving external storage; start, kill, and delete state gates; required OCI State fields, Linux PID lifecycle, annotations, and schema; unknown configuration annotation preservation; all six POSIX Hook phases with exact command, namespace, order, state-stdin, timeout, and failure policy; the four conditional Linux `/dev` links; all required and recommended OCI 1.3 Linux mount options, unknown filesystem-option pass-through, and accurate mount-option feature reporting; exact absolute, stable relative, and omission-generated private Linux cgroup paths with invalid-path rejection and cleanup; exact cgroup-v2 ownership delegation for the mapped process UID, with a new cgroup namespace, an exact writable mount, bounded kernel-listed files, normative fallback, and unlisted-file preservation; complete cgroup v2 CPU shares/quota/burst/period/cpuset/idle enforcement with explicit cgroup v1 realtime rejection; exact memory limit/reservation/swap and PIDs create/update mapping for finite, zero, and unlimited values with cgroup v1-only memory plus `net_cls`/`net_prio` network controls rejected before mutation; cgroup v2 Block I/O default/per-device weights and read/write BPS/IOPS limits with keyed read-back, partial-update preservation, reverse rollback, and explicit leaf-weight rejection; cgroup v2 HugeTLB usage and reservation limits with full-range input, dynamic page-size checks, partial-update preservation, exact effective read-back, and reverse rollback; cgroup v2 RDMA HCA handle/object limits with device preflight, partial-update preservation, kernel-effective read-back, and reverse rollback; bounded cgroup v2 Unified control-file writes with dynamic controller enablement, runtime-unknown and write-only file support, kernel-defined formatting, and readable no-op/rollback snapshots; exact OCI Linux static nodes, default devices, `/dev/ptmx`, terminal `/dev/console`, target cleanup, and immutable declared/default device-inventory BPF with ordered resource-rule narrowing; exact Seccomp schema and policy handling with real x86_64/AArch64 BPF installation plus pre-mutation rejection of unadvertised flags, architecture sets, listener fields, and notification actions; complete VM schema admission plus selected-driver rejection of caller-owned hypervisor, kernel, image, and hardware launch configuration before durable or platform mutation; all five process capability sets, structured warning-and-continue handling for recognized capabilities the kernel cannot grant, and `noNewPrivileges` with kernel and workload read-back; the 41-name capability feature registry; all 16 OCI rlimit mappings with exact soft/hard kernel read-back; OCI `oomScoreAdj`, scheduler, I/O-priority, init personality, init NUMA memory-policy, Intel RDT, and exec CPU-affinity semantics; schema-valid feature documents whose version, hooks, Linux platform, namespace, cgroup, seccomp, LSM, and ID-mapped-mount claims match the implementation; accurate unsafe-annotation, memory-policy, and Intel RDT feature reporting; exact valid-value rejection, typed additional-descriptor projection, network-device termination ownership, cgroup fit/default-path/v1-to-v2 behavior, rootfs propagation plus masked/read-only paths; and bounded transactional application of namespaced Linux sysctls enforced by the SDK transport, bundle loader, runtime lifecycle, and Linux executor |
| `conformant` | 12 | Optional `tmpcopyup` and SELinux mount labels are satisfied by typed rejection and honest feature reporting. The recommended Linux default filesystems are supplied where the executor owns the required namespace resources, with host sysfs deliberately withheld from a user namespace that inherits host networking. Runtime defines no nonstandard State values or extra State properties, defers optional remaining process properties until Start, passes no optional null descriptors, attaches no unrequested extra cgroup controllers, advertises an explicit supported value subset, and freezes configured-service capabilities outside workload execution. These are explicit reviewed dispositions, not unconditional implementation claims |
| `pending-review` | 0 | Every OCI 1.3 normative occurrence has an exact reviewed disposition |

An occurrence is an inventory unit, not an assertion that the surrounding
sentence has already been implemented. Some common documents contain
platform-specific clauses; every entry retains an explicit applicability and
ownership review.

`reviewed-external` is deliberately separate from implementation status. It
is used only when the normative subject is outside the runtime role, and each
binding must retain a non-empty rationale plus rule and test evidence for the
runtime boundary. It cannot be used to turn missing runtime behavior into a
conformance claim.

All 66 `runtime.md` entries are owner-bound. The runtime emits only the four
standard State values, preserves the exact Linux PID contract, validates and
applies or rejects the complete accepted configuration before committing
Create, and keeps the configured process behind the Start barrier. Failed
operations retain exact replay evidence without a live container, and durable
fault injection plus real hook rollback verifies the error policy. Init, exec,
and poststop warnings are logged while successful operation and cleanup flow
continue unchanged.

The Linux default-filesystem recommendation is resolved by a dedicated
immutable plan. In a new mount namespace, omitted `/proc` and eligible
read-only `/sys` mounts are applied before configured entries so child mounts
remain visible; omitted `/dev/pts` and writable `/dev/shm` mounts are applied
afterward so an explicit `/dev` parent cannot hide them. Exact configured
destinations win, while an inherited or joined mount namespace remains
untouched. A non-initial user namespace may receive `/sys` only when it owns a
new network namespace. Linux rejects a fresh sysfs otherwise, and binding the
host mount would expose host networking. Native Linux evidence covers all four
filesystem types plus a real `/dev/shm` write/remove cycle, and the rootless
inherited-network profile proves the three safe defaults with sysfs absent.

All 24 OCI VM configuration entries are owner-bound. The pinned schema accepts
the complete hypervisor, kernel, image, and hardware shape, checks every
required relationship and image format, and retains the four absolute-path
rules in semantic validation. A dedicated negative fixture rejects NUL bytes
in all executable VM paths and hypervisor or kernel parameters. The scoped
coverage gate freezes all 26 VM-related schema items as fail-closed and the
normative split as four validated path requirements plus 20 runtime-owned
controls. No current A3S driver executes bundle-selected VM launch material:
the host rejects any caller-provided `vm` section after driver selection but
before durable generation reservation, bundle handoff, hypervisor launch, or
mutating driver dispatch. A future driver must explicitly replace that
fail-closed default and validate and enforce every field it accepts.

The Linux namespace, user-mapping, and time-offset review promotes 17 entries
to enforced and leaves the two existing namespace path and uniqueness rules
validated. Pinned schema evidence requires each namespace type and all three
ID-mapping members. The executor distinguishes inherited, newly created, and
joined UTS, mount, IPC, network, cgroup, PID, user, and time namespaces; opens
and type-checks every join target before mutation; and verifies the resulting
descriptor identity. UID/GID mapping ranges are bounded, non-overlapping, and
read back exactly, while ID-mapped mount evidence proves the source ownership
is unchanged. Optional signed seconds and nanoseconds default independently,
then normalized monotonic and boottime offsets are written and read back in
Native Linux and utility-VM workloads.

The common Root, Mounts, POSIX-platform Mounts, Process, and POSIX-platform
User review promoted 37 entries. Rootfs admission now proves that the declared
path resolves to a directory before namespace entry. Mount planning preserves
the source array order, treats legacy relative destinations as rooted at `/`,
accepts omitted source, type, and option fields where OCI permits them, and
uses `mount_setattr(MOUNT_ATTR_IDMAP)` for explicit ID mappings. Init and exec
retain the exact argv, environment, cwd, terminal default, UID/GID,
supplementary groups, and umask. Native Linux rechecks those process values
inside an executable-script workload. Common-document clauses that only
describe native Windows, Solaris, FreeBSD, or z/OS workloads are tied to the
pre-mutation Linux-only rejection boundary. The conventional `rootfs`
basename is explicitly classified as bundle-author guidance: the runtime
accepts that name and preserves valid alternatives without rewriting them.

The common extensibility review promoted two entries. Bundle admission checks
all known schema and semantic constraints, retains the exact source document
and digest across SDK wire serialization, and ignores unknown top-level and
nested properties when constructing the typed execution model. The
dependency's deprecated top-level `uidMappings` and `gidMappings`
compatibility fields are retained only in the immutable raw document and are
never interpreted as executable configuration.

The common platform review promoted 18 entries. Linux and utility-VM sections
may coexist and pass the same schema and semantic boundary. Native FreeBSD,
Solaris, Windows, and z/OS sections fail before mutation. AppArmor and SELinux
remain accurately unadvertised and explicitly rejected when requested;
Windows username fields share the Windows-process rejection boundary. The
Linux executor applies and reads back exact hostname and domainname values,
and the retained Native Linux workload now checks both values through procfs.

The common configuration and runtime-feature annotation maps now have pinned
positive and negative schema evidence for omission, empty maps, string keys,
empty and non-empty string values, and structured or unstructured metadata.
Bundle round-trip evidence separately proves that unknown annotation keys and
their exact values are preserved. The OCI Image Specification reference used
by Runtime Specification 1.3.0 is pinned at
`v1.1.0-rc2@19a74bcb54ba211005a68d85c6b359c2947721ce`, with its configuration,
conversion, schema, definitions, and license sources retained verbatim. The
SDK accepts all eight standard Runtime Specification image keys and validates
each value against its image-property mapping. Creation times must satisfy RFC
3339, stop signals resolve to a bounded Linux signal name, real-time
expression, or number on every host platform, and `os.features` must contain a
JSON serialization of the Image Specification array of strings. Converter
provenance, reverse-domain and reserved-namespace authoring policy, default
stop orchestration, and future specification-key reservation are classified
as external responsibilities with explicit rationales. Unknown annotation
keys remain preserved under the separate runtime extensibility requirement.

The runtime feature report now derives `potentiallyUnsafeConfigAnnotations`
from one SDK-owned registry of exact built-in keys and the active drivers'
annotation-backed attachment extensions. Configured services publish a sorted,
deduplicated list that matches their actual capability inventory; probe-only
services publish an explicit empty list instead of claiming configuration
support.

Every emitted feature document is now validated against the pinned OCI 1.3
schema before it leaves the service. The advertised minimum and maximum
versions are the same constants used by bundle admission, and both boundaries
have direct acceptance tests. Hooks, Linux availability, namespaces, cgroup
managers, seccomp actions/operators/architectures/flags, AppArmor, SELinux, and
ID-mapped mounts are bound to exact report and executor tests. A3S resolves
driver-specific capabilities when the configured service is constructed, then
keeps the report stable across workload execution. This satisfies the intent
of the compile-time recommendation without making probe-only discovery claim
unconfigured drivers.

The final 17 pending entries are now owner-bound. Two common value-policy
entries require deterministic rejection of invalid or unsupported values and
an explicit supported subset. Two Linux runtime entries bind optional file
descriptors to the exact typed inherited-descriptor plan and record that A3S
does not add optional null descriptors. Two network-device entries prove that
Create moves interfaces in while workload termination neither reconfigures nor
moves them out. Six cgroup entries bind optional fit checks, the private
omission-generated path, absence of unrequested controllers, representable
v1-to-v2 conversion, and typed rejection where conversion is impossible.
Rootfs propagation, masked paths, and read-only paths retain planner plus
native read-back evidence. `linux.mountLabel` fails at selected-driver
preflight because SELinux mount labeling is not advertised. The final Features
recommendation is bound to the stable configured-service report. These reviews
add 15 owner-bound rules, move 12 entries to `enforced` and five to
`conformant`, and leave zero `pending-review` entries.

All 36 Seccomp and notification-state entries are owner-bound. Pinned-schema
tests cover required and optional nested members, empty lists, and every enum
family. The shared executor installs the advertised x86_64/AArch64 actions and
argument operators as bounded pure-Rust BPF, rejects invalid errno and
`valueTwo` relationships, and preserves omission as a no-op. It does not
advertise userspace notification, filter flags, non-native architecture sets,
or multi-architecture dispatch; requests for those controls fail during
immutable init planning before any runtime mutation. The conditional socket,
`SCM_RIGHTS`, and process-state transport requirements are therefore bound to
that explicit rejection boundary, not claimed as implemented transport.

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

All three OCI PIDs entries are owner-bound to one shared Create and live-Update
boundary. The executor writes finite and zero limits verbatim, converts the
`-1` unlimited sentinel to `pids.max=max`, and rejects values below `-1` before
mutation. The opt-in control/workload topology accepts zero for the workload
while retaining its finite management headroom, but rejects an unlimited
workload because that layout promises a bounded control-plane envelope.

All 14 OCI memory-controller entries are owner-bound. Create and live Update
share validation for the `limit`, `reservation`, and combined memory-plus-swap
fields: zero is preserved, `-1` becomes the cgroup v2 `max` token, values below
`-1` fail before mutation, and a finite combined swap limit requires a finite
compatible hard limit. `memory.low` remains independent from `memory.max`, as
required by cgroup v2 protection semantics. Kernel-memory, TCP kernel-memory,
swappiness, OOM-killer disablement, v1 hierarchy, and pre-update usage checks
fail with typed `Unsupported` errors instead of being silently ignored.

The Linux network-controller review promotes all five entries to enforced.
`linux.resources.network` describes the cgroup v1 `net_cls` and `net_prio`
interfaces, which have no equivalent on the runtime's cgroup v2 boundary. The
shared planner rejects class IDs and interface priorities with a typed
`Unsupported` error before both Create and live Update can mutate a cgroup or
device policy.

The Block I/O review promotes 14 previously pending entries to enforced. With
the existing validated weight/leaf-weight relationship, all 15 Block I/O
occurrences are owner-bound. The shared Linux executor treats `io` as an
optional cgroup v2 controller, maps default and per-device weights through BFQ
or generic `io.weight`, and merges the four throttle lists into keyed `io.max`
writes. Create and live Update verify every requested value; partial updates
preserve omitted fields, and failures reverse applied mutations. Device
identities and throttle rates are required, OCI zero rates map to cgroup v2
`max`, duplicate devices fail before mutation, and the cgroup v1-only
`leafWeight` model returns a typed `Unsupported` error.

The HugeTLB review promotes all three entries to enforced. The pinned schema
requires both fields and the local version-pinned OCI type correction retains
the full `uint64` limit range. The shared executor accepts only canonical page
sizes that match live cgroup-v2 controls, treats `hugetlb` as optional until a
limit is requested, and writes the kernel-representable usage limit plus the
reservation limit when that control exists. Create and live Update read every
effective value back; keyed updates preserve omitted page sizes and participate
in the same reverse rollback as static controls. `control-workload-v1` applies
HugeTLB only to the workload leaf. Native x86_64 and aarch64 qualification adds
real control/workload read-back whenever the runner exposes a usable HugeTLB
controller and page-size inventory.

The RDMA review promotes all five entries to enforced. The SDK still requires
at least one HCA limit per device, while the executor validates bounded device
names, requires the optional `rdma` controller only when requested, and checks
the live device inventory before device-policy mutation. Create and live Update
preserve omitted handle or object fields, normalize the kernel signed-counter
ceiling to `max`, read every effective keyed value back, and reverse applied
devices before earlier cgroup mutations. `control-workload-v1` applies RDMA only
to the workload leaf. Native qualification adds exact control/workload read-back
whenever the host exposes a usable RDMA controller and device.

The Unified review promotes all four entries to enforced. The executor accepts
bounded single-file maps, rejects unsafe names, runtime-owned `cgroup.*` state,
and typed/unified file conflicts, and keeps stable write order. Controller
inventory is kernel-driven rather than a runtime allowlist, so unknown
controllers remain usable when the hierarchy exposes and enables them. Missing
or unenableable controllers and unavailable files fail before device-policy
mutation. Create and live Update write each value without assuming how an
unknown file formats read-back. Update skips readable no-ops and snapshots
readable state for rollback while accepting write-only controls.
`control-workload-v1` keeps the map on the workload leaf. Native x86_64 and
aarch64 qualification reads `memory.high` from both children, verifies a
kernel-normalized partial `io.max` write when possible, and exercises rootful
and delegated-rootless live updates.

The Linux-device review promotes all 20 entries. Schema and semantic checks cover
all four node types, required paths and conditional device numbers, duplicate
kernel identities, optional metadata, and every allowed-device field. The
rootful executor creates exact private sources, accepts paths outside `/dev`,
rejects conflicting existing targets, supplies the six default nodes and
`/dev/ptmx`, and binds a terminal init's PTY slave to `/dev/console`. Its
rootfs-identity-bound manifest removes only placeholders it created. Ordered
device-access rules preserve wildcard and reset semantics, while omitted,
empty, cleared, and allow-all resource rules can only narrow the immutable
declared/default inventory boundary. When `linux.cgroupsPath` is omitted, the
runtime creates a private generation-fenced path so the boundary is always
attached. Native ARM64 Linux evidence grants `CAP_MKNOD`, permits a declared
node, rejects an undeclared node, then remounts a `nodev` device source with
`dev` and still receives `EPERM` on the undeclared device.

The cgroup-ownership review promotes all ten entries. Delegation is planned
only when the raw OCI mount source and destination are exactly `cgroup` and
`/sys/fs/cgroup`, the options contain no `ro`, the resulting filesystem is
cgroup v2, and the container creates a new cgroup namespace. The executor maps
`process.user.uid` to its host UID, restricts rootless delegation to the
executor identity, preserves GID, and uses a retained cgroup descriptor for
each ownership change and read-back. The bounded kernel inventory accepts only
single-component control names, tolerates listed files that do not exist, and
uses the three-file OCI fallback only when the inventory itself is absent.
Native Linux evidence proves mapped writable ownership, an unchanged unlisted
control, read-only preservation, child-cgroup creation, and complete cleanup.

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
`reviewed-external`, `validated`, `enforced`, `conformant`, and
rejected-inapplicable claims require non-empty rule and test evidence. External
bindings additionally require a non-empty rationale. The verifier rejects:

- a missing, extra, duplicate, or stale requirement;
- a changed document name, scope, or digest;
- an empty owner;
- empty or duplicate rule and test IDs;
- an implementation claim without both rule and test evidence;
- an external-role classification without a reviewed rationale.

Reviewed promotions live in
`conformance/oci-1.3.0-normative-evidence.json`. The generator applies that
small source-of-truth file to a fresh 764-entry baseline and produces
`conformance/oci-1.3.0-normative-coverage.json`. The SDK semantic-rule registry
and the owner-bound non-semantic rule registry are checked in both
directions: an evidence rule must exist, every non-semantic rule must retain
its declared owner, and every directly normative rule must have at least one
requirement binding.

Runtime implementation promotion is monotonic in reviewed commits, while a
requirement whose normative subject is outside the runtime takes a separate
reviewed branch:

```text
pending-review -> validated -> enforced -> conformant
              \-> reviewed-external
```

`validated` means static schema or semantic checks exist. `enforced` means the
selected executor or driver applies the behavior or fails. `conformant` means
the reviewed result satisfies the requirement: an optional behavior may be
intentionally omitted with typed rejection and honest discovery, while an
implemented mandatory behavior additionally requires lifecycle, negative,
recovery, and retained upstream evidence. `reviewed-external` never means
implemented; it records why a producer, caller, or specification-author
requirement is not owned by the runtime and how that boundary is tested.

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
