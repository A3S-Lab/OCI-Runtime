# macOS HVF Development

## Current capability boundary

macOS feature discovery reports the `libkrun-hvf` driver. The feature probe:

1. requires the Apple Silicon architecture supported by A3S OCI Runtime;
2. reads `kern.hv_support` directly through `sysctlbyname`;
3. records both observations in the versioned feature inventory;
4. does not create a VM or mutate runtime state;
5. keeps driver readiness at `probe-only`.

Intel macOS is reported as unsupported by A3S driver policy instead of being
silently treated as an unavailable Apple Silicon host.

The separate `hvf-smoke` command crosses the next host API boundary. On Apple
Silicon it calls the system Hypervisor.framework directly, creates the single
VM object associated with the process, destroys it, and emits a versioned
`a3s.oci.hvf-smoke.v1` report. No libkrun dependency is involved.

## Entitlement and signing

`kern.hv_support = 1` proves only that the host reports Hypervisor.framework
hardware support. It does not prove that the executable has permission to
create a VM.

The repository contains the minimal development entitlement at
`packaging/macos/a3s-oci-hvf.entitlements`:

```xml
<key>com.apple.security.hypervisor</key>
<true/>
```

Build the CLI and ad-hoc sign a disposable copy:

```sh
cargo build -p a3s-oci-cli

smoke_dir="$(mktemp -d)"
trap 'rm -rf "$smoke_dir"' EXIT
cp target/debug/a3s-oci "$smoke_dir/a3s-oci"
codesign --force --sign - \
  --entitlements packaging/macos/a3s-oci-hvf.entitlements \
  "$smoke_dir/a3s-oci"
codesign --verify --strict "$smoke_dir/a3s-oci"
"$smoke_dir/a3s-oci" hvf-smoke
```

The signed command exits successfully only when both `hv_vm_create` and
`hv_vm_destroy` succeed. It exits with status `2` for unsupported,
unavailable, denied, or partial-cleanup results.

On the local Apple Silicon validation host:

- `kern.hv_support` returned `1`;
- the unsigned executable failed with
  `hv_vm_create returned HV_DENIED (0xFAE94007)`;
- the ad-hoc signed executable created and destroyed the real VM object.

This negative and positive evidence proves that the implementation does not
mistake hardware discovery for executable authorization.

## Report contract

The stable report fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Always `a3s.oci.hvf-smoke.v1` for this contract |
| `platform` | Host platform on which the command ran |
| `status` | Overall prerequisite and VM-object lifecycle status |
| `apple_silicon` | Whether the runtime target is macOS arm64 |
| `hypervisor_supported` | `true`, `false`, or unavailable from the direct query |
| `vm_created` | Whether `hv_vm_create` succeeded |
| `vm_destroyed` | Whether `hv_vm_destroy` released the object |
| `reason` | Symbolic and numeric diagnostic for a failed gate |

A successful report is:

```json
{
  "schema_version": "a3s.oci.hvf-smoke.v1",
  "platform": "macos",
  "status": "available",
  "apple_silicon": true,
  "hypervisor_supported": true,
  "vm_created": true,
  "vm_destroyed": true
}
```

The VM guard retains cleanup ownership until `hv_vm_destroy` succeeds. If the
explicit destroy call fails, the guard makes a final best-effort destroy
attempt while the report remains unsuccessful.

## CI evidence

The macOS job signs the already-tested CLI copy with the checked-in entitlement
and runs `hvf-smoke`.

- If `kern.hv_support = 1`, CI requires a successful create/destroy report.
- Otherwise CI requires exit status `2`, `status = unavailable`, and both VM
  lifecycle fields to remain false.

Hosted-runner virtualization availability can vary, so CI retains both the
positive and fail-closed branches. Signed local Apple Silicon runs retain the
positive host lifecycle evidence independently of hosted-runner policy.

## Isolated libkrun context gate

The separate `a3s-oci-krun-shim` owns the native libkrun boundary. The main
runtime, public SDK, and feature CLI do not link or load libkrun.

The macOS arm64 shim carries a deterministic archive derived from the
A3S Box v3.1.0 release:

`crates/krun/runtime/macos-aarch64/krun-macos-arm64.tar.xz`

The build verifies the archive and both native files before staging them next
to the shim. The shim then:

1. rejects a runtime directory or asset that is a symbolic link;
2. recomputes both file hashes immediately before loading;
3. loads `libkrunfw.5.dylib` and `libkrun.1.17.0.dylib` by absolute path;
4. resolves only the functions required by the context and VM-entry smokes;
5. creates one libkrun configuration context;
6. records one vCPU and 128 MiB of memory;
7. replaces implicit TSI with plain vsock and maps guest port 4093 to a
   generated macOS Unix-socket path;
8. releases the context through an ownership guard.

Run a relocatable, signed copy:

```sh
cargo build -p a3s-oci-krun

smoke_dir="$(mktemp -d)"
cp target/debug/a3s-oci-krun-shim "$smoke_dir/"
cp -R target/debug/a3s-oci-krun-runtime "$smoke_dir/"
codesign --force --sign - \
  --entitlements packaging/macos/a3s-oci-hvf.entitlements \
  "$smoke_dir/a3s-oci-krun-shim"
"$smoke_dir/a3s-oci-krun-shim" context-smoke
```

A successful `a3s.oci.krun-context-smoke.v2` report requires:

```json
{
  "schema_version": "a3s.oci.krun-context-smoke.v2",
  "platform": "macos",
  "status": "available",
  "runtime_bundle_loaded": true,
  "context_created": true,
  "vm_configured": true,
  "agent_vsock_configured": true,
  "context_released": true,
  "vcpus": 1,
  "memory_mib": 128
}
```

macOS CI runs this gate independently of `kern.hv_support`, because allocating
and configuring a libkrun context does not enter a VM. CI also changes one byte
in a copied runtime asset and requires rejection before context creation.
Native runtime hashes and source provenance are recorded in
[Runtime Provenance](../crates/krun/RUNTIME-PROVENANCE.md).

## Real Linux guest entry gate

The `vm-smoke` command crosses the guest-execution boundary without claiming
an OCI workload driver. It uses the kernel embedded in the pinned
`libkrunfw.5.dylib`, presents a caller-supplied arm64 Linux rootfs through
virtiofs, executes `/bin/sh`, and requires an exact guest-written marker to be
visible on the host.

Standard macOS libkrun consumes the process in `krun_start_enter`. The shim
therefore keeps verification in a parent process and performs all libkrun work
in a hidden child:

```text
a3s-oci-krun-shim vm-smoke
        │
        ├── validate rootfs, /bin/sh, console, and absent marker
        ├── spawn signed worker and read bounded setup evidence
        │       ├── reverify and load the pinned native bundle
        │       ├── create and configure the context
        │       ├── configure rootfs, command, and console
        │       └── krun_start_enter → Linux guest → marker → guest exit
        ├── enforce 30-second timeout and reap the worker
        ├── require natural guest exit code 0
        └── verify and remove the exact marker
```

The parent never treats pre-entry evidence or a successful libkrun API call as
guest execution. Success requires all of the following in one report:

```json
{
  "schema_version": "a3s.oci.krun-vm-smoke.v1",
  "platform": "macos",
  "status": "available",
  "runtime_bundle_loaded": true,
  "context_created": true,
  "vm_configured": true,
  "rootfs_configured": true,
  "workload_configured": true,
  "console_configured": true,
  "vm_entered": true,
  "guest_exit_code": 0,
  "marker_verified": true,
  "marker_removed": true,
  "console_created": true,
  "vcpus": 1,
  "memory_mib": 512
}
```

The retained qualification rootfs is the untouched Alpine 3.22.5 aarch64
minirootfs:

- URL:
  `https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz`
- bytes: `3,966,256`
- SHA-256:
  `3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70`

Run the gate with the signed relocatable shim from the previous section:

```sh
asset_dir="$(mktemp -d)"
rootfs="$asset_dir/rootfs"
archive="$asset_dir/alpine-minirootfs-3.22.5-aarch64.tar.gz"
mkdir "$rootfs"
curl --fail --location --output "$archive" \
  https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz
printf '%s  %s\n' \
  '3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70' \
  "$archive" | shasum -a 256 --check
tar -xzf "$archive" -C "$rootfs"

"$smoke_dir/a3s-oci-krun-shim" vm-smoke \
  --rootfs "$rootfs" \
  --console "$asset_dir/console.log"
```

On the local Apple Silicon qualification host, the signed worker booted the
guest, returned exit code zero, verified and removed
`a3s-oci-hvf-vm-smoke-v1`, and left no smoke marker in the rootfs. The same
build without the Hypervisor entitlement reached the complete context
configuration boundary, failed `krun_start_enter`, returned status `2`, wrote
no marker, and reported no false VM entry.

macOS CI downloads and verifies the same rootfs. When
`kern.hv_support = 1`, it requires the complete positive report. On hosted
runners where virtualization is unavailable, it requires status `2`, complete
pre-entry configuration evidence, no guest exit code, no marker, and no false
success. The parent terminates and reaps a worker that exceeds the bounded
startup interval.

## Authenticated guest-agent bridge

The `agent-vm-smoke` command now crosses the authenticated host/guest boundary
without promoting HVF to a workload driver. It reuses the same protocol and
static Linux executor used by WHPX; there is no macOS-specific guest protocol.

The host runtime establishes the trust chain in this order:

1. generate an unguessable portable endpoint name and a one-time 256-bit
   session token;
2. atomically create `/private/tmp/<endpoint>` with mode `0700`;
3. bind `<endpoint>/agent.sock`, set mode `0600`, and verify that both entries
   are non-symlinks owned by the effective runtime user;
4. start the public shim as an isolated process-group leader;
5. let the shim spawn the direct worker that owns `krun_start_enter`;
6. accept the libkrun Unix connection and read its PID through
   `LOCAL_PEERPID`;
7. query `PROC_PIDTBSDINFO` through `proc_pidinfo` and require that the peer's
   parent is the exact public shim PID;
8. remove the socket and private directory while retaining the accepted
   stream;
9. send the token only after process identity verification, negotiate protocol
   version 9, and require the static arm64 guest to advertise exactly
   `create`, `state`, `start`, `kill`, `delete`, `wait`, `exec`,
   `signal-process`, `wait-process`, `pause`, `resume`, `processes`, `update`,
   `stats`, `read-output`, `write-stdin`, `close-stdin`, `resize`, `file`, and
   `filesystem`.

The parent shim validates the rootfs, fixed
`/usr/bin/a3s-oci-agent`, console, and protected socket before spawning the
worker. The worker validates them again, removes the bootstrap token from its
own environment, configures plain vsock port 4093, passes the token only to
the fixed guest executable, and emits bounded pre-entry evidence. Closing the
negotiated connection shuts down the guest executor and returns the natural
guest exit status through the worker and parent shim.

Build and install the static guest:

```sh
rustup target add aarch64-unknown-linux-musl
host_triple="$(rustc -vV | sed -n 's/^host: //p')"
rust_lld="$(
  rustc --print sysroot
)/lib/rustlib/$host_triple/bin/rust-lld"
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$rust_lld" \
  cargo build -p a3s-oci-agent --release \
    --target aarch64-unknown-linux-musl
cargo build -p a3s-oci-cli -p a3s-oci-krun

install -d "$rootfs/usr/bin"
install -m 0755 \
  target/aarch64-unknown-linux-musl/release/a3s-oci-agent \
  "$rootfs/usr/bin/a3s-oci-agent"
```

Use the signed relocatable shim prepared above:

```sh
target/debug/a3s-oci agent-vm-smoke \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --rootfs "$rootfs" \
  --console "$asset_dir/agent-console.log"
```

The top-level report is `a3s.oci.agent-vm-smoke.v9`. A successful Apple Silicon
qualification must retain the following contract:

```json
{
  "schema_version": "a3s.oci.agent-vm-smoke.v9",
  "platform": "macos",
  "status": "available",
  "endpoint_bound": true,
  "endpoint_name": "a3s-oci-agent-<32 lowercase hex characters>",
  "shim_spawned": true,
  "shim_process_id": 12345,
  "bridge_process_id": 12346,
  "shim_client_verified": true,
  "protocol_negotiated": true,
  "selected_protocol": 9,
  "agent_version": "0.1.0",
  "guest_architecture": "aarch64",
  "advertised_operations": [
    "create",
    "state",
    "start",
    "kill",
    "delete",
    "wait",
    "exec",
    "signal-process",
    "wait-process",
    "pause",
    "resume",
    "processes",
    "update",
    "stats",
    "read-output",
    "write-stdin",
    "close-stdin",
    "resize",
    "file",
    "filesystem"
  ],
  "shim_report_verified": true,
  "shim_exit_code": 0,
  "console_created": true,
  "macos_cleanup": {
    "endpoint_removed": true,
    "shim_reaped": true,
    "bridge_reaped": true,
    "open_descriptors_before": 11,
    "open_descriptors_after": 11,
    "descriptor_inventory_restored": true
  }
}
```

The numeric PIDs are observations rather than stable values. Success requires
both to be nonzero and different: the first identifies the public shim and the
second the kernel-identified direct worker child. Descriptor counts are also
observations rather than fixed values. Success requires a positive baseline,
an identical post-session count and complete `(fd, fd_type)` inventory, removal
of the exact reported endpoint, and disappearance of both observed processes.

The same local build without the Hypervisor entitlement completed all bounded
shim configuration, failed `krun_start_enter`, returned status `2`, reported
`protocol_negotiated = false`, and left neither a worker process nor an
`a3s-oci-agent-*` directory below `/private/tmp`. Tests also reject an
unrelated Unix peer before reading protocol bytes, reject a wrong token after
direct-child verification, prevent endpoint collisions, and terminate and
reap the entire shim process group on timeout.

macOS CI builds the static aarch64 musl agent and runs both signed and
missing-entitlement paths. A virtualization-capable runner must complete the
full authenticated report. An unavailable host must remain fail closed. Every
branch requires both the command's in-process cleanup evidence and the shell's
independent private-endpoint baseline comparison to pass.

## Fixed OCI lifecycle

`oci-vm-smoke` reuses the Windows lifecycle harness without introducing a
macOS-specific OCI profile. The checked-in
`fixtures/utility-vm/config.json` requests an explicit cgroup v2 leaf plus new
UTS, mount, IPC, network, cgroup, PID, user, and time namespaces. The
parent-authenticated user mapping
handshake installs exact rootful UID/GID maps before the remaining namespaces
are created, and the time offsets are written and read back before the first
namespace child is forked. A dedicated namespace PID 1 completes create-time
setup and remains as the reaper. The configured process at PID 2+ verifies the
maps and offsets, installs an explicit `SIGTERM` handler, writes the known
marker only after those checks and start, and remains running until the host
delivers the lifecycle signal.

Prepare a contained bundle from the already verified Alpine archive:

```sh
bundle="$rootfs/var/lib/a3s-oci-smoke/bundle"
mkdir -p "$bundle/rootfs"
cp fixtures/utility-vm/config.json "$bundle/config.json"
tar -xzf "$archive" -C "$bundle/rootfs"
sudo chown -R 0:0 "$bundle/rootfs"

target/debug/a3s-oci oci-vm-smoke \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --vm-rootfs "$rootfs" \
  --bundle "$bundle" \
  --console "$asset_dir/oci-console.log"
```

The fixture maps container ID 0 to guest ID 0. Rootfs trees extracted by a
macOS user therefore must be changed to guest-root ownership before the VM
starts; otherwise APFS ownership such as ID 501 remains unmapped and the
create barrier correctly fails instead of weakening filesystem checks.

The signed Apple Silicon qualification contract is
`a3s.oci.oci-vm-smoke.v9`: bundle loading, created state, exact create replay,
pre-start marker absence, start, running observation, a bounded wait that must
time out while running, exact kill replay, exact normal exit status from the
SIGTERM trap, repeated wait, exact-target exec replay, duplicate process-ID
rejection, bounded process wait, replayed pidfd process signal, stable repeated
process wait, exact init/exec inventory, replay-safe live CPU, memory, cpuset,
and PID updates, normalized cgroup-v2 stats, replayed pause/resume, a
progress-producing exec that remains unchanged while frozen and advances
   after resume, captured stdout/stderr with exact cursor pagination and EOF,
   piped stdin with idempotent close and rejected late writes, controlling PTY
   allocation, exact initial and resized dimensions, interactive input, merged
   terminal output and `VEOF` close, exact binary file upload/download with
   replay and changed-request conflict evidence, descriptor-confined
   mkdir/stat/list/move/recursive-remove with exact replay and cleanup,
   init-exit cleanup of another live exec,
   stopped observation, marker verification, stopped-only delete, exact delete
   replay, post-delete NotFound, marker removal, guest-runtime cleanup, and the
   complete nested authenticated bridge report.
The observed container PID must be positive, and the nested report must prove
exact endpoint removal, complete current-process descriptor-inventory
restoration, and disappearance of both shim/worker PIDs after exit.

The guest keeps a dedicated namespace PID 1 but opens a pidfd for the
authenticated configured process at PID 2+ before returning created state.
The lifecycle `SIGTERM` and all forced cleanup therefore target that retained
kernel process reference instead of resolving its numeric PID again.

The same command with an unsigned shim returned status `2` before protocol
negotiation, retained the nested `krun_start_enter` failure, wrote no workload
marker, and left no endpoint or VM worker. CI exercises the signed lifecycle
when virtualization is available and otherwise requires the same fail-closed
pre-entry behavior.

## Multi-container lifecycle

`oci-vm-multi-container-smoke` submits two distinct contained bundles over one
authenticated guest-agent connection. Both configured processes must remain
behind their create barriers with distinct positive guest-visible PIDs.
Starting,
killing, waiting for, and deleting A must preserve B's exact created state and
leave B's marker absent. A bounded wait on running A must return
`DeadlineExceeded` without preventing a concurrent state query for B.

The command then rejects A generation 1 after delete, recreates A as generation
2, rejects cross-container reuse of A's operation ID for B, removes recreated
A, and lets B complete independently:

```sh
jq '.linux.cgroupsPath = "a3s-oci-smoke-b"' \
  "$bundle_b/config.json" >"$bundle_b/config.json.tmp"
mv "$bundle_b/config.json.tmp" "$bundle_b/config.json"

target/debug/a3s-oci oci-vm-multi-container-smoke \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --vm-rootfs "$rootfs" \
  --bundle-a "$bundle_a" \
  --bundle-b "$bundle_b" \
  --console "$asset_dir/oci-multi-container.log"
```

The two simultaneously live bundles must use distinct cgroup v2 paths; the
checked-in fixture reserves `a3s-oci-smoke-a` for bundle A.

The `a3s.oci.oci-vm-multi-container-smoke.v9` report also requires exact
mutation replay, exact repeated normal-exit results for A and B, independent
wait/state progress, and an existing-namespace phase. That phase rejects a
wrong-type descriptor before state, joins donor UTS, IPC, network, cgroup, PID,
user, and time namespaces while retaining a private mount namespace, then
joins the donor mount namespace in a second workload. Both workloads must
cross `exec`, remain running for a bounded observation window, stop with the
expected status, leave the donor created record unchanged, and remove all
state. A third workload must create missing directory and file mount targets
before start and then prove shared rootfs propagation, a distinct read-only
path, empty read-only masked file and directory replacements, recursive VFS
attributes across an rbind submount, explicit `idmap` and `ridmap` ownership
on detached filesystem mounts, read-only rootfs behavior, an exact normal exit,
state removal, and host-side fixture cleanup. That workload must also run as
PID 2+ beneath a dedicated namespace PID 1 and prove that PID 1 reaps an
adopted child while the workload remains alive.

The complete report also requires both marker removals, no new guest runtime
root, exact host endpoint removal, shim and direct VM-worker reap, and full
descriptor-inventory restoration. The Apple Silicon HVF qualification and
macOS CI both run this gate; an unavailable-hypervisor branch must fail before
negotiation while retaining the same host cleanup evidence.

## Repeated HVF soak gate

`macos-hvf-soak` repeats the complete multi-container matrix above while
creating a fresh authenticated libkrun/HVF utility VM for every serial wave:

```sh
console_dir="$asset_dir/macos-hvf-soak-consoles"
mkdir "$console_dir"

target/debug/a3s-oci macos-hvf-soak \
  --shim "$smoke_dir/a3s-oci-krun-shim" \
  --vm-rootfs "$rootfs" \
  --bundle-a "$bundle_a" \
  --bundle-b "$bundle_b" \
  --console-dir "$console_dir" \
  --iterations 25
```

The bounded `a3s.oci.macos-hvf-soak.v1` configuration accepts 1–10,000 waves
and always keeps two primary containers live together. Each successful wave
qualifies initial A and B plus recreated A, then aggregates the existing
lifecycle/generation, eight-namespace join, rootfs/mount, ID-mapped mount,
namespace PID 1, and orphan-reaping evidence. It also requires removal of both
workload markers and the guest runtime directory, exact endpoint, shim, and VM
worker cleanup, a distinct protected endpoint name for every wave, and the
same positive host descriptor count before and after every wave.

Every console uses the sortable name `macos-hvf-soak-NNNNN.log`; the command
refuses to overwrite any existing path. A successful report must retain one
console and three primary container generations for every configured wave.
The macOS CI gate requests 25 waves, independently compares host endpoint and
guest runtime inventories, and uploads the JSON report plus all consoles for
14 days. Apple Silicon without available HVF must return status 2 with
`failure_iteration: 1`; Intel macOS is reported as unsupported. Neither branch
is counted as hardware soak success.

The historical pidfd requalification used the 8,493,136-byte static arm64
agent with
SHA-256
`28a283576a62fc36c02642638580ec9fbed29953b868bcb0705218cef50aaa3e`.
Both retained namespace-PID-1 handles completed independently, the observed
container PIDs were 205 and 207, the host descriptor inventory returned from
10 to 10, and the endpoint, both workload markers, shim, VM worker, and guest
runtime root were removed. This evidence predates the dedicated PID 1
supervisor.

The rootful user/time namespace requalification used the 8,618,816-byte static
arm64 agent with SHA-256
`4daaad94dd7166b15f6efbc4aae670897331e1dc58d681b32382dc98f5a90148`.
The fixed lifecycle, two-container lifecycle, and all three no-delete cleanup
phases passed on Apple Silicon HVF only after the workload verified its exact
UID/GID maps and monotonic/boottime offsets.

The recursive mount-attribute requalification used the 8,670,088-byte static
arm64 agent with SHA-256
`bbb1852f95cf59967816804807e831ef5c92a18d0a4fbaeee76101f0c81ff4b9`.
That report retained all lifecycle and eight-namespace join evidence, then
created missing directory and file mount targets before start and proved
shared rootfs propagation, `/proc/sys` read-only enforcement, private empty
read-only replacements for `/proc/meminfo` and `/proc/irq`, recursive
read-only, `nosuid`, `nodev`, `noexec`, `noatime`, `nodiratime`, and
`nosymfollow` attributes across an rbind submount, and a read-only rootfs. The
exact workload exited zero; all container state and fixture artifacts were
removed. The host descriptor inventory returned from 10 to 10, the shim and
VM worker were reaped, and the endpoint and guest runtime root were removed.

The ID-mapped mount requalification used the 8,734,336-byte static arm64 agent
with SHA-256
`f3e9eb482381b988deed1440383c772546558e39570921b100a071187e22e727`.
The schema-v7 workload additionally created detached non-recursive `idmap` and
recursive `ridmap` tmpfs mounts from exact dedicated UID/GID mappings and
observed ownership `1000:1000` and `2000:2000`, respectively. The complete
two-container, namespace-join, rootfs-enforcement, container-state, endpoint,
descriptor, shim, VM-worker, and guest-runtime cleanup gate passed on Apple
Silicon HVF.

The PID 1 supervision requalification used the 8,751,064-byte static arm64
agent with SHA-256
`63867ded67df080173ab9baca1219d56868f51c9ee4fbec57eb6808ea449314c`.
The schema-v7 report retained configured-process PIDs 206 and 209 plus donor
PID 225, proved that the enforcement workload ran as PID 2+ beneath a
dedicated namespace PID 1, and observed an orphan become a direct child of
PID 1 before its terminated `/proc` entry disappeared. The complete
two-container lifecycle, eight-namespace join, recursive and ID-mapped mount,
exact exit-status, state and fixture cleanup gate passed. The host descriptor
inventory returned from 10 to 10, the endpoint was removed, both the shim and
direct VM worker were reaped, and no guest runtime root remained.

## Fault-injected shutdown cleanup

`oci-vm-fault-cleanup` deliberately skips OCI delete after a successful create,
start, or kill boundary:

```sh
fault_dir="$(mktemp -d)"
for fault in after-create after-start after-kill; do
  target/debug/a3s-oci oci-vm-fault-cleanup \
    --shim "$smoke_dir/a3s-oci-krun-shim" \
    --vm-rootfs "$rootfs" \
    --bundle "$bundle" \
    --console "$fault_dir/$fault.log" \
    --fault-after "$fault"
done
```

Each `a3s.oci.oci-vm-fault-cleanup.v4` success retains the exact requested and
injected boundary, a positive guest configured-process PID, pre-start
non-execution, and `normal_delete_attempted: false`. Closing the authenticated
connection must then make the guest executor force-stop any live configured
process and its namespace supervisor, and remove its runtime root before the
agent and VM exit.

The nested `a3s.oci.agent-vm-smoke.v9` report independently requires exact
endpoint removal, shim and direct VM-worker PID disappearance, and complete
`(fd, fd_type)` inventory restoration. The outer report additionally requires
marker removal and no new `a3s-oci-agent-*` directory under the guest `/run`.
Both local Apple Silicon qualification and macOS CI run all three boundaries;
the CI shell compares endpoint and guest-runtime inventories around every
command.

## Host, Guest, and shutdown transport interruption cleanup

`oci-vm-transport-fault-cleanup` moves all nine protocol-v9 request/response
boundaries and both explicit Host shutdown points out of the in-memory matrix
and into a real authenticated HVF VM. Each invocation interrupts `create` at
one Host or Guest transition, or interrupts the first explicit close after a
successful `create`:

```sh
transport_dir="$(mktemp -d)"
for stage in \
  host-before-request-write \
  host-after-request-write \
  host-before-response-read \
  host-after-response-read \
  guest-after-request-read \
  guest-before-dispatch \
  guest-after-dispatch \
  guest-before-response-write \
  guest-after-response-write \
  host-before-shutdown \
  host-after-shutdown
do
  target/debug/a3s-oci oci-vm-transport-fault-cleanup \
    --shim "$smoke_dir/a3s-oci-krun-shim" \
    --vm-rootfs "$rootfs" \
    --bundle "$bundle" \
    --console "$transport_dir/$stage.log" \
    --fault-at "$stage"
done
```

The `a3s.oci.oci-vm-transport-fault-cleanup.v3` report succeeds only when the
selected versioned point is crossed exactly once and normal OCI delete is never
attempted. Host points return the qualification injector's retryable
`Unavailable`. Guest points carry the same validated `OperationId` as
`create`; the first four return a retryable transport disconnect, while
`guest-after-response-write` must deliver the completed response before a
follow-up request observes the disconnect. The fixed Guest writes a matching
console record only after the Linux executor has completed cleanup. Protocol,
service, and cleanup failures remain terminal. Both shutdown points require the
Host to receive the `create` response first. A retained clone then returns the
selected close fault while the sole VM owner performs an idempotent second
close and completes cleanup.

Every run also requires the workload marker to remain absent, no new Guest
runtime directory, a zero Guest and shim exit, exact endpoint removal, shim and
VM-worker reap, and restoration of the complete Host descriptor inventory. The
August 9, 2026 Apple Silicon qualification passed the four Host stages once and
five more complete waves, for 24 fresh HVF VMs, then passed all five Guest
stages in five fresh VMs. The final v3 requalification passed the complete
eleven-stage matrix in eleven fresh VMs. The unprivileged local bundle mapped
container UID/GID 0 to the caller-owned rootfs IDs; Runtime validation and the
Guest executor enforced that explicit mapping without changing the checked-in
rootful fixture.

This is real VM cleanup evidence for all nine Host/Guest `create` transitions
and both Host shutdown stages. It does not by itself prove durable service
reopen or a replacement VM owner.

## Durable service reopen and VM owner replacement

`oci-vm-reopen-replacement` carries all nine Host/Guest transitions for Create,
State, Start, Kill, Delete, Wait, Exec, SignalProcess, WaitProcess, Pause,
Resume, Processes, Update, and Stats through the durable Host service instead
of calling the diagnostic Agent client directly:

```sh
reopen_dir="$(mktemp -d)"
for operation in \
  create state start kill delete wait exec signal-process wait-process pause resume processes update stats
do
  for fault_stage in \
    host-before-request-write \
    host-after-request-write \
    host-before-response-read \
    host-after-response-read \
    guest-after-request-read \
    guest-before-dispatch \
    guest-after-dispatch \
    guest-before-response-write \
    guest-after-response-write
  do
    stage_dir="$reopen_dir/$operation/$fault_stage"
    mkdir -p "$stage_dir"
    target/debug/a3s-oci oci-vm-reopen-replacement \
      --operation "$operation" \
      --shim "$smoke_dir/a3s-oci-krun-shim" \
      --vm-rootfs "$rootfs" \
      --bundle "$bundle" \
      --console-dir "$stage_dir" \
      --fault-at "$fault_stage"
  done
done
```

The first qualification-only HVF driver opens a real authenticated VM and
injects the selected point into `create`. Host points and the first four Guest
points leave the exact durable record and OperationId in `creating`; the VM then
exits with its endpoint, processes, Guest runtime root, and Host descriptor
inventory fully restored. A second `HostRuntimeService` opens the same scratch
state root around a fresh VM/session owner. Its recovery hook accepts that one
record, and retrying the unchanged request completes the same generation.

`guest-after-response-write` has a separate contract because the first Create
response has already reached durable `created`. A State probe observes the
closed connection. The replacement driver rebuilds the pre-start Guest process
inside `recover`, returns `DriverRecovery::recreated_created`, and permits only
that recovery path to reconcile a changed PID. The next Create replay repairs
its cached response from the recovered record. Ordinary state and recovery
observations still reject PID replacement.

`a3s.oci.oci-vm-reopen-replacement.v2` retains nonce-bound Guest evidence and
both nested VM reports, and fails unless the endpoint, shim PID, and direct
VM-worker PID identities differ. It also requires generation and OperationId
reuse, one replacement recovery call, complete force-delete cleanup, and
removal of the scratch state root. The August 10, 2026 Apple Silicon matrix
passed all nine points in 18 fresh VMs. Three additional post-response waves
passed in six fresh VMs; one changed the Guest PID across owners and exercised
the journal repair path. This closes the `create` recovery paths.

For State, the first owner completes Create normally and injects the selected
point into an exact-generation query. The durable record remains `created`.
State carries no OperationId, so Guest qualification uses an independent
boot-time nonce and matches only the exact `state` operation and stage. After
the first VM closes, replacement recovery rebuilds the pre-start process with
the original Create identity and generation; the new query must equal that
recovered record. At `guest-after-response-write`, the first response must be
delivered and match durable state before a second query exposes the disconnect.

`a3s.oci.oci-vm-operation-reopen-replacement.v1` retains this State evidence.
The August 10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs,
including real PID changes across owners and complete cleanup after force
delete.

For Start, the first owner completes Create and injects the selected point into
the exact-generation Start request. The first eight points leave the durable
record in `created`. Replacement recovery rebuilds the pre-start process with
the original Create identity, rebinds the replacement PID, and sends the
unchanged Start identity once. At `guest-after-response-write`, the durable
record is already `running`; replacement recovery recreates and starts the
workload, repairs the completed Create and Start responses with the replacement
PID, and the subsequent Start replay returns without another driver dispatch.
Every path removes any marker written by the first owner before starting the
replacement and then requires the exact replacement marker.

`a3s.oci.oci-vm-operation-reopen-replacement.v2` retains this Start evidence.
The August 10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs,
including the completed-running replay path, distinct owners, and complete
cleanup after force delete.

For Kill, the first owner completes Create and Start, verifies the running
workload marker, and injects the selected point into an exact-generation
signal-9 request. The first eight points leave the durable record in `running`.
Replacement recovery recreates and starts that workload with the original
Create and Start identities, rebinds the replacement PID, repairs both setup
journal responses, and sends the unchanged Kill identity once. At
`guest-after-response-write`, the durable record is already `stopped`;
replacement recovery recreates, starts, and kills the workload to rebuild the
Guest tombstone, and the subsequent Kill replay returns from the completed
durable journal without an API-driven driver dispatch. Every path resets the
first-owner marker, verifies the replacement workload before Kill, and uses
stopped-only Delete.

`a3s.oci.oci-vm-operation-reopen-replacement.v3` retains this Kill evidence.
The August 10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs,
including the completed-stopped replay path, distinct owners, and complete
Host/Guest cleanup.

For Delete, the first owner completes Create, Start, and signal-9 Kill before
injecting the selected point into stopped-only Delete. The first eight points
retain the stopped record and a Prepared Delete journal. Replacement recovery
recreates, starts, and kills the workload with the original setup identities,
rebuilds the Guest tombstone, and dispatches the unchanged Delete once. At
`guest-after-response-write`, no live record remains and the journal is already
SucceededEmpty, so the fresh owner performs no workload recovery or driver
Delete. Schema `a3s.oci.oci-vm-operation-reopen-replacement.v4` retains this
evidence. The August 10, 2026 Apple Silicon matrix passed all nine stages in 18
fresh VMs.

For init Wait, the first owner uses the same stopped setup and injects the
selected point while resolving the exact init target. The first eight points
retain no terminal cache; replacement recovery reconstructs the Guest tombstone
and dispatches Wait once, then caches `signal=9, oom_killed=false`. At
`guest-after-response-write`, that cache is already durable and every reopened
or repeated Wait returns without another driver or Guest dispatch. Host and
Guest stale-generation probes must both fail before cleanup. Schema
`a3s.oci.oci-vm-operation-reopen-replacement.v5` retains this evidence. The
August 10, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

For terminal Exec, the first owner completes Create and Start, then submits one
nonce-bound long-running process with terminal stdin, stdout, and stderr. The
Linux executor reports success only after the target crosses `execve`; a
pre-exec failure returns through the typed control barrier. The first eight
points leave a Prepared Exec journal and a prepared process record with no live
PID, so the replacement owner rebuilds init and dispatches the unchanged Exec
once. At `guest-after-response-write`, the exact live `ProcessRecord` and
Succeeded journal are already durable. Replacement recovery recreates init and Exec,
rebinds both Guest PIDs, repairs the completed journals, and Host replay returns
without another API-driven dispatch. Every path fences the generation, process
ID, terminal mode, and complete request identity; rejects stale or changed Host
and Guest requests; validates a first-owner marker if scheduling reached it;
and requires the replacement process to write the exact marker before force
delete. Schema `a3s.oci.oci-vm-operation-reopen-replacement.v6` retains this
evidence. The August 10, 2026 Apple Silicon matrix passed all nine stages in 18
fresh VMs.

For SignalProcess, setup commits that same long-running terminal Exec with a
nonce-bound SIGUSR1 trap. The first eight points leave the signal journal
Prepared. Replacement recovery recreates init and Exec, then the exact
signal-10 request dispatches once. At `guest-after-response-write`, the journal
is already SucceededEmpty. Recovery waits for the replacement Exec readiness
marker so the trap is installed, reapplies the committed signal, and Host replay
returns without another API-driven driver dispatch. Every path fences complete
Exec and SignalProcess identities, rejects stale and changed Host and Guest
requests, and requires a fresh replacement signal marker before force delete.
Schema `a3s.oci.oci-vm-operation-reopen-replacement.v7` retains this evidence.
The August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

For WaitProcess, setup runs a terminal Exec that writes a nonce-bound readiness
marker, then terminates it with signal 10. Replacement recovery recreates that
Exec, waits for the marker, and reapplies the committed signal. The first eight
points have no Host exit cache, so WaitProcess dispatches once after reopen and
stores `signal=10, oom_killed=false`. At `guest-after-response-write`, the
first owner already stored that result; replacement and later calls replay it
without driver dispatch, and recovery does not report the rebuilt exited Exec
as live. The exact target, timeout, setup identities, stale-generation fences,
and complete cleanup are retained by
`a3s.oci.oci-vm-operation-reopen-replacement.v8`. The August 11, 2026 Apple
Silicon matrix passed all nine stages in 18 fresh VMs.

For Pause, setup completes Create and Start and verifies the nonce-bound init
marker before the injected request. The first eight points retain an unpaused
running record and Prepared Pause journal. Replacement recovery recreates and
starts init, rebinds its PID, repairs the completed setup responses, and sends
the unchanged Pause once. At `guest-after-response-write`, the record and
journal are already paused and Succeeded. Recovery starts the fresh init, waits
for the replacement marker, reapplies Pause, and reports explicit paused-process
recovery so Create, Start, and Pause journals can bind to the replacement PID.
The Host retry then replays without another driver dispatch. Changed and stale
requests fail at both Host and Guest boundaries, force-delete removes the frozen
generation, and both owners restore their resource inventories. Schema
`a3s.oci.oci-vm-operation-reopen-replacement.v9` retains this evidence. The
August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

For Resume, setup first commits Create, Start, and Pause. Replacement recovery
always starts the fresh init, waits for its nonce-bound readiness marker, and
replays the setup Pause. The first eight points retain a paused running record
and Prepared Resume journal, so the unchanged Resume dispatches once after
reopen. At `guest-after-response-write`, the record is already unpaused and the
Resume journal is Succeeded; recovery also replays that committed Resume and
returns recreated-running evidence. Create, Start, Pause, and Resume journal
responses retain their historical state while binding to the replacement PID.
Changed and stale requests fail at both boundaries, force-delete removes the
resumed generation, and both owners restore their inventories. Schema
`a3s.oci.oci-vm-operation-reopen-replacement.v10` retains this evidence. The
August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

For Processes, setup commits Create, Start, and a live terminal Exec. The
replacement owner recreates both processes and repairs their durable PIDs and
completed setup responses before querying inventory. The exact init and Exec
targets, generation, terminal modes, and positive replacement PIDs are
required. Processes is read-only and has no Host response journal, so every
replacement path sends one query to the fresh Guest even after a completely
written first response. Stale generations fail at both boundaries, force
delete removes the live generation, and both owners return to baseline. Schema
`a3s.oci.oci-vm-operation-reopen-replacement.v11` retains this evidence. The
August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

For Update, setup commits Create and Start, waits for the nonce-bound init
marker, and submits one exact complete `LinuxResources` profile. The first
eight paths retain a Prepared journal; replacement recovery rebuilds init and
the Host retry dispatches the unchanged Update once. At
`guest-after-response-write`, the journal is Succeeded but the old VM's cgroup
effect no longer exists. Recovery therefore waits for the fresh marker and
reapplies the committed Update before Host service open completes. The retry
repairs the completed response PID and returns without another API-driven
dispatch. Every path reads two fresh Stats snapshots and requires the 512 MiB
limit, monotonic CPU/memory counters, live process count, and memory/PID event
metrics. Changed resources and stale generations fail at both boundaries,
force delete removes the live generation, and both owners return to baseline.
Schema `a3s.oci.oci-vm-operation-reopen-replacement.v12` retains this evidence.
The August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

For Stats, setup commits Create, Start, and the complete resource Update before
injecting the selected read-only transition. Replacement recovery always
recreates and starts init, waits for the exact readiness marker, reapplies the
committed Update to the fresh cgroup, and repairs the completed Create, Start,
and Update response PIDs. Stats has no Host response journal, so every stage
dispatches one new replacement query, including
`guest-after-response-write`. Every returned snapshot must retain the exact
generation and prove the 512 MiB limit, live CPU and process counters, and
required memory/PID event metrics. When the first response was delivered, the
replacement timestamp and snapshot must be newer and distinct. Stale Host and
Guest generations fail closed, force delete removes the live generation, and
both owners return to baseline. Schema
`a3s.oci.oci-vm-operation-reopen-replacement.v13` retains this evidence. The
August 11, 2026 Apple Silicon matrix passed all nine stages in 18 fresh VMs.

ReadOutput now uses
`a3s.oci.oci-vm-operation-reopen-replacement.v14`. Both owners rebuild the
same non-terminal captured-output Exec identity; the replacement repairs the
Create, Start, and Exec response PIDs and receives one fresh cursor request at
every stage. Delivered first-owner output and replacement output must match the
exact nonce-bound stdout chunk, while stale generations and cleanup remain
hard gates.

WriteStdin now uses
`a3s.oci.oci-vm-operation-reopen-replacement.v15`. Recovery rebuilds the
pipe-backed Exec for every stage. Prepared Host journals dispatch the write
once after reopen. If the first owner already committed the write response,
recovery replays those exact bytes into the fresh Exec before Host open
completes, and the API retry is served without a second driver call. Exact
effect-marker bytes, request identity, changed-payload rejection, stale
generation fencing, PID rebinding, and cleanup all passed on Apple Silicon.

CloseStdin now uses
`a3s.oci.oci-vm-operation-reopen-replacement.v16`. Recovery rebuilds the
pipe-backed Exec for every stage. Prepared Host journals dispatch the close
once after reopen. If the first owner already committed the close response,
recovery closes the replacement Exec input before Host open completes and the
API retry is served without a second driver call. Exact EOF-marker bytes,
request identity, changed-target rejection, stale generation fencing, PID
rebinding, and cleanup passed all nine stages on Apple Silicon.

Resize now uses
`a3s.oci.oci-vm-operation-reopen-replacement.v17`. Recovery rebuilds the
terminal-backed Exec for every stage. Prepared Host journals dispatch one
`120x40` resize after reopen. If the first owner committed its response,
recovery restores the dimensions before Host open completes and the API retry
does not call the driver again. Exact SIGWINCH marker bytes, changed-size
rejection, stale generation fencing, fresh-owner PID rebinding, and cleanup
passed all nine stages on Apple Silicon. File and Filesystem are the two
remaining operation matrices.

## Remaining workload gates

The fixed lifecycle proves the real static A3S Linux guest, transport, and
reviewed executor slice, but it is not yet an arbitrary OCI workload driver.
The current gates do not:

- boot the production A3S immutable Linux system image.

The next macOS increments must add, in order:

1. the production A3S immutable system root;
2. negative tests for isolation weakening and exhaustive recovery injection.

Only after those gates and the shared Linux executor requirements pass may
the HVF driver move from `probe-only` to `experimental`.
