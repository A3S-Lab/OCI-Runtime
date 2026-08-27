# Native Linux Development

## Current capability boundary

Linux feature discovery reports two independent drivers:

- `native-linux` for direct namespace and cgroup execution on the host;
- `libkrun-kvm` for an optional Linux utility VM.

The probes deliberately do not share status. Missing or inaccessible KVM must
not make native Linux unavailable, and a usable KVM device must not imply that
the utility-VM driver can launch a workload.

Both entries in the default feature inventory remain `probe-only`.
`NativeLinuxDriver::open_experimental` is a separate, explicit development
opt-in. It changes only the constructed driver instance to `experimental`,
accepts only `shared-host-kernel` isolation, and reuses `LinuxExecutor`
directly without linking or initializing libkrun. The executor selects direct
rootful mapping or helper-backed rootless mapping from its effective host
identity.

A process that omits a user-namespace request inherits the current user
namespace, so container UID/GID values already identify the same host IDs and
host translation is the identity function. Created and joined user namespaces
still require explicit UID and GID mappings; the executor never invents a
mapping for either boundary.

## Multi-container host owner

The explicit development command below opens one long-lived Native Linux SDK
owner without probing or opening `/dev/kvm`:

```bash
a3s-oci native-linux-host-service \
  --root /run/a3s/oci-native \
  --agent /usr/libexec/a3s-oci-agent
```

`--root` and `--agent` must be absolute normalized paths. The root, durable
state directory, and executor directory are real same-UID `0700` directories.
The service opens `NativeLinuxDriver::open_experimental` and replays the
durable state before it publishes `runtime.sock`; the socket is same-UID
authenticated, mode `0600`, and removed only when its original inode is still
present. Multiple clients and containers share the owner, while the durable
host service keeps every later operation pinned to the driver and generation
selected at create time.

This command accepts ordinary SDK create attachments and deliberately carries
no A3S Box FD 3/4/5 resources. It is also the explicitly opted-in x86_64 and
aarch64 Box Sandbox production route: Box prepares the product bundle and
resources, then reuses this identity-fenced owner across fresh Box processes.
The separate `native-linux-service` command remains a single-container
compatibility and focused-qualification path. Default routing, transparent
live-session reattachment, and cross-platform cutover remain open.

## Native prerequisite probe

The native probe performs read-only inspection of:

- `/proc/self/ns/cgroup`;
- `/proc/self/ns/ipc`;
- `/proc/self/ns/mnt`;
- `/proc/self/ns/net`;
- `/proc/self/ns/pid`;
- `/proc/self/ns/time`;
- `/proc/self/ns/time_for_children`;
- `/proc/self/ns/user`;
- `/proc/self/ns/uts`;
- `/sys/fs/cgroup/cgroup.controllers`.

It also opens a pidfd for the probing process, sends signal `0` through
`pidfd_send_signal`, and closes the descriptor. This proves both required
kernel interfaces without delivering a signal. The stable
`pidfd_signaling=true` evidence field is required for an available native
result.

It also records `/proc/sys/kernel/unprivileged_userns_clone` when that
distribution-specific policy file exists. The policy is required when a
non-root caller opens the executor, but it is not required for rootful host
availability.
On kernels that expose
`/proc/sys/kernel/apparmor_restrict_unprivileged_userns`, the probe reports the
setting as `apparmor_restrict_unprivileged_userns`. This is diagnostic evidence:
an AppArmor or other LSM policy can still reject a requested user-namespace
mount after the read-only baseline probe succeeds.

The native probe never:

- opens `/dev/kvm`;
- links or initializes libkrun;
- creates a namespace;
- writes cgroup state;
- mutates runtime state.

An available result means only that the baseline kernel interfaces and pidfd
process control exist.
`DriverReadiness::ProbeOnly` prevents selection by the default
`HostRuntimeService`.

Intel RDT is a configuration-specific prerequisite, not part of this baseline
probe. A bundle with `linux.intelRdt` requires a resctrl filesystem mounted in
the runtime mount namespace. Create returns a typed error before hooks if no
such mount exists or if the requested CLOS, schemata, monitoring group, or PID
assignment cannot be prepared and read back. Bundles that omit `intelRdt` do
not inspect or mutate resctrl.

## Optional KVM probe

The KVM probe reports three independent facts:

- whether `/dev/kvm` exists;
- whether the runtime principal can open it read/write;
- whether `KVM_GET_API_VERSION` returns the supported API version 12.

The output distinguishes:

- an absent device;
- a permission or other open failure;
- a failed ioctl;
- an unexpected API version;
- a usable KVM API.

Opening `/dev/kvm` for the capability ioctl does not initialize libkrun or
create a VM.

## Isolated Linux libkrun context gate

The separate `a3s-oci-krun-shim` owns the optional native libkrun boundary.
The SDK, feature probe, durable host service, and Native Linux driver neither
link nor load these assets. Run the context gate explicitly with:

```bash
cargo run -p a3s-oci-krun --bin a3s-oci-krun-shim -- context-smoke
```

The build selects exactly one deterministic runtime archive for the target
architecture. The x86_64 and AArch64 archives each contain only
`libkrun.so.1.17.0` and `libkrunfw.so.5`. Their archive sizes and SHA-256
digests, both inner-file identities, and the firmware-exported kernel size,
guest load address, entry address, and digest are recorded in one shared
manifest. Full source and reproduction details live in
[`crates/krun/RUNTIME-PROVENANCE.md`](../crates/krun/RUNTIME-PROVENANCE.md).

At runtime the shim:

1. selects an adjacent packaged runtime directory, falling back to Cargo's
   staged directory only for a repository build;
2. requires a real directory and real regular files, rejecting symbolic
   links, wrong sizes, and digest drift;
3. loads the exact firmware with `RTLD_NOW | RTLD_GLOBAL`, then the exact
   libkrun object with `RTLD_NOW | RTLD_LOCAL`;
4. verifies the kernel exported by `krunfw_get_kernel` and resolves only the
   six context symbols it uses;
5. repeats the asset and exported-kernel checks before allocating a context;
6. creates one context, configures one vCPU, 128 MiB, and a plain AF_VSOCK
   device with the agent port, then releases the context.

A successful report has schema `a3s.oci.krun-context-smoke.v2`, platform
`linux`, status `available`, and all five lifecycle booleans set to `true`.
Tests also copy the shim beside a modified runtime and beside a runtime
directory symlink and require both attempts to fail before `krun_create_ctx`.

This gate deliberately does not open `/dev/kvm`, construct a VMM, enter a VM,
boot the guest agent, or register a workload driver. Its `available` status
describes only the isolated native context gate. The `libkrun-kvm` driver
therefore remains `probe-only` until the immutable system root, authenticated
guest session, complete SDK/recovery matrices, and real-KVM soak pass.

## Authenticated Linux KVM entry gate

The stronger entry gate uses the immutable system-image compatibility set and
never falls back to the Native Linux driver. Run it with the exact target
manifest:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-agent-entry.sh
```

The Host first validates a separate owner-only runtime share and binds a
same-UID Unix socket. It starts the shim as the direct child and leader of a
private process group. The shim pins the Host owner with a pidfd, writes the
one-time token below the exact runtime share, and starts a separate worker for
the process-takeover libkrun call. Immediately before entry, that worker:

1. revalidates the manifest, raw image, libkrun, firmware, exported kernel,
   static Guest Agent, target architecture, and runtime share before KVM-device
   access, then repeats the complete asset check at the final entry boundary;
2. attaches the immutable root disk read-only and exports only the
   descriptor-pinned, UID-owned, mode-`0700` generation share;
3. configures the fixed plain-vsock Agent port, Guest executable, environment,
   and bounded console;
4. opens a real nonsymlink `/dev/kvm` character device read/write, pins its
   device/inode identity, requires API version 12, and repeats those checks at
   the final entry boundary;
5. enters the VM and lets the Host accept only the worker PID reported by
   `SO_PEERCRED` whose direct parent is the exact shim.

Successful negotiation requires protocol version 10, the target architecture,
and all 21 Agent operations. The retained
`a3s.oci.linux-kvm-agent-entry.v1` report wraps the raw
`a3s.oci.agent-vm-smoke.v10` Host result and nested
`a3s.oci.krun-agent-vm-smoke.v7` boot-asset and KVM evidence. The v7 addition
records whether the qualification-only Linux post-probe failure was injected.
Normal entry requires that field to be false. The Windows handle-reclamation
evidence introduced in v6 remains mandatory under the shared v7 schema.

The same script is a strict unavailable-host gate. When the feature probe says
KVM is unavailable, it requires the worker to finish all non-KVM configuration
and then fail with explicit KVM evidence. It also compares endpoint and process
inventories and rejects leftover token or recovery handoffs. When the probe
says KVM is available, it first requires a real authenticated Guest boot and
zero exit, then runs a hidden qualification-only session. The second worker
must open and pin the real KVM device, verify API version 12, set
`kvm_post_probe_failure_injected=true`, and exit with status 2 before VM entry.
The Host must never accept a bridge or negotiate the token, and endpoint,
process, token-handoff, and runtime-share inventories must return exactly to
baseline. That expected failure is retained separately as
`a3s.oci.linux-kvm-post-probe-failure.v1`; unavailable hosts emit an explicit
zero-case result instead of omitting the artifact.

Both entry reports and every matrix below embed
`a3s.oci.linux-kvm-provenance.v1`. The helper rejects a dirty checkout or a
caller-supplied source revision that differs from `HEAD`, then binds the Git
object format, exact commit and tree, Linux platform and target architecture,
CLI and shim SHA-256, runtime-assets manifest and selected runtime bundle,
immutable system-image manifest, Cargo profile, qualification profile,
`libkrun-kvm` driver, and `dedicated-vm` isolation. It also verifies that the
adjacent runtime directory contains exactly the manifest-declared files with
the declared digests before any retained gate runs.

The compatibility-drift gate uses the same Host, shim parent, direct worker,
and cleanup path but stops before `/dev/kvm` is opened:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  bash .github/scripts/linux-kvm-compatibility-drift.sh
```

A qualification-only synchronization point introduces manifest and raw-image
replacement, same-size mutation, symlinks, or Guest Agent digest drift after
the worker has configured the complete compatibility set. Architecture,
runtime-target, Guest Agent version, runtime archive, libkrun, firmware, and
exported-kernel provenance mismatches are rejected during worker load. All 14
cases require exit code 2, no KVM access, bridge, protocol negotiation, or VM
entry, and exact endpoint, shim-process, token-handoff, and runtime-share
inventory restoration. The report schema is
`a3s.oci.linux-kvm-compatibility-drift.v2`. CI runs both entry contracts and
this matrix on x86_64 and AArch64.

The driver also has a KVM-independent isolation preflight on both Linux
architectures. It rejects `SharedHostKernel`, `SharedGuestKernel`, targets
without an exact generation, and Create requests without the atomic
bundle-handoff contract before touching a handoff. For a dedicated-VM request,
the runtime validates the complete caller-owned source before it creates
`shares/<container>/<generation>`. A missing source, linked or mode-open
handoff, changed `config.json`, linked rootfs, or absolute bind source leaves
no exact-generation share and cannot reach the VM factory. This gate exercises
the production handoff path and does not treat an unavailable KVM probe as a
pass for real Guest isolation.

The common HVF/KVM lifecycle also has a non-advertised SharedGuestKernel test
profile. It binds each exact session incarnation to a private share and marker,
serializes concurrent admission, enforces capacity and generation rotation,
and verifies destroy-on-empty, same-trust-domain retention, member-local
failure cleanup, and one-owner shutdown. KVM discovery deliberately continues
to reject that isolation class until cumulative storage/network transport is
implemented and the same behavior passes the real x86_64 and AArch64 restart,
cleanup, and soak gates.

The next gate runs the shared Utility VM lifecycle only when the feature probe
can open `/dev/kvm` and verify API version 12:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  A3S_OCI_LINUX_KVM_LIFECYCLE_REPORT=/absolute/path/to/report.json \
  bash .github/scripts/linux-kvm-lifecycle.sh
```

It creates a separate empty bootstrap root and UID-owned mode-`0700` runtime
share, downloads the architecture-specific pinned Alpine archive, and prepares
two ownership-normalized OCI bundles. Its 17 cases are the complete
20-operation lifecycle, the two-container generation/namespace/rootfs/PID
isolation lifecycle, one versioned ten-case Guest path-isolation profile,
three no-delete interruption boundaries, and all 11 protocol-v10 Host/Guest
transport fault points. The isolation profile covers reserved and external
bundles, absolute and symlinked rootfs entries, absolute, traversing, and
symlinked bind sources, and intermediate magic-link File/Filesystem escapes.
Each case must restore the
Unix endpoint and shim-process inventories, leave `run` unchanged, keep the
bootstrap empty, and remove markers plus token and recovery handoffs. The
aggregate schema is `a3s.oci.linux-kvm-lifecycle-matrix.v2`.

The recovery gate uses a separate qualification-only Host Service. The normal
KVM candidate remains `probe-only` and cannot register with
`HostRuntimeService`; only this entry carries the exact
`linux-kvm-owner-death-restart-only-v1` scope:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  A3S_OCI_LINUX_KVM_RECOVERY_REPORT=/absolute/path/to/recovery.json \
  bash .github/scripts/linux-kvm-recovery.sh
```

On a KVM-capable host it starts one live generation through the Unix SDK
service, verifies the one-shot authenticated endpoint was consumed, and sends
SIGKILL to the exact service process. The pidfd-bound shim and worker must
exit, retain an authenticated SIGKILL recovery record, and restore the
endpoint inventory. A distinct kernel-authenticated replacement service then
must recover exact stopped state, empty process inventory, and replayable
Wait status before stopped-only Delete. Its descriptor inventory, bundle
handoffs, runtime shares, recovery reports, endpoints, and service socket all
return to their baselines. The nested runtime schema is
`a3s.oci.linux-kvm-recovery-smoke.v1`; the retained aggregate is
`a3s.oci.linux-kvm-recovery-matrix.v2`.

The bounded soak has a different qualification owner and the exact
`linux-kvm-bounded-soak-only-v1` scope:

```bash
A3S_OCI_LINUX_KVM_SYSTEM_IMAGE_MANIFEST=/absolute/path/to/system-image.json \
  A3S_OCI_LINUX_KVM_SOAK_REPORT=/absolute/path/to/soak.json \
  A3S_OCI_LINUX_KVM_SOAK_ITERATIONS=25 \
  bash .github/scripts/linux-kvm-soak.sh
```

One durable service reuses the same container ID across fresh, monotonically
increasing generations. Each wave requires replay-safe Create, Kill, Wait, and
Delete; stale-generation rejection; a verified Guest init marker; distinct
shim and worker process incarnations; and restoration of the endpoint,
descriptor, bundle-handoff, runtime-share, and recovery-report inventories.
The configured Guest `cgroupsPath` is retained with every wave and its lifetime
is bounded by the reaped per-generation VM kernel. This is Guest-lifetime
evidence, not a claim that the Host directly observed a Guest cgroup. The
nested schema is `a3s.oci.linux-kvm-soak.v1`; the aggregate schema is
`a3s.oci.linux-kvm-soak-matrix.v2`.

If KVM is unavailable, none of the lifecycle, recovery, or soak scripts
downloads or unpacks the Alpine fixture. Lifecycle and recovery emit zero-case
`unavailable` reports; soak emits `completed_iterations: 0` and
`fixture_downloaded: false`. CI uploads those reports, but they are not
`available` hardware results. The driver remains `probe-only` until fresh
x86_64 and AArch64 KVM hosts retain all three available reports, including the
integrated Guest path-isolation evidence. Other real-entry Guest
negative-isolation profiles remain separate promotion gates.

## Experimental lifecycle gate

The `native-linux-smoke` command opens the native driver beneath isolated
runtime-owned directories. It exercises the durable init and process
lifecycle through `RuntimeClient`; `HostRuntimeService` journals exec,
per-process signal, pause/resume/update, and write-stdin/close-stdin/resize,
caches init and process terminal results, and dispatches the exact generation
through `NativeLinuxDriver` to the shared `LinuxExecutor`. The submitted bundle
is strictly loaded before the lifecycle begins.

The versioned `a3s.oci.native-linux-smoke.v20` report requires all of the
following:

1. the service advertises exactly `features`, `create`, `state`, `start`,
   `kill`, `delete`, `exec`, `wait`, `list`, `pause`, `resume`, `update`, `processes`,
   `stats`, `events`, `read-output`, `write-stdin`, `close-stdin`, `resize`,
   `signal-process`, `wait-process`, `file`, and `filesystem`, plus `prestart`,
   `createRuntime`, `createContainer`, `startContainer`, `poststart`, and
   `poststop` in the OCI feature document's normative order;
2. a dedicated-VM create fails as `Unsupported` before claiming the container
   ID or operation ID;
3. the process-local native create validates the A3S Box exec listener, PTY
   listener, and writable init log, duplicates collision-safe sources above
   every target, and exposes them only as descriptors 3, 4, and 5;
4. create returns the positive host-visible PID of the configured process in
   the exact OCI `created` state while a dedicated namespace PID 1 remains
   behind it;
5. the workload marker is absent before start;
6. retrying create with equivalent resources replays its exact result, while
   retrying without the stable attachment schema fails; source FD numbers and
   inode identities never enter the fingerprint; unfiltered and
   shared-host-kernel list return the exact record while a dedicated-VM filter
   returns none;
7. start releases `startContainer`, confirms the configured process crossed
   `execve`, runs `poststart`, and returns; the workload verifies exact rootful
   UID/GID maps, monotonic and boottime namespace offsets, and an applied
   `RLIMIT_NOFILE` soft/hard value of 64, retained separately as
   `init_rlimits_verified`, exact configured `oom_score_adj`
   value of 100, IPC `kernel.shm_rmid_forced=1`, network
   `net.ipv4.ip_forward=1`, best-effort I/O priority 4, `SCHED_BATCH` with nice
   6, the exact `LINUX32` execution domain as `init_personality_verified`,
   and an exact `MPOL_BIND` node-0 NUMA policy with
   `MPOL_F_STATIC_NODES` as `init_memory_policy_verified`,
   reads capability masks `CapInh=0x400`, `CapPrm=0x401`, `CapEff=0x401`,
   `CapBnd=0x401`, and `CapAmb=0x400` as
   `init_capabilities_verified`, and reads `NoNewPrivs=1` as
   `init_no_new_privileges_verified`,
   verifies FD 3 and FD 4 are sockets, and writes the exact
   `a3s-box-native-control-v1\n` bytes through FD 5 before the marker is
   observed; the host connects to both inherited listeners and reads back the
   exact log;
8. exact-target exec reads back its own `RLIMIT_NOFILE` soft/hard value of 48,
   retained separately as `exec_rlimits_verified`, plus exact configured
   `oom_score_adj` value of 200, best-effort I/O priority
   5, and `SCHED_BATCH` with nice 7; reads `0x400` for all five capability
   masks as `exec_capabilities_verified` and `NoNewPrivs=1` as
   `exec_no_new_privileges_verified`, then reads the exact final CPU set `0`
   as `exec_cpu_affinity_verified` after applying OCI `execCPUAffinity`
   before and after the workload cgroup transition; exec and its retry return
   the same positive authenticated PID, a duplicate process ID is rejected,
   and a 50-millisecond process wait returns `DeadlineExceeded`;
9. per-process `SIGKILL` and its exact retry succeed through the retained
   pidfd, process wait returns signal 9, and repeated process wait is stable;
10. process inventory returns exactly the live init and second exec process;
11. one exact durable update changes memory limit/reservation/swap, CPU
   shares/quota/burst/period/cpuset/idle, and the PID limit; retrying it
   returns the same container record;
12. two normalized stats snapshots remain generation-fenced, expose positive
   CPU and process counters, retain the updated memory limit, and carry the
   expected cgroup-v2 event metrics;
13. an exact-target process accepts piped stdin, returns captured stdout and
   stderr through byte-accurate partial pagination, emits EOF for both streams,
   accepts repeated stdin close, and rejects writes after close or exit;
14. a terminal process starts with a controlling 80x24 PTY, reports the initial
    and resized 120x40 dimensions, accepts interactive input through merged
    output, advances one byte cursor through EOF, and accepts repeated close
    while delivering `VEOF` to a live terminal reader;
15. a binary payload containing NUL and non-UTF-8 bytes survives exact-target
    upload and download; upload replay is byte-for-byte stable, reusing its
    operation ID for a changed destination fails as `FailedPrecondition`
    without creating that file, and mkdir/stat/list/move/recursive-remove each
    preserve exact metadata, mutation replay, and post-cleanup `NotFound`
    evidence;
16. pause and its replay expose a durable frozen state, the progress-producing
    exec remains unchanged for a bounded interval, resume and its replay expose
    a durable thawed state, and that same exec advances again;
17. the second live exec is terminated and reaped automatically when init
    exits, while process ID `init` returns the same result as lifecycle wait;
18. a 50-millisecond wait returns `DeadlineExceeded` while the configured
    process is still running;
19. `SIGKILL` reaches the configured process through its retained pidfd, and
    both internal supervisors preserve the exact signal result while retrying
    kill replays its exact result;
20. wait returns signal 9 with `oom_killed: false`, and a repeated wait returns
    the same terminal result;
21. state reaches `stopped`;
22. stopped-only delete and its exact retry succeed, and both inherited socket
    paths reject new connections afterward;
23. the host-owned event journal contains one ordered creating, created,
    started, paused, resumed, resources-updated, stopped, and deleted event,
    balanced exec create/start/exit events, the init exit, exact generation
    identity, a monotonic cursor, and an empty replay-safe tail poll;
24. a six-line trace proves exact hook order, `creating`, `created`, `running`,
    and `stopped` state, the exact container ID, OCI version, bundle path,
    annotations, and positive init PID for every live phase, with no PID in
    `poststop`;
25. state returns `NotFound` and durable list is empty after delete;
26. the marker, executor root, and complete smoke session are removed.

### Configured-init terminal and device-target gate

The wrapper runs the full v20 lifecycle twice more with
`process.terminal=true` and `consoleSize=120x40`. The workload requires file
descriptors 0, 1, and 2 to be terminals, reads 40 rows by 120 columns through
`stty`, and compares `/dev/console` with fd 0 by filesystem device, inode, and
special-device identity. It also requires `/dev/ptmx` to resolve to
`pts/ptmx` and an explicitly configured FIFO at `/run/a3s/device-fifo` to have
mode 0640 and mapped owner 1:2.

The first bundle starts without `/dev/console`; Delete must remove the console
and FIFO placeholders created by the runtime. The second starts with a regular
console placeholder containing a fixed marker. The PTY is mounted over it for
the lifetime of the container, then the original file and bytes must reappear
unchanged while the runtime-created FIFO disappears. This distinguishes mount
lifetime from file ownership and exercises the same manifest cleanup used by
failed Create, shutdown, and owner-death recovery.

For a bounded rerun of only these two real-kernel profiles:

```sh
A3S_OCI_NATIVE_FOCUS=terminal-init \
  bash .github/scripts/native-linux-smoke.sh
```

### Undeclared-device boundary gate

The device-boundary profile intentionally omits `linux.cgroupsPath`; the
executor assigns a private generation-fenced cgroup and installs the immutable
declared/default inventory filter before the workload starts. The workload has
`CAP_MKNOD` and `CAP_SYS_ADMIN`: it creates and uses the declared `c 1:3`
identity, receives `EPERM` while creating undeclared `c 240:0`, remounts a
`nodev` bind source with `dev`, and still receives `EPERM` while reading that
source's undeclared node. Create, Start, Update, Kill, and Delete must complete
with empty executor, session, and cgroup inventories.

Run only this real-kernel profile with:

```sh
A3S_OCI_NATIVE_FOCUS=device-boundary \
  bash .github/scripts/native-linux-smoke.sh
```

### Cgroup ownership delegation gate

The cgroup-ownership profile creates a new cgroup namespace and supplies the
exact writable OCI cgroup mount. Its mapped-root workload requires the cgroup
directory and every existing kernel-listed delegate file to appear as UID 0
inside the user namespace while their groups remain unmapped and unchanged.
It verifies that at least one delegated file exists, an unlisted cgroup-v2
control keeps its original ownership, and the workload can create and remove
a child cgroup. A second otherwise equivalent profile adds `ro`; it requires
the original ownership and a failed write. Both profiles run the complete
Create/Start/Kill/Wait/Delete lifecycle and require empty executor and session
state afterward.

The cgroup authority root belongs to the host or delegation owner. When its
`cpuset.cpus` or `cpuset.mems` value is empty, the executor requires the
matching `.effective` value to be nonempty but does not write the authority
root. Only Runtime-owned descendants copy those effective values before
controller enablement. This preserves inheritance while preventing container
creation from mutating a host-owned or delegated boundary.

Run only these positive and read-only real-kernel profiles with:

```sh
A3S_OCI_NATIVE_FOCUS=cgroup-ownership \
  bash .github/scripts/native-linux-smoke.sh
```

### Control/workload Unified, HugeTLB, and RDMA gate

The default matrix also runs the opt-in `control-workload-v1` topology with
`linux.resources.unified["memory.high"]=201326592`. Trusted init requires
`memory.high=max` on `a3s-control` and the exact configured value on
`a3s-workload`, proving that unified files remain workload-only. When a usable
block device exists, it also writes a partial `io.max` value and requires the
kernel-normalized line from `a3s-workload`, without requiring the omitted fields
to remain absent. The rootful live Update profile then writes
`memory.high=402653184`; the delegated-rootless profile writes `134217728`.
Both updates use the normal durable, idempotent replay path on x86_64 and
aarch64.

Run this gate without the broader recovery and network matrix with:

```bash
A3S_OCI_NATIVE_FOCUS=control-workload \
  bash .github/scripts/native-linux-smoke.sh
```

The downstream A3S Box R17 Resources profile was qualified against OCI Runtime
`e6b840b73a4e5c3bbfa72c2b5d6fd89104a60f9a` in Box PR
[#180](https://github.com/A3S-Lab/Box/pull/180). It resolves the fixed control
and workload children from the live Sandbox process, requires outer CPU,
memory, and PID headroom plus the exact workload limits, observes CPU
throttling, PID exhaustion, and a workload-only OOM, and then completes a fresh
exec through the surviving control transport. The
[required CI gate](https://github.com/A3S-Lab/Box/actions/runs/30416074539/job/90462773534)
passed all advertised R17 profiles and compared the final process, cgroup,
mount, provider-home, and runtime-state inventory with the clean baseline.

When the host exposes the `hugetlb` controller, a kernel hugepage inventory entry,
and its matching cgroup-v2 control, the wrapper selects the smallest available
canonical page size and adds a zero-byte HugeTLB limit to the workload profile.
The trusted init reads `hugetlb.<size>.max` as `max` on `a3s-control` and exactly
`0` on `a3s-workload`; when reservation accounting exists it makes the same
assertions for `hugetlb.<size>.rsvd.max`. This proves workload-only placement
without requiring preallocated huge pages. Hosts without that controller or a
matching page-size control skip only this positive real-kernel assertion; the
portable unsupported-controller, unavailable-page-size, update, read-back, and
rollback tests still run.

When the host also exposes the `rdma` controller, a usable device under
`/sys/class/infiniband`, and a matching root `rdma.max` entry, the wrapper adds
zero HCA handle and object limits for that device. Trusted init requires the
control child to retain `hca_handle=max hca_object=max` and the workload child
to read back `hca_handle=0 hca_object=0`. Hosts without a matching controller
and device skip only this positive real-kernel assertion; deterministic
planning, partial-update, exact read-back, and reverse-rollback tests still run.

The delegated-rootless counterpart omits `linux.cgroupsPath` and removes the
unrelated personality and memory-policy profiles from its temporary fixture.
It then runs both the core lifecycle with its six-device bootstrap and the live
device-policy replacement, rollback, clear, and restore sequence. This proves
the generated private path through the delegated helper; the default full
matrix retains the explicit path and both unrelated profiles:

```sh
A3S_OCI_NATIVE_FOCUS=rootless-device-boundary \
  bash .github/scripts/native-linux-smoke.sh
```

The accepted focus values are `terminal-init`, `device-boundary`,
`cgroup-ownership`, `control-workload`, and `rootless-device-boundary`; any
other nonempty value is rejected. The default remains the complete Native Linux
matrix.

The qualification wrapper also runs four OCI 1.3 `linux.netDevices` profiles.
For the positive profile it creates a down dummy interface with MTU 1450, a
fixed MAC address, and `192.0.2.10/24`, requests the target template
`a3seth%d`, and starts the same v20 lifecycle. The workload must observe
`a3seth0`, the exact MTU, MAC, and permanent address, and the `UP` flag before
it can emit the normal success marker. Deleting the private namespace must
leave no virtual device in the host namespace.

The three negative profiles prove that an exact `lo` target collision fails
without moving its source, a collision introduced by an earlier `%d` move
rolls every source back with its original name and attributes, and a rootless
request fails before touching a host dummy interface. The exit trap tracks all
test-created interfaces and deletes any source still present after a failed or
interrupted run.

The smoke uses `SIGKILL` to prove exact signal-status propagation through the
namespace PID 1 and outer launcher. The runtime never resolves the numeric PID
again for lifecycle or cleanup signaling.

GitHub Actions runs this real rootful lifecycle on x86_64 and aarch64 Ubuntu.
The checked-in fixture uses the same isolation boundary as A3S Box: container
root maps to host UID 100000 and GID 200000, never to host root. Its workload
reads both installed maps back before emitting the success marker. Each
architecture runs once with `/dev/kvm` absent and once with a directory at that
path, which is present but unusable as a KVM device. The script validates the
corresponding `kvm_device_present` report field and restores any original
device after the test.

The fixture is created beneath a private `/var/tmp` directory whose complete
ancestor chain is searchable by the mapped host root identity. This is required
after entering the child user namespace: its capabilities no longer bypass
mode bits owned by the initial user namespace. A production rootfs must
likewise be reachable by its configured host mappings; an inaccessible
ancestor or an LSM denial fails the create operation.

Run the same gate on a supported Ubuntu host:

```sh
bash .github/scripts/native-linux-smoke.sh
```

The script installs `busybox-static`, `iproute2`, `jq`, `uidmap`, and
`util-linux`, builds
the matching `a3s-oci-agent` and CLI binaries, constructs the checked-in
rootful fixture with a 100000:200000-owned searchable rootfs, `/proc` mount
target, and writable hook trace, injects one hook for every OCI phase, checks
that on-disk ownership and OCI mappings match, binds the two host-visible Unix
listeners and dedicated init log, and executes both KVM-independent cases. It
also constructs the rootless fixture described below. If Ubuntu exposes a
disabled unprivileged-user-namespace or restrictive AppArmor user-namespace
sysctl, the qualification script snapshots it, enables the isolated rootless
test, and restores the original value on exit. The complete qualification
directory and dedicated test account are removed on every exit path.

## Native SDK service gate

The Box-facing native path runs one long-lived `NativeLinuxService` owner per
Sandbox. Its public lifecycle boundary is the normal
`RuntimeClient::connect` Unix transport; Box does not import
`NativeLinuxDriver` or send descriptor-bearing private requests. The owner is
configured with one container ID and duplicates the inherited Box FD 3/4/5
roles before it opens any workload.

The `native-linux-service-smoke` command reuses the complete
`a3s.oci.native-linux-smoke.v20` lifecycle assertions over a real `0600` Unix
socket. In addition to the 26 lifecycle requirements above, success requires:

1. the service root, state root, and executor parent are real, owner-owned
   `0700` directories, while the endpoint is an owner-owned `0600` socket;
2. the endpoint accepts the same-UID SDK client and carries every advertised
   request through protocol negotiation and server-side validation;
3. normal transported create automatically attaches the inherited FD 3/4/5
   roles for the configured container ID;
4. create for any other container ID fails as `PermissionDenied` before
   driver dispatch or descriptor reuse;
5. create/start/exec, piped and terminal I/O, file transfer and filesystem
   mutations, update/stats, pause/resume, processes, kill/wait, events, and
   delete all cross the transport boundary;
6. service shutdown closes the retained Box descriptors, removes its exact
   socket inode, reaps every driver-owned process, and leaves the executor
   parent empty before the isolated session is removed.

The same x86_64 and aarch64 qualification script also launches the production
`native-linux-service` entry point with real inherited listeners and log,
checks every path mode, sends `SIGTERM`, waits for exit status zero, and proves
that the socket and executor slot are gone. Both gates run while `/dev/kvm` is
absent; neither the service bind nor native lifecycle initializes libkrun.

The owner command is intentionally fail-closed:

```text
a3s-oci native-linux-service \
  --root /absolute/private/sandbox/runtime \
  --agent /absolute/path/to/a3s-oci-agent \
  --container-id box-sandbox-42 \
  --a3s-box-control-fds
```

The root and agent paths must be absolute and normalized, and the root parent
must already exist. An existing root is accepted only when it is the exact
canonical owner-owned `0700` directory. A pre-existing socket, permissive
directory, wrong descriptor role, different peer UID, or second container ID
fails instead of weakening the boundary.

## Rootless core lifecycle gate

`native-linux-rootless-smoke` must run with nonzero effective UID/GID and no
supplementary groups. Executor startup verifies that unprivileged user
namespaces are enabled and accepts only fixed, regular, root-owned,
setuid-root, unprivileged-executable, not group/world-writable `newuidmap` and
`newgidmap` helpers. The bundle must map container ID 0 exactly to the
effective host UID/GID with size 1, map no host ID 0, and cover
container ID 1 through delegated subordinate ranges. Additional process GIDs
are rejected because the child installs `setgroups=deny` before `newgidmap`.

Helper-backed rootless execution requires `--delegated-cgroup-root` for the
immutable device boundary whether `linux.cgroupsPath` is explicit or omitted.
That path must already be canonical, be an empty cgroup-v2 directory owned by
the effective UID/GID, and expose and enable the `cpu`, `cpuset`, `memory`, and
`pids` controllers. The runtime revalidates its device/inode identity before
creating a private `a3s-oci-*` manager below it; an omitted OCI path receives a
generation-fenced path inside that manager. The runtime never guesses a
systemd scope or enables controllers outside the supplied delegation.

`linux.netDevices` is deliberately outside the current rootless authority
contract. A bundle that requests it is rejected before an executor slot,
namespace, rootfs, cgroup, or host interface is mutated. The qualification
script supplies a real host dummy interface and compares it before and after
the rejected Create, so this is a retained permission boundary rather than a
schema-only check.

A positive rootless run also uses `--rootless-device-bootstrap` and starts
with non-root real UID/GID plus effective root. Before Tokio is created, the
CLI pins the delegation, starts one parent-bound helper, and permanently drops
the owner to its real identity. The helper supplies descriptors for exactly
`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, and
`/dev/tty`. This is the OCI default-device mount path and does not require a
`linux.resources.devices` policy. A launch that needs those defaults but does
not provide the helper fails explicitly before rootfs mutation.

The CI fixture creates a dedicated UID/GID 20000 account with UID range
300000:65536 and GID range 400000:65536. A host file owned by 300000:400000
must appear as 1:1 inside the workload. The versioned
`a3s.oci.native-linux-rootless-smoke.v4` report then requires:

1. exact create and replay behind the OCI `created` barrier;
2. exact `/proc/<pid>/uid_map` and `gid_map` read-back plus
   `/proc/<pid>/setgroups == deny` before start;
3. a started workload that observes namespace root, the translated 1:1
   fixture ownership, and the exact type, major/minor, mode, and basic I/O
   behavior of all six default devices;
4. exact exec/replay, pidfd signal/replay, and stable signal-9 process wait;
5. exact init kill/replay and stable signal-9 lifecycle wait;
6. one ordered creating/created/started, exec create/start/exit, stopped, init
   exit, and deleted event sequence with an empty tail cursor;
7. delegated resource update/stats, exact pause/resume replay, and workload
   progress that stops while frozen and continues after resume;
8. stopped-only delete replay, post-delete `NotFound`, empty list, and removal
   of every process, marker, executor root, and durable session directory.

The hidden `native-linux-rootless-device-policy-smoke` extends the same helper
path with the exact A3S Box six-node device-access policy. It accepts only
framed, versioned install, replace, remove, mount-preparation, and explicit
shutdown messages for normalized paths below the pinned delegation. It does
not accept filesystem roots, raw BPF, arbitrary device nodes, or
caller-supplied program descriptors.

The v4 device-policy report verifies all six retained host nodes inside the
container, read/write behavior for the common devices, a live read-only
replacement, rejection with rollback for an out-of-profile update, resource
rule clear and restore while the immutable inventory filter stays attached,
the exact additional exec/update event sequence, helper shutdown, and an empty
delegated subtree. Unexpected owner or channel loss closes the helper without
detaching active filters, so policy remains fail-closed until the protected
cgroups are recovered and removed.

GitHub Actions prepares a dedicated cgroup-v2 subtree and runs these gates as
the dedicated user on both x86_64 and aarch64. The jobs retain the rootless
device-policy report separately and also run the owner-death recovery gate
described below. Runtime commit `bed43d2` passed both real-host lanes in CI run
`31714178349`. The retained v4 reports record `available`, exact UID/GID 20000,
verified helper, nodes, live policy updates, durable events, delete replay, and
complete cgroup, runtime, session, and marker cleanup. This qualifies the exact
six-device profile; broader unadvertised controller and security profiles
remain promotion gates.

## Multi-container generation gate

`native-linux-multi-container-smoke` opens one durable host service and one
shared `LinuxExecutor` for two distinct bundles. Both containers must return
positive, different PIDs in `created` before either workload marker exists.
Starting A must leave B's complete created record and marker unchanged;
killing, waiting for, and deleting A must do the same. A bounded wait on the
running A must return `DeadlineExceeded` without preventing a concurrent state
query for B.

After deleting A generation 1, the diagnostic removes only A's marker and
recreates the same container ID. The durable host must allocate generation 2,
reject an exact generation-1 state request, and reject reuse of A's create
operation ID for B without changing B. Recreated A is force-deleted while B
remains created, then B independently completes start, kill, stopped-only
delete, and post-delete `NotFound`. Both killed containers must return and
replay the exact signal-9 terminal result.

Run it with a second bundle containing its own rootfs:

```sh
jq '.linux.cgroupsPath = "/a3s-oci-smoke-b"' \
  "$bundle_b/config.json" >"$bundle_b/config.json.tmp"
mv "$bundle_b/config.json.tmp" "$bundle_b/config.json"

sudo target/debug/a3s-oci native-linux-multi-container-smoke \
  --agent "$PWD/target/debug/a3s-oci-agent" \
  --bundle-a "$bundle_a" \
  --bundle-b "$bundle_b" \
  --work-parent "$work_parent"
```

The checked-in qualification script can isolate this gate from the broader
rootless, network-device, recovery, and soak matrix with
`A3S_OCI_NATIVE_FOCUS=multi-container bash .github/scripts/native-linux-smoke.sh`.

The two simultaneously live bundles must use distinct cgroup v2 paths. Bundle
A uses relative `a3s-oci-smoke-a`; bundle B uses an absolute path so the gate
can compare its host membership directly with the requested mount-relative
value.

The `a3s.oci.native-linux-multi-container-smoke.v20` success additionally
requires exact create/start/kill/delete replay, stable repeated wait results,
independent wait/state progress, exact absolute-path membership, same-location
relative-path recreation, both cgroup removals, both marker removals, executor
shutdown, and complete durable-session removal. It then keeps a prepared donor behind its
create barrier and requires:

1. a namespace descriptor whose type disagrees with its OCI entry to fail
   before container state;
2. one workload to join the donor UTS, IPC, network, cgroup, PID, user, and
   time namespaces while retaining a private mount namespace, with all six
   default devices bound at their exact type, number, mode, and namespace-root
   ownership;
3. a second workload to join the donor mount namespace and execute through the
   rootfs descriptor retained before `setns`; its qualification-owned default
   devices are staged from the executor's fixed inventory, verified without
   injecting mounts into the donor namespace, and removed after joiner delete;
4. PID/time joins to cross `exec` and remain running for a bounded observation
   window;
5. both joiners to complete without changing the donor's created state;
6. all donor, joiner, and negative-case state to be removed.

The report compares network namespace device/inode identities rather than
inferring behavior from accepted configuration. It requires the private donor
to differ from `/proc/self/ns/net`, the joined workload to exactly match the
donor, and a profile with the network entry omitted to exactly match the host.
The private donor must also complete a real TCP connection over its activated
loopback interface. All three profiles must be unobservable after deletion.

The final enforcement workload must run as PID 2+ beneath a dedicated
namespace PID 1, prove the launcher-to-PID-1-to-workload identity chain, leave
a long-lived grandchild that is adopted by PID 1, terminate that child, and
observe its `/proc/<pid>` entry disappear while the workload remains alive.
This evidence fails if PID 1 does not continuously reap adopted zombies.

The same report then runs an independent rootfs enforcement workload and
requires:

1. every missing directory and file mount destination to exist before start
   while the evidence file remains absent;
2. start to release the prepared workload;
3. a fresh tmpfs to cover the image's `/dev`, followed by `/dev/fd`,
   `/dev/stdin`, `/dev/stdout`, and `/dev/stderr` resolving to the exact
   `/proc/self/fd`, `/proc/self/fd/0`, `/proc/self/fd/1`, and
   `/proc/self/fd/2` targets after mount processing;
4. the root mount to belong to a new shared peer group;
5. `/proc/sys` to be a distinct read-only mount, `/proc/meminfo` to be replaced
   by a private empty read-only file, and `/proc/irq` by an empty read-only
   directory;
6. recursive read-only, nosuid, nodev, noexec, noatime, nodiratime, and
   nosymfollow attributes to hold on both an rbind target and its nested
   submount while the source mounts remain writable and executable;
7. detached `idmap` and `ridmap` filesystem mounts to expose the exact
   requested UID/GID ownership;
8. the original nested bind source to remain owned by `0:0`, non-recursive
   `idmap` to map only the rbind top level to `1000:1000`, and recursive
   `ridmap` to map both the top level and real nested submount to `2000:2000`;
9. a file on an initial-user-namespace tmpfs to remain readable with its exact
   mode through a kernel-enforced read-only, nosuid, nodev, and noexec bind in
   the container user namespace, while rejecting a write;
10. the rootfs to be read-only and reject a write;
11. exact ordered evidence, a normal zero exit, deleted state, and removal of
   all host-side fixture paths.

The planner also runs an exhaustive contract test over the pinned OCI 1.3
mount-option table. All required and recommended names must be consumed as
control data, `tmpcopyup` must fail with `Unsupported`, unknown names must
remain filesystem-specific data, `rnorelatime` must select recursive strict
atime, and explicit bind remounts must not schedule a second remount. The
real-host workload above retains kernel evidence for the security-sensitive
bind, propagation, recursive-attribute, and ID-mapped paths; it does not claim
that every filesystem accepts every generic flag.

The same real-driver invocation also retains two product-facing configuration
matrices:

- A storage writer and reader remain live together. The writer publishes exact
  data through a read-write bind and creates a private tmpfs marker. The reader
  sees the shared data through a read-only bind, cannot modify it, and cannot
  see the writer's same-path tmpfs marker. After writer deletion, a fresh
  reader still observes the exact bind data. All mount targets and host source
  artifacts must be removed.
- Init runs cover inline shell, an executable rootfs script with an exact
  environment variable, direct BusyBox argv without a shell, and a normal
  nonzero exit of 42. Negative OCI Hook runs independently require prestart,
  createRuntime, and createContainer failures to roll create back before any
  state is visible; startContainer and poststart failures to stop the process
  and permit exact force cleanup; bounded prestart timeout to start a
  signal-resistant background descendant and prove that the complete private
  process group is terminated before it can emit delayed escape evidence; and
  warning-only poststop failure. The service list and every exact target must
  be empty afterward.

Before every Hook `exec`, the shared Linux executor applies
`close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)` in the forked child. Standard
input, output, and error remain available, while runtime control, namespace,
root, cgroup, pidfd, and journal descriptors cannot reach Hook code even if a
future caller accidentally omits `FD_CLOEXEC`. A kernel or seccomp profile that
cannot establish this boundary fails the Hook before `exec`. The portable
subprocess regression deliberately clears `FD_CLOEXEC` on a live descriptor
and requires it to be absent from the Hook's `/proc/self/fd` inventory.

GitHub Actions runs the gate on x86_64 and aarch64 both without `/dev/kvm` and
with a present but unusable placeholder at that path.

## Complex-container soak gate

`native-linux-soak` accepts one or more repeated `--bundle` arguments and
selects exactly `--concurrent-containers` distinct bundle/rootfs/cgroup slots.
It rejects fewer than two live slots, duplicate paths, missing cgroup paths,
unbounded iteration counts, and operation timeouts outside the recorded
configuration bounds before opening the native driver.

One iteration has these ordered phases:

1. release all create tasks together and retain every OCI `created` barrier;
2. require monotonic per-ID generations, reject prior exact targets after ID
   reuse, then release all starts together;
3. require the exact live list, unique positive PIDs, exact running state, a
   live init process, valid cgroup statistics, a zero-exit captured exec, and
   exact stdout for every slot;
4. pause every slot, drop the last handle to the single-writer durable store,
   reopen that store around the still-live driver, and recover the exact
   paused live set;
5. resume, SIGKILL, wait for the exact signal-9 result, stopped-only delete,
   require exact-target `NotFound`, and require an empty service list;
6. remove every marker and require an empty executor root, the original direct
   child-process count, and the first clean-wave open-descriptor count.

The final `a3s.oci.native-linux-soak.v1` report succeeds only after all
configured waves complete and driver shutdown removes the executor root and
complete durable session. `NativeLinuxSoakOperationCounts` makes partial
coverage visible rather than reducing the run to one success boolean.

The accepted bounds are 1–10,000 iterations, 2–32 concurrent containers, and
100–300,000 ms per SDK operation. `.github/scripts/native-linux-smoke.sh`
constructs four independent BusyBox bundles and defaults to 25 waves on both
x86_64 and aarch64, retaining 100 complete container lifecycles. Set
`A3S_OCI_NATIVE_SOAK_ITERATIONS` to another bounded value when an operator
needs a shorter diagnostic or a longer qualification; the script derives all
lifecycle, stale-generation, durable-reopen, and SDK-operation assertions from
that value. CI also sets `A3S_OCI_NATIVE_SOAK_REPORT` and uploads the resulting
JSON report for each architecture. This gate covers native lifecycle churn and
leak detection. Per-wave executor emptiness excludes only the protected
`owner.json` identity record that must remain until driver shutdown; every
generation slot must disappear after each wave and the complete executor root
must disappear at shutdown. Hook failure/security-negative soak and runtime-process
reattachment remain separate promotion work.

## Abrupt owner-death recovery gate

The Native Linux executor does not leave an uncontrolled workload behind when
its host-service process is killed. Before the top-level container launcher can
fork a namespace child, it installs `PR_SET_PDEATHSIG(SIGKILL)` and rechecks its
exact parent. Namespace init, payload, exec, and filesystem helpers apply the
same parent-bound rule at their own fork boundaries. An uncatchable owner exit
therefore terminates the authenticated process tree instead of orphaning a live
generation that a replacement driver cannot safely identify.

Every executor root contains a versioned owner record, and every successfully
created generation contains a versioned recovery record. Recovery schema v3
binds the immutable configuration digest to the exact owner, launcher, and init
PID start times plus only the cgroup directories created for that generation
and the exact resctrl paths owned for cleanup. It reads v2 and v1 records
without inventing resctrl ownership.
For v3 records, monitoring cleanup is limited to
`<clos>/mon_groups/<container-id>`, and a removable CLOS must be the direct
`<resctrl>/<container-id>` child.
Recovery rejects missing, duplicate, oversized, symlinked, permissive,
digest-drifted, generation-drifted, PID-drifted, or live-owner evidence. Numeric
PID equality alone is never accepted.

`.github/scripts/native-linux-smoke.sh` starts the hidden
`native-linux-recovery-owner` command with a real long-running bundle, waits for
`a3s.oci.native-linux-recovery-owner-ready.v2`, and sends `SIGKILL` to that exact
owner. A distinct `native-linux-recovery-resume` process then opens the same
durable state. Its `a3s.oci.native-linux-recovery-smoke.v2` report requires:

1. the replacement host service opens only after the exact old workload has
   disappeared;
2. durable state is reconciled to stopped with no PID and empty process
   inventory;
3. repeated kill is idempotent;
4. wait fails explicitly because no authenticated reaper survived to retain an
   exact exit result, rather than inventing signal 9;
5. stopped-only delete removes the durable record, exact executor slot,
   runtime-created cgroups, and recorded runtime-owned resctrl paths;
6. replacement-driver shutdown leaves the executor parent empty;
7. the report binds both owner processes to their effective UID/GID and records
   whether an explicit cgroup-v2 delegation was requested and verified;
8. a delegated run removes every runtime-created `a3s-oci-*` cgroup below the
   exact user-owned authority root while preserving its host-owned control
   child.

Both x86_64 and aarch64 Linux CI run the gate twice. The rootful report is
retained via `A3S_OCI_NATIVE_RECOVERY_REPORT`; the non-root UID/GID 20000 run
starts a bounded default-device helper before the original owner and recreates
that authority before the distinct replacement process reopens the same
explicit delegation. Its result is retained via
`A3S_OCI_NATIVE_ROOTLESS_RECOVERY_REPORT`. These gates prove safe termination,
helper replacement, and exact cleanup. They deliberately do not claim live
process-I/O session reattachment; that requires a persistent authenticated
supervisor and remains a promotion gate.

Runtime commit `49cea11` passed both real-host lanes in CI run `31674526443`.
The retained x86_64 and aarch64 rootless reports both record `available`, exact
UID/GID 20000 replacement ownership, verified explicit delegation, authenticated
workload termination, stopped-only deletion, and complete removal of every
runtime-created cgroup directory.

## Fault-injected shutdown cleanup

`native-linux-fault-cleanup` accepts exactly `after-create`, `after-start`, or
`after-kill`. It crosses the requested successful lifecycle boundary, records
the typed interruption, and closes the service without calling OCI delete:

```sh
for fault in after-create after-start after-kill; do
  sudo target/debug/a3s-oci native-linux-fault-cleanup \
    --agent "$PWD/target/debug/a3s-oci-agent" \
    --bundle "$bundle" \
    --work-parent "$work_parent" \
    --fault-after "$fault"
done
```

The versioned `a3s.oci.native-linux-fault-cleanup.v6` report requires:

1. the exact 21-operation service inventory, requested prefix, and a positive
   runtime-visible configured-process PID;
2. marker absence behind create and exact marker contents after start;
3. `normal_delete_attempted: false`;
4. successful executor shutdown and disappearance of the configured-process
   PID;
5. removal of the marker, executor runtime root, durable state, and complete
   diagnostic session root.

The x86_64 and aarch64 CI jobs run all three phases while `/dev/kvm` is absent.
The shell also independently requires an empty work parent and no marker after
every command.

## Remaining promotion gates

This evidence proves rootful and core rootless bootstrap profiles, not general
OCI support. The default driver must remain `probe-only` until at least the
following pass:

- real-host qualification before any broader rootless device or controller
  profile is advertised;
- broader namespace-join security negatives, donor teardown races, and
  restart recovery beyond the retained wrong-type pre-state rejection;
- mount security-negative and kernel-compatibility profiles, remaining
  credential controls, broader cgroup v2 policies,
  optional multi-architecture/notification seccomp profiles, and wider sysctl
  kernel-compatibility and security-negative profiles;
- live real-driver reattachment after runtime-process restart, plus generic SDK
  inherited process-I/O modes beyond the fixed A3S Box init-control profile;
- Hook crash-recovery, security-negative, and adversarial soak beyond the
  retained six-phase failure/timeout and descriptor-inheritance matrices,
  durable recovery for the remaining mutating operations, descriptor-relative
  path handling,
  transport-level fault injection, and adversarial cleanup beyond the bounded
  native lifecycle churn gate;
- the complete A3S Box Rust, Python, and TypeScript Sandbox SDK suites on
  x86_64 and aarch64 without KVM.

Only a caller that deliberately constructs `open_experimental` can use the
current lifecycle slice.
