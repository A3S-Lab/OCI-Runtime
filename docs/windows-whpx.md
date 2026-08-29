# Windows WHPX Development

## Current scope

The Windows foundation establishes an honest evidence boundary before OCI
lifecycle code is allowed to launch workloads.

The runtime:

1. loads `WinHvPlatform.dll` only from the Windows system directory search
   scope;
2. resolves `WHvGetCapability`, `WHvCreatePartition`, and
   `WHvDeletePartition`;
3. queries `WHvCapabilityCodeHypervisorPresent`;
4. optionally creates and deletes a WHPX partition object as a smoke test;
5. links the `a3s-libkrun-sys 3.1.0` FFI ABI only into an isolated shim and
   stages a runtime-owned, checksum-verified native bundle with firmware
   provenance from `A3S-Lab/Box@93fc281` and the segmented stream, writable
   virtio-fs, virtio queue, and owned PIT worker fixes from
   `A3S-Lab/libkrun@de07dd8`; its NUMA-capable Linux 6.12.91 firmware is built
   from `libkrunfw` v5.5.0 and the strict wrapper from
   `A3S-Lab/libkrun@10dca31`, merged as `414b2d3`;
6. creates, configures for one vCPU and 128 MiB, replaces implicit TSI with a
   zero-feature plain-vsock device, maps guest port 4093 to a validated bare
   Windows pipe name, and releases one real libkrun context without entering a
   VM;
7. creates the host side of that mapping as a first-instance-only local named
   pipe, limits its protected DACL to the runtime principal and LocalSystem,
   verifies the live handle's owner and access entries, requires the connected
   client PID to equal the previously spawned shim PID, and negotiates the
   authenticated agent protocol with a simulated local guest;
8. enters a one-vCPU, 512 MiB utility VM, executes `/bin/sh` from a supplied
   Linux rootfs, and verifies a guest-written marker through virtiofs;
9. boots `/usr/bin/a3s-oci-agent`, carries its host-CID port 4093 connection
   through libkrun to the protected pipe, authenticates the exact shim PID and
   one-time token, negotiates protocol version 10, advertises 20 workload
   operations plus the maintenance acknowledgement, and waits for zero
   guest/shim exit;
10. runs a fixed OCI bundle through distinct create, start, init signal/wait,
     exact-target exec, process signal/wait, live resource update and stats,
     pause/resume, process inventory, captured output, piped stdin, controlling
     PTYs, terminal resize, exact guest `MPOL_BIND` memory-policy readback, and
     delete calls, verifies replay and cleanup, and keeps the built-in driver
     disabled;
11. emits stable JSON evidence through `a3s-oci features`,
   `a3s-oci whpx-smoke`, `a3s-oci-krun-shim context-smoke`, and
   `a3s-oci-krun-shim vm-smoke`, plus nested host/shim evidence through
   `a3s-oci agent-vm-smoke` and `a3s-oci oci-vm-smoke`;
12. stages the one-time guest token in a create-new, fixed-size bootstrap file
    instead of exposing it in the Windows guest command line or environment,
    rejects alternate paths and links, and removes the file on every exit;
13. binds each shim to the exact host owner process and terminates the VM if
    that owner disappears, including during startup and a stuck shutdown;
14. exposes a repeatable hardware soak covering serial, parallel, same-VM
    multi-container, network, storage, init, typed-negative, lifecycle-fault,
    and owner-death profiles with machine-readable resource and inventory
    evidence;
15. gives each candidate-driver VM only its exact protected
    `shares/<container>/<generation>` directory through a second virtio-fs
    device, mounts the fixed `a3s-oci-runtime` tag before guest token access,
    and leaves the system root disjoint from writable bundle and handoff data;
16. exposes a versioned, qualification-only direct `RuntimeDriver` gate that
    verifies create/start/kill/wait replay, authenticated shutdown-report
    publication, stopped-only delete, and complete nominal cleanup while
    preserving `probe-only` readiness;
17. exposes a separate multi-process gate that force-terminates the exact
    host-service owner, injects the before- and after-`Recover` boundaries,
    reopens durable state, replays the authenticated signal-9 exit result, and
    proves stopped-only delete plus complete host/share cleanup. Its launch
    override is crate-private and scoped only to this gate, so normal discovery
    remains `probe-only`;
18. builds a byte-reproducible Alpine 3.22.5 x86_64 ext4 image containing the
    protocol-v10 agent, binds Linux 6.12.91 and every Box/libkrun/firmware
    revision and digest in `a3s.oci.windows-system-image.v1`, pins all boot
    inputs with read-only Windows handles, and switches from the empty
    bootstrap share to that read-only block root before starting the agent.

Product bundle preparation no longer needs to guess the runtime generation.
An explicitly annotated, digest-bound `dev.a3s.bundle-handoff` attachment lets
the product stage one portable bundle below the protected create-operation
path. Once durable state allocates the exact generation, the WHPX driver moves
that directory atomically into its exact runtime share. Retries require the
same source or matching destination evidence, while cleanup removes only a
marker-proven runtime-owned bundle. Requests without the extension retain the
strict fixed-bundle containment behavior used by qualification gates.

For both bundle-handoff and pre-positioned qualification bundles, the driver
creates and protects the exact share's `run` directory inside the serialized
Create boundary immediately before the first VM launch. Callers own neither
that runtime-state directory nor its ordering. If a shim exits or is terminated
before the authenticated Agent session passes its contract checks, the Host
removes only the console and recovery handoff paths that were absent before
that launch. Once the session is established, cleanup is disarmed so the
console and owner-death recovery handoff remain available as exact evidence.

The capability query follows the
[Windows Hypervisor Platform API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform).
The smoke operation uses
[`WHvCreatePartition`](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition)
and always attempts the matching delete operation.

## What the smoke proves

A successful WHPX smoke proves that:

- the WHPX API DLL and required symbols are present;
- the Windows hypervisor reports itself present;
- the process can create and release a WHPX partition object.

A successful libkrun context smoke additionally proves that:

- the exact packaged native runtime pair can be loaded;
- `krun_create_ctx` succeeds;
- `krun_set_vm_config` accepts the certified single-vCPU configuration;
- `krun_disable_implicit_vsock`, `krun_add_vsock(..., 0)`, and
  `krun_add_vsock_port_windows` accept the fixed agent mapping;
- `krun_free_ctx` releases the context.

The real Windows host-pipe test additionally proves that:

- the runtime and shim consume one validated endpoint type and fixed port;
- the runtime obtains an unguessable endpoint nonce and a nonzero 256-bit
  session token from the OS random source;
- the pipe rejects remote clients and competing first-instance ownership;
- the live pipe owner is the runtime principal;
- its protected DACL contains only full-access entries for that principal and
  LocalSystem, with no inherited or unexpected entries;
- an unexpected connected process is rejected before the session token is
  written;
- protocol version negotiation and token authentication succeed over the
  protected pipe with the exact core operation advertisement.

A successful libkrun VM smoke additionally proves that:

- the packaged kernel reaches Linux userspace through WHPX;
- `/bin/sh` executes from the supplied rootfs;
- Windows virtiofs preserves Linux `READLINK` syntax for standard absolute
  OCI rootfs links;
- the guest can write through the shared root and the host observes the exact
  marker contents;
- the guest returns exit code zero and the host removes the marker;
- fatal WHPX exits are not accepted as successful workload completion.

A successful end-to-end agent VM smoke additionally proves that:

- the manifest-bound ext4 image supplies the static musl guest agent and fixed
  Linux userspace;
- the image is attached read-only and remains separate from the writable
  runtime share;
- the manifest, raw image, `krun.dll`, and `libkrunfw.dll` retain their exact
  sizes, SHA-256 digests, file identities, and loaded-module paths through VM
  entry;
- guest AF_VSOCK reaches the protected Windows named pipe through libkrun;
- only the exact spawned shim PID is accepted before the token is sent;
- the real guest authenticates the one-time token and negotiates protocol
  version 10;
- the agent version and `x86_64` guest architecture are reported;
- the guest advertises exactly create, state, start, kill, delete, wait, exec,
  signal-process, wait-process, pause, resume, processes, update, stats,
  read-output, write-stdin, close-stdin, resize, file, and filesystem;
- the shim reports every VM configuration stage and a zero guest exit;
- the host rejects an existing console destination rather than overwriting
  it.

A successful fixed OCI VM smoke additionally proves that:

- the accepted bundle is a strict descendant of the supplied writable runtime
  share and is addressed below `/run/a3s-oci-runtime` in the guest;
- create establishes a new UTS namespace, applies the configured hostname and
  domainname, and reports ready only afterward;
- when configured, create establishes a new mount namespace, makes `/`
  recursively private, self-binds the rootfs, completes `pivot_root`, and
  reports ready only afterward;
- create applies existing-target mount entries in listed order, including
  relative bundle bind sources, common VFS flags, propagation modes, and
  filesystem-specific data;
- create atomically enters requested IPC, network, cgroup, and PID namespace
  setup before reporting ready;
- create returns `created` and the authenticated host-visible configured
  process PID without running it; a dedicated supervisor is PID 1 and the
  configured process is PID 2+ in a requested new PID namespace;
- state and an exact create retry match the original result;
- start releases a randomly named abstract Unix socket only after the parent
  verifies the launcher → PID 1 → configured-process identity chain;
- the wrapper applies the accepted rootfs, credentials, umask, and
  `no_new_privileges`, then calls `execve`;
- the host observes `running` and the exact workload marker;
- a bounded wait returns `DeadlineExceeded` while the workload is running;
- exact-target exec and its retry return the same authenticated process, a
  duplicate process ID is rejected, bounded process wait times out while the
  process runs, pidfd signal and its retry succeed, and repeated process wait
  returns the same terminal signal;
- process inventory returns exactly the live init and exec; replayed pause
  freezes their shared cgroup and stops an observed progress counter, while
  replayed resume thaws it and the counter advances again;
- an exact resource update and its retry apply memory, CPU, cpuset, and PID
  controls, while repeated stats return normalized generation-fenced cgroup
  counters;
- an exact-target process accepts piped stdin, returns captured stdout/stderr
  through bounded byte-cursor pagination with EOF, accepts repeated close, and
  rejects writes after close or exit;
- a terminal process proves controlling-PTY allocation, exact initial and
  resized dimensions, interactive input, merged output, one ordered cursor,
  EOF, and idempotent `VEOF` close;
- another live exec is terminated and reaped automatically when init exits;
- kill delivers `SIGTERM`, its exact retry replays the original result, wait
  returns and replays exit code zero, and state then observes `stopped`;
- stopped-only delete and its exact retry succeed;
- state returns NotFound after delete;
- the marker is removed and VM shutdown leaves no new agent runtime directory
  or A3S process.

A successful direct WHPX `RuntimeDriver` smoke additionally proves that:

- the formal driver accepts only a bundle strictly below the exact protected
  `shares/<container>/<generation>` directory;
- the candidate remains non-registerable and `probe-only` throughout the run;
- create, state, create replay, start, start replay, bounded running wait,
  kill, kill replay, exact wait, repeated wait, stopped state, and
  stopped-only delete all cross the driver boundary;
- the guest durably publishes its authenticated shutdown report through the
  writable virtio-fs share and the shim verifies the v2 share contract;
- delete removes the driver attachment, VM session, transient token/report
  directories, normalized recovery artifacts, workload marker, and host
  processes.

A successful WHPX owner-death recovery smoke additionally proves that:

- the parent starts with no A3S OCI process and force-terminates only the exact
  owner PID after one exact-generation workload is running and its marker is
  visible;
- the owner-bound shim survives long enough to stop the VM, collect the guest's
  authenticated shutdown report, and persist the exact signal-9 init result;
- a `Recover` before-call fault retains the protected pending/report handoff,
  and an after-call fault retains the normalized report for the next service;
- a newly opened `HostRuntimeService` observes stopped state and replays the
  exact wait result, while the recovered driver tombstone replays kill without
  claiming that a new service-level signal was delivered to a stopped process;
- stopped-only delete removes durable state, the driver attachment, VM session,
  session/report handoff directories, normalized recovery artifacts, workload
  marker, and every owned host process;
- the ordinary candidate remains `probe-only`, and only the crate-private
  qualification constructor reports its exact scoped override.

## A3S Box qualification owner

`a3s-oci box-whpx-qualification-service` exposes the same durable SDK service
over a protected local Windows named pipe for the explicit A3S Box product
lifecycle gate. It does not register or promote the public WHPX candidate. The
service opens a separate crate-private override whose capability evidence is
exactly `qualification_override=box-product-lifecycle-only`; the owner-death
gate retains its different `host-service-owner-death-only` scope.

```powershell
a3s-oci box-whpx-qualification-service `
  --shim C:\a3s\bin\a3s-oci-krun-shim.exe `
  --runtime-root C:\a3s\oci-runtime `
  --vm-rootfs C:\a3s\oci-runtime\bootstrap `
  --system-image-manifest C:\a3s\system-image\system-image.json `
  --state-root C:\a3s\oci-runtime\state `
  --pipe '\\.\pipe\a3s-oci-box-qualification' `
  --ready-file C:\a3s\oci-runtime\box-service-ready.json
```

The optional readiness file is created atomically only after the driver,
durable state, protected pipe ACL, and first pipe instance are ready. It uses
schema `a3s.oci.box-whpx-service-ready.v2`, records the owner PID, exact
endpoint and roots, and selected system-image manifest, and is removed on
graceful shutdown. A stale file after owner death is never connection
evidence; clients must still complete the SDK handshake and feature preflight.

This owner accepts the operation-scoped portable-bundle handoff contract used
by Box. The source must be exactly
`bundle-handoffs/<container>/<create-operation>/bundle` below the runtime root,
with a normalized relative `root.path` and no absolute bind source. The driver
atomically moves a valid source into its allocated generation before launch.

Box converts its host-side image manifest to the SDK-owned portable contract
and adds
`dev.a3s.oci.rootfs-metadata=a3s.oci.rootfs-metadata.v1`. Before any OCI mount
is installed, the guest validates and consumes the fixed
`.a3s-oci-rootfs-metadata.v1.json` manifest from the relative rootfs, then
restores Linux ownership and mode data that cannot be represented directly by
the Windows backing filesystem. Replay rejects an absolute root, a user or
missing mount namespace, a wrong annotation, manifests above 16 MiB or 250,000
entries, duplicate/reserved/escaping paths, symlink parents, type or
symlink-target drift, and any failed `lchown`, `chmod`, deletion, or directory
sync. All entries are validated before the first metadata mutation.

## Hardware soak gate

Run the complete gate from an x86-64 Windows host with WHPX enabled:

Every successful CI run retains `windows-whpx-qualification` for 14 days. Its
v2 manifest binds the exact source and workflow commits, and lists every file
size and SHA-256 digest. `bin/` contains the CLI, shim, `krun.dll`, and
`libkrunfw.dll`; the disjoint `system-image/` directory contains the raw ext4
image, compressed release copy, and `a3s.oci.windows-system-image.v1`
manifest. CI also publishes the same image separately as
`windows-system-image`. `guest-agents-musl` remains available for development,
but these qualification scripts boot the agent embedded in the immutable
image and do not copy a loose agent into a guest root.

```powershell
gh run download <run-id> --repo A3S-Lab/OCI-Runtime `
  --name windows-whpx-qualification --dir C:\a3s\oci-artifacts\windows
```

For a build-free qualification, copy the four files from `bin/` into
`target\debug`, keep `system-image/` separate, and pass its
`system-image.json` path with `-SystemImageManifest`. Then pass `-SkipBuild` to
the focused scripts. The scripts still bind their report to the checked-out
commit, so that checkout must match `source_commit` in the artifact manifest.
A pull-request artifact can name GitHub's temporary merge commit as
`workflow_commit`; a `main` push artifact has identical source and workflow
commits.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\windows-whpx-soak.ps1 `
  -RootfsArchive C:\path\to\alpine-minirootfs.tar `
  -SystemImageManifest C:\a3s\oci-artifacts\windows\system-image\system-image.json
```

Run the nominal formal-driver gate separately:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\windows-whpx-driver-smoke.ps1 `
  -RootfsArchive C:\path\to\alpine-minirootfs.tar `
  -SystemImageManifest C:\a3s\oci-artifacts\windows\system-image\system-image.json
```

Run the owner-death and host-service recovery gate separately:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\windows-whpx-recovery-smoke.ps1 `
  -RootfsArchive C:\path\to\alpine-minirootfs.tar `
  -SystemImageManifest C:\a3s\oci-artifacts\windows\system-image\system-image.json
```

The default profile requires:

- 25 consecutive full protocol-v10 OCI lifecycles with an x86_64/AArch64
  seccomp architecture set;
- three waves of two independent VMs and three two-container lifecycles inside
  one authenticated VM;
- cleanup without a normal delete after create, start, and kill;
- isolated and inherited network namespace identities;
- persistent read-write and enforced read-only bind volumes;
- a delayed successful init script and an expected nonzero init failure, both
  with state written through a bind volume;
- ten exact host/guest validation rejections, including an unadvertised S390X
  seccomp architecture;
- owner termination at 0, 250, 1000, and 2500 milliseconds after shim spawn.

The runner writes every Linux guest workload asset as BOM-free LF text even
when Git checked out the source on Windows. The storage profile adds a bounded
qualification annotation so its serialized OCI Create request remains above
4 KiB independently of PowerShell JSON whitespace behavior.

Success additionally requires exact requested/completed counts, no bootstrap
token directory, guest runtime directory, marker, host CLI, or host shim
remaining, every operation sample marked `pass`, a bounded owner-to-shim exit,
and bounded host working-set and log growth. The evidence directory contains
`host.json`, start/final process inventories, `capability-results.tsv`,
`operations.tsv`, `resource-samples.tsv`, every command report and console,
`summary.json`, and a final `verify.out`.

Guest-side rejections must retain the exact bounded post-VM bootstrap layout.
The host-side process-field preflight rejection must instead leave the initial
single empty `dev` directory pristine and must never bind an endpoint or spawn
the shim.

The August 1, 2026 direct-driver qualification ran from clean commit
`7bb09dff81b5445e275c31faff6592ad4c32a45f` and emitted
`a3s.oci.whpx-driver-smoke-run.v1`. From 12:50:37Z through 12:51:08Z it built
the pinned artifacts and passed every nominal lifecycle, replay, exact-share,
authenticated recovery-publication, and cleanup field. It used rootfs SHA-256
`4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282`,
agent SHA-256
`b97ba3f0989432a13873f825e37d66cbb4244bbe7c126d537b0518190ff4091d`,
shim SHA-256
`e41c337f8454d3276f8062a92458e7eb8e264fa90e10cc452c96d5c5f4728eb3`,
and `krun.dll` SHA-256
`f21293b65ee16058c9014b543c708d84c50dc28d7775dbd77bac32faabafa59e`.
The retained report and summary SHA-256 values are respectively
`b9442b1d8da3d091f5a1b4099697fdf50dda932fe3bcb31a95c100fd361aec6e`
and `64d898fcad1f1ad597e8ad98a19233dec260a3d7831de39178ef24562766047f`.

The August 1, 2026 owner-death qualification ran from clean commit
`2d91cd04f6ec1ecd9ea3fce4673be6fdc2b6f631` with an empty recorded worktree and
emitted `a3s.oci.whpx-recovery-smoke-run.v1`. From 13:41:20Z through 13:41:30Z
it rebuilt the artifacts, force-terminated owner PID 57496 only after running
and marker readiness, injected both Recover fault boundaries, reopened the host
service, replayed exact signal 9, replayed the recovered driver tombstone kill,
completed stopped-only delete, and passed every cleanup field. It used rootfs
SHA-256 `4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282`,
agent SHA-256 `b97ba3f0989432a13873f825e37d66cbb4244bbe7c126d537b0518190ff4091d`,
CLI SHA-256 `23db303dfae37a1b2cb2973cb74d3d52a441abe91f588b41fdf9a26686cc488e`,
shim SHA-256 `8072612e5a1e5f0dea69b80697bdffa2a19fa54dd0c7f1e2f43a4d821146e189`,
and `krun.dll` SHA-256
`f21293b65ee16058c9014b543c708d84c50dc28d7775dbd77bac32faabafa59e`.
The retained report and summary SHA-256 values are respectively
`db7daff5d912d9d0786a660c9321274aa3ee1d666368792b3985412a5a682734`
and `c8179b2f2f4ed38f1820103645a2d96487ea0cdfb98a7884181e2082737d5270`.

The focused August 1, 2026 transport qualification used the Alpine minirootfs
SHA-256
`4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282`,
guest-agent SHA-256
`e78261ee3c6628045692003d59c948e965eafbf44291797ce705319dccfc9826`,
and `krun.dll` SHA-256
`ab8ceb013795fa8b43a3793f9579179c0afb9608430af1c21f6e9145cf27d7d9`.
In 63.970 seconds it passed one serial lifecycle, two parallel lifecycles,
five workload cases, nine typed negative cases, and owner termination at four
timing points. Its storage create request crossed the 4 KiB WHPX stream
boundary, and every case left zero A3S host processes and zero guest
bootstrap/runtime directories. This is focused transport regression evidence;
the default profile above remains the broader hardware gate.

The focused August 29, 2026 immutable-root qualification ran from base commit
`94a1de2e46fc40ccffcad35d97f2f93ff1ec2e60` with the changes recorded by this
revision. It used `krun.dll` SHA-256
`cc18d354fec2c235fdce53b723b96dccb2ef3994a7dda141c923a0efa0bba7db`,
NUMA-capable `libkrunfw.dll` SHA-256
`295e8a8e660f396fd0007d48c43175d9ed5b19243570640ad65fc47b41e7596a`,
and kernel bundle SHA-256
`1c211df81b481a906409cb32f25f392577389a2f5ccf48bc2dd913bb64a1f6b4`.
The retained workload requested `MPOL_BIND` on node zero with
`MPOL_F_STATIC_NODES` and required `/proc/self/numa_maps` to contain
`bind=static:0` before publishing its marker. Its configuration SHA-256 is
`cf68d31de5e1ffd5076353953d4608f4b907d8165050cd7794a5a66de0cfb64a`.
The immediately preceding shim schema-v7 report completed real VM entry with
guest exit zero and recorded 127 process handles both before and after VM
entry, with `windows_handle_inventory_restored=true`; its outer report SHA-256
is `240abb97b6fb5f3476dc9be330ac482e22c23b547df2bfcd8a75f1d80fb63b1e`.
After synchronizing the Host's expected kernel-bundle size, the final direct
driver report passed every lifecycle, replay, deletion, and cleanup field. The
final report and summary SHA-256 values are respectively
`871c230ace4c7a2c1ca12c965ba7e03fc9b14d74859bacdb57e5d8bef3620292`
and `38fb73b6fe38acc3d596631d48dc034b04130a9a2bc8b44e769326e1e83bd92f`.
This is focused current-asset evidence; it does not replace the complete SDK,
recovery, negative, and soak matrix required for promotion.

`fixtures/utility-vm/config.windows.json` is an explicit Windows qualification
profile. It requests UTS, mount, IPC, network, cgroup, and PID namespaces. It
does not request user or time namespaces because those paths hang in the
current WHPX utility kernel, and the resource update omits only the unavailable
swap controller. The compatibility marker still has its historical
`user-time-v1` payload; the soak never treats that string as evidence that
Windows applied user or time namespaces.

The July 24, 2026 qualification used the untouched Alpine 3.22.5 x86_64
minirootfs archive with SHA-256
`4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282`.
The fixed runtime completed five consecutive marker runs without setting
`LIBKRUN_WINDOWS_HYPERV_ENLIGHTENMENTS`.

The fixed OCI lifecycle qualification used the 6,328,408-byte static musl agent
with SHA-256
`4b21a230d4183abe053823a63893f5ab0663c118811c81229bdfba0816fc9b81`.
Its report selected protocol version 1, identified the guest as `x86_64`,
verified every then-current fixed lifecycle field, retained the complete
successful shim report, and returned exit status zero. This historical run
predates the protocol-v2 wait gate and does not qualify the current report
schemas.

The UTS qualification configured hostname `a3s-smoke` and domainname
`runtime.test`, checked the hostname from the workload, and crossed the create
barrier only after the wrapper read both applied values back with `uname`.

The mount qualification requested new UTS and mount namespaces in the same
bundle. It first rbind-mounted a relative bundle source onto `/mnt`, then
mounted proc at `/mnt/proc`, a destination that only existed because the first
entry had already run, and finally mounted tmpfs from a relative destination
onto `/tmp`. The workload verified both filesystem types through
`/proc/self/mountinfo` and completed the full lifecycle after `pivot_root`. A
companion bundle omitted the mount namespace; create retained the exact typed
`Unsupported` rejection and left no guest runtime directory. A joined-mount
namespace negative was rejected by that historical agent.

The namespace qualification combined that ordered mount sequence with new IPC,
network, and cgroup namespaces. The workload compared
`/proc/self/ns/{ipc,net,cgroup}` with guest PID 1 and produced its marker only
after all three identities differed. The full lifecycle and cleanup report
passed. A companion bundle supplied `/proc/1/ns/net` as a network namespace
join path; the historical agent retained the exact typed `Unsupported`
rejection and left no guest runtime directory.

The PID qualification used the 6,371,704-byte static musl agent with SHA-256
`45d27bfdfec50ddedabd1f11a143dba4c11b4f472e7d2627a686594a0c514f6d`.
The supervisor forked a container init that required shell PID 1 and a matching
`/proc/1/ns/pid` identity before writing the marker. Create returned
authenticated host-visible PID 396, the complete lifecycle and cleanup report
passed, and the VM exited cleanly. A companion bundle joined
`/proc/1/ns/pid`; create retained `Unsupported` at
`linux.namespaces[5].path` and left no guest runtime directory.

The libkrun dependency is target-specific to the isolated shim. The main
runtime, CLI, and SDK dependency graphs do not contain it, and the Linux target
does not build it.

The fixed-bundle smokes do not prove that:

- the pinned immutable A3S system image boots;
- the rootful user/time namespace slice now exercised on native Linux and
  macOS, namespace joins, recursive or ID-mapped mounts, tmpfs, capabilities,
  seccomp, or hooks work through WHPX;
- arbitrary shared-guest-kernel isolation policies work; the current driver
  intentionally owns one dedicated VM per container;
- the driver is production ready.

For that reason, driver readiness remains `probe-only` even after all smokes
succeed. Driver resolution must reject `probe-only` readiness rather than
silently treating host capability as runtime support.

The runtime contains a qualification-only `WhpxRuntimeDriver` candidate.
It uses the same twenty-operation adapter as native Linux, owns one VM per
exact dedicated-VM generation, retains the VM across retryable create calls,
and reaps terminal create failures, deletes, and driver shutdown exactly once.
Opening it requires a bootstrap directory below the protected runtime root, a
manifest and image outside that mutable tree, and a disjoint runtime-created
`shares` parent. The driver creates an empty `dev` mount point and, after a VM
exit, accepts only the fixed empty `dev`, `newroot`, `proc`, and `sys` mount
points plus five bounded plain init logs. Create accepts a bundle only below
the exact `<container>/<generation>` share, exports only that directory, and rejects
cross-generation or external paths before launching a VM. The shim stages
token and recovery files in the share and emits v4 evidence for the read-only
block root, fixed native boot assets, and separate virtio-fs device; the host
requires the same manifest digest it retained before launch and includes that
digest in the durable driver binding used after host-service reopen. Its
reported readiness deliberately stays `probe-only`, so the durable host
service cannot register it yet.

The generic host now has an idempotent startup recovery handshake. WHPX uses
the shim's existing owner-PID watcher as its fail-closed contract: when a new
host process has no live in-process session for a durable generation, the old
VM is treated as owner-death-terminated and an exact stopped tombstone is
installed. `state`, idempotent `kill`, empty `processes`, and `delete` remain
safe. A live session in the same process is queried through the authenticated
agent and its generation plus configuration digest are revalidated.
An interrupted durable `creating` transition cannot legally become `stopped`
directly, so recovery retains its tombstone without committing an observation;
replaying the original create then returns a terminal error and the existing
durable failure path quarantines that generation.

The guest side of the next recovery gate is implemented: complete executor
shutdown emits a bounded, exact-generation report containing the canonical
configuration digest and real init exit status, authenticated with the
ephemeral session token. The owner-PID shim preserves the one-time guest path
during its 15-second cleanup grace, validates the authentication tag after the
VM exits, removes the guest copy, and atomically commits only the normalized
report into a protected host recovery directory outside the writable share. A
plain, protected pending marker spans VM launch through successful or failed
handoff. A restarted host now parses only the normalized report, rechecks the
exact target and durable configuration digest, commits `stopped`, and caches
the real init result through the durable wait path. When only the marker is
present it waits through the shim's bounded owner-death grace and fails
retryably on overrun instead of racing ahead. The report is retained across
both sides of the recovery fault boundary and removed only by exact-generation
delete. If neither authenticated evidence nor a pending handoff exists, the
stopped tombstone remains usable for cleanup while `wait` still fails instead
of inventing a result. The nominal direct-driver path and the
owner-death/service-restart path now have real WHPX evidence. The retained
`a3s.oci.whpx-recovery-smoke-run.v1` report at clean commit `2d91cd0` covers
exact owner termination, both recovery fault boundaries, service reopen,
terminal replay, stopped-only delete, and complete transient cleanup.

## Next Windows gate

The version-pinned image, read-only root attachment, source/digest manifest,
pre-entry drift checks, separate runtime-share path, NUMA-capable firmware, and
one focused real-host lifecycle are implemented. The release gate remains open
until the following two complete matrix gates pass:

1. rerun the complete WHPX SDK, soak, owner-death, and service-recovery
   matrices against the exact v1 manifest on a fresh WHPX-enabled Windows
   host, retaining the v4 boot evidence in every session;
2. retain the current v7 shim report from every matrix session and require its
   inherited v6 handle-reclamation fields, including nonzero
   `windows_handles_before_vm` and `windows_handles_after_vm` values to match,
   with `windows_handle_inventory_restored=true`.

The implementation now captures those two inventories in the libkrun shim,
after immutable assets are pinned and again immediately after
`krun_start_enter` returns. Before capturing the baseline it initializes the
Windows error-resource, WHPX partition/vCPU, and system-RNG facilities, then
releases the temporary vCPU and partition, so process-global lazy handles are
not misclassified as VM leaks. Host validation and the hardware soak script
reject missing, zero, mismatched, or false evidence. The focused current-asset
run retained exact equality, but the complete fresh-host rerun must retain the
same evidence before WHPX can become `experimental`.

Broader namespace, mount, capability, resource, seccomp, hook, and shared-guest
coverage remains part of the shared executor, OCI conformance, and later
readiness gates. It does not reopen the already-qualified owner-death recovery
contract.

Only completion of that gate may promote Windows driver readiness to
`experimental`.
