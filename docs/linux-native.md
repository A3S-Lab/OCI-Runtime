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

## Experimental lifecycle gate

The `native-linux-smoke` command opens the native driver beneath isolated
runtime-owned directories. It exercises the durable init and process
lifecycle through `RuntimeClient`; `HostRuntimeService` journals exec,
per-process signal, pause/resume/update, and write-stdin/close-stdin/resize,
caches init and process terminal results, and dispatches the exact generation
through `NativeLinuxDriver` to the shared `LinuxExecutor`. The submitted bundle
is strictly loaded before the lifecycle begins.

The versioned `a3s.oci.native-linux-smoke.v12` report requires all of the
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
   `RLIMIT_NOFILE` soft/hard value of 64, verifies FD 3 and FD 4 are sockets,
   and writes the exact `a3s-box-native-control-v1\n` bytes through FD 5
   before the marker is observed; the host connects to both inherited
   listeners and reads back the exact log;
8. exact-target exec reads back its own `RLIMIT_NOFILE` soft/hard value of 48;
   exec and its retry return the same positive authenticated PID, a duplicate
   process ID is rejected, and a 50-millisecond process wait returns
   `DeadlineExceeded`;
9. per-process `SIGKILL` and its exact retry succeed through the retained
   pidfd, process wait returns signal 9, and repeated process wait is stable;
10. process inventory returns exactly the live init and second exec process;
11. one exact durable update changes memory limit/reservation/swap, CPU
   shares/quota/period/cpuset, and the PID limit; retrying it returns the same
   container record;
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
    operation ID for a changed destination fails as `Conflict` without creating
    that file, and mkdir/stat/list/move/recursive-remove each preserve exact
    metadata, mutation replay, and post-cleanup `NotFound` evidence;
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

The script installs `busybox-static`, `jq`, `uidmap`, and `util-linux`, builds
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
`a3s.oci.native-linux-smoke.v12` lifecycle assertions over a real `0600` Unix
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

If the bundle contains `linux.cgroupsPath`, the command also requires
`--delegated-cgroup-root`. That path must already be canonical, be an empty
cgroup-v2 directory owned by the effective UID/GID, and expose and enable the
`cpu`, `cpuset`, `memory`, and `pids` controllers. The runtime revalidates its
device/inode identity before creating a private `a3s-oci-*` manager below it;
it never guesses a systemd scope or enables controllers outside the supplied
delegation.

The CI fixture creates a dedicated UID/GID 20000 account with UID range
300000:65536 and GID range 400000:65536. A host file owned by 300000:400000
must appear as 1:1 inside the workload. The versioned
`a3s.oci.native-linux-rootless-smoke.v4` report then requires:

1. exact create and replay behind the OCI `created` barrier;
2. exact `/proc/<pid>/uid_map` and `gid_map` read-back plus
   `/proc/<pid>/setgroups == deny` before start;
3. a started workload that observes namespace root and the translated 1:1
   fixture ownership;
4. exact exec/replay, pidfd signal/replay, and stable signal-9 process wait;
5. exact init kill/replay and stable signal-9 lifecycle wait;
6. one ordered creating/created/started, exec create/start/exit, stopped, init
   exit, and deleted event sequence with an empty tail cursor;
7. delegated resource update/stats, exact pause/resume replay, and workload
   progress that stops while frozen and continues after resume;
8. stopped-only delete replay, post-delete `NotFound`, empty list, and removal
   of every process, marker, executor root, and durable session directory.

The hidden `native-linux-rootless-device-policy-smoke` extends that gate for the
exact A3S Box six-node device profile. It must be launched with non-root real
UID/GID, effective UID/GID zero, and no supplementary groups. Before creating
Tokio, the CLI retains the exact delegated cgroup descriptor, forks one
parent-bound helper, then irreversibly drops all owner credentials to the real
identity. The helper accepts only framed, versioned install, replace, remove,
and explicit shutdown messages for normalized paths below that descriptor. It
does not accept filesystem roots, raw BPF, arbitrary device nodes, or
caller-supplied program descriptors.

The v4 device-policy report verifies all six retained host nodes inside the
container, read/write behavior for the common devices, a live read-only
replacement, rejection with rollback for an out-of-profile update, disable and
re-enable, the exact additional exec/update event sequence, helper shutdown,
and an empty delegated subtree. Unexpected owner or channel loss closes the
helper without detaching active filters, so policy remains fail-closed until
the protected cgroups are recovered and removed.

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
jq '.linux.cgroupsPath = "a3s-oci-smoke-b"' \
  "$bundle_b/config.json" >"$bundle_b/config.json.tmp"
mv "$bundle_b/config.json.tmp" "$bundle_b/config.json"

sudo target/debug/a3s-oci native-linux-multi-container-smoke \
  --agent "$PWD/target/debug/a3s-oci-agent" \
  --bundle-a "$bundle_a" \
  --bundle-b "$bundle_b" \
  --work-parent "$work_parent"
```

The two simultaneously live bundles must use distinct cgroup v2 paths; the
checked-in fixture reserves `a3s-oci-smoke-a` for bundle A.

The `a3s.oci.native-linux-multi-container-smoke.v14` success additionally
requires exact create/start/kill/delete replay, stable repeated wait results,
independent wait/state progress, both marker removals, executor shutdown, and
complete durable-session removal. It then keeps a prepared donor behind its
create barrier and requires:

1. a namespace descriptor whose type disagrees with its OCI entry to fail
   before container state;
2. one workload to join the donor UTS, IPC, network, cgroup, PID, user, and
   time namespaces while retaining a private mount namespace;
3. a second workload to join the donor mount namespace and execute through the
   rootfs descriptor retained before `setns`;
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
3. the root mount to belong to a new shared peer group;
4. `/proc/sys` to be a distinct read-only mount, `/proc/meminfo` to be replaced
   by a private empty read-only file, and `/proc/irq` by an empty read-only
   directory;
5. recursive read-only, nosuid, nodev, noexec, noatime, nodiratime, and
   nosymfollow attributes to hold on both an rbind target and its nested
   submount while the source mounts remain writable and executable;
6. detached `idmap` and `ridmap` filesystem mounts to expose the exact
   requested UID/GID ownership;
7. the original nested bind source to remain owned by `0:0`, non-recursive
   `idmap` to map only the rbind top level to `1000:1000`, and recursive
   `ridmap` to map both the top level and real nested submount to `2000:2000`;
8. a file on an initial-user-namespace tmpfs to remain readable with its exact
   mode through a kernel-enforced read-only, nosuid, nodev, and noexec bind in
   the container user namespace, while rejecting a write;
9. the rootfs to be read-only and reject a write;
10. exact ordered evidence, a normal zero exit, deleted state, and removal of
   all host-side fixture paths.

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
  nonzero exit of 42. Negative OCI Hook runs require createContainer failure
  rollback, startContainer failure followed by force cleanup, bounded prestart
  timeout and process-group termination, and warning-only poststop failure.
  The service list and every exact target must be empty afterward.

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
created generation contains a versioned recovery record. Those mode-0600 files
bind the immutable configuration digest to the exact owner, launcher, and init
PID start times plus only the cgroup directories created for that generation.
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
5. stopped-only delete removes the durable record, exact executor slot, and
   runtime-created cgroups;
6. replacement-driver shutdown leaves the executor parent empty;
7. the report binds both owner processes to their effective UID/GID and records
   whether an explicit cgroup-v2 delegation was requested and verified;
8. a delegated run removes every runtime-created `a3s-oci-*` cgroup below the
   exact user-owned authority root while preserving its host-owned control
   child.

Both x86_64 and aarch64 Linux CI run the gate twice. The rootful report is
retained via `A3S_OCI_NATIVE_RECOVERY_REPORT`; the non-root UID/GID 20000 run
reopens the same explicit delegation in a distinct non-root process and is
retained via `A3S_OCI_NATIVE_ROOTLESS_RECOVERY_REPORT`. These gates prove safe
termination and exact cleanup. They deliberately do not claim live process-I/O
session reattachment; that requires a persistent authenticated supervisor and
remains a promotion gate.

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
- remaining mount and credential controls, broader cgroup v2 policies,
  multi-architecture/notification seccomp, and broader sysctl enforcement;
- live real-driver reattachment after runtime-process restart, plus generic SDK
  inherited process-I/O modes beyond the fixed A3S Box init-control profile;
- broader Hook rollback/recovery/security-negative and adversarial soak beyond
  the retained create/start/timeout/poststop matrix, durable recovery for the
  remaining mutating operations, descriptor-relative path handling,
  transport-level fault injection, and adversarial cleanup beyond the bounded
  native lifecycle churn gate;
- the complete A3S Box Rust, Python, and TypeScript Sandbox SDK suites on
  x86_64 and aarch64 without KVM.

Only a caller that deliberately constructs `open_experimental` can use the
current lifecycle slice.
