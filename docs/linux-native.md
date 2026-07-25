# Native Linux Development

## Current capability boundary

Linux feature discovery reports two independent drivers:

- `native-linux` for direct namespace and cgroup execution on the host;
- `libkrun-kvm` for an optional Linux utility VM.

The probes deliberately do not share status. Missing or inaccessible KVM must
not make native Linux unavailable, and a usable KVM device must not imply that
the utility-VM driver can launch a workload.

Both entries in the default feature inventory remain `probe-only`.
`NativeLinuxDriver::open_experimental` is a separate, explicit rootful
development opt-in. It changes only the constructed driver instance to
`experimental`, accepts only `shared-host-kernel` isolation, and reuses
`LinuxExecutor` directly without linking or initializing libkrun.

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
distribution-specific policy file exists. The policy is evidence for future
rootless execution; it is not required for rootful host availability.
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
lifecycle through `RuntimeClient`; `HostRuntimeService` journals exec and
per-process signal, caches init and process terminal results, and dispatches
the exact generation through `NativeLinuxDriver` to the shared
`LinuxExecutor`. The submitted bundle is strictly loaded before the lifecycle
begins.

The versioned `a3s.oci.native-linux-smoke.v3` report requires all of the
following:

1. the service advertises exactly `features`, `create`, `state`, `start`,
   `kill`, `delete`, `exec`, `wait`, `signal-process`, and `wait-process`;
2. a dedicated-VM create fails as `Unsupported` before claiming the container
   ID or operation ID;
3. create returns the positive host-visible PID of the configured process in
   the exact OCI `created` state while a dedicated namespace PID 1 remains
   behind it;
4. the workload marker is absent before start;
5. retrying create replays its exact result;
6. start releases the prepared init; the workload verifies exact rootful
   UID/GID maps plus monotonic and boottime namespace offsets before the marker
   is observed;
7. exact-target exec and its retry return the same positive authenticated PID,
   a duplicate process ID is rejected, and a 50-millisecond process wait
   returns `DeadlineExceeded`;
8. per-process `SIGKILL` and its exact retry succeed through the retained
   pidfd, process wait returns signal 9, and repeated process wait is stable;
9. a second live exec is terminated and reaped automatically when init exits,
   while process ID `init` returns the same result as lifecycle wait;
10. a 50-millisecond wait returns `DeadlineExceeded` while the configured
   process is still running;
11. `SIGKILL` reaches the configured process through its retained pidfd, and
   both internal supervisors preserve the exact signal result while retrying
   kill replays its exact result;
12. wait returns signal 9 with `oom_killed: false`, and a repeated wait returns
   the same terminal result;
13. state reaches `stopped`;
14. stopped-only delete and its exact retry succeed;
15. state returns `NotFound` after delete;
16. the marker, executor root, and complete smoke session are removed.

The smoke uses `SIGKILL` to prove exact signal-status propagation through the
namespace PID 1 and outer launcher. The runtime never resolves the numeric PID
again for lifecycle or cleanup signaling.

GitHub Actions runs this real rootful lifecycle on x86_64 and aarch64 Ubuntu.
Each architecture runs once with `/dev/kvm` absent and once with a directory at
that path, which is present but unusable as a KVM device. The script validates
the corresponding `kvm_device_present` report field and restores any original
device after the test.

The fixture is created beneath a private `/var/tmp` directory whose complete
ancestor chain is searchable by the mapped host root identity. This is required
after entering the child user namespace: its capabilities no longer bypass
mode bits owned by the initial user namespace. The script does not weaken
AppArmor or another host security policy. A production rootfs must likewise be
reachable by its configured host mappings; an inaccessible ancestor or an LSM
denial fails the create operation.

Run the same gate on a supported Ubuntu host:

```sh
bash .github/scripts/native-linux-smoke.sh
```

The script installs `busybox-static` and `jq`, builds the matching
`a3s-oci-agent` and CLI binaries, constructs the checked-in fixture with a
root-owned, searchable rootfs and `/proc` mount target, executes both
KVM-independent cases, and removes its qualification directory on exit.

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
sudo target/debug/a3s-oci native-linux-multi-container-smoke \
  --agent "$PWD/target/debug/a3s-oci-agent" \
  --bundle-a "$bundle_a" \
  --bundle-b "$bundle_b" \
  --work-parent "$work_parent"
```

The `a3s.oci.native-linux-multi-container-smoke.v9` success additionally
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
8. the rootfs to be read-only and reject a write;
9. exact ordered evidence, a normal zero exit, deleted state, and removal of
   all host-side fixture paths.

GitHub Actions runs the gate on x86_64 and aarch64 both without `/dev/kvm` and
with a present but unusable placeholder at that path.

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

The versioned `a3s.oci.native-linux-fault-cleanup.v3` report requires:

1. the exact ten-operation service inventory, requested prefix, and a positive
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

This evidence proves one rootful bootstrap profile, not general OCI support.
The default driver must remain `probe-only` until at least the following pass:

- rootless lifecycle using subordinate UID/GID mappings and the
  `setgroups=deny` flow;
- broader namespace-join security negatives, donor teardown races, and
  restart recovery beyond the retained wrong-type pre-state rejection;
- complete mount, credential, capability, seccomp, LSM, and cgroup v2
  enforcement;
- real-driver reattachment after runtime-process restart, plus complete
  process I/O and PTY handling;
- hooks, durable recovery for the remaining mutating operations,
  descriptor-relative path handling, transport-level fault injection, and
  adversarial cleanup;
- the complete A3S Box Rust, Python, and TypeScript Sandbox SDK suites on
  x86_64 and aarch64 without KVM.

Only a caller that deliberately constructs `open_experimental` can use the
current lifecycle slice.
