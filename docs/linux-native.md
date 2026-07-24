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
runtime-owned directories and exercises it only through `RuntimeClient`. The
submitted bundle is strictly loaded before the lifecycle begins, and the
driver translates the durable host contract directly to the shared
`LinuxExecutor`.

The versioned `a3s.oci.native-linux-smoke.v2` report requires all of the
following:

1. the service advertises exactly `features`, `create`, `state`, `start`,
   `kill`, `delete`, and `wait`;
2. a dedicated-VM create fails as `Unsupported` before claiming the container
   ID or operation ID;
3. create returns a positive host-visible PID in the exact OCI `created`
   state;
4. the workload marker is absent before start;
5. retrying create replays its exact result;
6. start releases the prepared init; the workload verifies exact rootful
   UID/GID maps plus monotonic and boottime namespace offsets before the marker
   is observed;
7. a 50-millisecond wait returns `DeadlineExceeded` while the init process is
   still running;
8. `SIGKILL` reaches the namespace PID 1 through its retained pidfd, and
   retrying kill replays its exact result;
9. wait returns signal 9 with `oom_killed: false`, and a repeated wait returns
   the same terminal result;
10. state reaches `stopped`;
11. stopped-only delete and its exact retry succeed;
12. state returns `NotFound` after delete;
13. the marker, executor root, and complete smoke session are removed.

The smoke uses `SIGKILL` because Linux protects a PID-namespace init from
default-action signals such as `SIGTERM`. General PID 1 supervision and signal
forwarding remain part of the executor roadmap. The runtime never resolves the
numeric PID again for lifecycle or cleanup signaling.

GitHub Actions runs this real rootful lifecycle on x86_64 and aarch64 Ubuntu.
Each architecture runs once with `/dev/kvm` absent and once with a directory at
that path, which is present but unusable as a KVM device. The script validates
the corresponding `kvm_device_present` report field and restores any original
device after the test.

Ubuntu 24.04 GitHub-hosted runners enable an AppArmor policy that rejects the
fixture's mount operations inside its new user namespace. Only when
`GITHUB_ACTIONS=true`, the smoke script temporarily disables that one policy
for the duration of the qualification script and restores its original value
on exit. The runtime itself never changes host security policy. A production
host must provide an appropriate narrow LSM policy for the requested OCI
profile; a denied mount fails the create operation.

Run the same gate on a supported Ubuntu host:

```sh
bash .github/scripts/native-linux-smoke.sh
```

The script installs `busybox-static` and `jq`, builds the matching
`a3s-oci-agent` and CLI binaries, constructs the checked-in fixture with a
root-owned rootfs and `/proc` mount target, and executes both KVM-independent
cases.

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

The `a3s.oci.native-linux-multi-container-smoke.v2` success additionally
requires exact create/start/kill/delete replay, stable repeated wait results,
independent wait/state progress, both marker removals, executor shutdown, and
complete durable-session removal. GitHub Actions runs the gate on x86_64 and
aarch64 both without `/dev/kvm` and with a present but unusable placeholder at
that path.

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

The versioned `a3s.oci.native-linux-fault-cleanup.v2` report requires:

1. the exact seven-operation service inventory, requested prefix, and a
   positive runtime-visible init PID;
2. marker absence behind create and exact marker contents after start;
3. `normal_delete_attempted: false`;
4. successful executor shutdown and disappearance of the init PID;
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
- namespace joins and lifecycle-level namespace security-negative cases;
- complete mount, credential, capability, seccomp, LSM, and cgroup v2
  enforcement;
- namespace-internal init supervision and orphan/zombie reaping, exec,
  per-process wait, and complete process I/O;
- hooks, exhaustive durable-write and driver-error recovery injection,
  descriptor-relative path handling, and adversarial cleanup;
- the complete A3S Box Rust, Python, and TypeScript Sandbox SDK suites on
  x86_64 and aarch64 without KVM.

Only a caller that deliberately constructs `open_experimental` can use the
current lifecycle slice.
