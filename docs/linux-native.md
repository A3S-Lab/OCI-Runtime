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
- `/proc/self/ns/user`;
- `/proc/self/ns/uts`;
- `/sys/fs/cgroup/cgroup.controllers`.

It also records `/proc/sys/kernel/unprivileged_userns_clone` when that
distribution-specific policy file exists. The policy is evidence for future
rootless execution; it is not required for rootful host availability.

The native probe never:

- opens `/dev/kvm`;
- links or initializes libkrun;
- creates a namespace;
- writes cgroup state;
- mutates runtime state.

An available result means only that the baseline kernel interfaces exist.
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

The versioned `a3s.oci.native-linux-smoke.v1` report requires all of the
following:

1. the service advertises exactly `features`, `create`, `state`, `start`,
   `kill`, and `delete`;
2. a dedicated-VM create fails as `Unsupported` before claiming the container
   ID or operation ID;
3. create returns a positive host-visible PID in the exact OCI `created`
   state;
4. the workload marker is absent before start;
5. retrying create replays its exact result;
6. start releases the prepared init and the marker is observed;
7. `SIGKILL` terminates the namespace PID 1 and retrying kill replays its exact
   result;
8. state reaches `stopped`;
9. stopped-only delete and its exact retry succeed;
10. state returns `NotFound` after delete;
11. the marker, executor root, and complete smoke session are removed.

The smoke uses `SIGKILL` because Linux protects a PID-namespace init from
default-action signals such as `SIGTERM`. General PID 1 supervision and signal
forwarding remain part of the executor roadmap.

GitHub Actions runs this real rootful lifecycle on x86_64 and aarch64 Ubuntu.
Each architecture runs once with `/dev/kvm` absent and once with a directory at
that path, which is present but unusable as a KVM device. The script validates
the corresponding `kvm_device_present` report field and restores any original
device after the test.

Run the same gate on a supported Ubuntu host:

```sh
bash .github/scripts/native-linux-smoke.sh
```

The script installs `busybox-static` and `jq`, builds the matching
`a3s-oci-agent` and CLI binaries, constructs the checked-in fixture, and
executes both KVM-independent cases.

## Remaining promotion gates

This evidence proves one rootful bootstrap profile, not general OCI support.
The default driver must remain `probe-only` until at least the following pass:

- rootless lifecycle using user namespaces and UID/GID mappings;
- namespace joins, time namespaces, and security-negative cases;
- complete mount, credential, capability, seccomp, LSM, and cgroup v2
  enforcement;
- init supervision, zombie reaping, pidfd signaling, and complete process I/O;
- hooks, fault-injected recovery, descriptor-relative path handling, and
  adversarial cleanup;
- the complete A3S Box Rust, Python, and TypeScript Sandbox SDK suites on
  x86_64 and aarch64 without KVM.

Only a caller that deliberately constructs `open_experimental` can use the
current lifecycle slice.
