# Native Linux Development

## Current capability boundary

Linux feature discovery reports two independent drivers:

- `native-linux` for direct namespace and cgroup execution on the host;
- `libkrun-kvm` for an optional Linux utility VM.

The probes deliberately do not share status. Missing or inaccessible KVM must
not make native Linux unavailable, and a usable KVM device must not imply that
the utility-VM driver can launch a workload.

Both drivers remain `probe-only`.

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
`DriverReadiness::ProbeOnly` still prevents selection by
`HostRuntimeService::open`.

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

## Next native gate

The next native Linux increment must reuse the reviewed Linux executor and
complete a real Alpine lifecycle without KVM:

1. create a blocked init process;
2. return the exact OCI `created` state;
3. release it only on `start`;
4. preserve natural and signal exits;
5. clean namespaces, cgroups, mounts, processes, and durable state;
6. repeat with `/dev/kvm` absent and present but inaccessible.

The driver must stay `probe-only` until rootful and rootless lifecycle,
security-negative, recovery, and cleanup evidence passes on x86_64 and
aarch64.
