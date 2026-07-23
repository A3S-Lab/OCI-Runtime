# Windows WHPX Development

## Current scope

The first Windows slice establishes an honest capability boundary before
libkrun or OCI lifecycle code is allowed to launch workloads.

The runtime:

1. loads `WinHvPlatform.dll` only from the Windows system directory search
   scope;
2. resolves `WHvGetCapability`, `WHvCreatePartition`, and
   `WHvDeletePartition`;
3. queries `WHvCapabilityCodeHypervisorPresent`;
4. optionally creates and deletes a WHPX partition object as a smoke test;
5. emits stable JSON evidence through `a3s-oci features` and
   `a3s-oci whpx-smoke`.

The capability query follows the
[Windows Hypervisor Platform API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform).
The smoke operation uses
[`WHvCreatePartition`](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition)
and always attempts the matching delete operation.

## What the smoke proves

A successful smoke proves that:

- the WHPX API DLL and required symbols are present;
- the Windows hypervisor reports itself present;
- the process can create and release a WHPX partition object.

It does not prove that:

- libkrun can boot the pinned A3S Linux kernel;
- virtio-fs, vsock, named-pipe transport, or process I/O works;
- OCI create/start ordering is implemented;
- one or multiple Linux containers can execute;
- the driver is production ready.

For that reason, driver readiness remains `probe-only` even after a successful
smoke. Driver resolution must reject `probe-only` readiness rather than
silently treating host capability as runtime support.

## Next Windows gate

The next vertical slice must use `a3s-libkrun-sys` to:

1. create a one-vCPU, bounded-memory WHPX utility VM;
2. boot a version-pinned A3S kernel and static guest agent;
3. negotiate the versioned host/guest protocol;
4. mount one protected runtime-owned root through virtio-fs;
5. execute a fixed local Alpine OCI bundle with an exact create/start barrier;
6. return stdout, stderr, and the natural exit code;
7. reconcile stopped state after host runtime restart;
8. leave no process, handle, endpoint, or temporary state after delete.

Only completion of that gate may promote Windows driver readiness to
`experimental`.
