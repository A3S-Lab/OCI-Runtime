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
5. links `a3s-libkrun-sys 3.1.0` only into an isolated shim and stages its
   checksum-verified `krun.dll` and `libkrunfw.dll` pair;
6. creates, configures for one vCPU and 128 MiB, and releases one real libkrun
   context without entering a VM;
7. emits stable JSON evidence through `a3s-oci features`,
   `a3s-oci whpx-smoke`, and `a3s-oci-krun-shim context-smoke`.

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
- `krun_free_ctx` releases the context.

The libkrun dependency is target-specific to the isolated shim. The main
runtime, CLI, and SDK dependency graphs do not contain it, and the Linux target
does not build it.

The two smokes do not prove that:

- libkrun can boot the pinned A3S Linux kernel;
- virtio-fs, vsock, named-pipe transport, or process I/O works;
- OCI create/start ordering is implemented;
- one or multiple Linux containers can execute;
- the driver is production ready.

For that reason, driver readiness remains `probe-only` even after both smokes
succeed. Driver resolution must reject `probe-only` readiness rather than
silently treating host capability as runtime support.

## Next Windows gate

The next vertical slice must:

1. enter a one-vCPU, bounded-memory WHPX utility VM;
2. boot a version-pinned A3S kernel and static guest agent;
3. negotiate the versioned host/guest protocol;
4. mount one protected runtime-owned root through virtio-fs;
5. execute a fixed local Alpine OCI bundle with an exact create/start barrier;
6. return stdout, stderr, and the natural exit code;
7. reconcile stopped state after host runtime restart;
8. leave no process, handle, endpoint, or temporary state after delete.

Only completion of that gate may promote Windows driver readiness to
`experimental`.
