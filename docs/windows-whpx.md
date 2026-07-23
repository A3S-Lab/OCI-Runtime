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
   stages a runtime-owned, checksum-verified native bundle imported from
   `A3S-Lab/Box@46e17a8`;
6. creates, configures for one vCPU and 128 MiB, replaces implicit TSI with a
   zero-feature plain-vsock device, maps guest port 4093 to a validated bare
   Windows pipe name, and releases one real libkrun context without entering a
   VM;
7. enters a one-vCPU, 512 MiB utility VM, executes `/bin/sh` from a supplied
   Linux rootfs, and verifies a guest-written marker through virtiofs;
8. emits stable JSON evidence through `a3s-oci features`,
   `a3s-oci whpx-smoke`, `a3s-oci-krun-shim context-smoke`, and
   `a3s-oci-krun-shim vm-smoke`.

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

A successful libkrun VM smoke additionally proves that:

- the packaged kernel reaches Linux userspace through WHPX;
- `/bin/sh` executes from the supplied rootfs;
- Windows virtiofs preserves Linux `READLINK` syntax for standard absolute
  OCI rootfs links;
- the guest can write through the shared root and the host observes the exact
  marker contents;
- the guest returns exit code zero and the host removes the marker;
- fatal WHPX exits are not accepted as successful workload completion.

The July 24, 2026 qualification used the untouched Alpine 3.22.5 x86_64
minirootfs archive with SHA-256
`4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282`.
The fixed runtime completed five consecutive marker runs without setting
`LIBKRUN_WINDOWS_HYPERV_ENLIGHTENMENTS`.

The libkrun dependency is target-specific to the isolated shim. The main
runtime, CLI, and SDK dependency graphs do not contain it, and the Linux target
does not build it.

The smokes do not prove that:

- the static A3S guest agent or its system image boots;
- a guest connects through vsock to an access-controlled named-pipe server;
- networking or complete process I/O works;
- OCI create/start ordering is implemented;
- one or multiple Linux containers can execute;
- the driver is production ready.

For that reason, driver readiness remains `probe-only` even after both smokes
succeed. Driver resolution must reject `probe-only` readiness rather than
silently treating host capability as runtime support.

## Next Windows gate

The next vertical slice must:

1. boot a version-pinned A3S system image and static guest agent;
2. negotiate the versioned host/guest protocol;
3. mount one protected runtime-owned root through virtio-fs;
4. execute a fixed local Alpine OCI bundle with an exact create/start barrier;
5. return stdout, stderr, and the natural exit code;
6. reconcile stopped state after host runtime restart;
7. leave no process, handle, endpoint, or temporary state after delete.

Only completion of that gate may promote Windows driver readiness to
`experimental`.
