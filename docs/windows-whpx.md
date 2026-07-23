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
7. creates the host side of that mapping as a first-instance-only local named
   pipe, limits its protected DACL to the runtime principal and LocalSystem,
   verifies the live handle's owner and access entries, requires the connected
   client PID to equal the previously spawned shim PID, and negotiates the
   authenticated agent protocol with a simulated local guest;
8. enters a one-vCPU, 512 MiB utility VM, executes `/bin/sh` from a supplied
   Linux rootfs, and verifies a guest-written marker through virtiofs;
9. boots `/usr/bin/a3s-oci-agent`, carries its host-CID port 4093 connection
   through libkrun to the protected pipe, authenticates the exact shim PID and
   one-time token, negotiates protocol version 1, and waits for zero
   guest/shim exit;
10. emits stable JSON evidence through `a3s-oci features`,
   `a3s-oci whpx-smoke`, `a3s-oci-krun-shim context-smoke`, and
   `a3s-oci-krun-shim vm-smoke`, plus nested host/shim evidence through
   `a3s-oci agent-vm-smoke`.

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
  protected pipe without advertising unimplemented executor operations.

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

- the static musl guest agent starts from the supplied rootfs;
- guest AF_VSOCK reaches the protected Windows named pipe through libkrun;
- only the exact spawned shim PID is accepted before the token is sent;
- the real guest authenticates the one-time token and negotiates protocol
  version 1;
- the agent version and `x86_64` guest architecture are reported;
- the negotiation-only guest advertises no OCI executor operations;
- the shim reports every VM configuration stage and a zero guest exit;
- the host rejects an existing console destination rather than overwriting
  it.

The July 24, 2026 qualification used the untouched Alpine 3.22.5 x86_64
minirootfs archive with SHA-256
`4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282`.
The fixed runtime completed five consecutive marker runs without setting
`LIBKRUN_WINDOWS_HYPERV_ENLIGHTENMENTS`.

The end-to-end bridge qualification used the 5,824,440-byte static musl agent
with SHA-256
`b1e4cf22b0e9483b97f07f2f9063df950dbbf0ccdd4c10624e76ee61cbbbebb3`.
Its host report selected protocol version 1, identified the guest as
`x86_64`, retained the complete successful shim report, and returned exit
status zero.

The libkrun dependency is target-specific to the isolated shim. The main
runtime, CLI, and SDK dependency graphs do not contain it, and the Linux target
does not build it.

The smokes do not prove that:

- the pinned immutable A3S system image boots;
- networking or complete process I/O works;
- OCI create/start ordering is implemented;
- one or multiple Linux containers can execute;
- the driver is production ready.

For that reason, driver readiness remains `probe-only` even after both smokes
succeed. Driver resolution must reject `probe-only` readiness rather than
silently treating host capability as runtime support.

## Next Windows gate

The next vertical slice must:

1. boot a version-pinned A3S system image;
2. mount one protected runtime-owned root through virtio-fs;
3. implement the guest Linux executor;
4. execute a fixed local Alpine OCI bundle with an exact create/start barrier;
5. return stdout, stderr, and the natural exit code;
6. reconcile stopped state after host runtime restart;
7. leave no process, handle, endpoint, or temporary state after delete.

Only completion of that gate may promote Windows driver readiness to
`experimental`.
