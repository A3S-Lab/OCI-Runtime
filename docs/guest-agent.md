# Guest Agent Bootstrap

`a3s-oci-agent` is the Linux process behind utility-VM execution. It shares
the versioned protocol with the Windows, Linux, and macOS host drivers and
does not link libkrun.

## Bootstrap Contract

The host must:

1. generate an `AgentVsockEndpoint` and `SessionToken` from the operating
   system random source;
2. bind the protected host transport before starting the VM;
3. provision the token through the protected
   `A3S_OCI_AGENT_SESSION_TOKEN` environment entry;
4. execute `/usr/bin/a3s-oci-agent` as the fixed guest process.

At startup the agent removes the environment entry, retains the encoded input
in zeroizing memory only while decoding it, and connects to host CID 2 port
4093 through Linux AF_VSOCK. Connection attempts are individually bounded and
the complete retry window is bounded. The accepted protocol token is zeroized
when its last Rust owner is dropped.

The host must verify that the Windows named-pipe client PID is the previously
spawned libkrun shim before it sends the token over the protocol stream.

## Current Capability

The current binary deliberately advertises an empty operation set. It can
authenticate and negotiate protocol version 1, but every OCI lifecycle method
is unsupported. This is the correct evidence boundary until the shared Linux
executor implements and tests those operations.

Build the static x86-64 Linux artifact from Windows with:

```powershell
cargo zigbuild -p a3s-oci-agent --release `
  --target x86_64-unknown-linux-musl
```

The Windows `a3s-oci agent-vm-smoke` command now boots this artifact from a
supplied Linux rootfs and proves the real
guest-AF_VSOCK/libkrun/Windows-named-pipe path. The host binds first, starts
the isolated shim, verifies the connected shim PID, sends the token, validates
protocol-v1 negotiation, closes the connection, waits for zero guest/shim
exit, and retains the bounded shim report.

The July 24, 2026 qualification used an untouched Alpine 3.22.5 x86-64
minirootfs plus the static agent at `/usr/bin/a3s-oci-agent`. This proves
bootstrap and transport, not the immutable A3S system image, OCI lifecycle
execution, complete process I/O, networking, recovery, or cleanup under fault
injection. The WHPX driver therefore remains `probe-only`.
