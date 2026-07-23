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

The build alone does not prove WHPX transport. Promotion requires booting the
artifact from the pinned guest image, completing negotiation through the real
guest-vsock/libkrun/named-pipe path, and retaining host and guest cleanup
evidence.
