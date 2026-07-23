# Guest Agent Protocol

`a3s-oci-agent-protocol` is the boundary between a utility-VM driver and the
Linux guest executor. Windows WHPX, Linux KVM, and macOS HVF use the same
messages. The crate does not expose libkrun, hypervisor, or guest details to
A3S Box.

## Version 1 Contract

Before connection, the host calls `SessionToken::generate` to obtain a
nonzero 256-bit token from the operating system's preferred random source and
provisions it to the pinned guest through a protected bootstrap channel.
Callers may also import exactly 32 bytes from an equivalent protected
bootstrap. The token is redacted from Rust debug output.

The host opens one authenticated byte stream and sends its inclusive protocol
range plus the token. The guest selects the highest common version and returns
its agent version, architecture, operation set, and frame limit. Authentication
or negotiation failure closes the stream.

A guest may advertise an empty operation set during transport-only bootstrap.
That proves negotiation without claiming an OCI executor. The client rejects
every lifecycle call not present in the negotiated operation set.

After negotiation:

- every UTF-8 JSON message has a four-byte big-endian length prefix;
- empty frames and frames over 64 MiB are rejected before payload allocation;
- every request and response carries the negotiated version and a nonzero,
  monotonically allocated request ID;
- a correlation, framing, version, target, digest, or lifecycle-barrier
  violation permanently poisons the client connection;
- guest service errors retain the stable Rust SDK error code and retryability;
- cloned clients serialize requests on one connection.

Protocol version 1 carries `create`, `state`, `start`, `kill`, and `delete`.
Every target includes a positive exact generation. Mutating guest operations
must be idempotent by `OperationId` and recoverable after agent restart.

## Bundle Preservation

Create carries:

- the exact accepted `config.json` text;
- its canonical lowercase SHA-256 digest;
- an absolute normalized Linux guest bundle path;
- the complete process I/O request.

The receiver independently applies the SDK's pinned OCI schema and semantic
validation and recomputes the digest before dispatch. Start carries the
expected digest again. The client rejects a create response other than
`created`, a start response other than `running` or `stopped`, a response for
another generation, or a changed configuration digest.

`GuestPath` is parsed using Linux syntax on every host. It rejects relative
paths, dot components, duplicate or trailing separators, backslashes, NULs,
and values over 4,096 bytes. A Windows path is never interpreted as a guest
bundle path.

## Current Evidence Boundary

In-memory duplex tests cover:

- successful negotiation and the full core lifecycle;
- wrong-token and incompatible-version rejection;
- oversized-frame rejection from the header alone;
- configuration-digest tampering;
- response correlation failure and permanent connection poisoning;
- secret redaction and guest-path normalization.

Windows tests additionally create the real host-side named-pipe endpoint,
verify its live kernel-object owner and protected DACL, reject a second owner
of the same name, generate both an unguessable endpoint nonce and the session
token from the OS, reject a connected process whose PID is not the expected
libkrun shim, and complete authenticated negotiation with a local simulated
guest. PID verification occurs before the host sends the session token. The
endpoint type and fixed port 4093 are shared with the libkrun shim.

This proves the protocol and the Windows host half of the bridge, not a guest
vsock connection or Linux executor. The Linux agent binary and CID-host
connector now build as a static musl executable, but the pinned image, real
vsock-to-pipe boot test, bundle execution, process I/O, and recovery evidence
remain required before the WHPX driver can advance beyond `probe-only`.
