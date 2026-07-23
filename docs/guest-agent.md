# Guest Agent Bootstrap

`a3s-oci-agent` is the Linux process behind utility-VM execution. It shares
one versioned protocol with the Windows, Linux, and macOS host drivers and does
not link libkrun.

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
4093 through Linux AF_VSOCK. Connection attempts and the complete retry window
are bounded. The accepted token is zeroized when its last Rust owner is
dropped.

On Windows, the host verifies that the connected named-pipe client is the
exact libkrun shim PID before it sends the token.

## Current Executor Boundary

The current root-only bootstrap executor advertises
`create`, `state`, `start`, `kill`, and `delete`. It is intentionally narrower
than the final OCI executor and rejects every property it cannot enforce.

The accepted bootstrap profile requires:

- only `ociVersion`, `root`, and `process` at the configuration root;
- a writable normalized relative `root.path` equal to `rootfs`;
- `terminal: false` and null stdin, stdout, and stderr;
- `noNewPrivileges: true`;
- an absolute executable and working directory;
- numeric UID, GID, optional supplementary groups, and optional umask;
- bounded arguments and environment with unique environment names.

Create snapshots the exact digest-bound configuration, starts an internal init
wrapper, and waits for that wrapper on a randomly named Linux abstract Unix
socket. The parent accepts only the exact kernel-reported child PID. The
wrapper reports ready and remains blocked, so create returns `created` before
the configured process runs. Start sends the one-byte release signal; the
wrapper then revalidates the bundle, resolves a contained rootfs, applies
`chroot`, working directory, groups, GID, UID, umask, and
`PR_SET_NO_NEW_PRIVS`, and calls `execve`.

State observes the init process, kill delivers one positive Linux signal, and
delete supports stopped-only and force cleanup. Exact request retries are
fingerprinted by `OperationId`, and reused IDs with different requests fail.
Generation fences remain in memory after delete.

All guest registry, generation, and idempotency state is session-local. A
closed host connection force-stops remaining init processes and removes the
agent-owned runtime root. Agent restart recovery is not implemented yet.

The executor currently rejects mounts, namespaces, cgroups, capabilities,
seccomp, hooks, read-only rootfs, terminals, non-null I/O, process-group
signals, and every other unimplemented OCI property. These are release
blockers, not silently accepted compatibility gaps.

## Build And Evidence

Build the static x86-64 Linux artifact from Windows with:

```powershell
cargo zigbuild -p a3s-oci-agent --release `
  --target x86_64-unknown-linux-musl
```

`a3s-oci agent-vm-smoke` proves the authenticated
guest-AF_VSOCK/libkrun/Windows-named-pipe path and verifies the exact core
operation advertisement. `a3s-oci oci-vm-smoke` additionally loads a bundle
below the VM rootfs and proves the distinct create/start barrier, state
observation, exact create/delete replay, post-delete NotFound, marker cleanup,
and nominal guest runtime cleanup.

The July 24, 2026 qualification used an untouched Alpine 3.22.5 x86-64
minirootfs and the 6,285,448-byte static agent with SHA-256
`7f8c3d19d0cbe3ab70abb0215bcc9bdb8ed3b9f2fba9e31e8e508dc43841ecde`.
This proves the fixed bootstrap slice, not the immutable A3S system image,
complete OCI enforcement, process I/O, networking, restart recovery, or
fault-injected cleanup. The WHPX driver therefore remains `probe-only`.
