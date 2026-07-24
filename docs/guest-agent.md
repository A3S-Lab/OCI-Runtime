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

- only `ociVersion`, `root`, `process`, optional `hostname`, optional
  `domainname`, optional `mounts`, and optional `linux` at the configuration
  root;
- a writable normalized relative `root.path` equal to `rootfs`;
- `terminal: false` and null stdin, stdout, and stderr;
- `noNewPrivileges: true`;
- an absolute executable and working directory;
- numeric UID, GID, optional supplementary groups, and optional umask;
- bounded arguments and environment with unique environment names.

When `linux.namespaces` is present, it accepts only unique, newly created UTS,
mount, IPC, network, and cgroup namespace entries, in any order, with no join
paths. Omitting a namespace inherits the runtime namespace of that type.
Configured hostname and domainname values are bounded to the Linux kernel
limit and require the new UTS namespace.

The wrapper creates all requested UTS, mount, IPC, network, and cgroup
namespaces atomically in one `unshare` call. It applies and reads back hostname
and domainname with `uname`. When a mount namespace is requested, it then makes
`/` recursively private, recursively bind-mounts the rootfs onto itself,
applies every configured mount in listed order, and uses
`pivot_root(".", ".")` followed by a detached unmount of the old root. All of
this succeeds before readiness is reported, so namespace, mount, and rootfs
isolation are part of the create barrier. When a mount namespace is omitted,
the wrapper preserves the inherited namespace and uses the compatible
`chroot` path after start; mount entries are rejected on that path to prevent
changes from escaping into the agent's runtime mount namespace.

The current mount slice:

- requires each destination to exist and resolve strictly inside the rootfs;
- interprets relative destinations from `/` and relative bind sources from the
  bundle directory;
- supports bind/rbind, common mount flags, all required propagation modes, and
  bounded filesystem-specific option data;
- remounts bind attributes explicitly and fails the complete create operation
  on any syscall error;
- rejects root replacement, missing bind sources, multiple propagation modes,
  comma-packed options, idmapped mounts, recursive mount attributes,
  `tmpcopyup`, and mount moves instead of silently ignoring them.

Create snapshots the exact digest-bound configuration, starts an internal init
wrapper, and waits on a randomly named Linux abstract Unix socket. The parent
accepts only the exact kernel-reported child PID. The wrapper revalidates the
bundle, resolves a contained rootfs, and returns either a bounded typed error
or readiness before blocking. Create therefore preserves the exact rejection
or returns `created` before the configured process runs. Start sends the
one-byte release signal; the wrapper applies the inherited-namespace `chroot`
when needed, then working directory, groups, GID, UID, umask, and
`PR_SET_NO_NEW_PRIVS`, and calls `execve`.

State observes the init process, kill delivers one positive Linux signal, and
delete supports stopped-only and force cleanup. Exact request retries are
fingerprinted by `OperationId`, and reused IDs with different requests fail.
Generation fences remain in memory after delete.

All guest registry, generation, and idempotency state is session-local. A
closed host connection force-stops remaining init processes and removes the
agent-owned runtime root. Agent restart recovery is not implemented yet.

The executor currently rejects mount-target creation, rootfs propagation
overrides, idmapped and recursive-attribute mounts, every namespace type other
than UTS, mount, IPC, network, and cgroup, all namespace joins, cgroup
resources, capabilities, seccomp, hooks, read-only rootfs, terminals, non-null
I/O, process-group signals, and every other unimplemented OCI property. These
are release blockers, not silently accepted compatibility gaps.

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
observation, exact create/kill/delete replay, signal-driven stop, post-delete
NotFound, marker cleanup, and nominal guest runtime cleanup.

The July 24, 2026 qualification used an untouched Alpine 3.22.5 x86-64
minirootfs and the 6,328,408-byte static agent with SHA-256
`4b21a230d4183abe053823a63893f5ab0663c118811c81229bdfba0816fc9b81`.
The positive bundle requested new UTS, mount, IPC, network, and cgroup
namespaces, then ordered a relative-source rbind, a nested proc mount made
possible by that bind, and a relative-destination tmpfs. The workload verified
both filesystem types and proved that its IPC, network, and cgroup namespace
identities differed from guest PID 1 before producing its marker. A
joined-network negative bundle retained its typed `Unsupported` error and left
no guest runtime state. This proves the fixed bootstrap slice, not the
immutable A3S system image, complete OCI enforcement, process I/O, configured
networking, restart recovery, or fault-injected cleanup. The WHPX driver
therefore remains `probe-only`.
