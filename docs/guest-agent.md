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
`create`, `state`, `start`, `kill`, `delete`, and `wait`. It is intentionally
narrower than the final OCI executor and rejects every property it cannot
enforce.

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

When `linux.namespaces` is present, it accepts unique, newly created UTS,
mount, IPC, network, cgroup, PID, user, and time namespace entries in any
order, with no join paths. Omitting a namespace inherits the runtime namespace
of that type. Configured hostname and domainname values are bounded to the
Linux kernel limit and require the new UTS namespace.

The user-namespace profile is deliberately rootful. A new user namespace
requires both `uidMappings` and `gidMappings`, each list is bounded to the
kernel's 340-entry limit, and the process UID, GID, and every supplementary GID
must be covered. The wrapper creates the user namespace first, then blocks on
the authenticated control channel while the parent verifies the distinct
namespace, writes each `/proc/<pid>/{uid,gid}_map` exactly once, reads both
maps back, and requires `/proc/<pid>/setgroups` to remain `allow`. Rootless
`setgroups=deny` and subordinate-ID helper flows are not implemented.

The wrapper then requests the configured UTS, mount, IPC, network, cgroup, PID,
and time namespaces in one `unshare` call. Time offsets accept only normalized
`monotonic` and `boottime` values; the wrapper writes and reads them back
through `/proc/self/timens_offsets` before forking. A new PID or time namespace
applies to the caller's next child, so the wrapper remains as a supervisor and
forks the container init. With PID isolation that child is namespace PID 1.
The child applies and reads back hostname and domainname with `uname`. When a
mount namespace is requested, it then makes `/` recursively private,
recursively bind-mounts the rootfs onto itself, applies every configured mount
in listed order, and uses
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
accepts only the exact kernel-reported supervisor PID. The wrapper revalidates
the bundle, resolves a contained rootfs, and returns either a bounded typed
error or readiness with the runtime-visible init PID before blocking. The
authenticated parent permits exactly one expected user-mapping request. It
rejects readiness that bypasses that request, a repeated request, or a request
without a configured user namespace. For a new PID namespace, the agent
verifies the reported PID's parent, `NSpid` mapping to 1, and namespace
identity against the supervisor. It also verifies new user and time namespace
identities against the authenticated supervisor's intended namespace links.
Create therefore preserves the exact rejection or returns `created` before the
configured process runs. Before returning `created`, the executor opens a
pidfd for that authenticated init PID. Failure to open the descriptor
terminates the wrapper and fails create. Start sends the one-byte release
signal; the init applies the inherited-namespace `chroot` when needed, then
working directory, groups, GID, UID, umask, and `PR_SET_NO_NEW_PRIVS`, and
calls `execve`.

State observes the init process, kill delivers one positive Linux signal
through the retained pidfd, and delete supports stopped-only and force
cleanup. Cleanup also signals through the pidfd and always reaps the
authenticated wrapper before removing its runtime directory. Numeric PID
reuse can therefore never redirect a lifecycle signal to an unrelated
process.

The PID-namespace supervisor preserves the configured namespace-PID-1
process's terminal outcome: it exits with the same normal code or resets,
unblocks, and re-raises the same terminating signal. The executor converts
that raw Linux status into exactly one SDK exit code or signal, caches it per
generation, and returns it from every repeated init wait. A bounded wait
returns `DeadlineExceeded` while the process is still running, and the
executor releases its registry lock between observations so another
container remains independently queryable.

Exact request retries are fingerprinted by `OperationId`, and reused IDs with
different requests fail. Generation fences remain in memory after delete.

All guest registry, generation, and idempotency state is session-local. A
closed host connection force-stops remaining init processes and removes the
agent-owned runtime root. Agent restart recovery is not implemented yet.

The executor requires both `pidfd_open` and `pidfd_send_signal`. It currently
rejects mount-target creation, rootfs propagation overrides, idmapped and
recursive-attribute mounts, all namespace joins, rootless user-mapping policy,
cgroup resources, capabilities, seccomp, hooks, read-only rootfs, terminals,
non-null I/O, process-group signals, and every other unimplemented OCI
property. These are release blockers, not silently accepted compatibility
gaps.

## Build And Evidence

Build the static x86-64 Linux artifact from Windows with:

```powershell
cargo zigbuild -p a3s-oci-agent --release `
  --target x86_64-unknown-linux-musl
```

`a3s-oci agent-vm-smoke` proves the authenticated
guest-AF_VSOCK/libkrun/Windows-named-pipe path and verifies the exact
six-operation advertisement. `a3s-oci oci-vm-smoke` additionally loads a bundle
below the VM rootfs and proves the distinct create/start barrier, state
observation, exact create/kill/delete replay, bounded running wait, exact
repeated terminal status, signal-driven stop, post-delete NotFound, marker
cleanup, and nominal guest runtime cleanup.

`a3s-oci oci-vm-multi-container-smoke` keeps two distinct bundle rootfs and
runtime slots live behind the create barrier, proves that A's start, kill,
wait, delete, recreation, stale generation, and replay conflicts do not alter
or block B, then completes B independently. The macOS HVF gate sends both init
signals through distinct retained pidfds and retains both exact repeated exit
statuses and per-container markers together with guest-runtime and
host-process cleanup evidence.

`a3s-oci oci-vm-fault-cleanup` stops after create, start, or kill, explicitly
records that delete was not attempted, and requires guest executor shutdown to
remove the container process and runtime root. On macOS the nested report also
requires exact endpoint removal, both host PIDs to disappear, and the complete
descriptor inventory to return to its baseline.

The macOS path uses the same static agent, fixed fixture, protocol, and
lifecycle harness over the PID-verified Unix/vsock bridge. Only the host
endpoint and libkrun hypervisor backend differ.

The current native Linux and macOS lifecycle fixtures request all eight Linux
namespace types. Their workload markers are written only after `/proc` proves
the exact UID/GID maps and the configured monotonic and boottime offsets.
Multi-container and no-delete cleanup gates reuse the same fixture. The
retained WHPX qualification below predates this user/time requalification and
does not count as Windows evidence for the new slice.

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
networking, restart recovery, or exhaustive durable-write fault injection. The
WHPX driver therefore remains `probe-only`.

The PID qualification used the 6,371,704-byte static agent with SHA-256
`45d27bfdfec50ddedabd1f11a143dba4c11b4f472e7d2627a686594a0c514f6d`.
The workload required shell PID 1 and a matching `/proc/1/ns/pid` identity
before producing its marker. The agent returned authenticated host-visible PID
396, and the complete create/state/start/kill/delete lifecycle and cleanup
passed through WHPX. A joined-PID companion bundle retained `Unsupported` at
`linux.namespaces[5].path` and left no guest runtime state.
