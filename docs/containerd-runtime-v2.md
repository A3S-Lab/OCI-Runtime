# containerd Runtime V2

## Current support matrix

The shim is a development adapter. It does not make any runtime driver
`supported` and it is not yet a signed release artifact.

| containerd | Host | Runtime profile | Status | Retained gate |
| --- | --- | --- | --- | --- |
| 2.2.2 | Ubuntu arm64 | Native Linux, `shared-host-kernel` | Development-qualified | Real lifecycle, exec, FIFO/PTY I/O, controls, daemon restart, live shim replacement with exact output continuation, in-flight Create plus four-state shim `SIGKILL`, identity replacement, and four-task parallel cleanup |
| 2.0, 2.1, other 2.2 releases | Linux | Any | Not yet qualified | Compatibility record pending |
| 1.7 and earlier | Linux | Any | Not qualified | No compatibility claim |
| Any | Utility-VM profile | `dedicated-vm` | Not yet qualified through containerd | Driver-specific gate pending |

The implementation may interoperate with an unlisted release because the
runtime-v2 contract is stable. That is not a support claim. Add a release to
the table only after the same ignored real-host qualification passes against
the packaged shim, SDK, host service, agent, and selected driver.

## Runtime type and package layout

The containerd runtime type is:

```text
io.containerd.a3s-oci.v2
```

containerd resolves that type to this executable name:

```text
containerd-shim-a3s-oci-v2
```

The binary must be root-owned, executable, and visible in the containerd
daemon's `PATH`. The qualified development host currently uses
`/usr/local/bin/containerd-shim-a3s-oci-v2`. No containerd plugin block is
required when standard runtime-v2 binary discovery is available; callers can
select it with `--runtime io.containerd.a3s-oci.v2`.

The shim does not execute a driver directly. It connects to the long-lived
A3S OCI host service through the SDK endpoint. The default Unix socket is:

```text
/run/a3s-oci/runtime.sock
```

`A3S_OCI_RUNTIME_ENDPOINT` overrides that path. The legacy
`A3S_OCI_RUNTIME_SOCKET` name is accepted only as a fallback. The host service,
static agent, and their immutable assets are separate package entries; the
runtime socket and containerd task bundles are runtime state and must not be
shipped in a package.

The final release layout and checksums remain open. A release is not qualified
until it records at least the containerd version, shim checksum, OCI Runtime
commit, Cargo lock digest, SDK protocol, agent protocol, driver, kernel, and
host architecture.

## Identity mapping

containerd and the SDK keep separate identity domains:

| Input | A3S identity |
| --- | --- |
| containerd namespace + task ID | `ctrd-` plus a length-framed SHA-256 digest; stable and bounded |
| New containerd task incarnation | Random 32-byte value stored as 64 lowercase hexadecimal characters in the shim bundle |
| Runtime create | Monotonic runtime generation returned by the host service |
| namespace + task ID + exec ID | `exec-` plus a length-framed SHA-256 digest |
| Mutation | `ctrd-op-` plus namespace, task ID, incarnation, optional exec ID, and action digest |

Recreating the same namespace and task ID intentionally keeps the derived SDK
container ID while allocating a new incarnation and runtime generation. The
new incarnation prevents a replay from the deleted task from matching a new
mutation. Every live request carries the exact runtime generation.

The shim stores its incarnation and generation-bound metadata in the
containerd-owned task bundle. Rehydration verifies namespace, task ID,
generation, driver, and isolation against the host service and fails closed on
any drift. Metadata schema v2 also records the last init and exec output cursor
only after the corresponding FIFO write succeeds. A schema-v1 record remains
readable, defaults both cursor classes to zero, and is rewritten as schema v2
on the next metadata commit.

Before dispatching Create, the shim separately commits a schema-v1 create
intent containing the exact incarnation, isolation request, bundle, I/O shape,
and rootfs ownership. If the shim dies before it can record the returned
generation, DeleteShim replays the same digest-bound Create with the same
operation identity. The runtime either joins the request still in progress or
returns its completed result, after which DeleteShim kills and force-deletes
that exact generation. It never guesses a current generation from the stable
container ID.

## API mapping

The adapter uses the public `a3s-oci-sdk`; it does not call A3S Box or import a
driver implementation.

| containerd Tasks operation | SDK/runtime action |
| --- | --- |
| Create | Validate the OCI bundle and typed create options, mount the supplied rootfs, then `create` |
| Start | `start` for init or the exact exec process |
| Get | Exact-generation `state` or `process` plus durable exit evidence |
| Wait | `wait` or `wait_process` |
| Kill | `kill` for init, `signal_process` for exec |
| Delete / DeleteProcess | Stopped lifecycle `delete` or exec metadata removal |
| Exec | Decode the OCI `Process`, reserve its identity, then `exec` on Start |
| ResizePty | Exact-process `resize` |
| CloseIO | Drain the FIFO and call `close_stdin` once |
| Pause / Resume | `pause` / `resume` |
| Update | Decode OCI `LinuxResources`, then `update` |
| ListPids | Exact-generation `processes` |
| Metrics | `stats`, encoded as containerd cgroup-v2 metrics |
| Connect / Shutdown | Shim process coordination; no second lifecycle state |
| Checkpoint | Unimplemented; checkpoint/restore remains an optional future extension |

Create without A3S options selects `shared-host-kernel`. The versioned
`dev.a3s.oci.runtime.v1.CreateOptions` payload can request
`shared-host-kernel` or `dedicated-vm`. `shared-guest-kernel`, unknown fields,
unknown versions, and foreign option types fail closed. The dedicated-VM route
is not containerd-qualified yet.

## Restart and cleanup contract

The real gate restarts containerd while init is Created, Running, and Stopped;
while an exec is Added, Running, and Stopped; while a terminal exec is Running;
and while four independent tasks are Running. PID, terminal mode, exit status,
incarnation, and runtime generation must not drift.

The gate also suspends containerd, kills the live shim, starts a replacement
shim from the same bundle and socket, kills the suspended daemon, and restarts
containerd. A live terminal exec must retain its workload PID, incarnation,
runtime generation, and replacement shim PID. Output delivered before the
replacement must not replay, and a resize issued after replacement must
produce only its new terminal dimensions.

containerd 2.2 treats an already-stopped shim as leaked during some daemon
recovery paths. In that case it invokes DeleteShim. The shim replays durable
exit evidence, removes only the exact runtime generation and bundle, and
leaves caller-owned container metadata removable.

If the shim itself receives `SIGKILL` while init is Created or Running, or
while an exec is Added or Running, containerd's leak handler must terminate the
exact workload, force-delete its runtime generation, and remove the task
bundle. It must retain the container metadata. Recreating the same task ID must
produce a new incarnation and generation. Starting a standalone shim while
containerd's event endpoint is unavailable is not a supported recovery path;
the safe outcome is complete cleanup rather than an untracked live workload.

The same gate kills the shim while Create is in flight after its durable intent
commit but before the RPC returns. The host service is suspended at that exact
boundary and resumed only after the shim dies. Cleanup must converge the
original operation, delete its one resulting generation, and leave no runtime
state, task, workload process, bundle, or shim while preserving caller-owned
container metadata.

## Run the real qualification

The test is ignored because it is destructive: it requires root, restarts
containerd repeatedly, sends `SIGKILL`, and creates temporary tasks and
containers with an `a3s-r7-` prefix.

```bash
cargo test -p a3s-oci-containerd-shim \
  --test containerd_runtime_v2 \
  --no-run

sudo env \
  A3S_OCI_CONTAINERD_QUALIFY=1 \
  A3S_OCI_CONTAINERD_ALLOW_RESTART=1 \
  ./target/debug/deps/containerd_runtime_v2-<hash> \
  --ignored --exact real_containerd_runtime_v2_qualification --nocapture
```

The host service must already be running and the selected shim binary must be
installed where containerd can resolve it. Cleanup is prefix-scoped and the
test fails if any matching task or container remains.

## Open release gates

- qualify the supported containerd version range from exact release packages;
- publish signed or checksummed shim, host-service, agent, and driver assets;
- retain a machine-readable compatibility record;
- extend forced cleanup from the qualified in-flight Create boundary to every
  remaining lifecycle and process-I/O mutation boundary;
- run the same suite for every driver profile advertised through containerd;
- complete OCI conformance, security review, upgrade/rollback, and release
  soak gates.
