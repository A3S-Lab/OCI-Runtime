# containerd Runtime V2

## Current support matrix

The shim is a development adapter. It does not make any runtime driver
`supported` and it is not yet a signed release artifact.

| containerd | Host | Runtime profile | Status | Retained gate |
| --- | --- | --- | --- | --- |
| 2.2.2 | Ubuntu arm64 | Native Linux, `shared-host-kernel` | Development-qualified | Real lifecycle, exec, FIFO/PTY I/O, repeated controls, daemon restart, live shim replacement with exact input and output continuation, in-flight Create, committed Start/Kill/Delete/Exec/SignalProcess/Pause/Resume/Update/WriteStdin/CloseStdin, four-state shim `SIGKILL`, identity replacement, and four-task parallel cleanup |
| 2.0, 2.1, other 2.2 releases | Linux | Any | Not yet qualified | Compatibility record pending |
| 1.7 and earlier | Linux | Any | Not qualified | No compatibility claim |
| Any | Utility-VM profile | `dedicated-vm` | Not yet qualified through containerd | Driver-specific gate pending |

The implementation may interoperate with an unlisted release because the
runtime-v2 contract is stable. That is not a support claim. Add a release to
the table only after the same ignored real-host qualification passes against
the packaged shim, SDK, host service, agent, and selected driver.

The August 14, 2026 arm64 requalification used containerd 2.2.2 and the
release-built shim SHA-256
`856913e536c231449dd5423b0810306c7402dbeaae78f1aede6bb34e28a0575d`.
The host CLI, agent, and qualification executable SHA-256 values were
`9dfccc7e6a25593755a0c300bb3a8b4d5678919fcc2656bb8827e01652e34103`,
`0d368fe1727d34da0ed25bf4e0f845a4462825240066a7d6aff12ba4a480dbb4`,
and `d79a57091f4fd0c422fc9f2e4c18fc793cf3ab864fd7e48d7c3b12a12afaf0bc`.
The 42.31-second matrix passed two distinct resource updates, two complete
pause/resume cycles, durable terminal stdin before and after live shim
replacement, replay of a remotely committed write whose exact payload was
still locally pending, replay of a remotely committed CloseStdin while the
shim still recorded Closing, every retained restart and shim-crash boundary,
and its post-run audit with no task, container, shim, bundle, active runtime
container, workload process, or workload cgroup member left behind.

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
any drift. Metadata schema v5 records the last completed init and exec stdin
sequence, an optional in-flight sequence plus its exact bounded payload, the
Open, Closing, or Closed state of each stdin stream, and the last output cursor
only after the corresponding FIFO write succeeds. It
also records the last completed per-task control sequence, an optional
in-flight Pause, Resume, or Update, and the last completed Update request
digest. Schema-v1 records default input sequences, output cursors, and control
state to empty. Schema-v2 records preserve output cursors, schema-v3 adds the
control journal, and schema-v4 adds sequenced writes. Schemas v1 through v4
default stdin close state to Open and are rewritten as schema v5 on the next
metadata commit.

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

Pause, Resume, and Update share one monotonically increasing per-task control
sequence. Their SDK operation identities include that sequence, so a later
pause cycle or resource update cannot replay an earlier result. A task-scoped
async gate serializes concurrent control requests without blocking controls
for another task. Before dispatch, the shim durably records the sequence and
operation kind; Update also records a canonical JSON SHA-256 fingerprint whose
object ordering is stable after a shim or host-process restart. Retryable
errors retain that pending identity, terminal errors close it, and a completed
request commits the returned runtime record and sequence atomically. An
identical completed retry is answered without a second SDK dispatch.
The host Runtime writes canonical fingerprints as durable operation schema v2
while continuing to load and validate schema-v1 journals with their original
encoding.

Init and exec stdin use separate durable sequences. Before each FIFO chunk is
sent, the shim stores the next sequence and exact bytes; it clears that pending
entry only after the Runtime accepts the matching SDK operation. A replacement
shim first replays any pending entry with the same `OperationId` and payload,
then continues at the next sequence. Reusing a sequence with different bytes,
skipping a sequence, attaching journal state to a process without stdin, or
loading an oversized pending payload fails closed. The retained arm64 gate
proves that a live terminal exec receives input before and after manual shim
replacement without duplicating the first remote effect. It also freezes the
original shim after the next exact payload is durable but before dispatch can
finish, commits that same operation through the Runtime, and replaces the shim
while its journal still records the payload as pending. The replacement must
join the completed operation, emit the input effect exactly once, clear the
pending entry, and continue from the following sequence.

CloseStdin uses a separate durable state machine. The shim commits Closing only
after every FIFO byte and pending write has completed, then dispatches the
stable process-scoped `close-stdin` operation. A successful response commits
Closed. A replacement that loads Closing replays that exact operation without
opening the FIFO and commits Closed; a replacement that loads Closed returns a
completed CloseIO result without opening the FIFO or dispatching another SDK
operation. The retained arm64 gate freezes the original shim in Closing,
commits the Runtime effect while its response cannot be observed, replaces the
shim, and requires one terminal EOF marker plus a successful repeated CloseIO.

## Restart and cleanup contract

The real gate restarts containerd while init is Created, Running, and Stopped;
while an exec is Added, Running, and Stopped; while a terminal exec is Running;
and while four independent tasks are Running. PID, terminal mode, exit status,
incarnation, and runtime generation must not drift.

The gate also suspends containerd, kills the live shim, starts a replacement
shim from the same bundle and socket, kills the suspended daemon, and restarts
containerd. A live terminal exec must retain its workload PID, incarnation,
runtime generation, replacement shim PID, completed stdin sequence, and output
cursor. Output delivered before the replacement must not replay; new stdin
must use the next durable operation identity and reach the original PTY; and a
resize issued after replacement must produce only its new terminal dimensions.

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

The post-commit Start gate submits the shim's exact stable Start identity while
durable shim metadata still records Created, then kills the shim after the
runtime reports that generation Running. DeleteShim must bound its kill/wait
path, force-delete only that generation, and leave no process, runtime state,
bundle, or shim while preserving containerd-owned metadata.

The post-commit Exec gate records the process as Added in shim metadata, then
submits the exact stable Runtime Exec and verifies its generation-scoped
process identity and live PID before killing the shim. DeleteShim must reap
both the init and unrecorded exec PIDs and remove only that runtime generation,
task bundle, and shim while preserving containerd-owned metadata.

The post-commit SignalProcess gate starts an exec, suspends the shim, then
submits the exact stable exec-scoped SIGKILL mutation directly to the runtime.
It requires the exact signal-9 exit while the init remains Running with its
original PID before killing the stopped shim. DeleteShim must then remove the
terminal exec, live init, exact generation, task bundle, and shim without
touching containerd-owned metadata.

The post-commit Kill gate submits the exact stable SIGSTOP mutation to a
running generation, verifies that the runtime retains the same live PID, and
kills the shim before local state observes that mutation. DeleteShim must send
the terminal signal, bound its wait, reap that exact PID, and remove the exact
generation without touching containerd-owned metadata.

The committed control gates repeat the same lost-response boundary for Pause,
Resume, and Update. They verify the real freezer state and the exact `pids.max`
read-back before killing the shim, then require bounded deletion of the same
generation with no process, cgroup, bundle, or shim residue. DeleteShim sends
an exact force Delete directly for a paused generation instead of waiting on a
terminal signal that a frozen process cannot complete; the runtime thaws and
stops that generation inside the one deletion operation.

The post-commit Delete gate stops the task, submits the shim's exact stable
StoppedOnly Delete identity directly to the runtime, and kills the shim while
its durable local metadata and rootfs ownership still exist. DeleteShim must
accept `NotFound` only for that exact generation and only after its stable
normal or force Delete identity replays a committed deletion. It then finishes
local cleanup and preserves containerd-owned container metadata. Missing
replay evidence and generation conflicts remain hard failures, so state loss or
a replacement can never be mistaken for the deleted task.

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
- extend forced cleanup from the qualified in-flight Create and post-commit
  Start/Kill/Delete/Exec/SignalProcess/Pause/Resume/Update boundaries to every
  remaining lifecycle and process-I/O mutation boundary;
- run the same suite for every driver profile advertised through containerd;
- complete OCI conformance, security review, upgrade/rollback, and release
  soak gates.
