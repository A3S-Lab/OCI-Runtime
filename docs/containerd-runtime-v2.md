# containerd Runtime V2

## Current support matrix

The shim is a development adapter. It does not make any runtime driver
`supported` and it is not yet a signed release artifact.

| containerd | Host | Runtime profile | Status | Retained gate |
| --- | --- | --- | --- | --- |
| 2.2.2 | Ubuntu arm64 | Native Linux, `shared-host-kernel` | Development-qualified | Three consecutive same-Host real lifecycle matrices with guest-journal reclamation, exec, deleted exec-ID reuse, FIFO/PTY I/O, repeated controls and signals, daemon restart, live shim replacement with exact input and output continuation, in-flight Create, committed Start/Kill/Delete/Exec/SignalProcess/Pause/Resume/Update/WriteStdin/CloseStdin/ResizePty, sequenced committed SignalProcess replay, four-state shim `SIGKILL`, identity replacement, and four-task parallel cleanup |
| 2.0, 2.1, other 2.2 releases | Linux | Any | Not yet qualified | Compatibility record pending |
| 1.7 and earlier | Linux | Any | Not qualified | No compatibility claim |
| Any | Utility-VM profile | `dedicated-vm` | Not yet qualified through containerd | Driver-specific gate pending |

The implementation may interoperate with an unlisted release because the
runtime-v2 contract is stable. That is not a support claim. Add a release to
the table only after the same ignored real-host qualification passes against
the packaged shim, SDK, host service, agent, and selected driver.

Contract v1 owns this matrix in code and exposes it through the shim's version
output and RuntimeInfo annotations. The accepted ttrpc service is
`containerd.task.v2.Task`. State, Create, Start, Delete, Pids, Pause, Resume,
Kill, Exec, ResizePty, CloseIO, Update, Wait, Stats, Connect, and Shutdown are
implemented. Checkpoint is part of that API but deliberately returns
Unimplemented; Create requests containing checkpoint restore fields do the
same. The contract also freezes the OCI Features, Process, LinuxResources, and
versioned A3S CreateOptions type URLs consumed by those methods.

The August 14, 2026 arm64 requalification used containerd 2.2.2 and Linux
7.0.11. Three complete 46.92, 47.39, and 47.23-second matrices ran
consecutively through the same Host PID. The release-built shim SHA-256 was
`a0e7dce493308ebea0b4642dd81a9e489109a8b3709f2a1ede62b015cc123482`.
The Host CLI, agent, and qualification executable SHA-256 values were
`f097da3529c47a06b32271550417ed810d698a2a6e385f122771c197b7de2b67`,
`be0b13215c21a2312f8a3e8d79cc9a39ed1a4b07b539f3d557e0f4e168c3345a`,
and `90a6e92260ec121f7cddca2dbe5db167ef864cd0a405f08665d1b4c2082ccc1d`.
The Cargo lock SHA-256 was
`1b23294aa01fb3b92745ebfce02b0f6a79e6e22dc9636cb404fecb5bd073d90f`.
Every matrix ran an exec to exit 7, deleted it, reused the same containerd exec
ID, restarted containerd while the replacement was Added, and observed exit
23 from the new process. It also passed two distinct resource updates, two
complete pause/resume cycles, durable terminal stdin before and after live
shim replacement, and replay of remotely committed WriteStdin, CloseStdin,
SignalProcess, and ResizePty operations while schema-v8 metadata still held
the corresponding pending request. The replacement proved the real process
moved through `SIGSTOP→SIGCONT→SIGSTOP→SIGCONT` with four distinct identities,
suppressed an identical resize retry, and proved a real `A→B→A` PTY transition
with distinct identities. Each durable Native Linux Host outcome then released
its guest replay record, including all derived identities for chunked stdin.
An independent post-run audit reported zero tasks, containers, task bundles,
workload cgroups, runtime container records, prepared Host operations, shim
processes, and agent children; containerd remained active and the one expected
Host service remained live.

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

Tagged Linux host archives have this contract-v1 layout:

```text
a3s-oci-runtime-v<version>-linux-<architecture>/
├── a3s-oci
├── a3s-oci-agent
├── containerd-shim-a3s-oci-v2
├── README.md
├── CHANGELOG.md
├── LICENSE
└── docs/
    └── containerd-runtime-v2.md
```

The archive entry is installed at
`/usr/local/bin/containerd-shim-a3s-oci-v2`; it is not renamed or wrapped.
The release workflow includes the complete archive in `SHA256SUMS`.

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

The layout is frozen, but published-artifact qualification remains open. A
release is not qualified until it records at least the containerd version,
shim checksum, OCI Runtime commit, Cargo lock digest, SDK protocol, agent
protocol, driver, kernel, and host architecture.

## Guest replay-journal lifetime

The Native Linux executor keeps at most 4,096 completed or in-flight mutation
records so a lost Host response can replay an effect without running it twice.
The Host acknowledges Create, Start, Kill, Delete, Exec, Pause, Resume, Update,
WriteStdin, CloseStdin, Resize, and SignalProcess only after success or a
terminal failure is durably committed. It repeats the acknowledgement when a
completed Host result is replayed. Retryable failures, prepared operations,
and asynchronous unit operations that are still executing are never released.
An acknowledgement containing any pending operation fails atomically, and an
unknown identity succeeds because it is already absent.

A Host stdin request may cross the 4 MiB guest payload boundary and become
several deterministic guest operations. The Native Linux driver retains the
complete parent-to-child identity set until the Host outcome commits and then
acknowledges the whole set as one batch. A failed acknowledgement restores that
set for retry.

Native Linux releases replay records locally. Protocol-v10 utility-VM drivers
carry the same boundary through the bounded `acknowledge-operations`
maintenance request; protocol-v1 through protocol-v9 peers retain the
compatibility no-op. Host File upload and Filesystem mkdir/move/remove now use
v3 durable operation records and join this commit boundary. A lost
acknowledgement is retried from the completed Host journal without redispatching
the workload mutation.

## Identity mapping

containerd and the SDK keep separate identity domains:

| Input | A3S identity |
| --- | --- |
| containerd namespace + task ID | `ctrd-` plus a length-framed SHA-256 digest; stable and bounded |
| New containerd task incarnation | Random 32-byte value stored as 64 lowercase hexadecimal characters in the shim bundle |
| Runtime create | Monotonic runtime generation returned by the host service |
| namespace + task ID + exec ID + exec incarnation | `exec-` plus a length-framed SHA-256 digest |
| Mutation | `ctrd-op-` plus namespace, task ID, task incarnation, optional exec ID and exec incarnation, and action digest |

The named encoding is `sha256-length-framed-u64be-v1`. For each component, the
shim feeds an unsigned 64-bit big-endian byte length followed by the exact
component bytes into SHA-256, then adds the identity-domain prefix outside the
digest. Fixed compatibility vectors are:

| Input | Output |
| --- | --- |
| namespace `k8s.io`, task ID `task/a` | `ctrd-9e87b4d0ad12d991219bcd3bb40312c1e1abce101b71be36752f3b7de9550106` |
| namespace `k8s.io`, task ID `task`, exec ID `shell`, exec incarnation 1 | `exec-3e8eaef01bc980653a2a276d5b11463dc2714fbe1673bd871108180d4d6473b2` |

Generation mapping is `runtime-assigned-monotonic-exact`. Create sends the
stable derived container ID and receives a monotonic generation from the Host;
the shim stores that returned generation in its metadata. It never derives a
generation from containerd input, looks up an unqualified current generation,
or changes generation on a later task request.

Recreating the same namespace and task ID intentionally keeps the derived SDK
container ID while allocating a new incarnation and runtime generation. The
new incarnation prevents a replay from the deleted task from matching a new
mutation. Every live request carries the exact runtime generation.

Each successful containerd `Exec` allocation increments a durable per-task
sequence and assigns that value as the exec incarnation. `DeleteProcess`
removes the current exec record but retains the sequence. Reusing the same
containerd exec ID therefore produces a different SDK process identity and a
fresh set of exec-scoped mutation identities, including after shim or
containerd restart.

The shim stores its incarnation and generation-bound metadata in the
containerd-owned task bundle. Rehydration verifies namespace, task ID,
generation, driver, and isolation against the host service and fails closed on
any drift. Metadata schema v8 records the last allocated task exec sequence
and every current exec incarnation. It also retains the last completed init
and exec stdin sequence, an optional in-flight sequence plus its exact bounded
payload, the Open, Closing, or Closed state of each stdin stream, and the last
output cursor only after the corresponding FIFO write succeeds. For each
terminal process it records a separate completed resize sequence, one pending
size, and the last committed size. Init and every exec also have an independent
completed signal sequence plus one pending signal and the init-only `all`
flag. The task record stores the last completed per-task control sequence, an
optional in-flight Pause, Resume, or Update, and the last completed Update
request digest. Schema-v1 records default input sequences, output cursors, and
control state to empty. Schema-v2 records preserve output cursors, schema-v3
adds the control journal, schema-v4 adds sequenced writes, schema-v5 adds
durable stdin close state, schema-v6 adds durable terminal resize state,
schema-v7 adds durable init and exec signal state, and schema-v8 adds exec
incarnations. Schemas v1
through v4 default stdin close state to Open. Schemas v1 through v5 default
resize state to empty. Schemas v1 through v6 default signal state to empty,
and schemas v1 through v7 default exec incarnations to zero. Incarnation zero
preserves the legacy process and operation identity encoding. Every legacy
schema is rewritten as schema v8 on the next metadata commit.

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

A code-owned translation table freezes 23 exact Task and FIFO-pump routes.
Their deduplicated union is the 18 public SDK operations required by the shim,
and endpoint admission fails closed before task dispatch if any operation is
absent. RuntimeInfo publishes that union under
`dev.a3s.oci.containerd-sdk-operations`, and `--version` prints every route.
Manifest contract tests prohibit dependencies on A3S Box, the Host Runtime
implementation, the Agent, or Core internals.

Four implemented routes remain local to the shim. `Exec(stage)` validates and
durably allocates an exec incarnation without dispatching an SDK operation;
`Start(exec)` first calls `processes` and then dispatches the public SDK `exec`
operation. `Delete(exec)` removes a stopped exec incarnation locally, while
`Connect` and `Shutdown` only coordinate the shim process. `Checkpoint` is the
sole unimplemented Task method and is not part of the required SDK-operation
union.

| containerd Tasks operation | SDK/runtime action |
| --- | --- |
| Create | Validate the OCI bundle and typed create options, mount the supplied rootfs, then `create` |
| Start | `start` for init; for exec, inspect `processes` and then dispatch `exec` for the exact staged incarnation |
| State | Exact-generation `state` or process inventory plus durable exit evidence |
| Wait | `wait` or `wait_process` |
| Kill | `kill` for init, `signal_process` for exec |
| Delete / DeleteProcess | Stopped lifecycle `delete`, or durable removal of the current exec while retaining its allocation sequence |
| Exec | Decode the OCI `Process` and durably allocate a fresh incarnation; defer the SDK `exec` call until Start |
| ResizePty | Exact-process `resize` |
| CloseIO | Drain the FIFO and call `close_stdin` once |
| Pause / Resume | `pause` / `resume` |
| Update | Decode OCI `LinuxResources`, then `update` |
| Pids | Exact-generation `processes` |
| Stats | `stats`, encoded as containerd cgroup-v2 metrics |
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

Init and exec signals use independent durable sequences and process-local
serialization gates. The shim stores the next sequence, exact signal, and the
init-only `all` flag before dispatch. SDK identities are `kill-{sequence}` for
init and `signal-{sequence}` for exec, so a repeated signal after an
intervening mutation is a new operation. Retryable failures retain the pending
request; terminal failures close its sequence; replacement rehydration replays
an unsettled request with the original identity before serving new signals.
The retained arm64 gate freezes the Runtime with exec sequence 1 SIGSTOP
pending, freezes and kills the original shim after committing that exact
Runtime request, and requires the replacement to join the completed operation
without another signal effect. It then dispatches SIGCONT, SIGSTOP, and
SIGCONT as sequences 2 through 4 and reads `/proc/<pid>/status` after every
request to prove the actual workload transitions instead of journal-only
success.

Init and exec terminal resize use separate durable sequences and process-local
serialization gates. The shim stores the next sequence and exact dimensions
before dispatch. Its SDK operation identity is derived from that sequence; the
Runtime request fingerprint independently binds the process and dimensions.
This distinction is required for `A→B→A`: the second A must not reuse the first
A's cached Runtime result while the real terminal remains at B. A successful
response atomically commits the sequence and size. Retryable failures retain
the pending operation for exact replay; a confirmed process exit settles it
without leaving recovery blocked. A completed same-size request is a no-op.
The retained arm64 gate freezes the Host Runtime with sequence 3 pending,
freezes the original shim, commits the exact resize directly, kills that shim,
and requires its replacement to join the completed Runtime operation and clear
the pending record. It then proves same-size suppression and real terminal
dimensions across sequences 4 and 5 for the full `A→B→A` transition.

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

The exec-reuse gate starts `restart-exec`, observes exit 7, deletes that exec,
and adds `restart-exec` again. It restarts containerd before the second Start,
then requires a new SDK process identity and exit 23 from the replacement.
The deleted incarnation must not replay its Exec operation or publish a late
exit into the replacement.

The gate also suspends containerd, kills the live shim, starts a replacement
shim from the same bundle and socket, kills the suspended daemon, and restarts
containerd. A live terminal exec must retain its workload PID, incarnation,
runtime generation, replacement shim PID, completed stdin sequence, and output
cursor. Output delivered before the replacement must not replay; new stdin
must use the next durable operation identity and reach the original PTY; and a
resize issued after replacement must produce only its new terminal dimensions.
The committed-resize boundary repeats the replacement while ResizePty is
durably pending but already complete in the Runtime. The replacement must use
the same operation identity, avoid a second PTY effect, preserve the live PID,
and commit the exact size before serving a same-size retry or the later
`A→B→A` sequence.

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

The committed SignalProcess rehydration gate instead keeps the exec alive. It
persists sequence 1 SIGSTOP, freezes the original shim and Runtime, commits the
exact signal directly to the Runtime, then kills and replaces the shim before
the local journal can observe the response. The replacement must replay the
same operation identity, clear the pending record, retain the exec PID and
generation, and continue with fresh sequences for
`SIGCONT→SIGSTOP→SIGCONT`.

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
containers with an `a3s-r8-` prefix.

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
