# Feature coverage

This inventory records what the runtime implements and which evidence layer
covers it. It is not a line-coverage percentage, and it is not a release
conformance claim.

The checked-in OCI 1.3.0 locks classify every named schema item and every RFC
2119 occurrence. Classification is not promotion. The schema lock has zero
`conformant` items. No built-in driver is `supported`. Existing-host greens
never set `promotes_readiness=true`.

Coverage layers used below:

| Layer | Meaning |
| --- | --- |
| Lock | A reviewed requirement, rule, and test binding exists |
| CI | Workspace tests or a fail-closed hardware step run in CI |
| Existing host | A real host produced an observation. It does not promote readiness |
| Open | Required release evidence is missing |

The latest published workspace archive is
[`v0.3.6`](https://github.com/A3S-Lab/OCI-Runtime/releases/tag/v0.3.6).
It does not promote readiness. Fresh-host matrices check out current `main`.

## Public operations

Guest protocol v10 is 20 workload operations plus one maintenance
acknowledgement. The portable reopen matrix is 20 operations by 9 stages
(180 paths) and is wired in unit tests. Live completeness depends on the
driver table below.

`features`, `list`, and `events` are query operations outside those 20.
`checkpoint`, `restore`, and `attest` exist in the SDK and are not advertised
by production drivers.

| Operation | Coverage | Open |
| --- | --- | --- |
| `features` | Lock + CI. Linux Features 41/41 enforced | Not a conformance declaration |
| `create` / `start` / `state` / `kill` / `delete` / `wait` | Lock + CI, including Native Linux real containers | CLI rejects terminals, `--console-socket`, and nonzero `LISTEN_FDS`. Upstream Runtime Tools `start` and `pidfile` stay classified under two audited harness defects |
| `list` / `events` | Lock + CI | Not `conformant` |
| `exec` / `signal-process` / `wait-process` / `processes` | Lock + CI, including the 180-path matrix | Live I/O reattach after owner death remains open |
| `pause` / `resume` | Lock + CI. Native soak replays operation IDs | Not a per-driver release qualification |
| `update` / `stats` | Lock + Native Linux read-back | Broader rootless delegation remains incomplete |
| `read-output` / `write-stdin` / `close-stdin` / `resize` | Lock + CI. Selected containerd matrices are observations | Not release evidence for every driver |
| `file` / `filesystem` | Lock. HVF retains 9/9 replacement paths each | Other utility-VM drivers lack that live qualification |
| `checkpoint` / `restore` | Contract and unit tests. Default drivers fail closed | Only a rootful Native Linux CRIU constructor has an existing-host observation |
| `attest` | Contract and unit tests | No production SEV-SNP/TDX driver |

## Shared Linux executor

Native Linux, HVF, WHPX, and KVM share this executor. Linux configuration
requirements are owner-bound (206 enforced, 9 validated, 3 conformant of 218).
All 41 `features-linux.md` requirements are enforced.

| Capability | Coverage | Open |
| --- | --- | --- |
| Namespace, mount, rootfs, devices, seccomp, capabilities, hooks, cgroup v2 | Lock + Native Linux CI read-back on x86_64 and aarch64 | Hook adversarial soak, broader join hardening, and rootless device profiles remain open |
| HugeTLB / RDMA | Lock. CI reads back only when the runner exposes the controller | Absent hardware is not a pass |
| Intel RDT | Lock + unit tests. Features may advertise it | No CAT/MBA host qualification |
| Namespaced sysctl, NUMA memory policy, `linux.netDevices` | Lock + Native Linux evidence when configured | Rootless network-device moves are rejected before mutation |
| Caller-supplied VM launch configuration | Fail-closed before durable mutation | Current drivers do not execute it |
| AppArmor, SELinux, cgroup v1 realtime, `net_cls` / `net_prio` | Rejected and not advertised | Not missing implementation |
| Native FreeBSD, Solaris, Windows, and z/OS containers | Rejected as inapplicable | Not a workload this runtime runs |

## Drivers and adapters

| Surface | Readiness | Coverage | Open |
| --- | --- | --- | --- |
| Native Linux x86_64 / aarch64 | Default `probe-only`. Explicit development open is `experimental` | CI real containers, rootless, hooks, and soak without `/dev/kvm` | Live session reattach, default cutover, production security, and OCI conformance |
| macOS HVF | `experimental` | Recorded revision: 20 driver operations plus `features` / `list` / `events`, 180/180 replacement paths, 25/25 fresh-VM soak | Signed package, OCI conformance, security review, upgrade/rollback, and longer soak |
| Windows WHPX | `probe-only` | Existing-host 180/180, 25/25 soak, and handle reclamation. Does not promote | Fresh-host attestation-bound matrix |
| Linux KVM | `probe-only`. Public candidate is not registered | CI fail-closed without KVM. Existing x86_64 host retained 180/180 and 25/25. Does not promote | Fresh x86_64 and fresh AArch64 attestation-bound matrices |
| CLI | Short-process adapter | Unix and Windows IPC lifecycle tests | No terminal bundle, console socket, or `LISTEN_FDS` |
| containerd runtime-v2 | Adapter implemented. Not production-ready | Unit tests plus dated live observations | Cross-driver and signed-package qualification. Production drivers do not advertise Checkpoint |
| Attachments v1–v4 | SDK contract | Unit tests | Production HVF/KVM/WHPX registrations advertise only qualified profiles |
| A3S Box consumer | Public SDK only | Box CI on Native Linux with `/dev/kvm` absent | Default and cross-platform cutover remain open. A finished consumer is not runtime completion |
| W4 Box cutover | Not started | None that can close the gate | Must not land before the fresh-host matrices |
