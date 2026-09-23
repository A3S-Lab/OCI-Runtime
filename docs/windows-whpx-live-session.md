# Windows/WHPX mid-run Live session ownership

Status: **AgentVmSession wired** for durable Guest survival across Host death
(`A3S_OCI_WHPX_SESSION_OWNER=1` → `session-owner` Job Object spawn + binding
publish). Host-control named-pipe ownership / Live reattach remain **open**.
Does **not** claim Box Enterprise GA or flip `b2_process_session_recovery_closed`.

## Why this exists

Box binder gate 9 / Axis A needs mid-run Host death with retained Live stream
and filesystem reattach under packaged Box-owned WHPX. KVM already has
`A3S_OCI_KVM_SESSION_OWNER=1` plus a durable session-owner parent so Host
SIGKILL does not tear down the Guest.

WHPX today is **Host-bound**: the libkrun shim owner watchdog
(`crates/krun/src/owner_process.rs`) terminates the shim when the Host Service
PID exits. That matches stopped-only recovery (`whpx_recovery_smoke`) and is
why Created-state Host re-ensure (Box WHPX cutover gate 4) is not mid-run Live.

## Contract (target)

| Piece | Behavior |
| --- | --- |
| Env `A3S_OCI_WHPX_SESSION_OWNER=1` | Request durable session ownership |
| Default (unset) | Host-bound; Host taskkill → Guest teardown (stopped-only) |
| Durable mode | Shim owner watchdog watches a **session-owner** process that outlives Host |
| Binding | `a3s.oci.whpx-live-session-binding.v1` under the runtime share (PID + `GetProcessTimes` creation ticks for session-owner and shim; host-control + service named pipes; session token) |
| Reattach | Replacement Host authenticates binding, reconnects host-control pipe, resumes Ready without inventing exit |

## Landed in this slice

- `whpx_durable_session_owner`: env parse, `spawn_via_session_owner_helper`
  (breakaway + Job Object via `a3s-oci-krun-shim session-owner`), and
  `require_durable_spawn_ready` Ok once the helper is productized.
- `whpx_live_session_binding`: schema, publish/load/authenticate/remove, Windows
  process identity via `GetProcessTimes`.
- `a3s-oci-krun-shim session-owner` / `session-owner-probe` on Windows
  (`KILL_ON_JOB_CLOSE` Job Object).
- AgentVmSession Windows path: DurableSession omits Host `--owner-pid`, spawns
  through the helper, publishes binding after hello. First Host still binds the
  product service pipe (Live stream reattach needs session-owner pipe ownership).

## Next slices (ordered)

1. Session-owner-owned host-control named pipe + Live reattach (Unavailable → Ready).
2. Box tip-prove `a3s.box.windows-whpx-live-session.v1` on real WHPX; keep
   `b2_process_session_recovery_closed=false` until multi-driver B2 exit criteria.

## Refuse

- Treating stopped-only owner-death recovery as mid-run Live.
- Soft-falling DurableSession to Host-bound when the env is set.
- Self-certifying B2 close from a single harness report.
