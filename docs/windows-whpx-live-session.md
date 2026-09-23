# Windows/WHPX mid-run Live session ownership

Status: **scaffolding** (binding + fail-closed env). Durable spawn and Host
reattach are **not** tip-proven. Does **not** claim Box Enterprise GA or flip
`b2_process_session_recovery_closed`.

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

- `whpx_durable_session_owner`: env parse + **fail-closed** when DurableSession is
  requested before spawn exists (`box-whpx-qualification-service` refuses start).
- `whpx_live_session_binding`: schema, publish/load/authenticate/remove, Windows
  process identity via `GetProcessTimes`.

## Next slices (ordered)

1. Windows Job Object / intermediate process that owns the shim and hosts the
   host-control named pipe (shim `owner_pid` = session-owner, not Host).
2. Publish binding at create/start under DurableSession.
3. Host reopen Live reattach path (Unavailable → Ready) without inventing exit.
4. Box tip-prove `a3s.box.windows-whpx-live-session.v1` on real WHPX; keep
   `b2_process_session_recovery_closed=false` until multi-driver B2 exit criteria.

## Refuse

- Treating stopped-only owner-death recovery as mid-run Live.
- Soft-falling DurableSession to Host-bound when the env is set.
- Self-certifying B2 close from a single harness report.
