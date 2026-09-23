# Windows/WHPX mid-run Live session ownership

Status: **AgentVmSession durable Live path** owns the guest agent named pipe and
host-control named pipe inside `a3s-oci-krun-shim session-owner` when
`A3S_OCI_WHPX_SESSION_OWNER=1`. First Host connects as a NamedPipeClient to
host-control. Host-control EOF closes the guest pipe so the Linux guest can
Host-EOF reconnect (`A3S_OCI_GUEST_HOST_RECONNECT=1`, KVM parity) before the
replacement Host's Live HostHello. `WhpxRuntimeDriver::recover` calls
`whpx_live_reattach::try_reattach_live` before inventing `RecoveredStopped`.
Does **not** claim Box Enterprise GA, tip-prove binder gate 9, or flip
`b2_process_session_recovery_closed`.

## Why this exists

Box binder gate 9 / Axis A needs mid-run Host death with retained Live stream
and filesystem reattach under packaged Box-owned WHPX. KVM already has
`A3S_OCI_KVM_SESSION_OWNER=1` plus a durable session-owner parent so Host
SIGKILL does not tear down the Guest.

WHPX default remains **Host-bound**: the libkrun shim owner watchdog
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
  (breakaway + Job Object via `a3s-oci-krun-shim session-owner`), optional
  `--host-control`, and `require_durable_spawn_ready` Ok once the helper is
  productized.
- `whpx_live_session_binding`: schema, publish/load/authenticate/remove, Windows
  process identity via `GetProcessTimes`; stable
  `host_control_pipe_for_service` naming.
- `a3s-oci-krun-shim session-owner` / `session-owner-probe` /
  `session-owner-bridge-echo` on Windows (`KILL_ON_JOB_CLOSE` Job Object +
  duplex named-pipe Host↔shim byte bridge when `--host-control` is set;
  Host-control EOF re-accepts guest then Host for Live reopen).
- AgentVmSession Windows durable path: omits Host `--owner-pid`, does **not**
  bind `WindowsAgentPipeListener` on the product agent pipe, spawns through the
  helper with host-control + `A3S_OCI_GUEST_HOST_RECONNECT=1`, connects as
  `NamedPipeClient`, publishes binding after hello.
- `utility_vm_driver/whpx_live_reattach.rs` (pulled via `#[path]` from the
  runtime crate root on Windows): authenticate binding → host-control connect →
  agent hello → `ReattachedLive` for the driver. Wired into
  `WhpxRuntimeDriver::recover` before stopped-only recovery; dead/drifted
  identities fall through to stopped; permanent hello rejects stay non-retryable.

## Next slices (ordered)

1. Box tip-prove `a3s.box.windows-whpx-live-session.v1` on real WHPX (binder
   gate 9); keep `b2_process_session_recovery_closed=false` until multi-driver
   B2 exit criteria.

## Refuse

- Treating stopped-only owner-death recovery as mid-run Live.
- Soft-falling DurableSession to Host-bound when the env is set.
- Self-certifying B2 close from a single harness report.
