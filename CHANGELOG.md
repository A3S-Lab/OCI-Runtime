# Changelog

All notable changes to A3S OCI Runtime are documented in this file.

## [Unreleased]

### Added

- A versioned, bounded guest shutdown report for restart-stable utility-VM
  evidence. The Linux executor now retains the exact init terminal result for
  every exact container generation only after complete cleanup, binds each
  result to its canonical configuration digest, and authenticates the sorted
  report with a session-scoped HMAC-SHA256 tag. Missing, partial, oversized,
  malformed, stale-generation, and tampered reports remain unusable; protected
  Windows shim handoff and durable host consumption are the next gate.
- An idempotent startup `RuntimeDriver::recover` handshake that dispatches each
  durable generation only to its recorded driver, commits an optional exact
  state observation before the host accepts requests, and is covered by the
  same typed before/after fault matrix as every lifecycle call. The WHPX
  candidate now converts owner-death cleanup into a stopped, generation-fenced
  tombstone that supports state, idempotent kill, empty process inventory, and
  delete without inventing an init exit status or relaunching the generation.
- Clone-wide, idempotent guest-agent client shutdown that waits for an
  in-flight request, blocks every later dispatch, and actively closes the
  shared transport before a utility-VM owner reaps its shim process.
- A shareable utility-VM session boundary with one VM owner, cloned concurrent
  guest clients, and one cached shutdown/cleanup result. WHPX and HVF smoke,
  fault-cleanup, and multi-container paths now exercise that driver-ready
  ownership model.
- A shared eighteen-operation agent driver adapter used by native Linux and a
  new one-VM-per-container WHPX `RuntimeDriver` candidate. The candidate binds
  exact generations to one guest session, serializes same-ID create while
  launching distinct container VMs concurrently, reuses the VM for retryable
  create, reaps terminal create failures and successful deletes once, requires
  bundles below a protected runtime-owned guest root, and intentionally remains
  non-registerable at `probe-only` readiness while restart-stable exact exit
  evidence and immutable-system-root qualification are pending.
- Target-correct KVM ioctl request typing so both glibc (`c_ulong`) and musl
  (`c_int`) Linux builds compile against their actual libc ABI.
- A protected Windows host SDK service that binds the first local named-pipe
  instance with a verified current-user/LocalSystem DACL, rejects remote
  clients, serves bounded concurrent connections, and releases the endpoint
  on graceful shutdown.
- A deterministic multi-driver host registry that selects exactly one
  launch-ready driver for each requested isolation class, routes every later
  operation through the driver persisted in the container record, preserves
  routing across host-service reopen, and rejects duplicate isolation owners
  or inconsistent operation and hook surfaces before creating durable state.
  Service startup now audits every durable container and fails closed if its
  recorded driver is missing or no longer advertises the recorded isolation,
  without dispatching to any driver or silently rerouting the workload.
- An opt-in `control-workload-v1` cgroup-v2 layout that keeps
  `linux.resources` exact for the workload, derives bounded control-plane
  headroom, hands fixed membership descriptors to a trusted init, and keeps
  update, freeze, statistics, OOM behavior, and cleanup scoped to one
  runtime-owned topology.

### Fixed

- Prepare read-only bind mounts from parent-namespace filesystems as detached
  mount objects before entering a container user namespace. Requested kernel
  security attributes are applied with `mount_setattr` and the prepared mount
  is attached with `move_mount`, avoiding an impossible less-privileged bind
  remount without falling back to a writable Secret mount. Native Linux
  conformance now proves this boundary with a real private tmpfs source, and
  its multi-container report advances to
  `a3s.oci.native-linux-multi-container-smoke.v14`.
- Root the native init's cgroup namespace at the empty management envelope,
  move trusted bootstrap processes into `control` through the inherited
  descriptor, and only then delegate domain controllers and apply exact
  workload limits. This preserves both namespace visibility and the cgroup-v2
  no-internal-process invariant. The native Linux gate now executes this exact
  layout and proves management-root visibility plus control/workload
  membership before the normal lifecycle, update, freeze, stats, and cleanup
  checks.

## [0.2.0] - 2026-07-27

### Added

- A bounded, versioned native Linux complex-container soak with concurrent
  lifecycle, captured exec, pause/resume, durable reopen, generation reuse,
  and process/descriptor/runtime leak evidence.
- Real x86_64 and aarch64 network-mode evidence for private, host-inherited,
  and donor-shared network namespaces.
- Real shared read-write bind, read-only bind, private tmpfs, and
  delete/recreate persistence evidence.
- Real inline-shell, executable-script, direct-argv, and exact nonzero init
  profiles, plus create/start/timeout/poststop OCI Hook failure behavior.
- A tag-driven GitHub Release workflow with checksummed Linux, macOS, and
  Windows archives.

### Changed

- Native multi-container report schema advanced to
  `a3s.oci.native-linux-multi-container-smoke.v13`.
- Documentation and conformance evidence now distinguish runtime namespace and
  mount enforcement from A3S Box product-level network and volume management.

[0.2.0]: https://github.com/A3S-Lab/OCI-Runtime/releases/tag/v0.2.0
