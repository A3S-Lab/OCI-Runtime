# Changelog

All notable changes to A3S OCI Runtime are documented in this file.

## [Unreleased]

### Added

- An opt-in `control-workload-v1` cgroup-v2 layout that keeps
  `linux.resources` exact for the workload, derives bounded control-plane
  headroom, hands fixed membership descriptors to a trusted init, and keeps
  update, freeze, statistics, OOM behavior, and cleanup scoped to one
  runtime-owned topology.

### Fixed

- Stage trusted native init processes in the management cgroup, then activate
  the fixed `control` and `workload` children after the init creates its cgroup
  namespace, preserving the cgroup-v2 no-internal-process invariant without
  exposing the host cgroup hierarchy inside the container.

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
