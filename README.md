# A3S OCI Runtime

`a3s-oci-runtime` is the A3S-owned cross-platform runtime for Linux OCI
workloads. It will provide:

- native Linux execution without requiring KVM;
- Linux utility VMs through KVM, macOS HVF, and Windows WHPX;
- dedicated-VM, shared-guest-kernel, and shared-host-kernel isolation with
  explicit capability evidence;
- one reviewed Linux container executor shared by native Linux and utility-VM
  guest paths.

The project is experimental. The current Windows milestone implements
machine-readable WHPX capability discovery, a partition-object smoke test, and
the OCI lifecycle state contract. It does not yet create or run OCI
containers, and reports the WHPX driver readiness as `probe-only`.

## Build and test

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo run -p a3s-oci-cli -- features
cargo run -p a3s-oci-cli -- whpx-smoke
```

`features` succeeds even when WHPX is unavailable and reports the reason.
`whpx-smoke` returns a non-zero status unless the Windows hypervisor is present
and a WHPX partition object can be created and deleted.

See [Windows WHPX development](docs/windows-whpx.md) for the current boundary
and test evidence required before the driver may run workloads.

## Repository layout

```text
crates/
|-- core/       # pure capability and OCI lifecycle contracts
|-- runtime/    # platform probes and runtime drivers
`-- cli/        # a3s-oci command
```

The runtime repository does not depend on A3S Box. Box will consume released,
revision-pinned runtime artifacts through a narrow execution adapter.
