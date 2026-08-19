# A3S patch inventory

This directory contains the `oci-spec` 0.10.0 crate with one wire-type
correction in `src/runtime/linux.rs`:

- `LinuxHugepageLimit.limit` is `u64`, matching OCI Runtime Specification
  1.3.0 `config-linux.md`, rather than the upstream crate's `i64`.
- The optional property-test generator uses the same corrected type.

`src/lib.rs` also allows `dead_code` because Cargo caps lints for registry
dependencies but not path patches; the upstream serialization helpers are
intentionally dormant in this workspace's runtime-only feature build.

Trailing whitespace in packaged upstream text was normalized so the workspace
diff check remains clean; that normalization does not change Rust or wire
semantics.

The workspace `[patch.crates-io]` entry is intentionally version-local. Remove
this copy when a released upstream crate models the field as `u64` and the
full-range regression test passes against that release.
