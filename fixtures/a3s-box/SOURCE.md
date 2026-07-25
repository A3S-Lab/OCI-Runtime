# A3S Box OCI bundle fixture

`config.json` is the direct, pretty-printed output of
`a3s_box_runtime::sandbox::oci::compile_oci_spec` for that module's
`sample_input()` at A3S Box commit
`d24c951989c8ee8dbc772ccd0021713855613656`.

The fixture was generated on `aarch64`, so its certified seccomp architecture is
`SCMP_ARCH_AARCH64`. It must not be edited by hand. Regenerate it from the A3S
Box compiler whenever the compiler's output changes.

SHA-256:

```text
027f5f54b5c063134c2b6825bb5d3139b05abfa70b11c57171cf095a95211925
```
