# macOS HVF Development

## Current capability boundary

macOS feature discovery reports the `libkrun-hvf` driver. The current probe:

1. requires the Apple Silicon architecture supported by A3S OCI Runtime;
2. reads `kern.hv_support` through `sysctlbyname`;
3. records both observations in the versioned feature inventory;
4. keeps driver readiness at `probe-only`.

The implementation does not spawn `/usr/sbin/sysctl`, search the current
directory for a framework, initialize libkrun, create a VM, or mutate runtime
state.

`kern.hv_support = 1` proves that the host reports Hypervisor.framework
hardware support. It does not prove that the current executable carries the
required entitlement, that the packaged libkrun artifacts are correct, or
that an OCI workload can run.

Intel macOS is reported as unsupported by the A3S driver policy instead of
being silently treated as an unavailable Apple Silicon host.

## Current feature evidence

The stable evidence fields are:

| Field | Meaning |
| --- | --- |
| `apple_silicon` | Whether the runtime target is macOS arm64 |
| `kern_hv_support` | `true`, `false`, or `unavailable` from the direct query |

An available host capability still has
`DriverReadiness::ProbeOnly`, so `can_launch()` remains false.

## Next HVF gate

The next macOS increment must add retained evidence for:

1. an entitlement-aware Hypervisor.framework or isolated libkrun context
   create/configure/release round trip;
2. the version-pinned A3S kernel and immutable Linux system image;
3. the authenticated AF_VSOCK guest-agent protocol;
4. the same fixed OCI create/start/kill/delete lifecycle used by WHPX;
5. deterministic process, file, handle, and VM cleanup;
6. negative tests for missing entitlement and unavailable virtualization.

Only after the shared Linux executor and those host-specific gates pass may
the HVF driver move from `probe-only` to `experimental`.
