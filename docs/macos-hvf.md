# macOS HVF Development

## Current capability boundary

macOS feature discovery reports the `libkrun-hvf` driver. The feature probe:

1. requires the Apple Silicon architecture supported by A3S OCI Runtime;
2. reads `kern.hv_support` directly through `sysctlbyname`;
3. records both observations in the versioned feature inventory;
4. does not create a VM or mutate runtime state;
5. keeps driver readiness at `probe-only`.

Intel macOS is reported as unsupported by A3S driver policy instead of being
silently treated as an unavailable Apple Silicon host.

The separate `hvf-smoke` command crosses the next host API boundary. On Apple
Silicon it calls the system Hypervisor.framework directly, creates the single
VM object associated with the process, destroys it, and emits a versioned
`a3s.oci.hvf-smoke.v1` report. No libkrun dependency is involved.

## Entitlement and signing

`kern.hv_support = 1` proves only that the host reports Hypervisor.framework
hardware support. It does not prove that the executable has permission to
create a VM.

The repository contains the minimal development entitlement at
`packaging/macos/a3s-oci-hvf.entitlements`:

```xml
<key>com.apple.security.hypervisor</key>
<true/>
```

Build the CLI and ad-hoc sign a disposable copy:

```sh
cargo build -p a3s-oci-cli

smoke_dir="$(mktemp -d)"
trap 'rm -rf "$smoke_dir"' EXIT
cp target/debug/a3s-oci "$smoke_dir/a3s-oci"
codesign --force --sign - \
  --entitlements packaging/macos/a3s-oci-hvf.entitlements \
  "$smoke_dir/a3s-oci"
codesign --verify --strict "$smoke_dir/a3s-oci"
"$smoke_dir/a3s-oci" hvf-smoke
```

The signed command exits successfully only when both `hv_vm_create` and
`hv_vm_destroy` succeed. It exits with status `2` for unsupported,
unavailable, denied, or partial-cleanup results.

On the local Apple Silicon validation host:

- `kern.hv_support` returned `1`;
- the unsigned executable failed with
  `hv_vm_create returned HV_DENIED (0xFAE94007)`;
- the ad-hoc signed executable created and destroyed the real VM object.

This negative and positive evidence proves that the implementation does not
mistake hardware discovery for executable authorization.

## Report contract

The stable report fields are:

| Field | Meaning |
| --- | --- |
| `schema_version` | Always `a3s.oci.hvf-smoke.v1` for this contract |
| `platform` | Host platform on which the command ran |
| `status` | Overall prerequisite and VM-object lifecycle status |
| `apple_silicon` | Whether the runtime target is macOS arm64 |
| `hypervisor_supported` | `true`, `false`, or unavailable from the direct query |
| `vm_created` | Whether `hv_vm_create` succeeded |
| `vm_destroyed` | Whether `hv_vm_destroy` released the object |
| `reason` | Symbolic and numeric diagnostic for a failed gate |

A successful report is:

```json
{
  "schema_version": "a3s.oci.hvf-smoke.v1",
  "platform": "macos",
  "status": "available",
  "apple_silicon": true,
  "hypervisor_supported": true,
  "vm_created": true,
  "vm_destroyed": true
}
```

The VM guard retains cleanup ownership until `hv_vm_destroy` succeeds. If the
explicit destroy call fails, the guard makes a final best-effort destroy
attempt while the report remains unsuccessful.

## CI evidence

The macOS job signs the already-tested CLI copy with the checked-in entitlement
and runs `hvf-smoke`.

- If `kern.hv_support = 1`, CI requires a successful create/destroy report.
- Otherwise CI requires exit status `2`, `status = unavailable`, and both VM
  lifecycle fields to remain false.

GitHub-hosted macOS currently reports `kern.hv_support = 0`, so hosted CI
retains the fail-closed branch. The signed local Apple Silicon run supplies
the positive host lifecycle evidence until a virtualization-capable CI runner
is available.

## Remaining workload gates

VM-object creation is not workload execution. The current smoke does not:

- load or initialize libkrun;
- stage or verify a runtime bundle;
- allocate a vCPU or guest memory;
- boot the pinned A3S kernel or immutable Linux system image;
- establish the AF_VSOCK guest-agent protocol;
- execute any OCI lifecycle operation.

The next macOS increments must add, in order:

1. an isolated libkrun shim and checksum-verified macOS runtime assets;
2. a context create/configure/release round trip;
3. the pinned A3S kernel and immutable system root;
4. authenticated guest-agent negotiation;
5. the same fixed OCI create/start/kill/delete lifecycle used by WHPX;
6. deterministic process, descriptor, file, and VM cleanup;
7. negative tests for invalid assets, failed guest boot, isolation weakening,
   and recovery.

Only after those gates and the shared Linux executor requirements pass may
the HVF driver move from `probe-only` to `experimental`.
