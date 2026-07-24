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

## Isolated libkrun context gate

The separate `a3s-oci-krun-shim` owns the native libkrun boundary. The main
runtime, public SDK, and feature CLI do not link or load libkrun.

The macOS arm64 shim carries a deterministic archive derived from the
A3S Box v3.1.0 release:

`crates/krun/runtime/macos-aarch64/krun-macos-arm64.tar.xz`

The build verifies the archive and both native files before staging them next
to the shim. The shim then:

1. rejects a runtime directory or asset that is a symbolic link;
2. recomputes both file hashes immediately before loading;
3. loads `libkrunfw.5.dylib` and `libkrun.1.17.0.dylib` by absolute path;
4. resolves only the functions required by the context and VM-entry smokes;
5. creates one libkrun configuration context;
6. records one vCPU and 128 MiB of memory;
7. replaces implicit TSI with plain vsock and maps guest port 4093 to a
   generated macOS Unix-socket path;
8. releases the context through an ownership guard.

Run a relocatable, signed copy:

```sh
cargo build -p a3s-oci-krun

smoke_dir="$(mktemp -d)"
cp target/debug/a3s-oci-krun-shim "$smoke_dir/"
cp -R target/debug/a3s-oci-krun-runtime "$smoke_dir/"
codesign --force --sign - \
  --entitlements packaging/macos/a3s-oci-hvf.entitlements \
  "$smoke_dir/a3s-oci-krun-shim"
"$smoke_dir/a3s-oci-krun-shim" context-smoke
```

A successful `a3s.oci.krun-context-smoke.v2` report requires:

```json
{
  "schema_version": "a3s.oci.krun-context-smoke.v2",
  "platform": "macos",
  "status": "available",
  "runtime_bundle_loaded": true,
  "context_created": true,
  "vm_configured": true,
  "agent_vsock_configured": true,
  "context_released": true,
  "vcpus": 1,
  "memory_mib": 128
}
```

macOS CI runs this gate independently of `kern.hv_support`, because allocating
and configuring a libkrun context does not enter a VM. CI also changes one byte
in a copied runtime asset and requires rejection before context creation.
Native runtime hashes and source provenance are recorded in
[Runtime Provenance](../crates/krun/RUNTIME-PROVENANCE.md).

## Real Linux guest entry gate

The `vm-smoke` command crosses the guest-execution boundary without claiming
an OCI workload driver. It uses the kernel embedded in the pinned
`libkrunfw.5.dylib`, presents a caller-supplied arm64 Linux rootfs through
virtiofs, executes `/bin/sh`, and requires an exact guest-written marker to be
visible on the host.

Standard macOS libkrun consumes the process in `krun_start_enter`. The shim
therefore keeps verification in a parent process and performs all libkrun work
in a hidden child:

```text
a3s-oci-krun-shim vm-smoke
        │
        ├── validate rootfs, /bin/sh, console, and absent marker
        ├── spawn signed worker and read bounded setup evidence
        │       ├── reverify and load the pinned native bundle
        │       ├── create and configure the context
        │       ├── configure rootfs, command, and console
        │       └── krun_start_enter → Linux guest → marker → guest exit
        ├── enforce 30-second timeout and reap the worker
        ├── require natural guest exit code 0
        └── verify and remove the exact marker
```

The parent never treats pre-entry evidence or a successful libkrun API call as
guest execution. Success requires all of the following in one report:

```json
{
  "schema_version": "a3s.oci.krun-vm-smoke.v1",
  "platform": "macos",
  "status": "available",
  "runtime_bundle_loaded": true,
  "context_created": true,
  "vm_configured": true,
  "rootfs_configured": true,
  "workload_configured": true,
  "console_configured": true,
  "vm_entered": true,
  "guest_exit_code": 0,
  "marker_verified": true,
  "marker_removed": true,
  "console_created": true,
  "vcpus": 1,
  "memory_mib": 512
}
```

The retained qualification rootfs is the untouched Alpine 3.22.5 aarch64
minirootfs:

- URL:
  `https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz`
- bytes: `3,966,256`
- SHA-256:
  `3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70`

Run the gate with the signed relocatable shim from the previous section:

```sh
asset_dir="$(mktemp -d)"
rootfs="$asset_dir/rootfs"
archive="$asset_dir/alpine-minirootfs-3.22.5-aarch64.tar.gz"
mkdir "$rootfs"
curl --fail --location --output "$archive" \
  https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/aarch64/alpine-minirootfs-3.22.5-aarch64.tar.gz
printf '%s  %s\n' \
  '3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70' \
  "$archive" | shasum -a 256 --check
tar -xzf "$archive" -C "$rootfs"

"$smoke_dir/a3s-oci-krun-shim" vm-smoke \
  --rootfs "$rootfs" \
  --console "$asset_dir/console.log"
```

On the local Apple Silicon qualification host, the signed worker booted the
guest, returned exit code zero, verified and removed
`a3s-oci-hvf-vm-smoke-v1`, and left no smoke marker in the rootfs. The same
build without the Hypervisor entitlement reached the complete context
configuration boundary, failed `krun_start_enter`, returned status `2`, wrote
no marker, and reported no false VM entry.

macOS CI downloads and verifies the same rootfs. When
`kern.hv_support = 1`, it requires the complete positive report. On hosted
runners where virtualization is unavailable, it requires status `2`, complete
pre-entry configuration evidence, no guest exit code, no marker, and no false
success. The parent terminates and reaps a worker that exceeds the bounded
startup interval.

## Remaining workload gates

The marker smoke proves real Linux guest execution, but it is not an
authenticated A3S guest or an OCI lifecycle. The current gates do not:

- boot the production A3S immutable Linux system image;
- bind the real host Unix socket or authenticate a guest-agent session;
- execute any OCI lifecycle operation.

The next macOS increments must add, in order:

1. the production A3S immutable system root;
2. authenticated guest-agent negotiation over the macOS Unix-socket bridge;
3. the same fixed OCI create/start/kill/delete lifecycle used by WHPX;
4. deterministic descriptor and runtime-root cleanup around that lifecycle;
5. negative tests for agent startup, isolation weakening,
   and recovery.

Only after those gates and the shared Linux executor requirements pass may
the HVF driver move from `probe-only` to `experimental`.
