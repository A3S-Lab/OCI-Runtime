# Windows WHPX Host package layout

Status: **contract for Box #650 / OCI #349** — not yet an installer product.

Box omit-isolation → OCI DedicatedVm on Windows needs the same durable Host
artifacts that CI already publishes as `windows-whpx-qualification`, without
re-downloading them for every operator session.

## Layout (install root)

Place beside `a3s-box.exe` or under `%USERPROFILE%\.a3s\`:

```text
a3s-oci.exe
a3s-oci-krun-shim.exe
krun.dll
libkrunfw.dll
system-image/
  system-image.json          # a3s.oci.windows-system-image.v1
  <ext4 image + companions>  # as bound by the manifest
bootstrap-vm-rootfs/         # empty seed; Box materializes the live copy
```

`box-whpx-qualification-service` requires both `--vm-rootfs` (bootstrap) and
`--system-image-manifest`. The guest agent is embedded in the system image;
do not require a loose `usr\bin\a3s-oci-agent` under the bootstrap root for
Box-owned ensure.

### Mutable service root (disjoint from system-image)

OCI WHPX requires:

1. Live `--vm-rootfs` is a **strict descendant** of the mutable `--runtime-root`
2. Immutable `system-image/` is **disjoint** from that mutable runtime root

Do **not** point `A3S_BOX_OCI_HOST_ROOT` / `A3S_BOX_WHPX_OCI_SERVICE_ROOT` at
the install root that contains `system-image/`. Box packaged opt-in defaults
the mutable service root under the A3S home (`run/oci-host`) and materializes
`bootstrap-vm-rootfs/` there from the packaged seed.

## Staging from CI (operator / packager)

```powershell
gh run download <run-id> --repo A3S-Lab/OCI-Runtime `
  --name windows-whpx-qualification --dir C:\a3s\oci-host-package

# Expected under that directory after extract:
#   bin\a3s-oci.exe, bin\a3s-oci-krun-shim.exe, bin\krun.dll, bin\libkrunfw.dll
#   system-image\system-image.json (+ image files)
```

Copy `bin\*` and `system-image\` into the install root above. Create an empty
`bootstrap-vm-rootfs` directory (or reuse the soak bootstrap fixture).

## Non-claims

- Does not flip Box default omit→DedicatedVm until Box tip-proves discovery +
  lifecycle gates (see Box `docs/microvm-whpx-ga-evidence.md`).
- Does not replace qualification artifact verification for CI release matrix.
