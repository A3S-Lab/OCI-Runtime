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
bootstrap-vm-rootfs/         # empty or minimal init.krun bootstrap directory
```

`box-whpx-qualification-service` requires both `--vm-rootfs` (bootstrap) and
`--system-image-manifest`. The guest agent is embedded in the system image;
do not require a loose `usr\bin\a3s-oci-agent` under the bootstrap root for
Box-owned ensure.

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
