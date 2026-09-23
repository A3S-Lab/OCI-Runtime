# Windows WHPX Host package layout

Status: **contract for Box #650 / OCI #349** — not yet an installer product.

Box omit-isolation → OCI DedicatedVm on Windows needs the same durable Host
artifacts that CI already publishes as `windows-whpx-qualification`, without
re-downloading them for every operator session.

## Layout (install root)

Keep Host binaries under `bin/` and immutable `system-image/` as a **sibling**
directory. Do **not** flatten `bin/*` into the same directory as
`system-image/` — WHPX `WindowsSystemImage::load` requires the shim/runtime
directory and the system-image directory to be disjoint.

Place beside `a3s-box.exe` under an install root, or under
`%USERPROFILE%\.a3s\`:

```text
install-root/
  bin/
    a3s-oci.exe
    a3s-oci-krun-shim.exe
    krun.dll
    libkrunfw.dll
  system-image/
    system-image.json          # a3s.oci.windows-system-image.v1
    <ext4 image + companions>  # as bound by the manifest
  bootstrap-vm-rootfs/         # empty seed; Box materializes the live copy
```

Equivalent A3S-home layout:

```text
%USERPROFILE%\.a3s\
  bin\                         # Host binaries (+ optional a3s-box.exe)
  share\a3s\
    system-image\
    bootstrap-vm-rootfs\       # empty seed
```

`box-whpx-qualification-service` requires both `--vm-rootfs` (bootstrap) and
`--system-image-manifest`. The guest agent is embedded in the system image;
do not require a loose `usr\bin\a3s-oci-agent` under the bootstrap root for
Box-owned ensure. The bootstrap root must stay empty (or only the fixed
post-boot mount points / bounded init logs); it is not an Alpine rootfs.

### Mutable service root (disjoint from system-image)

OCI WHPX requires:

1. Live `--vm-rootfs` is a **strict descendant** of the mutable `--runtime-root`
2. Immutable `system-image/` is **disjoint** from that mutable runtime root
3. Host `bin/` (shim/runtime directory) is **disjoint** from `system-image/`

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

Preserve the artifact’s `bin\` vs `system-image\` sibling layout when copying
into the install root (or into `%USERPROFILE%\.a3s\bin` +
`%USERPROFILE%\.a3s\share\a3s\system-image`). Create an empty
`bootstrap-vm-rootfs` directory beside `system-image` (or under
`share\a3s\`). Do **not** copy `bin\*` into the same folder as `system-image\`.

## Non-claims

- Does not flip Box default omit→DedicatedVm until Box tip-proves discovery +
  lifecycle gates (see Box `docs/microvm-whpx-ga-evidence.md`).
- Does not replace qualification artifact verification for CI release matrix.
