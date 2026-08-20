# Native Runtime Provenance

## Linux x86_64 And AArch64

The Linux shim carries one minimal native runtime archive for each advertised
KVM architecture. Each archive contains exactly the versioned libkrun object
and the firmware object that it loads; no Box executable, symbolic link, or
mutable root filesystem is included.

| Target | Archive bytes | Archive SHA-256 | Source Box release SHA-256 |
| --- | ---: | --- | --- |
| `linux-x86_64` | 7,471,288 | `8df72533d8006ee0a929048e015192f23f57b0582a155a47a616f9272a2bc719` | `d1aa83dc0111f8982a8ac984064fd4e8cf553deb87a94f28ad85b9f1da9af530` |
| `linux-aarch64` | 11,538,808 | `f930a75945862ce039646b521783b06268c49cd9470f9d64a66fc585350ce7e4` | `2420b5f5c46bc773856f7a07a3525c80f61946a81127033770e7d340b9b277cd` |

The inner file identities are:

| Target | File | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `linux-x86_64` | `libkrun.so.1.17.0` | 5,824,233 | `5a1fdec0e6fc3021aaa6314703b939c4094694662251f6219e8a7ebb1a91390c` |
| `linux-x86_64` | `libkrunfw.so.5` | 19,206,985 | `dfe9796599c397ef914f6948e81f47384aca33a404aea32c82ca9134472936d6` |
| `linux-aarch64` | `libkrun.so.1.17.0` | 4,918,753 | `02236ec44afac5a1d1831fea1dda9a6250a67a5c5c6d47550dfdb72591b0fde3` |
| `linux-aarch64` | `libkrunfw.so.5` | 23,004,041 | `b440b30751cefb2e9325d39853c64cc397acc9d72cdedc5a07a5e56daf553e46` |

All four files come without modification from the checksum-verified
[`A3S-Lab/Box v3.1.0`](https://github.com/A3S-Lab/Box/releases/tag/v3.1.0)
Linux packages at commit
[`5328dea`](https://github.com/A3S-Lab/Box/commit/5328dea976d07643945fa7d42b9ed5256e9afc58).
That revision pins its libkrun source gitlink to
[`A3S-Lab/libkrun@e506839`](https://github.com/A3S-Lab/libkrun/commit/e50683984386611f9a06d7a66d87976d8aa4bbcb),
and the matching release publishes `a3s-libkrun-source.tar` with SHA-256
`05f6d3137d424e131aafc9cd0fdef6cde019b4ede15b19cacf6435280748588e`.

The Box build obtains its Linux firmware inputs from
[`boxlite-ai/libkrunfw v5.3.0`](https://github.com/boxlite-ai/libkrunfw/releases/tag/v5.3.0),
commit
[`fad43a1`](https://github.com/boxlite-ai/libkrunfw/commit/fad43a12d689586b4cb46110efc1d2a0f20b5361).
It pins the x86_64 release asset to SHA-256
`0a7bb64a35a273b8501801dd69b75736a8c676aa21aa62fb5642842cda9dc91d`
and the AArch64 asset to
`8b5b9211da5445d9301dafb2201431f4392ab96455512bce63a5cfbd33c49839`,
then gives the packaged object its final `libkrunfw.so.5` SONAME. The firmware
source tag builds Linux 6.12.76 from the kernel.org archive whose published
SHA-256 is
`bbb43e834c46e6bd49a5c28f22e679a937443404e1f653204d4b24929f3ad896`.
Its checked-in x86_64 and AArch64 configurations and complete patch series are
therefore bound to the same immutable source revision as the binary inputs.

The two minimal archives were each produced twice with GNU tar 1.35 and
matched byte for byte. Starting from a directory containing the two exact
regular files, the command is:

```bash
XZ_OPT=-9 tar --sort=name --format=ustar --mtime=@0 \
  --owner=0 --group=0 --numeric-owner \
  -cJf krun-linux-ARCH.tar.xz \
  libkrun.so.1.17.0 libkrunfw.so.5
```

`runtime/runtime-assets.json` is the single machine-readable identity for all
packaged native bundles. Its strict schema gives every file one semantic role,
rejects unknown fields, unsupported or duplicate targets, platforms, roles,
names, unsafe paths, zero values, and malformed digests, and requires exactly
one library and firmware for each target. The build script and Linux shim parse
that same checked-in document. Archive tests additionally reject non-file,
duplicate, undeclared, or nested entries and verify every extracted byte.

## Immutable Linux KVM System Roots

`scripts/build-linux-kvm-system-image.sh` selects the exact Linux target bundle
from the shared runtime manifest instead of copying its values into shell. For
both x86_64 and AArch64, CI supplies the matching static `a3s-oci-agent`, builds
the ext4 image twice, requires byte equality, extracts the installed agent back
out of the image, and requires it to equal the supplied executable. The output
manifest uses schema `a3s.oci.linux-kvm-system-image.v1` and binds the image,
compressed archive, Alpine input, exact agent, native runtime, firmware-exported
kernel, filesystem UUID, and compatibility level.

The Linux shim accepts only an absolute real-file manifest and its real-file
sibling image. It opens both with `O_NOFOLLOW`, retains read-only descriptors,
checks path and descriptor identity, size, digest, architecture, and the exact
runtime-bundle object, then exposes the image to libkrun through its retained
`/proc/self/fd` descriptor. The `system-image-context-smoke` gate configures
that disk read-only together with VM resources and plain agent vsock, reverifies
all pinned bytes, and releases the context without opening `/dev/kvm` or
entering a VM. Symbolic links, path replacement, same-size mutation, unknown
manifest fields, and runtime drift fail closed.

This closes the immutable compatibility-set gate. It does not register a KVM
driver or complete authenticated guest boot, real-KVM lifecycle, recovery, or
soak gates.

## Windows x86_64

The Windows x86_64 shim carries one deterministic native runtime archive:

`runtime/windows-x86_64/krun-windows-x64.tar.xz`

Its SHA-256 is
`ce178184bc9e309c9f8fef181312cd6c398fc825807124e31afab949b790627e`.
The build script verifies the archive and every extracted file before linking
or staging them:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `krun.dll` | 7,428,608 | `f21293b65ee16058c9014b543c708d84c50dc28d7775dbd77bac32faabafa59e` |
| `krun.lib` | 11,870 | `3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d` |
| `libkrunfw.dll` | 21,473,280 | `44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077` |

The archive is created with bsdtar 3.8.2 using the file order above and fixed
ustar metadata:

```powershell
tar.exe -cJf krun-windows-x64.tar.xz --format ustar `
  --mtime '1970-01-01 00:00:00 UTC' -C stage `
  krun.dll krun.lib libkrunfw.dll
```

Repacking the prior archive with this command reproduced its SHA-256 exactly;
two independent staging directories produced the new hash above.

`krun.dll` and `krun.lib` were built from
[`A3S-Lab/libkrun@dc5519f`](https://github.com/A3S-Lab/libkrun/commit/dc5519faeabd8bf38d984ed29c44e6da977f0b5c).
That revision retains segmented Windows host-to-guest stream reads and opens
writable virtio-fs files with write access before `fsync`, allowing the guest
to durably publish its authenticated shutdown report. The native build
controls are in that revision. License notices, firmware provenance, and the
corresponding kernel source are recorded by
[`A3S-Lab/Box@93fc281`](https://github.com/A3S-Lab/Box/commit/93fc281a798cdfd8ee463f69add3f6989d561ee3)
under `src/deps/libkrun-sys`.

The Rust FFI declarations remain pinned to `a3s-libkrun-sys 3.1.0`. The import
library ABI is unchanged from that release; the runtime-owned archive prevents
a clean OCI Runtime checkout from loading the older WHPX DLL while the fixed
crate release is prepared.

## macOS arm64

The macOS shim carries this deterministic runtime archive:

`runtime/macos-aarch64/krun-macos-arm64.tar.xz`

Its SHA-256 is
`5486f38e91eb4da0e58888b543c93fe669c918ad4b84dd495f0d1dfdffc43b56`.
It contains exactly:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `libkrun.1.17.0.dylib` | 4,557,488 | `c5353f9cbd91564ce26eceaf1bdc33341097b43280fe029203ccca02807c082d` |
| `libkrunfw.5.dylib` | 22,952,096 | `841bc9d5eecbc2aeeb6098fbc75d484427680d7503f5ed9bcdfe9d072a9420d4` |

Both files were copied without modification from
[`A3S-Lab/Box v3.1.0`](https://github.com/A3S-Lab/Box/releases/tag/v3.1.0),
commit
[`5328dea`](https://github.com/A3S-Lab/Box/commit/5328dea976d07643945fa7d42b9ed5256e9afc58).
The source release asset
`a3s-box-v3.1.0-macos-arm64.tar.gz` has SHA-256
`4f1c248e785be55b8ccab8acca19ad089b38b1d5b115eeaed144a5437fb200b9`.

That Box release builds libkrun from
[`A3S-Lab/libkrun@e506839`](https://github.com/A3S-Lab/libkrun/commit/e50683984386611f9a06d7a66d87976d8aa4bbcb)
and pins its macOS firmware input. The matching release also publishes
`a3s-libkrun-source.tar` with SHA-256
`05f6d3137d424e131aafc9cd0fdef6cde019b4ede15b19cacf6435280748588e`,
plus the applicable native license and corresponding-source notices.

The OCI Runtime build script verifies the inner archive and both extracted
files. The macOS shim repeats the two file checks immediately before loading
the absolute paths, rejects symbolic links, loads firmware before libkrun, and
resolves only the context and VM-entry ABI it uses. A modified staged library
is rejected before `krun_create_ctx`.

The real VM-entry qualification does not add a rootfs to the runtime archive.
CI and local qualification download the upstream Alpine 3.22.5 aarch64
minirootfs separately and require SHA-256
`3fbc6285032ed46821b511292633d7b2a6306a2e254f590e92bdafff56cf2f70`
before extraction. This keeps the native runtime bundle deterministic while
binding the diagnostic userspace used for retained guest-execution evidence.
