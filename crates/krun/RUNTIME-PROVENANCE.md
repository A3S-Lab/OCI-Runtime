# Native Runtime Provenance

## Windows x86_64

The Windows x86_64 shim carries one deterministic native runtime archive:

`runtime/windows-x86_64/krun-windows-x64.tar.xz`

Its SHA-256 is
`f6bc8d37681788454acded5872d54d6cf1047ee786876cedf6e81e0115232e9b`.
The build script verifies the archive and every extracted file before linking
or staging them:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `krun.dll` | 7,422,976 | `0d28ac43fca4e9e592b98779f9d6e8e948be566ca2f433a6974d2460375d45cd` |
| `krun.lib` | 11,870 | `3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d` |
| `libkrunfw.dll` | 21,473,280 | `44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077` |

The archive is created with bsdtar 3.5.3, libarchive 3.7.4, and liblzma 5.4.3
using the file order above and fixed ustar metadata:

```bash
chmod 0666 stage/krun.dll stage/krun.lib stage/libkrunfw.dll
TZ=UTC touch -t 197001010000.00 \
  stage/krun.dll stage/krun.lib stage/libkrunfw.dll
COPYFILE_DISABLE=1 /usr/bin/tar -cJf krun-windows-x64.tar.xz --format ustar \
  --uid 0 --gid 0 --uname '' --gname '' -C stage \
  krun.dll krun.lib libkrunfw.dll
```

Two independent staging directories produced byte-identical archives with the
hash above.

`krun.dll` and `krun.lib` were built from
[`A3S-Lab/libkrun@35cc832`](https://github.com/A3S-Lab/libkrun/commit/35cc832b3de33e2bcbb6f1d4687ab18685d92396).
The files came from `krun-windows-x64`, artifact `9245492618`, produced by
[Windows CI run `31878747322`](https://github.com/A3S-Lab/libkrun/actions/runs/31878747322)
for that exact source revision. The pull-request checkout commit
`300b9367ac0ed7f52fdd71a7c5b5c62dd65c117d` and source revision shared Git
tree `c64917f9c56dc5d7943f07b51c5a839d5fa80a11`. GitHub recorded SHA-256
`77cb80ad83ae49598c81703b614ebea11df90e1c7189b7582e5ad5ef8efba175`
for the uploaded artifact archive.
That revision retains segmented Windows host-to-guest stream reads and
writable virtio-fs flush support. It also cancels and joins vCPU, monitor,
timer, virtiofs, vsock, and stdin-reader workers, releases the WHPX partition
last, and removes the Windows VM-entry ownership leaks so repeated entries can
return without relying on process teardown. The native build controls and
required guest-wrapper Rust target are in the same revision. License notices,
firmware provenance, and the corresponding kernel source are recorded by
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
