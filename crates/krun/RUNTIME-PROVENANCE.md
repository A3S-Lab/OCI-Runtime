# Native Runtime Provenance

## Windows x86_64

The Windows x86_64 shim carries one deterministic native runtime archive:

`runtime/windows-x86_64/krun-windows-x64.tar.xz`

Its SHA-256 is
`c8d14bd0ceb86190effac9c9af12892f1dbb5b82f22123e8524dd375014d5493`.
The build script verifies the archive and every extracted file before linking
or staging them:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `krun.dll` | 7,428,608 | `e5debc685ae171e3f60a6e3b9c1c4e12a7c3eb943a68ceb1169e153f0cc6c255` |
| `krun.lib` | 11,870 | `3ac760758158bd4d2d6570db58037d47cd370a8e6ea04ccf54a8b24fd1fdec3d` |
| `libkrunfw.dll` | 21,473,280 | `44f25540f58155c01258fe123617636fdc6cff27873e38e71dbc75f139602077` |

`krun.dll` and `krun.lib` were built from
[`A3S-Lab/libkrun@513268f`](https://github.com/A3S-Lab/libkrun/commit/513268f40c83979b45f39410c3fe96888ddd60ea).
The complete deterministic source archive, build controls, native license
notices, firmware provenance, and corresponding kernel source are recorded by
[`A3S-Lab/Box@46e17a8`](https://github.com/A3S-Lab/Box/commit/46e17a82e9a1034a627b2eebd01503c9d1f0e7bb)
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
resolves only the context-lifecycle ABI it uses. A modified staged library is
rejected before `krun_create_ctx`.
