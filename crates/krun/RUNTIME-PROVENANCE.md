# Windows Native Runtime Provenance

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
