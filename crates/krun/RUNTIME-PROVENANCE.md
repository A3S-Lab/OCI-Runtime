# Windows Native Runtime Provenance

The Windows x86_64 shim carries one deterministic native runtime archive:

`runtime/windows-x86_64/krun-windows-x64.tar.xz`

Its SHA-256 is
`99329b39d23ba8462d63a448af267bcd8fcd238ed2ea1b2656d4cdf84ebf1e5c`.
The build script verifies the archive and every extracted file before linking
or staging them:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `krun.dll` | 7,428,608 | `ab8ceb013795fa8b43a3793f9579179c0afb9608430af1c21f6e9145cf27d7d9` |
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
[`A3S-Lab/libkrun@9480ee3`](https://github.com/A3S-Lab/libkrun/commit/9480ee360cdfcf0855ca4fa0951743ea09d2f550).
That revision splits Windows host-to-guest stream reads into 3 KiB chunks so a
message larger than the guest's receive descriptor is delivered without
stalling. The native build controls are in that revision. License notices,
firmware provenance, and the corresponding kernel source are recorded by
[`A3S-Lab/Box@46e17a8`](https://github.com/A3S-Lab/Box/commit/46e17a82e9a1034a627b2eebd01503c9d1f0e7bb)
under `src/deps/libkrun-sys`.

The Rust FFI declarations remain pinned to `a3s-libkrun-sys 3.1.0`. The import
library ABI is unchanged from that release; the runtime-owned archive prevents
a clean OCI Runtime checkout from loading the older WHPX DLL while the fixed
crate release is prepared.
