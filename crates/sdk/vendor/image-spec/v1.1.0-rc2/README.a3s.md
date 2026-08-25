# Vendored OCI Image Specification Reference

This directory pins the OCI Image Specification reference used by the OCI
Runtime Specification 1.3.0 annotation contract. The Runtime Specification
links to tag `v1.1.0-rc2`; that annotated tag resolves to commit
`19a74bcb54ba211005a68d85c6b359c2947721ce`.

The retained files are unmodified upstream sources:

| File | SHA-256 |
| --- | --- |
| `config.md` | `fac2d89de4130d18d393d4539c4db4827f16cba6d1f893fb743351b4595bc740` |
| `conversion.md` | `e3dc948043dc9ec16d4ca818d3af954377e48c9eb353ac554200480a953148ed` |
| `schema/config-schema.json` | `ddf035e2512daed6d501add9e69caeb187a2203a4595e994b03ff7cc203ee7bd` |
| `schema/defs.json` | `35246f51344bcb4e2cf30f968e234a4ae8dbd916ff1a3c490fe53c0b2518b82c` |
| `LICENSE` | `b0a3f39513927db306adabea11d14c23f079d4febcea241d123a68d1a0d45418` |

The SDK validates the runtime annotation values that have an unambiguous
mapping to an Image Configuration property. `os.features` remains outside
that claim because the image property is an array of strings while an OCI
Runtime annotation value must be a string, and the referenced conversion
document does not define a serialization for that array.
