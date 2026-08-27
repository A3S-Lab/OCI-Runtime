# Release verification

A full Runtime tag produced by the current release workflow publishes five
platform archives, `SHA256SUMS`, and one portable Sigstore bundle named
`a3s-oci-runtime-<tag>-provenance.sigstore.json`. The release workflow creates
one signed SLSA build-provenance attestation whose subjects are the five
archives and `SHA256SUMS`.

The provenance binds subject names and SHA-256 digests to the GitHub Actions
workflow identity. It does not establish that an experimental or probe-only
driver is supported, and it does not replace the real-host, containerd, OCI
conformance, security, upgrade, rollback, or soak gates.

## Verify with GitHub

Install a current GitHub CLI with the `gh attestation` commands, choose the tag
and archive, and download the release entries:

```bash
tag=vX.Y.Z
archive="a3s-oci-runtime-${tag}-linux-x86_64.tar.gz"
bundle="a3s-oci-runtime-${tag}-provenance.sigstore.json"

gh release download "$tag" \
  --repo A3S-Lab/OCI-Runtime \
  --pattern "$archive" \
  --pattern SHA256SUMS \
  --pattern "$bundle"
sha256sum --check --ignore-missing SHA256SUMS
```

Online verification fetches the repository attestation from GitHub and
requires both the expected signing workflow and tag source reference:

```bash
tag=vX.Y.Z
archive="a3s-oci-runtime-${tag}-linux-x86_64.tar.gz"

gh attestation verify "$archive" \
  --repo A3S-Lab/OCI-Runtime \
  --signer-workflow A3S-Lab/OCI-Runtime/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag"
```

Verify `SHA256SUMS` with the same command before treating its checksum result
as trusted.

## Verify offline

Fetch the trusted root while online and transfer it through the same trusted
channel as the verifier, not as an unverified release substitute:

```bash
gh attestation trusted-root > trusted_root.jsonl
```

On the offline machine, place the archive, release bundle, and trusted root in
the current directory, then run:

```bash
tag=vX.Y.Z
archive="a3s-oci-runtime-${tag}-linux-x86_64.tar.gz"
bundle="a3s-oci-runtime-${tag}-provenance.sigstore.json"

gh attestation verify "$archive" \
  --repo A3S-Lab/OCI-Runtime \
  --bundle "$bundle" \
  --custom-trusted-root trusted_root.jsonl \
  --signer-workflow A3S-Lab/OCI-Runtime/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag"
```

A successful result verifies the selected artifact against the signed
provenance. Keep enforcing the exact driver readiness returned by that
artifact's `a3s-oci features` command and the qualification records required
for the intended host and integration.
