# Release verification

A full Runtime tag produced by the current release workflow publishes five
platform archives, `SHA256SUMS`, and one portable Sigstore bundle named
`a3s-oci-runtime-<tag>-provenance.sigstore.json`. The release workflow creates
one signed SLSA build-provenance attestation whose subjects are the five
archives and `SHA256SUMS`. Every external Action in that release workflow is
pinned to an immutable commit rather than a movable tag or branch.

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

## Linux package qualification

Each Linux host archive contains
`qualification/native-linux-package.json` with schema
`a3s.oci.native-linux-package-qualification.v3`. The tag workflow creates this
report before compression by running the staged musl CLI and Agent, not Cargo
development binaries. The gate verifies the package layout and all three
static ELF executables, removes `/dev/kvm` across the lifecycle portion, and
runs the complete Native Linux SDK, rootless, owner-death, Hook-recovery,
OAR-01 network-enforcement, fault-cleanup, and OAR-02 pause/resume recovery
soak matrix.

The report binds the source commit, workflow run, Linux architecture and
kernel, `native-linux` driver, `shared-host-kernel` isolation class, exact test
profile, runtime version, and SHA-256 digest and size of the CLI, Agent, and
containerd shim. Its `evidence` array binds the retained Features, soak,
rootful recovery, Hook recovery, rootless recovery, rootless device-policy,
OAR-01 network-enforcement, and KVM-absence records. Soak schema v2 retains
every exact Pause and Resume operation ID, both post-reopen response replays,
and the frozen and resumed workload counters for all 100 lifecycles. After
verifying the outer archive provenance, inspect the package report with:

```bash
jq --exit-status \
  '.schema_version == "a3s.oci.native-linux-package-qualification.v3"
   and .status == "available"
   and .static_elf_verified
   and .kvm_absent_before_lifecycle
   and .full_sdk_matrix_completed
   and .oar02_pause_resume_verified
   and (.evidence | length == 8)' \
  a3s-oci-runtime-vX.Y.Z-linux-*/qualification/native-linux-package.json
```

This report qualifies the packaged Native mechanism only. It does not turn
the `probe-only` driver into a supported capability or substitute the separate
A3S Box consumer, upstream OCI, security, upgrade, rollback, and long-running
release gates.

## Native Linux CRIU checkpoint qualification

CRIU is host-provided and is not bundled into the Runtime archive. The initial
`native-linux-criu` checkpoint format therefore has a separate rootful gate
that binds the exact CRIU, CLI, Agent, source commit, driver-build digest, and
resulting immutable artifact:

```bash
A3S_OCI_NATIVE_RUNTIME_BINARY=/absolute/path/to/a3s-oci \
  A3S_OCI_NATIVE_AGENT_BINARY=/absolute/path/to/a3s-oci-agent \
  A3S_OCI_CRIU_BINARY=/absolute/path/to/criu \
  A3S_QUALIFICATION_SOURCE_COMMIT=<40-character-commit> \
  A3S_OCI_NATIVE_CHECKPOINT_REPORT=/absolute/path/to/checkpoint.json \
  A3S_OCI_NATIVE_CHECKPOINT_PIDNS_REPORT=/absolute/path/to/checkpoint-pidns.json \
  A3S_OCI_NATIVE_CHECKPOINT_NETNS_REPORT=/absolute/path/to/checkpoint-netns.json \
  bash .github/scripts/native-linux-checkpoint.sh
```

The positive report schema is
`a3s.oci.native-linux-checkpoint-smoke.v2`. It proves atomic no-replace
publication, checkpoint and restore replay after response-loss faults, exact
artifact digest and size, paused-source preservation and resume, exact newer
paused-generation restore, restored resume and exit, caller-artifact
immutability and survival, and scoped cleanup. Companion unavailable reports
prove the version-1 private-PID-namespace and configured-network-namespace
rejections. Default Features must still omit Checkpoint and Restore, while the
explicit CRIU-qualified driver advertises both operations.

These three reports are not yet members of
`a3s.oci.native-linux-package-qualification.v3` and are not covered merely by
verifying a release archive's provenance. Retain them beside the exact host
and CRIU identity when evaluating the experimental checkpoint profile.
Driver-local cross-process restore replay, broader source profiles,
multi-architecture package qualification, security, upgrade, rollback, and
release soak remain open.
