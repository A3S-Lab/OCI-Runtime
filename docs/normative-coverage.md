# OCI Normative Coverage

## Corpus

The conformance corpus is pinned to OCI Runtime Specification v1.3.0 commit
`92249139eea7161e13745abd4cb6d0ea02a3227a`. It contains the 15 Markdown
documents linked by that release's `spec.md` table of contents:

- common specification, principles, bundle, runtime, configuration, features,
  and glossary documents;
- Linux configuration, runtime, and features documents;
- VM configuration;
- FreeBSD, Solaris, Windows, and z/OS configuration documents.

Every document is embedded from `vendor/runtime-spec/v1.3.0/`. The checked-in
manifest records its SHA-256 digest, so CI fails if the source changes without
an explicit specification update.

## Inventory

`OciNormativeInventory` scans outside fenced examples and HTML comments. It
records every RFC 2119 keyword occurrence with:

- a content-derived SHA-256 ID;
- document and table-of-contents scope;
- source line and heading;
- keyword and same-line occurrence number;
- normalized source text.

The v1.3.0 corpus currently contains 764 entries:

| Disposition | Count | Meaning |
| --- | ---: | --- |
| `specification-definition` | 19 | Notational or glossary definitions |
| `rejected-inapplicable-platform` | 90 | Native FreeBSD, Solaris, Windows, or z/OS workload requirements rejected by the Linux-only workload boundary |
| `pending-review` | 655 | Common, Linux, or VM entries awaiting exact evidence binding |

An occurrence is an inventory unit, not an assertion that the surrounding
sentence has already been implemented. Some common documents contain
platform-specific clauses; each pending entry still requires human
applicability review.

## Promotion

Each coverage item has an owner, disposition, rule IDs, and test IDs.
`validated`, `enforced`, `conformant`, and rejected-inapplicable claims require
non-empty rule and test evidence. The verifier rejects:

- a missing, extra, duplicate, or stale requirement;
- a changed document name, scope, or digest;
- an empty owner;
- empty or duplicate rule and test IDs;
- an implementation claim without both rule and test evidence.

Promotion is monotonic in reviewed commits:

```text
pending-review -> validated -> enforced -> conformant
```

`validated` means static schema or semantic checks exist. `enforced` means the
selected executor or driver applies the behavior or fails. `conformant` also
requires lifecycle, negative, recovery, and retained upstream evidence.

## Update Workflow

For an intentional OCI release update:

1. replace the vendored corpus and schemas from one exact upstream commit;
2. update the supported version and provenance;
3. generate fresh schema and normative baselines;
4. review every added, removed, or changed inventory item;
5. restore exact rule, owner, and test mappings only where the new release
   still has valid evidence;
6. run the full conformance and platform suites before raising support.

The normative generator emits a baseline and resets applicable entries to
`pending-review`. It is not a routine formatting command and must not be used
to erase reviewed evidence.
