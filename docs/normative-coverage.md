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
| `validated` | 25 | Exact semantic and bundle-validation rules with positive and negative SDK tests |
| `enforced` | 138 | Root `config.json` placement; required lifecycle arguments and operation set; valid, unique, and reusable container IDs; exact Query State results; post-create configuration immutability; the create-to-start process barrier; exact process launch and signal exit; scoped delete that removes owned resources while preserving external storage; start, kill, and delete state gates; required OCI State fields, Linux PID lifecycle, annotations, and schema; all six POSIX Hook phases with exact command, namespace, order, state-stdin, timeout, and failure policy; the four conditional Linux `/dev` links; all five process capability sets and `noNewPrivileges` with kernel and workload read-back; the 41-name capability feature registry; all 16 OCI rlimit mappings with exact soft/hard kernel read-back; and OCI `oomScoreAdj`, scheduler, and I/O-priority semantics enforced by the SDK transport, bundle loader, runtime lifecycle, and Linux executor |
| `pending-review` | 492 | Common, Linux, or VM entries awaiting exact evidence binding, including the two capability warning-policy requirements |

An occurrence is an inventory unit, not an assertion that the surrounding
sentence has already been implemented. Some common documents contain
platform-specific clauses; each pending entry still requires human
applicability review.

The exact capability-set requirements are enforced, but the adjacent warning
policy is not promoted. The current executor rejects a capability that cannot
be mapped or granted; OCI requires a warning and recommends continuing. Those
two occurrences stay `pending-review` until that behavior and its retained
warning evidence exist.

## Promotion

Each coverage item has an owner, disposition, rule IDs, and test IDs.
`validated`, `enforced`, `conformant`, and rejected-inapplicable claims require
non-empty rule and test evidence. The verifier rejects:

- a missing, extra, duplicate, or stale requirement;
- a changed document name, scope, or digest;
- an empty owner;
- empty or duplicate rule and test IDs;
- an implementation claim without both rule and test evidence.

Reviewed promotions live in
`conformance/oci-1.3.0-normative-evidence.json`. The generator applies that
small source-of-truth file to a fresh 764-entry baseline and produces
`conformance/oci-1.3.0-normative-coverage.json`. The SDK semantic-rule registry
and the owner-bound non-semantic rule registry are checked in both
directions: an evidence rule must exist, every non-semantic rule must retain
its declared owner, and every directly normative rule must have at least one
requirement binding.

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
3. generate a fresh schema baseline and apply reviewed normative evidence;
4. review every added, removed, or changed inventory item;
5. restore exact rule, owner, and test mappings only where the new release
   still has valid evidence;
6. run the full conformance and platform suites before raising support.

The normative generator rejects stale evidence instead of silently dropping
it. New or changed requirements remain `pending-review` until an explicit
binding is added.
