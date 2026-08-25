#!/usr/bin/env python3
"""Verify that the publishable Rust SDK carries exact OCI specification snapshots."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOTS = (
    (
        REPOSITORY_ROOT / "vendor/runtime-spec/v1.3.0",
        REPOSITORY_ROOT / "crates/sdk/vendor/runtime-spec/v1.3.0",
    ),
    (
        REPOSITORY_ROOT / "vendor/image-spec/v1.1.0-rc2",
        REPOSITORY_ROOT / "crates/sdk/vendor/image-spec/v1.1.0-rc2",
    ),
)


def inventory(root: Path) -> dict[str, str]:
    """Return a stable relative-path to SHA-256 inventory for one snapshot."""
    if not root.is_dir():
        raise FileNotFoundError(f"snapshot directory is missing: {root}")
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def main() -> int:
    failures: list[str] = []
    for source, packaged in SNAPSHOTS:
        source_inventory = inventory(source)
        packaged_inventory = inventory(packaged)
        if source_inventory != packaged_inventory:
            source_names = set(source_inventory)
            packaged_names = set(packaged_inventory)
            missing = sorted(source_names - packaged_names)
            extra = sorted(packaged_names - source_names)
            changed = sorted(
                name
                for name in source_names & packaged_names
                if source_inventory[name] != packaged_inventory[name]
            )
            failures.append(
                f"{packaged.relative_to(REPOSITORY_ROOT)} drifted: "
                f"missing={missing}, extra={extra}, changed={changed}"
            )

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Verified publishable SDK specification snapshots")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
