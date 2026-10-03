"""Tamper-evident, hash-chained audit log (JSON Lines).

Every security-relevant action - key lifecycle events, configuration remediation,
re-encryption runs, rollbacks and phase-gate evaluations - appends an entry whose
SHA-256 hash covers the previous entry's hash (FR-05 / NFR-04, NIST SP 800-53 AU-9).
``cryptomigrate audit verify`` recomputes the chain: editing, deleting or reordering
any entry breaks it. Hash chaining makes tampering *evident*, not impossible - anchor
the head hash somewhere outside the operator's sole control (the attestation package,
a signed Git tag, a ticket) so that truncation is detectable as well.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .util import actor, canonical_json, ensure_private_dir, isotime, sha256_bytes

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def head(self) -> str:
        entries = self.entries()
        return entries[-1]["hash"] if entries else GENESIS

    def append(self, event: str, **details: Any) -> dict[str, Any]:
        ensure_private_dir(self.path.parent)
        entries = self.entries()
        entry: dict[str, Any] = {
            "seq": len(entries) + 1,
            "ts": isotime(),
            "actor": actor(),
            "event": event,
            "details": json.loads(json.dumps(details, default=str)),  # normalise to plain JSON types
            "prev": entries[-1]["hash"] if entries else GENESIS,
        }
        entry["hash"] = sha256_bytes(canonical_json(entry))
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def verify(self) -> tuple[bool, int, str | None]:
        """Return (ok, entries_checked, error)."""
        try:
            entries = self.entries()
        except json.JSONDecodeError as exc:
            return False, 0, f"unparseable audit line: {exc}"
        prev = GENESIS
        for index, entry in enumerate(entries, 1):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != index:
                return False, index, f"sequence break at entry {index} (entry removed or reordered)"
            if entry.get("prev") != prev:
                return False, index, f"chain break at entry {index}"
            if sha256_bytes(canonical_json(body)) != entry.get("hash"):
                return False, index, f"hash mismatch at entry {index} (entry modified)"
            prev = entry["hash"]
        return True, len(entries), None
