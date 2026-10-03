"""Source-code and configuration scanner (Phase 2: Discovery / cryptographic inventory).

Suppression mechanisms (all recorded in the inventory for auditors, never silently dropped):

* ``.cryptomigrateignore`` - gitignore-style globs for paths that must not be scanned
* inline ``cryptomigrate: ignore[=RULE,...] -- justification`` on the line or the line above
* file-level ``cryptomigrate: ignore-file[=RULE,...] -- justification`` in the first 20 lines
* governance exceptions in migration.yaml (risk acceptance with approver and expiry date)
"""

from __future__ import annotations

import bisect
import codecs
import hashlib
import math
import os
import re
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..config import glob_match
from ..util import parse_date, utcnow
from .ciphers import VALIDATORS
from .policy import Policy, Rule

IGNORE_FILE = ".cryptomigrateignore"
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z",
    ".jar", ".war", ".ear", ".class", ".so", ".dll", ".dylib", ".exe", ".bin", ".o", ".a", ".lib", ".pyc", ".whl",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".docx", ".xlsx", ".pptx", ".db",
    ".sqlite", ".sqlite3", ".enc", ".der", ".p12", ".pfx", ".jks", ".keystore",
}
SUPPRESS_RE = re.compile(r"cryptomigrate:\s*ignore(?P<file>-file)?(?:=(?P<rules>[A-Za-z0-9_,\-]+))?"
                         r"(?:\s*--\s*(?P<reason>[^\n]*))?")
_MODE_HINT = re.compile(r"(cbc|ecb|cfb|ofb|ctr|gcm)", re.I)
_QUOTED = re.compile(r"""(['"])([A-Za-z0-9+/=]{20,})\1""")
_LONG_HEX = re.compile(r"\b[0-9A-Fa-f]{32,}\b")


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str  # source | config | protocol | data | manual
    algorithm: str
    severity: str
    confidence: str
    location: str  # repo-relative path, host:port, data source/column, or asset name
    line: int | None = None
    column: int | None = None
    mode: str | None = None
    snippet: str = ""
    detail: str = ""
    fingerprint: str = ""
    system: str | None = None
    suppressed: bool = False
    suppression: str | None = None
    exception: str | None = None
    fixable: bool = False
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    layer: str = ""

    @property
    def active(self) -> bool:
        return not self.suppressed and not self.exception

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def _entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def redact(text: str) -> str:
    """Keep likely key material (long hex, high-entropy base64 literals) out of reports and SARIF."""
    text = _LONG_HEX.sub("<redacted-hex>", text)
    return _QUOTED.sub(lambda m: m.group(1) + "<redacted>" + m.group(1) if _entropy(m.group(2)) >= 4.0
                       else m.group(0), text)


def fingerprint(rule_id: str, location: str, line_text: str, occurrence: int = 0) -> str:
    normalized = " ".join(line_text.split())
    return hashlib.sha256(f"{rule_id}|{location}|{normalized}|{occurrence}".encode()).hexdigest()[:20]


def read_text(path: Path, max_size: int) -> str | None:
    try:
        if path.stat().st_size > max_size:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", "replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):  # e.g. regedit .reg exports
        return data.decode("utf-16", "replace")
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def load_ignore_patterns(*roots: Path) -> list[str]:
    patterns: list[str] = []
    for root in roots:
        candidate = Path(root) / IGNORE_FILE
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns


class Scanner:
    def __init__(self, policy: Policy, root: Path, exclude_dirs: Iterable[str] = (),
                 ignore_patterns: Iterable[str] = (), max_file_size: int = 2 * 1024 * 1024,
                 exclude_files: Iterable[Path] = ()):
        self.policy = policy
        self.root = Path(root).resolve()
        self.exclude_dirs = set(exclude_dirs)
        self.ignore_patterns = list(ignore_patterns)
        self.max_file_size = max_file_size
        self.exclude_files = {Path(p).resolve() for p in exclude_files}
        self.rules = [r for r in policy.rules if not r.synthetic]
        self.stats = {"files_scanned": 0, "files_skipped": 0, "files_ignored": 0, "duration_s": 0.0}

    # ----------------------------------------------------------------- walking
    def relpath(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.resolve().as_posix()

    def ignored(self, relpath: str) -> bool:
        return any(glob_match(relpath, p) for p in self.ignore_patterns)

    def walk(self, paths: Iterable[Path]) -> Iterator[tuple[Path, str]]:
        for base in paths:
            base = Path(base)
            if base.is_file():
                yield base, self.relpath(base)
                continue
            for dirpath, dirnames, filenames in os.walk(base):
                current = Path(dirpath)
                dirnames[:] = sorted(d for d in dirnames if d not in self.exclude_dirs
                                     and not self.ignored(self.relpath(current / d) + "/"))
                for name in sorted(filenames):
                    path = current / name
                    rel = self.relpath(path)
                    if path.resolve() in self.exclude_files or self.ignored(rel):
                        self.stats["files_ignored"] += 1
                        continue
                    yield path, rel

    # ---------------------------------------------------------------- scanning
    def scan(self, paths: Iterable[Path]) -> list[Finding]:
        started = time.monotonic()
        findings: list[Finding] = []
        for path, rel in self.walk(paths):
            rules = [r for r in self.rules if r.applies_to(rel)]
            if not rules or path.suffix.lower() in BINARY_EXT:
                continue
            text = read_text(path, self.max_file_size)
            if text is None:
                self.stats["files_skipped"] += 1
                continue
            self.stats["files_scanned"] += 1
            findings.extend(self.scan_text(text, rel, rules))
        self.stats["duration_s"] = round(time.monotonic() - started, 3)
        return findings

    def scan_text(self, text: str, relpath: str, rules: list[Rule] | None = None) -> list[Finding]:
        rules = rules if rules is not None else [r for r in self.rules if r.applies_to(relpath)]
        if not rules:
            return []
        line_starts = [0] + [m.end() for m in re.finditer("\n", text)]
        lines = text.split("\n")
        file_level = self._file_suppressions(lines[:20])
        occurrences: Counter = Counter()
        seen: set[tuple[str, int]] = set()  # one finding per rule per line
        out: list[Finding] = []
        for rule in rules:
            for match in rule.pattern.finditer(text):
                finding = self._finding(rule, match, text, relpath, line_starts, lines)
                if finding is None or (rule.id, finding.line) in seen:
                    continue
                seen.add((rule.id, finding.line))
                line_text = lines[finding.line - 1]
                key = (rule.id, " ".join(line_text.split()))
                finding.fingerprint = fingerprint(rule.id, relpath, line_text, occurrences[key])
                occurrences[key] += 1
                self._apply_inline_suppression(finding, rule, lines, file_level)
                out.append(finding)
        return out

    def _finding(self, rule: Rule, match: re.Match, text: str, relpath: str, line_starts: list[int],
                 lines: list[str]) -> Finding | None:
        groups = match.groupdict()
        raw_alg = next((v for k, v in groups.items() if k.startswith("alg") and v), None)
        raw_mode = next((v for k, v in groups.items() if k.startswith("mode") and v), None)
        primary = rule.pack in ("", self.policy.id)
        algorithm = self.policy.normalize(raw_alg, rule.pack) or rule.algorithm or (
            (self.policy.legacy_algorithms or ["?"])[-1] if primary else "n/a")
        if not raw_mode and raw_alg:
            hint = _MODE_HINT.search(raw_alg)
            raw_mode = hint.group(1) if hint else None
        refinement: dict[str, Any] = {}
        if rule.validator:
            check = VALIDATORS.get(rule.validator)
            if check is None:
                raise ValueError(f"rule {rule.id}: unknown validator {rule.validator}")
            refinement = check(match, text)
            if refinement is None:
                return None
        algorithm = refinement.get("algorithm", algorithm)
        mode = refinement.get("mode") or raw_mode
        line_no = bisect.bisect_right(line_starts, match.start())
        column = match.start() - line_starts[line_no - 1] + 1
        line_text = lines[line_no - 1]
        secret = groups.get("secret")
        shown = line_text.replace(secret, "<redacted>") if secret else line_text
        return Finding(
            rule_id=rule.id, title=rule.title, category=rule.category, algorithm=algorithm,
            severity=refinement.get("severity") or rule.severity_for(algorithm),
            confidence=refinement.get("confidence") or rule.confidence, location=relpath, line=line_no,
            column=column, mode=mode.upper() if mode else None,
            snippet=redact(shown.strip())[:240], detail=refinement.get("detail", ""),
            fixable=rule.can_fix(relpath), cwe=list(rule.cwe), cve=list(rule.cve), remediation=rule.remediation,
            layer=rule.pack or self.policy.id,
        )

    @staticmethod
    def _file_suppressions(head: list[str]) -> list[tuple[set[str] | None, str]]:
        out = []
        for line in head:
            for m in SUPPRESS_RE.finditer(line):
                if m.group("file"):
                    rules = set(m.group("rules").split(",")) if m.group("rules") else None
                    out.append((rules, _clean_reason(m.group("reason"))))
        return out

    @staticmethod
    def _apply_inline_suppression(finding: Finding, rule: Rule, lines: list[str],
                                  file_level: list[tuple[set[str] | None, str]]) -> None:
        for rules, reason in file_level:
            if rules is None or rule.id in rules:
                finding.suppressed, finding.suppression = True, reason or "file-level suppression (no justification)"
                return
        index = finding.line - 1
        for candidate in (lines[index], lines[index - 1] if index > 0 else ""):
            for m in SUPPRESS_RE.finditer(candidate):
                if m.group("file"):
                    continue
                rules = set(m.group("rules").split(",")) if m.group("rules") else None
                if rules is None or rule.id in rules:
                    finding.suppressed = True
                    finding.suppression = _clean_reason(m.group("reason")) or "inline suppression (no justification)"
                    return


def _clean_reason(reason: str | None) -> str:
    if not reason:
        return ""
    reason = reason.strip()
    for closer in ("*/", "-->", '"""', "'''"):
        if reason.endswith(closer):
            reason = reason[: -len(closer)].rstrip()
    return reason


def apply_exceptions(findings: list[Finding], exceptions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach governance exceptions (risk acceptances). Returns the expired ones for the gate/assessment."""
    today = utcnow().date()
    expired = []
    for exc in exceptions:
        expires = parse_date(exc.get("expires"))
        if expires is not None and expires < today:
            expired.append(exc)
            continue
        for finding in findings:
            if finding.exception:
                continue
            if exc.get("fingerprint") and exc["fingerprint"] == finding.fingerprint:
                finding.exception = exc.get("id", "exception")
            elif exc.get("rule") and exc.get("path") and exc["rule"] == finding.rule_id \
                    and glob_match(finding.location, exc["path"]):
                finding.exception = exc.get("id", "exception")
    return expired
