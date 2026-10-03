"""Shared helpers: time, hashing, JSON I/O, terminal output and placeholder detection."""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import json
import os
import re
import socket
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_WEIGHT = {"info": 0, "low": 2, "medium": 4, "high": 7, "critical": 10}
CRITICALITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CRITICALITIES = ("low", "medium", "high", "critical")


def severity_rank(sev: str | None) -> int:
    try:
        return SEVERITIES.index((sev or "info").lower())
    except ValueError:
        return 0


# --------------------------------------------------------------------------- time
def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


def isotime(dt: _dt.datetime | None = None) -> str:
    return (dt or utcnow()).isoformat().replace("+00:00", "Z")


def parse_isotime(value: str) -> _dt.datetime:
    dt = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=_dt.timezone.utc)


def parse_date(value: Any) -> _dt.date | None:
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def new_run_id(prefix: str) -> str:
    return f"{prefix}-{utcnow().strftime('%Y%m%dT%H%M%SZ')}-{os.urandom(3).hex()}"


def actor() -> str:
    """Identity recorded in audit entries (override with CRYPTOMIGRATE_ACTOR, e.g. in CI)."""
    explicit = os.environ.get("CRYPTOMIGRATE_ACTOR")
    if explicit:
        return explicit
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can raise several OS-specific errors
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


# ------------------------------------------------------------------------ hashing
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


# ---------------------------------------------------------------------------- I/O
def write_json(path: Path, obj: Any) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` (and parents); a directory created here is restricted to its owner (0700)."""
    path = Path(path)
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path, 0o700)
        except OSError:  # pragma: no cover - non-POSIX permission models
            pass
    return path


def write_text(path: Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)
    return path


# ------------------------------------------------------------------- placeholders
_PLACEHOLDER = re.compile(r"\[[^\]]*\]|YYYY-MM-DD|\bTBD\b|\bTODO\b", re.IGNORECASE)


def is_placeholder(value: Any) -> bool:
    """True for empty values and template placeholders such as "[Organization Name]"."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip() or bool(_PLACEHOLDER.search(value))
    if isinstance(value, (list, tuple, dict, set)):
        return len(value) == 0
    return False


# ------------------------------------------------------------------------ output
_COLORS = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36", "bold": "1",
           "dim": "2"}


def _use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def color(text: str, name: str) -> str:
    return f"\033[{_COLORS[name]}m{text}\033[0m" if _use_color() else text


SEVERITY_COLOR = {"critical": "magenta", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
STATUS_COLOR = {"pass": "green", "fail": "red", "warn": "yellow", "pending": "yellow", "skip": "dim", "ok": "green"}


def text_table(headers: Sequence[str], rows: Iterable[Sequence[Any]], max_width: int = 60) -> str:
    rows = [["" if v is None else str(v) for v in row] for row in rows]
    cells = [[h for h in headers], *rows]
    widths = [min(max_width, max(len(r[i]) for r in cells)) for i in range(len(headers))]

    def fmt(row: Sequence[str]) -> str:
        out = []
        for i, value in enumerate(row):
            value = value if len(value) <= widths[i] else value[: widths[i] - 1] + "\u2026"
            out.append(value.ljust(widths[i]))
        return "  ".join(out).rstrip()

    lines = [fmt(headers), "  ".join("-" * w for w in widths)]
    lines += [fmt(r) for r in rows]
    return "\n".join(lines)


def md_escape(value: Any) -> str:
    return str("" if value is None else value).replace("|", "\\|").replace("\n", " ")


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    out = ["| " + " | ".join(md_escape(h) for h in headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(md_escape(v) for v in row) + " |" for row in rows]
    return "\n".join(out)
