"""Automated configuration remediation for TLS and SSH cipher lists.

Only changes that are safe to make unilaterally are automated. Settings that must match a
peer - IPsec/IKE proposals, Kerberos enctypes, SNMPv3, network devices - are never
auto-applied, because changing one side drops the tunnel or realm; they go to the runbook.

Dry-run (default) prints a unified diff. ``--apply`` backs each file up under
``.cryptomigrate/backups/<run-id>/files/``, writes atomically, re-scans the new text to prove
the finding is gone, records a manifest and is reversible with ``cryptomigrate rollback``.
"""

from __future__ import annotations

import difflib
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .audit import AuditLog
from .config import Config
from .discovery.ciphers import FIXERS, IANA_DES, VALIDATORS
from .discovery.policy import Policy
from .util import actor, isotime, new_run_id, read_json, sha256_bytes, sha256_file, write_json


@dataclass
class FileChange:
    path: Path
    relpath: str
    before: str
    after: str
    bom: bool = False
    changes: list[dict[str, Any]] = field(default_factory=list)

    def diff(self) -> str:
        return "".join(difflib.unified_diff(self.before.splitlines(keepends=True), self.after.splitlines(keepends=True),
                                            fromfile=f"a/{self.relpath}", tofile=f"b/{self.relpath}"))


def _still_vulnerable(rule, line: str) -> bool:
    match = rule.pattern.search(line)
    if match is None:
        return False
    if rule.validator == "iana-suite":
        return bool(IANA_DES.search(line))
    if rule.validator:
        return VALIDATORS[rule.validator](match, line) is not None
    return True


def plan_remediation(cfg: Config, policy: Policy, findings: list[dict[str, Any]],
                     only_rules: set[str] | None = None, only_paths: list[str] | None = None
                     ) -> tuple[list[FileChange], list[dict[str, Any]]]:
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        if f.get("suppressed") or f.get("exception") or not f.get("fixable") or not f.get("line"):
            continue
        if only_rules and f["rule_id"] not in only_rules:
            continue
        if only_paths and not any(f["location"].startswith(p.rstrip("/")) for p in only_paths):
            continue
        by_file.setdefault(f["location"], []).append(f)
    changes, manual = [], []
    for rel, items in sorted(by_file.items()):
        path = Path(rel) if Path(rel).is_absolute() else cfg.root / rel
        try:
            raw = path.read_bytes()
            bom = raw.startswith(b"\xef\xbb\xbf")
            text = raw[3 if bom else 0:].decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            manual += [{**f, "reason": f"cannot read as UTF-8: {exc}"} for f in items]
            continue
        lines = text.splitlines(keepends=True)
        change = FileChange(path, rel, text, text, bom)
        for f in sorted(items, key=lambda x: x["line"]):
            index = f["line"] - 1
            if index >= len(lines):
                manual.append({**f, "reason": "file changed since discovery - re-run discover"})
                continue
            original = lines[index]
            body = original.rstrip("\r\n")
            ending = original[len(body):]
            rule = policy.rule(f["rule_id"])
            match = rule.pattern.search(body)
            if match is None:
                manual.append({**f, "reason": "line changed since discovery - re-run discover"})
                continue
            fixed = FIXERS[rule.fix](body, match)
            if fixed is None or fixed == body:
                manual.append({**f, "reason": "no safe automatic fix (would leave no ciphers / needs a human)"})
                continue
            if _still_vulnerable(rule, fixed):
                manual.append({**f, "reason": "fix did not clear the finding - left unchanged"})
                continue
            lines[index] = fixed + ending
            change.changes.append({"line": f["line"], "rule_id": rule.id, "before": body.strip(),
                                   "after": fixed.strip()})
        change.after = "".join(lines)
        if change.changes:
            changes.append(change)
    return changes, manual


def apply_remediation(cfg: Config, changes: list[FileChange], change_ticket: str | None = None,
                      approver: str | None = None) -> dict[str, Any]:
    if cfg.governance.get("require_change_ticket") and not change_ticket:
        raise RuntimeError("governance.require_change_ticket is set - pass --change-ticket (NFR-04)")
    run_id = new_run_id("remediate")
    backup_root = cfg.state("backups", run_id, "files")
    files = []
    for change in changes:
        backup = backup_root / change.relpath.lstrip("/")
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(change.path, backup)
        data = (b"\xef\xbb\xbf" if change.bom else b"") + change.after.encode("utf-8")
        tmp = change.path.with_name(f".{change.path.name}.cm-tmp-{os.getpid()}")
        tmp.write_bytes(data)
        shutil.copymode(change.path, tmp)
        os.replace(tmp, change.path)
        files.append({"relpath": change.relpath, "path": str(change.path), "backup": str(backup),
                      "sha256_before": sha256_file(backup), "sha256_after": sha256_bytes(data),
                      "changes": change.changes})
    manifest = {"run_id": run_id, "type": "remediate", "tool_version": __version__, "mode": "apply",
                "status": "completed", "started": isotime(), "finished": isotime(), "operator": actor(),
                "change_ticket": change_ticket, "approver": approver, "files": files}
    write_json(cfg.artifact("runs", f"{run_id}.json"), manifest)
    AuditLog(cfg.audit_path).append("remediate.apply", run_id=run_id, change_ticket=change_ticket, approver=approver,
                                    files=[f["relpath"] for f in files],
                                    changes=sum(len(f["changes"]) for f in files))
    return manifest


def rollback_remediation(cfg: Config, run_id: str, change_ticket: str | None = None) -> dict[str, Any]:
    path = cfg.artifact("runs", f"{run_id}.json")
    manifest = read_json(path)
    if manifest.get("status") == "rolled-back":
        raise RuntimeError(f"run {run_id} was already rolled back")
    restored, conflicts = 0, []
    for f in manifest["files"]:
        target = Path(f["path"])
        if target.exists() and sha256_file(target) == f["sha256_after"]:
            shutil.copy2(f["backup"], target)
            restored += 1
        else:
            conflicts.append({"relpath": f["relpath"], "reason": "file changed after remediation - left untouched"})
    manifest["status"] = "rolled-back"
    manifest["rollback"] = {"at": isotime(), "operator": actor(), "change_ticket": change_ticket,
                            "restored": restored, "conflicts": conflicts}
    write_json(path, manifest)
    AuditLog(cfg.audit_path).append("remediate.rollback", run_id=run_id, restored=restored, conflicts=len(conflicts),
                                    change_ticket=change_ticket)
    return manifest
