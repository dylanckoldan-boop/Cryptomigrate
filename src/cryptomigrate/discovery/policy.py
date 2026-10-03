"""Policy packs: algorithm metadata, compliance mappings and detection rules (see policies/*.yaml)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from ..config import glob_match
from ..util import severity_rank

BUILTIN_PACKAGE = "cryptomigrate.policies"


class PolicyError(ValueError):
    pass


@dataclass
class Rule:
    id: str
    title: str
    category: str
    files: list[str] = field(default_factory=list)
    pattern: re.Pattern | None = None
    algorithm: str | None = None
    severity: Any = "medium"
    confidence: str = "medium"
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    remediation: str = ""
    validator: str | None = None
    fix: str | None = None
    fix_files: list[str] = field(default_factory=list)
    synthetic: bool = False
    pack: str = ""

    def applies_to(self, relpath: str) -> bool:
        return not self.synthetic and any(glob_match(relpath, g) for g in self.files)

    def can_fix(self, relpath: str) -> bool:
        return bool(self.fix) and any(glob_match(relpath, g) for g in (self.fix_files or self.files))

    def severity_for(self, algorithm: str | None) -> str:
        if isinstance(self.severity, dict):
            if algorithm in self.severity:
                return str(self.severity[algorithm])
            return str(max(self.severity.values(), key=severity_rank))
        return str(self.severity or "medium")


@dataclass
class Policy:
    id: str
    name: str
    version: str
    description: str
    target_algorithm: str
    legacy_algorithms: list[str]
    normalization: list[dict[str, Any]]
    algorithms: dict[str, dict[str, Any]]
    compliance: dict[str, dict[str, Any]]
    rules: list[Rule]
    source: str
    packs: list[dict[str, Any]] = field(default_factory=list)
    pack_normalization: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def rule(self, rule_id: str) -> Rule:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise PolicyError(f"policy {self.id} has no rule {rule_id}")

    def has_rule(self, rule_id: str) -> bool:
        return any(r.id == rule_id for r in self.rules)

    def normalize(self, name: str | None, pack: str | None = None) -> str | None:
        """Map a captured name to a canonical algorithm, using the rule's own pack's normalization table."""
        if not name:
            return None
        compact = re.sub(r"[^a-z0-9]", "", name.lower())
        table = self.pack_normalization.get(pack, []) if pack and pack != self.id else self.normalization
        for entry in table:
            if any(marker in compact for marker in entry.get("markers", [])):
                return entry["algorithm"]
        return None

    def algorithm_meta(self, algorithm: str) -> dict[str, Any]:
        return self.algorithms.get(algorithm, {})


def builtin_policies() -> list[str]:
    return sorted(p.name[:-5] for p in resources.files(BUILTIN_PACKAGE).iterdir() if p.name.endswith(".yaml"))


def _parse(data: dict[str, Any], source: str) -> Policy:
    rules = []
    seen = set()
    for raw in data.get("rules") or []:
        rule_id = raw.get("id")
        if not rule_id or rule_id in seen:
            raise PolicyError(f"{source}: every rule needs a unique id ({raw.get('title')!r})")
        seen.add(rule_id)
        pattern = None
        if not raw.get("synthetic"):
            try:
                pattern = re.compile(raw["pattern"])
            except (KeyError, re.error) as exc:
                raise PolicyError(f"{source}: rule {rule_id} has an invalid pattern: {exc}") from exc
        rules.append(Rule(
            id=rule_id, title=raw.get("title", rule_id), category=raw.get("category", "source"),
            files=list(raw.get("files") or []), pattern=pattern, algorithm=raw.get("algorithm"),
            severity=raw.get("severity", "medium"), confidence=raw.get("confidence", "medium"),
            cwe=list(raw.get("cwe") or []), cve=list(raw.get("cve") or []),
            remediation=" ".join(str(raw.get("remediation", "")).split()), validator=raw.get("validator"),
            fix=raw.get("fix"), fix_files=list(raw.get("fix_files") or []), synthetic=bool(raw.get("synthetic")),
            pack=str(data.get("id", "")),
        ))
    for key in ("id", "name", "target_algorithm"):
        if not data.get(key):
            raise PolicyError(f"{source}: policy is missing '{key}'")
    return Policy(
        id=data["id"], name=data["name"], version=str(data.get("version", "0")),
        description=" ".join(str(data.get("description", "")).split()), target_algorithm=data["target_algorithm"],
        legacy_algorithms=list(data.get("legacy_algorithms") or []),
        normalization=list(data.get("normalization") or []),
        algorithms=dict(data.get("algorithms") or {}),
        compliance={k: {**v, "pack": data["id"]} for k, v in (data.get("compliance") or {}).items()}, rules=rules,
        source=source, packs=[{"id": data["id"], "name": data["name"], "version": str(data.get("version", "0")),
                               "source": source}],
        pack_normalization={data["id"]: list(data.get("normalization") or [])},
    )


def load_policy_set(primary: str, layers: list[str] | None = None, root: Path | None = None) -> Policy:
    """The migration pack plus security-layer packs, merged into one rule set (layer findings keep their pack id)."""
    base = load_policy(primary, root)
    for ref in layers or []:
        extra = load_policy(ref, root)
        known = {r.id for r in base.rules}
        clash = sorted(r.id for r in extra.rules if r.id in known)
        if clash:
            raise PolicyError(f"layer {extra.id} redefines rules {clash}")
        base.rules.extend(extra.rules)
        for name, meta in extra.algorithms.items():
            base.algorithms.setdefault(name, meta)
        for key, spec in extra.compliance.items():
            base.compliance[key if key not in base.compliance else f"{extra.id}:{key}"] = spec
        base.pack_normalization.update(extra.pack_normalization)
        base.packs.extend(extra.packs)
    return base


def load_policy(ref: str, root: Path | None = None) -> Policy:
    """Load a built-in policy pack by id (e.g. ``des-to-aes``) or a YAML file by path."""
    candidates = [Path(ref)]
    if root is not None:
        candidates.insert(0, Path(root) / ref)
    for path in candidates:
        if path.suffix in (".yaml", ".yml") and path.exists():
            return _parse(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, str(path))
    resource = resources.files(BUILTIN_PACKAGE).joinpath(f"{ref}.yaml")
    if not resource.is_file():
        raise PolicyError(f"unknown policy {ref!r}; built-in packs: {builtin_policies()}")
    return _parse(yaml.safe_load(resource.read_text(encoding="utf-8")) or {}, f"builtin:{ref}")
