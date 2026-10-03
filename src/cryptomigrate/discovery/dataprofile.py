"""Data-at-rest profiling for the inventory - runs without any keys.

For each configured column/file set it samples stored values and applies block-size
forensics: ciphertext from a 64-bit block cipher (DES/3DES) always has a body length
that is a multiple of 8, and values whose length is 8 mod 16 cannot be AES output.
It also projects the stored size after migration, so too-narrow VARCHAR columns are
caught in Phase 2 instead of failing in Phase 6.
"""

from __future__ import annotations

from typing import Any

from ..config import Config
from ..crypto import legacy
from ..crypto.envelope import dearmor, is_armored, is_envelope, projected_length
from ..crypto.envelope import parse as parse_envelope
from .policy import Policy
from .scanner import Finding, fingerprint

ASSUMED_KEY_ID_LEN = 22  # e.g. "aes256-20261002-a1b2c3"


def _classify(value: Any, profile: legacy.LegacyProfile, storage: str) -> tuple[str, int | None]:
    if value is None or value in ("", b""):
        return "empty", None
    if isinstance(value, memoryview):
        value = value.tobytes()
    try:
        if storage == "text" and is_armored(value):
            parse_envelope(dearmor(value))
            return "v2", None
        if storage == "blob" and isinstance(value, (bytes, bytearray)) and is_envelope(bytes(value)):
            return "v2", None
        raw = legacy.decode(profile, value)
    except Exception:  # noqa: BLE001 - undecodable values are evidence too
        return "undecodable", None
    body = len(raw) - profile.prefix_overhead
    if body <= 0 or body % 8:
        return "undecodable", None
    return ("block64-only" if body % 16 == 8 else "block64-compatible"), body


def profile_sources(cfg: Config, policy: Policy, sample_size: int | None = None) -> tuple[list[Finding], list[dict]]:
    from ..migration.adapters import open_adapter

    findings: list[Finding] = []
    profiles: list[dict[str, Any]] = []
    rule = policy.rule("CM-DATA-001")
    size = sample_size or cfg.data_sample_size
    for ds in cfg.data_sources:
        try:
            adapter = open_adapter(ds)
        except Exception as exc:  # noqa: BLE001 - unreachable sources are an inventory gap, not a crash
            profiles.append({"source": ds.name, "status": "error", "error": str(exc)})
            continue
        with adapter:
            for target in adapter.targets():
                profile = cfg.legacy_profiles[target.legacy_profile]
                stats = {"sampled": 0, "empty": 0, "v2": 0, "block64-only": 0, "block64-compatible": 0,
                         "undecodable": 0}
                max_body = 0
                try:
                    values = adapter.sample(target.name, size)
                except Exception as exc:  # noqa: BLE001
                    profiles.append({"source": ds.name, "field": target.name, "status": "error", "error": str(exc)})
                    continue
                for value in values:
                    kind, body = _classify(value, profile, target.storage)
                    stats["sampled"] += 1
                    stats[kind] += 1
                    max_body = max(max_body, body or 0)
                legacy_count = stats["block64-only"] + stats["block64-compatible"]
                projected = projected_length(max_body, ASSUMED_KEY_ID_LEN, target.storage == "text") if max_body else 0
                field_label = target.name if ds.adapter == "sql" else ds.glob
                record = {"source": ds.name, "system": ds.system, "field": field_label, "status": "ok",
                          "legacy_profile": target.legacy_profile, "declared_algorithm": profile.algorithm,
                          "stats": stats, "max_legacy_body_bytes": max_body,
                          "projected_max_length": projected, "max_length": target.max_length}
                profiles.append(record)
                if not legacy_count:
                    continue
                location = f"{ds.name}:{ds.table}.{target.name}" if ds.adapter == "sql" else f"{ds.name}:{ds.glob}"
                detail = (f"{legacy_count}/{stats['sampled']} sampled values look like 64-bit-block ciphertext "
                          f"({stats['block64-only']} cannot be AES output); {stats['v2']} already migrated")
                if target.max_length and projected > target.max_length:
                    detail += f"; projected AES-GCM size {projected} exceeds max_length {target.max_length}"
                findings.append(Finding(
                    rule_id=rule.id, title=rule.title, category="data", algorithm=profile.algorithm,
                    severity=rule.severity_for(profile.algorithm),
                    confidence="high" if stats["block64-only"] else rule.confidence, location=location,
                    mode=profile.mode, detail=detail, fingerprint=fingerprint(rule.id, location, ""),
                    system=ds.system, cwe=list(rule.cwe), remediation=rule.remediation.replace("<name>", ds.name),
                    evidence=record, layer=rule.pack))
    return findings, profiles
