"""Phase 7 attestation: compliance evidence package with a SHA-256 manifest.

The package bundles every artifact an auditor needs, a control-by-control evidence map,
and a manifest of hashes. Its digest - and the audit-log head hash at that moment - are
written to the audit log, anchoring both. Sign the zip (gpg / Sigstore cosign) or attach
it to a release for an external timestamp.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from .. import __version__
from ..audit import AuditLog
from ..config import Config
from ..util import (
    canonical_json,
    isotime,
    md_table,
    read_json,
    sha256_bytes,
    sha256_file,
    utcnow,
    write_json,
    write_text,
)

EVIDENCE_MAP = [
    ("NIST SP 800-131A Rev. 2", "No DES/TDEA used to apply protection", "verification/verification.json"),
    ("PCI DSS 4.0.1 Req. 12.3.3", "Inventory of cipher suites & protocols", "cbom.cdx.json, inventory.md"),
    ("PCI DSS 4.0.1 Req. 3.6.1 / 3.7", "Key-management procedures & lifecycle", "plan/key-management-plan.md, "
                                                                                 "keys.json, audit.log"),
    ("PCI DSS 4.0.1 Req. 4.2.1", "Strong cryptography for transmission", "verification (TLS probes)"),
    ("NIST SP 800-53 SC-12 / SC-13", "Key management; approved cryptography (KATs)",
     "validation/validation-report.json, keys.json"),
    ("NIST SP 800-53 SC-28 / SC-8", "Protection at rest / in transit", "runs/*.json, verification/verification.json"),
    ("NIST SP 800-53 CM-8", "System component (crypto asset) inventory", "inventory.json, cbom.cdx.json"),
    ("NIST SP 800-53 AU-9", "Protection of audit information", "audit.log (hash chain verified)"),
    ("ISO/IEC 27001:2022 A.8.24", "Use of cryptography & key management", "plan/key-management-plan.md, policy"),
    ("NIST CSF 2.0 ID.AM-07 / PR.DS-01 / PR.DS-02", "Data inventory; data at rest & in transit protected",
     "inventory.json, verification/verification.json"),
    ("HIPAA 164.312(a)(2)(iv) / (e)(2)(ii)", "Encryption at rest / in transit", "verification/verification.json"),
    ("OWASP ASVS 4.0.3 V6.2.5", "No small-block ciphers or insecure modes in code", "verification/final-scan"),
]


def _collect(cfg: Config) -> list[Path]:
    base = cfg.artifacts_dir
    patterns = ["inventory.json", "inventory.md", "cbom.cdx.json", "cryptomigrate.sarif", "assessment.json",
                "assessment.md", "plan/**/*.md", "plan/*.json", "validation/*", "runs/*.json", "verification/**/*",
                "gates/*.json"]
    found: dict[Path, None] = {}
    for pattern in patterns:
        for path in sorted(base.glob(pattern)):
            if path.is_file():
                found[path] = None
    return list(found)


def build_attestation(cfg: Config, keys: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    out = cfg.artifact("attestation")
    out.mkdir(parents=True, exist_ok=True)
    verification_path = cfg.artifact("verification", "verification.json")
    verification = read_json(verification_path) if verification_path.exists() else None
    audit = AuditLog(cfg.audit_path)
    chain_ok, entries, chain_error = audit.verify()
    if keys is not None:
        write_json(out / "keys.json", {"generated": isotime(), "keys": keys})  # metadata only, never key material
    attested = bool(verification and verification["status"] == "pass" and chain_ok)
    files = _collect(cfg) + ([out / "keys.json"] if keys is not None else [])
    if cfg.audit_path.exists():
        files.append(cfg.audit_path)
    manifest_entries = [{"path": p.relative_to(cfg.root).as_posix() if p.is_relative_to(cfg.root) else str(p),
                         "sha256": sha256_file(p), "bytes": p.stat().st_size} for p in files]
    digest = sha256_bytes(canonical_json(manifest_entries))
    statement = {
        "schema": "cryptomigrate-attestation/1", "generated": isotime(), "tool_version": __version__,
        "project": cfg.project, "attested": attested,
        "verification_status": verification["status"] if verification else "missing",
        "audit": {"chain_ok": chain_ok, "entries": entries, "error": chain_error, "head": audit.head()},
        "evidence_digest": digest, "evidence": manifest_entries,
    }
    write_json(out / "evidence-manifest.json", statement)
    p = cfg.project
    status_line = ("**ATTESTED** - final verification passed and the audit chain is intact." if attested else
                   "**NOT ATTESTED** - final verification is missing or failing, or the audit chain is broken. "
                   "This package documents the current state only.")
    checks = verification["checks"] if verification else []
    md = [
        f"# Cryptographic migration attestation - {p.get('name') or 'project'}", "",
        f"Organization: {p.get('organization') or '-'} - generated {statement['generated']} - "
        f"cryptomigrate {__version__}", "", status_line, "",
        "## Statement", "",
        "The systems in scope were inventoried, migrated and verified as described in the evidence below. "
        "DES and Triple-DES (TDEA) are no longer used to apply cryptographic protection; data at rest is protected "
        f"with {cfg.target_algorithm} and verified record-by-record.", "",
        "## Verification results", "",
        md_table(["Check", "Status", "Detail"], [[c["id"], c["status"].upper(), c["detail"]] for c in checks])
        if checks else "_No verification report found - run `cryptomigrate verify`._", "",
        "## Control-by-control evidence map", "",
        md_table(["Framework / control", "Objective", "Evidence"], EVIDENCE_MAP), "",
        "## Integrity", "",
        f"* Evidence manifest digest (SHA-256): `{digest}`",
        f"* Audit log head hash: `{statement['audit']['head']}` ({entries} entries, chain "
        f"{'intact' if chain_ok else 'BROKEN: ' + str(chain_error)})", "",
        "## Sign-off", "",
        md_table(["Role", "Name", "Signature", "Date"],
                 [["Executive Sponsor", p.get("sponsor") or "", "", ""],
                  ["CISO / Security Lead", p.get("security_lead") or "", "", ""],
                  ["Compliance / Internal Audit", "", "", ""]]), "",
    ]
    write_text(out / "ATTESTATION.md", "\n".join(md))
    package = out / f"evidence-{utcnow().strftime('%Y%m%dT%H%M%SZ')}.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in [*files, out / "evidence-manifest.json", out / "ATTESTATION.md"]:
            arc = path.relative_to(cfg.root).as_posix() if path.is_relative_to(cfg.root) else path.name
            zf.write(path, arc)
    audit.append("attest.generate", attested=attested, evidence_digest=digest, package=package.name,
                 files=len(manifest_entries))
    return {**statement, "package": str(package), "evidence": len(manifest_entries)}


def summarize_json(statement: dict[str, Any]) -> str:
    return json.dumps({k: statement[k] for k in ("attested", "verification_status", "evidence_digest", "package")},
                      indent=2)
