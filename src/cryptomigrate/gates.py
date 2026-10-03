"""Phase gates: the workplan's exit criteria, evaluated from evidence instead of opinion.

Each phase's exit criteria are the next phase's entry criteria. Automated criteria read
artifacts, the keystore and the audit log; manual criteria (approvals) are satisfied by a
sign-off recorded under ``governance.signoffs`` in migration.yaml - ideally merged through
a pull request approved by CODEOWNERS, which makes the approval itself auditable.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Config
from .crypto.selftest import selftest_ok
from .migration.engine import list_runs
from .util import is_placeholder, isotime, parse_date, parse_isotime, read_json, severity_rank, utcnow, write_json

PHASES = {1: "Initiation", 2: "Planning & Discovery", 3: "Analysis & Design", 4: "Development / Implementation",
          5: "Testing & Validation", 6: "Deployment / Phased Rollout", 7: "Post-Implementation & Closeout"}
SIGNOFFS = {1: ("charter", "Project charter approved by the executive sponsor"),
            2: ("inventory_validation", "Inventory validated by system/application owners"),
            3: ("design_review", "Target architecture & key-management design approved (CISO / architecture)"),
            4: ("code_review", "Security code review of cryptographic changes completed"),
            5: ("uat", "User acceptance testing signed off by application owners"),
            6: ("change_approval", "Production change approval (CAB) recorded"),
            7: ("closeout", "Sponsor formally accepts project closure")}


class _Gate:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.criteria: list[dict[str, Any]] = []

    def add(self, cid: str, text: str, ok: bool | None, evidence: str = "", warn: bool = False) -> None:
        status = "pass" if ok else ("warn" if warn else "fail")
        self.criteria.append({"id": cid, "type": "auto", "criterion": text, "status": status, "evidence": evidence})

    def manual(self, phase: int) -> None:
        gate, text = SIGNOFFS[phase]
        signoff = self.cfg.signoff(gate)
        status = "pass" if signoff else "fail"
        evidence = (f"{signoff['by']} on {signoff.get('date', '?')} {signoff.get('ref', '')}".strip() if signoff
                    else f"record governance.signoffs.{gate}: {{by, date, ref}} in migration.yaml")
        if signoff and self.cfg.governance.get("require_signed_commits"):
            ok, detail = signed_config_commit(self.cfg)  # approver authenticated by their commit signature
            status, evidence = ("pass" if ok else "fail"), f"{evidence} - {detail}"
        self.criteria.append({"id": f"P{phase}-SIGNOFF", "type": "manual", "criterion": text, "status": status,
                              "evidence": evidence})

    def artifact(self, cid: str, text: str, rel: str) -> dict[str, Any] | None:
        path = self.cfg.artifact(*rel.split("/"))
        if not path.exists():
            self.add(cid, text, False, f"missing {rel}")
            return None
        data = read_json(path) if path.suffix == ".json" else {}
        age_limit = int(self.cfg.governance.get("max_artifact_age_days", 30))
        generated = data.get("generated") if isinstance(data, dict) else None
        if generated:
            age = (utcnow() - parse_isotime(generated)).days
            self.add(cid, text, age <= age_limit, f"{rel} generated {generated} ({age} days old, limit {age_limit})")
        else:
            self.add(cid, text, True, f"{rel} present")
        return data if isinstance(data, dict) else {}


def _latest_full_runs(cfg: Config, mode: str, statuses: tuple[str, ...] | None = None) -> dict[str, dict[str, Any]]:
    """Latest full (non-canary) run per source, optionally only among runs with the given statuses."""
    latest: dict[str, dict[str, Any]] = {}
    for run in list_runs(cfg):  # ordered by start time, then file modification time
        if run.get("type") != "reencrypt" or run.get("mode") != mode or run.get("limit") is not None:
            continue
        if statuses is None or run.get("status") in statuses:
            latest[run["source"]] = run
    return latest


def signed_config_commit(cfg: Config) -> tuple[bool, str]:
    """Was the latest change to migration.yaml (and so its sign-offs) made in a cryptographically signed commit?"""
    if cfg.path is None:
        return False, "no config file"
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%G?%x09%GS", "--", cfg.path.name], cwd=cfg.root,
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"git unavailable: {exc}"
    if out.returncode != 0 or not out.stdout.strip():
        return False, f"{cfg.path.name} is not committed to a git repository"
    status, _, signer = out.stdout.strip().partition("\t")
    detail = f"last commit to {cfg.path.name}: signature {status}" + (f" by {signer}" if signer else "")
    return status in ("G", "U"), detail


def _active(f: dict[str, Any]) -> bool:
    return not f.get("suppressed") and not f.get("exception")


def _primary_findings(inventory: dict[str, Any], categories: set[str]) -> list[dict[str, Any]]:
    primary = inventory.get("policy", {}).get("id")
    return [f for f in inventory["findings"]
            if _active(f) and (f.get("layer") or primary) == primary and f["category"] in categories]


def _layer_blocking(cfg: Config, inventory: dict[str, Any], categories: set[str]) -> list[dict[str, Any]]:
    primary = inventory.get("policy", {}).get("id")
    threshold = severity_rank(cfg.layer_fail_on)
    return [f for f in inventory["findings"] if _active(f) and (f.get("layer") or primary) != primary
            and f["category"] in categories and severity_rank(f["severity"]) >= threshold]


def _rules_summary(findings: list[dict[str, Any]]) -> str:
    return ", ".join(f"{rule} x{n}" for rule, n in Counter(f["rule_id"] for f in findings).most_common(6)) or "none"


def evaluate_gate(cfg: Config, phase: int, keystore=None, keystore_error: str | None = None) -> dict[str, Any]:
    if phase not in PHASES:
        raise ValueError("phase must be 1..7")
    g = _Gate(cfg)
    inventory = None
    if phase == 1:
        p = cfg.project
        missing = [k for k in ("name", "organization", "sponsor", "project_manager", "security_lead")
                   if is_placeholder(p.get(k))]
        g.add("P1-CHARTER", "Charter fields populated (name, organization, sponsor, PM, security lead)", not missing,
              f"missing/placeholder: {missing}" if missing else "all populated")
        target = parse_date(p.get("target_completion"))
        g.add("P1-DATE", "Target completion date set", target is not None,
              str(target) if target else "project.target_completion must be YYYY-MM-DD")
        frameworks = p.get("compliance_frameworks") or []
        g.add("P1-FRAMEWORKS", "Applicable compliance frameworks declared", bool(frameworks),
              ", ".join(frameworks) or "project.compliance_frameworks is empty")
    elif phase == 2:
        inventory = g.artifact("P2-INVENTORY", "Cryptographic inventory generated and current", "inventory.json")
        g.add("P2-CBOM", "CycloneDX CBOM exported", cfg.artifact("cbom.cdx.json").exists(), "cbom.cdx.json")
        assessment = g.artifact("P2-ASSESS", "Gap & compatibility assessment generated", "assessment.json")
        if inventory is not None:
            unassigned = inventory["summary"]["by_system"].get("unassigned", 0)
            g.add("P2-OWNERSHIP", "Every active finding mapped to an owning system", unassigned == 0,
                  f"{unassigned} unassigned")
            bad = [p["endpoint"] for p in inventory.get("probes", []) if p["status"] in ("inconclusive", "unreachable")]
            g.add("P2-PROBES", "Every TLS endpoint conclusively probed", not bad, ", ".join(bad) or "all conclusive")
            errors = [d["source"] for d in inventory.get("data_profiles", []) if d.get("status") == "error"]
            g.add("P2-DATA", "Every data source profiled", not errors, ", ".join(errors) or "all profiled")
        if assessment is not None and inventory is not None:
            g.add("P2-FRESH", "Assessment built from the current inventory",
                  assessment.get("inventory_generated") == inventory.get("generated"),
                  f"assessment of {assessment.get('inventory_generated')}, inventory {inventory.get('generated')}")
        ownerless = [s.id for s in cfg.systems if is_placeholder(s.owner)]
        g.add("P2-OWNERS", "Every system has a named owner", not ownerless, ", ".join(ownerless) or "all named")
    elif phase == 3:
        g.add("P3-TARGET", "Target algorithm is authenticated AES (GCM)", cfg.target_algorithm.endswith("-GCM"),
              cfg.target_algorithm)
        if keystore is None:
            g.add("P3-KEYSTORE", "Keystore opens and holds an active AES key", False, keystore_error or "not opened")
        else:
            try:
                g.add("P3-KEYSTORE", "Keystore opens and holds an active AES key", True, keystore.active_key_id())
            except Exception as exc:  # noqa: BLE001
                g.add("P3-KEYSTORE", "Keystore opens and holds an active AES key", False, str(exc))
            needed = sorted({cfg.legacy_profiles[p].key_id for d in cfg.data_sources for p in d.profiles()})
            verification = cfg.artifact("verification", "verification.json")
            verified = verification.exists() and read_json(verification).get("status") == "pass"
            shredded = [k for k in needed if not keystore.has_material(k) and verified
                        and keystore.data["keys"].get(k, {}).get("state") == "destroyed"]
            absent = [k for k in needed if not keystore.has_material(k) and k not in shredded]
            g.add("P3-LEGACY-KEYS", "Legacy keys available to read existing data", not absent,
                  f"missing: {absent}" if absent else
                  (f"destroyed after verified migration: {shredded}" if shredded else ", ".join(needed) or "n/a"))
        plan_dir = cfg.artifact("plan")
        g.add("P3-PLAN", "Wave plan, runbooks and key-management plan generated",
              (plan_dir / "wave-plan.md").exists() and (plan_dir / "key-management-plan.md").exists(),
              str(plan_dir))
        g.add("P3-ROLLBACK", "Rollback path defined (column/file backups enabled)",
              bool(cfg.migration.get("backup", True)), f"migration.backup={cfg.migration.get('backup', True)}")
        assessment_path = cfg.artifact("assessment.json")
        narrow = [x["detail"] for x in read_json(assessment_path).get("gaps", []) if x["type"] == "column-too-narrow"] \
            if assessment_path.exists() else []
        g.add("P3-SCHEMA", "No column too narrow for AES-GCM output", not narrow, "; ".join(narrow) or "ok")
    elif phase == 4:
        g.add("P4-SELFTEST", "Cryptographic known-answer self-test passes", selftest_ok(), "cryptomigrate selftest")
        inv_path = cfg.artifact("inventory.json")
        if inv_path.exists():
            inventory = read_json(inv_path)
            code = _primary_findings(inventory, {"source"})
            g.add("P4-CODE", "No active DES/3DES in source code (latest inventory)", not code,
                  f"{len(code)} active source findings")
            if cfg.layers:
                blocking = _layer_blocking(cfg, inventory, {"source", "binary"})
                g.add("P4-LAYERS", f"No {cfg.layer_fail_on}+ security-layer findings in code or binaries "
                                   "(injection, memory safety, TLS verification, credentials)", not blocking,
                      _rules_summary(blocking))
        else:
            g.add("P4-CODE", "No active DES/3DES in source code (latest inventory)", False, "run discover")
        workflows = cfg.root / ".github" / "workflows"
        wired = any("cryptomigrate discover" in p.read_text(encoding="utf-8", errors="ignore")
                    for p in workflows.glob("*.y*ml")) if workflows.is_dir() else False
        g.add("P4-CI", "CI crypto gate blocks new DES/3DES (GitHub Actions)", wired,
              str(workflows) if wired else "add .github/workflows/crypto-gate.yml (cryptomigrate init --github)")
    elif phase == 5:
        report = g.artifact("P5-VALIDATION", "Validation suite report present and current",
                            "validation/validation-report.json")
        if report is not None:
            g.add("P5-VALIDATION-PASS", "All validation checks pass (KAT, tamper, AAD, no-fallback, NFR-01)",
                  report.get("status") == "pass", f"{report.get('summary')}")
        dry = _latest_full_runs(cfg, "dry-run")
        for ds in cfg.data_sources:
            run = dry.get(ds.name)
            ok = bool(run and run["status"] == "completed" and run["counters"]["errors"] == 0)
            g.add(f"P5-DRYRUN:{ds.name}", f"Full dry run of {ds.name} completed with zero errors", ok,
                  f"{run['run_id']}: {run['status']}, errors={run['counters']['errors']}, "
                  f"would migrate {run['counters']['would_migrate']}" if run else "no dry run recorded")
    elif phase == 6:
        applied = _latest_full_runs(cfg, "apply", ("completed",))  # rolled-back canaries do not count
        for ds in cfg.data_sources:
            run = applied.get(ds.name)
            ok = run is not None
            g.add(f"P6-APPLY:{ds.name}", f"Re-encryption of {ds.name} applied", ok,
                  f"{run['run_id']}: {run['status']} migrated={run['counters']['migrated']}" if run else "not applied")
        inv_path = cfg.artifact("inventory.json")
        if inv_path.exists():
            inventory = read_json(inv_path)
            remaining = _primary_findings(inventory, {"config", "protocol"})
            g.add("P6-CONFIG", "No active DES/3DES in configuration or on TLS endpoints", not remaining,
                  f"{len(remaining)} remaining (re-run discover after remediation)")
            if cfg.layers:
                blocking = _layer_blocking(cfg, inventory, {"config", "protocol", "certificate"})
                g.add("P6-LAYERS", f"No {cfg.layer_fail_on}+ security-layer findings in configuration, certificates, "
                                   "TLS endpoints or wireless", not blocking, _rules_summary(blocking))
    elif phase == 7:
        verification = g.artifact("P7-VERIFY", "Final verification report present and current",
                                  "verification/verification.json")
        if verification is not None:
            g.add("P7-VERIFY-PASS", "Final verification passed", verification.get("status") == "pass",
                  f"{verification.get('summary')}")
        if keystore is not None:
            remaining = keystore.legacy_keys()
            g.add("P7-KEYS", "Legacy DES/TDEA keys destroyed", not remaining, ", ".join(remaining) or "none remain")
        else:
            g.add("P7-KEYS", "Legacy DES/TDEA keys destroyed", False, keystore_error or "keystore not opened")
        ok, entries, error = AuditLog(cfg.audit_path).verify()
        g.add("P7-AUDIT", "Audit log hash chain intact", ok and entries > 0, error or f"{entries} entries")
        g.add("P7-STRICT", "Applications switched to strict (AES-only) mode", cfg.migration_mode == "strict",
              f"migration.mode={cfg.migration_mode}", warn=True)
        g.add("P7-ATTEST", "Attestation & evidence package generated",
              cfg.artifact("attestation", "evidence-manifest.json").exists(), "attestation/evidence-manifest.json")
    g.manual(phase)
    failed = [c for c in g.criteria if c["status"] == "fail"]
    return {"phase": phase, "name": PHASES[phase], "evaluated": isotime(), "status": "fail" if failed else "pass",
            "passed": sum(c["status"] == "pass" for c in g.criteria), "total": len(g.criteria),
            "criteria": g.criteria}


def write_gate(cfg: Config, result: dict[str, Any]) -> Path:
    path = write_json(cfg.artifact("gates", f"phase-{result['phase']}.json"), result)
    AuditLog(cfg.audit_path).append("gate.evaluate", phase=result["phase"], status=result["status"],
                                    passed=result["passed"], total=result["total"])
    return path
