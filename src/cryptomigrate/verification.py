"""Phase 7 verification: prove that no DES/3DES remains anywhere in scope.

* fresh code/configuration scan - zero active findings (exceptions are disclosed, not hidden)
* TLS re-probe - every endpoint must positively refuse DES suites (unreachable = unverified)
* every stored value in every data source is a v2 AES-GCM envelope that authenticates
* the audit log chain is intact; remaining legacy keys are reported for destruction
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Config
from .discovery.policy import Policy
from .discovery.run import run_discovery
from .migration.engine import MigrationEngine
from .reporting.formats import write_inventory
from .util import isotime, md_table, severity_rank, write_json, write_text


def run_verification(cfg: Config, policy: Policy, keystore=None, probe_tls: bool = True) -> dict[str, Any]:
    inventory = run_discovery(cfg, policy, probe_tls=probe_tls, profile_data=False)
    write_inventory(cfg, inventory, policy, ("json", "cbom", "md"), cfg.artifact("verification", "final-scan"))
    findings = inventory["findings"]
    primary = inventory["policy"]["id"]
    live = [f for f in findings if not f.get("suppressed") and not f.get("exception")]
    active = [f for f in live if (f.get("layer") or primary) == primary]
    checks: list[dict[str, Any]] = [{
        "id": "VER-SCAN", "title": "No active DES/3DES in source code, configuration or manual inventory",
        "status": "pass" if not active else "fail",
        "detail": f"{len(active)} active, {sum(1 for f in findings if f.get('exception'))} under exception, "
                  f"{sum(1 for f in findings if f.get('suppressed'))} suppressed",
    }]
    if cfg.layers:
        threshold = severity_rank(cfg.layer_fail_on)
        blocking = [f for f in live
                    if (f.get("layer") or primary) != primary and severity_rank(f["severity"]) >= threshold]
        by_layer = ", ".join(f"{layer}: {sum(1 for f in blocking if f.get('layer') == layer)}" for layer in cfg.layers)
        checks.append({"id": "VER-LAYERS", "title": f"No {cfg.layer_fail_on}+ findings in the security layers",
                       "status": "pass" if not blocking else "fail", "detail": by_layer})
    for probe in inventory.get("probes", []):
        checks.append({"id": f"VER-TLS:{probe['endpoint']}", "title": f"TLS endpoint {probe['endpoint']} refuses DES",
                       "status": "pass" if probe["status"] == "not-accepted" else "fail",
                       "detail": f"{probe['status']}: {probe.get('detail', '')}"})
    data_results = []
    if cfg.data_sources:
        if keystore is None:
            checks.append({"id": "VER-DATA", "title": "Data at rest verified", "status": "fail",
                           "detail": "keystore unavailable (set the KEK) - data cannot be verified"})
        else:
            engine = MigrationEngine(cfg, keystore)
            for ds in cfg.data_sources:
                result = engine.verify_source(ds)
                data_results.append(result)
                checks.append({"id": f"VER-DATA:{ds.name}", "title": f"All values in {ds.name} are AES-GCM v2",
                               "status": result["status"] if result["status"] != "error" else "fail",
                               "detail": result.get("message") or f"{result['v2']}/{result['total'] - result['empty']} "
                                                                 f"v2, {result['legacy']} legacy, "
                                                                 f"{result['invalid']} invalid"})
    ok, entries, error = AuditLog(cfg.audit_path).verify()
    checks.append({"id": "VER-AUDIT", "title": "Audit log hash chain intact", "status": "pass" if ok else "fail",
                   "detail": error or f"{entries} entries verified"})
    legacy_keys = keystore.legacy_keys() if keystore is not None else []
    checks.append({"id": "VER-LEGACY-KEYS", "title": "Legacy DES/TDEA keys destroyed",
                   "status": "pass" if keystore is not None and not legacy_keys else "warn",
                   "detail": (f"still present: {', '.join(legacy_keys)} - destroy after the stabilisation window "
                              "with `cryptomigrate keys destroy`") if legacy_keys else
                   ("none remain" if keystore is not None else "keystore not opened")})
    failed = [c for c in checks if c["status"] == "fail"]
    return {"schema": "cryptomigrate-verification/1", "generated": isotime(),
            "status": "fail" if failed else "pass", "checks": checks, "data": data_results,
            "exceptions": [f for f in findings if f.get("exception")],
            "suppressed": [f for f in findings if f.get("suppressed")],
            "summary": {"checks": len(checks), "failed": len(failed),
                        "warnings": sum(c["status"] == "warn" for c in checks)}}


def write_verification(cfg: Config, report: dict[str, Any]) -> dict[str, Path]:
    out = cfg.artifact("verification")
    md = [f"# Final verification ({report['status'].upper()})", "", f"Generated {report['generated']}.", "",
          md_table(["Check", "Status", "Title", "Detail"],
                   [[c["id"], c["status"].upper(), c["title"], c["detail"]] for c in report["checks"]]), ""]
    if report["exceptions"] or report["suppressed"]:
        md += ["## Disclosed exceptions and suppressions", "",
               md_table(["Kind", "Location", "Rule", "Justification"],
                        [["exception", f["location"], f["rule_id"], f.get("exception")] for f in report["exceptions"]]
                        + [["suppressed", f"{f['location']}:{f.get('line')}", f["rule_id"], f.get("suppression")]
                           for f in report["suppressed"]]), ""]
    return {"json": write_json(out / "verification.json", report),
            "md": write_text(out / "verification.md", "\n".join(md))}
