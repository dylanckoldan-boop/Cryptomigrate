"""Phase 2 assessment: compatibility & gap analysis, compliance mapping and risk scoring."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from ..config import Config
from ..discovery.policy import Policy
from ..util import CRITICALITY_WEIGHT, SEVERITY_WEIGHT, isotime, md_table, severity_rank

ASSESSMENT_SCHEMA = "cryptomigrate-assessment/1"

# change type, how it gets done, relative effort (S/M/L), what to check
CHANGE_TYPES: dict[str, tuple[str, str, str, str]] = {
    "source": ("Code change", "Guided (runbook)", "M",
               "Library support for AES-GCM; IV/tag storage; dual-mode decrypt until data is re-encrypted."),
    "config-fixable": ("Configuration change", "Automated - cryptomigrate remediate", "S",
                       "Client compatibility with the remaining cipher suites."),
    "config": ("Coordinated configuration change", "Manual - peers/clients must change together", "M",
               "Every peer (VPN, Kerberos realm, SNMP poller) supports AES before cut-over."),
    "protocol": ("Endpoint TLS change", "Manual / remediate the terminator's config", "S",
                 "Legacy clients that only speak 3DES (e.g. Windows XP/IE8 era) - accept or isolate."),
    "data": ("Data re-encryption", "Automated - cryptomigrate reencrypt", "M",
             "Column width, read paths using dual mode, batch window and DB load."),
    "manual:hsm": ("HSM firmware/licence or hardware refresh", "Manual", "L",
                   "FIPS 140-3 validated AES support; key block format (e.g. TR-31) and key ceremony."),
    "manual:embedded": ("Firmware update or hardware replacement", "Manual", "L",
                        "Vendor AES firmware availability; field update logistics."),
    "manual:third-party": ("Vendor remediation (contractual)", "Manual", "L",
                           "Contract clause, vendor timeline, compensating controls meanwhile."),
    "manual:other": ("Manual remediation", "Manual", "M", "Owner-led assessment."),
    "certificate": ("Certificate reissue / rotation", "Manual (PKI) - automate renewal with ACME", "S",
                    "Chain trust, SAN, key size, signature hash and lifetime; renewal automation for 200/100/47 days."),
    "binary": ("Rebuild with hardening flags", "Build pipeline change", "S",
               "Stack protector, FORTIFY_SOURCE, PIE, full RELRO, non-executable stack; regression tests."),
}


def change_type(f: dict[str, Any]) -> str:
    if f["category"] == "config":
        return "config-fixable" if f.get("fixable") else "config"
    if f["category"] in ("certificate", "binary"):
        return f["category"]
    if f["category"] == "manual":
        key = f"manual:{(f.get('evidence') or {}).get('type', 'other')}"
        return key if key in CHANGE_TYPES else "manual:other"
    return f["category"] if f["category"] in CHANGE_TYPES else "source"


def risk_score(f: dict[str, Any], cfg: Config) -> int:
    system = cfg.system(f.get("system"))
    weight = CRITICALITY_WEIGHT.get(system.criticality if system else "medium", 2)
    return SEVERITY_WEIGHT.get(f["severity"], 4) * weight


def build_assessment(cfg: Config, policy: Policy, inventory: dict[str, Any]) -> dict[str, Any]:
    active = [f for f in inventory["findings"] if not f.get("suppressed") and not f.get("exception")]
    enriched = []
    for f in active:
        kind = change_type(f)
        label, automation, effort, check = CHANGE_TYPES[kind]
        status = policy.algorithm_meta(f["algorithm"]).get("status", {})
        enriched.append({**f, "change_type": label, "automation": automation, "effort": effort,
                         "compatibility_check": check, "risk_score": risk_score(f, cfg),
                         "nist_status": f"encrypt {status.get('encrypt', '?')}, decrypt {status.get('decrypt', '?')}",
                         "wave": cfg.wave_of(f.get("system"))})
    enriched.sort(key=lambda f: (-f["risk_score"], f["location"]))

    systems = []
    for system in cfg.systems:
        mine = [f for f in enriched if f.get("system") == system.id]
        sources = [d.name for d in cfg.data_sources if d.system == system.id]
        systems.append({
            "id": system.id, "name": system.name, "owner": system.owner, "criticality": system.criticality,
            "wave": cfg.wave_of(system.id), "active_findings": len(mine),
            "risk_score": sum(f["risk_score"] for f in mine),
            "algorithms": dict(Counter(f["algorithm"] for f in mine)),
            "change_types": dict(Counter(f["change_type"] for f in mine)), "data_sources": sources,
            "endpoints": system.endpoints,
        })
    unassigned = [f for f in enriched if not f.get("system")]

    gaps = []
    if unassigned:
        gaps.append({"type": "unassigned-findings", "severity": "high", "count": len(unassigned),
                     "detail": "findings not mapped to an owning system - add path globs under systems[].paths"})
    for system in cfg.systems:
        if not system.owner or "[" in str(system.owner):
            gaps.append({"type": "system-without-owner", "severity": "high", "count": 1,
                         "detail": f"system {system.id} has no named owner"})
    for probe in inventory.get("probes", []):
        if probe["status"] in ("inconclusive", "unreachable"):
            gaps.append({"type": "probe-" + probe["status"], "severity": "medium", "count": 1,
                         "detail": f"{probe['endpoint']}: {probe.get('detail', '')}"})
    for profile in inventory.get("data_profiles", []):
        if profile.get("status") == "error":
            gaps.append({"type": "data-source-unreachable", "severity": "medium", "count": 1,
                         "detail": f"{profile['source']}: {profile.get('error')}"})
        elif profile.get("max_length") and profile.get("projected_max_length", 0) > profile["max_length"]:
            gaps.append({"type": "column-too-narrow", "severity": "high", "count": 1,
                         "detail": f"{profile['source']}.{profile['field']}: needs {profile['projected_max_length']} "
                                   f"> max_length {profile['max_length']} - schema change before Phase 6"})
    for exc in inventory.get("expired_exceptions", []):
        gaps.append({"type": "expired-exception", "severity": "high", "count": 1,
                     "detail": f"exception {exc.get('id')} expired {exc.get('expires')}"})
    unjustified = [f for f in inventory["findings"] if f.get("suppressed") and "no justification" in
                   (f.get("suppression") or "")]
    if unjustified:
        gaps.append({"type": "unjustified-suppression", "severity": "medium", "count": len(unjustified),
                     "detail": "inline suppressions without `-- justification`"})

    primary = inventory["policy"]["id"]
    compliance = {}
    for key, spec in policy.compliance.items():
        pack = spec.get("pack") or primary
        mine = [f for f in active if (f.get("layer") or primary) == pack]
        compliance[key] = {"title": spec.get("title", key), "controls": spec.get("controls", []),
                           "requirement": " ".join(str(spec.get("requirement", "")).split()),
                           "status": "non-conformant" if mine else "conformant", "active_findings": len(mine),
                           "layer": pack}

    return {
        "schema": ASSESSMENT_SCHEMA, "generated": isotime(), "inventory_generated": inventory["generated"],
        "policy": inventory["policy"], "project": cfg.project,
        "summary": {
            "active_findings": len(active), "systems": len(cfg.systems), "unassigned_findings": len(unassigned),
            "total_risk_score": sum(f["risk_score"] for f in enriched), "gaps": len(gaps),
            "by_change_type": dict(Counter(f["change_type"] for f in enriched)),
            "by_algorithm": dict(Counter(f["algorithm"] for f in enriched)),
            "automatable": sum(1 for f in enriched if f["automation"].startswith("Automated")),
            "by_layer": dict(Counter(f.get("layer") or "-" for f in enriched)),
        },
        "systems": sorted(systems, key=lambda s: (s["wave"], s["id"])),
        "gaps": gaps, "compliance": compliance, "findings": enriched,
    }


def assessment_markdown(a: dict[str, Any]) -> str:
    s = a["summary"]
    by_type = defaultdict(list)
    for f in a["findings"]:
        by_type[f["change_type"]].append(f)
    lines = [
        f"# Gap & compatibility assessment - {a['project'].get('name') or 'project'}",
        "",
        f"Generated {a['generated']} from the inventory of {a['inventory_generated']}.",
        "",
        "## Executive summary",
        "",
        f"* **{s['active_findings']} active findings** across {s['systems']} systems "
        f"({s['unassigned_findings']} not yet mapped to an owner).",
        f"* **{s['automatable']}** can be remediated automatically (config remediation or data re-encryption).",
        f"* Total risk score **{s['total_risk_score']}** (severity weight x system criticality).",
        f"* **{s['gaps']} inventory/governance gaps** must close before the Phase 2 gate.",
        "",
        "## Compliance position",
        "",
        md_table(["Framework", "Status", "Controls", "Requirement"],
                 [[v["title"], v["status"], ", ".join(v["controls"]), v["requirement"]]
                  for v in a["compliance"].values()]),
        "",
        "## Systems (rollout order)",
        "",
        md_table(["Wave", "System", "Owner", "Criticality", "Active findings", "Risk", "Change types"],
                 [[x["wave"], f"{x['name']} (`{x['id']}`)", x["owner"] or "**MISSING**", x["criticality"],
                   x["active_findings"], x["risk_score"],
                   ", ".join(f"{k}: {v}" for k, v in x["change_types"].items()) or "-"] for x in a["systems"]]),
        "",
        "## Compatibility & effort",
        "",
        md_table(["Change type", "Findings", "How", "Effort", "Compatibility check"],
                 [[k, len(v), v[0]["automation"], v[0]["effort"], v[0]["compatibility_check"]]
                  for k, v in sorted(by_type.items())]),
        "",
    ]
    if a["gaps"]:
        lines += ["## Gaps to close", "", md_table(["Type", "Severity", "Detail"],
                                                   [[g["type"], g["severity"], g["detail"]] for g in a["gaps"]]), ""]
    top = sorted(a["findings"], key=lambda f: (-f["risk_score"], -severity_rank(f["severity"])))[:25]
    if top:
        lines += ["## Highest-risk findings", "", md_table(
            ["Risk", "Severity", "Algorithm", "Location", "System", "Change", "NIST SP 800-131A"],
            [[f["risk_score"], f["severity"], f["algorithm"],
              f["location"] + (f":{f['line']}" if f.get("line") else ""),
              f.get("system") or "unassigned", f["change_type"], f["nist_status"]] for f in top]), ""]
    return "\n".join(lines)
