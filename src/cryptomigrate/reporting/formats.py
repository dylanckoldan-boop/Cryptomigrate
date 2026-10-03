"""Inventory renderers.

* ``inventory.json``       - native format consumed by assess/plan/gate/attest
* ``cryptomigrate.sarif``  - OASIS SARIF 2.1.0 for GitHub code scanning / any SAST dashboard
* ``cbom.cdx.json``        - CycloneDX 1.6 Cryptography Bill of Materials (CBOM); satisfies the
                              "inventory of cipher suites and protocols" evidence (PCI DSS 12.3.3)
* ``inventory.md``         - human-readable report
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import Config
from ..discovery.policy import Policy
from ..util import md_table, severity_rank, write_json, write_text

SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
CDX_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}
FORMATS = ("json", "sarif", "cbom", "md")


def _status(f: dict[str, Any]) -> str:
    if f.get("suppressed"):
        return "suppressed"
    if f.get("exception"):
        return f"exception {f['exception']}"
    return "active"


# --------------------------------------------------------------------------- SARIF
def to_sarif(inventory: dict[str, Any], policy: Policy) -> dict[str, Any]:
    findings = [f for f in inventory["findings"]
                if (f["category"] in ("source", "config") and f.get("line"))
                or (f["category"] in ("certificate", "binary") and (f.get("evidence") or {}).get("origin") == "file")]
    rules, index = [], {}
    for rule_id in sorted({f["rule_id"] for f in findings}):
        rule = policy.rule(rule_id)
        severity = rule.severity_for(None)
        index[rule_id] = len(rules)
        refs = ", ".join([*rule.cwe, *rule.cve])
        rules.append({
            "id": rule.id,
            "name": "".join(part.capitalize() for part in rule.id.split("-")),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": f"{rule.title}. {policy.name}."},
            "help": {"text": rule.remediation,
                     "markdown": f"**Remediation:** {rule.remediation}"
                                 + (f"\n\n**References:** {refs}" if refs else "")},
            "defaultConfiguration": {"level": SARIF_LEVEL[severity]},
            "properties": {"tags": ["security", "cryptography", *rule.cwe],
                           "security-severity": SECURITY_SEVERITY[severity],
                           "precision": rule.confidence if rule.confidence in ("high", "medium", "low") else "medium"},
        })
    results = []
    for f in findings:
        label = f["algorithm"] + (f"-{f['mode']}" if f.get("mode") else "")
        result = {
            "ruleId": f["rule_id"], "ruleIndex": index[f["rule_id"]], "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{label}: {f['title']}" + (f" - {f['detail']}" if f.get("detail") else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["location"], "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": int(f.get("line") or 1), "startColumn": int(f.get("column") or 1)}}}],
            "partialFingerprints": {"cryptomigrate/v1": f["fingerprint"]},
            "properties": {"algorithm": f["algorithm"], "severity": f["severity"], "system": f.get("system")},
        }
        if f.get("suppressed") or f.get("exception"):
            result["suppressions"] = [{
                "kind": "inSource" if f.get("suppressed") else "external",
                "justification": f.get("suppression") or f"governance exception {f.get('exception')}"}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "cryptomigrate", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/dylanckoldan-boop/cryptomigrate",
                                "rules": rules}},
            "automationDetails": {"id": f"cryptomigrate/{policy.id}/"},
            "results": results,
        }],
    }


# ---------------------------------------------------------------------------- CBOM
def _algorithm_component(name: str, ref: str, meta: dict[str, Any], mode: str | None) -> dict[str, Any]:
    props: dict[str, Any] = {"primitive": meta.get("primitive", "block-cipher"),
                             "cryptoFunctions": ["encrypt", "decrypt"]}
    if meta.get("primitive") == "ae":
        props["cryptoFunctions"].append("tag")
    if mode:
        props["mode"] = mode.lower() if mode.lower() in CDX_MODES else "other"
    if meta.get("classical_security_bits") is not None:
        props["classicalSecurityLevel"] = int(meta["classical_security_bits"])
    if meta.get("nist_quantum_security_level") is not None:
        props["nistQuantumSecurityLevel"] = int(meta["nist_quantum_security_level"])
    crypto: dict[str, Any] = {"assetType": "algorithm", "algorithmProperties": props}
    if meta.get("oid"):
        crypto["oid"] = meta["oid"]
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": name, "cryptoProperties": crypto}


def to_cbom(inventory: dict[str, Any], policy: Policy) -> dict[str, Any]:
    groups: dict[tuple[str, str | None], list[dict[str, Any]]] = defaultdict(list)
    for f in inventory["findings"]:  # algorithm assets; certificates and protocols are added below
        if f["algorithm"] in policy.algorithms and f["category"] != "certificate":
            groups[(f["algorithm"], f.get("mode"))].append(f)
    components = []
    for (algorithm, mode), items in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        meta = policy.algorithm_meta(algorithm)
        name = algorithm + (f"-{mode}" if mode else "")
        component = _algorithm_component(name, f"crypto/algorithm/{name.lower()}", meta, mode)
        occurrences = []
        for f in items:
            occurrence: dict[str, Any] = {"location": f["location"]}
            if f.get("line"):
                occurrence["line"] = int(f["line"])
            occurrence["additionalContext"] = f"{f['rule_id']} {f['title']} [{_status(f)}]"
            occurrences.append(occurrence)
        component["evidence"] = {"occurrences": occurrences}
        status = meta.get("status", {})
        component["properties"] = [
            {"name": "cryptomigrate:nist-status", "value": f"encrypt={status.get('encrypt', 'unknown')}; "
                                                          f"decrypt={status.get('decrypt', 'unknown')}"},
            {"name": "cryptomigrate:active-findings", "value": str(sum(1 for f in items if _status(f) == "active"))},
            {"name": "cryptomigrate:systems", "value": ", ".join(sorted({f.get('system') or 'unassigned'
                                                                          for f in items}))},
        ]
        components.append(component)
    by_fingerprint: dict[str, dict[str, Any]] = {}
    for cert in inventory.get("certificates", []):
        entry = by_fingerprint.get(cert["sha256"])
        if entry is None:
            entry = {"type": "cryptographic-asset", "bom-ref": f"crypto/certificate/{cert['sha256'][:24]}",
                     "name": cert.get("common_name") or cert["subject"] or "certificate",
                     "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                         "subjectName": cert["subject"], "issuerName": cert["issuer"],
                         "notValidBefore": cert["not_before"], "notValidAfter": cert["not_after"],
                         "certificateFormat": "X.509"}},
                     "evidence": {"occurrences": []},
                     "properties": [{"name": "cryptomigrate:signature-hash", "value": str(cert.get("signature_hash"))},
                                    {"name": "cryptomigrate:public-key",
                                     "value": f"{cert.get('key_type')}-{cert.get('key_bits')}"}]}
            by_fingerprint[cert["sha256"]] = entry
            components.append(entry)
        entry["evidence"]["occurrences"].append({"location": cert["location"]})
    for tls in inventory.get("tls_assessments", []):
        if tls.get("protocol"):
            components.append({
                "type": "cryptographic-asset", "bom-ref": f"crypto/protocol/tls/{tls['endpoint']}",
                "name": f"TLS {tls['endpoint']}",
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                    "type": "tls", "version": str(tls["protocol"]).replace("TLSv", ""),
                    "cipherSuites": [{"name": str(tls.get("cipher"))}]}},
                "evidence": {"occurrences": [{"location": tls["endpoint"]}]}})
    target = policy.target_algorithm
    target_component = _algorithm_component(target, f"crypto/algorithm/{target.lower()}",
                                            policy.algorithm_meta(target), "GCM")
    target_component["properties"] = [{"name": "cryptomigrate:role", "value": "migration-target"}]
    components.append(target_component)
    project = inventory.get("project") or {}
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": inventory["generated"],
            "tools": {"components": [{"type": "application", "name": "cryptomigrate", "version": __version__}]},
            "component": {"type": "application", "bom-ref": "project",
                          "name": project.get("name") or "unnamed-project"},
        },
        "components": components,
    }


# ------------------------------------------------------------------------ Markdown
def to_markdown(inventory: dict[str, Any]) -> str:
    s = inventory["summary"]
    lines = [
        f"# Cryptographic inventory - {inventory['policy']['name']}",
        "",
        f"Generated {inventory['generated']} by cryptomigrate {inventory['tool']['version']} "
        f"(policy `{inventory['policy']['id']}` v{inventory['policy']['version']}). "
        f"Files scanned: {inventory['scan'].get('files_scanned', 0)}.",
        "",
        f"**{s['active']} active findings** ({s['suppressed']} suppressed, {s['excepted']} under exception, "
        f"{s['fixable']} auto-fixable).",
        "",
        md_table(["Dimension", "Breakdown"], [
            ["Algorithm", ", ".join(f"{k}: {v}" for k, v in sorted(s["by_algorithm"].items())) or "-"],
            ["Severity", ", ".join(f"{k}: {v}" for k, v in sorted(s["by_severity"].items(),
                                                                key=lambda kv: -severity_rank(kv[0]))) or "-"],
            ["Category", ", ".join(f"{k}: {v}" for k, v in sorted(s["by_category"].items())) or "-"],
            ["System", ", ".join(f"{k}: {v}" for k, v in sorted(s["by_system"].items())) or "-"],
        ]),
        "",
    ]
    findings = sorted(inventory["findings"], key=lambda f: (-severity_rank(f["severity"]), f["location"],
                                                            f.get("line") or 0))
    if findings:
        lines += ["## Findings", "", md_table(
            ["Severity", "Algorithm", "Location", "Rule", "System", "Status", "Detail"],
            [[f["severity"], f["algorithm"] + (f"/{f['mode']}" if f.get("mode") else ""),
              f["location"] + (f":{f['line']}" if f.get("line") else ""), f["rule_id"], f.get("system") or "-",
              _status(f), (f.get("detail") or f.get("snippet") or "")[:120]] for f in findings]), ""]
    if inventory.get("probes"):
        lines += ["## TLS endpoint probes", "", md_table(
            ["Endpoint", "Status", "Cipher", "Detail"],
            [[p["endpoint"], p["status"], p.get("cipher") or "-", p.get("detail", "")] for p in inventory["probes"]]),
            ""]
    if inventory.get("data_profiles"):
        lines += ["## Data-at-rest profiles", "", md_table(
            ["Source", "Field", "Sampled", "Legacy-looking", "Already v2", "Projected max length"],
            [[p["source"], p.get("field", "-"), p.get("stats", {}).get("sampled", "-"),
              p.get("stats", {}).get("block64-only", 0) + p.get("stats", {}).get("block64-compatible", 0)
              if p.get("stats") else p.get("error", "-"),
              p.get("stats", {}).get("v2", "-"), p.get("projected_max_length", "-")]
             for p in inventory["data_profiles"]]), ""]
    return "\n".join(lines)


def write_inventory(cfg: Config, inventory: dict[str, Any], policy: Policy,
                    formats: tuple[str, ...] = FORMATS, out_dir: Path | None = None) -> dict[str, Path]:
    out_dir = Path(out_dir or cfg.artifacts_dir)
    written = {}
    if "json" in formats:
        written["json"] = write_json(out_dir / "inventory.json", inventory)
    if "sarif" in formats:
        written["sarif"] = write_json(out_dir / "cryptomigrate.sarif", to_sarif(inventory, policy))
    if "cbom" in formats:
        written["cbom"] = write_json(out_dir / "cbom.cdx.json", to_cbom(inventory, policy))
    if "md" in formats:
        written["md"] = write_text(out_dir / "inventory.md", to_markdown(inventory))
    return written
