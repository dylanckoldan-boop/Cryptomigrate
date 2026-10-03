"""Phase 3 planning: wave plan, per-system runbooks, key-management plan and WBS work items.

The work items mirror the workplan's Work Breakdown Structure and can be pushed to GitHub
Issues with the generated ``create_github_issues.sh`` (requires the GitHub CLI, ``gh``).
"""

from __future__ import annotations

import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..config import Config
from ..util import isotime, md_table, write_json, write_text

PHASE_LABELS = {1: "phase:1-initiation", 2: "phase:2-discovery", 3: "phase:3-design", 4: "phase:4-build",
                5: "phase:5-test", 6: "phase:6-deploy", 7: "phase:7-closeout"}


def _runbook(cfg: Config, system: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    sid = system["id"]
    sources = [d for d in cfg.data_sources if d.system == sid]
    profiles = sorted({p for d in sources for p in d.profiles()})
    legacy_keys = sorted({cfg.legacy_profiles[p].key_id for p in profiles})
    code = [f for f in findings if f["category"] == "source"]
    auto_config = [f for f in findings if f["category"] == "config" and f.get("fixable")]
    manual_config = [f for f in findings if f["category"] in ("config", "protocol") and not f.get("fixable")]
    manual_assets = [f for f in findings if f["category"] == "manual"]
    cfg_flag = f" --config {cfg.path.name}" if cfg.path else ""

    def loc(f: dict[str, Any]) -> str:
        return f"`{f['location']}" + (f":{f['line']}`" if f.get("line") else "`")

    lines = [
        f"# Runbook - {system['name']} (`{sid}`)",
        "",
        f"Wave **{system['wave']}** - criticality **{system['criticality']}** - "
        f"owner **{system['owner'] or 'UNASSIGNED'}**"
        f" - generated {isotime()}",
        "",
        "## 1. Scope",
        "",
        f"{len(findings)} active findings; data sources: {', '.join(d.name for d in sources) or 'none'}.",
        "",
    ]
    if findings:
        lines += [md_table(["Severity", "Algorithm", "Location", "Change type", "Effort"],
                           [[f["severity"], f["algorithm"], f["location"] + (f":{f['line']}" if f.get("line") else ""),
                             f["change_type"], f["effort"]] for f in findings]), ""]
    lines += [
        "## 2. Pre-requisites (Phase 3 exit / Phase 4 entry)",
        "",
        "- [ ] Design review approved (`governance.signoffs.design_review`)",
        f"- [ ] Active AES key present: `cryptomigrate keys list{cfg_flag}`",
    ]
    lines += [f"- [ ] Legacy key `{k}` imported and its KCV matches the HSM/custodian record" for k in legacy_keys]
    lines += [
        "- [ ] Full database/file-system backup taken (in addition to cryptomigrate's column-level backup)",
        "- [ ] Change ticket raised: ________  - maintenance window (if any): ________",
        "",
        "## 3. Build (Phase 4)",
        "",
    ]
    if code:
        lines += ["### Code changes", ""]
        lines += [f"- [ ] {loc(f)} - {f['algorithm']}{'/' + f['mode'] if f.get('mode') else ''}: {f['remediation']}"
                  for f in code]
        lines += ["", "Write paths must produce AES-GCM immediately; read paths must keep accepting legacy ciphertext "
                      "(dual mode) until every data source in this runbook is re-encrypted. Python services can call "
                      "`CryptoService`; other languages implement the v2 envelope in docs/ENVELOPE_SPEC.md "
                      "(interoperability vectors included).", ""]
    if auto_config:
        lines += ["### Configuration changes (automated)", "",
                  f"```bash\ncryptomigrate remediate{cfg_flag}                       # review the diff\n"
                  f"cryptomigrate remediate{cfg_flag} --apply --change-ticket <CHG>\n```", ""]
        lines += [f"- [ ] {loc(f)} - {f.get('detail') or f['title']}" for f in auto_config]
        lines.append("")
    if manual_config:
        lines += ["### Coordinated changes (manual)", ""]
        lines += [f"- [ ] {loc(f)} - {f['remediation']}" for f in manual_config]
        lines.append("")
    if manual_assets:
        lines += ["### Hardware / third-party assets", ""]
        lines += [f"- [ ] {f['location']} - {f.get('detail', '')}: {f['remediation']}" for f in manual_assets]
        lines.append("")
    lines += [
        "## 4. Test (Phase 5)",
        "",
        "```bash",
        f"cryptomigrate validate{cfg_flag}",
    ]
    lines += [f"cryptomigrate reencrypt{cfg_flag} --source {d.name}            # dry run: expect errors = 0"
              for d in sources]
    lines += ["```", "", "- [ ] UAT sign-off recorded (`governance.signoffs.uat`)", "",
              "## 5. Deploy (Phase 6)", "", "```bash"]
    for d in sources:
        lines.append(f"cryptomigrate reencrypt{cfg_flag} --source {d.name} --apply --limit 100 "
                     "--change-ticket <CHG>   # canary")
        lines.append(f"cryptomigrate reencrypt{cfg_flag} --source {d.name} --apply --change-ticket <CHG> "
                     "--approver <name>")
    lines += ["```", "",
              "Monitor application error rates and latency after each step; continue only when stable.", "",
              "## 6. Rollback", "",
              "```bash",
              f"cryptomigrate rollback{cfg_flag} --run <run-id>   # restores original ciphertext (CAS-protected)",
              "```", "",
              "Rollback is possible only while the legacy key exists. Legacy keys are destroyed in Phase 7 after the "
              "stabilisation window - after that, rollback is intentionally impossible (crypto-shredding).", "",
              "## 7. Verify & sign-off (Phase 7)", "",
              f"```bash\ncryptomigrate verify{cfg_flag}\n```", "",
              f"- [ ] Owner sign-off: {system['owner'] or '________'}   date: ________", ""]
    return "\n".join(lines)


def _key_plan(cfg: Config, keys: list[dict[str, Any]] | None) -> str:
    profiles = cfg.legacy_profiles
    rows = [[k["id"], k["algorithm"], k["state"], k.get("kcv", ""), k.get("created", ""),
             k.get("usage", {}).get("encryptions", 0)] for k in (keys or [])]
    lines = [
        "# Key Management Plan (generated)",
        "",
        "Aligned to NIST SP 800-57 Part 1 and the workplan's Key Management Plan template.",
        "",
        md_table(["Lifecycle stage", "Implementation in this project"], [
            ["Generation", f"`cryptomigrate keys init/rotate` - {cfg.target_algorithm} keys from the OS CSPRNG"],
            ["Distribution", "Keys never leave the keystore in plaintext; applications load them via CryptoService"],
            ["Storage", f"Wrapped with AES-KWP (RFC 5649) under a KEK from `{cfg.kek_env}`; keystore "
                        f"`{cfg.keystore_path.name}` is mode 0600 and must not be committed to Git"],
            ["Rotation", "`cryptomigrate keys rotate` - new key active, previous key decrypt-only; rotate at least "
                         "annually and before 2^31 encryptions (SP 800-38D random-IV limit 2^32)"],
            ["Legacy key handling", "DES/TDEA keys imported decrypt-only; destroyed in Phase 7 once verification "
                                    "shows zero legacy records"],
            ["Destruction", "`cryptomigrate keys destroy` - refuses while legacy data remains; audit-logged"],
            ["Audit & monitoring", "Hash-chained audit log; `cryptomigrate audit verify`"],
        ]),
        "",
        "## Legacy profiles",
        "",
        md_table(["Profile", "Algorithm", "Mode", "IV", "Padding", "Encoding", "Key id"],
                 [[p.name, p.algorithm, p.mode, p.iv, p.padding, p.encoding, p.key_id] for p in profiles.values()]),
        "",
    ]
    if rows:
        lines += ["## Current keys", "", md_table(["Key id", "Algorithm", "State", "KCV", "Created", "Encryptions"],
                                                  rows), ""]
    else:
        lines += ["_Keystore not opened (no KEK in the environment) - key table omitted._", ""]
    return "\n".join(lines)


def build_work_items(cfg: Config, assessment: dict[str, Any]) -> list[dict[str, Any]]:
    items = [
        {"wbs": "1.1", "phase": 1, "title": "Charter approval & kickoff", "owner": cfg.project.get("project_manager")},
        {"wbs": "2.1", "phase": 2, "title": "Cryptographic asset inventory (cryptomigrate discover)",
         "owner": cfg.project.get("security_lead")},
        {"wbs": "2.2", "phase": 2, "title": "Compatibility & gap assessment (cryptomigrate assess)",
         "owner": cfg.project.get("security_lead")},
        {"wbs": "3.1", "phase": 3, "title": "Target architecture & key management plan",
         "owner": cfg.project.get("security_lead")},
    ]
    for system in assessment["systems"]:
        if not system["active_findings"] and not system["data_sources"]:
            continue
        sid = system["id"]
        items += [
            {"wbs": "3.2", "phase": 3, "title": f"[{sid}] Approve migration runbook", "owner": system["owner"],
             "system": sid, "wave": system["wave"], "body": f"Runbook: artifacts/plan/runbooks/{sid}.md"},
            {"wbs": "4.1", "phase": 4, "title": f"[{sid}] Implement AES-GCM code/config changes",
             "owner": system["owner"], "system": sid, "wave": system["wave"]},
            {"wbs": "5.1", "phase": 5, "title": f"[{sid}] Dry-run re-encryption & UAT", "owner": system["owner"],
             "system": sid, "wave": system["wave"]},
            {"wbs": "6.x", "phase": 6, "title": f"[{sid}] Production rollout (wave {system['wave']})",
             "owner": system["owner"], "system": sid, "wave": system["wave"]},
        ]
    items += [
        {"wbs": "7.1", "phase": 7, "title": "Final verification & legacy key destruction",
         "owner": cfg.project.get("security_lead")},
        {"wbs": "7.2", "phase": 7, "title": "Compliance evidence package (cryptomigrate attest)",
         "owner": cfg.project.get("security_lead")},
        {"wbs": "7.3", "phase": 7, "title": "Retrospective & template archive",
         "owner": cfg.project.get("project_manager")},
    ]
    return items


def _issue_script(items: list[dict[str, Any]]) -> str:
    lines = ["#!/usr/bin/env bash", "# Generated by `cryptomigrate plan` - creates the WBS as GitHub Issues.",
             "# Requires the GitHub CLI (gh auth login); labels phase:N and wave:N are created below.",
             "set -euo pipefail",
             ""]
    labels = sorted({PHASE_LABELS[i["phase"]] for i in items} | {f"wave:{i['wave']}" for i in items if i.get("wave")})
    lines += [f"gh label create {shlex.quote(label)} --force >/dev/null" for label in labels]
    lines.append("")
    for item in items:
        body = (item.get("body", "") + f"\n\nWBS {item['wbs']} - owner: {item.get('owner') or 'TBD'}").strip()
        cmd = ["gh", "issue", "create", "--title", f"WBS {item['wbs']}: {item['title']}", "--body", body,
               "--label", PHASE_LABELS[item["phase"]]]
        if item.get("wave"):
            cmd += ["--label", f"wave:{item['wave']}"]
        lines.append(" ".join(shlex.quote(c) for c in cmd))
    return "\n".join(lines) + "\n"


def write_plan(cfg: Config, assessment: dict[str, Any], keys: list[dict[str, Any]] | None = None) -> dict[str, Path]:
    out = cfg.artifact("plan")
    by_system: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in assessment["findings"]:
        by_system[f.get("system") or "unassigned"].append(f)
    written: dict[str, Path] = {}
    systems = list(assessment["systems"])
    if by_system.get("unassigned"):
        systems.append({"id": "unassigned", "name": "Unassigned findings", "owner": None, "criticality": "medium",
                        "wave": max([s["wave"] for s in systems] + [0]) + 1, "active_findings":
                            len(by_system["unassigned"]), "data_sources": []})
    for system in systems:
        if not by_system.get(system["id"]) and not system.get("data_sources"):
            continue
        written[f"runbook:{system['id']}"] = write_text(out / "runbooks" / f"{system['id']}.md",
                                                        _runbook(cfg, system, by_system.get(system["id"], [])))
    waves: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for system in systems:
        waves[system["wave"]].append(system)
    wave_lines = ["# Rollout wave plan", "",
                  "Waves run from lowest to highest business criticality (workplan Phase 6). Each wave starts only "
                  "after the previous wave is verified and stable.", ""]
    for wave in sorted(waves):
        wave_lines += [f"## Wave {wave}", "", md_table(
            ["System", "Owner", "Criticality", "Active findings", "Data sources"],
            [[f"{s['name']} (`{s['id']}`)", s.get("owner") or "UNASSIGNED", s["criticality"], s["active_findings"],
              ", ".join(s.get("data_sources") or []) or "-"] for s in waves[wave]]), ""]
    written["waves"] = write_text(out / "wave-plan.md", "\n".join(wave_lines))
    written["key_plan"] = write_text(out / "key-management-plan.md", _key_plan(cfg, keys))
    items = build_work_items(cfg, assessment)
    written["work_items"] = write_json(out / "work-items.json", {"generated": isotime(), "items": items})
    script = write_text(out / "create_github_issues.sh", _issue_script(items))
    script.chmod(0o755)
    written["github_issues"] = script
    return written
