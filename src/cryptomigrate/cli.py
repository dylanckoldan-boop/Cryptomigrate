"""cryptomigrate command-line interface - one command per SDLC activity.

    Phase 1  init                      scaffold migration.yaml (charter) [+ GitHub governance files]
    Phase 2  discover, assess          inventory (JSON/SARIF/CBOM/MD) and gap assessment
    Phase 3  plan, keys                wave plan, runbooks, key-management plan; key lifecycle
    Phase 4  remediate, selftest       automated config fixes; crypto known-answer tests
    Phase 5  validate, reencrypt       validation suite; dry-run re-encryption
    Phase 6  reencrypt --apply         production re-encryption (canary --limit, waves), rollback
    Phase 7  verify, attest            final verification; evidence package
    Any      gate, status, audit       phase gates, progress dashboard, audit-chain verification

Exit codes: 0 ok - 1 findings / gate or verification failure - 2 usage or configuration error.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from importlib import resources
from pathlib import Path

from . import __version__
from .audit import AuditLog
from .config import ConfigError, load_config
from .util import SEVERITIES, SEVERITY_COLOR, STATUS_COLOR, color, read_json, severity_rank, text_table, write_json

TEMPLATES = "cryptomigrate.templates"


class CLIError(Exception):
    pass


def _out(args, *parts) -> None:
    if not getattr(args, "quiet", False):
        print(*parts)


def _cfg(args, require: bool = False):
    return load_config(args.config, require=require)


def _policy(cfg, args=None):
    from .discovery.policy import load_policy, load_policy_set

    override = getattr(args, "policy", None)
    return load_policy(override, cfg.root) if override else load_policy_set(cfg.policy, cfg.layers, cfg.root)


def _keystore(cfg, required: bool = True):
    from .keys.keystore import Keystore, KeystoreError

    try:
        return Keystore.from_config(cfg), None
    except KeystoreError as exc:
        if required:
            raise CLIError(str(exc)) from exc
        return None, str(exc)


def _status(value: str) -> str:
    return color(value.upper(), STATUS_COLOR.get(value, "bold"))


# ------------------------------------------------------------------- phase 1
def cmd_init(args) -> int:
    target = Path(args.dir).resolve()
    target.mkdir(parents=True, exist_ok=True)
    templates = resources.files(TEMPLATES)
    created = []
    for name, dest in (("migration.yaml", target / "migration.yaml"),
                       ("cryptomigrateignore", target / ".cryptomigrateignore")):
        if dest.exists() and not args.force:
            _out(args, f"  exists, skipped: {dest.name} (use --force to overwrite)")
            continue
        dest.write_text(templates.joinpath(name).read_text(encoding="utf-8"), encoding="utf-8")
        created.append(dest.name)
    gitignore = target / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    if ".cryptomigrate/" not in existing:
        with open(gitignore, "a", encoding="utf-8") as fh:
            fh.write(("\n" if existing and not existing.endswith("\n") else "") +
                     "# cryptomigrate state: keystore, backups, audit log - never commit\n.cryptomigrate/\n")
        created.append(".gitignore (+.cryptomigrate/)")
    if args.github:
        source = templates.joinpath("github")
        for sub in ("", "workflows", "ISSUE_TEMPLATE"):
            folder = source.joinpath(sub) if sub else source
            for item in folder.iterdir():
                if not item.is_file() or item.name == "__init__.py":
                    continue
                dest = target / ".github" / sub / item.name
                if dest.exists() and not args.force:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(item.read_text(encoding="utf-8"), encoding="utf-8")
                created.append(str(dest.relative_to(target)))
    for path in created:
        _out(args, f"  created {path}")
    _out(args, "\nNext: fill in the [placeholders] in migration.yaml (Phase 1 charter), then run "
               "`cryptomigrate gate --phase 1`.")
    return 0


# ------------------------------------------------------------------- phase 2
def _print_findings(args, inventory) -> None:
    active = [f for f in inventory["findings"] if not f["suppressed"] and not f["exception"]]
    active.sort(key=lambda f: (-severity_rank(f["severity"]), f["location"], f.get("line") or 0))
    rows = [[color(f["severity"], SEVERITY_COLOR[f["severity"]]),
             f["algorithm"] + (f"/{f['mode']}" if f["mode"] else ""),
             f["location"] + (f":{f['line']}" if f.get("line") else ""), f["rule_id"], f.get("system") or "-"]
            for f in active[: args.limit]]
    if rows:
        _out(args, text_table(["severity", "algorithm", "location", "rule", "system"], rows))
        if len(active) > args.limit:
            _out(args, f"... and {len(active) - args.limit} more (see artifacts)")


def cmd_discover(args) -> int:
    from .discovery.run import run_discovery
    from .reporting.formats import FORMATS, write_inventory

    cfg = _cfg(args)
    if args.layers is not None:
        cfg.layers = [layer.strip() for layer in args.layers.split(",") if layer.strip()]
    policy = _policy(cfg, args)
    formats = tuple(f.strip() for f in args.format.split(",") if f.strip())
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise CLIError(f"unknown format(s) {sorted(unknown)}; choose from {FORMATS}")
    paths = [Path(p).resolve() for p in args.paths] if args.paths else None
    inventory = run_discovery(cfg, policy, paths, probe_tls=not args.no_tls, profile_data=not args.no_data,
                              extra_endpoints=args.tls, binaries=[Path(b) for b in args.binaries],
                              ca_bundle=args.ca_bundle)
    written = write_inventory(cfg, inventory, policy, formats, Path(args.out) if args.out else None)
    s = inventory["summary"]
    _out(args, f"Scanned {inventory['scan']['files_scanned']} files in {inventory['scan']['duration_s']}s - "
               f"{color(str(s['active']), 'bold')} active findings ({s['suppressed']} suppressed, "
               f"{s['excepted']} excepted, {s['fixable']} auto-fixable)")
    _print_findings(args, inventory)
    for probe in inventory["probes"]:
        _out(args, f"  TLS {probe['endpoint']}: {probe['status']} {probe.get('cipher') or ''} "
                   f"{probe.get('detail', '')}")
    for tls in inventory.get("tls_assessments", []):
        _out(args, f"  TLS {tls['endpoint']}: {tls.get('protocol') or 'no handshake'} {tls.get('cipher') or ''} "
                   f"verified={tls.get('verified')} legacy={','.join(tls['legacy_protocols']) or 'none'}")
    if inventory.get("layers"):
        _out(args, "  layers: " + ", ".join(f"{p['id']} ({inventory['summary']['by_layer'].get(p['id'], 0)})"
                                            for p in inventory["layers"]))
    for kind, path in written.items():
        _out(args, f"  wrote {kind:5} {path}")
    if args.fail_on:
        threshold = severity_rank(args.fail_on)
        blocking = [f for f in inventory["findings"] if not f["suppressed"] and not f["exception"]
                    and severity_rank(f["severity"]) >= threshold]
        if blocking:
            _out(args, color(f"FAIL: {len(blocking)} active finding(s) at or above '{args.fail_on}'", "red"))
            return 1
    return 0


def cmd_assess(args) -> int:
    from .reporting.assess import assessment_markdown, build_assessment
    from .util import write_text

    cfg = _cfg(args, require=True)
    inv_path = cfg.artifact("inventory.json")
    if not inv_path.exists():
        raise CLIError("no inventory - run `cryptomigrate discover` first")
    assessment = build_assessment(cfg, _policy(cfg), read_json(inv_path))
    write_json(cfg.artifact("assessment.json"), assessment)
    write_text(cfg.artifact("assessment.md"), assessment_markdown(assessment))
    s = assessment["summary"]
    _out(args, f"{s['active_findings']} active findings, risk score {s['total_risk_score']}, "
               f"{s['automatable']} automatable, {s['gaps']} gaps")
    rows = [[x["wave"], x["id"], x["owner"] or color("MISSING", "red"), x["criticality"], x["active_findings"],
             x["risk_score"]] for x in assessment["systems"]]
    if rows:
        _out(args, text_table(["wave", "system", "owner", "criticality", "findings", "risk"], rows))
    for gap in assessment["gaps"]:
        _out(args, f"  gap [{gap['severity']}] {gap['type']}: {gap['detail']}")
    _out(args, f"  wrote {cfg.artifact('assessment.md')}")
    return 0


# ------------------------------------------------------------------- phase 3
def cmd_plan(args) -> int:
    from .reporting.plan import write_plan

    cfg = _cfg(args, require=True)
    path = cfg.artifact("assessment.json")
    if not path.exists():
        raise CLIError("no assessment - run `cryptomigrate assess` first")
    keystore, _ = _keystore(cfg, required=False)
    written = write_plan(cfg, read_json(path), keystore.list() if keystore else None)
    for kind, file in written.items():
        _out(args, f"  wrote {kind:22} {file}")
    return 0


def cmd_keys(args) -> int:
    from .keys.keystore import Keystore, KeystoreError

    if args.keys_cmd == "new-kek":
        print(base64.b64encode(os.urandom(32)).decode())
        print("# Store this in your secrets manager / CI secret and export it as CRYPTOMIGRATE_KEK.", file=sys.stderr)
        return 0
    cfg = _cfg(args, require=True)
    try:
        if args.keys_cmd == "init":
            store = Keystore.from_config(cfg, create=True)
            key_id = store.generate(args.bits, reason="initial key")
            _out(args, f"Created {cfg.keystore_path} with active key {key_id} (KCV {store.meta(key_id)['kcv']})")
            return 0
        store = Keystore.from_config(cfg)
        if args.keys_cmd == "list":
            rows = [[k["id"], k["algorithm"], k["state"], k.get("kcv", ""), k.get("created", ""),
                     k.get("usage", {}).get("encryptions", 0), "; ".join(k.get("notes") or [])] for k in store.list()]
            _out(args, text_table(["key id", "algorithm", "state", "kcv", "created", "encryptions", "notes"], rows, 70))
            for warning in store.usage_warnings():
                _out(args, color(f"  WARNING {warning}", "yellow"))
        elif args.keys_cmd == "rotate":
            key_id = store.generate(args.bits, reason=args.reason)
            _out(args, f"New active key {key_id} (KCV {store.meta(key_id)['kcv']}); previous key is now decrypt-only")
        elif args.keys_cmd == "import-legacy" and args.algorithm == "RSA":
            if not (args.pem_file or args.pem_env):
                raise CLIError("RSA keys are imported with --pem-file or --pem-env")
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            pem = Path(args.pem_file).read_bytes() if args.pem_file else os.environ.get(args.pem_env, "").encode()
            secret = os.environ.get(args.pem_password_env or "", "")
            try:
                private = serialization.load_pem_private_key(pem, password=secret.encode() if secret else None)
            except (ValueError, TypeError) as exc:
                raise CLIError(f"cannot load the RSA private key: {exc}") from exc
            if not isinstance(private, rsa.RSAPrivateKey):
                raise CLIError("not an RSA private key")
            der = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            notes = store.import_legacy(args.key_id, "RSA", der)
            _out(args, f"Imported {args.key_id} (RSA-{private.key_size}, decrypt-only) KCV "
                       f"{store.meta(args.key_id)['kcv']} - confirm it matches the custodian record")
            for note in notes:
                _out(args, color(f"  note: {note}", "yellow"))
        elif args.keys_cmd == "import-legacy":
            if args.pem_file or args.pem_env:
                raise CLIError("--pem-file/--pem-env are for --algorithm RSA; DES/3DES keys use --hex-env or --stdin")
            if args.hex_env:
                material = os.environ.get(args.hex_env)
                if not material:
                    raise CLIError(f"environment variable {args.hex_env} is empty")
            else:
                material = sys.stdin.readline()
            try:
                key = bytes.fromhex(material.strip().replace(" ", ""))
            except ValueError as exc:
                raise CLIError("legacy key must be hexadecimal") from exc
            notes = store.import_legacy(args.key_id, args.algorithm, key)
            _out(args, f"Imported {args.key_id} ({args.algorithm}, decrypt-only) KCV {store.meta(args.key_id)['kcv']}"
                       " - confirm it matches the custodian/HSM record")
            for note in notes:
                _out(args, color(f"  note: {note}", "yellow"))
        elif args.keys_cmd == "destroy":
            return _destroy_key(args, cfg, store)
    except (KeystoreError, ValueError) as exc:
        raise CLIError(str(exc)) from exc
    return 0


def _destroy_key(args, cfg, store) -> int:
    from .migration.engine import MigrationEngine

    if args.confirm != args.key_id:
        raise CLIError(f"type the key id to confirm: --confirm {args.key_id}")
    approvers: set[str] = set()
    if cfg.governance.get("dual_control"):  # two-person rule for an irreversible operation
        approvals = (cfg.governance.get("approvals") or {}).get("key_destruction") or []
        approvers = {str(a.get("by")) for a in approvals if isinstance(a, dict) and a.get("by")}
        if len(approvers) < 2:
            raise CLIError("dual control is on: record two distinct approvers under governance.approvals."
                           "key_destruction (merged through a reviewed, signed pull request)")
    meta = store.meta(args.key_id)
    if meta.get("legacy"):
        dependent = [d for d in cfg.data_sources
                     if any(cfg.legacy_profiles[p].key_id == args.key_id for p in d.profiles())]
        engine = MigrationEngine(cfg, store)
        blocking = []
        for ds in dependent:
            result = engine.verify_source(ds)
            if result["status"] == "error" or result["legacy"] or result["invalid"]:
                detail = result.get("message") or f"{result['legacy']} legacy, {result['invalid']} unreadable"
                blocking.append(f"{ds.name}: {detail}")
        if blocking and not args.force:
            raise CLIError("refusing to destroy a legacy key while data still depends on it (it would become "
                           "permanently unreadable): " + "; ".join(blocking) + " - use --force only with a recorded "
                                                                              "risk acceptance")
    store.destroy(args.key_id, args.reason + (f" (approved by {', '.join(sorted(approvers))})" if approvers else ""))
    _out(args, f"Destroyed {args.key_id} (crypto-shredded; audit-logged). "
               "Backups encrypted under it are now unreadable.")
    return 0


# ------------------------------------------------------------------- phase 4/5
def cmd_selftest(args) -> int:
    from .crypto.selftest import run_selftest

    results = run_selftest()
    _out(args, text_table(["test", "status", "description", "source"],
                          [[r["id"], _status("pass" if r["passed"] else "fail"), r["description"], r["source"]]
                           for r in results]))
    return 0 if all(r["passed"] for r in results) else 1


def cmd_validate(args) -> int:
    from .crypto.service import CryptoService
    from .validation import run_validation, write_validation

    cfg = _cfg(args, require=True)
    store, _ = _keystore(cfg)
    service = CryptoService(store, cfg.target_algorithm, cfg.legacy_profiles, mode="dual")
    report = run_validation(cfg, service, quick=args.quick)
    written = write_validation(cfg, report)
    _out(args, text_table(["check", "status", "detail"], [[c["id"], _status(c["status"]), c["detail"]]
                                                          for c in report["checks"]], 80))
    _out(args, f"\nValidation {_status(report['status'])} - wrote {written['md']}")
    return 0 if report["status"] == "pass" else 1


def cmd_remediate(args) -> int:
    from .remediation import apply_remediation, plan_remediation

    cfg = _cfg(args, require=True)
    inv_path = cfg.artifact("inventory.json")
    if not inv_path.exists():
        raise CLIError("no inventory - run `cryptomigrate discover` first")
    changes, manual = plan_remediation(cfg, _policy(cfg), read_json(inv_path)["findings"],
                                       set(args.rule) if args.rule else None, args.path)
    for change in changes:
        _out(args, change.diff())
    for item in manual:
        _out(args, color(f"  manual: {item['location']}:{item['line']} {item['rule_id']} - {item['reason']}", "yellow"))
    if not changes:
        _out(args, "Nothing to remediate automatically.")
        return 0
    if not args.apply:
        _out(args, f"\nDry run: {sum(len(c.changes) for c in changes)} change(s) in {len(changes)} file(s). "
                   "Re-run with --apply to write them (backed up and reversible).")
        return 0
    try:
        manifest = apply_remediation(cfg, changes, args.change_ticket, args.approver)
    except RuntimeError as exc:
        raise CLIError(str(exc)) from exc
    _out(args, f"Applied - run {manifest['run_id']} (rollback: cryptomigrate rollback --run {manifest['run_id']}). "
               "Reload the affected services, then re-run discover.")
    return 0


# ------------------------------------------------------------------- phase 5/6
def cmd_reencrypt(args) -> int:
    from .migration.engine import MigrationAborted, MigrationEngine

    cfg = _cfg(args, require=True)
    if not cfg.data_sources:
        raise CLIError("no data_sources configured in migration.yaml")
    if args.source:
        sources = [cfg.source(args.source)]
    elif args.wave is not None:
        sources = [d for d in cfg.data_sources if cfg.source_wave(d) == args.wave]
    else:
        sources = sorted(cfg.data_sources, key=cfg.source_wave)
    if not sources:
        raise CLIError(f"no data sources in wave {args.wave}")
    if args.resume and len(sources) != 1:
        raise CLIError("--resume needs --source")
    store, _ = _keystore(cfg)
    engine = MigrationEngine(cfg, store)
    exit_code = 0
    for ds in sources:
        try:
            manifest = engine.run(ds, apply=args.apply, resume=args.resume, change_ticket=args.change_ticket,
                                  approver=args.approver, limit=args.limit)
        except MigrationAborted as exc:
            _out(args, color(f"{ds.name}: {exc}", "red"))
            return 1
        c = manifest["counters"]
        verb = "migrated" if args.apply else "would migrate"
        shown = "pass" if manifest["status"] == "completed" else manifest["status"]
        _out(args, f"{ds.name} [{manifest['mode']}] {_status(shown)}"
                   f" run={manifest['run_id']} scanned={c['scanned']} {verb}="
                   f"{c['migrated'] if args.apply else c['would_migrate']} already_v2={c['already_v2']} "
                   f"empty={c['empty']} errors={c['errors']} concurrent_skips={c['concurrent_skips']}")
        if manifest.get("message"):
            _out(args, color(f"  {manifest['message']}", "red"))
        for error in manifest["errors"][:5]:
            _out(args, f"  error {error['record']}/{error['field']}: {error['error']}")
        if manifest["status"] != "completed" or c["errors"]:
            exit_code = 1
    return exit_code


def cmd_rollback(args) -> int:
    cfg = _cfg(args, require=True)
    path = cfg.artifact("runs", f"{args.run}.json")
    if not path.exists():
        raise CLIError(f"no run manifest {path}")
    kind = read_json(path).get("type")
    try:
        if kind == "remediate":
            from .remediation import rollback_remediation

            manifest = rollback_remediation(cfg, args.run, args.change_ticket)
        else:
            from .migration.engine import MigrationEngine

            store, _ = _keystore(cfg)
            manifest = MigrationEngine(cfg, store).rollback(args.run, args.change_ticket)
    except RuntimeError as exc:
        raise CLIError(str(exc)) from exc
    rb = manifest["rollback"]
    _out(args, f"Rolled back {args.run}: restored {rb['restored']}, conflicts {len(rb['conflicts'])}")
    return 0 if not rb["conflicts"] else 1


# ------------------------------------------------------------------- phase 7
def cmd_verify(args) -> int:
    from .verification import run_verification, write_verification

    cfg = _cfg(args, require=True)
    store, _ = _keystore(cfg, required=False)
    report = run_verification(cfg, _policy(cfg), store, probe_tls=not args.no_tls)
    written = write_verification(cfg, report)
    _out(args, text_table(["check", "status", "detail"], [[c["id"], _status(c["status"]), c["detail"]]
                                                          for c in report["checks"]], 90))
    _out(args, f"\nVerification {_status(report['status'])} - wrote {written['md']}")
    return 0 if report["status"] == "pass" else 1


def cmd_attest(args) -> int:
    from .reporting.attest import build_attestation

    cfg = _cfg(args, require=True)
    store, _ = _keystore(cfg, required=False)
    statement = build_attestation(cfg, store.list() if store else None)
    _out(args, f"{'ATTESTED' if statement['attested'] else 'NOT ATTESTED'} - {statement['evidence']} evidence files, "
               f"digest {statement['evidence_digest']}\n  package: {statement['package']}")
    return 0 if statement["attested"] else 1


# ------------------------------------------------------------------- governance
def cmd_gate(args) -> int:
    from .gates import PHASES, evaluate_gate, write_gate

    cfg = _cfg(args, require=True)
    store, error = _keystore(cfg, required=False)
    phases = list(PHASES) if args.all else [args.phase]
    worst = 0
    for phase in phases:
        result = evaluate_gate(cfg, phase, store, error)
        write_gate(cfg, result)
        _out(args, f"\nPhase {phase} - {result['name']}: {_status(result['status'])} "
                   f"({result['passed']}/{result['total']})")
        _out(args, text_table(["criterion", "type", "status", "evidence"],
                              [[c["criterion"], c["type"], _status(c["status"]), c["evidence"]]
                               for c in result["criteria"]], 70))
        worst = max(worst, 0 if result["status"] == "pass" else 1)
    return worst


def cmd_status(args) -> int:
    from .gates import PHASES, evaluate_gate

    cfg = _cfg(args, require=True)
    store, error = _keystore(cfg, required=False)
    results = [evaluate_gate(cfg, phase, store, error) for phase in PHASES]
    current = next((r for r in results if r["status"] != "pass"), None)
    _out(args, f"{cfg.project.get('name') or 'Project'} - {cfg.project.get('organization') or ''}".strip(" -"))
    _out(args, text_table(["phase", "name", "exit criteria", "status"],
                          [[r["phase"], r["name"], f"{r['passed']}/{r['total']}", _status(r["status"])]
                           for r in results]))
    if current:
        _out(args, f"\nCurrent phase: {current['phase']} - {current['name']}. Outstanding:")
        for c in current["criteria"]:
            if c["status"] == "fail":
                _out(args, f"  - {c['criterion']}: {c['evidence']}")
    else:
        _out(args, "\nAll seven phase gates pass. Migration complete.")
    return 0


def cmd_audit(args) -> int:
    cfg = _cfg(args)
    log = AuditLog(cfg.audit_path)
    if args.audit_cmd == "verify":
        ok, entries, error = log.verify()
        suffix = f" - {error}" if error else ""
        _out(args, f"{_status('pass' if ok else 'fail')} {entries} entries, head {log.head()}{suffix}")
        return 0 if ok else 1
    for entry in log.entries()[-args.n:]:
        _out(args, f"{entry['seq']:>5} {entry['ts']} {entry['actor']:<24} {entry['event']:<20} "
                   f"{', '.join(f'{k}={v}' for k, v in entry['details'].items())[:120]}")
    return 0


def cmd_doctor(args) -> int:
    from .doctor import run_doctor

    checks = run_doctor(_cfg(args))
    _out(args, text_table(["check", "status", "title", "detail"],
                          [[c["id"], _status(c["status"]), c["title"], c["detail"]] for c in checks], 70))
    return 1 if any(c["status"] == "fail" for c in checks) else 0


def cmd_policies(args) -> int:
    from .discovery.policy import builtin_policies, load_policy

    for name in builtin_policies():
        policy = load_policy(name)
        _out(args, f"{policy.id:16} v{policy.version:8} {len(policy.rules):>3} rules  {policy.name}")
    return 0


# ------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cryptomigrate", description="SDLC-driven DES/3DES -> AES migration toolkit.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n")[1])
    p.add_argument("--version", action="version", version=f"cryptomigrate {__version__}")
    p.add_argument("-c", "--config", help="path to migration.yaml (default: ./migration.yaml)")
    p.add_argument("-q", "--quiet", action="store_true")
    common = argparse.ArgumentParser(add_help=False)  # lets -c/-q also follow the subcommand
    common.add_argument("-c", "--config", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    common.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    _add = sub.add_parser
    sub.add_parser = lambda *a, **k: _add(*a, parents=[common, *k.pop("parents", [])], **k)  # type: ignore[method-assign]

    s = sub.add_parser("init", help="Phase 1: scaffold migration.yaml, ignore file, .gitignore [and GitHub files]")
    s.add_argument("--dir", default=".")
    s.add_argument("--github", action="store_true", help="also install CI gate, issue forms, PR template, CODEOWNERS")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("discover", help="Phase 2: build the cryptographic inventory")
    s.add_argument("paths", nargs="*", help="override scan.paths")
    s.add_argument("--format", default="json,sarif,cbom,md", help="comma list of json,sarif,cbom,md")
    s.add_argument("--out", help="artifact directory (default: artifacts_dir)")
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if an active finding is at/above this severity")
    s.add_argument("--tls", action="append", default=[], metavar="HOST:PORT", help="extra TLS endpoint to probe")
    s.add_argument("--no-tls", action="store_true", help="skip TLS endpoint probes")
    s.add_argument("--no-data", action="store_true", help="skip data-at-rest profiling")
    s.add_argument("--policy", help="policy pack id or YAML path (default: config policy)")
    s.add_argument("--layers", help="comma list of security layers, overriding the config (e.g. pki-tls,secure-coding)")
    s.add_argument("--binaries", action="append", default=[], metavar="PATH", help="ELF binaries/dirs to check")
    s.add_argument("--ca-bundle", help="CA bundle for verifying TLS endpoints (private PKI)")
    s.add_argument("--limit", type=int, default=25, help="max findings printed")
    s.set_defaults(func=cmd_discover)

    sub.add_parser("assess", help="Phase 2: gap, compatibility & compliance assessment").set_defaults(func=cmd_assess)
    sub.add_parser("plan", help="Phase 3: wave plan, runbooks, key plan, WBS issues").set_defaults(func=cmd_plan)

    s = sub.add_parser("keys", help="Phase 3/4/7: key lifecycle")
    ks = s.add_subparsers(dest="keys_cmd", required=True)
    ks.add_parser("new-kek", help="print a fresh random KEK (base64) for CRYPTOMIGRATE_KEK")
    k = ks.add_parser("init", help="create the keystore and the first AES key")
    k.add_argument("--bits", type=int, choices=(128, 256), default=256)
    ks.add_parser("list", help="list keys (metadata only)")
    k = ks.add_parser("rotate", help="generate a new active key; previous key becomes decrypt-only")
    k.add_argument("--bits", type=int, choices=(128, 256), default=256)
    k.add_argument("--reason", default="scheduled rotation")
    k = ks.add_parser("import-legacy", help="import a legacy DES/3DES key or hybrid RSA private key (decrypt-only)")
    k.add_argument("--key-id", required=True)
    k.add_argument("--algorithm", choices=("DES", "3DES", "RSA"), default="3DES")
    group = k.add_mutually_exclusive_group(required=True)
    group.add_argument("--hex-env", metavar="VAR", help="environment variable holding the hex DES/3DES key")
    group.add_argument("--stdin", action="store_true", help="read the hex DES/3DES key from stdin")
    group.add_argument("--pem-file", metavar="PATH", help="PEM file holding the legacy RSA private key")
    group.add_argument("--pem-env", metavar="VAR", help="environment variable holding the PEM RSA private key")
    k.add_argument("--pem-password-env", metavar="VAR", help="environment variable holding the PEM passphrase")
    k = ks.add_parser("destroy", help="crypto-shred a key (refuses while legacy data depends on it)")
    k.add_argument("--key-id", required=True)
    k.add_argument("--confirm", required=True, help="repeat the key id to confirm")
    k.add_argument("--reason", required=True)
    k.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_keys)

    sub.add_parser("selftest", help="Phase 4: cryptographic known-answer tests").set_defaults(func=cmd_selftest)
    s = sub.add_parser("validate", help="Phase 5: validation suite (KAT, tamper, AAD, no-fallback, NFR-01, data)")
    s.add_argument("--quick", action="store_true")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("remediate", help="Phase 4/6: fix TLS/SSH cipher lists (dry run unless --apply)")
    s.add_argument("--apply", action="store_true")
    s.add_argument("--rule", action="append", help="limit to rule id(s)")
    s.add_argument("--path", action="append", help="limit to path prefix(es)")
    s.add_argument("--change-ticket")
    s.add_argument("--approver")
    s.set_defaults(func=cmd_remediate)

    s = sub.add_parser("reencrypt", help="Phase 5/6: re-encrypt data at rest (dry run unless --apply)")
    target = s.add_mutually_exclusive_group()
    target.add_argument("--source")
    target.add_argument("--wave", type=int)
    s.add_argument("--apply", action="store_true")
    s.add_argument("--resume", metavar="RUN_ID")
    s.add_argument("--limit", type=int, help="process at most N records (canary)")
    s.add_argument("--change-ticket")
    s.add_argument("--approver")
    s.set_defaults(func=cmd_reencrypt)

    s = sub.add_parser("rollback", help="Phase 6: reverse a reencrypt or remediate run")
    s.add_argument("--run", required=True)
    s.add_argument("--change-ticket")
    s.set_defaults(func=cmd_rollback)

    s = sub.add_parser("verify", help="Phase 7: prove no DES/3DES remains (scan, probes, every stored value)")
    s.add_argument("--no-tls", action="store_true")
    s.set_defaults(func=cmd_verify)
    sub.add_parser("attest", help="Phase 7: compliance evidence package").set_defaults(func=cmd_attest)

    s = sub.add_parser("gate", help="evaluate phase exit criteria")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--phase", type=int, choices=range(1, 8))
    g.add_argument("--all", action="store_true")
    s.set_defaults(func=cmd_gate)
    sub.add_parser("status", help="progress dashboard across all seven phases").set_defaults(func=cmd_status)

    s = sub.add_parser("audit", help="audit log")
    a = s.add_subparsers(dest="audit_cmd", required=True)
    a.add_parser("verify", help="verify the hash chain")
    t = a.add_parser("tail", help="show recent entries")
    t.add_argument("-n", type=int, default=20)
    s.set_defaults(func=cmd_audit)
    sub.add_parser("policies", help="list built-in policy packs").set_defaults(func=cmd_policies)
    sub.add_parser("doctor", help="host hardening preflight for the migration operator").set_defaults(func=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    try:  # key material must never reach a core file
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except (CLIError, ConfigError) as exc:
        print(color(f"error: {exc}", "red"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

