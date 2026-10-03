import json
import shutil
from importlib import resources

import pytest
import yaml

from cryptomigrate.cli import main
from cryptomigrate.config import ConfigError, build_config, load_config
from cryptomigrate.crypto.service import CryptoService
from cryptomigrate.discovery.policy import load_policy
from cryptomigrate.discovery.run import run_discovery
from cryptomigrate.gates import evaluate_gate
from cryptomigrate.reporting.formats import to_cbom, to_sarif
from cryptomigrate.validation import run_validation

from .conftest import FIXTURES

POLICY = load_policy("des-to-aes")


@pytest.fixture
def fixture_inventory(tmp_path):
    shutil.copytree(FIXTURES, tmp_path / "repo")
    cfg = build_config({"systems": [{"id": "app", "name": "App", "owner": "Owner", "paths": ["source/**"]},
                                    {"id": "ops", "name": "Ops", "owner": "Ops", "paths": ["config/**"]}]},
                       tmp_path / "repo")
    return cfg, run_discovery(cfg, POLICY, probe_tls=False, profile_data=False)


def test_sarif_is_well_formed(fixture_inventory):
    _, inventory = fixture_inventory
    sarif = to_sarif(inventory, POLICY)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "cryptomigrate"
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1 and result["message"]["text"]
        assert result["level"] in ("error", "warning", "note")
    assert any("suppressions" in r for r in run["results"])
    assert all(float(r["properties"]["security-severity"]) >= 0 for r in rules)


def test_cbom_validates_against_cyclonedx_1_6_schema(fixture_inventory):
    validation = pytest.importorskip("cyclonedx.validation.json")
    schema = pytest.importorskip("cyclonedx.schema")
    _, inventory = fixture_inventory
    bom = to_cbom(inventory, POLICY)
    error = validation.JsonStrictValidator(schema.SchemaVersion.V1_6).validate_str(json.dumps(bom))
    assert error is None, str(error)
    names = {c["name"] for c in bom["components"]}
    assert {"3DES-CBC", "DES", "AES-256-GCM"} <= names
    tdes = next(c for c in bom["components"] if c["name"] == "3DES-CBC")
    assert tdes["cryptoProperties"]["oid"] == "1.2.840.113549.3.7"
    assert tdes["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 112


def test_assessment_and_plan(fixture_inventory):
    from cryptomigrate.reporting.assess import assessment_markdown, build_assessment
    from cryptomigrate.reporting.plan import write_plan

    cfg, inventory = fixture_inventory
    assessment = build_assessment(cfg, POLICY, inventory)
    assert assessment["summary"]["unassigned_findings"] == 0
    assert assessment["compliance"]["PCI-DSS-4.0"]["status"] == "non-conformant"
    types = assessment["summary"]["by_change_type"]
    assert types["Configuration change"] >= 4 and types["Coordinated configuration change"] >= 5
    assert "Compliance position" in assessment_markdown(assessment)
    written = write_plan(cfg, assessment)
    runbook = written["runbook:ops"].read_text()
    assert "cryptomigrate remediate" in runbook and "Rollback" in runbook
    script = written["github_issues"].read_text()
    assert "gh issue create" in script and "phase:7-closeout" in script


def test_remediation_fixes_and_rolls_back(fixture_inventory):
    from cryptomigrate.remediation import apply_remediation, plan_remediation, rollback_remediation

    cfg, inventory = fixture_inventory
    originals = {p: (cfg.root / p).read_text() for p in ("config/nginx.conf", "config/sshd_config",
                                                          "config/server.xml", "config/application.properties")}
    changes, manual = plan_remediation(cfg, POLICY, inventory["findings"])
    assert {c.relpath for c in changes} == set(originals) | {"config/httpd-ssl.conf"}
    manifest = apply_remediation(cfg, changes, change_ticket="CHG-9")
    nginx = (cfg.root / "config/nginx.conf").read_text()
    assert "ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:!3DES:!DES';" in nginx
    assert "ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!DES;" in nginx
    assert "Ciphers aes256-gcm@openssh.com\n" in (cfg.root / "config/sshd_config").read_text()
    assert 'ciphers="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"' in (cfg.root / "config/server.xml").read_text()
    rescan = run_discovery(cfg, POLICY, probe_tls=False, profile_data=False)
    fixed_rules = {"CM-TLS-001", "CM-TLS-002", "CM-SSH-001"}
    assert not [f for f in rescan["findings"] if f["rule_id"] in fixed_rules]
    rollback_remediation(cfg, manifest["run_id"])
    assert {p: (cfg.root / p).read_text() for p in originals} == originals


def test_gate_phase1_requires_charter_and_signoff(tmp_path):
    template = resources.files("cryptomigrate.templates").joinpath("migration.yaml").read_text()
    (tmp_path / "migration.yaml").write_text(template)
    cfg = load_config(tmp_path / "migration.yaml")
    result = evaluate_gate(cfg, 1)
    assert result["status"] == "fail"
    assert {c["id"] for c in result["criteria"] if c["status"] == "fail"} >= {"P1-CHARTER", "P1-DATE", "P1-SIGNOFF"}
    data = yaml.safe_load((tmp_path / "migration.yaml").read_text())
    data["project"].update(name="X", organization="Y", sponsor="S", project_manager="P", security_lead="L",
                           target_completion="2027-01-31")
    data["governance"]["signoffs"] = {"charter": {"by": "S (Sponsor)", "date": "2026-10-01", "ref": "#1"}}
    data["systems"][0]["id"] = "app"
    (tmp_path / "migration.yaml").write_text(yaml.safe_dump(data))
    assert evaluate_gate(load_config(tmp_path / "migration.yaml"), 1)["status"] == "pass"


def test_validation_suite_passes(project):
    cfg, store = project
    report = run_validation(cfg, CryptoService(store, cfg.target_algorithm, cfg.legacy_profiles), quick=True)
    failing = [c for c in report["checks"] if c["status"] == "fail" and c["id"] != "VAL-PERF"]
    assert not failing, failing
    ids = {c["id"] for c in report["checks"]}
    assert {"KAT-TDEA", "VAL-TAMPER", "VAL-AAD", "VAL-NO-FALLBACK", "VAL-PROFILE:customers:ssn_enc"} <= ids


@pytest.mark.parametrize("patch,message", [
    ({"target": {"algorithm": "AES-256-CBC"}}, "target.algorithm"),
    ({"legacy_profiles": {"p": {"mode": "ECB", "iv": "prefix"}}}, "ECB mode"),
    ({"data_sources": [{"name": "d", "adapter": "sql", "driver": "sqlite3", "table": "t; DROP TABLE x",
                        "primary_key": "id", "columns": [{"name": "c", "legacy_profile": "p"}]}],
      "legacy_profiles": {"p": {}}}, "invalid SQL identifier"),
    ({"data_sources": [{"name": "d", "adapter": "files", "path": "x", "legacy_profile": "missing"}]}, "not defined"),
])
def test_config_validation(tmp_path, patch, message):
    with pytest.raises(ConfigError, match=message):
        build_config(patch, tmp_path)


def test_cli_init_discover_and_fail_on(tmp_path, capsys):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "source", repo / "src")
    assert main(["init", "--dir", str(repo), "--github"]) == 0
    assert (repo / ".github/workflows/crypto-gate.yml").exists() and (repo / ".github/CODEOWNERS").exists()
    assert ".cryptomigrate/" in (repo / ".gitignore").read_text()
    cfg_path = str(repo / "migration.yaml")
    assert main(["--config", cfg_path, "discover", "--no-tls", "--no-data", "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "active findings" in out and (repo / "artifacts/cbom.cdx.json").exists()
    assert main(["--config", cfg_path, "discover", "--no-tls", "--no-data", "--fail-on", "critical",
                 "--format", "json"]) == 1  # single DES findings are critical
    assert main(["--config", cfg_path, "gate", "--phase", "4"]) == 1


def test_extending_doc_policy_example_works(tmp_path):
    """The SHA-1 policy pack shown in docs/EXTENDING.md must load and detect - docs may not drift from code."""
    from pathlib import Path

    doc = (Path(__file__).parent.parent / "docs" / "EXTENDING.md").read_text()
    block = doc.split("```yaml\n", 1)[1].split("```", 1)[0]
    (tmp_path / "sha1.yaml").write_text(block)
    (tmp_path / "app.py").write_text("import hashlib\nd = hashlib.sha1(b'x')\n")
    (tmp_path / "Digest.java").write_text('MessageDigest md = MessageDigest.getInstance("SHA-1");\n')
    cfg = build_config({"policy": "sha1.yaml"}, tmp_path)
    policy = load_policy(cfg.policy, cfg.root)
    inventory = run_discovery(cfg, policy, probe_tls=False, profile_data=False)  # no CM-MANUAL-001 needed
    assert sorted((f["rule_id"], f["algorithm"]) for f in inventory["findings"]) == [
        ("SHA1-JAVA-001", "SHA-1"), ("SHA1-PY-001", "SHA-1")]
