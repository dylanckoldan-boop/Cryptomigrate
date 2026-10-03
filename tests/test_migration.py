import sqlite3

import pytest
import yaml

from cryptomigrate.cli import main
from cryptomigrate.config import load_config
from cryptomigrate.crypto.service import CryptoService
from cryptomigrate.migration.adapters import SQLAdapter
from cryptomigrate.migration.engine import MigrationAborted, MigrationEngine

from .conftest import FILES, PEOPLE


def rows(cfg):
    db = sqlite3.connect(cfg.root / "legacy.db")
    out = {r[0]: (r[1], r[2]) for r in db.execute("SELECT id, ssn_enc, card_enc FROM customers ORDER BY id")}
    db.close()
    return out


def test_dry_run_changes_nothing(project):
    cfg, store = project
    before = rows(cfg)
    manifest = MigrationEngine(cfg, store).run(cfg.source("customers"))
    c = manifest["counters"]
    assert manifest["status"] == "completed" and manifest["mode"] == "dry-run"
    assert c["would_migrate"] == 12 and c["empty"] == 2 and c["errors"] == 0 and c["migrated"] == 0
    assert rows(cfg) == before and manifest["backup"] is None


def test_apply_is_correct_idempotent_and_readable_by_the_app(project):
    cfg, store = project
    engine = MigrationEngine(cfg, store)
    first = engine.run(cfg.source("customers"), apply=True, change_ticket="CHG-1")
    assert first["status"] == "completed" and first["counters"]["migrated"] == 12
    svc = CryptoService(store, cfg.target_algorithm, cfg.legacy_profiles, mode="strict")
    after = rows(cfg)
    for pk, _name, ssn, card in PEOPLE:
        ssn_value, card_value = after[pk]
        if ssn:
            assert ssn_value.startswith("$cm2$")
            assert svc.decrypt(ssn_value, f"customers.ssn_enc#{pk}") == ssn
        if card is not None:
            assert svc.decrypt(card_value, f"customers.card_enc#{pk}") == card
    second = engine.run(cfg.source("customers"), apply=True)
    assert second["counters"]["migrated"] == 0 and second["counters"]["already_v2"] == 12
    assert engine.verify_source(cfg.source("customers"))["status"] == "pass"
    assert store.meta(store.active_key_id())["usage"]["encryptions"] == 12


def test_rollback_restores_exact_ciphertext(project):
    cfg, store = project
    before = rows(cfg)
    engine = MigrationEngine(cfg, store)
    run = engine.run(cfg.source("customers"), apply=True)
    assert rows(cfg) != before
    rolled = engine.rollback(run["run_id"])
    assert rolled["status"] == "rolled-back" and rolled["rollback"]["restored"] == 12
    assert rows(cfg) == before
    assert engine.verify_source(cfg.source("customers"))["legacy"] == 12
    with pytest.raises(MigrationAborted, match="already rolled back"):
        engine.rollback(run["run_id"])


def test_concurrent_application_write_is_never_clobbered(project, monkeypatch):
    cfg, store = project
    svc = CryptoService(store, cfg.target_algorithm, cfg.legacy_profiles)
    app_value = svc.encrypt_text(b"999-99-9999", "customers.ssn_enc#3")
    original = SQLAdapter.update_cas

    def racing(self, pk, column, old, new):
        if pk == 3 and column == "ssn_enc":  # the live app re-encrypts row 3 between our read and our write
            self.conn.execute("UPDATE customers SET ssn_enc = ? WHERE id = 3", (app_value,))
        return original(self, pk, column, old, new)

    monkeypatch.setattr(SQLAdapter, "update_cas", racing)
    manifest = MigrationEngine(cfg, store).run(cfg.source("customers"), apply=True)
    assert manifest["counters"]["concurrent_skips"] == 1 and manifest["counters"]["migrated"] == 11
    assert rows(cfg)[3][0] == app_value


def test_truncating_database_rolls_back_the_batch(project):
    cfg, store = project
    db = sqlite3.connect(cfg.root / "legacy.db")
    db.execute("CREATE TRIGGER truncate AFTER UPDATE OF ssn_enc ON customers BEGIN "
               "UPDATE customers SET ssn_enc = substr(NEW.ssn_enc, 1, 40) WHERE id = NEW.id; END")
    db.commit()
    db.close()
    before = rows(cfg)
    manifest = MigrationEngine(cfg, store).run(cfg.source("customers"), apply=True)
    assert manifest["status"] == "aborted" and "read-back verification failed" in manifest["message"]
    assert rows(cfg) == before  # whole batch rolled back, nothing half-written


def test_column_too_narrow_is_caught_before_writing(tmp_path, kek):
    from .conftest import LEGACY_KEY, build_legacy_project

    path = build_legacy_project(tmp_path / "p")
    data = yaml.safe_load(path.read_text())
    data["data_sources"][0]["columns"][0]["max_length"] = 40
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    cfg = load_config(path)
    from cryptomigrate.keys.keystore import Keystore

    store = Keystore.from_config(cfg, create=True)
    store.generate()
    store.import_legacy("legacy-3des", "3DES", LEGACY_KEY)
    dry = MigrationEngine(cfg, store).run(cfg.source("customers"))
    assert dry["counters"]["errors"] == 6 and "widen the column" in dry["errors"][0]["error"]
    applied = MigrationEngine(cfg, store).run(cfg.source("customers"), apply=True)
    assert applied["status"] == "aborted" and "error rate" in applied["message"]


def test_files_apply_verify_and_rollback(project):
    cfg, store = project
    engine = MigrationEngine(cfg, store)
    originals = {rel: (cfg.root / "archive" / rel).read_bytes() for rel in FILES}
    run = engine.run(cfg.source("archive"), apply=True)
    assert run["counters"]["migrated"] == 3
    svc = CryptoService(store, cfg.target_algorithm, cfg.legacy_profiles, mode="strict")
    for rel, content in FILES.items():
        assert svc.decrypt((cfg.root / "archive" / rel).read_bytes()) == content
    assert engine.verify_source(cfg.source("archive"))["status"] == "pass"
    engine.rollback(run["run_id"])
    assert {rel: (cfg.root / "archive" / rel).read_bytes() for rel in FILES} == originals


def test_resume_after_failure(project, monkeypatch):
    cfg, store = project
    calls = {"n": 0}
    original = MigrationEngine._apply_sql

    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ConnectionError("database went away")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(MigrationEngine, "_apply_sql", flaky)
    engine = MigrationEngine(cfg, store)
    failed = engine.run(cfg.source("customers"), apply=True)
    assert failed["status"] == "failed" and failed["counters"]["migrated"] < 12
    monkeypatch.setattr(MigrationEngine, "_apply_sql", original)
    resumed = engine.run(cfg.source("customers"), apply=True, resume=failed["run_id"])
    assert resumed["status"] == "completed" and resumed["run_id"] == failed["run_id"]
    assert engine.verify_source(cfg.source("customers"))["status"] == "pass"


def test_canary_limit(project):
    cfg, store = project
    run = MigrationEngine(cfg, store).run(cfg.source("customers"), apply=True, limit=2)
    assert run["counters"]["migrated"] == 4 and run["limit"] == 2


def test_preflight_requires_legacy_key_and_change_ticket(project):
    cfg, store = project
    cfg.governance["require_change_ticket"] = True
    with pytest.raises(MigrationAborted, match="change-ticket"):
        MigrationEngine(cfg, store).run(cfg.source("customers"), apply=True)
    cfg.governance["require_change_ticket"] = False
    store.destroy("legacy-3des", "test")
    with pytest.raises(MigrationAborted, match="legacy key"):
        MigrationEngine(cfg, store).run(cfg.source("customers"))


def test_key_destroy_interlock_via_cli(project, capsys):
    cfg, _ = project
    args = ["--config", str(cfg.path), "keys", "destroy", "--key-id", "legacy-3des", "--confirm", "legacy-3des",
            "--reason", "test"]
    assert main(args) == 2 and "refusing to destroy" in capsys.readouterr().err
    assert main(["--config", str(cfg.path), "reencrypt", "--apply"]) == 0
    assert main(args) == 0


def test_gate_counts_full_run_after_rolled_back_canary(project):
    """Regression: canary + rollback + full run in the same second must still satisfy the Phase 6 gate."""
    from cryptomigrate.gates import evaluate_gate

    cfg, store = project
    engine = MigrationEngine(cfg, store)
    canary = engine.run(cfg.source("customers"), apply=True, limit=1)
    engine.rollback(canary["run_id"])
    engine.run(cfg.source("customers"), apply=True)
    criteria = {c["id"]: c for c in evaluate_gate(cfg, 6, store)["criteria"]}
    assert criteria["P6-APPLY:customers"]["status"] == "pass"
    assert criteria["P6-APPLY:archive"]["status"] == "fail"  # never applied
