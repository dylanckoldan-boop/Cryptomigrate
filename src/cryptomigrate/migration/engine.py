"""Re-encryption engine (Phase 6) and full-population verification (Phase 7).

Safety properties (traceable to FR-02, FR-06, NFR-02, R-04 in the workplan):

* **Dry-run by default** - nothing is written without ``apply=True``.
* **Pre-flight** - known-answer self-test, active AES key, legacy keys present, backups on.
* **Backup before write** - original ciphertext of every changed value is staged in a
  per-run SQLite backup (files are copied) *before* the source is touched.
* **Compare-and-swap writes** - ``UPDATE ... WHERE pk = ? AND col = <value we read>`` so
  rows changed concurrently by the live application are skipped, never clobbered.
* **Read-back inside the transaction** - written values are re-read before COMMIT; any
  truncation/coercion rolls the whole batch back.
* **Idempotent and resumable** - v2 values are skipped; a checkpoint allows ``--resume``.
* **No plaintext persisted** - verification happens in memory; manifests hold counts only.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .. import __version__
from ..audit import AuditLog
from ..config import Config, DataSource
from ..crypto.selftest import run_selftest
from ..crypto.service import CryptoService
from ..malware import MalwareScanError, ping, scan_bytes
from ..util import actor, ensure_private_dir, isotime, new_run_id, read_json, sha256_bytes, write_json
from .adapters import FILE_FIELD, FileAdapter, SQLAdapter, Target, open_adapter

MAX_ERRORS_RECORDED = 1000


class MigrationAborted(RuntimeError):
    pass


def _storable(value: Any) -> Any:
    return value.tobytes() if isinstance(value, memoryview) else value


class BackupStore:
    """Column-level backup of original ciphertext, independent of the source database engine."""

    def __init__(self, path: Path):
        ensure_private_dir(path.parent)
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute("CREATE TABLE IF NOT EXISTS backup (record TEXT NOT NULL, field TEXT NOT NULL, "
                          "old_value, new_value, status TEXT NOT NULL, PRIMARY KEY (record, field))")
        self.conn.commit()

    def stage(self, rows: list[tuple[str, str, Any, Any]]) -> None:
        self.conn.executemany("INSERT OR REPLACE INTO backup VALUES (?, ?, ?, ?, 'pending')", rows)
        self.conn.commit()

    def mark(self, keys: list[tuple[str, str]], status: str) -> None:
        self.conn.executemany("UPDATE backup SET status = ? WHERE record = ? AND field = ?",
                              [(status, r, f) for r, f in keys])
        self.conn.commit()

    def discard(self, keys: list[tuple[str, str]]) -> None:
        self.conn.executemany("DELETE FROM backup WHERE record = ? AND field = ?", keys)
        self.conn.commit()

    def rows(self, statuses: tuple[str, ...]):
        marks = ",".join("?" * len(statuses))
        sql = f"SELECT record, field, old_value, new_value, status FROM backup WHERE status IN ({marks})"  # noqa: S608
        return self.conn.execute(sql, statuses).fetchall()  # only '?' placeholders were interpolated above

    def counts(self) -> dict[str, int]:
        return dict(self.conn.execute("SELECT status, COUNT(*) FROM backup GROUP BY status").fetchall())

    def close(self) -> None:
        self.conn.close()


class MigrationEngine:
    def __init__(self, cfg: Config, keystore, audit: AuditLog | None = None):
        self.cfg = cfg
        self.keystore = keystore
        self.audit = audit or AuditLog(cfg.audit_path)
        # The engine must read legacy data, so it always runs in dual mode whatever the app setting is.
        self.service = CryptoService(keystore, cfg.target_algorithm, cfg.legacy_profiles, mode="dual")
        self.malware = cfg.malware if cfg.malware.get("enabled") else None

    # ------------------------------------------------------------------ helpers
    def manifest_path(self, run_id: str) -> Path:
        return self.cfg.artifact("runs", f"{run_id}.json")

    def _save(self, manifest: dict[str, Any]) -> None:
        write_json(self.manifest_path(manifest["run_id"]), manifest)

    @staticmethod
    def _error(manifest: dict[str, Any], record: Any, field: str, message: str | None) -> None:
        manifest["counters"]["errors"] += 1
        if len(manifest["errors"]) < MAX_ERRORS_RECORDED:
            manifest["errors"].append({"record": json.dumps(record, default=str), "field": field,
                                       "error": message or "unknown error"})

    @staticmethod
    def _error_rate_exceeded(ds: DataSource, manifest: dict[str, Any]) -> bool:
        c = manifest["counters"]
        return c["errors"] > ds.max_error_rate * max(1, c["scanned"])

    def preflight(self, ds: DataSource, apply: bool) -> list[str]:
        problems = []
        failed = [r["id"] for r in run_selftest() if not r["passed"]]
        if failed:
            problems.append(f"crypto self-test failed: {failed}")
        try:
            self.keystore.active_key_id()
        except Exception as exc:  # noqa: BLE001
            problems.append(str(exc))
        for name in sorted(ds.profiles()):
            key_id = self.cfg.legacy_profiles[name].key_id
            if not self.keystore.has_material(key_id):
                problems.append(f"legacy key {key_id!r} (profile {name}) is missing or destroyed - "
                                f"`cryptomigrate keys import-legacy --key-id {key_id} ...`")
        if apply and not self.cfg.migration.get("backup", True):
            problems.append("migration.backup is false - refusing to apply without a rollback path")
        if self.malware and not ping(str(self.malware.get("clamd", ""))):
            problems.append(f"malware scanning is enabled but clamd is unreachable at {self.malware.get('clamd')}")
        return problems

    # ---------------------------------------------------------------- re-encrypt
    def run(self, ds: DataSource, apply: bool = False, resume: str | None = None, change_ticket: str | None = None,
            approver: str | None = None, limit: int | None = None) -> dict[str, Any]:
        if apply and self.cfg.governance.get("require_change_ticket") and not change_ticket:
            raise MigrationAborted("governance.require_change_ticket is set - pass --change-ticket (NFR-04)")
        problems = self.preflight(ds, apply)
        if problems:
            raise MigrationAborted("pre-flight failed: " + "; ".join(problems))
        target_key = self.keystore.active_key_id()
        if resume:
            manifest = read_json(self.manifest_path(resume))
            if manifest.get("source") != ds.name or manifest.get("mode") != ("apply" if apply else "dry-run"):
                raise MigrationAborted(f"run {resume} is for {manifest.get('source')} ({manifest.get('mode')})")
            if manifest.get("status") not in ("aborted", "failed", "running"):
                raise MigrationAborted(f"run {resume} has status {manifest.get('status')} - nothing to resume")
        else:
            run_id = new_run_id("reencrypt")
            manifest = {
                "run_id": run_id, "type": "reencrypt", "tool_version": __version__, "source": ds.name,
                "adapter": ds.adapter, "system": ds.system, "wave": self.cfg.source_wave(ds),
                "mode": "apply" if apply else "dry-run", "status": "running", "started": isotime(),
                "finished": None, "operator": actor(), "change_ticket": change_ticket, "approver": approver,
                "target_algorithm": self.cfg.target_algorithm, "target_key_id": target_key,
                "legacy_profiles": sorted(ds.profiles()), "limit": limit,
                "counters": {"scanned": 0, "migrated": 0, "would_migrate": 0, "already_v2": 0, "empty": 0,
                             "errors": 0, "concurrent_skips": 0, "malware": 0},
                "errors": [], "checkpoint": {"last_record": None},
                "backup": str(self.cfg.state("backups", run_id, "backup.sqlite")) if apply else None,
            }
        manifest["status"] = "running"
        manifest["resumed"] = manifest.get("resumed", 0) + (1 if resume else 0)
        self._save(manifest)
        self.audit.append("reencrypt.start", run_id=manifest["run_id"], source=ds.name, mode=manifest["mode"],
                          change_ticket=change_ticket, approver=approver, target_key_id=target_key, resume=bool(resume))
        migrated_before = manifest["counters"]["migrated"]
        backup = BackupStore(Path(manifest["backup"])) if apply else None
        try:
            with open_adapter(ds) as adapter:
                if isinstance(adapter, SQLAdapter):
                    self._run_sql(adapter, ds, manifest, apply, backup, limit)
                else:
                    self._run_files(adapter, ds, manifest, apply, backup, limit)
            manifest["status"] = "completed"
        except MigrationAborted as exc:
            manifest["status"], manifest["message"] = "aborted", str(exc)
        except Exception as exc:  # noqa: BLE001 - recorded in the manifest and audit log, then surfaced
            manifest["status"], manifest["message"] = "failed", f"{type(exc).__name__}: {exc}"
        finally:
            manifest["finished"] = isotime()
            if backup:
                manifest["backup_counts"] = backup.counts()
                backup.close()
            self._save(manifest)
            if apply:
                self.keystore.record_usage(target_key, manifest["counters"]["migrated"] - migrated_before)
            self.audit.append("reencrypt.finish", run_id=manifest["run_id"], source=ds.name, mode=manifest["mode"],
                              status=manifest["status"], counters=manifest["counters"])
        return manifest

    def _plan_value(self, old: Any, context: str, target: Target, record: Any, manifest: dict[str, Any],
                    scan: bool = False) -> Any:
        counters = manifest["counters"]
        result = self.service.classify(old, context, target.legacy_profile)
        if result.kind == "empty":
            counters["empty"] += 1
            return None
        if result.kind == "v2":
            counters["already_v2"] += 1
            return None
        if result.kind == "invalid":
            self._error(manifest, record, target.name, result.error)
            return None
        plaintext = result.plaintext
        if scan and self.malware:  # decrypted content is visible to AV for the first time: inspect before re-sealing
            try:
                signature = scan_bytes(plaintext, str(self.malware.get("clamd")),
                                       float(self.malware.get("timeout_s", 30)))
            except MalwareScanError as exc:
                raise MigrationAborted(f"malware scanner failed - failing closed: {exc}") from exc
            if signature:
                counters["malware"] = counters.get("malware", 0) + 1
                self._error(manifest, record, target.name,
                            f"malware detected ({signature}) - left untouched under legacy encryption")
                self.audit.append("malware.detected", run_id=manifest["run_id"], field=target.name,
                                  record=json.dumps(record, default=str), signature=signature)
                return None
        if target.storage == "text":
            new = self.service.encrypt_text(plaintext, context)
        else:
            new = self.service.encrypt(plaintext, context)
        if target.max_length and len(new) > target.max_length:
            self._error(manifest, record, target.name, f"new value needs {len(new)} chars but max_length is "
                                                       f"{target.max_length} - widen the column first")
            return None
        check = self.service.classify(new, context, None)
        if check.kind != "v2" or check.plaintext != plaintext:
            raise MigrationAborted(f"in-memory verification failed for {record}/{target.name}")
        return new

    def _run_sql(self, adapter: SQLAdapter, ds: DataSource, manifest: dict[str, Any], apply: bool,
                 backup: BackupStore | None, limit: int | None) -> None:
        checkpoint = manifest["checkpoint"]
        after = json.loads(checkpoint["last_record"]) if checkpoint.get("last_record") is not None else None
        targets = adapter.targets()
        processed = 0
        for batch in adapter.batches(after, ds.batch_size):
            if limit is not None:
                if processed >= limit:
                    break
                batch = batch[: limit - processed]
            updates = []
            for pk, values in batch:
                processed += 1
                for target in targets:
                    manifest["counters"]["scanned"] += 1
                    new = self._plan_value(values[target.name], adapter.context(target.name, pk), target, pk,
                                           manifest, scan=target.storage == "blob")
                    if new is not None:
                        updates.append((pk, target.name, values[target.name], new))
            if apply:
                if updates:
                    self._apply_sql(adapter, updates, backup, manifest)
            else:
                manifest["counters"]["would_migrate"] += len(updates)
            checkpoint["last_record"] = json.dumps(batch[-1][0], default=str)
            self._save(manifest)
            if apply and self._error_rate_exceeded(ds, manifest):
                raise MigrationAborted(f"error rate exceeded max_error_rate={ds.max_error_rate} - fix the failing "
                                       "records (see errors) and --resume")
            if ds.throttle_ms:
                time.sleep(ds.throttle_ms / 1000)

    def _apply_sql(self, adapter: SQLAdapter, updates: list[tuple[Any, str, Any, Any]], backup: BackupStore,
                   manifest: dict[str, Any]) -> None:
        keyed = [(json.dumps(pk, default=str), col, _storable(old), _storable(new)) for pk, col, old, new in updates]
        backup.stage(keyed)
        applied, skipped = [], []
        try:
            for (pk, col, old, new), row in zip(updates, keyed, strict=True):
                (applied if adapter.update_cas(pk, col, old, new) else skipped).append((pk, col, new, row))
            by_column: dict[str, list[tuple[Any, Any]]] = defaultdict(list)
            for pk, col, new, _ in applied:
                by_column[col].append((pk, new))
            for col, items in by_column.items():  # read back BEFORE commit: truncation rolls the batch back
                stored = adapter.fetch([pk for pk, _ in items], col)
                for pk, new in items:
                    if _storable(stored.get(pk)) != _storable(new):
                        raise MigrationAborted(f"read-back verification failed for {pk}/{col}: the database stored a "
                                               "different value (column too narrow or type coercion?) - batch "
                                               "rolled back")
            adapter.commit()
        except Exception:
            adapter.rollback()
            backup.discard([(r[0], r[1]) for r in keyed])
            raise
        backup.mark([(row[0], row[1]) for *_, row in applied], "applied")
        backup.mark([(row[0], row[1]) for *_, row in skipped], "skipped")
        manifest["counters"]["migrated"] += len(applied)
        manifest["counters"]["concurrent_skips"] += len(skipped)

    def _run_files(self, adapter: FileAdapter, ds: DataSource, manifest: dict[str, Any], apply: bool,
                   backup: BackupStore | None, limit: int | None) -> None:
        checkpoint = manifest["checkpoint"]
        last = checkpoint.get("last_record")
        target = adapter.targets()[0]
        copies = backup.path.parent / "files" if backup else None
        processed = 0
        for rel in adapter.files():
            if last is not None and rel <= last:
                continue
            if limit is not None and processed >= limit:
                break
            processed += 1
            manifest["counters"]["scanned"] += 1
            old = adapter.read(rel)
            new = self._plan_value(old, adapter.context(target.name, rel), target, rel, manifest, scan=True)
            if new is not None and not apply:
                manifest["counters"]["would_migrate"] += 1
            elif new is not None:
                copy = copies / rel
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes(old)
                backup.stage([(rel, FILE_FIELD, None, sha256_bytes(new))])
                if adapter.write_atomic(rel, new, expected=old):
                    if adapter.read(rel) != new:
                        adapter.write_atomic(rel, old)
                        backup.discard([(rel, FILE_FIELD)])
                        raise MigrationAborted(f"read-back verification failed for {rel} - original restored")
                    backup.mark([(rel, FILE_FIELD)], "applied")
                    manifest["counters"]["migrated"] += 1
                else:
                    backup.mark([(rel, FILE_FIELD)], "skipped")
                    manifest["counters"]["concurrent_skips"] += 1
            checkpoint["last_record"] = rel
            if processed % max(1, ds.batch_size) == 0:
                self._save(manifest)
                if ds.throttle_ms:
                    time.sleep(ds.throttle_ms / 1000)
            if apply and self._error_rate_exceeded(ds, manifest):
                raise MigrationAborted(f"error rate exceeded max_error_rate={ds.max_error_rate}")

    # ------------------------------------------------------------------ rollback
    def rollback(self, run_id: str, change_ticket: str | None = None) -> dict[str, Any]:
        path = self.manifest_path(run_id)
        if not path.exists():
            raise MigrationAborted(f"no run manifest {path}")
        manifest = read_json(path)
        if manifest.get("mode") != "apply":
            raise MigrationAborted("dry runs change nothing - there is nothing to roll back")
        if manifest.get("status") == "rolled-back":
            raise MigrationAborted(f"run {run_id} was already rolled back")
        ds = self.cfg.source(manifest["source"])
        backup = BackupStore(Path(manifest["backup"]))
        copies = Path(manifest["backup"]).parent / "files"
        restored, conflicts = 0, []
        try:
            with open_adapter(ds) as adapter:
                for record, field, old, new, _status in backup.rows(("applied", "pending")):
                    if isinstance(adapter, SQLAdapter):
                        ok = adapter.update_cas(json.loads(record), field, new, old)
                    else:
                        current = adapter.read(record)
                        ok = sha256_bytes(current) == new and adapter.write_atomic(
                            record, (copies / record).read_bytes(), expected=current)
                    if ok:
                        restored += 1
                        backup.mark([(record, field)], "rolled-back")
                    else:
                        conflicts.append({"record": record, "field": field,
                                          "reason": "value changed since the run - left untouched"})
                adapter.commit()
        finally:
            backup.close()
        manifest["status"] = "rolled-back"
        manifest["rollback"] = {"at": isotime(), "operator": actor(), "change_ticket": change_ticket,
                                "restored": restored, "conflicts": conflicts[:MAX_ERRORS_RECORDED]}
        self._save(manifest)
        self.audit.append("reencrypt.rollback", run_id=run_id, source=ds.name, restored=restored,
                          conflicts=len(conflicts), change_ticket=change_ticket)
        return manifest

    # -------------------------------------------------------------- verification
    def verify_source(self, ds: DataSource) -> dict[str, Any]:
        """Classify every stored value: all must be v2 envelopes that authenticate under their context."""
        result: dict[str, Any] = {"source": ds.name, "system": ds.system, "total": 0, "v2": 0, "legacy": 0,
                                  "invalid": 0, "empty": 0, "errors": [], "key_ids": {}}

        def tally(value: Any, context: str, target: Target, record: Any) -> None:
            outcome = self.service.classify(value, context, target.legacy_profile)
            result["total"] += 1
            result[outcome.kind] += 1
            if outcome.kind == "v2":
                result["key_ids"][outcome.key_id] = result["key_ids"].get(outcome.key_id, 0) + 1
            elif outcome.kind in ("legacy", "invalid") and len(result["errors"]) < 100:
                result["errors"].append({"record": json.dumps(record, default=str), "field": target.name,
                                         "kind": outcome.kind, "error": outcome.error})

        try:
            with open_adapter(ds) as adapter:
                targets = adapter.targets()
                if isinstance(adapter, SQLAdapter):
                    for batch in adapter.batches(None, ds.batch_size):
                        for pk, values in batch:
                            for target in targets:
                                tally(values[target.name], adapter.context(target.name, pk), target, pk)
                else:
                    for rel in adapter.files():
                        tally(adapter.read(rel), adapter.context(targets[0].name, rel), targets[0], rel)
        except Exception as exc:  # noqa: BLE001
            result["status"], result["message"] = "error", f"{type(exc).__name__}: {exc}"
            return result
        result["status"] = "pass" if result["legacy"] == 0 and result["invalid"] == 0 else "fail"
        return result


def list_runs(cfg: Config) -> list[dict[str, Any]]:
    runs_dir = cfg.artifact("runs")
    if not runs_dir.is_dir():
        return []
    runs = []
    for path in runs_dir.glob("*.json"):
        manifest = read_json(path)
        manifest["_mtime_ns"] = path.stat().st_mtime_ns  # tie-breaker: several runs can start in the same second
        runs.append(manifest)
    return sorted(runs, key=lambda m: (m.get("started") or "", m["_mtime_ns"]))


def remove_backup(cfg: Config, run_id: str) -> None:
    """Delete a run's backup directory (after the stabilisation window; backups hold legacy ciphertext)."""
    shutil.rmtree(cfg.state("backups", run_id), ignore_errors=True)
