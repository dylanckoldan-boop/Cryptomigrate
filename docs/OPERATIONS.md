# Operations guide

How to run the transition against real systems safely.

## Order of operations per system

The application must be able to read the new format **before** any stored value changes:

1. **Deploy dual-mode readers.** Every code path that reads the data accepts both legacy ciphertext and v2 envelopes (`CryptoService.decrypt`, or the envelope spec in another language).
2. **Switch writers to AES-GCM.** New and updated values are written as v2 envelopes. From now on, legacy ciphertext only shrinks.
3. **Re-encrypt at rest.** `reencrypt` in waves: dry run → canary (`--limit`) → full run.
4. **Verify.** `verify` authenticates every stored value.
5. **Close the window.** After the stabilisation period: delete run backups, `keys destroy` the legacy key, set `migration.mode: strict`.

Keep the dual-mode window short. Legacy CBC ciphertext is unauthenticated, so an online endpoint that decrypts attacker-supplied legacy values can act as a padding oracle. cryptomigrate returns one generic error for every legacy failure, but timing is not constant-time.

## Production readiness checklist

- [ ] `cryptomigrate validate` passes, including `VAL-PROFILE:*` against **production-like** data (wrong IV handling or padding shows up here, not in Phase 6).
- [ ] A full dry run per data source reports `errors=0` (gate `P5-DRYRUN`).
- [ ] Columns are wide enough: the assessment's `column-too-narrow` gap and `VAL-WIDTH:*` are clear. An SSN grows from about 32 to about 105 characters as armored AES-GCM.
- [ ] A platform-level backup or snapshot exists in addition to cryptomigrate's column-level backup.
- [ ] `governance.require_change_ticket: true`, and the change ticket and window are approved.
- [ ] The state directory (keystore, backups, audit log) is on persistent, access-controlled storage, not a CI workspace that gets cleaned.

## Database notes

| Topic | Guidance |
|---|---|
| Drivers | Any DB-API 2.0 module: `sqlite3`, `psycopg2`/`psycopg`, `pymysql`, `mysql.connector`, `oracledb`, `pyodbc`. Placeholders follow the driver's `paramstyle` automatically. |
| Pagination | Keyset pagination on a single-column, orderable primary key (index it). `limit_style`: `limit` (PostgreSQL, MySQL, SQLite), `fetch` (Oracle 12c+, Db2, PostgreSQL), `top` (SQL Server). |
| Credentials | Use `${ENV_VAR}` references in `connect`; they are resolved only when the source is opened. |
| Load | Tune `batch_size` and `throttle_ms`; each batch is one short transaction. Run dry runs against a replica if the primary is sensitive to read load. |
| Concurrency | Compare-and-swap updates skip rows the application changed mid-flight (`concurrent_skips`); re-run to pick them up. |
| Truncation | Values are re-read inside the transaction before commit; MySQL non-strict truncation or type coercion rolls the batch back. |
| LOBs | The CAS update compares the column with `=`. Oracle CLOB/BLOB columns cannot be compared that way; write a small adapter that compares `DBMS_LOB.COMPARE` or a hash column. |
| Encodings | `storage: text` for VARCHAR/TEXT (legacy base64/hex → armored v2); `storage: blob` for BLOB/BYTEA/VARBINARY (raw → binary v2). |

## Rollback window

`cryptomigrate rollback --run <run-id>` restores the exact original ciphertext from the per-run backup, using compare-and-swap so values changed since the run are left alone and reported as conflicts. Rollback works only while the legacy key exists and the backup is retained. Destroying the legacy key at close-out deliberately ends the rollback window: that is the point of crypto-shredding.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `VAL-PROFILE` fails, dry run shows `legacy decryption failed` | wrong legacy profile (IV fixed vs. prefix, padding, encoding) or wrong legacy key | inspect a known record with the legacy team; compare the KCV; adjust `legacy_profiles` |
| `pre-flight failed: legacy key ... missing` | legacy key not imported or already destroyed | `keys import-legacy`; if destroyed, the data is unrecoverable by design |
| Run status `aborted`, error rate exceeded | some records cannot be decrypted | review `errors` in the run manifest, fix or except them, then `--resume <run-id>` |
| Run status `failed` (connection lost) | infrastructure | `reencrypt --source X --apply --resume <run-id>` continues from the checkpoint |
| `read-back verification failed` | column too narrow or coerced | widen the column; the batch was rolled back, so nothing is half-written |
| `the supplied KEK does not match this keystore` | wrong secret injected | fix the secret; never re-create the keystore over an existing one |
| Gate fails on stale artifacts | evidence older than `max_artifact_age_days` | re-run `discover` / `assess` / `validate` |

## Containers

```bash
docker build -t cryptomigrate .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -e CRYPTOMIGRATE_KEK cryptomigrate discover
```
