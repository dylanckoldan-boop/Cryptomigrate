# Requirements traceability matrix

Traces every requirement, risk, WBS item and Key Management Plan stage in the workplan to the code that implements it, the tests that verify it, and the artifact an auditor can inspect. Test names refer to files in `tests/`.

## Functional requirements (BRD 3.4)

| ID | Requirement | Implementation | Verification | Evidence |
|---|---|---|---|---|
| FR-01 | AES for all newly encrypted data (≥ AES-128, target AES-256) | `crypto/envelope.py` (AES-128/256-GCM only); `config.py` rejects non-GCM targets | `test_crypto.py::TestEnvelope`, KATs `KAT-GCM-128/256-*`, `test_config_validation` | `validation/validation-report.json` |
| FR-02 | Migrate DES/3DES data to AES without loss | `migration/engine.py`: backup before write, in-memory + in-transaction read-back verification | `test_apply_is_correct_idempotent_and_readable_by_the_app`, `test_truncating_database_rolls_back_the_batch`, `test_column_too_narrow_is_caught_before_writing` | `runs/*.json`, `verification/verification.json` |
| FR-03 | Dual-algorithm transition mode | `crypto/service.py` (`mode: dual` / `strict`) | `TestService::test_dual_mode_classification`, `test_strict_mode_rejects_legacy`, `test_magic_collision_falls_back_to_legacy` | `VAL-STRICT` in validation report |
| FR-04 | Key generation, distribution, rotation, destruction | `keys/keystore.py` | `TestKeystore::*` | `attestation/keys.json`, `audit.log`, `plan/key-management-plan.md` |
| FR-05 | Log all cryptographic configuration changes | `audit.py` (hash chain); remediation & run manifests | `TestAudit::test_chain_detects_edit_delete_and_reorder`, `test_remediation_fixes_and_rolls_back` | `.cryptomigrate/audit.log`, `runs/remediate-*.json` |
| FR-06 | Rollback to a known-good state | `MigrationEngine.rollback`, `remediation.rollback_remediation` | `test_rollback_restores_exact_ciphertext`, `test_files_apply_verify_and_rollback`, `test_remediation_fixes_and_rolls_back` | `rollback` section of run manifests |
| FR-07 | *Organization-specific* | add a policy rule, adapter or check ([EXTENDING.md](EXTENDING.md)) | add a test | — |

## Non-functional requirements (BRD 3.5)

| ID | Requirement | Implementation | Verification | Evidence |
|---|---|---|---|---|
| NFR-01 | Latency increase ≤ X % of baseline; use AES-NI | `validation.py` `VAL-PERF` against `nfr.max_latency_increase_pct`; AES-NI detection | `test_validation_suite_passes` | `validation-report.json` (`measurements_us`) |
| NFR-02 | No unplanned downtime | online migration: compare-and-swap writes, small batches, `throttle_ms`, canary `--limit`, waves | `test_concurrent_application_write_is_never_clobbered`, `test_canary_limit` | run manifests (`concurrent_skips`) |
| NFR-03 | SP 800-38 modes; no ECB | GCM only for new data; ECB/CBC findings flagged; header + context bound as AAD | `test_context_and_header_are_authenticated`, `VAL-TAMPER`, `VAL-AAD` | validation report |
| NFR-04 | Traceable to change ticket, approver, rollback plan | `--change-ticket`, `--approver`, `governance.require_change_ticket`; backups per run | `test_preflight_requires_legacy_key_and_change_ticket` | run manifests, audit log |
| NFR-05 | Onboard new systems without re-architecture | policy packs, DB-API adapter (any driver), file adapter, systems/waves config | `test_invalid_policy_pattern_reports_rule`; demo onboards 4 systems by config only | `migration.yaml` |

## Risk register (workplan Section 7)

| ID | Risk | Mitigation in the toolkit | Verification |
|---|---|---|---|
| R-01 | Undiscovered DES/3DES after migration | four discovery channels; weekly scheduled CI re-scan; final scan in `verify`; `P2-OWNERSHIP` gate | 34 detection cases in `test_scanner.py`; `test_tlsprobe.py` |
| R-02 | Legacy hardware lacks AES | `manual_assets` (hsm/embedded) with `aes_support`; effort "L" in assessment | `test_assessment_and_plan` |
| R-03 | Performance regression | `VAL-PERF` gate input; AES-NI detection | `test_validation_suite_passes` |
| R-04 | Data loss during re-encryption | dry run, backups, CAS, read-back, resume, key-destroy interlock | `test_truncating_*`, `test_resume_after_failure`, `test_key_destroy_interlock_via_cli` |
| R-05 | Vendor cannot remediate on time | manual asset `type: third-party`; time-boxed exceptions; exception-request issue form | `test_exceptions_apply_until_expiry` |
| R-06 | Key-management gaps | CSPRNG keys; AES-KWP wrapping; KEK never on disk; PBKDF2 600k; weak-key detection; SP 800-38D usage counter | `TestKeystore`, `test_key_notes_flag_weak_material` |
| R-07 | Compliance deadline missed | `target_completion`, gates, `status` dashboard, waves | `test_gate_phase1_requires_charter_and_signoff` |

## Work breakdown structure (workplan Section 5)

| WBS | Task | Command / artifact |
|---|---|---|
| 1.1 | Charter approval & kickoff | `init`, `gate --phase 1` |
| 2.1 | Cryptographic asset inventory | `discover` → inventory, CBOM, SARIF |
| 2.2 | Compatibility & gap assessment | `assess` |
| 2.3 | Detailed schedule & risk register | `plan` → `work-items.json`, `create_github_issues.sh`; risk issue form |
| 3.1 | Target architecture & key management plan | `keys init`, `plan` → `key-management-plan.md` |
| 3.2 | Per-system migration runbooks | `plan` → `runbooks/*.md` |
| 4.1 | Application/library updates | runbook code items; `CryptoService`; CI gate |
| 4.2 | HSM/KMS AES configuration | keystore / `KeyProvider` extension |
| 5.1 | Functional & interoperability testing | `validate` (round trip, AAD, profile checks); envelope vectors |
| 5.2 | Performance & security testing | `validate` (`VAL-PERF`, `VAL-TAMPER`, `VAL-NO-FALLBACK`), `selftest` |
| 5.3 | UAT sign-off | `governance.signoffs.uat`, `gate --phase 5` |
| 6.1 | Wave 1 production rollout | `reencrypt --wave 1 --apply` |
| 6.2 | Waves 2–N | `reencrypt --wave N --apply`, `remediate --apply` |
| 6.3 | At-rest data re-encryption | `reencrypt` engine |
| 7.1 | Final scan & legacy key destruction | `verify`, `keys destroy` |
| 7.2 | Compliance evidence package | `attest` |
| 7.3 | Retrospective & template archive | this repository as template; new policy packs |

## Key Management Plan (workplan Section 8)

| Lifecycle stage | Implementation |
|---|---|
| Generation | `keys init` / `keys rotate`: OS CSPRNG, AES-256 (or 128), KCV recorded |
| Distribution | keys never leave the keystore in plaintext; services load them through `CryptoService`; KEK delivered via secrets manager |
| Storage | AES-KWP (RFC 5649 / SP 800-38F) under a KEK that never touches disk; keystore mode 0600; never committed |
| Rotation | new key active, old key decrypt-only; usage counter against the SP 800-38D 2^32 random-IV limit |
| Legacy key handling | `keys import-legacy`: decrypt-only, KCV for the ceremony, strength notes (2-key, degenerate, weak keys) |
| Destruction | `keys destroy`: refuses while data depends on the key; crypto-shredding; audit entry |
| Audit & monitoring | hash-chained audit log; `audit verify`; head hash anchored in the attestation |

## Extensions beyond the original workplan (v1.1)

| ID | Requirement | Implementation | Verification | Evidence |
|---|---|---|---|---|
| HYB-01 | Migrate hybrid records (RSA-wrapped DES/3DES content keys) | `crypto/legacy.py` (`key_transport`), `keys import-legacy --algorithm RSA` | `test_hybrid.py::test_hybrid_profile_decrypts_each_key_transport`, `test_hybrid_end_to_end_migration` | run manifests, verification |
| HYB-02 | RSA may protect the AES data keys | `keys/keystore.py` (`rsa-aes-kwp`, pairwise consistency test) | `test_rsa_kek_protects_aes_keys` | keystore metadata, audit log |
| SEC-01 | Certificate hygiene (files and endpoints) | `discovery/certs.py`, `pki-tls` CERT-* | `test_certificate_checks` | inventory, CBOM certificate assets |
| SEC-02 | TLS 1.2/1.3 only; verification never disabled | `pki-tls` TLS-PROTO/VERIFY rules, `remediate` fixer | `test_tls_protocol_remediation_is_safe_and_complete`, `test_layer_rules_detect_exactly_the_expected_weaknesses` | remediation manifests |
| SEC-03 | Live SSL/TLS handshake assessment | `discovery/tlsassess.py`, TLS-PROBE-* | `test_tls_assessment_*`, `test_discovery_turns_assessments_into_findings_and_cbom` | inventory `tls_assessments`, CBOM protocol assets |
| SEC-04 | Strong user authentication; authenticated approvals | `auth-wireless` AUTH-*; `require_signed_commits`; `dual_control` | `test_signoffs_require_signed_commits`, `test_dual_control_for_key_destruction` | gate results, audit log |
| SEC-05 | Wireless security (WPA3, PMF, validated 802.1X) | `auth-wireless` WIFI-* | `test_layer_rules_detect_exactly_the_expected_weaknesses` | inventory |
| SEC-06 | SQL injection prevention | `secure-coding` SQLI-*; parameterized adapter | layer detection test; `test_config_validation` (identifier injection) | inventory, SARIF |
| SEC-07 | Buffer-overflow prevention and binary hardening | `secure-coding` MEM-*; `discovery/binaries.py` | `test_binary_hardening_flags_are_verified`, `test_hardened_system_binary` | inventory `binaries` |
| SEC-08 | Malware: scan exposed plaintext; hardened, verifiable toolchain | `malware.py`, `doctor.py`, CI (pip-audit, CodeQL, dependency review, provenance) | `test_clamd_client`, `test_engine_quarantines_malware_found_while_decrypting`, `test_doctor_reports_private_state` | audit `malware.detected`, release attestations |
| SEC-09 | Layer findings gate the SDLC | `gates.py` P4-LAYERS / P6-LAYERS, `verification.py` VER-LAYERS | `test_layer_gates_block_only_at_threshold` | `gates/phase-*.json` |
