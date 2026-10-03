# SDLC mapping: workplan → toolkit

This document maps each phase of the project workplan (`docs/workplan/AES_Migration_Project_Workplan.docx`, Section 4) to what the toolkit automates, the artifact it produces, the exit criteria `cryptomigrate gate` evaluates, and the GitHub feature that carries the governance. Each phase's exit criteria are the next phase's entry criteria.

Manual criteria are approvals. They are recorded as `governance.signoffs.<gate>: {by, date, ref}` in `migration.yaml`, merged through a pull request that CODEOWNERS must approve and that links the *Phase gate review* issue. The approval is therefore itself versioned, reviewed and auditable.

---

## Phase 1 - Initiation (workplan 4.1)

**Objective:** charter the project, secure sponsorship, establish governance.

| Workplan activity | Toolkit support |
|---|---|
| Draft and approve the charter | `cryptomigrate init` writes `migration.yaml`, whose `project:` block *is* the charter (sponsor, PM, security lead, target date, compliance frameworks) |
| Identify sponsor, PM, team | Charter fields; `[placeholders]` fail the gate until replaced |
| Define scope and target date | `scan.paths`, `systems`, `project.target_completion` |
| Establish governance cadence | `init --github`: CI crypto gate, phase-gate / risk / exception issue forms, PR template, CODEOWNERS |

**Exit criteria:** `P1-CHARTER`, `P1-DATE`, `P1-FRAMEWORKS`, `P1-SIGNOFF` (charter).
**GitHub:** issue form *Phase gate review*; CODEOWNERS on `migration.yaml`.

## Phase 2 - Planning & Discovery (workplan 4.2)

**Objective:** find every use of DES/3DES and assess compatibility.

| Workplan activity | Toolkit support |
|---|---|
| Full cryptographic inventory (apps, DBs, HSMs, embedded, VPNs, third parties) | `discover`: 31-rule scanner across 12+ languages and 15+ config formats, wire-level TLS probe, data-at-rest profiler, `manual_assets` for what no scanner can see |
| Classify by sensitivity, criticality, regulation | `systems[].criticality`, `data_classification`; findings mapped to systems by path |
| Assess AES compatibility (software, firmware, hardware) | `assess`: change type, automation level, effort and compatibility check per finding; projected ciphertext size vs. column width |
| Confirm HSM/KMS AES support | manual assets with `aes_support`; assessment change type "HSM firmware/licence or hardware refresh" |
| Baseline risk register | risk score (severity × criticality); *Risk register item* issue form |

**Deliverables → artifacts:** inventory report → `inventory.json`, `inventory.md`, `cbom.cdx.json` (CycloneDX 1.6 CBOM), `cryptomigrate.sarif`; gap assessment → `assessment.json`, `assessment.md`.
**Exit criteria:** `P2-INVENTORY`, `P2-CBOM`, `P2-ASSESS`, `P2-FRESH`, `P2-OWNERSHIP`, `P2-OWNERS`, `P2-PROBES`, `P2-DATA`, `P2-SIGNOFF` (inventory validated by owners).
**GitHub:** SARIF in code scanning; weekly scheduled re-scan catches new code paths (R-01).

## Phase 3 - Analysis & Design (workplan 4.3)

**Objective:** target architecture and migration approach per system.

| Workplan activity | Toolkit support |
|---|---|
| Key lengths and modes (SP 800-38 series) | `target.algorithm`: AES-256-GCM or AES-128-GCM only; unauthenticated modes are rejected at config load |
| Key Management Plan | `keys init`, `keys import-legacy` (KCV for the key ceremony), `plan` → `key-management-plan.md` |
| Dual-support transition design | `migration.mode: dual` and `CryptoService`; v2 envelope ([ENVELOPE_SPEC.md](ENVELOPE_SPEC.md)) |
| Data re-encryption approach | batch re-encryption engine: keyset pagination, CAS writes, throttling, waves |
| Per-system runbooks with rollback | `plan` → `plan/runbooks/<system>.md`, `wave-plan.md`, `work-items.json`, `create_github_issues.sh` |
| Design review / threat model | `P3-SIGNOFF`; security notes in [OPERATIONS.md](OPERATIONS.md) |

**Exit criteria:** `P3-TARGET`, `P3-KEYSTORE`, `P3-LEGACY-KEYS`, `P3-PLAN`, `P3-ROLLBACK`, `P3-SCHEMA`, `P3-SIGNOFF` (design review).
**GitHub:** WBS pushed as issues with `phase:N` and `wave:N` labels.

## Phase 4 - Development / Implementation (workplan 4.4)

**Objective:** implement AES support in code, configuration and infrastructure (non-production first).

| Workplan activity | Toolkit support |
|---|---|
| Update code to vetted AES libraries | runbook guidance per finding; `CryptoService` for Python; envelope spec + vectors for other languages |
| Firmware/hardware for devices without AES | tracked as manual assets until `status: remediated` |
| Configure HSM/KMS for AES keys | keystore now; `KeyProvider` extension point for HSM/KMS ([KEY_MANAGEMENT.md](KEY_MANAGEMENT.md)) |
| Update CI/CD to enforce AES | CI crypto gate fails pull requests that introduce DES/3DES |
| Peer and security review | PR template checklist; CODEOWNERS; `P4-SIGNOFF` |
| Configuration hardening | `remediate` (TLS/SSH cipher lists): diff, backup, re-scan proof, rollback |

**Exit criteria:** `P4-SELFTEST`, `P4-CODE`, `P4-CI`, `P4-SIGNOFF` (security code review).

## Phase 5 - Testing & Validation (workplan 4.5)

**Objective:** prove correctness, security and performance before production.

| Workplan activity | Toolkit check (`cryptomigrate validate`) |
|---|---|
| Encryption/decryption correctness | `KAT-*` (NIST GCM, RFC 3394/5649, SP 800-67, DES vectors), `VAL-ROUNDTRIP` |
| Interoperability | envelope interoperability vector; `VAL-PROFILE:*` decrypts real sampled legacy data |
| Transition-state (dual mode) | `VAL-STRICT`, dry-run re-encryption classifies legacy vs. v2 |
| Performance against NFR-01 | `VAL-PERF` (best-of-3 timing, 256 B and 64 KiB, AES-NI detection) |
| Security: no fallback, no hard-coded keys | `VAL-NO-FALLBACK`, `VAL-TAMPER`, `VAL-AAD`, `VAL-NONCE`; scanner redacts key material |
| Backup & recovery | dry run per data source; rollback tested in the test suite |
| UAT | `P5-SIGNOFF` |

**Exit criteria:** `P5-VALIDATION`, `P5-VALIDATION-PASS`, `P5-DRYRUN:<source>` (full dry run, zero errors), `P5-SIGNOFF` (UAT).

## Phase 6 - Deployment / Phased Rollout (workplan 4.6)

**Objective:** risk-based rollout, lowest criticality first.

| Workplan activity | Toolkit support |
|---|---|
| Sequence waves by criticality | waves derived from `criticality` (low → critical) unless set explicitly |
| Change management per wave | `--change-ticket`, `--approver` recorded in run manifests and the audit log |
| Monitor each wave | canary (`--limit N`), manifests with counters, `app` read checks in the runbook |
| Re-encrypt data at rest | `reencrypt --wave N --apply` (backup → CAS → read-back → commit) |
| Rollback readiness | `rollback --run <id>` restores exact original ciphertext while the legacy key exists |
| Communicate changes | GitHub issues per wave; runbooks |

**Exit criteria:** `P6-APPLY:<source>` (completed full run, not rolled back), `P6-CONFIG`, `P6-SIGNOFF` (change approval).
**GitHub:** the `production` environment's required reviewers approve each `reencrypt-wave` pipeline run.

## Phase 7 - Post-Implementation & Closeout (workplan 4.7)

**Objective:** confirm retirement, destroy legacy keys, produce evidence, hand over.

| Workplan activity | Toolkit support |
|---|---|
| Final scan: no DES/3DES remains | `verify`: fresh scan, TLS re-probe, **every stored value** authenticated as AES-GCM |
| Destroy legacy keys | `keys destroy` (refuses while data depends on the key) |
| Update policy and standards | `migration.mode: strict`; policy pack remains as the CI standard |
| Compliance evidence package | `attest` → `ATTESTATION.md`, `evidence-manifest.json` (SHA-256), zip |
| Lessons learned, archive template | retrospective issue; the repo itself is the reusable template |

**Exit criteria:** `P7-VERIFY`, `P7-VERIFY-PASS`, `P7-KEYS`, `P7-AUDIT`, `P7-STRICT` (warning if dual), `P7-ATTEST`, `P7-SIGNOFF` (sponsor acceptance).

---

## RACI → GitHub

| Workplan role | GitHub mechanism |
|---|---|
| Executive Sponsor (A for charter, deployment approval) | sign-off entries; `production` environment reviewer for wave runs |
| CISO / Security (A for design, inventory, key destruction) | CODEOWNERS on `migration.yaml`, `.cryptomigrateignore`, workflows, `src/**/crypto/` |
| Project Manager (R for charter, testing, rollout) | issue triage, `cryptomigrate status`, WBS issues |
| Application Owners (R for inventory, A for UAT) | system `owner` field; per-system runbooks; UAT sign-off |
| Infrastructure / DBA (R for keys, re-encryption) | migration pipeline operators; self-hosted runner |
| Compliance / Audit (A/R for evidence) | attestation package; audit-log verification |
