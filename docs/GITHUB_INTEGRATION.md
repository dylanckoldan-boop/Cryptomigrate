# GitHub integration

## Workflows in this repository

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push, pull request | ruff (incl. bandit security rules), known-answer self-test, tests on Python 3.10-3.13, `pip-audit` dependency audit, end-to-end demo with evidence upload |
| `crypto-gate.yml` | push, pull request, weekly | this repository's own gate with all security layers: fails on new high/critical findings, uploads SARIF |
| `migration-pipeline.yml` | manual (`workflow_dispatch`) | runs SDLC stages against real systems from a self-hosted runner, with environment approvals |
| `codeql.yml` | push, pull request, weekly | CodeQL `security-extended` data-flow analysis of the toolkit itself |
| `dependency-review.yml` | pull request | blocks new dependencies with known high-severity vulnerabilities |
| `release.yml` | tag `v*` | builds, tests the wheel, generates a CycloneDX SBOM, signs SLSA build provenance, publishes the release |

## Adopting it in another repository

```bash
cryptomigrate init --github
```

This installs `.github/workflows/crypto-gate.yml`, the phase-gate / risk / exception issue forms, a PR template with a cryptography checklist, and a CODEOWNERS skeleton. Then:

1. **Branch protection:** require the *Crypto gate* check and CODEOWNERS review on `main`.
2. **Code scanning:** the gate uploads SARIF (`security-events: write`). Private repositories need GitHub Code Security; without it, the upload step is skipped (`continue-on-error`) and the gate still enforces through its exit code.
3. **CODEOWNERS:** route `migration.yaml`, `.cryptomigrateignore` and `.github/workflows/` to your security team. Sign-offs and exceptions then cannot merge without security review.

## Environments as change approval

Create two environments under *Settings → Environments*:

| Environment | Protection | Secrets |
|---|---|---|
| `migration-test` | optional reviewers | `CRYPTOMIGRATE_KEK` for non-production keystores |
| `production` | **required reviewers = your change-advisory board**; deployment branches limited to `main` | production `CRYPTOMIGRATE_KEK` |

The pipeline's `reencrypt-wave` job targets `production`, so every wave pauses until a reviewer approves. GitHub records who approved and when, which is the Phase 6 change approval. The job also checks the Phase 5 gate as its entry criterion and refuses to run without a change ticket.

## Self-hosted runner

Migration stages need network access to databases and endpoints, so they run on a self-hosted runner labelled `cryptomigrate` inside your network.

**Keep state outside the workspace.** `actions/checkout` cleans the workspace on every run, which would delete the keystore, backups and audit log. In the `migration.yaml` used by the pipeline, set absolute persistent paths:

```yaml
keystore:  {path: /var/lib/cryptomigrate/<project>/keystore.json}
state_dir: /var/lib/cryptomigrate/<project>/state
artifacts_dir: /var/lib/cryptomigrate/<project>/artifacts
```

Restrict the directory to the runner's service account, back it up, and register the runner to this repository only.

## Issues as the project plan

`cryptomigrate plan` writes `artifacts/plan/create_github_issues.sh`, which creates the WBS as issues labelled `phase:N` and `wave:N` (requires the GitHub CLI). Use a GitHub Project board grouped by phase or wave as the schedule view. The phase-gate issue form records each manual approval, which is then entered into `governance.signoffs` by pull request.

## Evidence retention

Each pipeline run uploads its artifacts. For the final evidence package, attach the attestation zip to a GitHub Release and sign it (for example with Sigstore `cosign sign-blob` or GPG) for an external timestamp. Its SHA-256 digest is already anchored in the audit log.

## Hardening notes

* Workflow inputs are passed to scripts via environment variables, never interpolated into `run:` blocks (script-injection guidance).
* Workflows request least-privilege `permissions`.
* Dependabot keeps actions and Python dependencies current. Pin actions to commit SHAs if your policy requires it.
* Make this repository a template (*Settings → Template repository*) so each migration project starts from it.
