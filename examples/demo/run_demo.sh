#!/usr/bin/env bash
# =============================================================================
# End-to-end SDLC demo: build a fake legacy 3DES system, then take it through all
# seven phases of the workplan to a verified, attested AES-256-GCM end state.
#
#   bash examples/demo/run_demo.sh [workspace-dir]      (default: ./demo-workspace)
#
# Human decisions (approvals, code changes, the HSM team's firmware work) are
# simulated by make_legacy_system.py so the run is fully automatic.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS="$(mkdir -p "${1:-$PWD/demo-workspace}" && cd "${1:-$PWD/demo-workspace}" && pwd)"
SIM="python3 $HERE/make_legacy_system.py $WS"
step() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*"; }
note() { printf '\033[2m# %s\033[0m\n' "$*"; }

rm -rf "${WS:?}"/* "$WS"/.cryptomigrate "$WS"/.github "$WS"/.cryptomigrateignore 2>/dev/null || true
export CRYPTOMIGRATE_KEK="$(cryptomigrate keys new-kek 2>/dev/null)"   # in production: from your secrets manager
export CRYPTOMIGRATE_ACTOR="demo-operator"
export NO_COLOR=1

step "Setup - a legacy system that still uses Triple-DES"
$SIM create
cd "$WS"

step "Phase 1 - Initiation: charter + governance scaffolding"
cryptomigrate init --github
cryptomigrate gate --phase 1

step "Phase 2 - Planning & Discovery: inventory, CBOM, assessment"
cryptomigrate discover
cryptomigrate assess
$SIM signoff inventory_validation "System owners (validation meeting)"
cryptomigrate gate --phase 2

step "Phase 3 - Analysis & Design: keys, legacy key ceremony, plan"
cryptomigrate keys init
note "Key ceremony: the custodian hands over the legacy key; compare the printed KCV with their record."
LEGACY_3DES_KEY_HEX="$(cat legacy-key.hex)" \
  cryptomigrate keys import-legacy --key-id legacy-3des --algorithm 3DES --hex-env LEGACY_3DES_KEY_HEX
note "Hybrid system: the messaging team hands over its RSA private key (it wraps a per-message 3DES key)."
cryptomigrate keys import-legacy --key-id legacy-rsa --algorithm RSA --pem-file legacy-rsa.pem
cryptomigrate plan
$SIM signoff design_review "Avery Patel (CISO)"
cryptomigrate gate --phase 3

step "Phase 4 - Development: code changes (simulated PRs), self-test, CI gate"
python3 "$HERE/app_read.py"
$SIM modernize
cryptomigrate discover
cryptomigrate assess
cryptomigrate selftest
cryptomigrate doctor
$SIM signoff code_review "Security code review (PR #42)"
cryptomigrate gate --phase 4

step "Phase 5 - Testing & Validation: validation suite + full dry runs"
cryptomigrate validate
cryptomigrate reencrypt
$SIM signoff uat "Application owners (UAT)"
cryptomigrate gate --phase 5

step "Phase 6 - Deployment: risk-based waves (low criticality first)"
note "Wave 1 - Records Archive (low)"
cryptomigrate reencrypt --wave 1 --apply --change-ticket CHG-2001 --approver "Dana Ortiz"
note "Wave 2 - Edge & Access + Secure Messaging (medium): TLS/SSH remediation, hybrid RSA+3DES data"
cryptomigrate remediate
cryptomigrate remediate --apply --change-ticket CHG-2002 --approver "Sam Okafor"
cryptomigrate reencrypt --wave 2 --apply --change-ticket CHG-2002 --approver "Lena Novak"
note "Wave 3 - Customer Portal (high): canary, rollback drill, full run"
CANARY="$(cryptomigrate reencrypt --source customers-ssn --apply --limit 5 --change-ticket CHG-2003 \
          | grep -o 'run=[^ ]*' | cut -d= -f2)"
cryptomigrate rollback --run "$CANARY" --change-ticket CHG-2003
cryptomigrate reencrypt --wave 3 --apply --change-ticket CHG-2003 --approver "Priya Shah"
python3 "$HERE/app_read.py"
note "Wave 4 - Payments (critical): HSM team completes AES firmware cut-over, then data"
$SIM asset "Payment HSM cluster" remediated
cryptomigrate reencrypt --wave 4 --apply --change-ticket CHG-2004 --approver "Marcus Lee"
cryptomigrate discover
cryptomigrate assess
$SIM signoff change_approval "Change Advisory Board"
cryptomigrate gate --phase 6

step "Phase 7 - Closeout: verify, crypto-shred legacy key, strict mode, attest"
cryptomigrate verify
note "Dual control: two approvers must be recorded before any legacy key is destroyed."
$SIM approve key_destruction "Avery Patel (CISO)"
$SIM approve key_destruction "Kim Lee (Key custodian)"
for key in legacy-3des legacy-rsa; do
  cryptomigrate keys destroy --key-id "$key" --confirm "$key" --reason "Phase 7: verification shows zero legacy records"
done
rm -f legacy-key.hex legacy-rsa.pem
$SIM set migration.mode strict
python3 "$HERE/app_read.py"
cryptomigrate verify
cryptomigrate attest
$SIM signoff closeout "Jordan Rivera (CIO)"
cryptomigrate gate --phase 7

step "Result"
cryptomigrate status
cryptomigrate audit verify
note "Evidence: $WS/artifacts  (inventory, CBOM, SARIF, assessment, plan, validation, runs, verification, attestation)"
