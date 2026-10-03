# How cryptomigrate works

## 1. Installing it

cryptomigrate is a Python package: Python 3.10 or newer, with two dependencies (`cryptography`, `PyYAML`).

```bash
pip install "cryptomigrate @ git+https://github.com/dylanckoldan-boop/cryptomigrate@v1.1.1"   # from GitHub
pip install -e ".[dev]"                                                           # from a clone, with test tools
cryptomigrate --version && cryptomigrate selftest && cryptomigrate doctor         # confirm it works
```

Containers: `docker build -t cryptomigrate .`, then
`docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -e CRYPTOMIGRATE_KEK cryptomigrate status`.

## 2. How it opens

There is no window. cryptomigrate is a command-line tool: open a terminal in the folder of the system you are migrating and run `cryptomigrate <command>`. `cryptomigrate --help` lists every command and `cryptomigrate status` shows where the project stands across the seven phases. The same program also runs as a Python library (`from cryptomigrate import CryptoService`) and inside GitHub Actions.

| Location | What lives there | Commit it? |
|---|---|---|
| `migration.yaml` | project charter, systems, data sources, layers, sign-offs | yes - change it by reviewed pull request |
| `artifacts/` | evidence: inventory, CBOM, SARIF, assessment, plans, runs, verification, attestation | yes, or upload as CI artifacts |
| `.cryptomigrate/keystore.json` | wrapped keys (mode 0600) | **never** - destruction relies on it |
| `.cryptomigrate/audit.log` | hash-chained audit trail | back it up; never edit |
| `.cryptomigrate/backups/` | original ciphertext per run (rollback) | never; delete after the stabilisation window |

## 3. The process

One command per phase of the workplan; `cryptomigrate gate --phase N` checks that phase's exit criteria against evidence.

| Phase | Commands | What happens |
|---|---|---|
| 1 Initiation | `init --github` | charter file, CI gate, issue forms, PR template, CODEOWNERS |
| 2 Discovery | `discover`, `assess` | 79 rules across code and configuration, certificate files, live TLS probes and handshake assessment, binaries, stored data and manual assets; ranked by risk and owner |
| 3 Design | `keys init`, `keys import-legacy`, `plan` | new AES key, legacy keys imported decrypt-only, wave plan, per-system runbooks, GitHub issues |
| 4 Build | `remediate`, `selftest`, `doctor` | TLS/SSH configuration fixed automatically; developers fix code from the runbooks |
| 5 Test | `validate`, `reencrypt` (dry run) | known-answer tests, tamper/AAD/no-fallback checks, performance budget, legacy profile proven on real data |
| 6 Deploy | `reencrypt --apply` (waves, `--limit` canary), `rollback` | stored data migrated, lowest-risk systems first |
| 7 Closeout | `verify`, `keys destroy`, `attest` | every record checked, legacy keys crypto-shredded (two approvers), evidence package |

What happens to each stored value in step 6:

```
read value ──> classify: already AES-GCM? ──yes──> skip (idempotent)
                   │ no (legacy)
                   v
   [hybrid] RSA-decrypt the per-record content key
                   v
   DES/3DES-decrypt with the legacy profile
                   v
   [optional] stream plaintext to ClamAV ──infected──> leave encrypted, report, audit
                   v
   AES-256-GCM encrypt, bound to "table.column#pk" ──> decrypt again in memory and compare
                   v
   back up original ciphertext ──> UPDATE ... WHERE value = <what we read> (skips concurrent app writes)
                   v
   re-read inside the transaction ──mismatch──> roll back the whole batch
                   v
   COMMIT ──> checkpoint (resumable with --resume)
```

## 4. Hybrid systems: RSA protecting symmetric keys

A hybrid system encrypts data with a fast symmetric key and protects that key with RSA. cryptomigrate supports this in three places.

**4.1 Legacy hybrid data (RSA-wrapped 3DES keys).** Each stored value is `RSA(content key) || IV || 3DES ciphertext`. Describe the layout once in a legacy profile:

```yaml
legacy_profiles:
  hybrid-rsa-3des:
    algorithm: 3DES
    mode: CBC
    iv: prefix
    padding: pkcs7
    encoding: raw
    key_transport: rsa-pkcs1v15     # or rsa-oaep-sha1 / rsa-oaep-sha256
    rsa_key_bits: 2048
    key_id: legacy-rsa
```

Import the legacy RSA private key decrypt-only: `cryptomigrate keys import-legacy --key-id legacy-rsa --algorithm RSA --pem-file key.pem`. The engine unwraps each record's content key, decrypts it, and re-encrypts it as AES-256-GCM. The demo migrates 40 such messages. After verification, the RSA key is destroyed with the 3DES key.

**4.2 RSA protecting the new AES keys.** Set `keystore.wrap: rsa-aes-kwp`. Each AES key is then wrapped by a one-time AES key, and that key is wrapped with RSA-OAEP-SHA256: the PKCS#11 `CKM_RSA_AES_KEY_WRAP` construction. Creating and rotating keys needs only the public key, so a key custodian can rotate without being able to decrypt. Unwrapping needs the private key, which belongs in an HSM or a protected file (`CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE`). A pairwise-consistency test runs whenever the key pair loads. See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md).

**4.3 Hybrid code and protocols.** Discovery flags the following:

| What | Rule |
|---|---|
| CMS / S/MIME content encryption with 3DES (BouncyCastle `CMSAlgorithm.DES_EDE3_CBC`, .NET `EnvelopedCms` defaults) | `CM-CMS-001` |
| DES/3DES algorithm identifiers (OIDs) in code | `CM-OID-*` |
| RSA encryption without OAEP | `TLS-RSA-002` |
| RSA keys under 2048 bits | `TLS-RSA-001` |
| Private keys encrypted with 3DES | `CM-PEM-001` |

Runbooks give the fix: AES-GCM content encryption with RSA-OAEP key transport.

**4.4 Not built (by design, documented).** A per-record hybrid *output* format, where writers hold only a public key, is not built. The v2 envelope uses a stored key instead, protected by RSA if you choose 4.2. RSA itself has a deadline: NIST's draft IR 8547 proposes deprecating RSA-2048 after 2030. The same pipeline can drive an RSA → ML-KEM migration with a new policy pack.

## 5. Security layers

`layers: [pki-tls, auth-wireless, secure-coding]` adds three policy packs to the migration. They cover:

- certificates and TLS handshakes
- authentication and Wi-Fi
- SQL injection and memory safety

Layer findings at or above `layer_fail_on` (default `high`) block the Phase 4 and 6 gates and final verification. Malware scanning, host hardening, and the operators' own authentication are built into the engine and governance. Details, prevention strategies and limits: [SECURITY_LAYERS.md](SECURITY_LAYERS.md).

## 6. How the GitHub repository solves the DES → AES problem

* **Stops new DES and weak security from entering.** The crypto-gate workflow fails pull requests with high or critical findings and posts them to code scanning.
* **Finds what exists.** The inventory and CycloneDX CBOM answer "where is DES?" for auditors (PCI DSS 12.3.3).
* **Plans and records decisions in the open.** Runbooks and WBS issues; approvals are pull requests to `migration.yaml` reviewed by CODEOWNERS, optionally signed.
* **Executes safely.** The migration-pipeline workflow re-encrypts from a runner inside your network, pausing for the `production` environment's reviewers before each wave.
* **Proves the result.** Verification checks every record; the attestation zip carries SHA-256 hashes anchored in the audit log, and releases ship with an SBOM and signed build provenance.

Use it either as a template repository per migration project, or install it into existing repositories with `cryptomigrate init --github`.
