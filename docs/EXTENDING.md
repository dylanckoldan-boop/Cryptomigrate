# Extending cryptomigrate

Everything algorithm-specific lives in a **policy pack** (YAML). The SDLC machinery - inventory, CBOM/SARIF, assessment, planning, phase gates, audit log and attestation - is algorithm-agnostic and reusable as-is.

## What is reusable for which migration

| Migration | Discovery & reporting | Gates & attestation | Data re-encryption engine |
|---|---|---|---|
| Other legacy *symmetric ciphers* → AES-GCM (Blowfish, RC4, AES-CBC/ECB) | new policy pack | as-is | add the cipher to `crypto/legacy.py` |
| Hashes (SHA-1 / MD5 → SHA-256) | new policy pack | as-is | not applicable: hashes are re-computed, e.g. password re-hash on next login |
| Signatures / key exchange (RSA → ML-DSA / ML-KEM) | new policy pack | as-is | not applicable: re-sign or re-key instead |

## Writing a policy pack

Copy `src/cryptomigrate/policies/des-to-aes.yaml`, then point `policy:` in `migration.yaml` at your file (a path) or drop it in the `policies/` package directory (an id). A minimal example:

```yaml
id: sha1-to-sha256
name: "SHA-1 to SHA-256"
version: "0.1.0"
target_algorithm: SHA-256
legacy_algorithms: [SHA-1]
normalization:                     # matched against the lower-cased alphanumeric capture
  - algorithm: SHA-1
    markers: [sha1]
algorithms:
  SHA-1:   {oid: "1.3.14.3.2.26", primitive: hash, status: {digest: disallowed}}
  SHA-256: {oid: "2.16.840.1.101.3.4.2.1", primitive: hash, status: {digest: acceptable}}
compliance: {}
rules:
  - id: SHA1-JAVA-001
    title: "MessageDigest using SHA-1"
    category: source
    files: ["*.java", "*.kt"]
    pattern: '(?i)MessageDigest\.getInstance\(\s*"(?P<alg>SHA-?1)"'
    severity: high
    confidence: high
    cwe: [CWE-328]
    remediation: 'Use MessageDigest.getInstance("SHA-256").'
  - id: SHA1-PY-001
    title: "hashlib.sha1"
    category: source
    files: ["*.py"]
    pattern: '\bhashlib\.(?P<alg>sha1)\s*\('
    severity: high
    confidence: high
    cwe: [CWE-328]
    remediation: "Use hashlib.sha256()."
```

Rule fields: `files` are globs matched against the file name and repo-relative path; `pattern` is a Python regex whose named groups starting with `alg`/`mode` capture the algorithm and mode; `severity` is a level or a per-algorithm map; `validator` and `fix` reference functions in `discovery/ciphers.py`; `synthetic: true` marks rules emitted by probes or profilers. If your configuration uses `manual_assets` or data profiling, include the synthetic rules `CM-MANUAL-001` / `CM-DATA-001`. The built-in TLS probe is DES-specific: run discovery with `--no-tls` for other packs, or add a probe.

**Test every rule** with a positive and a negative fixture, as `tests/test_scanner.py` does. False negatives undermine the inventory, and false positives undermine trust in the gate.

## Validators and fixers

A validator decides whether a regex match is really a finding: `def validate(match, text) -> dict | None`. Returning `None` means "not a finding"; a dict can refine `algorithm`, `severity`, `confidence`, `mode` and `detail`. A fixer returns a corrected line, or `None` when a human must decide: `def fix(line, match) -> str | None`. Register both in `VALIDATORS` / `FIXERS`. Remediation re-scans each fixed line and refuses fixes that do not clear the finding.

Only automate changes that are safe to make unilaterally. Anything that must match a peer (VPN proposals, Kerberos, SNMP) stays manual.

## Data-source adapters

The engine needs this small surface (see `migration/adapters.py`):

| Method | Purpose |
|---|---|
| `targets()` | the encrypted fields: name, legacy profile, `text`/`blob`, optional `max_length` |
| `batches(after, size)` | yield `[(record_key, {field: value})]`, resumable from `after` |
| `sample(field, n)` | values for profiling and validation |
| `fetch(keys, field)` | read-back after write |
| `update_cas(key, field, old, new)` | write only if the value is still `old`; return success |
| `context(field, key)` | the AAD context string |
| `commit()`, `rollback()`, `close()`, `count()` | transaction plumbing |

Examples worth adding: an Oracle LOB adapter (compare with `DBMS_LOB.COMPARE`), a MongoDB adapter, an S3/object-store adapter (conditional writes on ETag act as compare-and-swap).

## More legacy ciphers

To migrate another legacy symmetric cipher, add it to `ALGORITHMS` and `_cipher()` in `crypto/legacy.py` (decrypt only), add a known-answer vector from its specification to `crypto/selftest.py`, and add detection rules to a policy pack. Blowfish is a natural candidate: it has the same 64-bit block, so the same Sweet32 exposure.

## Key providers

See [KEY_MANAGEMENT.md](KEY_MANAGEMENT.md#hsm--kms-integration).
