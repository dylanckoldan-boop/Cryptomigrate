# Security layers

The migration removes DES. The layers check the controls *around* the cryptography, because a perfect AES migration still fails if:

- certificates are not validated,
- passwords are stored with fast hashes,
- Wi-Fi still runs TKIP,
- a query concatenates user input,
- a binary ships without an executable-stack guard.

Enable them in `migration.yaml`:

```yaml
layers: [pki-tls, auth-wireless, secure-coding]
layer_fail_on: high     # findings at/above this severity block gates 4 and 6 and final verification
```

Every layer is a policy pack, so its rules, severities and remediation text can be read and changed in one YAML file. Findings carry their layer, so the assessment reports compliance per layer and gates can treat the migration and the layers separately.

Each section below lists the most effective prevention first (what removes the risk class), then what cryptomigrate checks, then mitigation and limits.

## 1. Certificates (PKI)

**Prevent.**
- Automate issuance and renewal (ACME / certificate lifecycle management). Publicly-trusted TLS lifetimes are 200 days since 2026-03-15, 100 from 2027-03-15 and 47 from 2029-03-15 (CA/Browser Forum SC-081v3); manual renewal does not scale to that.
- Use ECDSA P-256 or RSA-3072+ keys, SHA-256+ signatures, and subjectAltName for every name.
- Trust private CAs through CA bundles, never by disabling verification.

**cryptomigrate checks.** Every certificate file found during discovery, and every live endpoint's certificate:

| Check | Rule |
|---|---|
| MD5/SHA-1 signature | `CERT-SIG-001` |
| RSA < 2048 bits, DSA, or EC < 224 bits | `CERT-KEY-001` |
| Expired / expiring within `cert_expiry_warn_days` | `CERT-EXP-001` / `CERT-EXP-002` |
| Self-signed end-entity certificate | `CERT-SELF-001` |
| No subjectAltName | `CERT-SAN-001` |
| Lifetime above the CA/B limit in force when it was issued | `CERT-LIFE-001` |

Trust anchors (self-signed CAs) are exempt from signature and expiry checks. Certificates appear in the CBOM as CycloneDX `certificate` assets.

**Mitigate / limits.** Monitor Certificate Transparency logs for your domains. Revocation status (OCSP/CRL) is not checked.

## 2. SSL/TLS handshakes and transport

**Prevent.**
- TLS 1.2 and 1.3 only (RFC 8996, NIST SP 800-52 Rev. 2, RFC 9325).
- AEAD cipher suites with ECDHE key exchange.
- Certificate *and* hostname verification always on.
- Mutual TLS for service-to-service traffic; HSTS for web front ends.

**cryptomigrate checks.**

| Check | Rule |
|---|---|
| Configuration that enables SSLv3/TLS 1.0/1.1 (nginx, Apache, Postfix, Dovecot, HAProxy, `openssl.cnf`, Java/Tomcat/Spring) | `TLS-PROTO-001` |
| Code that disables verification (`verify=False`, `InsecureSkipVerify`, `rejectUnauthorized: false`, trust-all managers, `curl -k`, and similar) | `TLS-VERIFY-001` |

`TLS-PROTO-001` is **auto-fixed** by `cryptomigrate remediate` in each file's own syntax. Each fix is checked by re-scanning, and the change can be rolled back.

For live endpoints (`scan.tls_endpoints`, `systems[].endpoints`), the probe writes raw ClientHellos, so it works even where local OpenSSL has disabled old protocols. It checks:

| Check | Rule |
|---|---|
| Server negotiates SSLv3, TLS 1.0 or TLS 1.1 | `TLS-PROBE-PROTO-001` |
| A TLS 1.2+ handshake fails | `TLS-PROBE-MODERN-001` |
| Chain or hostname verification fails | `TLS-PROBE-CERT-001` |
| No forward secrecy | `TLS-PROBE-FS-001` |
| DES/3DES suites accepted | `CM-PROBE-TLS-001` |

Negotiated protocols are recorded as CycloneDX `protocol` assets.

**Limits.** Direct TLS only. STARTTLS (SMTP/IMAP/LDAP) and QUIC are not probed.

## 3. User authentication

**Prevent.**
- Centralise authentication in an identity provider with phishing-resistant MFA (FIDO2/WebAuthn passkeys; NIST SP 800-63B).
- Store passwords with Argon2id (m=19 MiB, t=2, p=1), scrypt, bcrypt (cost ≥ 10) or PBKDF2-HMAC-SHA256 (600,000 iterations) - OWASP Password Storage Cheat Sheet.
- Retire NTLM in favour of Kerberos; retire PPTP.
- Keep secrets in a secrets manager.

**cryptomigrate checks.** DES survives in authentication long after it leaves encryption, and these rules find it:

| Check | Rule |
|---|---|
| DES `crypt(3)` hashes in shadow/htpasswd files | `AUTH-CRYPT-001` |
| LM / NTLMv1 allowed, or LM hashes stored (Windows `.reg` exports) | `AUTH-NTLM-001` / `AUTH-NTLM-002` |
| PPTP / MS-CHAPv2 | `AUTH-MSCHAP-001` |

Plus:

| Check | Rule |
|---|---|
| Weak htpasswd schemes | `AUTH-HTPASSWD-001` |
| Passwords hashed with fast hashes | `AUTH-HASH-001` (low confidence; key-derivation functions excluded) |
| Hard-coded credentials | `AUTH-CRED-001` |

Values that match the hash and credential rules are redacted from every report.

**The toolkit's own operators.** Authentication is delegated to systems built for it rather than reinvented:

- GitHub SSO + MFA for everyone.
- CODEOWNERS review of `migration.yaml`.
- `production` environment reviewers approve each wave.
- `governance.require_signed_commits: true` makes sign-offs count only when `migration.yaml`'s last commit is cryptographically signed.
- `governance.dual_control: true` requires two distinct recorded approvers before any key is destroyed.

**Limits.** Configuration and code only. Identity-provider policies (MFA enforcement, session lifetimes) are not inspected.

## 4. Wireless

**Prevent.**
- WPA3-Personal (SAE) or WPA3-Enterprise (192-bit mode for sensitive networks).
- Protected Management Frames required.
- EAP-TLS with RADIUS server-certificate validation.
- No WEP, TKIP or WPS.
- Guest and IoT networks segmented (NIST SP 800-153).

**cryptomigrate checks** (`hostapd`, `wpa_supplicant` and NetworkManager files):

| Check | Rule |
|---|---|
| WEP | `WIFI-WEP-001` |
| TKIP | `WIFI-TKIP-001` |
| WPA version 1 / mixed mode | `WIFI-WPA1-001` |
| PMF disabled | `WIFI-PMF-001` |
| WPS enabled | `WIFI-WPS-001` |
| PEAP/TTLS-MS-CHAPv2 without server-certificate validation | `WIFI-EAP-001` |

That last one is the DES connection: a rogue access point captures MS-CHAPv2, which reduces to one DES key search.

**Limits.** No radio-frequency scanning or rogue-AP detection. Use a wireless intrusion prevention system for that.

## 5. SQL injection

**Prevent.**
- Parameterized queries / prepared statements everywhere, or an ORM's safe APIs.
- Allow-list any dynamic identifiers.
- Least-privilege database accounts.
- (OWASP SQL Injection Prevention Cheat Sheet; OWASP Top 10 A03.)

**cryptomigrate checks.** SQL assembled by formatting or concatenation in Python, Java/JVM, PHP, JavaScript/TypeScript, .NET and Go (`SQLI-*-001`). The toolkit's own SQL layer binds every value and validates every identifier at configuration load; a test proves `"t; DROP TABLE x"` is rejected.

**Mitigate / limits.** These rules are pattern-based (medium confidence), not taint analysis. The repository's CodeQL workflow adds data-flow analysis for its own code; run CodeQL or Semgrep on your applications too. A WAF and database activity monitoring are compensating controls, not fixes.

## 6. Buffer overflows and memory safety

**Prevent.**
- Write new components in memory-safe languages (CISA/NSA memory-safety guidance).
- In C/C++ use bounded APIs.
- Compile with the OpenSSF hardening set: `-fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fcf-protection=full -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack`.
- Fuzz with AddressSanitizer/UBSan in CI.

**cryptomigrate checks.**

| Check | Rule |
|---|---|
| `gets` | `MEM-C-001` |
| `strcpy`/`strcat`/`sprintf` family | `MEM-C-002` |
| `scanf` `%s` without a width | `MEM-C-003` |
| Builds that switch mitigations off (`-fno-stack-protector`, `-z execstack`, `-no-pie`, `/GS-`, ...) | `MEM-BUILD-001` |

Shipped binaries (`scan.binaries` or `discover --binaries`) are verified directly from their ELF headers, checksec-style:

| Mitigation | Rule |
|---|---|
| Executable stack | `MEM-BIN-NX-001` |
| PIE | `MEM-BIN-PIE-001` |
| RELRO | `MEM-BIN-RELRO-001` |
| Stack canary | `MEM-BIN-CANARY-001` |
| FORTIFY_SOURCE | `MEM-BIN-FORTIFY-001` |

The checks are tested against binaries compiled with and without each flag. Go and Rust binaries skip the canary and FORTIFY checks.

**Limits.** ELF only (use Microsoft BinSkim for Windows PE). A canary can be legitimately absent from tiny functions.

## 7. Malware

**Prevent** (supply chain first, since the toolkit handles keys):
- Reviewed, pinned dependencies with automated updates: dependency review on pull requests, `pip-audit` in CI, Dependabot.
- CodeQL on the toolkit's code.
- Releases with an SBOM and signed SLSA build provenance (`gh attestation verify`).
- A hardened migration host: `cryptomigrate doctor` checks privileges, core dumps (disabled automatically), file permissions, keystore not in Git, OpenSSL version and FIPS mode.

**Detect in the data path.** Encrypted files are opaque to antivirus at rest; migration is the first time their contents are visible. With `migration.malware_scan.enabled`, every decrypted file and BLOB is streamed to ClamAV (clamd `INSTREAM`) *before* re-encryption.

**Respond.**
- Detections stay under their legacy encryption, which keeps them inert.
- They are reported in the run manifest and audit log (`malware.detected`).
- They block verification until a human decides.
- If the scanner is unavailable, the run aborts (fail closed).

**Limits.** ClamAV is signature-based. Pair it with endpoint detection and response on the migration host (NIST SP 800-83).

## 8. "Certification" in the compliance sense

If the requirement is formal certification rather than X.509, the evidence trail is already in place:

- The attestation package maps every control to evidence (NIST SP 800-131A/53, PCI DSS 4.0.1, HIPAA, ISO 27001, CSF 2.0, ASVS).
- `doctor` reports kernel FIPS mode.

cryptomigrate is not a FIPS 140-3 validated module itself; validated operation depends on the OpenSSL FIPS provider under `pyca/cryptography`.
