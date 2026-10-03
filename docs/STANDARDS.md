# Standards and references

What each standard requires and where the toolkit implements or evidences it. Standards are revised: confirm the current version of each before relying on this table for a compliance decision. cryptomigrate is not a FIPS 140-3 validated module; its cryptography comes from `pyca/cryptography` (OpenSSL), whose validation status depends on the OpenSSL FIPS provider your platform ships.

## Cryptographic standards

| Standard | Relevance | Implementation |
|---|---|---|
| FIPS 197 (AES) | migration target | AES-128/256 via the envelope |
| NIST SP 800-38D (GCM) | authenticated mode; IV construction (§8.2); invocation limits (§8.3) | 96-bit random nonces, 128-bit tags, usage counter and warning |
| NIST SP 800-38F (KW / KWP) | key wrapping | AES-KWP for every stored key; RFC 3394 / 5649 KATs |
| NIST SP 800-131A Rev. 2 (Rev. 3 initial public draft, Oct 2024; check for the final version) | DES/TDEA disallowed for applying protection; TDEA decrypt for legacy use only; Rev. 3 draft proposes retiring ECB | decrypt-only legacy module; GCM-only target; algorithm status in the CBOM |
| NIST SP 800-67 Rev. 2 (withdrawn 1 Jan 2024) | TDEA specification | legacy decrypt; SP 800-67 example used as a KAT |
| FIPS 46-3 (withdrawn 2005) | DES | flagged critical everywhere |
| NIST SP 800-57 Part 1 Rev. 5 | key management, cryptoperiods | lifecycle states, rotation guidance, destruction |
| NIST SP 800-132 | password-based key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, random salt for passphrase KEKs |
| RFC 3394, RFC 5649 | AES key wrap (with padding) | keystore wrapping; KAT vectors |

## Compliance frameworks

| Framework | Controls | Evidence |
|---|---|---|
| PCI DSS v4.0.1 | 3.5.1 (render PAN unreadable), 3.6.1 / 3.7 (key management), 4.2.1 (strong cryptography in transit), **12.3.3** (documented, annually reviewed inventory of cipher suites and protocols; mandatory since 31 Mar 2025) | CBOM, inventory, key-management plan, verification, audit log |
| NIST SP 800-53 Rev. 5 | SC-8, SC-12, SC-13, SC-28, CM-8, AU-9 | see the attestation evidence map |
| NIST CSF 2.0 | ID.AM-07, PR.DS-01, PR.DS-02 | inventory, data verification, TLS probes |
| HIPAA Security Rule | 45 CFR 164.312(a)(2)(iv), (e)(2)(ii) | data verification, TLS probes |
| ISO/IEC 27001:2022 | Annex A 8.24 (use of cryptography) | policy pack, key-management plan |
| OWASP ASVS 4.0.3 | V6.2.5 (no small-block ciphers or insecure modes); renumbered in ASVS 5.0 | CI crypto gate, final scan |
| OMB M-23-02 (US federal) | annual cryptographic inventory toward post-quantum migration | CycloneDX CBOM |

## Security-layer standards (v1.1)

| Standard | Layer | Use |
|---|---|---|
| NIST SP 800-52 Rev. 2; RFC 8996; RFC 9325 (BCP 195) | TLS | TLS 1.2/1.3 only, recommended suites, certificate validation |
| CA/Browser Forum Baseline Requirements (SC-31, SC-081v3) | certificates | 398 → 200 (2026-03-15) → 100 (2027-03-15) → 47 days (2029-03-15) |
| RFC 5280 | certificates | X.509 profile: basic constraints, subjectAltName, validity |
| RFC 8017 (PKCS #1 v2.2); PKCS#11 `CKM_RSA_AES_KEY_WRAP` | hybrid | RSA-OAEP; RSA-wrapped AES-KWP construction used by `rsa-aes-kwp` |
| NIST IR 8547 (initial public draft, 2024) | hybrid | proposed post-quantum deprecation of RSA-2048 after 2030 |
| NIST SP 800-63B; OWASP Password Storage Cheat Sheet | authentication | phishing-resistant MFA; Argon2id/scrypt/bcrypt/PBKDF2 parameters |
| NIST SP 800-153; Wi-Fi Alliance WPA3; IEEE 802.11w | wireless | hardened WLANs, SAE, PMF, no WEP/TKIP |
| OWASP Top 10 (A03 Injection); OWASP SQL Injection Prevention Cheat Sheet | secure coding | parameterized queries, least privilege |
| OpenSSF Compiler Options Hardening Guide; CISA/NSA memory-safety guidance; SEI CERT C | secure coding | hardening flags, bounded APIs, memory-safe languages |
| NIST SP 800-218 (SSDF); SLSA build provenance; CycloneDX SBOM | supply chain | secure build, verified releases |
| NIST SP 800-83 Rev. 1 | malware | prevention and incident handling; scanner + EDR |

## Weaknesses and vulnerabilities

| ID | Meaning |
|---|---|
| CWE-327 | Use of a broken or risky cryptographic algorithm |
| CWE-326 | Inadequate encryption strength |
| CWE-328 | Use of weak hash (certificate signatures, hash policy packs) |
| CWE-295 / CWE-298 | Improper certificate validation / expired certificates |
| CWE-780 | RSA without OAEP |
| CWE-89 | SQL injection |
| CWE-120 / CWE-121 / CWE-242 / CWE-676 | Buffer overflow / stack overflow / inherently dangerous / potentially dangerous functions |
| CWE-693 | Protection mechanism failure (disabled exploit mitigations) |
| CWE-798 / CWE-916 | Hard-coded credentials / password hash with insufficient effort |
| CVE-2016-2183 (Sweet32) | birthday attack on 64-bit block ciphers (3DES) in long TLS sessions |

## Formats and process

| Standard | Use |
|---|---|
| CycloneDX 1.6 (ECMA-424) | Cryptography Bill of Materials (`cbom.cdx.json`), validated against the official schema in the tests |
| OASIS SARIF 2.1.0 | static-analysis results for GitHub code scanning |
| PMBOK Guide | phase structure, WBS and RACI used by the workplan |

## Known-answer test sources

| Test | Source |
|---|---|
| AES-GCM Test Cases 2, 13, 14 | McGrew & Viega, *The Galois/Counter Mode of Operation* (GCM specification) |
| AES Key Wrap | RFC 3394 §4.6 |
| AES Key Wrap with Padding | RFC 5649 §6 |
| 3-key TDEA | NIST SP 800-67 Rev. 2 worked example |
| DES | J. Orlin Grabbe, *The DES Algorithm Illustrated* |
