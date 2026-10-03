# Changelog

## 1.1.1 - 2026-10-03

* Single-DES keys are expanded to the equivalent K1=K2=K3 TDEA bundle before decryption, ahead of
  `cryptography` removing 8-byte TDEA keys (deprecated in 47+). Behaviour is unchanged.
* The test suite now fails on `CryptographyDeprecationWarning`, so CI flags library deprecations early.
* GitHub Actions bumped to current majors (checkout v7, setup-python v7, upload-artifact v7,
  dependency-review-action v5, attest-build-provenance v4), including the adopter workflow template.

## 1.1.0 - 2026-10-03

* **Hybrid RSA + symmetric systems**: legacy profiles with per-record RSA-wrapped DES/3DES content keys
  (`key_transport`: rsa-pkcs1v15 / rsa-oaep-sha1 / rsa-oaep-sha256); legacy RSA key import; keystore option
  `wrap: rsa-aes-kwp` that protects AES keys with RSA-OAEP-SHA256 (PKCS#11 CKM_RSA_AES_KEY_WRAP construction).
* **Security layers** (`layers:`): `pki-tls` (certificate inventory & hygiene, TLS protocol versions with safe
  auto-remediation, verification bypasses, weak RSA, committed private keys, live TLS handshake assessment),
  `auth-wireless` (DES crypt, LM/NTLMv1, MS-CHAPv2, weak password storage, hard-coded credentials, WEP/TKIP/WPA1/
  PMF/WPS/802.1X validation), `secure-coding` (SQL injection in six languages, unsafe C functions, disabled build
  hardening, ELF binary checks for NX/PIE/RELRO/canary/FORTIFY).
* CMS/S-MIME, OID and DES-encrypted PEM key detection in the DES pack; CBOM certificate and protocol assets.
* ClamAV hook scanning decrypted content before re-encryption; `doctor` host-hardening preflight; core dumps
  disabled; private (0700/0600) state; dual control for key destruction; signed-commit sign-offs.
* CI: dependency audit, CodeQL, dependency review, release workflow with SBOM and build provenance.

## 1.0.0 - 2026-10-02

Initial release: discovery (31 rules, wire-level TLS probe, data profiler, manual inventory), JSON/SARIF/CycloneDX 1.6 CBOM output, assessment, planning with runbooks and GitHub issues, keystore with AES-KWP, config remediation, validation suite, re-encryption engine with backup / compare-and-swap / read-back / resume / rollback, verification, attestation, seven phase gates, GitHub workflows and governance templates, end-to-end demo.
