# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** (private security advisory) rather than a public issue. Include the affected version, a description, and reproduction steps. We aim to acknowledge reports within 3 business days.

## Supported versions

| Version | Supported |
|---|---|
| 1.x | yes |

## Security design summary

* New encryption is AES-GCM only (FIPS 197 + SP 800-38D) with random 96-bit nonces and context-bound associated data.
* The legacy DES/TDEA module is decrypt-only; a validation check proves no encryption path exists.
* Keys are wrapped with AES-KWP under a KEK that never touches disk; the keystore is mode 0600 and must not be committed.
* Legacy decryption failures are deliberately generic (padding-oracle hygiene); keep the dual-mode window short.
* No plaintext or plaintext-derived value is persisted in manifests, backups or reports; likely key material is redacted from findings.
* Every key event, run, rollback and gate evaluation is recorded in a hash-chained audit log.
* The TLS probe only sends a ClientHello and reads the ServerHello. Probe only endpoints you are authorised to assess.

This toolkit is not a FIPS 140-3 validated module; validation depends on the OpenSSL build underneath `pyca/cryptography`.
