# Key management

Aligned with NIST SP 800-57 Part 1 and the workplan's Key Management Plan (Section 8). `cryptomigrate plan` generates a project-specific `key-management-plan.md` from your configuration and keystore.

## Key hierarchy

```
KEK (key-encryption key)            never written to disk: env var / passphrase / HSM / KMS
 ├── AES data keys (DEKs)            wrapped with AES-KWP (RFC 5649, SP 800-38F); one active, older ones decrypt-only
 └── legacy DES/TDEA keys            wrapped the same way; decrypt-only; destroyed at close-out
```

The keystore (`keystore.path`, default `.cryptomigrate/keystore.json`, mode 0600) holds only wrapped keys plus metadata: algorithm, state, key check value (KCV), timestamps, usage counter and strength notes. **Never commit it**: Git history would defeat destruction (crypto-shredding). `cryptomigrate init` adds `.cryptomigrate/` to `.gitignore`.

## KEK sources

| Source | Use for | How |
|---|---|---|
| `CRYPTOMIGRATE_KEK` (base64, 32 bytes) | CI, pipelines, most deployments | `cryptomigrate keys new-kek` once; store in a secrets manager; inject at run time |
| `CRYPTOMIGRATE_KEK_PASSPHRASE` | workstations, demos | PBKDF2-HMAC-SHA256, 600,000 iterations, random salt (SP 800-132) |
| HSM / cloud KMS | production with regulated data | implement a key provider (below) |

A KEK check value is stored so a wrong KEK fails immediately with a clear error rather than at the first unwrap.

## RSA protecting the AES keys (`wrap: rsa-aes-kwp`)

```yaml
keystore:
  wrap: rsa-aes-kwp
  rsa_public_key: keys/kek-public.pem          # public half: safe to commit
# private half: path in CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE (+ CRYPTOMIGRATE_KEK_RSA_PASSPHRASE)
```

Every stored key - AES data keys and imported legacy keys alike - is wrapped with a one-time AES-256 key (AES-KWP), and that AES key is wrapped with RSA-OAEP-SHA256: the PKCS#11 `CKM_RSA_AES_KEY_WRAP` construction. The two-step design matters: RSA-OAEP alone could not wrap a legacy RSA private key (about 1.2 KB).

| Operation | Needs |
|---|---|
| `keys init`, `keys rotate`, `keys import-legacy` | public key only - a custodian can create keys without being able to decrypt data |
| encrypting/decrypting data, re-encryption, verification | private key (HSM-backed or a protected file) |

The KEK must be RSA ≥ 2048 bits (3072+ recommended). Whenever the private key is loaded, its public-key fingerprint is checked against the keystore and a pairwise-consistency test runs. Prefer this mode when policy demands that the decrypting key live only in an HSM.

## Lifecycle

| Stage | Command | Notes |
|---|---|---|
| Generation | `keys init`, `keys rotate` | 256-bit (or 128-bit) keys from the OS CSPRNG; KCV = first 3 bytes of AES-CMAC over a zero block |
| Activation | automatic | exactly one active AES key; encryption always uses it |
| Rotation | `keys rotate --reason ...` | new key active, previous key decrypt-only; rotate within the SP 800-57 originator-usage period for data-encryption keys (≤ 2 years) and well before 2^32 encryptions (random-nonce limit); `keys list` warns at 50 % |
| Legacy import | `keys import-legacy --key-id ID --algorithm 3DES --hex-env VAR` (or `--stdin`) | decrypt-only; never accepted on the command line (shell history); records strength notes |
| Destruction | `keys destroy --key-id ID --confirm ID --reason ...` | refuses while any record still needs the key; removes wrapped material; audit-logged |

## Legacy key ceremony

1. Two custodians retrieve the legacy key (dual control) from its current home (HSM export under a transport key, sealed envelope, or the legacy application's key store).
2. One custodian exports it into an environment variable on the migration host (or pipes it to `--stdin`); nothing is typed as a command-line argument.
3. `import-legacy` prints the **KCV**: the first three bytes of the TDEA-ECB encryption of a zero block, the convention HSMs and key-custodian forms use. Both custodians confirm it matches their record. A mismatch means the wrong key: stop.
4. Review the printed strength notes: 2-key TDEA, degenerate bundles (K1 = K2 or K2 = K3, i.e. single DES), and DES weak or semi-weak components are all flagged and should be recorded in the risk register.
5. Clear the environment variable and destroy any temporary copies.

## Destruction semantics

Destruction removes the wrapped key from the keystore. Because the KEK never touches disk, the remaining ciphertext and the backups encrypted under that key become permanently unreadable: crypto-shredding. File-level deletion cannot guarantee physical erasure on journaling file systems or SSDs; for certified destruction, keep legacy keys in an HSM and use its destruction function, recording the reference in the audit log.

Order of operations at close-out: verification passes → stabilisation window ends → delete run backups (`.cryptomigrate/backups/`) → `keys destroy` → `migration.mode: strict`.

## HSM / KMS integration

`CryptoService` and the engine need a key provider with this small surface (implemented by `keys/keystore.py::Keystore`):

```python
class KeyProvider(Protocol):
    def active_key_id(self) -> str: ...
    def get(self, key_id: str) -> bytes: ...          # raw key bytes, held in memory only
    def has_material(self, key_id: str) -> bool: ...
    def legacy_keys(self) -> list[str]: ...
    def list(self) -> list[dict]: ...                 # metadata only
    def record_usage(self, key_id: str, encryptions: int) -> None: ...
    def usage_warnings(self) -> list[str]: ...
```

Two integration patterns:

* **KEK in KMS/HSM, wrapped data keys (envelope encryption).** Keep the keystore format and replace the local KEK with a KMS/HSM unwrap call in `get()`, for example AWS KMS `Decrypt`, Azure Key Vault `unwrapKey`, HashiCorp Vault Transit `decrypt`, or PKCS#11 `C_UnwrapKey`. Data keys exist in memory only while the process runs. This fits the interface unchanged.
* **Non-extractable keys in an HSM.** If keys must never leave the HSM, the provider cannot return bytes. Implement a `CryptoService` variant whose `encrypt`/`decrypt` call the HSM's AES-GCM mechanism (e.g. PKCS#11 `CKM_AES_GCM`) and emit the same envelope ([ENVELOPE_SPEC.md](ENVELOPE_SPEC.md)). Legacy TDEA decryption likewise runs in the HSM.
