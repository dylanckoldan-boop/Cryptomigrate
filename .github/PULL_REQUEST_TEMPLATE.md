## Summary

<!-- What changes and why. Link the WBS issue. -->

## Cryptography checklist

- [ ] No new DES/3DES - the **Crypto gate** check is green
- [ ] New encryption uses AES-GCM through `CryptoService` or an approved library, with a unique nonce per message
- [ ] Every `cryptomigrate: ignore` suppression carries a `-- justification`
- [ ] No keys, KEKs or plaintext secrets committed (the keystore lives in `.cryptomigrate/`, which is git-ignored)
- [ ] Changes to `migration.yaml` sign-offs or exceptions link the approving issue

## Change management

- Change ticket:
- Phase / WBS item:
- Rollback plan: <!-- e.g. `cryptomigrate rollback --run <run-id>` -->
