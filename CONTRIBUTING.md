# Contributing

```bash
make dev      # editable install with test extras
make check    # ruff (incl. bandit security rules) + crypto self-test + pytest
make demo     # end-to-end SDLC demo
make gate     # this repository's own crypto gate
```

## Ground rules

* **Every detection rule needs a positive and a negative fixture** under `tests/fixtures/` and a case in `tests/test_scanner.py`.
* **Cryptographic code changes** (`crypto/`, `keys/`) need a known-answer test from a published source and a review by the security team (CODEOWNERS).
* Never add an encryption path for legacy algorithms; legacy support is decrypt-only by design.
* Keep `docs/TRACEABILITY_MATRIX.md` current when a change affects a requirement, risk or gate.
* Suppressions in shipped code must carry a `-- justification`.
