"""Phase 5 validation suite - produces the test evidence for the Testing phase gate.

Checks: published known-answer tests, randomized round trips, tamper detection, context
(AAD) binding, nonce uniqueness, no-fallback (the toolkit cannot emit DES/3DES), legacy
profile correctness against real sampled data, column-width headroom and the NFR-01
performance budget. Results are written to artifacts/validation/ as JSON and Markdown.
"""

from __future__ import annotations

import inspect
import os
import platform
import time
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .crypto import legacy
from .crypto.envelope import DecryptionError, is_armored, is_envelope, open_envelope, parse, projected_length, seal
from .crypto.selftest import run_selftest
from .crypto.service import CryptoService
from .util import isotime, md_table, write_json, write_text


def _check(checks: list[dict[str, Any]], check_id: str, title: str, passed: bool | None, detail: str = "",
           evidence: Any = None) -> None:
    status = "skip" if passed is None else ("pass" if passed else "fail")
    checks.append({"id": check_id, "title": title, "status": status, "detail": detail, "evidence": evidence})


def aes_ni_available() -> str:
    try:
        if platform.system() == "Linux":
            flags = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
            return "yes" if " aes " in flags.replace("\n", " ") else "no"
        if platform.system() == "Darwin":
            return "yes (Apple silicon / x86 AES instructions)"
    except OSError:
        pass
    return "unknown"


def _bench(fn, iterations: int, repeats: int = 3) -> float:
    """Best-of-N microseconds per call (the minimum is the least noisy estimator, as in timeit)."""
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        for _ in range(iterations):
            fn()
        best = min(best, (time.perf_counter() - start) / iterations * 1e6)
    return best


def _is_v2(value: Any) -> bool:
    if isinstance(value, str):
        return is_armored(value)
    return isinstance(value, (bytes, bytearray)) and is_envelope(bytes(value))


def run_validation(cfg: Config, service: CryptoService, quick: bool = False) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    kats = run_selftest()
    for kat in kats:
        _check(checks, kat["id"], f"{kat['description']} [{kat['source']}]", kat["passed"], kat["detail"])

    rounds = 100 if quick else 1000
    failures = 0
    for i in range(rounds):
        plaintext = os.urandom(i % 4097)
        context = f"roundtrip#{i}"
        blob = service.encrypt(plaintext, context) if i % 2 else service.encrypt_text(plaintext, context)
        if service.decrypt(blob, context) != plaintext:
            failures += 1
    _check(checks, "VAL-ROUNDTRIP", f"Randomized round trip ({rounds} messages, 0-4096 bytes, binary + text)",
           failures == 0, f"{failures} failures")

    blob = service.encrypt(b"tamper-test", "ctx")
    header_len = 7 + blob[6]
    positions = {"magic": 1, "key id": 7, "nonce": header_len + 1, "ciphertext": header_len + 13, "tag": len(blob) - 1}
    undetected = []
    for name, pos in positions.items():
        mutated = bytearray(blob)
        mutated[pos] ^= 0x40
        try:
            service.decrypt(bytes(mutated), "ctx")
            undetected.append(name)
        except DecryptionError:
            pass
    _check(checks, "VAL-TAMPER", "Single-bit tampering detected in every envelope field", not undetected,
           f"undetected: {undetected}" if undetected else "all fields authenticated")

    try:
        service.decrypt(service.encrypt(b"row-a", "customers.ssn#1"), "customers.ssn#2")
        bound = False
    except DecryptionError:
        bound = True
    _check(checks, "VAL-AAD", "Ciphertext bound to its context (row swap rejected)", bound)

    n = 2000 if quick else 10000
    nonces = {parse(service.encrypt(b"x")).nonce for _ in range(n)}
    _check(checks, "VAL-NONCE", f"No nonce reuse across {n} encryptions (96-bit random IVs)", len(nonces) == n,
           f"{n - len(nonces)} duplicates")

    sample = service.encrypt(b"fallback-check")
    exported = [name for name, obj in inspect.getmembers(legacy, inspect.isfunction)
                if "encrypt" in name.lower() and obj.__module__ == legacy.__name__]
    env = parse(sample)
    _check(checks, "VAL-NO-FALLBACK", "Encryption can only produce AES-GCM; legacy module is decrypt-only",
           is_envelope(sample) and is_armored(service.encrypt_text(b"x")) and env.algorithm == cfg.target_algorithm
           and not exported, f"algorithm={env.algorithm}; legacy encrypt functions exported: {exported or 'none'}")

    strict = CryptoService(service.keystore, cfg.target_algorithm, cfg.legacy_profiles, mode="strict")
    _check(checks, "VAL-STRICT", "Strict mode rejects legacy ciphertext",
           strict.classify("AAAAAAAAAAAAAAAAAAAAAA==", b"", next(iter(cfg.legacy_profiles), None)).kind == "invalid")

    # Legacy profile correctness on real data: the single most important pre-migration test.
    from .migration.adapters import open_adapter
    for ds in cfg.data_sources:
        try:
            with open_adapter(ds) as adapter:
                for target in adapter.targets():
                    label = target.name if ds.adapter == "sql" else "files"
                    profile = cfg.legacy_profiles[target.legacy_profile]
                    values = adapter.sample(target.name, 25 if quick else 200)
                    outcome = {"legacy": 0, "v2": 0, "invalid": 0, "empty": 0}
                    errors, longest = [], 0
                    for value in values:
                        value = value.tobytes() if isinstance(value, memoryview) else value
                        if _is_v2(value):  # already migrated: format check only (its AAD may need the row key)
                            outcome["v2"] += 1
                            continue
                        result = service.classify(value, b"", target.legacy_profile)
                        outcome[result.kind] += 1
                        if result.kind == "legacy":
                            longest = max(longest, len(legacy.decode(profile, value)) - profile.prefix_overhead)
                        elif result.kind == "invalid" and len(errors) < 3:
                            errors.append(result.error)
                    _check(checks, f"VAL-PROFILE:{ds.name}:{label}",
                           f"Legacy profile '{target.legacy_profile}' decrypts sampled data in {ds.name}.{label}",
                           outcome["invalid"] == 0, ", ".join(f"{k}={v}" for k, v in outcome.items()), errors or None)
                    if target.max_length and longest:
                        need = projected_length(longest, 22, target.storage == "text")
                        _check(checks, f"VAL-WIDTH:{ds.name}:{target.name}",
                               f"Column {target.name} can hold AES-GCM output", need <= target.max_length,
                               f"needs {need}, max_length {target.max_length}")
        except Exception as exc:  # noqa: BLE001
            _check(checks, f"VAL-PROFILE:{ds.name}", f"Data source {ds.name} reachable for validation", False,
                   f"{type(exc).__name__}: {exc}")

    size = int(cfg.nfr.get("benchmark_record_bytes", 256))
    iterations = 300 if quick else int(cfg.nfr.get("benchmark_iterations", 2000))
    budget = float(cfg.nfr.get("max_latency_increase_pct", 10))
    bench_key = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
    aes_key = os.urandom(32)
    profile = legacy.LegacyProfile("bench", "3DES", "CBC", "bench", "prefix", "pkcs7", "raw")
    measured = {}
    for label, length, n in (("record", size, iterations), ("64KiB", 65536, max(20, iterations // 20))):
        record = os.urandom(length)
        legacy_blob = _legacy_fixture(bench_key, record)
        env = parse(seal(aes_key, "bench", record, b"bench"))
        measured[label] = {
            "tdea_cbc_decrypt_us": _bench(lambda b=legacy_blob: legacy.decrypt(profile, bench_key, b), n),
            "aes_gcm_decrypt_us": _bench(lambda e=env: open_envelope(aes_key, e, b"bench"), n),
            "aes_gcm_encrypt_us": _bench(lambda r=record: seal(aes_key, "bench", r, b"bench"), n),
        }
    rec = measured["record"]
    service_us = _bench(lambda: service.encrypt(b"x" * size, "bench"), iterations)
    worst = max(rec["aes_gcm_decrypt_us"], rec["aes_gcm_encrypt_us"])
    change = (worst / rec["tdea_cbc_decrypt_us"] - 1) * 100
    big = measured["64KiB"]
    _check(checks, "VAL-PERF", f"NFR-01: AES-GCM per-record latency within +{budget:g}% of the 3DES-CBC baseline",
           change <= budget,
           f"{size} B: AES-GCM dec {rec['aes_gcm_decrypt_us']:.1f} us / enc {rec['aes_gcm_encrypt_us']:.1f} us vs "
           f"3DES {rec['tdea_cbc_decrypt_us']:.1f} us ({change:+.0f}%); 64 KiB: "
           f"{big['tdea_cbc_decrypt_us'] / big['aes_gcm_decrypt_us']:.0f}x faster; AES-NI: {aes_ni_available()}",
           {"measurements_us": {k: {m: round(v, 2) for m, v in d.items()} for k, d in measured.items()},
            "crypto_service_encrypt_us": round(service_us, 2), "latency_change_pct": round(change, 1)})

    for warning in service.keystore.usage_warnings():
        _check(checks, "VAL-KEY-USAGE", "Key usage below SP 800-38D random-IV threshold", False, warning)

    failed = [c for c in checks if c["status"] == "fail"]
    return {"schema": "cryptomigrate-validation/1", "generated": isotime(), "tool_version": __version__,
            "quick": quick, "status": "fail" if failed else "pass",
            "summary": {"total": len(checks), "passed": sum(c["status"] == "pass" for c in checks),
                        "failed": len(failed), "skipped": sum(c["status"] == "skip" for c in checks)},
            "environment": {"python": platform.python_version(), "platform": platform.platform(),
                            "aes_ni": aes_ni_available()},
            "checks": checks}


def _legacy_fixture(key: bytes, record: bytes) -> bytes:
    """3DES-CBC ciphertext used only as the benchmark baseline (built with the raw primitive, not the toolkit API)."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    iv = bytes(8)
    padder = padding.PKCS7(64).padder()
    data = padder.update(record) + padder.finalize()
    enc = Cipher(legacy._tdea()(key), modes.CBC(iv)).encryptor()  # cryptomigrate: ignore -- benchmark baseline only
    return iv + enc.update(data) + enc.finalize()


def write_validation(cfg: Config, report: dict[str, Any]) -> dict[str, Path]:
    out = cfg.artifact("validation")
    md = [f"# Validation report ({report['status'].upper()})", "",
          f"Generated {report['generated']} - {report['summary']['passed']}/{report['summary']['total']} checks passed"
          f"{' (quick mode)' if report['quick'] else ''}. Environment: Python {report['environment']['python']}, "
          f"AES-NI {report['environment']['aes_ni']}.", "",
          md_table(["Check", "Status", "Title", "Detail"],
                   [[c["id"], c["status"].upper(), c["title"], c["detail"]] for c in report["checks"]]), ""]
    return {"json": write_json(out / "validation-report.json", report),
            "md": write_text(out / "validation-report.md", "\n".join(md))}
