"""Power-on style self-test: known-answer tests (KATs) from independently published vectors.

Run before any key operation or re-encryption run (FIPS 140-3 style pre-operational
self-test). Each vector comes from a public specification, not from this code base, so a
pass proves the runtime crypto library - not just our own round trip - behaves correctly.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_wrap_with_padding

from . import legacy
from .envelope import DecryptionError, open_envelope, parse, seal

_H = bytes.fromhex


def _gcm(key_hex: str, iv_hex: str, pt_hex: str, expected_hex: str) -> bool:
    return AESGCM(_H(key_hex)).encrypt(_H(iv_hex), _H(pt_hex), None).hex() == expected_hex


def _legacy_ecb(alg: str, key_hex: str, ct_hex: str, expected_pt: bytes) -> bool:
    profile = legacy.LegacyProfile("kat", alg, "ECB", "kat", "none", "none", "raw").validate()
    return legacy.decrypt(profile, _H(key_hex), _H(ct_hex)) == expected_pt


def _envelope_selfcheck() -> bool:
    key = bytes(range(32))
    blob = seal(key, "kat", b"cryptomigrate", b"ctx")
    if open_envelope(key, parse(blob), b"ctx") != b"cryptomigrate":
        return False
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    for candidate, ctx in ((bytes(tampered), b"ctx"), (blob, b"other-ctx")):
        try:
            open_envelope(key, parse(candidate), ctx)
            return False
        except DecryptionError:
            pass
    return True


KATS = [
    ("KAT-GCM-128", "AES-128-GCM encrypt", "GCM spec (McGrew & Viega) Test Case 2",
     lambda: _gcm("00" * 16, "00" * 12, "00" * 16,
                  "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")),
    ("KAT-GCM-256-A", "AES-256-GCM tag (empty plaintext)", "GCM spec Test Case 13",
     lambda: _gcm("00" * 32, "00" * 12, "", "530f8afbc74536b9a963b4f1c4cb738b")),
    ("KAT-GCM-256-B", "AES-256-GCM encrypt", "GCM spec Test Case 14",
     lambda: _gcm("00" * 32, "00" * 12, "00" * 16,
                  "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")),
    ("KAT-KW", "AES Key Wrap (256-bit KEK, 256-bit key)", "RFC 3394 sec. 4.6 / NIST SP 800-38F KW",
     lambda: aes_key_wrap(bytes(range(32)), _H("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F"))
     .hex().upper() == "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"),
    ("KAT-KWP", "AES Key Wrap with Padding (20-byte key)", "RFC 5649 sec. 6 / NIST SP 800-38F KWP",
     lambda: aes_key_wrap_with_padding(_H("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"),
                                       _H("c37b7e6492584340bed12207808941155068f738")).hex()
     == "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"),
    ("KAT-TDEA", "3-key TDEA ECB decrypt (legacy path)", "NIST SP 800-67 Rev.2 example",
     lambda: _legacy_ecb("3DES", "0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123",
                         "A826FD8CE53B855FCCE21C8112256FE668D5C05DD9B6B900", b"The qufck brown fox jump")),
    ("KAT-DES", "Single DES ECB decrypt (legacy path)", "Grabbe, 'The DES Algorithm Illustrated'",
     lambda: _legacy_ecb("DES", "133457799BBCDFF1", "85E813540F0AB405", _H("0123456789ABCDEF"))),
    ("SELF-ENVELOPE", "v2 envelope round trip, tamper and context binding", "implementation self-check",
     _envelope_selfcheck),
]


def run_selftest() -> list[dict]:
    results = []
    for test_id, description, source, check in KATS:
        try:
            passed, detail = bool(check()), ""
        except Exception as exc:  # noqa: BLE001 - a crashing KAT is a failing KAT
            passed, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({"id": test_id, "description": description, "source": source, "passed": passed,
                         "detail": detail})
    return results


def selftest_ok() -> bool:
    return all(r["passed"] for r in run_selftest())
