"""Legacy DES / Triple-DES (TDEA) support - DECRYPT ONLY.

cryptomigrate: ignore-file=CM-PY-002 -- sanctioned decrypt-only legacy path (NIST SP 800-131A Rev.2 "legacy use")

NIST SP 800-131A Rev. 2 disallows DES/TDEA for *applying* protection but permits TDEA
decryption to process already-protected data ("legacy use"). This module therefore
exposes no data-encryption function: the toolkit is structurally unable to produce new
DES/3DES ciphertext (verified by the no-fallback test in ``cryptomigrate validate``).

A *legacy profile* describes how an existing system stored its ciphertext so the data can
be read back exactly once and re-protected with AES-GCM:

    algorithm  DES | 3DES          mode    CBC | ECB
    iv         prefix | fixed:<16 hex digits> | none      (ECB uses none)
    padding    pkcs7 (== PKCS#5 for 8-byte blocks) | zero | none
    encoding   base64 | hex | raw
    key_transport  none | rsa-oaep-sha256 | rsa-oaep-sha1 | rsa-pkcs1v15   (hybrid systems)

A *hybrid* profile describes RSA-on-symmetric-key records: each value is ``RSA(content key) || IV || ciphertext``.
The profile's key id then names the legacy RSA private key; the per-record DES/3DES content key is unwrapped
first. PKCS#1 v1.5 key transport is accepted for reading only - it is the Bleichenbacher/ROBOT-prone scheme the
migration retires.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import warnings
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from .envelope import DecryptionError


def _tdea():
    try:  # cryptography >= 43 moved TDEA to the "decrepit" namespace
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # pragma: no cover - older cryptography
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    return TripleDES


BLOCK = 8
ALGORITHMS = ("DES", "3DES")
MODES = ("CBC", "ECB")
PADDINGS = ("pkcs7", "zero", "none")
ENCODINGS = ("base64", "hex", "raw")
KEY_TRANSPORTS = ("none", "rsa-oaep-sha256", "rsa-oaep-sha1", "rsa-pkcs1v15")
KEY_ALGORITHMS = ("DES", "3DES", "RSA")

# DES weak / semi-weak keys (FIPS 74). Compared with parity bits stripped.
_WEAK = ["0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E"]
_SEMI_WEAK = [
    "01FE01FE01FE01FE", "FE01FE01FE01FE01", "1FE01FE00EF10EF1", "E01FE01FF10EF10E",
    "01E001E001F101F1", "E001E001F101F101", "1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E",
    "011F011F010E010E", "1F011F010E010E01", "E0FEE0FEF1FEF1FE", "FEE0FEE0FEF1FEF1",
]


def _strip_parity(block: bytes) -> bytes:
    return bytes(b & 0xFE for b in block)


_WEAK_SET = {_strip_parity(bytes.fromhex(k)) for k in _WEAK}
_SEMI_WEAK_SET = {_strip_parity(bytes.fromhex(k)) for k in _SEMI_WEAK}


@dataclass(frozen=True)
class LegacyProfile:
    name: str
    algorithm: str = "3DES"
    mode: str = "CBC"
    key_id: str = "legacy-3des"
    iv: str = "prefix"
    padding: str = "pkcs7"
    encoding: str = "base64"
    key_transport: str = "none"
    rsa_key_bits: int = 2048

    def validate(self) -> LegacyProfile:
        if self.key_transport not in KEY_TRANSPORTS:
            raise ValueError(f"legacy profile {self.name}: key_transport must be one of {KEY_TRANSPORTS}")
        if self.hybrid and (self.rsa_key_bits < 1024 or self.rsa_key_bits % 8):
            raise ValueError(f"legacy profile {self.name}: rsa_key_bits must be a multiple of 8, >= 1024")
        if self.algorithm not in ALGORITHMS:
            raise ValueError(f"legacy profile {self.name}: algorithm must be one of {ALGORITHMS}")
        if self.mode not in MODES:
            raise ValueError(f"legacy profile {self.name}: mode must be one of {MODES}")
        if self.padding not in PADDINGS:
            raise ValueError(f"legacy profile {self.name}: padding must be one of {PADDINGS}")
        if self.encoding not in ENCODINGS:
            raise ValueError(f"legacy profile {self.name}: encoding must be one of {ENCODINGS}")
        if self.mode == "ECB" and self.iv != "none":
            raise ValueError(f"legacy profile {self.name}: ECB mode takes iv: none")
        if self.mode == "CBC":
            if self.iv == "none":
                raise ValueError(f"legacy profile {self.name}: CBC mode needs iv: prefix or iv: fixed:<hex>")
            if self.iv.startswith("fixed:"):
                try:
                    if len(bytes.fromhex(self.iv[6:])) != BLOCK:
                        raise ValueError
                except ValueError as exc:
                    raise ValueError(f"legacy profile {self.name}: fixed IV must be 16 hex digits") from exc
            elif self.iv != "prefix":
                raise ValueError(f"legacy profile {self.name}: iv must be prefix, fixed:<hex> or none")
        return self

    @property
    def iv_overhead(self) -> int:
        return BLOCK if self.mode == "CBC" and self.iv == "prefix" else 0

    @property
    def hybrid(self) -> bool:
        return self.key_transport != "none"

    @property
    def prefix_overhead(self) -> int:
        """Bytes before the ciphertext body: RSA-wrapped content key (hybrid) plus IV."""
        return (self.rsa_key_bits // 8 if self.hybrid else 0) + self.iv_overhead


_RSA_CACHE: dict[bytes, Any] = {}


def _rsa_private(der: bytes):
    digest = hashlib.sha256(der).digest()
    if digest not in _RSA_CACHE:
        key = serialization.load_der_private_key(der, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("not an RSA private key")
        if len(_RSA_CACHE) > 8:
            _RSA_CACHE.clear()
        _RSA_CACHE[digest] = key
    return _RSA_CACHE[digest]


def rsa_key_bits(der: bytes) -> int:
    return _rsa_private(der).key_size


def _rsa_padding(transport: str):
    if transport == "rsa-pkcs1v15":
        return asym_padding.PKCS1v15()
    # OAEP-SHA1 exists only to READ legacy hybrid records; OAEP's security does not rest on SHA-1 collision resistance
    digest = hashes.SHA256() if transport == "rsa-oaep-sha256" else hashes.SHA1()  # noqa: S303
    return asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=digest), algorithm=digest, label=None)


def key_check_value(algorithm: str, key: bytes) -> str:
    """KCV for the key ceremony: TDEA convention for DES/3DES, SHA-256 of the public key (SPKI) for RSA."""
    if algorithm == "RSA":
        public = _rsa_private(key).public_key().public_bytes(serialization.Encoding.DER,
                                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        return "SPKI-SHA256:" + hashlib.sha256(public).hexdigest()[:16].upper()
    return kcv(key)


def check_key(algorithm: str, key: bytes) -> None:
    if algorithm == "RSA":
        _rsa_private(key)
        return
    if algorithm == "DES" and len(key) != 8:
        raise ValueError("DES keys are 8 bytes (64 bits incl. parity)")
    if algorithm == "3DES" and len(key) not in (16, 24):
        raise ValueError("TDEA keys are 16 bytes (2-key) or 24 bytes (3-key)")
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unsupported legacy algorithm {algorithm}")


def key_notes(algorithm: str, key: bytes) -> list[str]:
    """Strength findings recorded when a legacy key is imported (feeds the assessment)."""
    check_key(algorithm, key)
    notes: list[str] = []
    if algorithm == "RSA":
        bits = rsa_key_bits(key)
        notes.append(f"RSA-{bits} key-transport key for hybrid records (decrypt-only).")
        if bits < 2048:
            notes.append("RSA below 2048 bits: under 112-bit strength - disallowed (SP 800-131A).")
        elif bits < 3072:
            notes.append("RSA-2048: acceptable today; NIST's draft post-quantum transition (IR 8547) proposes "
                         "deprecation after 2030.")
        return notes
    parts = [key[i:i + 8] for i in range(0, len(key), 8)]
    if algorithm == "DES":
        notes.append("Single DES: 56-bit key, exhaustively searchable - treat data as weakly protected.")
    elif len(key) == 16:
        notes.append("2-key TDEA (keying option 2): <= 80-bit strength; encryption disallowed since 2015.")
    else:
        k1, k2, k3 = (_strip_parity(p) for p in parts)
        if k1 == k2 or k2 == k3:
            notes.append("Degenerate TDEA key bundle (K1==K2 or K2==K3): behaves as single DES.")
        elif k1 == k3:
            notes.append("K1==K3: effectively 2-key TDEA (<= 80-bit strength).")
        else:
            notes.append("3-key TDEA: 112-bit strength; encryption disallowed after 2023-12-31 (legacy decrypt only).")
    for index, part in enumerate(parts, 1):
        stripped = _strip_parity(part)
        if stripped in _WEAK_SET:
            notes.append(f"Key component {index} is a DES weak key.")
        elif stripped in _SEMI_WEAK_SET:
            notes.append(f"Key component {index} is a DES semi-weak key.")
    return notes


def decode(profile: LegacyProfile, data: bytes | str) -> bytes:
    if profile.encoding == "raw":
        if isinstance(data, str):
            raise DecryptionError("decryption failed")
        return bytes(data)
    text = data.decode("ascii", "strict") if isinstance(data, (bytes, bytearray)) else data
    try:
        if profile.encoding == "base64":
            return base64.b64decode(text.strip(), validate=True)
        return bytes.fromhex(text.strip())
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise DecryptionError("decryption failed") from exc


def _cipher(key: bytes, mode) -> Cipher:
    return Cipher(_tdea()(key), mode)  # an 8-byte key makes TDEA collapse to single DES (K1=K2=K3)


def decrypt(profile: LegacyProfile, key: bytes, data: bytes | str) -> bytes:
    """Decrypt one legacy value. Every failure raises the same generic DecryptionError."""
    try:
        raw = decode(profile, data)
        if profile.hybrid:  # RSA(content key) || IV || ciphertext
            private = _rsa_private(key)
            size = private.key_size // 8
            key, raw = private.decrypt(raw[:size], _rsa_padding(profile.key_transport)), raw[size:]
        check_key(profile.algorithm, key)
        if profile.mode == "CBC":
            if profile.iv == "prefix":
                iv, body = raw[:BLOCK], raw[BLOCK:]
            else:
                iv, body = bytes.fromhex(profile.iv[6:]), raw
            mode = modes.CBC(iv)
        else:
            body, mode = raw, modes.ECB()  # noqa: S305 - decrypting existing ECB data is the point of this path
        if not body or len(body) % BLOCK:
            raise DecryptionError("decryption failed")
        dec = _cipher(key, mode).decryptor()
        padded = dec.update(body) + dec.finalize()
        if profile.padding == "pkcs7":
            n = padded[-1]
            if not 1 <= n <= BLOCK or padded[-n:] != bytes([n]) * n:
                raise DecryptionError("decryption failed")
            return padded[:-n]
        if profile.padding == "zero":
            return padded.rstrip(b"\x00")
        return padded
    except DecryptionError:
        raise
    except Exception as exc:  # noqa: BLE001 - collapse every error into one generic failure
        raise DecryptionError("decryption failed") from exc


def kcv(key: bytes) -> str:
    """TDEA key check value: first 3 bytes of the ECB encryption of a zero block (HSM ceremony convention).

    This is a key-verification function, not a data-encryption path.
    """
    enc = _cipher(key, modes.ECB()).encryptor()  # noqa: S305 - single zero block, KCV convention
    return (enc.update(bytes(BLOCK)) + enc.finalize())[:3].hex().upper()
