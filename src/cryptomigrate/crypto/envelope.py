"""cryptomigrate ciphertext envelope, format v2 (AES-GCM, NIST SP 800-38D).

Binary layout (integers unsigned)::

    offset  size   field
    0       4      magic           0x89 'C' 'M' 'E'
    4       1      version         0x02
    5       1      algorithm id    0x01 = AES-128-GCM, 0x02 = AES-256-GCM
    6       1      key-id length   L (1..64)
    7       L      key id          ASCII [A-Za-z0-9._:-]
    7+L     12     nonce           random 96-bit IV (SP 800-38D sec. 8.2.2)
    19+L    n+16   ciphertext || 128-bit authentication tag

GCM additional authenticated data (AAD) = header (bytes 0 .. 7+L) || 0x00 || context.
Binding the header stops key-id / algorithm substitution; binding a caller-supplied
*context* (e.g. ``"customers.ssn#42"``) stops ciphertexts being swapped between rows.

Text armor for VARCHAR/TEXT columns: ``"$cm2$" + base64(envelope)``. ``$`` is outside
the base64 and hex alphabets, so armored values can never be confused with legacy
base64/hex ciphertext. See docs/ENVELOPE_SPEC.md for the language-neutral spec.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"\x89CME"
VERSION = 2
TEXT_PREFIX = "$cm2$"
ALG_IDS = {"AES-128-GCM": 1, "AES-256-GCM": 2}
ALG_NAMES = {v: k for k, v in ALG_IDS.items()}
KEY_LEN = {"AES-128-GCM": 16, "AES-256-GCM": 32}
NONCE_LEN = 12
TAG_LEN = 16
KEY_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")


class EnvelopeError(ValueError):
    """The bytes are not a well-formed v2 envelope."""


class DecryptionError(Exception):
    """Decryption failed. Deliberately generic: callers must not learn *why* (padding-oracle hygiene)."""


@dataclass(frozen=True)
class Envelope:
    algorithm: str
    key_id: str
    nonce: bytes
    ciphertext: bytes  # includes the 16-byte tag
    header: bytes


def build_header(algorithm: str, key_id: str) -> bytes:
    if algorithm not in ALG_IDS:
        raise ValueError(f"unsupported target algorithm {algorithm!r}; use one of {sorted(ALG_IDS)}")
    if not KEY_ID_RE.match(key_id):
        raise ValueError(f"invalid key id {key_id!r}")
    kid = key_id.encode("ascii")
    return MAGIC + bytes([VERSION, ALG_IDS[algorithm], len(kid)]) + kid


def _aad(header: bytes, context: bytes) -> bytes:
    return header + b"\x00" + context


def seal(key: bytes, key_id: str, plaintext: bytes, context: bytes = b"", algorithm: str = "AES-256-GCM") -> bytes:
    if len(key) != KEY_LEN.get(algorithm, -1):
        raise ValueError(f"{algorithm} requires a {KEY_LEN.get(algorithm)}-byte key, got {len(key)}")
    header = build_header(algorithm, key_id)
    nonce = os.urandom(NONCE_LEN)
    return header + nonce + AESGCM(key).encrypt(nonce, plaintext, _aad(header, context))


def parse(blob: bytes) -> Envelope:
    if len(blob) < 7 or blob[:4] != MAGIC:
        raise EnvelopeError("not a cryptomigrate v2 envelope")
    version, alg_id, kid_len = blob[4], blob[5], blob[6]
    if version != VERSION:
        raise EnvelopeError(f"unsupported envelope version {version}")
    if alg_id not in ALG_NAMES:
        raise EnvelopeError(f"unknown algorithm id {alg_id}")
    if not 1 <= kid_len <= 64:
        raise EnvelopeError("invalid key-id length")
    end = 7 + kid_len
    if len(blob) < end + NONCE_LEN + TAG_LEN:
        raise EnvelopeError("envelope truncated")
    try:
        key_id = blob[7:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise EnvelopeError("key id is not ASCII") from exc
    if not KEY_ID_RE.match(key_id):
        raise EnvelopeError("invalid key id")
    return Envelope(ALG_NAMES[alg_id], key_id, blob[end:end + NONCE_LEN], blob[end + NONCE_LEN:], blob[:end])


def open_envelope(key: bytes, env: Envelope, context: bytes = b"") -> bytes:
    if len(key) != KEY_LEN[env.algorithm]:
        raise DecryptionError("decryption failed")
    try:
        return AESGCM(key).decrypt(env.nonce, env.ciphertext, _aad(env.header, context))
    except InvalidTag as exc:
        raise DecryptionError("decryption failed") from exc


def is_envelope(blob: bytes) -> bool:
    try:
        parse(blob)
        return True
    except EnvelopeError:
        return False


def armor(blob: bytes) -> str:
    return TEXT_PREFIX + base64.b64encode(blob).decode("ascii")


def is_armored(text: str) -> bool:
    return isinstance(text, str) and text.startswith(TEXT_PREFIX)


def dearmor(text: str) -> bytes:
    if not is_armored(text):
        raise EnvelopeError("missing $cm2$ prefix")
    try:
        return base64.b64decode(text[len(TEXT_PREFIX):], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EnvelopeError("armored payload is not valid base64") from exc


def projected_length(plaintext_len: int, key_id_len: int, text: bool = True) -> int:
    """Stored size of a v2 value - used to warn about column-width overflow before migrating."""
    raw = 7 + key_id_len + NONCE_LEN + plaintext_len + TAG_LEN
    return len(TEXT_PREFIX) + 4 * ((raw + 2) // 3) if text else raw


def aes_kcv(key: bytes) -> str:
    """Key check value: first 3 bytes of AES-CMAC over a zero block (confirms a key without exposing it)."""
    mac = cmac.CMAC(algorithms.AES(key))
    mac.update(bytes(16))
    return mac.finalize()[:3].hex().upper()
