"""CryptoService - the drop-in API applications use during and after the transition.

* ``encrypt`` / ``encrypt_text`` always produce an AES-GCM v2 envelope with the active key.
  There is no code path that produces DES/3DES ciphertext (FR-01, no-fallback).
* ``decrypt`` accepts v2 envelopes and - only while ``mode: dual`` - legacy ciphertext
  described by a legacy profile (FR-03 dual-algorithm transition mode).
* ``mode: strict`` (set at close-out) rejects legacy ciphertext outright.

Security note for dual mode: legacy CBC ciphertext is unauthenticated, so an online
decrypt endpoint can act as a padding oracle. All legacy failures raise one generic
error, but timing is not constant - keep the dual-mode window short and re-encrypt
data at rest with ``cryptomigrate reencrypt`` rather than lazily on read.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import legacy
from .envelope import (
    DecryptionError,
    EnvelopeError,
    armor,
    dearmor,
    is_armored,
    is_envelope,
    open_envelope,
    parse,
    seal,
)


@dataclass
class Classification:
    kind: str  # "v2" | "legacy" | "invalid" | "empty"
    plaintext: bytes | None = None
    key_id: str | None = None
    error: str | None = None


def _ctx(context: str | bytes | None) -> bytes:
    if context is None:
        return b""
    return context.encode("utf-8") if isinstance(context, str) else bytes(context)


class CryptoService:
    def __init__(self, keystore, algorithm: str = "AES-256-GCM",
                 legacy_profiles: dict[str, legacy.LegacyProfile] | None = None, mode: str = "dual"):
        if mode not in ("dual", "strict"):
            raise ValueError("mode must be 'dual' or 'strict'")
        self.keystore = keystore
        self.algorithm = algorithm
        self.mode = mode
        self.legacy_profiles = dict(legacy_profiles or {})
        self.encryptions = 0

    @classmethod
    def from_config(cls, config=None) -> CryptoService:
        from ..config import Config, load_config
        from ..keys.keystore import Keystore

        cfg = config if isinstance(config, Config) else load_config(config, require=True)
        return cls(Keystore.from_config(cfg), cfg.target_algorithm, cfg.legacy_profiles, cfg.migration_mode)

    # ----------------------------------------------------------- encryption (AES only)
    def encrypt(self, plaintext: bytes, context: str | bytes | None = b"") -> bytes:
        key_id = self.keystore.active_key_id()
        blob = seal(self.keystore.get(key_id), key_id, bytes(plaintext), _ctx(context), self.algorithm)
        self.encryptions += 1
        return blob

    def encrypt_text(self, plaintext: bytes, context: str | bytes | None = b"") -> str:
        return armor(self.encrypt(plaintext, context))

    # ----------------------------------------------------------------- decryption
    def decrypt(self, data: bytes | str, context: str | bytes | None = b"", legacy_profile: str | None = None) -> bytes:
        result = self.classify(data, context, legacy_profile)
        if result.kind in ("v2", "legacy"):
            return result.plaintext  # type: ignore[return-value]
        raise DecryptionError(result.error or "decryption failed")

    def classify(self, data: bytes | str | None, context: str | bytes | None = b"",
                 legacy_profile: str | None = None) -> Classification:
        """Decide what a stored value is and decrypt it: the core of re-encryption and verification."""
        ctx = _ctx(context)
        if data is None or data == "" or data == b"":
            return Classification("empty")
        if isinstance(data, memoryview):
            data = data.tobytes()
        if isinstance(data, str):
            if is_armored(data):
                try:
                    return self._open_v2(parse(dearmor(data)), ctx)
                except EnvelopeError as exc:
                    return Classification("invalid", error=f"malformed v2 value: {exc}")
            return self._legacy(data, legacy_profile)
        if is_envelope(data):
            result = self._open_v2(parse(data), ctx)
            if result.kind == "v2" or legacy_profile is None or self.mode == "strict":
                return result
            # Raw-binary legacy ciphertext starting with the 5-byte magic (p ~ 2^-40): try legacy too.
            alternative = self._legacy(data, legacy_profile)
            return alternative if alternative.kind == "legacy" else result
        return self._legacy(data, legacy_profile)

    def _open_v2(self, env, ctx: bytes) -> Classification:
        try:
            key = self.keystore.get(env.key_id)
        except Exception as exc:  # noqa: BLE001 - KeystoreError or unknown key
            return Classification("invalid", key_id=env.key_id, error=f"key unavailable: {exc}")
        try:
            return Classification("v2", open_envelope(key, env, ctx), env.key_id)
        except DecryptionError:
            return Classification("invalid", key_id=env.key_id,
                                  error="AES-GCM authentication failed (wrong key or context, or tampered data)")

    def _legacy(self, data: bytes | str, profile_name: str | None) -> Classification:
        if self.mode == "strict":
            return Classification("invalid", error="legacy ciphertext rejected: service is in strict (AES-only) mode")
        if not profile_name:
            return Classification("invalid", error="not a v2 envelope and no legacy profile configured")
        profile = self.legacy_profiles.get(profile_name)
        if profile is None:
            return Classification("invalid", error=f"unknown legacy profile {profile_name!r}")
        try:
            key = self.keystore.get(profile.key_id)
        except Exception as exc:  # noqa: BLE001
            return Classification("invalid", key_id=profile.key_id, error=f"legacy key unavailable: {exc}")
        try:
            return Classification("legacy", legacy.decrypt(profile, key, data), profile.key_id)
        except DecryptionError:
            return Classification("invalid", key_id=profile.key_id, error="legacy decryption failed")
