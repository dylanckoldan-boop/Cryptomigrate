"""Local key store: data keys wrapped under a key-encryption key (KEK) that never touches disk.

Two wrapping modes (``keystore.wrap`` in migration.yaml):

* ``aes-kwp`` (default) - AES Key Wrap with Padding (RFC 5649 / NIST SP 800-38F) under a 256-bit KEK taken from
  ``CRYPTOMIGRATE_KEK`` or derived from ``CRYPTOMIGRATE_KEK_PASSPHRASE`` (PBKDF2-HMAC-SHA256, SP 800-132).
* ``rsa-aes-kwp`` - *RSA on AES keys*: every stored key is wrapped with a one-time AES-256 key (AES-KWP) and that
  AES key is wrapped with RSA-OAEP-SHA256 under the KEK's public key - the PKCS#11 CKM_RSA_AES_KEY_WRAP
  construction. Wrapping needs only the public key; unwrapping needs the private key (an HSM or a protected file).

Lifecycle (NIST SP 800-57 Part 1): generation (CSPRNG), activation, rotation (previous key -> decrypt-only),
legacy import (decrypt-only, strength notes), destruction (wrapped material removed), all audit-logged.

Limitation: deleting bytes from a file cannot guarantee physical erasure on journaling file systems or SSDs.
Destruction is meaningful because the KEK never touches disk; for certified destruction use an HSM.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap_with_padding, aes_key_wrap_with_padding

from ..audit import AuditLog
from ..crypto import legacy
from ..crypto.envelope import aes_kcv
from ..util import ensure_private_dir, isotime, utcnow

FORMAT = "cryptomigrate-keystore/1"
PBKDF2_ITERATIONS = 600_000  # OWASP Password Storage Cheat Sheet recommendation for PBKDF2-HMAC-SHA256
KEK_CHECK_LABEL = b"cryptomigrate/kek-check/v1"
GCM_RANDOM_IV_LIMIT = 2**32  # SP 800-38D sec. 8.3: max invocations per key with random 96-bit IVs
WRAP_MODES = ("aes-kwp", "rsa-aes-kwp")
RSA_PRIVATE_ENV = "CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE"
RSA_PASSPHRASE_ENV = "CRYPTOMIGRATE_KEK_RSA_PASSPHRASE"  # noqa: S105 - environment variable *name*
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class KeystoreError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def resolve_kek(kek_env: str, passphrase_env: str, kdf: dict[str, Any] | None = None) -> tuple[bytes, dict[str, Any]]:
    raw = os.environ.get(kek_env)
    if raw:
        try:
            kek = base64.b64decode(raw.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise KeystoreError(f"{kek_env} is not valid base64") from exc
        if len(kek) != 32:
            raise KeystoreError(f"{kek_env} must decode to 32 bytes (got {len(kek)})")
        return kek, {"type": "env", "variable": kek_env}
    secret = os.environ.get(passphrase_env)
    if secret:
        salt = base64.b64decode(kdf["salt"]) if kdf else os.urandom(16)
        iterations = int(kdf.get("iterations", PBKDF2_ITERATIONS)) if kdf else PBKDF2_ITERATIONS
        kek = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(
            secret.encode("utf-8"))
        return kek, {"type": "passphrase", "variable": passphrase_env,
                     "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": iterations, "salt": _b64(salt)}}
    raise KeystoreError(
        f"No key-encryption key available. Export {kek_env} (base64 32-byte key - create one with "
        f"`cryptomigrate keys new-kek` and keep it in your secrets manager) or {passphrase_env}.")


def spki_fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def load_rsa_private_key(path_env: str, passphrase_env: str):
    """RSA private KEK from the PEM file named by ``path_env`` (optionally passphrase-protected); None if unset."""
    path = os.environ.get(path_env)
    if not path:
        return None
    secret = os.environ.get(passphrase_env)
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=secret.encode() if secret else None)
    except (OSError, ValueError, TypeError) as exc:
        raise KeystoreError(f"cannot load the RSA private key named by {path_env}: {exc}") from exc
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise KeystoreError(f"{path_env} must name an RSA private key of at least 2048 bits (3072+ recommended)")
    return key


def _pairwise_consistency(public_key, private_key) -> None:
    """FIPS 140-3 style pairwise consistency test of the RSA key pair before it protects anything."""
    probe = os.urandom(32)
    if private_key.decrypt(public_key.encrypt(probe, _OAEP), _OAEP) != probe:
        raise KeystoreError("RSA key pair failed the pairwise consistency test")


class AesKwpWrapper:
    kind = "aes-kwp"

    def __init__(self, kek: bytes):
        self.kek = kek

    def wrap(self, material: bytes) -> bytes:
        return aes_key_wrap_with_padding(self.kek, material)

    def unwrap(self, blob: bytes) -> bytes:
        return aes_key_unwrap_with_padding(self.kek, blob)


class RsaAesKwpWrapper:
    """RSA-OAEP-SHA256 wraps a one-time AES-256 key, which AES-KWP-wraps the material (CKM_RSA_AES_KEY_WRAP)."""

    kind = "rsa-aes-kwp"

    def __init__(self, public_key, private_key=None, private_env: str = RSA_PRIVATE_ENV):
        self.public_key, self.private_key, self.private_env = public_key, private_key, private_env

    def wrap(self, material: bytes) -> bytes:
        ephemeral = os.urandom(32)
        return self.public_key.encrypt(ephemeral, _OAEP) + aes_key_wrap_with_padding(ephemeral, material)

    def unwrap(self, blob: bytes) -> bytes:
        if self.private_key is None:
            raise KeystoreError(f"the RSA private key is not available - set {self.private_env} "
                                "(wrapping needs only the public key; unwrapping needs the private key)")
        size = self.private_key.key_size // 8
        return aes_key_unwrap_with_padding(self.private_key.decrypt(blob[:size], _OAEP), blob[size:])


class Keystore:
    def __init__(self, path: Path, data: dict[str, Any], wrapper, audit: AuditLog | None = None):
        self.path = Path(path)
        self.data = data
        self._wrapper = wrapper
        self.audit = audit
        self._cache: dict[str, bytes] = {}

    # ------------------------------------------------------------------ factory
    @staticmethod
    def kek_check(kek: bytes) -> str:
        return hmac.new(kek, KEK_CHECK_LABEL, hashlib.sha256).hexdigest()[:32]

    @classmethod
    def create(cls, path: Path, kek_env: str = "CRYPTOMIGRATE_KEK",
               passphrase_env: str = "CRYPTOMIGRATE_KEK_PASSPHRASE",  # noqa: S107 - variable *name*, not a secret
               audit: AuditLog | None = None, wrap: str = "aes-kwp", rsa_public_key: str | None = None,
               rsa_private_env: str = RSA_PRIVATE_ENV, rsa_passphrase_env: str = RSA_PASSPHRASE_ENV) -> Keystore:
        path = Path(path)
        if path.exists():
            raise KeystoreError(f"keystore already exists: {path}")
        if wrap not in WRAP_MODES:
            raise KeystoreError(f"keystore.wrap must be one of {WRAP_MODES}")
        if wrap == "rsa-aes-kwp":
            private = load_rsa_private_key(rsa_private_env, rsa_passphrase_env)
            if rsa_public_key:
                try:
                    public = serialization.load_pem_public_key(Path(rsa_public_key).read_bytes())
                except (OSError, ValueError) as exc:
                    raise KeystoreError(f"cannot load keystore.rsa_public_key: {exc}") from exc
            elif private is not None:
                public = private.public_key()
            else:
                raise KeystoreError(f"wrap: rsa-aes-kwp needs keystore.rsa_public_key or {rsa_private_env}")
            if not isinstance(public, rsa.RSAPublicKey) or public.key_size < 2048:
                raise KeystoreError("the RSA key-encryption key must be RSA with at least 2048 bits "
                                    "(3072+ recommended)")
            if private is not None:
                if spki_fingerprint(private.public_key()) != spki_fingerprint(public):
                    raise KeystoreError("the RSA private key does not match keystore.rsa_public_key")
                _pairwise_consistency(public, private)
            descriptor = {"wrap": "rsa-aes-kwp", "type": "rsa-oaep-sha256", "key_bits": public.key_size,
                          "fingerprint": spki_fingerprint(public),
                          "public_key_pem": public.public_bytes(serialization.Encoding.PEM,
                                                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()}
            wrapper = RsaAesKwpWrapper(public, private, rsa_private_env)
        else:
            kek, source = resolve_kek(kek_env, passphrase_env)
            descriptor = {"wrap": "aes-kwp", **source, "check": cls.kek_check(kek)}
            wrapper = AesKwpWrapper(kek)
        data = {"format": FORMAT, "created": isotime(), "kek": descriptor, "keys": {}}
        store = cls(path, data, wrapper, audit)
        store._save()
        store._audit("keystore.create", path=str(path), wrap=descriptor["wrap"], kek_source=descriptor["type"],
                     fingerprint=descriptor.get("fingerprint"))
        return store

    @classmethod
    def open(cls, path: Path, kek_env: str = "CRYPTOMIGRATE_KEK",
             passphrase_env: str = "CRYPTOMIGRATE_KEK_PASSPHRASE",  # noqa: S107 - variable *name*, not a secret
             audit: AuditLog | None = None, rsa_private_env: str = RSA_PRIVATE_ENV,
             rsa_passphrase_env: str = RSA_PASSPHRASE_ENV) -> Keystore:
        path = Path(path)
        if not path.exists():
            raise KeystoreError(f"keystore not found: {path} (run `cryptomigrate keys init`)")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != FORMAT:
            raise KeystoreError(f"unsupported keystore format {data.get('format')!r}")
        kek = data["kek"]
        if kek.get("wrap") == "rsa-aes-kwp":
            public = serialization.load_pem_public_key(kek["public_key_pem"].encode())
            private = load_rsa_private_key(rsa_private_env, rsa_passphrase_env)
            if private is not None:
                if spki_fingerprint(private.public_key()) != kek["fingerprint"]:
                    raise KeystoreError("the RSA private key does not match this keystore")
                _pairwise_consistency(public, private)
            return cls(path, data, RsaAesKwpWrapper(public, private, rsa_private_env), audit)
        secret, _ = resolve_kek(kek_env, passphrase_env, kek.get("kdf"))
        if not hmac.compare_digest(cls.kek_check(secret), kek["check"]):
            raise KeystoreError("the supplied KEK does not match this keystore")
        return cls(path, data, AesKwpWrapper(secret), audit)

    @classmethod
    def from_config(cls, cfg, create: bool = False) -> Keystore:
        audit = AuditLog(cfg.audit_path)
        options = cfg.keystore_wrap
        envs = {"rsa_private_env": options.get("rsa_private_key_env") or RSA_PRIVATE_ENV,
                "rsa_passphrase_env": options.get("rsa_passphrase_env") or RSA_PASSPHRASE_ENV}
        if create:
            return cls.create(cfg.keystore_path, cfg.kek_env, cfg.kek_passphrase_env, audit,
                              wrap=options.get("wrap", "aes-kwp"), rsa_public_key=options.get("rsa_public_key"), **envs)
        return cls.open(cfg.keystore_path, cfg.kek_env, cfg.kek_passphrase_env, audit, **envs)

    # ------------------------------------------------------------------ helpers
    @property
    def wrap_mode(self) -> str:
        return self.data["kek"].get("wrap", "aes-kwp")

    def _save(self) -> None:
        ensure_private_dir(self.path.parent)
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - e.g. Windows ACL semantics
            pass

    def _audit(self, event: str, **details: Any) -> None:
        if self.audit:
            self.audit.append(event, **details)

    def _keys(self) -> dict[str, dict[str, Any]]:
        return self.data["keys"]

    # ------------------------------------------------------------------ queries
    def list(self) -> list[dict[str, Any]]:
        return [{"id": kid, **{k: v for k, v in meta.items() if k != "wrapped"}} for kid, meta in self._keys().items()]

    def meta(self, key_id: str) -> dict[str, Any]:
        if key_id not in self._keys():
            raise KeystoreError(f"unknown key id {key_id!r}")
        return self._keys()[key_id]

    def active_key_id(self) -> str:
        active = [kid for kid, m in self._keys().items() if m["state"] == "active" and not m.get("legacy")]
        if not active:
            raise KeystoreError("no active AES key - run `cryptomigrate keys init` or `cryptomigrate keys rotate`")
        return active[-1]

    def has_material(self, key_id: str) -> bool:
        return key_id in self._keys() and self._keys()[key_id].get("wrapped") is not None

    def legacy_keys(self, with_material_only: bool = True) -> list[str]:
        return [kid for kid, m in self._keys().items()
                if m.get("legacy") and (m.get("wrapped") is not None or not with_material_only)]

    def get(self, key_id: str) -> bytes:
        if key_id in self._cache:
            return self._cache[key_id]
        meta = self.meta(key_id)
        if meta["state"] == "destroyed" or meta.get("wrapped") is None:
            raise KeystoreError(f"key {key_id} was destroyed on {meta.get('destroyed')}")
        try:
            key = self._wrapper.unwrap(base64.b64decode(meta["wrapped"]))
        except (InvalidUnwrap, ValueError) as exc:
            raise KeystoreError(f"key {key_id} failed its integrity check on unwrap") from exc
        self._cache[key_id] = key
        return key

    # ---------------------------------------------------------------- lifecycle
    def _store(self, key_id: str, key: bytes, meta: dict[str, Any]) -> None:
        if key_id in self._keys():
            raise KeystoreError(f"key id {key_id!r} already exists")
        self._keys()[key_id] = {**meta, "wrapped": _b64(self._wrapper.wrap(key))}
        self._cache[key_id] = key

    def generate(self, bits: int = 256, reason: str = "initial") -> str:
        if bits not in (128, 256):
            raise KeystoreError("AES key size must be 128 or 256 bits")
        key = os.urandom(bits // 8)
        key_id = f"aes{bits}-{utcnow().strftime('%Y%m%d')}-{os.urandom(3).hex()}"
        previous = None
        try:
            previous = self.active_key_id()
        except KeystoreError:
            pass
        now = isotime()
        if previous:
            self._keys()[previous]["state"] = "decrypt-only"
            self._keys()[previous]["deactivated"] = now
        self._store(key_id, key, {
            "algorithm": f"AES-{bits}", "legacy": False, "state": "active", "created": now, "activated": now,
            "deactivated": None, "destroyed": None, "kcv": aes_kcv(key), "usage": {"encryptions": 0}, "notes": [],
        })
        self._save()
        self._audit("key.rotate" if previous else "key.generate", key_id=key_id, algorithm=f"AES-{bits}",
                    kcv=aes_kcv(key), previous=previous, reason=reason, wrap=self.wrap_mode)
        return key_id

    def import_legacy(self, key_id: str, algorithm: str, key: bytes) -> list[str]:
        algorithm = algorithm.upper()
        if algorithm not in legacy.KEY_ALGORITHMS:
            raise KeystoreError(f"legacy key algorithm must be one of {legacy.KEY_ALGORITHMS}")
        notes = legacy.key_notes(algorithm, key)
        label = f"RSA-{legacy.rsa_key_bits(key)}" if algorithm == "RSA" else algorithm
        now = isotime()
        check = legacy.key_check_value(algorithm, key)
        self._store(key_id, key, {
            "algorithm": label, "legacy": True, "state": "decrypt-only", "created": now, "activated": None,
            "deactivated": now, "destroyed": None, "kcv": check, "usage": {"encryptions": 0}, "notes": notes,
            "key_bytes": len(key),
        })
        self._save()
        self._audit("key.import_legacy", key_id=key_id, algorithm=label, kcv=check, notes=notes)
        return notes

    def destroy(self, key_id: str, reason: str) -> None:
        meta = self.meta(key_id)
        if meta["state"] == "active":
            raise KeystoreError("refusing to destroy the active key - rotate first")
        if meta["state"] == "destroyed":
            raise KeystoreError(f"key {key_id} is already destroyed")
        meta.update({"state": "destroyed", "wrapped": None, "destroyed": isotime(), "destroy_reason": reason})
        self._cache.pop(key_id, None)
        self._save()
        self._audit("key.destroy", key_id=key_id, algorithm=meta["algorithm"], kcv=meta.get("kcv"), reason=reason)

    def record_usage(self, key_id: str, encryptions: int) -> None:
        if encryptions <= 0 or key_id not in self._keys():
            return
        usage = self._keys()[key_id].setdefault("usage", {"encryptions": 0})
        usage["encryptions"] = int(usage.get("encryptions", 0)) + int(encryptions)
        usage["updated"] = isotime()
        self._save()

    def usage_warnings(self) -> list[str]:
        warnings_out = []
        for kid, meta in self._keys().items():
            used = int(meta.get("usage", {}).get("encryptions", 0))
            if not meta.get("legacy") and used >= GCM_RANDOM_IV_LIMIT // 2:
                warnings_out.append(f"{kid}: {used} encryptions - over 50% of the SP 800-38D random-IV limit; rotate.")
        return warnings_out

    def age_days(self, key_id: str) -> int:
        created = self.meta(key_id).get("created")
        return (utcnow() - datetime.fromisoformat(created.replace("Z", "+00:00"))).days if created else 0
