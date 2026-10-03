import base64
import json
import os

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptomigrate.audit import AuditLog
from cryptomigrate.crypto import envelope, legacy
from cryptomigrate.crypto.selftest import run_selftest
from cryptomigrate.crypto.service import CryptoService
from cryptomigrate.keys.keystore import Keystore, KeystoreError

from .conftest import LEGACY_KEY, legacy_encrypt


def test_selftest_all_known_answers_pass():
    assert all(r["passed"] for r in run_selftest())


class TestEnvelope:
    def test_round_trip_and_layout(self):
        key = os.urandom(32)
        blob = envelope.seal(key, "k1", b"hello", b"ctx")
        env = envelope.parse(blob)
        assert blob[:4] == envelope.MAGIC and blob[4] == 2 and env.algorithm == "AES-256-GCM"
        assert env.key_id == "k1" and len(env.nonce) == 12
        assert envelope.open_envelope(key, env, b"ctx") == b"hello"

    def test_context_and_header_are_authenticated(self):
        key = os.urandom(32)
        blob = envelope.seal(key, "k1", b"hello", b"row#1")
        with pytest.raises(envelope.DecryptionError):
            envelope.open_envelope(key, envelope.parse(blob), b"row#2")
        swapped = bytearray(blob)
        swapped[5] = 1  # claim AES-128 - header is in the AAD
        with pytest.raises((envelope.DecryptionError, envelope.EnvelopeError)):
            envelope.open_envelope(key, envelope.parse(bytes(swapped)), b"row#1")

    @pytest.mark.parametrize("bad", [b"", b"\x89CME", b"\x89CME\x03\x02\x02k1" + bytes(40),
                                     b"\x89CME\x02\x09\x02k1" + bytes(40), b"\x89CME\x02\x02\x00" + bytes(40),
                                     b"\x89CME\x02\x02\x02k1" + bytes(10)])
    def test_malformed_envelopes_rejected(self, bad):
        assert not envelope.is_envelope(bad)

    def test_armor_and_projected_length(self):
        key = os.urandom(32)
        for n in (0, 1, 9, 16, 100):
            text = envelope.armor(envelope.seal(key, "aes256-20261002-a1b2c3", os.urandom(n)))
            assert text.startswith("$cm2$") and len(text) == envelope.projected_length(n, 22)
            assert envelope.is_envelope(envelope.dearmor(text))
        with pytest.raises(envelope.EnvelopeError):
            envelope.dearmor("$cm2$***")


class TestLegacy:
    def test_cbc_prefix_base64(self):
        profile = legacy.LegacyProfile("p").validate()
        assert legacy.decrypt(profile, LEGACY_KEY, legacy_encrypt(b"secret")) == b"secret"

    def test_ecb_hex_and_single_des(self):
        profile = legacy.LegacyProfile("p", "3DES", "ECB", "k", "none", "pkcs7", "hex").validate()
        assert legacy.decrypt(profile, LEGACY_KEY, legacy_encrypt(b"abc", mode="ECB", encoding="hex")) == b"abc"
        des_key = bytes.fromhex("133457799BBCDFF1")
        des = legacy.LegacyProfile("d", "DES", "ECB", "k", "none", "none", "raw").validate()
        assert legacy.decrypt(des, des_key, bytes.fromhex("85E813540F0AB405")) == bytes.fromhex("0123456789ABCDEF")

    def test_fixed_iv_and_zero_padding(self):
        iv = bytes.fromhex("0102030405060708")
        enc = Cipher(TripleDES(LEGACY_KEY), modes.CBC(iv)).encryptor()
        ct = enc.update(b"ZEROPAD\x00") + enc.finalize()
        profile = legacy.LegacyProfile("p", "3DES", "CBC", "k", "fixed:0102030405060708", "zero", "raw").validate()
        assert legacy.decrypt(profile, LEGACY_KEY, ct) == b"ZEROPAD"

    @pytest.mark.parametrize("data", ["not base64!!", base64.b64encode(b"short").decode(),
                                      base64.b64encode(os.urandom(24)).decode()])
    def test_failures_are_generic(self, data):
        with pytest.raises(envelope.DecryptionError, match="^decryption failed$"):
            legacy.decrypt(legacy.LegacyProfile("p").validate(), LEGACY_KEY, data)

    def test_profile_validation(self):
        with pytest.raises(ValueError):
            legacy.LegacyProfile("p", mode="ECB", iv="prefix").validate()
        with pytest.raises(ValueError):
            legacy.LegacyProfile("p", iv="fixed:01").validate()

    def test_key_notes_flag_weak_material(self):
        assert any("single DES" in n for n in legacy.key_notes("3DES", bytes.fromhex("0123456789ABCDEF") * 3))
        assert any("2-key" in n for n in legacy.key_notes("3DES", LEGACY_KEY[:16]))
        assert any("weak key" in n for n in legacy.key_notes("DES", bytes.fromhex("0101010101010101")))

    def test_module_exposes_no_encrypt_function(self):
        assert not [n for n in dir(legacy) if "encrypt" in n.lower()]


class TestService:
    def test_dual_mode_classification(self, project):
        cfg, store = project
        svc = CryptoService(store, legacy_profiles=cfg.legacy_profiles)
        assert svc.classify(legacy_encrypt(b"x"), b"", "tdes-b64").kind == "legacy"
        token = svc.encrypt_text(b"x", "c")
        assert svc.classify(token, "c").kind == "v2"
        assert svc.classify(token, "other").kind == "invalid"
        assert svc.classify(None).kind == "empty" and svc.classify("").kind == "empty"
        assert svc.decrypt(legacy_encrypt(b"y"), legacy_profile="tdes-b64") == b"y"

    def test_strict_mode_rejects_legacy(self, project):
        cfg, store = project
        svc = CryptoService(store, legacy_profiles=cfg.legacy_profiles, mode="strict")
        result = svc.classify(legacy_encrypt(b"x"), b"", "tdes-b64")
        assert result.kind == "invalid" and "strict" in result.error
        with pytest.raises(envelope.DecryptionError):
            svc.decrypt(legacy_encrypt(b"x"), legacy_profile="tdes-b64")

    def test_magic_collision_falls_back_to_legacy(self, project):
        """Raw legacy ciphertext that happens to parse as an envelope (p ~ 2^-40) is still migrated correctly."""
        cfg, store = project
        crafted = envelope.MAGIC + bytes([2, 2, 4]) + b"abcd" + os.urandom(37)  # 48 bytes = 6 TDEA blocks
        dec = Cipher(TripleDES(LEGACY_KEY), modes.ECB()).decryptor()
        plaintext = dec.update(crafted) + dec.finalize()  # the plaintext whose ECB encryption is `crafted`
        profiles = {"ecb": legacy.LegacyProfile("ecb", "3DES", "ECB", "legacy-3des", "none", "none", "raw")}
        svc = CryptoService(store, legacy_profiles=profiles)
        assert envelope.is_envelope(crafted)
        result = svc.classify(crafted, b"", "ecb")
        assert result.kind == "legacy" and result.plaintext == plaintext


class TestKeystore:
    def test_lifecycle_and_audit(self, project):
        cfg, store = project
        first = store.active_key_id()
        second = store.generate(256, reason="test rotation")
        assert store.active_key_id() == second and store.meta(first)["state"] == "decrypt-only"
        with pytest.raises(KeystoreError, match="rotate first"):
            store.destroy(second, "nope")
        store.destroy("legacy-3des", "verified")
        with pytest.raises(KeystoreError, match="destroyed"):
            store.get("legacy-3des")
        raw = json.loads(cfg.keystore_path.read_text())
        assert raw["keys"]["legacy-3des"]["wrapped"] is None
        assert LEGACY_KEY.hex() not in cfg.keystore_path.read_text().lower()
        events = [e["event"] for e in AuditLog(cfg.audit_path).entries()]
        assert events[:4] == ["keystore.create", "key.generate", "key.import_legacy", "key.rotate"]
        assert events[-1] == "key.destroy"
        assert (cfg.keystore_path.stat().st_mode & 0o777) == 0o600

    def test_wrong_kek_rejected(self, project, monkeypatch):
        cfg, _ = project
        monkeypatch.setenv("CRYPTOMIGRATE_KEK", base64.b64encode(os.urandom(32)).decode())
        with pytest.raises(KeystoreError, match="does not match"):
            Keystore.from_config(cfg)

    def test_passphrase_kek(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CRYPTOMIGRATE_KEK", raising=False)
        monkeypatch.setenv("CRYPTOMIGRATE_KEK_PASSPHRASE", "correct horse battery staple")
        store = Keystore.create(tmp_path / "ks.json")
        key_id = store.generate(128)
        reopened = Keystore.open(tmp_path / "ks.json")
        assert reopened.get(key_id) == store.get(key_id)
        assert json.loads((tmp_path / "ks.json").read_text())["kek"]["kdf"]["name"] == "PBKDF2-HMAC-SHA256"

    def test_missing_kek_is_a_clear_error(self, tmp_path, monkeypatch):
        monkeypatch.delenv("CRYPTOMIGRATE_KEK", raising=False)
        monkeypatch.delenv("CRYPTOMIGRATE_KEK_PASSPHRASE", raising=False)
        with pytest.raises(KeystoreError, match="No key-encryption key"):
            Keystore.create(tmp_path / "ks.json")


class TestAudit:
    def test_chain_detects_edit_delete_and_reorder(self, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        for i in range(4):
            log.append("event", n=i)
        assert log.verify() == (True, 4, None)
        lines = (tmp_path / "audit.log").read_text().splitlines()

        def check(mutated):
            (tmp_path / "audit.log").write_text("\n".join(mutated) + "\n")
            return log.verify()

        edited = json.loads(lines[1])
        edited["details"]["n"] = 99
        assert not check([lines[0], json.dumps(edited), *lines[2:]])[0]
        assert not check([lines[0], *lines[2:]])[0]
        assert not check([lines[1], lines[0], *lines[2:]])[0]
        assert check(lines)[0]


def test_documented_interoperability_vector():
    """The vector published in docs/ENVELOPE_SPEC.md - other-language implementations must reproduce it."""
    blob = bytes.fromhex("89434d450202166165733235362d32303236313030322d613162326333cafebabefacedbaddecaf888"
                         "bb91930b9e4f622d7133642dc86064e41e2cc2cf6a199cf23d4b10")
    env = envelope.parse(blob)
    assert (env.algorithm, env.key_id) == ("AES-256-GCM", "aes256-20261002-a1b2c3")
    assert envelope.open_envelope(bytes(range(32)), env, b"customers.ssn_enc#42") == b"123-45-6789"
    assert envelope.armor(blob) == ("$cm2$iUNNRQICFmFlczI1Ni0yMDI2MTAwMi1hMWIyYzPK/rq++s7brd7K+Ii7kZMLnk9iLXEzZC3IYGTk"
                                    "HizCz2oZnPI9SxA=")
