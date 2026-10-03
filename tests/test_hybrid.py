"""Hybrid RSA + symmetric systems: legacy RSA-wrapped 3DES records, and RSA protecting the AES data keys."""

import base64
import json
import os
import sqlite3

import pytest
import yaml
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from cryptomigrate.config import load_config
from cryptomigrate.crypto import legacy
from cryptomigrate.crypto.service import CryptoService
from cryptomigrate.discovery.policy import load_policy_set
from cryptomigrate.discovery.scanner import Scanner
from cryptomigrate.keys.keystore import Keystore, KeystoreError
from cryptomigrate.migration.engine import MigrationEngine

from .conftest import build_legacy_project

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
DER = RSA_KEY.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
TRANSPORTS = {
    "rsa-pkcs1v15": padding.PKCS1v15(),
    "rsa-oaep-sha1": padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    "rsa-oaep-sha256": padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
}


def hybrid_record(plaintext: bytes, transport: str = "rsa-pkcs1v15") -> bytes:
    content_key, iv = os.urandom(24), os.urandom(8)
    padder = sym_padding.PKCS7(64).padder()
    enc = Cipher(TripleDES(content_key), modes.CBC(iv)).encryptor()
    body = enc.update(padder.update(plaintext) + padder.finalize()) + enc.finalize()
    return RSA_KEY.public_key().encrypt(content_key, TRANSPORTS[transport]) + iv + body


@pytest.mark.parametrize("transport", list(TRANSPORTS))
def test_hybrid_profile_decrypts_each_key_transport(transport):
    profile = legacy.LegacyProfile("h", "3DES", "CBC", "legacy-rsa", "prefix", "pkcs7", "raw", transport).validate()
    assert profile.hybrid and profile.prefix_overhead == 256 + 8
    assert legacy.decrypt(profile, DER, hybrid_record(b"wire transfer #42", transport)) == b"wire transfer #42"


def test_hybrid_wrong_transport_fails_generically():
    profile = legacy.LegacyProfile("h", "3DES", "CBC", "k", "prefix", "pkcs7", "raw", "rsa-oaep-sha256").validate()
    with pytest.raises(legacy.DecryptionError, match="^decryption failed$"):
        legacy.decrypt(profile, DER, hybrid_record(b"x", "rsa-pkcs1v15"))


def test_rsa_legacy_key_import(tmp_path, kek):
    store = Keystore.create(tmp_path / "ks.json")
    notes = store.import_legacy("legacy-rsa", "RSA", DER)
    meta = store.meta("legacy-rsa")
    assert meta["algorithm"] == "RSA-2048" and meta["kcv"].startswith("SPKI-SHA256:")
    assert any("IR 8547" in n for n in notes) and store.get("legacy-rsa") == DER


def test_hybrid_end_to_end_migration(tmp_path, kek):
    path = build_legacy_project(tmp_path / "p")
    db = sqlite3.connect(tmp_path / "p" / "legacy.db")
    db.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, body BLOB)")
    bodies = {i: f"message {i} ".encode() * i for i in range(1, 8)}
    for i, body in bodies.items():
        db.execute("INSERT INTO messages VALUES (?, ?)", (i, hybrid_record(body)))
    db.commit()
    db.close()
    data = yaml.safe_load(path.read_text())
    data["legacy_profiles"]["hybrid"] = {"algorithm": "3DES", "mode": "CBC", "iv": "prefix", "padding": "pkcs7",
                                         "encoding": "raw", "key_transport": "rsa-pkcs1v15", "key_id": "legacy-rsa"}
    data["data_sources"].append({"name": "messages", "adapter": "sql", "driver": "sqlite3",
                                 "connect": {"database": "legacy.db"}, "table": "messages", "primary_key": "id",
                                 "columns": [{"name": "body", "legacy_profile": "hybrid", "storage": "blob"}]})
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    cfg = load_config(path)
    store = Keystore.from_config(cfg, create=True)
    store.generate()
    store.import_legacy("legacy-rsa", "RSA", DER)
    engine = MigrationEngine(cfg, store)
    run = engine.run(cfg.source("messages"), apply=True)
    assert run["status"] == "completed" and run["counters"]["migrated"] == 7
    svc = CryptoService(store, cfg.target_algorithm, cfg.legacy_profiles, mode="strict")
    db = sqlite3.connect(tmp_path / "p" / "legacy.db")
    for pk, value in db.execute("SELECT id, body FROM messages"):
        assert svc.decrypt(value, f"messages.body#{pk}") == bodies[pk]
    assert engine.verify_source(cfg.source("messages"))["status"] == "pass"


def _pem_pair(directory, key):
    directory.mkdir(parents=True, exist_ok=True)
    private, public = directory / "kek.pem", directory / "kek.pub.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public


def test_rsa_kek_protects_aes_keys(tmp_path, monkeypatch):
    private, public = _pem_pair(tmp_path / "kek", rsa.generate_private_key(public_exponent=65537, key_size=3072))
    monkeypatch.delenv("CRYPTOMIGRATE_KEK", raising=False)
    monkeypatch.setenv("CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE", str(private))
    store = Keystore.create(tmp_path / "ks.json", wrap="rsa-aes-kwp", rsa_public_key=str(public))
    key_id = store.generate()
    store.import_legacy("legacy-rsa", "RSA", DER)  # ~1.2 KB - more than RSA-OAEP alone could wrap
    raw = json.loads((tmp_path / "ks.json").read_text())
    assert raw["kek"]["wrap"] == "rsa-aes-kwp" and raw["kek"]["key_bits"] == 3072
    assert len(base64.b64decode(raw["keys"][key_id]["wrapped"])) == 384 + 40  # RSA-3072 block + KWP(32 bytes)
    reopened = Keystore.open(tmp_path / "ks.json")
    assert reopened.get(key_id) == store.get(key_id) and reopened.get("legacy-rsa") == DER
    monkeypatch.delenv("CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE")
    public_only = Keystore.open(tmp_path / "ks.json")
    with pytest.raises(KeystoreError, match="private key is not available"):
        public_only.get(key_id)
    public_only.generate(reason="rotation by a custodian who cannot decrypt")  # wrapping needs only the public key
    other, _ = _pem_pair(tmp_path / "other", rsa.generate_private_key(public_exponent=65537, key_size=2048))
    monkeypatch.setenv("CRYPTOMIGRATE_KEK_RSA_PRIVATE_FILE", str(other))
    with pytest.raises(KeystoreError, match="does not match"):
        Keystore.open(tmp_path / "ks.json")


def test_hybrid_and_cms_detection(tmp_path):
    (tmp_path / "Mail.java").write_text(
        "OutputEncryptor e = new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).build();\n")
    (tmp_path / "Mail.cs").write_text('var cms = new EnvelopedCms(content);\nvar oid = new Oid("1.2.840.113549.3.7");\n')
    (tmp_path / "key.pem").write_text("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
                                      "DEK-Info: DES-EDE3-CBC,0123456789ABCDEF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n")
    (tmp_path / "Wrap.java").write_text('Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");\n')
    policy = load_policy_set("des-to-aes", ["pki-tls"])
    found = {(f.location, f.rule_id, f.algorithm, f.severity) for f in Scanner(policy, tmp_path).scan([tmp_path])}
    assert {("Mail.java", "CM-CMS-001", "3DES", "high"), ("Mail.cs", "CM-CMS-001", "3DES", "high"),
            ("Mail.cs", "CM-OID-001", "3DES", "high"), ("key.pem", "CM-PEM-001", "3DES", "high"),
            ("key.pem", "TLS-KEY-001", "n/a", "medium"), ("Wrap.java", "TLS-RSA-002", "RSA", "high")} <= found
